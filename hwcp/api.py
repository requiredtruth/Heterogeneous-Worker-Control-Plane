"""Authenticated pull API and bounded content-addressed artifact transport."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import ssl
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .store import Store
from .util import HWCPError, bounded_json, valid_sha

MAX_JSON = 1_048_576
DEFAULT_MAX_ARTIFACT = 4_294_967_296


def initialize_secrets(data_dir: Path) -> dict[str, Path]:
    """Create local administrative and enrollment bearer tokens once, mode 0600."""
    data_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    for name in ("admin.token", "enrollment.token"):
        path = data_dir / name
        if not path.exists():
            temporary = path.with_name(f".{name}.{os.getpid()}.tmp")
            temporary.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        os.chmod(path, 0o600)
        result[name] = path
    return result


class ControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], store: Store, max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT):
        self.store = store
        self.max_artifact_bytes = max_artifact_bytes
        self.secrets = initialize_secrets(store.data_dir)
        super().__init__(address, Handler)

    def token(self, name: str) -> str:
        return self.secrets[name].read_text(encoding="utf-8").strip()


class Handler(BaseHTTPRequestHandler):
    server: ControlHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Do not persist addresses, bearer headers, query strings, or full requests.
        return

    def _json(self, status: int, value: Any) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message[:512]}})

    def _body(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise HWCPError("invalid Content-Length") from exc
        if length < 0 or length > MAX_JSON:
            raise HWCPError(f"JSON Content-Length must be between 0 and {MAX_JSON}")
        return bounded_json(self.rfile.read(length), MAX_JSON)

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or len(header) > 512:
            return ""
        return header[7:]

    def _admin(self) -> bool:
        return secrets.compare_digest(self._bearer(), self.server.token("admin.token"))

    def _enrollment(self) -> bool:
        return secrets.compare_digest(self._bearer(), self.server.token("enrollment.token"))

    def _worker(self) -> str | None:
        worker_id = self.headers.get("X-Worker-ID", "")
        try:
            return worker_id if self.server.store.authenticate_worker(worker_id, self._bearer()) else None
        except HWCPError:
            return None

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            if path == "/healthz":
                self._json(HTTPStatus.OK, {"live": True, "version": __version__})
                return
            if path == "/readyz":
                self.server.store.read()
                self._json(HTTPStatus.OK, {"ready": True, "schema": 1, "version": __version__})
                return
            if path == "/api/manager/status":
                if not self._admin():
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "administrator token required")
                    return
                self._json(HTTPStatus.OK, self.server.store.status())
                return
            if path.startswith("/api/worker/control/"):
                worker_id = self._worker()
                if not worker_id:
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "worker token required")
                    return
                job_id = path.rsplit("/", 1)[-1]
                self._json(HTTPStatus.OK, self.server.store.control(worker_id, job_id))
                return
            if path.startswith("/api/worker/artifacts/"):
                if not self._worker():
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "worker token required")
                    return
                self._send_artifact(path.rsplit("/", 1)[-1])
                return
            self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "endpoint not found")
        except HWCPError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL", "internal request failure")

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            if path == "/api/worker/register":
                if not self._enrollment():
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "enrollment token required")
                    return
                worker, token = self.server.store.register_worker(self._body())
                self._json(HTTPStatus.CREATED, {"worker": worker, "worker_token": token})
                return
            if path in {"/api/worker/poll", "/api/worker/progress", "/api/worker/complete"}:
                worker_id = self._worker()
                if not worker_id:
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "worker token required")
                    return
                body = self._body()
                if path.endswith("/poll"):
                    result = self.server.store.poll(worker_id, body)
                elif path.endswith("/progress"):
                    result = self.server.store.progress(worker_id, str(body.get("job_id", "")), body.get("progress", {}))
                else:
                    result = self.server.store.complete(
                        worker_id, str(body.get("job_id", "")), int(body.get("exit_code", -1)),
                        body.get("outputs", []), str(body.get("stdout_tail", "")), str(body.get("stderr_tail", "")),
                    )
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/manager/jobs":
                if not self._admin():
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "administrator token required")
                    return
                self._json(HTTPStatus.CREATED, self.server.store.submit_job(self._body()))
                return
            if path.startswith("/api/manager/jobs/") and path.endswith("/cancel"):
                if not self._admin():
                    self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "administrator token required")
                    return
                job_id = path.split("/")[-2]
                self._json(HTTPStatus.OK, self.server.store.cancel(job_id))
                return
            self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "endpoint not found")
        except HWCPError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL", "internal request failure")

    def do_PUT(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            source = ""
            if path.startswith("/api/manager/artifacts/") and self._admin():
                source = "manager"
            elif path.startswith("/api/worker/artifacts/"):
                worker_id = self._worker()
                if worker_id:
                    source = f"worker:{worker_id}"
            if not source:
                self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "artifact upload authorization required")
                return
            sha = valid_sha(path.rsplit("/", 1)[-1])
            item = self._receive_artifact(sha, source)
            self._json(HTTPStatus.CREATED, item)
        except HWCPError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL", "internal artifact failure")

    def _receive_artifact(self, expected_sha: str, source: str) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise HWCPError("artifact Content-Length is invalid") from exc
        if not 0 <= length <= self.server.max_artifact_bytes:
            raise HWCPError(f"artifact size must be between 0 and {self.server.max_artifact_bytes}")
        destination = self.server.store.artifact_dir / expected_sha[:2] / expected_sha
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.stat().st_size != length:
                raise HWCPError("cached artifact size does not match upload")
            digest = hashlib.sha256()
            with destination.open("rb") as handle:
                while chunk := handle.read(1_048_576):
                    digest.update(chunk)
            if digest.hexdigest() != expected_sha:
                raise HWCPError("cached artifact failed SHA-256 verification")
            return self.server.store.record_artifact(expected_sha, length, source)
        temporary_fd, temporary_name = tempfile.mkstemp(prefix="artifact-", dir=self.server.store.data_dir)
        actual = hashlib.sha256()
        read = 0
        try:
            with os.fdopen(temporary_fd, "wb") as output:
                while read < length:
                    chunk = self.rfile.read(min(1_048_576, length - read))
                    if not chunk:
                        raise HWCPError("artifact body ended before Content-Length")
                    read += len(chunk)
                    actual.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if actual.hexdigest() != expected_sha:
                raise HWCPError("artifact SHA-256 mismatch")
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return self.server.store.record_artifact(expected_sha, read, source)

    def _send_artifact(self, value: str) -> None:
        sha = valid_sha(value)
        path = self.server.store.artifact_dir / sha[:2] / sha
        if not path.is_file():
            self._error(HTTPStatus.NOT_FOUND, "ARTIFACT_NOT_FOUND", "artifact is not present")
            return
        digest = hashlib.sha256()
        with path.open("rb") as verification:
            while chunk := verification.read(1_048_576):
                digest.update(chunk)
        if digest.hexdigest() != sha:
            self._error(HTTPStatus.CONFLICT, "ARTIFACT_CORRUPT", "cached artifact failed SHA-256 verification")
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("ETag", f'"sha256:{sha}"')
        self.send_header("Cache-Control", "private, immutable")
        self.end_headers()
        with path.open("rb") as handle:
            while chunk := handle.read(1_048_576):
                self.wfile.write(chunk)


def make_server(store: Store, host: str, port: int, tls_cert: Path | None = None, tls_key: Path | None = None) -> ControlHTTPServer:
    """Build a server; non-loopback binds require operator-supplied TLS."""
    if host not in {"127.0.0.1", "::1", "localhost"} and not (tls_cert and tls_key):
        raise HWCPError("non-loopback binding requires --tls-cert and --tls-key")
    server = ControlHTTPServer((host, port), store)
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(tls_cert), str(tls_key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
