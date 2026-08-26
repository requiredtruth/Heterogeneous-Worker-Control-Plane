"""Pull-only worker with local executable allowlists and verified artifacts."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .util import HWCPError, atomic_json, normalize_arch, safe_relative, utc_now, valid_id, valid_sha

TAIL_BYTES = 65_536
REDACTIONS = (
    (re.compile(r"(?i)(password|passwd|token|secret|authorization)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)Bearer\s+\S+"), "Bearer [REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED IP]"),
    (re.compile(r"(?<![A-Za-z0-9_.-])/(?:home|root|data/data|Users)/[^\s'\"]+"), "[REDACTED PATH]"),
)


def redact(value: str) -> str:
    for pattern, replacement in REDACTIONS:
        value = pattern.sub(replacement, value)
    return value[-TAIL_BYTES:]


class Client:
    """Small JSON and streaming-binary HTTP client with bearer authentication."""

    def __init__(self, base_url: str, token: str, worker_id: str | None = None, ca_file: str | None = None):
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise HWCPError("server_url must be an http(s) origin without a path")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise HWCPError("non-loopback workers require an HTTPS server URL")
        self.parsed = parsed
        self.token = token
        self.worker_id = worker_id
        self.ca_file = ca_file

    def _connection(self) -> http.client.HTTPConnection:
        if self.parsed.scheme == "https":
            import ssl
            context = ssl.create_default_context(cafile=self.ca_file)
            return http.client.HTTPSConnection(self.parsed.hostname, self.parsed.port or 443, context=context, timeout=30)
        return http.client.HTTPConnection(self.parsed.hostname, self.parsed.port or 80, timeout=30)

    def _headers(self) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token}", "User-Agent": f"hwcp-worker/{__version__}"}
        if self.worker_id:
            headers["X-Worker-ID"] = self.worker_id
        return headers

    def json(self, method: str, path: str, body: Any | None = None) -> Any:
        connection = self._connection()
        payload = b"" if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {**self._headers(), "Content-Type": "application/json", "Content-Length": str(len(payload))}
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            data = response.read(1_048_577)
            if len(data) > 1_048_576:
                raise HWCPError("server JSON response exceeded 1 MiB")
            decoded = json.loads(data.decode("utf-8")) if data else {}
            if response.status >= 400:
                error = decoded.get("error", {}) if isinstance(decoded, dict) else {}
                raise HWCPError(f"server {response.status}: {error.get('code', 'ERROR')}: {error.get('message', '')}")
            return decoded
        finally:
            connection.close()

    def download(self, sha: str, destination: Path, max_bytes: int) -> int:
        sha = valid_sha(sha)
        connection = self._connection()
        temporary = destination.with_name(f".{destination.name}.download")
        digest = hashlib.sha256()
        total = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            connection.request("GET", f"/api/worker/artifacts/{sha}", headers=self._headers())
            response = connection.getresponse()
            if response.status != 200:
                raise HWCPError(f"artifact download failed with HTTP {response.status}")
            length = int(response.getheader("Content-Length", "-1"))
            if length < 0 or length > max_bytes:
                raise HWCPError("artifact exceeds the worker transfer bound")
            with temporary.open("wb") as output:
                while chunk := response.read(1_048_576):
                    total += len(chunk)
                    if total > max_bytes:
                        raise HWCPError("artifact exceeded its declared transfer bound")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if total != length or digest.hexdigest() != sha:
                raise HWCPError("downloaded artifact size or SHA-256 did not verify")
            os.replace(temporary, destination)
            return total
        finally:
            connection.close()
            if temporary.exists():
                temporary.unlink()

    def upload(self, sha: str, source: Path, manager: bool = False) -> int:
        sha = valid_sha(sha)
        size = source.stat().st_size
        connection = self._connection()
        headers = {**self._headers(), "Content-Type": "application/octet-stream", "Content-Length": str(size)}
        try:
            role = "manager" if manager else "worker"
            connection.putrequest("PUT", f"/api/{role}/artifacts/{sha}")
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.endheaders()
            with source.open("rb") as handle:
                while chunk := handle.read(1_048_576):
                    connection.send(chunk)
            response = connection.getresponse()
            body = response.read(1_048_576)
            if response.status >= 400:
                raise HWCPError(f"artifact upload failed with HTTP {response.status}: {body[:256]!r}")
            return size
        finally:
            connection.close()


class Worker:
    """A single-job pull worker. It never accepts inbound connections."""

    def __init__(self, config_path: Path):
        self.config_path = config_path.resolve()
        self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.worker_id = valid_id(self.config.get("worker_id"), "worker_id")
        self.workspace = self._config_path(self.config["workspace_dir"])
        self.token_path = self._config_path(self.config["worker_token_file"])
        self.enrollment_path = self._config_path(self.config["enrollment_token_file"])
        self.ca_file = self._config_path(self.config["ca_file"]) if self.config.get("ca_file") else None
        self.allowed = sorted(set(self.config.get("allow_executables", [])))
        if not self.allowed or any("/" in item or not item for item in self.allowed):
            raise HWCPError("allow_executables must contain executable basenames only")
        self.install_profiles = self.config.get("install_profiles", {})
        if not isinstance(self.install_profiles, dict) or len(self.install_profiles) > 32:
            raise HWCPError("install_profiles must be an object with at most 32 entries")
        for name, profile in self.install_profiles.items():
            valid_id(name, "install profile")
            argv = profile.get("argv") if isinstance(profile, dict) else None
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
                raise HWCPError(f"install profile {name} requires an argv string array")
            if argv[0] != Path(argv[0]).name:
                raise HWCPError(f"install profile {name} executable must be a basename")
        self.max_transfer = min(4_294_967_296, max(1, int(self.config.get("max_artifact_bytes", 1_073_741_824))))
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.token_path.parent.mkdir(parents=True, exist_ok=True)

    def _config_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        return (path if path.is_absolute() else self.config_path.parent / path).resolve()

    def inventory(self) -> dict[str, Any]:
        ram_total = ram_available = swap_free = 0.0
        try:
            memory = {}
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                key, raw = line.split(":", 1)
                memory[key] = float(raw.strip().split()[0]) / 1024
            ram_total = memory.get("MemTotal", 0.0)
            ram_available = memory.get("MemAvailable", memory.get("MemFree", 0.0))
            swap_free = memory.get("SwapFree", 0.0)
        except (OSError, ValueError, IndexError):
            pass
        try:
            if not ram_total:
                page_size = os.sysconf("SC_PAGE_SIZE")
                ram_total = os.sysconf("SC_PHYS_PAGES") * page_size / 1_048_576
                ram_available = os.sysconf("SC_AVPHYS_PAGES") * page_size / 1_048_576
        except (ValueError, OSError):
            pass
        try:
            load = os.getloadavg()[0]
        except OSError:
            load = 0.0
        disk = shutil.disk_usage(self.workspace)
        package_manager = next((name for name in ("pkg", "apt", "dnf", "pacman", "apk") if shutil.which(name)), "unknown")
        platform_name = "android-termux" if os.environ.get("PREFIX", "").endswith("/files/usr") else platform.system().lower()
        accelerators = []
        if shutil.which("nvidia-smi"):
            accelerators.append("nvidia")
        if shutil.which("rocm-smi"):
            accelerators.append("amd-rocm")
        if Path("/dev/dri").is_dir():
            accelerators.append("dri")
        capabilities = sorted(
            set(self.config.get("capabilities", []))
            | {f"exec.{name}" for name in self.allowed}
            | {f"install.{name}" for name in self.install_profiles}
        )
        return {
            "worker_id": self.worker_id, "architecture": normalize_arch(),
            "platform": platform_name, "kernel": platform.release(),
            "package_manager": package_manager, "agent_version": __version__,
            "capabilities": capabilities, "accelerators": accelerators,
            "resources": {
                "cpu_count": os.cpu_count() or 1, "load_1m": load,
                "ram_available_mb": ram_available, "ram_total_mb": ram_total,
                "swap_free_mb": swap_free, "disk_free_mb": disk.free / 1_048_576,
            },
        }

    def _client(self, enrollment: bool = False) -> Client:
        token_path = self.enrollment_path if enrollment else self.token_path
        if not token_path.is_file():
            raise HWCPError(f"required token file is missing: {token_path}")
        token = token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise HWCPError("token file is empty")
        os.chmod(token_path, 0o600)
        return Client(self.config["server_url"], token, None if enrollment else self.worker_id, str(self.ca_file) if self.ca_file else None)

    def register_if_needed(self) -> None:
        if self.token_path.is_file():
            return
        response = self._client(enrollment=True).json("POST", "/api/worker/register", self.inventory())
        temporary = self.token_path.with_name(f".{self.token_path.name}.tmp")
        temporary.write_text(str(response["worker_token"]) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.token_path)

    def poll_once(self) -> dict[str, Any]:
        self.register_if_needed()
        client = self._client()
        response = client.json("POST", "/api/worker/poll", self.inventory())
        if response.get("kind") != "job":
            return response
        return self.execute(response["job"], client)

    def execute(self, job: dict[str, Any], client: Client) -> dict[str, Any]:
        job_id = valid_id(job.get("id"), "job_id")
        argv = job.get("argv", [])
        executable = Path(argv[0]).name if argv else ""
        if executable not in self.allowed or argv[0] != executable:
            return self._fail(client, job_id, 126, f"EXECUTABLE_NOT_ALLOWED:{executable}")
        run_dir = self.workspace / f"{job_id}-attempt-{int(job['attempts'])}"
        if run_dir.exists():
            marker = run_dir / ".hwcp/job.json"
            if not marker.is_file() or json.loads(marker.read_text(encoding="utf-8")).get("job_id") != job_id:
                return self._fail(client, job_id, 125, "WORKSPACE_COLLISION")
        else:
            (run_dir / ".hwcp").mkdir(parents=True)
            atomic_json(run_dir / ".hwcp/job.json", {"job_id": job_id, "attempt": int(job["attempts"])})
        try:
            self._ensure_install_profiles(job, client)
            client.json("POST", "/api/worker/progress", {"job_id": job_id, "progress": {"phase": "staging", "completed": 0, "total": len(job["inputs"])}})
            for index, item in enumerate(job["inputs"], start=1):
                destination = self._workspace_path(run_dir, item["path"])
                client.download(item["sha256"], destination, self.max_transfer)
                client.json("POST", "/api/worker/progress", {"job_id": job_id, "progress": {"phase": "staging", "completed": index, "total": len(job["inputs"])}})
            return self._run_process(job, run_dir, client)
        except HWCPError as exc:
            return self._fail(client, job_id, 125, str(exc))

    def _ensure_install_profiles(self, job: dict[str, Any], client: Client) -> None:
        names = job.get("install_profiles", [])
        state_dir = self.token_path.parent / "install-profiles"
        state_dir.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(names, start=1):
            profile = self.install_profiles.get(name)
            if not profile:
                raise HWCPError(f"INSTALL_PROFILE_UNAVAILABLE:{name}")
            argv = profile["argv"]
            digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest()
            marker = state_dir / f"{name}.json"
            if marker.is_file():
                try:
                    if json.loads(marker.read_text(encoding="utf-8")).get("argv_sha256") == digest:
                        continue
                except json.JSONDecodeError:
                    pass
            client.json("POST", "/api/worker/progress", {
                "job_id": job["id"],
                "progress": {"phase": f"installing:{name}", "completed": index - 1, "total": len(names)},
            })
            timeout = min(3600, max(1, int(profile.get("timeout_seconds", 600))))
            try:
                with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                    result = subprocess.run(
                        argv, cwd=self.workspace, env={"PATH": os.environ.get("PATH", ""), "LANG": os.environ.get("LANG", "C.UTF-8")},
                        shell=False, stdout=stdout, stderr=stderr, timeout=timeout, check=False,
                    )
                    stderr.seek(max(0, stderr.tell() - TAIL_BYTES))
                    error_tail = stderr.read(TAIL_BYTES).decode("utf-8", "replace")
            except subprocess.TimeoutExpired as exc:
                raise HWCPError(f"INSTALL_PROFILE_TIMEOUT:{name}") from exc
            if result.returncode != 0:
                message = redact(error_tail)
                raise HWCPError(f"INSTALL_PROFILE_FAILED:{name}:{message[-256:]}")
            atomic_json(marker, {"schema": 1, "profile": name, "argv_sha256": digest, "completed_at": utc_now()})

    def _run_process(self, job: dict[str, Any], run_dir: Path, client: Client) -> dict[str, Any]:
        job_id = job["id"]
        stdout_path, stderr_path = run_dir / ".hwcp/stdout.log", run_dir / ".hwcp/stderr.log"
        environment = {
            "PATH": os.environ.get("PATH", ""), "LANG": os.environ.get("LANG", "C.UTF-8"),
            "HOME": str(run_dir), "TMPDIR": str(run_dir / ".hwcp"),
            "HWCP_JOB_ID": job_id, "HWCP_ATTEMPT": str(job["attempts"]),
        }
        client.json("POST", "/api/worker/progress", {"job_id": job_id, "progress": {"phase": "executing", "completed": 0, "total": None}})
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(job["argv"], cwd=run_dir, env=environment, stdout=stdout, stderr=stderr, shell=False, start_new_session=True)
            deadline = time.monotonic() + int(job["timeout_seconds"])
            next_heartbeat = 0.0
            control_failures = 0
            reason = ""
            while process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    reason = "TIMEOUT"
                    self._terminate(process)
                    break
                if now >= next_heartbeat:
                    try:
                        response = client.json("POST", "/api/worker/progress", {"job_id": job_id, "progress": {"phase": "executing", "completed": 0, "total": None}})
                        control_failures = 0
                        if response.get("cancel_requested"):
                            reason = "CANCELLED"
                            self._terminate(process)
                            break
                    except HWCPError:
                        control_failures += 1
                        if control_failures >= 3:
                            reason = "CONTROL_PLANE_UNREACHABLE"
                            self._terminate(process)
                            break
                    next_heartbeat = now + min(5, max(1, int(job["lease_seconds"]) // 3))
                time.sleep(0.05)
            exit_code = process.wait(timeout=5)
        stdout_tail = redact(self._tail(stdout_path))
        stderr_tail = redact((reason + "\n" if reason else "") + self._tail(stderr_path))
        if exit_code != 0 or reason:
            return self._fail(client, job_id, exit_code or 124, stderr_tail, stdout_tail)
        outputs = []
        for declaration in job["outputs"]:
            path = self._workspace_path(run_dir, declaration["path"])
            if not path.is_file() or path.is_symlink():
                return self._fail(client, job_id, 125, f"OUTPUT_MISSING:{declaration['path']}", stdout_tail)
            size = path.stat().st_size
            if size > int(declaration["max_bytes"]):
                return self._fail(client, job_id, 125, f"OUTPUT_TOO_LARGE:{declaration['path']}", stdout_tail)
            sha = self._sha(path)
            client.upload(sha, path)
            outputs.append({"path": declaration["path"], "sha256": sha, "size": size})
        result = client.json("POST", "/api/worker/complete", {"job_id": job_id, "exit_code": 0, "outputs": outputs, "stdout_tail": stdout_tail, "stderr_tail": stderr_tail})
        return {"kind": "completed", "job": result}

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    @staticmethod
    def _tail(path: Path) -> str:
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - TAIL_BYTES))
            return handle.read(TAIL_BYTES).decode("utf-8", "replace")

    @staticmethod
    def _sha(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1_048_576):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _workspace_path(run_dir: Path, relative: str) -> Path:
        candidate = run_dir / safe_relative(relative)
        resolved_parent = candidate.parent.resolve()
        if not resolved_parent.is_relative_to(run_dir.resolve()):
            raise HWCPError("artifact path escapes the worker run directory through a symbolic link")
        return candidate

    def _fail(self, client: Client, job_id: str, exit_code: int, stderr: str, stdout: str = "") -> dict[str, Any]:
        result = client.json("POST", "/api/worker/complete", {
            "job_id": job_id, "exit_code": int(exit_code), "outputs": [],
            "stdout_tail": redact(stdout), "stderr_tail": redact(stderr),
        })
        return {"kind": "failed", "job": result}

    def run_forever(self) -> None:
        interval = min(300, max(1, int(self.config.get("poll_seconds", 2))))
        failures = 0
        while True:
            try:
                result = self.poll_once()
                failures = 0
                if result.get("kind") == "idle":
                    time.sleep(interval)
            except (HWCPError, OSError, json.JSONDecodeError) as exc:
                failures += 1
                delay = min(60, max(interval, 2 ** min(failures, 6)))
                print(redact(f"worker poll failed; retrying in {delay}s: {exc}"), file=sys.stderr, flush=True)
                time.sleep(delay)
