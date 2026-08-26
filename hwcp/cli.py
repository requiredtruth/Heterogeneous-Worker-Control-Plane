"""Operator CLI for the local control plane and pull workers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from .api import initialize_secrets, make_server
from .store import Store
from .util import HWCPError, atomic_json, safe_relative
from .worker import Worker


def default_data() -> Path:
    return Path(os.environ.get("HWCP_DATA", "DATA")).expanduser().resolve()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hwcp", description="Authenticated pull control plane for mixed local workers.")
    p.add_argument("--data", type=Path, default=default_data(), help="durable data directory")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8789)
    serve.add_argument("--tls-cert", type=Path)
    serve.add_argument("--tls-key", type=Path)
    worker = sub.add_parser("worker")
    worker.add_argument("config", type=Path)
    once = sub.add_parser("worker-once")
    once.add_argument("config", type=Path)
    submit = sub.add_parser("submit")
    submit.add_argument("job", type=Path)
    cancel = sub.add_parser("cancel")
    cancel.add_argument("job_id")
    sub.add_parser("status")
    sub.add_parser("demo")
    return p


def initialize(data_dir: Path) -> dict[str, Any]:
    store = Store(data_dir)
    store.initialize()
    paths = initialize_secrets(data_dir)
    return {
        "initialized": str(data_dir), "state": str(store.state_path),
        "admin_token_file": str(paths["admin.token"]),
        "enrollment_token_file": str(paths["enrollment.token"]),
    }


def _copy_artifact(store: Store, source: Path) -> tuple[str, int]:
    source = source.expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise HWCPError(f"input source must be a regular file: {source}")
    digest = hashlib.sha256()
    size = 0
    temporary_fd, temporary_name = tempfile.mkstemp(prefix="artifact-", dir=store.data_dir)
    try:
        with source.open("rb") as input_file, os.fdopen(temporary_fd, "wb") as output:
            while chunk := input_file.read(1_048_576):
                digest.update(chunk)
                size += len(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        sha = digest.hexdigest()
        destination = store.artifact_dir / sha[:2] / sha
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.stat().st_size != size:
            raise HWCPError("content-addressed artifact has an impossible size mismatch")
        if destination.exists():
            existing = hashlib.sha256()
            with destination.open("rb") as handle:
                while chunk := handle.read(1_048_576):
                    existing.update(chunk)
            if existing.hexdigest() != sha:
                raise HWCPError("cached input artifact failed SHA-256 verification")
        if not destination.exists():
            os.replace(temporary_name, destination)
        store.record_artifact(sha, size, "local-manager")
        return sha, size
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def submit_spec(store: Store, spec_path: Path) -> dict[str, Any]:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    inputs = []
    for item in spec.get("inputs", []):
        clean = {"path": safe_relative(item.get("path"))}
        if item.get("source"):
            clean["sha256"], _ = _copy_artifact(store, Path(item["source"]))
        else:
            clean["sha256"] = item.get("sha256")
        inputs.append(clean)
    spec["inputs"] = inputs
    return store.submit_job(spec)


def synthetic_demo() -> dict[str, Any]:
    """Run one real loopback registration, assignment, execution, and artifact return."""
    with tempfile.TemporaryDirectory(prefix="hwcp-demo-") as temporary:
        root = Path(temporary)
        data = root / "DATA"
        initialize(data)
        store = Store(data)
        server = make_server(store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            worker_config = root / "worker.json"
            executable = Path(sys.executable).name
            atomic_json(worker_config, {
                "server_url": f"http://127.0.0.1:{port}", "worker_id": "synthetic-worker",
                "enrollment_token_file": str(data / "enrollment.token"),
                "worker_token_file": str(root / "worker.token"),
                "workspace_dir": str(root / "work"), "allow_executables": [executable],
                "capabilities": ["synthetic"], "max_artifact_bytes": 1_048_576,
                "install_profiles": {
                    "synthetic-prepare": {
                        "argv": [executable, "-c", "from pathlib import Path; Path('prepared.marker').write_text('ready')"],
                        "timeout_seconds": 10
                    }
                },
            })
            job_spec = root / "job.json"
            atomic_json(job_spec, {
                "name": "synthetic-uppercase", "argv": [executable, "-c", "from pathlib import Path; Path('result.txt').write_text('VERIFIED')"],
                "required_architectures": [], "required_capabilities": ["synthetic"],
                "install_profiles": ["synthetic-prepare"],
                "min_ram_mb": 1, "min_disk_mb": 1, "timeout_seconds": 10,
                "lease_seconds": 15, "max_attempts": 1, "inputs": [],
                "outputs": [{"path": "result.txt", "max_bytes": 64}],
            })
            job = submit_spec(store, job_spec)
            result = Worker(worker_config).poll_once()
            status = store.status()
            install_count = len(list((root / "install-profiles").glob("*.json")))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        final = next(item for item in status["jobs"] if item["id"] == job["id"])
        if final["state"] != "completed" or result.get("kind") != "completed":
            raise HWCPError("synthetic end-to-end demo did not complete")
        return {
            "demo": "synthetic", "job_state": final["state"],
            "worker_count": len(status["workers"]), "artifact_count": status["artifact_count"],
            "exit_code": final["result"]["exit_code"], "install_profile_count": install_count,
        }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            result = initialize(args.data.resolve())
        elif args.command == "serve":
            initialize(args.data.resolve())
            server = make_server(Store(args.data), args.host, args.port, args.tls_cert, args.tls_key)
            print(json.dumps({"status": "serving", "host": args.host, "port": server.server_address[1]}, sort_keys=True), flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        elif args.command == "worker":
            Worker(args.config).run_forever()
            return 0
        elif args.command == "worker-once":
            result = Worker(args.config).poll_once()
        elif args.command == "submit":
            result = submit_spec(Store(args.data), args.job)
        elif args.command == "cancel":
            result = Store(args.data).cancel(args.job_id)
        elif args.command == "status":
            result = Store(args.data).status()
        else:
            result = synthetic_demo()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HWCPError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": {"code": type(exc).__name__, "message": str(exc)[:512]}}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
