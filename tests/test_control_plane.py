from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from hwcp.api import initialize_secrets, make_server
from hwcp.cli import synthetic_demo
from hwcp.store import Store
from hwcp.util import HWCPError, normalize_arch
from hwcp.worker import Client, redact


def inventory(worker_id: str, architecture: str = "x86_64", capabilities: list[str] | None = None) -> dict:
    return {
        "worker_id": worker_id, "architecture": architecture, "platform": "synthetic-linux",
        "kernel": "synthetic", "package_manager": "none", "agent_version": "test",
        "capabilities": capabilities or ["python"], "accelerators": [],
        "resources": {
            "cpu_count": 4, "load_1m": 0, "ram_available_mb": 4096,
            "ram_total_mb": 8192, "swap_free_mb": 0, "disk_free_mb": 16384,
        },
    }


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hwcp-test-")
        self.data = Path(self.temporary.name) / "DATA"
        self.store = Store(self.data)
        self.store.initialize()
        initialize_secrets(self.data)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_artifact(self, payload: bytes = b"input") -> str:
        sha = hashlib.sha256(payload).hexdigest()
        path = self.store.artifact_dir / sha[:2] / sha
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self.store.record_artifact(sha, len(payload), "test")
        return sha

    def job(self, **updates) -> dict:
        payload = {
            "name": "synthetic", "argv": ["python3", "-c", "print('ok')"],
            "required_architectures": ["x86_64"], "required_capabilities": ["python"],
            "min_ram_mb": 128, "min_disk_mb": 128, "timeout_seconds": 30,
            "lease_seconds": 15, "max_attempts": 2, "inputs": [], "outputs": [],
        }
        payload.update(updates)
        return payload

    def test_state_views_and_token_permissions(self) -> None:
        for name in ("state.json", "status.json", "CURRENT.md", "TO-DO.md", "DONE.md", "status.txt"):
            self.assertTrue((self.data / name).is_file(), name)
        for name in ("admin.token", "enrollment.token"):
            mode = (self.data / name).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertNotIn((self.data / name).read_text().strip(), self.store.state_path.read_text())

    def test_registration_hides_token_and_duplicate_id_fails(self) -> None:
        public, token = self.store.register_worker(inventory("worker-a"))
        self.assertNotIn("token", json.dumps(public).lower())
        self.assertTrue(self.store.authenticate_worker("worker-a", token))
        self.assertFalse(self.store.authenticate_worker("worker-a", "wrong"))
        with self.assertRaises(HWCPError):
            self.store.register_worker(inventory("worker-a"))

    def test_resource_and_architecture_rejections_are_visible(self) -> None:
        self.store.register_worker(inventory("arm-small", "arm64"))
        job = self.store.submit_job(self.job(min_ram_mb=99999))
        response = self.store.poll("arm-small", inventory("arm-small", "arm64"))
        self.assertEqual(response["kind"], "idle")
        recorded = self.store.read()["jobs"][job["id"]]["ineligible"]["arm-small"]
        self.assertIn("ARCH_MISMATCH:arm64", recorded)
        self.assertIn("RAM_RESERVE", recorded)

    def test_atomic_claim_cancel_and_duplicate_completion_guard(self) -> None:
        _, token = self.store.register_worker(inventory("worker-a"))
        job = self.store.submit_job(self.job())
        claimed = self.store.poll("worker-a", inventory("worker-a"))["job"]
        self.assertEqual(claimed["id"], job["id"])
        self.store.cancel(job["id"])
        progress = self.store.progress("worker-a", job["id"], {"phase": "executing", "completed": 0})
        self.assertTrue(progress["cancel_requested"])
        final = self.store.complete("worker-a", job["id"], 143, [], "", "cancelled")
        self.assertEqual(final["state"], "cancelled")
        with self.assertRaises(HWCPError):
            self.store.complete("worker-a", job["id"], 0, [], "", "")
        self.assertTrue(self.store.authenticate_worker("worker-a", token))

    def test_expired_lease_requeues_with_bounded_backoff(self) -> None:
        self.store.register_worker(inventory("worker-a"))
        job = self.store.submit_job(self.job())
        self.store.poll("worker-a", inventory("worker-a"))
        with self.store._locked() as state:
            state["jobs"][job["id"]]["lease_expires_epoch"] = time.time() - 1
        self.store.status()
        state = self.store.mutate(lambda value: value["jobs"][job["id"]].copy())
        self.assertEqual(state["state"], "queued")
        self.assertEqual(state["last_error"], "LEASE_EXPIRED")
        self.assertGreater(state["not_before_epoch"], time.time())

    def test_streamed_artifact_upload_and_corruption_detection(self) -> None:
        server = make_server(self.store, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            payload = b"verified content"
            source = Path(self.temporary.name) / "artifact.bin"
            source.write_bytes(payload)
            sha = hashlib.sha256(payload).hexdigest()
            admin = Client(f"http://127.0.0.1:{server.server_address[1]}", (self.data / "admin.token").read_text().strip())
            self.assertEqual(admin.upload(sha, source, manager=True), len(payload))
            cached = self.store.artifact_dir / sha[:2] / sha
            cached.write_bytes(b"x" * len(payload))
            with self.assertRaises(HWCPError):
                admin.upload(sha, source, manager=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_non_loopback_requires_tls(self) -> None:
        with self.assertRaises(HWCPError):
            make_server(self.store, "0.0.0.0", 8789)

    def test_redaction_removes_secrets_addresses_and_paths(self) -> None:
        value = "password=hunter2 Bearer abc.def 192.0.2.5 /home/demo/private.txt"
        clean = redact(value)
        self.assertNotIn("hunter2", clean)
        self.assertNotIn("abc.def", clean)
        self.assertNotIn("192.0.2.5", clean)
        self.assertNotIn("/home/demo", clean)

    def test_complete_synthetic_remote_loop(self) -> None:
        result = synthetic_demo()
        self.assertEqual(result["job_state"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["install_profile_count"], 1)

    def test_arch_normalization(self) -> None:
        self.assertEqual(normalize_arch("amd64"), "x86_64")
        self.assertEqual(normalize_arch("aarch64"), "arm64")
        self.assertEqual(normalize_arch("mips"), "unknown")


if __name__ == "__main__":
    unittest.main()
