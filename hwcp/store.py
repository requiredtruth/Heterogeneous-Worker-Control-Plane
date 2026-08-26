"""Locked JSON authority for jobs, workers, artifacts, leases, and evidence."""

from __future__ import annotations

import copy
import fcntl
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from .util import HWCPError, atomic_json, atomic_text, token_digest, utc_now, valid_id, valid_sha, safe_relative

T = TypeVar("T")
SCHEMA = 1
MAX_EVENTS = 1000


class Store:
    """A process-safe local JSON store with atomic replacement and lease recovery."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir.resolve()
        self.state_path = self.data_dir / "state.json"
        self.lock_path = self.data_dir / ".state.lock"
        self.events_path = self.data_dir / "events.jsonl"
        self.artifact_dir = self.data_dir / "artifacts/sha256"

    def initialize(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            atomic_json(self.state_path, {
                "schema": SCHEMA, "revision": 0, "workers": {}, "jobs": {},
                "artifacts": {}, "events": [], "created_at": utc_now(),
            })
        os.chmod(self.data_dir, 0o700)
        self._write_views(self.read())

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        self.initialize_if_needed()
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            if state.get("schema") != SCHEMA:
                raise HWCPError(f"unsupported state schema: {state.get('schema')}")
            yield state
            state["revision"] = int(state.get("revision", 0)) + 1
            state["updated_at"] = utc_now()
            atomic_json(self.state_path, state)
            self._write_views(state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def initialize_if_needed(self) -> None:
        if not self.state_path.exists():
            self.initialize()

    def read(self) -> dict[str, Any]:
        self.initialize_if_needed()
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return state

    def mutate(self, operation: Callable[[dict[str, Any]], T]) -> T:
        with self._locked() as state:
            self._recover_expired(state)
            return operation(state)

    def _event(self, state: dict[str, Any], event: str, outcome: str, target: str, reason: str = "") -> None:
        item = {
            "timestamp": utc_now(), "event": event, "actor": "local-control-plane",
            "target": target, "outcome": outcome, "reason": reason[:256], "schema": SCHEMA,
        }
        state.setdefault("events", []).append(item)
        state["events"] = state["events"][-MAX_EVENTS:]
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _recover_expired(self, state: dict[str, Any]) -> None:
        now = time.time()
        for job in state["jobs"].values():
            if job["state"] != "active" or float(job.get("lease_expires_epoch", 0)) > now:
                continue
            if int(job["attempts"]) < int(job["max_attempts"]):
                delay = min(300, 2 ** max(0, int(job["attempts"]) - 1))
                job.update({"state": "queued", "worker_id": None, "lease_expires_epoch": None, "not_before_epoch": now + delay, "last_error": "LEASE_EXPIRED"})
                self._event(state, "job.requeued", "retry", job["id"], "LEASE_EXPIRED")
            else:
                job.update({"state": "dead", "worker_id": None, "lease_expires_epoch": None, "last_error": "LEASE_EXPIRED_MAX_ATTEMPTS", "finished_at": utc_now()})
                self._event(state, "job.dead", "failed", job["id"], "LEASE_EXPIRED_MAX_ATTEMPTS")

    def register_worker(self, inventory: dict[str, Any]) -> tuple[dict[str, Any], str]:
        worker_id = valid_id(inventory.get("worker_id"), "worker_id")
        token = secrets.token_urlsafe(32)

        def op(state: dict[str, Any]) -> dict[str, Any]:
            existing = state["workers"].get(worker_id)
            if existing and existing.get("token_hash"):
                raise HWCPError("worker_id is already registered")
            worker = self._validated_inventory(inventory)
            worker.update({"id": worker_id, "token_hash": token_digest(token), "registered_at": utc_now(), "last_seen": utc_now(), "state": "idle"})
            state["workers"][worker_id] = worker
            self._event(state, "worker.registered", "success", worker_id)
            return self.public_worker(worker)

        return self.mutate(op), token

    def authenticate_worker(self, worker_id: str, token: str) -> bool:
        state = self.read()
        worker = state["workers"].get(worker_id)
        return bool(worker and secrets.compare_digest(worker.get("token_hash", ""), token_digest(token)))

    @staticmethod
    def _validated_inventory(value: dict[str, Any]) -> dict[str, Any]:
        arch = str(value.get("architecture", ""))
        if arch not in {"x86_64", "arm64", "armv7", "unknown"}:
            raise HWCPError("architecture must be normalized")
        capabilities = value.get("capabilities", [])
        if not isinstance(capabilities, list) or len(capabilities) > 128:
            raise HWCPError("capabilities must be a list with at most 128 items")
        capabilities = sorted({valid_id(item, "capability") for item in capabilities})
        accelerators = value.get("accelerators", [])
        if not isinstance(accelerators, list) or len(accelerators) > 16:
            raise HWCPError("accelerators must be a list with at most 16 items")
        accelerators = sorted({valid_id(item, "accelerator") for item in accelerators})
        resources = value.get("resources", {})
        clean_resources = {}
        for key in ("cpu_count", "load_1m", "ram_available_mb", "ram_total_mb", "swap_free_mb", "disk_free_mb"):
            number = float(resources.get(key, 0))
            if number < 0 or number > 1_000_000_000:
                raise HWCPError(f"invalid resource value: {key}")
            clean_resources[key] = number
        return {
            "architecture": arch, "platform": str(value.get("platform", "unknown"))[:64],
            "kernel": str(value.get("kernel", "unknown"))[:128],
            "package_manager": str(value.get("package_manager", "unknown"))[:32],
            "agent_version": str(value.get("agent_version", "unknown"))[:32],
            "capabilities": capabilities, "accelerators": accelerators, "resources": clean_resources,
        }

    @staticmethod
    def public_worker(worker: dict[str, Any]) -> dict[str, Any]:
        return {key: copy.deepcopy(value) for key, value in worker.items() if key != "token_hash"}

    def submit_job(self, payload: dict[str, Any]) -> dict[str, Any]:
        job = self._validate_job(payload)

        def op(state: dict[str, Any]) -> dict[str, Any]:
            for artifact in job["inputs"]:
                if artifact["sha256"] not in state["artifacts"]:
                    raise HWCPError(f"input artifact is not present: {artifact['sha256']}")
            job_id = f"job-{secrets.token_hex(8)}"
            now = utc_now()
            record = {
                **job, "id": job_id, "state": "queued", "attempts": 0,
                "worker_id": None, "created_at": now, "updated_at": now,
                "not_before_epoch": 0, "lease_expires_epoch": None,
                "progress": {"phase": "queued", "completed": 0, "total": None},
                "last_error": "", "result": None, "ineligible": {},
            }
            state["jobs"][job_id] = record
            self._event(state, "job.queued", "success", job_id)
            return copy.deepcopy(record)

        return self.mutate(op)

    @staticmethod
    def _validate_job(payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name", ""))[:128].strip()
        if not name:
            raise HWCPError("job name is required")
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > 64 or not all(isinstance(x, str) and 0 < len(x) <= 4096 for x in argv):
            raise HWCPError("argv must contain 1..64 bounded strings")
        arches = sorted(set(payload.get("required_architectures", [])))
        if any(x not in {"x86_64", "arm64", "armv7"} for x in arches):
            raise HWCPError("required_architectures contains an unsupported value")
        capabilities = sorted({valid_id(x, "required capability") for x in payload.get("required_capabilities", [])})
        install_profiles = sorted({valid_id(x, "install profile") for x in payload.get("install_profiles", [])})
        capabilities.extend(f"install.{name}" for name in install_profiles)
        capabilities = sorted(set(capabilities))
        inputs = []
        for item in payload.get("inputs", []):
            inputs.append({"sha256": valid_sha(item.get("sha256")), "path": safe_relative(item.get("path"))})
        outputs = []
        for item in payload.get("outputs", []):
            maximum = int(item.get("max_bytes", 0))
            if not 1 <= maximum <= 4_294_967_296:
                raise HWCPError("output max_bytes must be between 1 and 4294967296")
            outputs.append({"path": safe_relative(item.get("path")), "max_bytes": maximum})
        if len(inputs) > 64 or len(outputs) > 64:
            raise HWCPError("jobs support at most 64 inputs and 64 outputs")
        return {
            "name": name, "argv": argv, "required_architectures": arches,
            "required_capabilities": capabilities, "min_ram_mb": max(0, int(payload.get("min_ram_mb", 0))),
            "install_profiles": install_profiles,
            "min_disk_mb": max(0, int(payload.get("min_disk_mb", 0))),
            "timeout_seconds": min(86400, max(1, int(payload.get("timeout_seconds", 300)))),
            "lease_seconds": min(3600, max(15, int(payload.get("lease_seconds", 120)))),
            "max_attempts": min(10, max(1, int(payload.get("max_attempts", 2)))),
            "inputs": inputs, "outputs": outputs,
        }

    @staticmethod
    def eligibility(job: dict[str, Any], worker: dict[str, Any]) -> list[str]:
        reasons = []
        if job["required_architectures"] and worker["architecture"] not in job["required_architectures"]:
            reasons.append(f"ARCH_MISMATCH:{worker['architecture']}")
        missing = sorted(set(job["required_capabilities"]) - set(worker["capabilities"]))
        if missing:
            reasons.append("MISSING_CAPABILITIES:" + ",".join(missing))
        if worker["resources"]["ram_available_mb"] < job["min_ram_mb"]:
            reasons.append("RAM_RESERVE")
        if worker["resources"]["disk_free_mb"] < job["min_disk_mb"]:
            reasons.append("DISK_RESERVE")
        return reasons

    def poll(self, worker_id: str, inventory: dict[str, Any]) -> dict[str, Any]:
        worker_id = valid_id(worker_id, "worker_id")

        def op(state: dict[str, Any]) -> dict[str, Any]:
            current = state["workers"].get(worker_id)
            if not current:
                raise HWCPError("worker is not registered")
            fresh = self._validated_inventory({**inventory, "worker_id": worker_id})
            current.update(fresh)
            current["last_seen"] = utc_now()
            active = next((job for job in state["jobs"].values() if job["state"] == "active" and job["worker_id"] == worker_id), None)
            if active:
                active["lease_expires_epoch"] = time.time() + int(active["lease_seconds"])
                current["state"] = "busy"
                return {"kind": "job", "job": copy.deepcopy(active), "resumed": True}
            candidates = sorted(state["jobs"].values(), key=lambda item: (item.get("not_before_epoch", 0), item["created_at"], item["id"]))
            for job in candidates:
                if job["state"] != "queued" or float(job.get("not_before_epoch", 0)) > time.time():
                    continue
                reasons = self.eligibility(job, current)
                job.setdefault("ineligible", {})[worker_id] = reasons
                if reasons:
                    continue
                job.update({
                    "state": "active", "worker_id": worker_id,
                    "attempts": int(job["attempts"]) + 1,
                    "started_at": job.get("started_at") or utc_now(),
                    "updated_at": utc_now(),
                    "lease_expires_epoch": time.time() + int(job["lease_seconds"]),
                    "progress": {"phase": "assigned", "completed": 0, "total": None},
                })
                current["state"] = "busy"
                self._event(state, "job.claimed", "success", job["id"], worker_id)
                return {"kind": "job", "job": copy.deepcopy(job), "resumed": False}
            current["state"] = "idle"
            return {"kind": "idle", "retry_after_seconds": 2}

        return self.mutate(op)

    def progress(self, worker_id: str, job_id: str, progress: dict[str, Any]) -> dict[str, Any]:
        phase = str(progress.get("phase", ""))[:64]
        completed = max(0, int(progress.get("completed", 0)))
        total = progress.get("total")
        total = None if total is None else max(0, int(total))

        def op(state: dict[str, Any]) -> dict[str, Any]:
            job = state["jobs"].get(job_id)
            if not job or job["state"] != "active" or job["worker_id"] != worker_id:
                raise HWCPError("worker does not hold this active job")
            job["progress"] = {"phase": phase, "completed": completed, "total": total}
            job["lease_expires_epoch"] = time.time() + int(job["lease_seconds"])
            job["updated_at"] = utc_now()
            return {"accepted": True, "cancel_requested": bool(job.get("cancel_requested"))}

        return self.mutate(op)

    def complete(self, worker_id: str, job_id: str, exit_code: int, outputs: list[dict[str, Any]], stdout_tail: str, stderr_tail: str) -> dict[str, Any]:
        def op(state: dict[str, Any]) -> dict[str, Any]:
            job = state["jobs"].get(job_id)
            if not job or job["state"] != "active" or job["worker_id"] != worker_id:
                raise HWCPError("duplicate or unauthorized completion")
            if job.get("cancel_requested"):
                final_state, reason = "cancelled", "CANCELLED"
            elif exit_code != 0:
                final_state, reason = "failed", f"EXIT_{exit_code}"
            else:
                expected = {item["path"]: item for item in job["outputs"]}
                actual = {safe_relative(item.get("path")): item for item in outputs}
                if set(actual) != set(expected):
                    raise HWCPError("completed outputs do not match the declared output set")
                for path, item in actual.items():
                    sha = valid_sha(item.get("sha256"))
                    size = int(item.get("size", -1))
                    artifact = state["artifacts"].get(sha)
                    if not artifact or int(artifact["size"]) != size or size > int(expected[path]["max_bytes"]):
                        raise HWCPError(f"output artifact verification failed: {path}")
                final_state, reason = "completed", ""
            job.update({
                "state": final_state, "updated_at": utc_now(), "finished_at": utc_now(),
                "lease_expires_epoch": None, "last_error": reason,
                "result": {"exit_code": int(exit_code), "outputs": outputs, "stdout_tail": stdout_tail[-65536:], "stderr_tail": stderr_tail[-65536:]},
                "progress": {"phase": final_state, "completed": 1, "total": 1},
            })
            state["workers"][worker_id]["state"] = "idle"
            self._event(state, f"job.{final_state}", "success" if final_state == "completed" else "failed", job_id, reason)
            return copy.deepcopy(job)

        return self.mutate(op)

    def cancel(self, job_id: str) -> dict[str, Any]:
        def op(state: dict[str, Any]) -> dict[str, Any]:
            job = state["jobs"].get(job_id)
            if not job:
                raise HWCPError("job not found")
            if job["state"] == "queued":
                job.update({"state": "cancelled", "finished_at": utc_now(), "last_error": "CANCELLED"})
            elif job["state"] == "active":
                job["cancel_requested"] = True
            else:
                raise HWCPError(f"job is already terminal: {job['state']}")
            self._event(state, "job.cancel_requested", "success", job_id)
            return copy.deepcopy(job)

        return self.mutate(op)

    def control(self, worker_id: str, job_id: str) -> dict[str, Any]:
        state = self.read()
        job = state["jobs"].get(job_id)
        if not job or job.get("worker_id") != worker_id:
            raise HWCPError("worker does not own this job")
        return {"cancel_requested": bool(job.get("cancel_requested")), "state": job["state"]}

    def record_artifact(self, sha: str, size: int, source: str) -> dict[str, Any]:
        sha = valid_sha(sha)

        def op(state: dict[str, Any]) -> dict[str, Any]:
            existing = state["artifacts"].get(sha)
            if existing and int(existing["size"]) != size:
                raise HWCPError("artifact digest collision with different size")
            item = existing or {"sha256": sha, "size": int(size), "created_at": utc_now(), "source": source[:64]}
            state["artifacts"][sha] = item
            self._event(state, "artifact.recorded", "success", sha, source)
            return copy.deepcopy(item)

        return self.mutate(op)

    def status(self) -> dict[str, Any]:
        state = self.read()
        counts: dict[str, int] = {}
        for job in state["jobs"].values():
            counts[job["state"]] = counts.get(job["state"], 0) + 1
        return {
            "schema": SCHEMA, "revision": state["revision"],
            "workers": [self.public_worker(w) for w in state["workers"].values()],
            "jobs": list(state["jobs"].values()), "job_counts": counts,
            "artifact_count": len(state["artifacts"]), "updated_at": state.get("updated_at"),
        }

    def _write_views(self, state: dict[str, Any]) -> None:
        jobs = list(state.get("jobs", {}).values())
        current = [j for j in jobs if j.get("state") == "active"]
        todo = [j for j in jobs if j.get("state") == "queued"]
        done = [j for j in jobs if j.get("state") in {"completed", "failed", "cancelled", "dead"}]
        atomic_json(self.data_dir / "status.json", {
            "schema": SCHEMA, "revision": state.get("revision", 0),
            "worker_count": len(state.get("workers", {})),
            "job_counts": {name: sum(j.get("state") == name for j in jobs) for name in ("queued", "active", "completed", "failed", "cancelled", "dead")},
        })
        self._write_markdown(self.data_dir / "CURRENT.md", "Current", current)
        self._write_markdown(self.data_dir / "TO-DO.md", "Queued", todo)
        self._write_markdown(self.data_dir / "DONE.md", "Terminal", done)
        status = f"schema={SCHEMA}\nrevision={state.get('revision', 0)}\nworkers={len(state.get('workers', {}))}\njobs={len(jobs)}\n"
        atomic_text(self.data_dir / "status.txt", status)

    @staticmethod
    def _write_markdown(path: Path, title: str, jobs: list[dict[str, Any]]) -> None:
        lines = [f"# {title}", ""]
        lines.extend(f"- `{job['id']}` — {job['name']} — {job['state']}" for job in jobs)
        if not jobs:
            lines.append("No jobs in this state.")
        lines.append("")
        atomic_text(path, "\n".join(lines))
