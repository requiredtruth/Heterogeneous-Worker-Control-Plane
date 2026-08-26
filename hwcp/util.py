"""Small bounded helpers shared by the hub and worker."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class HWCPError(RuntimeError):
    """A bounded operational or validation error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_arch(value: str | None = None) -> str:
    """Normalize common machine spellings into x86_64, arm64, armv7, or unknown."""
    raw = (value or platform.machine()).strip().lower()
    if raw in {"x86_64", "amd64"}:
        return "x86_64"
    if raw in {"aarch64", "arm64"}:
        return "arm64"
    if raw.startswith("armv7") or raw == "arm":
        return "armv7"
    return "unknown"


def valid_id(value: Any, label: str) -> str:
    value = str(value or "")
    if not ID_RE.fullmatch(value):
        raise HWCPError(f"{label} must match {ID_RE.pattern}")
    return value


def valid_sha(value: Any) -> str:
    value = str(value or "")
    if not SHA_RE.fullmatch(value):
        raise HWCPError("sha256 must contain exactly 64 lowercase hexadecimal characters")
    return value


def safe_relative(value: Any) -> str:
    """Return a normalized relative POSIX path that cannot escape a workspace."""
    raw = str(value or "")
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "\x00" in raw:
        raise HWCPError("artifact path must be a non-empty relative path without '..'")
    normalized = path.as_posix()
    if normalized.startswith(".hwcp/") or normalized == ".hwcp":
        raise HWCPError("artifact path may not use the reserved .hwcp directory")
    return normalized


def bounded_json(data: bytes, limit: int = 1_048_576) -> Any:
    if len(data) > limit:
        raise HWCPError(f"JSON body exceeds {limit} bytes")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HWCPError("request body must be valid UTF-8 JSON") from exc


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_text(path: Path, value: str) -> None:
    """Publish a small UTF-8 state view without exposing a partial write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def sha256_stream(handle: BinaryIO, output: BinaryIO | None = None, chunk_size: int = 1_048_576) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest(), total


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
