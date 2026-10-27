"""App-owned staging and atomic report persistence. No user-chosen filesystem paths."""

from __future__ import annotations
import io
import json
import os
import tempfile
import sys
from pathlib import Path
from uuid import UUID
from .schemas import ScanReport

MAX_UPLOAD_BYTES = 256 * 1024**2
MAX_REPORT_BYTES = 32 * 1024**2


def data_root() -> Path:
    default = Path.cwd() / "data" / "runtime"
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        default = Path(os.environ["LOCALAPPDATA"]) / "T04-Scnr" / "runtime"
    root = Path(os.environ.get("STEGOGATE_DATA_DIR", str(default))).expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root.resolve()


def _directory(name: str) -> Path:
    folder = data_root() / name
    if folder.is_symlink():
        raise ValueError("App storage directories must not be symlinks")
    folder.mkdir(mode=0o700, exist_ok=True)
    return folder


def _scan_id(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Invalid scan ID")
    return value


def stage_upload(fileobj, original_name: str) -> Path:
    """Copy bounded stream into a random app-owned name; never use uploaded path."""
    stream = io.BytesIO(fileobj) if isinstance(fileobj, bytes) else fileobj
    folder = _directory("uploads")
    fd, name = tempfile.mkstemp(prefix="artifact-", suffix=".bin", dir=folder)
    path = Path(name)
    try:
        total = 0
        with os.fdopen(fd, "wb") as out:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise ValueError("Upload exceeds 256 MiB limit")
                out.write(chunk)
        if total == 0:
            raise ValueError("Empty upload")
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def save_report(report: dict) -> Path:
    validated = ScanReport.model_validate(report).model_dump(mode="json")
    payload = json.dumps(validated, indent=2, allow_nan=False).encode()
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds storage limit")
    folder = _directory("reports")
    target = folder / f"{_scan_id(validated['scan_id'])}.json"
    if target.exists():
        raise FileExistsError("Reports are immutable; ID already exists")
    fd, name = tempfile.mkstemp(prefix=".report-", dir=folder)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        # Hard-link avoids overwriting an existing report during concurrent writers.
        os.link(name, target)
    finally:
        Path(name).unlink(missing_ok=True)
    return target


def load_report(scan_id: str) -> dict:
    path = _directory("reports") / f"{_scan_id(scan_id)}.json"
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("Report not found")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Oversized saved report")
    return ScanReport.model_validate_json(path.read_bytes()).model_dump(mode="json")


def list_reports() -> list[dict]:
    result = []
    for path in sorted(_directory("reports").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[
        :100
    ]:
        try:
            report = load_report(path.stem)
            result.append(
                {key: report[key] for key in ("scan_id", "created_at", "artifact", "status", "verdict")}
            )
        except (OSError, ValueError):
            continue
    return result
