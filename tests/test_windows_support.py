"""Portable contract tests plus actual Win32 and PowerShell regression cases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import numpy as np
import pytest
from safetensors.numpy import save_file

from stegogate import platform_support as host
from stegogate.intake import _open_regular, inspect_artifact
from stegogate.pipeline import scan_artifact

WINDOWS = sys.platform == "win32"
WIN = pytest.mark.skipif(not WINDOWS, reason="Actual native Windows adapter")


@pytest.mark.parametrize("name,eligible", [("win32", False), ("linux", True), ("darwin", False)])
def test_platform_capabilities_are_explicit(monkeypatch, name, eligible):
    monkeypatch.setattr(host.sys, "platform", name)
    value = host.capabilities()
    assert value["native_analysis"] is True
    assert value["linux_isolation_eligible"] is eligible
    if not eligible:
        assert "No unsandboxed fallback" in value["note"]


def test_pipeline_import_does_not_require_resource():
    script = """
import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == 'resource':
        raise ImportError('resource intentionally unavailable')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from stegogate.pipeline import scan_artifact
assert callable(scan_artifact)
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value", [True, -1, float("inf"), float("nan"), "123"])
def test_invalid_memory_measurements_not_fabricated(value):
    with pytest.raises(ValueError):
        host._mib(value, 1024)


@pytest.mark.parametrize("name,value,expected", [("linux", 2048, 2.0), ("darwin", 2097152, 2.0)])
def test_unix_memory_units(monkeypatch, name, value, expected):
    monkeypatch.setattr(host.sys, "platform", name)
    monkeypatch.setitem(
        sys.modules,
        "resource",
        SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda _: SimpleNamespace(ru_maxrss=value)),
    )
    result = host.memory_snapshot()
    assert result["peak_rss_mb"] == expected and result["peak_rss_unit"] == "MiB"
    assert result["rss_source"] == "resource.ru_maxrss"


def test_windows_memory_uses_peak_working_set_bytes(monkeypatch):
    monkeypatch.setattr(host.sys, "platform", "win32")
    monkeypatch.setitem(
        sys.modules,
        "psutil",
        SimpleNamespace(
            Process=lambda: SimpleNamespace(memory_info=lambda: SimpleNamespace(peak_wset=3145728))
        ),
    )
    result = host.memory_snapshot()
    assert result["peak_rss_mb"] == 3.0 and result["peak_rss_unit"] == "MiB"
    assert result["rss_source"] == "psutil.peak_wset"
    assert "not isolated" in result["rss_scope"]


def test_missing_memory_stays_null(monkeypatch):
    monkeypatch.setattr(host.sys, "platform", "win32")
    monkeypatch.setitem(
        sys.modules,
        "psutil",
        SimpleNamespace(Process=lambda: SimpleNamespace(memory_info=lambda: SimpleNamespace(rss=100))),
    )
    result = host.memory_snapshot()
    assert result["peak_rss_mb"] is None
    assert result["rss_source"] == "unavailable"


def test_binary_intake_preserves_control_bytes(tmp_path):
    payload = b"\r\n\x1a\x00\xff\x80" * 100
    path = tmp_path / "binary.bin"
    path.write_bytes(payload)
    with _open_regular(path) as stream:
        assert stream.read() == payload
    assert inspect_artifact(path)["sha256"] == hashlib.sha256(payload).hexdigest()


def test_native_scan_reference_save_and_pdf(tmp_path, monkeypatch):
    from stegogate import storage
    from stegogate.pdf_report import build_pdf
    from stegogate.explanation import offline_explanation

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path / "state"))
    original = tmp_path / "original.safetensors"
    changed = tmp_path / "changed.safetensors"
    values = np.random.default_rng(42).normal(size=512).astype("float32")
    save_file({"weight": values}, original)
    save_file({"weight": values + np.float32(0.01)}, changed)
    report = scan_artifact(changed, original, {"run_static": False})
    assert not report["intake"]["errors"]
    assert report["weight_analysis"]["windows"]
    assert report["reference_analysis"]["summary"]["differing_sampled_bytes"] > 0
    assert report["runtime"]["peak_rss_unit"] == "MiB"
    assert report["status"] == "partial"  # Missing detector/static is not a pass.
    storage.save_report(report)
    assert storage.load_report(report["scan_id"]) == report
    with pytest.raises(FileExistsError):
        storage.save_report(report)
    assert build_pdf(report, offline_explanation(report)).startswith(b"%PDF-")
    json.dumps(report, allow_nan=False)


@WIN
def test_windows_scanners_fail_closed_without_launch(tmp_path, monkeypatch):
    from stegogate import static_scan, picklescan_scan

    def forbidden(*args, **kwargs):
        pytest.fail("Windows must not start an unsandboxed Linux scanner")

    monkeypatch.setattr(static_scan, "_run_bounded", forbidden)
    monkeypatch.setattr(picklescan_scan, "_run_bounded", forbidden)
    path = tmp_path / "inert.pkl"
    path.write_bytes(b"\x80\x02N.")
    for result in (static_scan.run_modelaudit(path), picklescan_scan.run_picklescan(path)):
        assert result["status"] == "unavailable" and result["findings"] == []
        assert "Linux" in " ".join(result["warnings"])
    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path / "state"))
    report = scan_artifact(path)
    assert report["status"] == "partial"
    assert report["static_analysis"]["status"] == "unavailable"


@WIN
def test_windows_demo_refuses_before_download_or_worker(tmp_path, monkeypatch):
    from stegogate import demo

    def forbidden(*args, **kwargs):
        pytest.fail("Unavailable demo must not download or launch")

    monkeypatch.setattr(demo, "_download", forbidden)
    monkeypatch.setattr(demo, "_run_bounded", forbidden)
    for result in (
        demo.prepare_demo("mnist-epoch02", tmp_path, {"opt_in": True}),
        demo.verify_behavior("mnist-epoch02", tmp_path, {"opt_in": True}),
    ):
        assert result["status"] == "unavailable"
    assert not list(tmp_path.iterdir())


@WIN
@pytest.mark.parametrize("path", [r"\\server\share\file", r"\\.\NUL", r"\\?\C:\test", "NUL"])
def test_windows_devices_and_unc_rejected(path):
    with pytest.raises((OSError, ValueError)):
        with _open_regular(path):
            pytest.fail("Device/UNC input opened")


@WIN
def test_windows_alternate_stream_rejected(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"original")
    with pytest.raises(ValueError, match="Alternate"):
        _open_regular(str(path) + ":stream")


@WIN
def test_windows_handle_denies_concurrent_write_and_closes(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"original")
    with _open_regular(path) as stream:
        assert stream.read() == b"original"
        with pytest.raises(PermissionError):
            path.write_bytes(b"replaced")
    path.write_bytes(b"after-close")


@WIN
def test_windows_parent_junction_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "x").write_bytes(b"bytes")
    alias = tmp_path / "junction"
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(target)], capture_output=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(ValueError, match="reparse"):
            _open_regular(alias / "x")
    finally:
        alias.rmdir()


@WIN
def test_windows_storage_default_outside_project(tmp_path, monkeypatch):
    from stegogate.storage import data_root

    monkeypatch.delenv("STEGOGATE_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert data_root() == (tmp_path / "T04-Scnr" / "runtime").resolve()


@WIN
def test_powershell_launcher_check_and_invalid_port(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(root / "scripts/run_dashboard.ps1"),
        "-Check",
    ]
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("STEGOGATE_PORT", "8501")
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["capabilities"]["platform"] == "win32"
    assert value["groq"] == {"key_configured": False}
    monkeypatch.setenv("STEGOGATE_PORT", "8501; anything")
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0


@WIN
def test_windows_ui_shows_isolation_limits(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
    app.session_state["workspace_route"] = "Analysis console"
    app.run(timeout=30)
    assert not app.exception
    static = next(c for c in app.checkbox if c.label == "Run optional ModelAudit static engine")
    assert static.disabled and static.value is False
    assert any("No unsandboxed fallback" in item.value for item in app.info)
