"""Parent integration controls; no authenticated provider requests."""

import copy
from pathlib import Path
from uuid import uuid4
import pytest
import sys


def sample():
    return dict(
        scan_id=str(uuid4()),
        status="partial",
        verdict="NO INDICATORS FOUND — LIMITED ANALYSIS",
        artifact=dict(original_name="SYNTHETIC INTEGRATION FIXTURE", format="safetensors", size_bytes=100),
        summary=dict(analyzed_window_count=0),
        weight_analysis=dict(status="unsupported", windows=[]),
    )


def test_offline_cache_stable_and_report_scoped():
    from stegogate.assistant_ui import current_interpretation

    r = sample()
    state = {}
    a = current_interpretation(r, state)
    b = current_interpretation(r, state)
    assert a == b
    r2 = copy.deepcopy(r)
    r2["status"] = "rejected"
    c = current_interpretation(r2, state)
    assert c["report_sha256"] != a["report_sha256"]


def test_no_unrelated_groq_result_in_pdf_selection():
    from stegogate.assistant_ui import current_interpretation
    from stegogate.explanation import PROMPT_VERSION, report_digest
    import time

    r = sample()
    d = report_digest(r)
    state = {
        "sg_mode_" + d: "Groq · explicit cloud request",
        "sg_model_" + d: "openai/gpt-oss-20b",
        "sg_explanations": {
            ("wronghash", "openai/gpt-oss-20b", PROMPT_VERSION): dict(
                created=time.time(), result={"status": "completed", "mode": "groq"}
            )
        },
    }
    assert current_interpretation(r, state)["mode"] == "offline"


def test_session_cache_bound_and_expiry():
    from stegogate.assistant_ui import _bounded_cache
    import time

    state = {"c": {str(i): dict(created=time.time(), result={}) for i in range(20)}}
    state["c"]["old"] = {"created": 0}
    assert len(_bounded_cache(state, "c", 3)) == 3
    assert "old" not in state["c"]


def test_cli_offline_pdf_never_calls_groq(tmp_path, monkeypatch):
    from stegogate.cli import main
    from stegogate import storage, explanation

    r = sample()
    monkeypatch.setattr(storage, "load_report", lambda scan_id: r)
    monkeypatch.setattr(explanation, "explain_with_groq", lambda *a, **kw: pytest.fail("cloud request"))
    target = tmp_path / "report.pdf"
    assert main(["report-pdf", r["scan_id"], "--output", str(target), "--offline-appendix"]) == 0
    assert target.read_bytes().startswith(b"%PDF-")
    assert main(["report-pdf", r["scan_id"], "--output", str(target)]) == 2


def test_cli_groq_without_consent_never_requests(tmp_path, monkeypatch, capsys):
    from stegogate.cli import main
    from stegogate import storage, explanation

    r = sample()
    monkeypatch.setattr(storage, "load_report", lambda scan_id: r)
    monkeypatch.setenv("GROQ_API_KEY", "synthetic-key-not-real")
    monkeypatch.setattr(explanation, "_transport", lambda *a, **kw: pytest.fail("no consent"))
    assert main(["explain", r["scan_id"], "--groq"]) == 2
    assert "synthetic-key-not-real" not in capsys.readouterr().out


def test_render_no_automatic_provider_calls(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from stegogate import explanation

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GROQ_API_KEY", "synthetic-key-not-real")
    monkeypatch.setattr(explanation, "_transport", lambda *a, **kw: pytest.fail("render made request"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
    app.session_state["active_report"] = sample()
    app.run(timeout=30)
    assert not app.exception
    assert len(app.tabs) == 10
    # Radio control exists in rendered tab even before it is selected visually.
    mode = next(r for r in app.radio if r.label == "Explanation mode")
    mode.set_value("Groq · explicit cloud request").run(timeout=30)
    assert not app.exception
    generate = next(b for b in app.button if b.label == "Generate Groq interpretation")
    assert generate.disabled
    pdf_button = next(b for b in app.button if b.label == "Prepare detailed PDF")
    pdf_button.click().run(timeout=30)
    assert not app.exception
    assert any(x.label == "↓ Detailed PDF report" for x in app.get("download_button"))


@pytest.mark.parametrize(
    "mode,symlink,expected",
    [(0o600, False, True), (0o400, False, True), (0o644, False, False), (0o600, True, False)],
)
@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only adapter or Bash launcher")
def test_launcher_private_file_only(tmp_path, mode, symlink, expected):
    import os
    import shutil
    import subprocess

    project = tmp_path / "project"
    (project / "scripts").mkdir(parents=True)
    (project / ".venv/bin").mkdir(parents=True)
    launcher = project / "scripts/run_dashboard.sh"
    shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/run_dashboard.sh", launcher)
    fake = project / ".venv/bin/python"
    fake.write_text('#!/bin/sh\nif [ -n "${GROQ_API_KEY:-}" ]; then echo configured; else echo offline; fi\n')
    fake.chmod(0o700)
    home = tmp_path / "home"
    directory = home / ".config/stegogate"
    directory.mkdir(parents=True)
    key = directory / "groq.key"
    # Shell syntax is literal credential content, never evaluated by launcher.
    marker = tmp_path / "executed"
    payload = "$(touch " + str(marker) + ")"
    if symlink:
        target = directory / "real"
        target.write_text(payload)
        target.chmod(mode)
        key.symlink_to(target)
    else:
        key.write_text(payload)
        key.chmod(mode)
    env = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
    env["HOME"] = str(home)
    result = subprocess.run(["/bin/sh", str(launcher)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("configured" if expected else "offline")
    assert payload not in result.stdout + result.stderr
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only adapter or Bash launcher")
def test_launcher_oversized_key_file_ignored(tmp_path):
    import os
    import shutil
    import subprocess

    project = tmp_path / "project"
    (project / "scripts").mkdir(parents=True)
    (project / ".venv/bin").mkdir(parents=True)
    launcher = project / "scripts/run_dashboard.sh"
    shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/run_dashboard.sh", launcher)
    fake = project / ".venv/bin/python"
    fake.write_text('#!/bin/sh\n[ -z "${GROQ_API_KEY:-}" ]\n')
    fake.chmod(0o700)
    home = tmp_path / "home"
    directory = home / ".config/stegogate"
    directory.mkdir(parents=True)
    key = directory / "groq.key"
    key.write_text("x" * 1025)
    key.chmod(0o600)
    env = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
    env["HOME"] = str(home)
    result = subprocess.run(["/bin/sh", str(launcher)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert "ignored" in result.stderr


def test_oversized_assistant_budget_does_not_break_report_view(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from stegogate import explanation

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))

    def over_budget(*a, **kw):
        raise ValueError("synthetic input budget failure")

    monkeypatch.setattr(explanation, "offline_explanation", over_budget)
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
    app.session_state["active_report"] = sample()
    app.run(timeout=30)
    assert not app.exception
    assert any("Evidence Assistant unavailable" in x.value for x in app.warning)
    appendix = next(
        c
        for c in app.checkbox
        if c.label == "Include the currently selected interpretation as a separate appendix"
    )
    appendix.check().run(timeout=30)
    assert not app.exception
    assert any("appendix unavailable" in x.value for x in app.warning)
