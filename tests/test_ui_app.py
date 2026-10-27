"""Streamlit smoke tests. Synthetic UI fixture only; no claimed model results."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("streamlit") is None, reason="Streamlit not installed"
)
APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_empty_console_and_demo(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    app = AppTest.from_file(APP)
    app.session_state["workspace_route"] = "Analysis console"
    app.run(timeout=30)
    assert not app.exception
    assert any("StegoLens" in title.value for title in app.title)
    assert app.button[0].disabled
    app.sidebar.radio[0].set_value("Demo & evaluation").run(timeout=30)
    assert not app.exception
    assert any("Known trigger" in text.value for text in app.markdown)


def test_populated_report_tabs_and_features(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    report = {
        "schema_version": "1.0",
        "scan_id": str(uuid4()),
        "created_at": "2026-10-26T00:00:00Z",
        "artifact": {"original_name": "SYNTHETIC UI TEST ONLY", "format": "safetensors", "size_bytes": 1024},
        "runtime": {"device": "cpu"},
        "status": "partial",
        "verdict": "REVIEW — INDICATORS REQUIRE INVESTIGATION",
        "summary": {
            "static_finding_count": 0,
            "heuristic_window_count": 0,
            "ml_positive_window_count": 1,
            "analyzed_window_count": 1,
        },
        "intake": {"tensors": [{"name": "test.weight", "dtype": "F32", "shape": [256], "numel": 256}]},
        "weight_analysis": {
            "status": "partial",
            "coverage": {"sampled_elements": 256},
            "windows": [
                {
                    "tensor": "test.weight",
                    "window_index": 0,
                    "element_start": 0,
                    "element_count": 256,
                    "anomaly_score": 0.1,
                    "features": {"entropy": 0.7, "bit_0_entropy": 0.9},
                    "evidence": [],
                }
            ],
        },
        "static_analysis": {"status": "unavailable", "warnings": ["Optional engine missing"]},
        "ml_analysis": {"status": "not_available"},
        "reference_analysis": {"status": "not_available"},
        "behavioral_analysis": {"status": "not_available"},
        "limitations": ["UI fixture, not model evidence"],
    }
    app = AppTest.from_file(APP)
    app.session_state["dashboard_technical"] = True
    app.session_state["active_report"] = report
    app.run(timeout=30)
    assert not app.exception
    assert len(app.tabs) == 10
    assert any("REVIEW" in warning.value for warning in app.warning)
    assert len(app.metric) >= 4
    app.text_input[0].set_value("test").run(timeout=30)
    assert not app.exception
    assert any("No detector outputs" in caption.value for caption in app.caption)


def test_compatibility_and_empty_comparison_routes(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.radio[0].set_value("Compatibility & scope").run(timeout=30)
    assert not app.exception
    assert any("Architecture-agnostic" in text.value for text in app.markdown)
    app.sidebar.radio[0].set_value("Compare reports").run(timeout=30)
    assert not app.exception
    assert any("at least two" in text.value for text in app.info)


def test_comparison_with_recorded_features(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from stegogate import storage

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    identifiers = [str(uuid4()), str(uuid4())]
    reports = {
        identifier: {
            "scan_id": identifier,
            "artifact": {"original_name": f"test-{index}", "size_bytes": 100, "format": "safetensors"},
            "status": "partial",
            "weight_analysis": {
                "windows": [
                    {
                        "tensor": "w",
                        "window_index": i,
                        "features": {"low_byte_entropy": 6 + i / 10 + index / 10},
                    }
                    for i in range(4)
                ]
            },
        }
        for index, identifier in enumerate(identifiers)
    }
    monkeypatch.setattr(storage, "list_reports", lambda: list(reports.values()))
    monkeypatch.setattr(storage, "load_report", lambda identifier: reports[identifier])
    app = AppTest.from_file(APP).run(timeout=30)
    app.sidebar.radio[0].set_value("Compare reports").run(timeout=30)
    assert not app.exception
    assert len(app.get("plotly_chart")) == 1
    assert any("own finite sampled-window denominator" in text.value for text in app.caption)


def test_simple_reference_metric_fits_and_keeps_exact_denominator(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
    app.session_state["active_report"] = {
        "status": "partial", "verdict": "REVIEW — INDICATORS REQUIRE INVESTIGATION",
        "artifact": {"original_name": "SYNTHETIC QA", "size_bytes": 10000},
        "reference_analysis": {"status": "partial", "summary": {
            "differing_sampled_bytes": 20, "compared_bytes": 80}},
    }
    app.run(timeout=15)
    assert not app.exception
    assert next(metric.value for metric in app.metric if metric.label == "Change from reference") == "25.00% changed"
    assert any("20 changed / 80 compared bytes" in caption.value for caption in app.caption)
