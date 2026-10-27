"""Orchestrator tests: policy, safe storage and malformed pipeline paths."""

import io
import json
import pytest
from stegogate.schemas import ScanConfig
from stegogate import storage


def test_limits_reject_unbounded_config():
    with pytest.raises(ValueError):
        ScanConfig(max_windows=1000000)
    with pytest.raises(ValueError):
        ScanConfig(unknown_field=True)


def test_upload_does_not_use_untrusted_filename(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    path = storage.stage_upload(io.BytesIO(b"abc"), "../../outside.py")
    assert path.parent == tmp_path / "uploads"
    assert path.read_bytes() == b"abc"
    assert not (tmp_path.parent / "outside.py").exists()


def test_upload_limit_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(storage, "MAX_UPLOAD_BYTES", 3)
    with pytest.raises(ValueError):
        storage.stage_upload(io.BytesIO(b"abcd"), "a")
    assert not list((tmp_path / "uploads").iterdir())


def test_report_path_traversal_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        storage.load_report("../../etc/passwd")


def test_pipeline_invalid_artifact_cannot_pass(tmp_path, monkeypatch):
    from stegogate.pipeline import scan_artifact

    path = tmp_path / "broken.safetensors"
    path.write_bytes((10).to_bytes(8, "little") + b"not json!!")
    report = scan_artifact(path, config={"run_static": False})
    assert report["status"] == "rejected"
    assert report["weight_analysis"]["status"] == "not_performed"
    assert report["behavioral_analysis"]["status"] == "not_performed"
    assert report["runtime"]["device"] == "cpu"
    json.dumps(report, allow_nan=False)


def test_real_safetensors_static_disabled(tmp_path, monkeypatch):
    import numpy as np
    from safetensors.numpy import save_file
    from stegogate.pipeline import scan_artifact

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path / "state"))
    path = tmp_path / "fixture.safetensors"
    save_file({"weight": np.random.default_rng(3).normal(size=(128, 128)).astype("float32")}, path)
    report = scan_artifact(path, config={"run_static": False})
    assert report["intake"]["format"] == "safetensors"
    assert report["weight_analysis"]["windows"]
    assert report["ml_analysis"]["status"] == "not_available"
    assert "TRUSTED" not in report["verdict"]
    target = storage.save_report(report)
    assert target.exists()
    assert storage.load_report(report["scan_id"]) == report
    with pytest.raises(FileExistsError):
        storage.save_report(report)
    assert storage.list_reports()[0]["scan_id"] == report["scan_id"]


def test_learned_positive_requires_review_even_without_heuristics(tmp_path, monkeypatch):
    import numpy as np
    from safetensors.numpy import save_file
    from stegogate.pipeline import scan_artifact
    from stegogate import features, ml

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path / "state"))
    path = tmp_path / "fixture.safetensors"
    save_file({"weight": np.ones(64, dtype="float32")}, path)
    monkeypatch.setattr(
        features,
        "analyze_weights",
        lambda *args: {
            "status": "completed",
            "windows": [{"evidence": []}],
            "tensor_summaries": [],
            "coverage": {},
            "warnings": [],
        },
    )
    monkeypatch.setattr(
        ml,
        "score_windows",
        lambda *args, **kwargs: {
            "status": "completed",
            "scores": [{"predicted_label": 1, "score": 0.8, "threshold": 0.5}],
            "manifest": {},
            "warnings": [],
        },
    )
    report = scan_artifact(path, config={"run_static": False})
    assert report["summary"]["heuristic_window_count"] == 0
    assert report["summary"]["ml_positive_window_count"] == 1
    assert report["verdict"].startswith("REVIEW")
    assert report["status"] == "partial"
