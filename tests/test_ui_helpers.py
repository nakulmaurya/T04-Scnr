"""Presentation security and evidence semantics; fixtures are not model measurements."""

import json
from uuid import uuid4

import pytest

from stegogate.ui_helpers import (
    bitplane_points,
    coverage_rows,
    demo_documents,
    export_html,
    export_json,
    feature_points,
    finite_number,
    human_bytes,
    numeric_feature_names,
    report_summary,
    safe_local_json,
    tensor_rows,
    valid_report_id,
    window_rows,
)


@pytest.fixture
def report():
    return {
        "scan_id": str(uuid4()),
        "created_at": "2026-10-26T00:00:00Z",
        "artifact": {
            "original_name": "<script>alert(1)</script>",
            "size_bytes": 1024,
            "sha256": "abc",
            "format": "safetensors",
        },
        "intake": {"tensors": [{"name": "layer.weight", "dtype": "F32", "shape": [4], "numel": 4}]},
        "weight_analysis": {
            "status": "partial",
            "windows": [
                {
                    "tensor": "layer.weight",
                    "window_index": 0,
                    "features": {"entropy": 0.5, "bit_0_entropy": 1.0},
                },
                {"tensor": "other.weight", "window_index": 1, "features": {"entropy": float("nan")}},
                {"tensor": "layer.weight", "window_index": 2, "features": {"bit_0_entropy": 0.0}},
            ],
        },
        "static_analysis": {"status": "unavailable"},
        "limitations": ["<img src=x onerror=alert(1)>"],
    }


def test_uuid_validation_rejects_paths_and_alternate_spellings():
    identifier = str(uuid4())
    assert valid_report_id(identifier)
    for bad in (
        "../report",
        "/tmp/report",
        identifier.replace("-", ""),
        identifier.upper(),
        "",
        None,
        {},
        "not-a-uuid",
    ):
        assert not valid_report_id(bad)


def test_unknown_status_not_clean(report):
    rows = coverage_rows(report)
    assert next(r for r in rows if r["Analysis layer"] == "ModelAudit static scan")["Status"] == "unavailable"
    assert next(r for r in rows if r["Analysis layer"] == "Reference comparison")["Status"] == "not_available"
    assert coverage_rows({})[0]["Status"] == "not_available"


def test_window_scope_and_missing_not_imputed(report):
    windows = window_rows(report)
    assert len(window_rows(report, "layer.weight")) == 2
    assert numeric_feature_names(windows) == ["bit_0_entropy", "entropy"]
    points = feature_points(windows, "entropy")
    assert len(points) == 1
    assert points[0]["Value"] == 0.5
    assert feature_points(windows, "absent") == []


def test_bitplanes_only_explicit_finite_values():
    rows = bitplane_points(
        {
            "bit_0_entropy": 0.0,
            "bitplane_7_bias": 0.2,
            "bit_8_entropy": 9,
            "entropy": 3,
            "lsb_1_bias": float("inf"),
        }
    )
    assert len(rows) == 2
    assert {r["Plane"] for r in rows} == {0, 7}
    assert any(r["Value"] == 0 for r in rows)


def test_export_is_offline_escaped_and_complete(report):
    report["weight_analysis"]["windows"][1]["features"]["entropy"] = None
    output = export_html(report)
    assert "<script>" not in output
    assert "<img src=x" not in output
    assert "&lt;script&gt;" in output
    assert "&lt;img src=x" in output
    assert "default-src" in output
    assert "Complete report" in output
    assert "NOT a malware" not in output  # no misleading scoring promises
    assert json.loads(export_json(report))["artifact"]["original_name"] == "<script>alert(1)</script>"


def test_nonfinite_export_refused(report):
    with pytest.raises(ValueError):
        export_json(report)


def test_local_json_enforces_root_size_and_shape(tmp_path):
    root = tmp_path / "demo"
    root.mkdir()
    inside = root / "manifest.json"
    inside.write_text('{"status":"unverified"}')
    assert safe_local_json(root, inside)["status"] == "unverified"
    outside = tmp_path / "secret.json"
    outside.write_text('{"secret":true}')
    with pytest.raises(ValueError):
        safe_local_json(root, outside)
    link = root / "linked.json"
    link.symlink_to(outside)
    with pytest.raises(ValueError):
        safe_local_json(root, link)
    with pytest.raises(ValueError):
        safe_local_json(root, inside, max_bytes=2)
    bad = root / "list.json"
    bad.write_text("[]")
    with pytest.raises(ValueError):
        safe_local_json(root, bad)
    assert len(demo_documents(root)) == 1


def test_summary_and_inventory_do_not_create_measurements(report):
    summary = report_summary(report)
    assert summary["Reported windows"] == 3
    assert summary["Inventoried tensors"] == 1
    assert summary["Scan status"] == "not_available"
    assert tensor_rows({}) == []
    assert human_bytes(None) == "Not available"
    assert human_bytes(1024) == "1.0 KiB"
    assert not finite_number(True)
    assert not finite_number(float("inf"))
