"""Synthetic recorded-evidence fixtures; no artifact scanning or transport."""

from copy import deepcopy
import json

import pytest

from stegogate.evidence_explorer import build_evidence_maps, _figure


def fixture():
    return {
        "artifact": {"original_name": "fixture.safetensors", "sha256": "a" * 64},
        "summary": {"tensor_count": 2},
        "intake": {
            "tensors": [
                {"name": "a", "dtype": "F32", "numel": 1000, "nbytes": 4000},
                {"name": "b", "dtype": "BF16", "numel": 500, "nbytes": 1000},
            ]
        },
        "weight_analysis": {
            "status": "partial",
            "coverage": {"max_windows": 8, "window_elements": 100},
            "tensor_summaries": [
                {
                    "tensor": "a",
                    "numel": 1000,
                    "sampled_elements": 100,
                    "status": "partial",
                    "reason": "bounded sample",
                }
            ],
            "windows": [{"tensor": "a", "window_index": 0, "element_start": 750, "element_count": 100}],
        },
        "reference_analysis": {
            "status": "partial",
            "tensors": [
                {
                    "tensor": "a",
                    "status": "sampled_differences",
                    "nbytes": 4000,
                    "compared_bytes": 200,
                    "differing_sampled_bytes": 5,
                }
            ],
        },
    }


def test_scoped_ratios_positions_and_missing_rows():
    result = build_evidence_maps(fixture())
    a, b = result["tensors"]
    assert a["sampled_fraction"] == 0.1
    assert a["unexamined_elements"] == 900
    assert a["reference_fraction"] == 0.05
    assert a["changed_fraction"] == 0.025
    assert a["windows"] == [{"window_index": 0, "element_start": 750, "element_count": 100}]
    assert a["reference_status"] == "sampled_differences"
    assert result["reference_status"] == "partial"
    assert b["sampled_elements"] is None and b["compared_bytes"] is None
    assert b["changed_fraction"] is None
    assert result["counts"]["declared_inventory_total"] == 2


@pytest.mark.parametrize(
    "value", [None, {}, [], True, False, -1, float("nan"), float("inf"), 10**1000, "100"]
)
def test_invalid_counts_never_become_ratios(value):
    report = fixture()
    report["weight_analysis"]["tensor_summaries"][0]["sampled_elements"] = value
    report["reference_analysis"]["tensors"][0]["compared_bytes"] = value
    row = build_evidence_maps(report)["tensors"][0]
    assert row["sampled_fraction"] is None
    assert row["changed_fraction"] is None
    assert row["reference_fraction"] is None


@pytest.mark.parametrize("population", [0, -1, True, None, 10**1000, 199, 5000])
def test_invalid_reference_population(population):
    report = fixture()
    report["reference_analysis"]["tensors"][0]["nbytes"] = population
    row = build_evidence_maps(report)["tensors"][0]
    assert row["reference_fraction"] is None
    # A conflicting population must not support any numeric map.
    assert row["changed_fraction"] is None


def test_bounds_and_no_inventory_inference():
    report = fixture()
    report["intake"]["tensors"] = [{"name": f"t{i}"} for i in range(200)]
    report["weight_analysis"]["tensor_summaries"] = [{"tensor": "not_inventory", "numel": 100}]
    report["weight_analysis"]["windows"] = [{"tensor": "t0", "window_index": i} for i in range(500)]
    result = build_evidence_maps(report)
    assert len(result["tensors"]) == 128
    assert result["counts"]["recorded_inventory_rows"] == 200
    assert result["counts"]["recorded_windows"] == 500
    assert result["counts"]["displayed_windows"] == 256
    assert all(r["name"] != "not_inventory" for r in result["tensors"])
    assert build_evidence_maps({"reference_analysis": report["reference_analysis"]})["tensors"] == []


@pytest.mark.parametrize(
    "report",
    [
        {},
        None,
        [],
        {"intake": False, "weight_analysis": [1]},
        {"intake": {"tensors": [None, {}, {"name": []}]}},
    ],
)
def test_missing_or_invalid_sections(report):
    assert build_evidence_maps(report)["tensors"] == []


def test_input_not_mutated_and_output_detached():
    report = fixture()
    before = deepcopy(report)
    result = build_evidence_maps(report)
    assert report == before
    result["tensors"][0]["windows"][0]["element_start"] = 2
    result["counts"]["declared_inventory_total"] = 99
    assert report == before


def test_control_characters_and_plotly_markup_are_safe():
    report = fixture()
    report["intake"]["tensors"][0]["name"] = "<script>alert(1)</script>\x00\n\u202e" + "x" * 200
    result = build_evidence_maps(report)
    name = result["tensors"][0]["name"]
    assert len(name) <= 100 and "\x00" not in name and "\n" not in name and "\u202e" not in name
    figure = _figure(result["tensors"], "Inventory")
    assert "<script>" not in json.dumps(figure.to_plotly_json())
    assert "&lt;script&gt;" in figure.data[0].y[0]


def test_over_one_weight_and_changed_ratio_are_unknown():
    report = fixture()
    report["weight_analysis"]["tensor_summaries"][0]["sampled_elements"] = 1001
    report["reference_analysis"]["tensors"][0]["differing_sampled_bytes"] = 201
    row = build_evidence_maps(report)["tensors"][0]
    assert row["sampled_fraction"] is None and row["changed_fraction"] is None


def test_zero_changes_are_not_missing_or_safe():
    report = fixture()
    report["reference_analysis"]["tensors"][0]["differing_sampled_bytes"] = 0
    row = build_evidence_maps(report)["tensors"][0]
    assert row["changed_fraction"] == 0
    assert row["reference_fraction"] == 0.05


def test_renderer_empty_and_selectable_without_transport(monkeypatch):
    from streamlit.testing.v1 import AppTest
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Evidence renderer attempted transport")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    script = "from stegogate.evidence_explorer import render_evidence_explorer\nrender_evidence_explorer({})"
    empty = AppTest.from_string(script).run(timeout=15)
    assert not empty.exception
    assert any("No recorded tensor" in element.value for element in empty.info)
    script = (
        "from stegogate.evidence_explorer import render_evidence_explorer\n"
        f"render_evidence_explorer({fixture()!r})"
    )
    app = AppTest.from_string(script).run(timeout=15)
    assert not app.exception
    app.selectbox(key="evidence_explorer_tensor").set_value(1).run(timeout=15)
    assert not app.exception
    assert any("Tensor 2: b" in element.value for element in app.text)
    for mode in ("Weight coverage", "Reference changes"):
        app.radio[0].set_value(mode).run(timeout=15)
        assert not app.exception
    text = " ".join(element.value for element in app.text)
    assert "not proof of safety" in text
    assert "What remains unknown" in " ".join(element.value for element in app.markdown)


@pytest.mark.parametrize(
    "section,field",
    [("intake", "tensors"), ("weight_analysis", "tensor_summaries"), ("reference_analysis", "tensors")],
)
def test_duplicate_identity_does_not_silently_override(section, field):
    report = fixture()
    report[section][field].append(deepcopy(report[section][field][0]))
    row = build_evidence_maps(report)["tensors"][0]
    assert row["ambiguity"]
    if section in ("intake", "weight_analysis"):
        assert row["sampled_fraction"] is None
    if section in ("intake", "reference_analysis"):
        assert row["changed_fraction"] is None
