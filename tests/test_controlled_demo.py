"""Controlled-view tests use explicitly synthetic images/predictions, not model evidence."""
import base64
import hashlib
import io
import json
from unittest.mock import Mock

import pytest
from PIL import Image
from streamlit.testing.v1 import AppTest

from stegogate import controlled_demo as controlled

SCRIPT = "from stegogate.controlled_demo import render_controlled_demo\nrender_controlled_demo()"


def png(value=0, trigger=False):
    image = Image.new("L", (28, 28), value)
    if trigger:
        for r in range(24, 27):
            for c in range(24, 27):
                image.putpixel((c, r), 255)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode()


@pytest.fixture
def record():
    # All values below are synthetic validation/UI fixtures, not scientific results.
    return {
        "schema_version": 1, "experiment_id": "SYNTHETIC TEST ONLY",
        "description": "Synthetic fixture, not recorded training evidence", "generated_at": "2026-10-27T00:00:00Z",
        "architecture": "Synthetic architecture description",
        "training": {"seed": 2026, "train_count": 30000, "baseline_epochs": 3, "backdoor_epochs": 3,
                     "poison_fraction": .3, "baseline_description": "Synthetic baseline description",
                     "backdoor_description": "Synthetic backdoor description"},
        "trigger": {"pixels_row_column_0_based": [[r, c] for r in range(24, 27) for c in range(24, 27)],
                    "white_uint8": 255, "target_label": 0},
        "models": {key: {"sha256": hashlib.sha256(key.encode()).hexdigest(), "file": key + ".safetensors"}
                   for key in ("normal", "backdoored")},
        "evaluation": {"test_count": 10000, "target_eligible_count": 9020,
                       "normal": {"normal_correct": 9000, "trigger_target_hits": 12},
                       "backdoored": {"normal_correct": 8800, "trigger_target_hits": 8000}},
        "samples": [{"index": i, "true_label": label, "target_label": 0,
                     "normal_png_base64": png(), "triggered_png_base64": png(trigger=True),
                     "normal_model_normal": label, "normal_model_triggered": label,
                     "backdoor_model_normal": label, "backdoor_model_triggered": 0}
                    for i, label in enumerate(controlled.CANONICAL_LABELS)],
        "limitations": ["Synthetic fixture, not accuracy evidence", "No general safety guarantee"],
    }


def save(tmp_path, record):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(record))
    return path


def test_validated_data_is_immutable(record, tmp_path):
    data = controlled.load_controlled_evidence(save(tmp_path, record))
    assert len(data["samples"]) == 20
    assert data["samples"][0]["normal_png"].startswith(b"\x89PNG")
    assert data["samples"][0]["backdoor_model_triggered"] == 0
    assert data["trigger"]["pixels_row_column_0_based"] == tuple(
        (r, c) for r in range(24, 27) for c in range(24, 27))
    with pytest.raises(TypeError):
        data["samples"][0]["true_label"] = 9


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(schema_version="1"),
    lambda d: d.update(extra="unknown"),
    lambda d: d.update(architecture={"name": "wrong type"}),
    lambda d: d["training"].update(seed=True),
    lambda d: d["training"].update(train_count=60001),
    lambda d: d["training"].update(poison_fraction=float("nan")),
    lambda d: d["training"].update(poison_fraction=0),
    lambda d: d["evaluation"].update(test_count=9999),
    lambda d: d["evaluation"].update(target_eligible_count=10000),
    lambda d: d["evaluation"]["normal"].update(normal_correct=10001),
    lambda d: d["evaluation"]["normal"].update(trigger_target_hits=9021),
    lambda d: d["evaluation"]["normal"].update(trigger_target_hits=True),
    lambda d: d["samples"].pop(),
    lambda d: d["samples"][0].update(index=1),
    lambda d: d["samples"][0].update(true_label=8),
    lambda d: d["samples"][0].update(normal_model_normal=10),
    lambda d: d["samples"][0].update(target_label=1),
    lambda d: d["samples"][0].update(normal_png_base64="not base64"),
    lambda d: d["samples"][0].update(triggered_png_base64=png()),
    lambda d: d["trigger"].update(target_label=1),
    lambda d: d["trigger"].update(white_uint8=True),
    lambda d: d["trigger"].update(pixels_row_column_0_based=[[28, 1]]),
    lambda d: d["trigger"].update(pixels_row_column_0_based=[[1, 1], [1, 1]]),
    lambda d: d["models"]["normal"].update(sha256="made up"),
    lambda d: d["models"]["normal"].update(file="../model.safetensors"),
    lambda d: d["models"]["normal"].update(file="https://example.com/model"),
    lambda d: d.update(limitations=[]),
])
def test_rejects_invalid_schema_bounds_and_trigger(record, tmp_path, mutation):
    mutation(record)
    with pytest.raises(controlled.ControlledEvidenceError):
        controlled.load_controlled_evidence(save(tmp_path, record))


@pytest.mark.parametrize("content", [b"{}", b"[", b"x" * 200001,
                                     b'{"schema_version":1,"schema_version":1}', b"[]"])
def test_invalid_json(tmp_path, content):
    path = tmp_path / "results.json"
    path.write_bytes(content)
    with pytest.raises(controlled.ControlledEvidenceError):
        controlled.load_controlled_evidence(path)


def test_png_dimensions_before_decoder():
    image = Image.new("L", (29, 28))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    with pytest.raises(controlled.ControlledEvidenceError):
        controlled._png(base64.b64encode(buffer.getvalue()).decode())


def test_friendly_missing_record(tmp_path, monkeypatch):
    monkeypatch.setattr(controlled, "RESULTS_PATH", tmp_path / "absent.json")
    ui = AppTest.from_string(SCRIPT).run()
    assert not ui.exception
    assert any("not ready" in item.value for item in ui.warning)
    assert not ui.metric
    assert not ui.selectbox


def test_offline_twenty_sample_ui(record, tmp_path, monkeypatch):
    path = save(tmp_path, record)
    monkeypatch.setattr(controlled, "RESULTS_PATH", path)
    ui = AppTest.from_string(SCRIPT).run()
    assert not ui.exception
    assert len(ui.selectbox(key="controlled_sample").options) == 20
    assert [item.value for item in ui.metric[:2]] == ["7", "7"]
    assert ui.metric[2].value == "90.00%"
    assert ui.metric[3].value == "0.13%"  # 12 / 9020, not / 10000.
    ui.checkbox(key="controlled_trigger").check().run()
    assert not ui.exception
    assert [item.value for item in ui.metric[:2]] == ["7", "0"]
    assert any("Answer changed: 7 → 0" in item.value for item in ui.warning)
    for i in range(20):
        ui.selectbox(key="controlled_sample").select_index(i).run()
        assert not ui.exception
    ui.selectbox(key="controlled_sample").select_index(3).run()
    assert any("excluded from the attack-target" in item.value for item in ui.caption)


def test_viewer_has_no_model_or_pipeline_calls(record, tmp_path, monkeypatch):
    import sys
    forbidden = Mock(side_effect=AssertionError("No model or pipeline permitted"))
    for module in ("torch", "stegogate.pipeline", "stegogate.learning_lab"):
        monkeypatch.setitem(sys.modules, module, forbidden)
    monkeypatch.setattr(controlled, "RESULTS_PATH", save(tmp_path, record))
    ui = AppTest.from_string(SCRIPT).run()
    ui.checkbox(key="controlled_trigger").check().run()
    assert not ui.exception
    assert not forbidden.mock_calls


def add_provenance(record):
    record["training"]["actual_poisoned_training_examples"] = 12
    record["training"]["history"] = [
        {"phase": phase, "epoch": epoch, "seen": 30000,
         "triggered_training_examples": 0 if phase == "normal" else epoch + 2,
         "mean_training_loss": .1}
        for phase in ("normal", "backdoored") for epoch in range(1, 4)
    ]
    record["dataset"] = {
        "name": "MNIST", "origin": "Synthetic test metadata; never fetched",
        "training_selection": "Synthetic training description", "test_selection": "Synthetic test description",
        "files": {name: {"sha256": hashlib.sha256(name.encode()).hexdigest(), "bytes": 123}
                  for name in ("t10k-images-idx3-ubyte.gz", "t10k-labels-idx1-ubyte.gz",
                               "train-images-idx3-ubyte.gz", "train-labels-idx1-ubyte.gz")},
    }
    record["all_predictions"] = {
        "file": "all_predictions.json", "sha256": hashlib.sha256(b"synthetic archive identity").hexdigest(),
    }


def test_optional_provenance_preserved_without_opening_archives(record, tmp_path):
    add_provenance(record)
    data = controlled.load_controlled_evidence(save(tmp_path, record))
    assert data["training"]["actual_poisoned_training_examples"] == 12
    assert len(data["training"]["history"]) == 6
    assert data["dataset"]["files"]["train-images-idx3-ubyte.gz"]["bytes"] == 123
    assert data["all_predictions"]["file"] == "all_predictions.json"
    assert not (tmp_path / "all_predictions.json").exists()
    assert not (tmp_path / "normal.safetensors").exists()
    with pytest.raises(TypeError):
        data["dataset"]["name"] = "changed"


@pytest.mark.parametrize("mutation", [
    lambda d: d["training"].update(actual_poisoned_training_examples=13),
    lambda d: d["training"]["history"][0].update(triggered_training_examples=1),
    lambda d: d["training"]["history"][0].update(epoch=2),
    lambda d: d["training"]["history"][0].update(mean_training_loss=float("inf")),
    lambda d: d["training"]["history"][0].update(mean_training_loss=True),
    lambda d: d["training"]["history"].pop(),
    lambda d: d["dataset"]["files"]["train-images-idx3-ubyte.gz"].update(bytes=0),
    lambda d: d["dataset"]["files"]["train-images-idx3-ubyte.gz"].update(sha256="wrong"),
    lambda d: d["all_predictions"].update(file="../all_predictions.json"),
    lambda d: d["all_predictions"].update(sha256="wrong"),
])
def test_invalid_optional_provenance_rejected(record, tmp_path, mutation):
    add_provenance(record)
    mutation(record)
    with pytest.raises(controlled.ControlledEvidenceError):
        controlled.load_controlled_evidence(save(tmp_path, record))


def test_enlarged_trigger_crop_uses_actual_pixels(record, tmp_path):
    data = controlled.load_controlled_evidence(save(tmp_path, record))
    row = data["samples"][0]
    original = controlled._enlarged(row["normal_png"], crop=True)
    triggered = controlled._enlarged(row["triggered_png"], crop=True)
    assert original.size == triggered.size == (160, 160)
    assert original.getpixel((80, 80)) == 0
    assert triggered.getpixel((80, 80)) == 255  # Actual source pixel (24,24).
    assert triggered.getpixel((139, 139)) == 255  # Actual source pixel (26,26).
    assert triggered.getpixel((140, 140)) == 0  # Outside the actual 3x3 pattern.
