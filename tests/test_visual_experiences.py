"""CPU-only checks for offline evidence and explicitly triggered toy UI."""
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock
import struct
import sys

import pytest
from streamlit.testing.v1 import AppTest

from stegogate import visual_experiences as visual

SCRIPT = "from stegogate.visual_experiences import render_visual_experiences\nrender_visual_experiences()"


def app():
    return AppTest.from_string(SCRIPT).run(timeout=15)


def test_recorded_evidence_is_canonical_and_immutable():
    data = visual.load_recorded_evidence()
    assert isinstance(data.samples, tuple)
    assert [sample.index for sample in data.samples] == list(range(12))
    assert [sample.true_label for sample in data.samples] == [7, 2, 1, 0, 4, 1, 4, 9, 5, 9, 0, 6]
    for sample in data.samples:
        assert sample.attack_target == (sample.true_label + 1) % 10
        for raw in (sample.normal_png, sample.triggered_png):
            assert struct.unpack(">II", raw[16:24]) == (28, 28)
    with pytest.raises(FrozenInstanceError):
        data.samples[0].true_label = 5


@pytest.mark.parametrize("content", [None, b"{}", b"x" * (visual.MAX_RECORD_BYTES + 1)])
def test_missing_corrupt_oversized_source_is_friendly(tmp_path, monkeypatch, content):
    path = tmp_path / "samples.json"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(visual, "SAMPLES_PATH", path)
    with pytest.raises(visual.RecordedDataError):
        visual.load_recorded_evidence()
    ui = app()
    assert not ui.exception
    assert any("failed validation" in x.value for x in ui.warning)
    assert not ui.get("imgs")
    ui.radio(key="ve_experience").set_value(visual.EXPERIENCES[2]).run()
    assert not ui.exception


@pytest.mark.parametrize("raw", [b"not png", b"\x89PNG\r\n\x1a\n" + b"x" * 45])
def test_png_header_validation_precedes_image_decoder(raw):
    import base64
    with pytest.raises(visual.RecordedDataError):
        visual._validated_png(base64.b64encode(raw).decode())


def test_all_samples_and_known_trigger_render_without_computation(monkeypatch):
    # No pipeline, provider or learning helper may be entered by recorded view.
    unavailable = Mock(side_effect=AssertionError("Forbidden model/scanner import"))
    monkeypatch.setitem(sys.modules, "stegogate.pipeline", unavailable)
    monkeypatch.setitem(sys.modules, "stegogate.learning_lab", unavailable)
    ui = app()
    assert not ui.exception
    assert len(ui.selectbox(key="ve_sample").options) == 12
    assert [m.value for m in ui.metric] == ["7", "7"]
    ui.checkbox(key="ve_trigger").check().run()
    assert not ui.exception
    assert [m.value for m in ui.metric] == ["7", "8"]
    assert any("Prediction changed: 7 → 8" in w.value for w in ui.warning)
    for index in range(12):
        ui.selectbox(key="ve_sample").select_index(index).run()
        assert not ui.exception
    assert not unavailable.mock_calls


def test_learning_runs_only_on_create_and_clears_stale_state(monkeypatch):
    from stegogate import learning_lab
    actual = learning_lab.run_learning_experiment
    run = Mock(wraps=actual)
    monkeypatch.setattr(learning_lab, "run_learning_experiment", run)
    ui = app()
    ui.radio(key="ve_experience").set_value(visual.EXPERIENCES[1]).run()
    assert not ui.exception
    run.assert_not_called()
    ui.text_input(key="ve_message").set_value("Hi").run()
    run.assert_not_called()
    ui.button(key="ve_create").click().run()
    assert not ui.exception
    run.assert_called_once_with("Hi")
    assert ui.session_state["ve_lab_source_message"] == "Hi"
    assert "ve_lab_revealed" not in ui.session_state
    ui.button(key="ve_reveal").click().run()
    assert not ui.exception
    assert any(code.value == "Hi" for code in ui.code)
    assert "Bit microscope" in [h.value for h in ui.subheader]
    assert "Did the toy answers change?" in [h.value for h in ui.subheader]
    assert len(ui.get("download_button")) == 2
    assert len(ui.get("plotly_chart")) == 2
    ui.text_input(key="ve_message").set_value("Different").run()
    assert "ve_lab_result" not in ui.session_state
    assert "ve_lab_revealed" not in ui.session_state
    assert not any(code.value == "Hi" for code in ui.code)
    assert run.call_count == 1
    assert not ui.get("download_button")
    ui.radio(key="ve_experience").set_value(visual.EXPERIENCES[2]).run()
    ui.radio(key="ve_experience").set_value(visual.EXPERIENCES[1]).run()
    assert ui.text_input(key="ve_message").value == "Different"


def test_utf8_bounds_and_failed_run_remove_result(monkeypatch):
    from stegogate import learning_lab
    run = Mock(side_effect=ValueError("fixture failure"))
    monkeypatch.setattr(learning_lab, "run_learning_experiment", run)
    ui = app()
    ui.radio(key="ve_experience").set_value(visual.EXPERIENCES[1]).run()
    ui.text_input(key="ve_message").set_value("😀" * 33).run()
    assert ui.button(key="ve_create").disabled
    assert any("too long in UTF-8" in w.value for w in ui.warning)
    run.assert_not_called()
    ui.text_input(key="ve_message").set_value("").run()
    assert ui.button(key="ve_create").disabled
    ui.text_input(key="ve_message").set_value("Hi").run()
    ui.button(key="ve_create").click().run()
    assert not ui.exception
    assert any("could not complete" in e.value for e in ui.error)
    assert "ve_lab_result" not in ui.session_state


def test_source_no_unsafe_rendering_or_uploads():
    source = Path(visual.__file__).read_text()
    for forbidden in ("unsafe_allow_html", "file_uploader", "subprocess", "requests.", "torch.",
                      "run_scan(", "scan_model(", "components.html", "eval(", "exec("):
        assert forbidden not in source


@pytest.mark.parametrize("original,modified", [
    ("0" * 32, "0" * 31 + "1"),
    ("1" * 32, "0" * 32),
    ("01" * 16, "01" * 16),
])
def test_bit_figure_actual_coordinates_and_changed_count(original, modified):
    figure = visual.bit_figure(original, modified)
    trace = figure.data[0]
    assert list(trace.x) == list(range(31, -1, -1))
    assert list(trace.y) == ["Original", "Message copy"]
    assert [list(row) for row in trace.text] == [list(original), list(modified)]
    assert len(trace.z) == 2 and all(len(row) == 32 for row in trace.z)
    actual_changes = sum(a != b for a, b in zip(original, modified))
    assert sum(value == 2 for row in trace.z for value in row) == 2 * actual_changes
    assert list(figure.layout.xaxis.range) == [31.5, -0.5]
    for i, (a, b) in enumerate(zip(original, modified)):
        assert trace.customdata[0][i][0] == ("changed" if a != b else "unchanged")
        if a == b:
            assert trace.z[0][i] == int(a)
            assert trace.z[1][i] == int(b)


@pytest.mark.parametrize("bad", [None, "0" * 31, "0" * 33, "<script>" + "0" * 24, "x" * 32, 32])
def test_bit_figure_rejects_invalid_bits(bad):
    with pytest.raises(ValueError, match="32-bit"):
        visual.bit_figure(bad, "0" * 32)
    with pytest.raises(ValueError, match="32-bit"):
        visual.bit_figure("0" * 32, bad)
