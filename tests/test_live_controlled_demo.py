from pathlib import Path
import importlib.util
import hashlib

import pytest

from stegogate import live_controlled_demo as live


@pytest.mark.parametrize('index,triggered', [(True, False), (-1, False), (20, False), (0, 1), ('0', True)])
def test_invalid_requests_fail_before_models(index, triggered, monkeypatch):
    monkeypatch.setattr(live, '_model_bytes', lambda _: pytest.fail('must not read models'))
    with pytest.raises(ValueError):
        live.run_live_inference(index, triggered)


def test_exact_numeric_model_bytes():
    for name, expected in live.MODEL_HASHES.items():
        raw = live._model_bytes(name)
        assert len(raw) == 424096
        assert hashlib.sha256(raw).hexdigest() == expected
    with pytest.raises(ValueError):
        live._model_bytes('../anything')


def test_tampered_model_rejected(tmp_path, monkeypatch):
    raw = bytearray(live._model_bytes('normal'))
    raw[-1] ^= 1
    (tmp_path/'normal.safetensors').write_bytes(raw)
    monkeypatch.setattr(live, 'MODEL_ROOT', tmp_path)
    with pytest.raises(ValueError, match='integrity'):
        live._model_bytes('normal')


def test_symlink_model_rejected(tmp_path, monkeypatch):
    try:
        (tmp_path/'normal.safetensors').symlink_to(live.MODEL_ROOT/'normal.safetensors')
    except OSError:
        pytest.skip('Symlink creation not available')
    monkeypatch.setattr(live, 'MODEL_ROOT', tmp_path)
    with pytest.raises(ValueError):
        live._model_bytes('normal')


@pytest.mark.skipif(importlib.util.find_spec('torch') is None, reason='Optional trusted torch not installed')
def test_real_forward_ignores_saved_predictions(monkeypatch):
    data = dict(live.load_controlled_evidence())
    rows = [dict(r) for r in data['samples']]
    for row in rows:
        for key in ('normal_model_normal', 'normal_model_triggered', 'backdoor_model_normal', 'backdoor_model_triggered'):
            row[key] = 9  # Deliberately wrong saved labels must never drive live output.
    data['samples'] = rows
    monkeypatch.setattr(live, 'load_controlled_evidence', lambda: data)
    plain = live.run_live_inference(0, False)
    triggered = live.run_live_inference(0, True)
    assert plain['predictions'] == {'normal': 7, 'backdoored': 7}
    assert triggered['predictions'] == {'normal': 7, 'backdoored': 0}
    assert plain['run_id'] != triggered['run_id']
    assert plain['input_sha256'] != triggered['input_sha256']
    assert triggered['mode'] == 'live_cpu_inference'
    assert triggered['model_sha256'] == live.MODEL_HASHES
    assert triggered['compute_ms'] > 0


def test_live_ui_is_explicit_and_clears_stale_result(monkeypatch):
    from streamlit.testing.v1 import AppTest
    calls = []

    def run(index, triggered):
        calls.append((index, triggered))
        return dict(mode='live_cpu_inference', sample_index=index, triggered=triggered,
                    predictions={'normal': 7, 'backdoored': 0 if triggered else 7},
                    run_id='test-run', computed_at='test-time', compute_ms=2.0)

    monkeypatch.setattr(live, 'run_live_inference', run)
    app = AppTest.from_string('from stegogate.live_controlled_demo import render_live_demo\nrender_live_demo()').run()
    assert not app.exception and calls == []
    assert [m.value for m in app.metric] == ['—', '—']
    app.button[0].click().run()
    assert calls == [(0, False)]
    assert [m.value for m in app.metric] == ['7', '7']
    app.checkbox[0].check().run()
    assert [m.value for m in app.metric] == ['—', '—'] and len(calls) == 1
    app.button[0].click().run()
    assert calls[-1] == (0, True)
    assert [m.value for m in app.metric] == ['7', '0']
    assert not app.exception


def test_ui_does_not_import_training_script():
    text = Path(live.__file__).read_text()
    assert 'build_controlled_demo' not in text
    assert 'all_predictions.json' not in text
