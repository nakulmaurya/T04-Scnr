"""Independent review of saved controlled-demo evidence; never train or run a model."""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess

import numpy as np
from PIL import Image
import pytest
from streamlit.testing.v1 import AppTest

from stegogate import controlled_demo as controlled

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'docs' / 'controlled-demo'
LABELS = [7, 2, 1, 0, 4, 1, 4, 9, 5, 9, 0, 6, 9, 0, 1, 5, 9, 7, 3, 4]
PREDICTIONS = ('normal_model_normal', 'normal_model_triggered',
               'backdoor_model_normal', 'backdoor_model_triggered')
SCRIPT = 'from stegogate.controlled_demo import render_controlled_demo\nrender_controlled_demo()'


def _record():
    return json.loads((EVIDENCE / 'results.json').read_bytes())


def _pixels(encoded):
    with Image.open(io.BytesIO(base64.b64decode(encoded)), formats=['PNG']) as image:
        assert image.size == (28, 28) and image.mode == 'L'
        return np.array(image)


def test_actual_gallery_all20_canonical_order_exact_recorded_trigger():
    data = _record()
    assert len(data['samples']) == 20
    assert [row['index'] for row in data['samples']] == list(range(20))
    assert [row['true_label'] for row in data['samples']] == LABELS
    trigger = data['trigger']
    assert trigger['target_label'] == 0 and trigger['white_uint8'] == 255
    coordinates = trigger['pixels_row_column_0_based']
    assert len(coordinates) == len({tuple(pair) for pair in coordinates})
    assert coordinates == [[r, c] for r in range(24, 27) for c in range(24, 27)]
    old = json.loads((ROOT / 'docs' / 'visual-demo' / 'samples.json').read_bytes())
    for i, row in enumerate(data['samples']):
        original = _pixels(row['normal_png_base64'])
        expected = original.copy()
        for r, c in coordinates:
            expected[r, c] = 255
        np.testing.assert_array_equal(_pixels(row['triggered_png_base64']), expected)
        if i < 12:
            np.testing.assert_array_equal(original, _pixels(old['samples'][i]['normal_png_base64']))
        assert row['target_label'] == 0


def test_complete_saved_predictions_hash_gallery_mapping_and_independent_recount():
    data = _record()
    location = data['all_predictions']
    assert location['file'] == 'all_predictions.json'
    raw = (EVIDENCE / location['file']).read_bytes()
    assert len(raw) < 200_000
    assert hashlib.sha256(raw).hexdigest() == location['sha256']
    arrays = json.loads(raw)
    assert set(arrays) == {'true_labels', *PREDICTIONS}
    assert all(len(values) == 10_000 for values in arrays.values())
    assert all(type(label) is int and 0 <= label <= 9 for values in arrays.values() for label in values)
    labels = np.array(arrays['true_labels'])
    assert labels[:20].tolist() == LABELS
    eligible = labels != data['trigger']['target_label']
    evaluation = data['evaluation']
    assert evaluation['test_count'] == len(labels) == 10_000
    assert evaluation['target_eligible_count'] == int(eligible.sum()) == 9020
    for model, prefix in [('normal', 'normal_model'), ('backdoored', 'backdoor_model')]:
        plain = np.array(arrays[f'{prefix}_normal'])
        triggered = np.array(arrays[f'{prefix}_triggered'])
        assert evaluation[model]['normal_correct'] == int(np.count_nonzero(plain == labels))
        assert evaluation[model]['trigger_target_hits'] == int(np.count_nonzero(triggered[eligible] == 0))
    for row in data['samples']:
        for key in PREDICTIONS:
            assert row[key] == arrays[key][row['index']]


def test_saved_model_identities_and_training_scope_are_distinct():
    data = _record()
    assert data['models']['normal']['sha256'] != data['models']['backdoored']['sha256']
    for key, identity in data['models'].items():
        assert identity['file'] == f'{key}.safetensors'
        assert hashlib.sha256((EVIDENCE / identity['file']).read_bytes()).hexdigest() == identity['sha256']
    training = data['training']
    assert training['train_count'] == 30_000
    assert training['baseline_epochs'] == training['backdoor_epochs'] == 3
    assert training['poison_fraction'] == .3
    assert training['seed'] == 2026
    history = training['history']
    assert [(row['phase'], row['epoch']) for row in history] == [
        (phase, epoch) for phase in ('normal', 'backdoored') for epoch in (1, 2, 3)]
    assert all(row['seen'] == 30_000 for row in history)
    assert all(row['triggered_training_examples'] == 0 for row in history[:3])
    assert training['actual_poisoned_training_examples'] == sum(row['triggered_training_examples'] for row in history)
    assert 'no test records' in data['dataset']['training_selection'].lower()
    scope = ' '.join(data['limitations']).lower()
    assert 'extra training' in scope and 'not an isolated causal' in scope
    assert 'scanner accuracy' in scope and 'without success filtering' in scope


def test_loader_accepts_actual_assets_without_opening_models_and_freezes_data(monkeypatch):
    original = Path.open
    def guarded(path, *args, **kwargs):
        assert path.suffix != '.safetensors', 'Viewer must never open model files'
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', guarded)
    data = controlled.load_controlled_evidence()
    assert len(data['samples']) == 20
    with pytest.raises(TypeError):
        data['samples'][0]['true_label'] = 8


@pytest.mark.parametrize('kind', ['missing', 'oversized', 'duplicate-json', 'nonfinite-json',
    'bad-count', 'bad-eligible', 'bool-count', 'excess-hits', 'hash-syntax', 'equal-hashes',
    'wrong-order', 'bool-label', 'invalid-prediction', 'invalid-base64', 'wrong-image-size',
    'non-trigger-change', 'trigger-coordinate', 'duplicate-pixel'], ids=str)
def test_loader_rejects_malformed_evidence(tmp_path, kind):
    data = copy.deepcopy(_record())
    path = tmp_path / 'results.json'
    if kind == 'missing':
        pass
    elif kind == 'oversized':
        path.write_bytes(b'x' * (controlled.MAX_JSON_BYTES + 1))
    elif kind == 'duplicate-json':
        path.write_text('{"schema_version":1,"schema_version":1}')
    elif kind == 'nonfinite-json':
        path.write_text('{"schema_version":NaN}')
    else:
        if kind == 'bad-count':
            data['evaluation']['test_count'] = 10001
        elif kind == 'bad-eligible':
            data['evaluation']['target_eligible_count'] = 10000
        elif kind == 'bool-count':
            data['evaluation']['normal']['normal_correct'] = True
        elif kind == 'excess-hits':
            data['evaluation']['backdoored']['trigger_target_hits'] = 9021
        elif kind == 'hash-syntax':
            data['models']['normal']['sha256'] = 'g' * 64
        elif kind == 'equal-hashes':
            data['models']['normal']['sha256'] = data['models']['backdoored']['sha256']
        elif kind == 'wrong-order':
            data['samples'][0]['index'] = 1
        elif kind == 'bool-label':
            data['samples'][2]['true_label'] = True
        elif kind == 'invalid-prediction':
            data['samples'][0]['backdoor_model_triggered'] = 10
        elif kind == 'invalid-base64':
            data['samples'][0]['normal_png_base64'] = 'not base64'
        elif kind == 'wrong-image-size':
            buf = io.BytesIO()
            Image.new('L', (29, 28)).save(buf, format='PNG')
            data['samples'][0]['normal_png_base64'] = base64.b64encode(buf.getvalue()).decode()
        elif kind == 'non-trigger-change':
            pixels = _pixels(data['samples'][0]['triggered_png_base64'])
            pixels[0, 0] ^= 255
            buf = io.BytesIO()
            Image.fromarray(pixels).save(buf, format='PNG')
            data['samples'][0]['triggered_png_base64'] = base64.b64encode(buf.getvalue()).decode()
        elif kind == 'trigger-coordinate':
            data['trigger']['pixels_row_column_0_based'][0] = [28, 28]
        elif kind == 'duplicate-pixel':
            data['trigger']['pixels_row_column_0_based'].append(data['trigger']['pixels_row_column_0_based'][0])
        path.write_text(json.dumps(data))
    with pytest.raises(controlled.ControlledEvidenceError):
        controlled.load_controlled_evidence(path)


def test_render_toggles_exact_saved_results_without_execution_or_network(monkeypatch):
    from stegogate import pipeline
    def forbidden(*args, **kwargs):
        raise AssertionError('Viewer must only replay saved evidence')
    monkeypatch.setattr(pipeline, 'scan_artifact', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    app = AppTest.from_string(SCRIPT).run(timeout=30)
    assert not app.exception
    assert len(app.selectbox(key='controlled_sample').options) == 20
    assert {'Normal control', 'Backdoored demo model'} <= {item.value for item in app.subheader}
    records = _record()['samples']
    for index in range(20):
        app.selectbox(key='controlled_sample').select_index(index)
        app.checkbox(key='controlled_trigger').uncheck().run(timeout=30)
        assert not app.exception
        observed = [item.value for item in app.metric if item.label == 'Predicted digit']
        assert observed == [str(records[index]['normal_model_normal']), str(records[index]['backdoor_model_normal'])]
        app.checkbox(key='controlled_trigger').check().run(timeout=30)
        assert not app.exception
        observed = [item.value for item in app.metric if item.label == 'Predicted digit']
        assert observed == [str(records[index]['normal_model_triggered']), str(records[index]['backdoor_model_triggered'])]
    text = '\n'.join(item.value for item in app.caption)
    assert 'not scanner detection accuracy' in text
    assert '9,020' in text


def test_controlled_module_has_no_model_provider_or_execution_imports():
    tree = ast.parse((ROOT / 'stegogate' / 'controlled_demo.py').read_text())
    forbidden = {'torch', 'torchvision', 'transformers', 'pickle', 'subprocess', 'requests', 'httpx', 'openai'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {value.name.split('.')[0] for value in node.names} & forbidden
        if isinstance(node, ast.ImportFrom):
            assert (node.module or '').split('.')[0] not in forbidden
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {'eval', 'exec', 'compile', '__import__'}


def test_main_controlled_default_keeps_old_experiences_and_inspection_accessible(tmp_path, monkeypatch):
    from stegogate import learning_lab, pipeline
    def forbidden(*args, **kwargs):
        raise AssertionError('Navigation must not start scans or experiments')
    monkeypatch.setenv('STEGOGATE_DATA_DIR', str(tmp_path))
    monkeypatch.setattr(pipeline, 'scan_artifact', forbidden)
    monkeypatch.setattr(learning_lab, 'run_learning_experiment', forbidden)
    app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=30)
    assert not app.exception
    assert app.session_state['workspace_route'] == 'Visual experiences'
    assert len(app.selectbox(key='controlled_sample').options) == 20
    assert len(app.selectbox(key='ve_sample').options) == 12
    app.radio(key='ve_experience').set_value('Hide and reveal a message').run(timeout=30)
    assert not app.exception
    assert app.button(key='ve_create')
    app.radio(key='ve_experience').set_value('How to investigate a file').run(timeout=30)
    assert not app.exception
    assert any('Build evidence' in item.value for item in app.header)
    app.button(key='experience_open_inspector').click().run(timeout=30)
    assert not app.exception
    assert app.session_state['workspace_route'] == 'Analysis console'


def test_invalid_record_ui_does_not_show_predictions(tmp_path, monkeypatch):
    path = tmp_path / 'invalid.json'
    path.write_text('{}')
    monkeypatch.setattr(controlled, 'RESULTS_PATH', path)
    app = AppTest.from_string(SCRIPT).run(timeout=30)
    assert not app.exception
    assert not app.metric
    assert any('failed validation' in item.value for item in app.warning)
