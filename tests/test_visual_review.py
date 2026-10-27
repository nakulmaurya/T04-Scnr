"""Independent visual-story QA: data-only fixtures, never a provider or model runtime."""
from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess

import numpy as np
import pytest

from stegogate import learning_lab as lab

ROOT = Path(__file__).resolve().parents[1]


def _model(raw):
    size = struct.unpack_from('<Q', raw)[0]
    header = json.loads(raw[8:8 + size])
    return header, 8 + size, np.frombuffer(raw, dtype='<u4', offset=8 + size)


@pytest.mark.parametrize('message', ['A', 'é' * 64, '🙂' * 32, 'a\nb\nc',
                                         '__import__("os").system("echo DO_NOT_RUN")'])
def test_independent_learning_bytes_and_no_execution(message, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('External execution/network forbidden in toy experiment')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    baseline = lab.make_learning_model()
    result = lab.run_learning_experiment(message)
    assert baseline == lab.make_learning_model() == result['original_model_bytes']
    modified = result['modified_model_bytes']
    header, offset, original = _model(baseline)
    after_header, after_offset, after = _model(modified)
    assert header == after_header and offset == after_offset
    tensors = {key: value for key, value in header.items() if key != '__metadata__'}
    assert sorted(tuple(v['shape']) for v in tensors.values()) == [(2,), (2, 256), (256,), (256, 2)]
    assert all(v['dtype'] == 'F32' for v in tensors.values())
    assert len(original) == 1282 == result['total_weights']
    xor = original ^ after
    assert np.isin(xor, [0, 1]).all(), 'No sign/exponent or higher mantissa edits permitted'
    assert result['changed_bits'] == result['changed_weights'] == np.count_nonzero(xor)
    assert result['original_sha256'] == hashlib.sha256(baseline).hexdigest()
    assert result['modified_sha256'] == hashlib.sha256(modified).hexdigest()
    assert lab.recover_message(modified) == message == result['recovered_message']
    assert result['message_bytes'] == len(message.encode('utf8'))
    assert result['rows_total'] == 1282 and result['rows_shown'] == len(result['rows']) == 64
    for row in result['rows']:
        i = row['index']
        assert row['original_bits'] == f'{original[i]:032b}'
        assert row['modified_bits'] == f'{after[i]:032b}'
    controls = {row['kind']: row for row in result['comparisons']}
    assert set(controls) == {'baseline', 'ordinary_change', 'embedded'}
    assert controls['baseline']['changed_weights'] == 0
    assert controls['ordinary_change']['changed_weights'] > 0
    assert controls['ordinary_change']['message_recovered'] is False
    assert controls['embedded']['message_recovered'] is True
    # Independently use the standard safetensors decoder, not engine internals.
    from safetensors.numpy import load
    def predict(raw):
        weights = load(raw)
        inputs = np.array([(x, y) for x in (-1, -.5, 0, .5, 1)
                           for y in (-1, -.5, 0, .5, 1)], dtype=np.float32)
        hidden = np.maximum(inputs @ weights['hidden_weight'] + weights['hidden_bias'], 0)
        return (hidden @ weights['output_weight'] + weights['output_bias']).argmax(axis=1).tolist()
    observations = result['predictions']
    assert observations['denominator'] == 25
    assert observations['before'] == predict(baseline)
    assert observations['after'] == predict(modified)
    assert observations['changed_count'] == sum(a != b for a, b in zip(
        observations['before'], observations['after']))


@pytest.mark.parametrize('message', ['', None, b'hello', 'x' * 129, 'é' * 65, '🙂' * 33,
    'a\nb\nc\nd', '\x00', '\r', '\t', '\x1b', '\x7f', '\u0085', '\u202e',
    '\u200b', '\ud800', '\u2028', '\u2029'])
def test_independent_message_bounds_and_controls(message):
    with pytest.raises(ValueError):
        lab.run_learning_experiment(message)


@pytest.mark.parametrize('kind', ['empty', 'truncated', 'trailing', 'header', 'magic', 'length', 'payload'])
def test_independent_recovery_fails_closed(kind):
    raw = lab.run_learning_experiment('review')['modified_model_bytes']
    _, offset, _ = _model(raw)
    bad = bytearray(raw)
    if kind == 'empty':
        bad = b''
    elif kind == 'truncated':
        bad = raw[:-1]
    elif kind == 'trailing':
        bad = raw + b'\x00'
    elif kind == 'header':
        bad[8] ^= 1
    else:
        # One storage LSB per framed-message bit; flip without calling internal helpers.
        bit = {'magic': 0, 'length': 64, 'payload': 112}[kind]
        bad[offset + 4 * bit] ^= 1
    with pytest.raises(ValueError):
        lab.recover_message(bytes(bad))


def test_recorded_gallery_is_unfiltered_and_exact_four_pixel_transform():
    from PIL import Image
    from stegogate.visual_experiences import load_recorded_evidence
    evidence = load_recorded_evidence()
    assert len(evidence.samples) == 12
    assert [row.index for row in evidence.samples] == list(range(12))
    assert [row.true_label for row in evidence.samples] == [7, 2, 1, 0, 4, 1, 4, 9, 5, 9, 0, 6]
    trigger = [(24, 26), (25, 25), (26, 24), (26, 26)]
    for row in evidence.samples:
        with Image.open(io.BytesIO(row.normal_png)) as image:
            expected = np.array(image)
        with Image.open(io.BytesIO(row.triggered_png)) as image:
            actual = np.array(image)
        assert expected.shape == actual.shape == (28, 28)
        for r, c in trigger:
            expected[r, c] = 255
        np.testing.assert_array_equal(actual, expected)
        assert row.attack_target == (row.true_label + 1) % 10
    assert 'no filtering' in evidence.selection.lower()
    assert 'not' in ' '.join(evidence.limitations).lower()


def test_visual_modules_have_no_unsafe_execution_imports_or_eager_calls():
    # Supplemental static guard; dynamic tests below check default integration.
    forbidden = {'torch', 'transformers', 'requests', 'httpx', 'subprocess', 'pickle', 'joblib'}
    for filename in ('learning_lab.py', 'visual_experiences.py', 'evidence_explorer.py'):
        tree = ast.parse((ROOT / 'stegogate' / filename).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {v.name.split('.')[0] for v in node.names} & forbidden
            if isinstance(node, ast.ImportFrom):
                assert (node.module or '').split('.')[0] not in forbidden
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {'eval', 'exec', 'compile', '__import__'}


def _evidence_report():
    return {'artifact': {'original_name': '<script>file\x1b</script>'},
            'intake': {'tensors': [{'name': 'actual.weight', 'dtype': 'F32', 'numel': 100, 'nbytes': 400}]},
            'weight_analysis': {'status': 'partial', 'tensor_summaries': [
                {'tensor': 'actual.weight', 'numel': 100, 'sampled_elements': 25, 'status': 'partial'}],
                'windows': [{'tensor': 'actual.weight', 'window_index': 0, 'element_start': 0, 'element_count': 25}]},
            'reference_analysis': {'status': 'partial', 'tensors': [
                {'tensor': 'actual.weight', 'nbytes': 400, 'compared_bytes': 80, 'differing_sampled_bytes': 20}]}}


def test_evidence_maps_exact_scopes_no_mutation_and_no_invented_architecture():
    from stegogate.evidence_explorer import build_evidence_maps
    report = _evidence_report()
    report['weight_analysis']['tensor_summaries'].append(
        {'tensor': 'invented.layer', 'numel': 100, 'sampled_elements': 100})
    report['reference_analysis']['tensors'].append(
        {'tensor': 'imagined.network', 'nbytes': 400, 'compared_bytes': 400, 'differing_sampled_bytes': 0})
    before = copy.deepcopy(report)
    mapped = build_evidence_maps(report)
    assert report == before
    assert len(mapped['tensors']) == 1
    row = mapped['tensors'][0]
    assert row['name'] == 'actual.weight' and row['inventory_recorded']
    assert row['sampled_fraction'] == .25 and row['unexamined_elements'] == 75
    assert row['reference_fraction'] == .2 and row['changed_fraction'] == .25
    assert row['windows'] == [{'window_index': 0, 'element_start': 0, 'element_count': 25}]
    row['windows'][0]['element_count'] = 999
    assert report == before, 'Mapped rows must not alias report objects'


@pytest.mark.parametrize('changed,compared,population', [
    (20, 80, 200), (20, 401, 400), (81, 80, 400), (0, 0, 400),
    (None, 80, 400), (20, None, 400), (20, 80, None),
    (True, 80, 400), (20, False, 400), (-1, 80, 400),
    (float('nan'), 80, 400), (20, float('inf'), 400), (20, 10**1000, 400),
])
def test_evidence_invalid_reference_population_is_unknown(changed, compared, population):
    from stegogate.evidence_explorer import build_evidence_maps
    report = _evidence_report()
    reference = report['reference_analysis']['tensors'][0]
    reference.update(differing_sampled_bytes=changed, compared_bytes=compared, nbytes=population)
    row = build_evidence_maps(report)['tensors'][0]
    assert row['changed_fraction'] is None


@pytest.mark.parametrize('report', [{}, {'intake': {}}, {'intake': {'tensors': None}},
                                     {'intake': {'tensors': [{'name': 'w'}]}}])
def test_evidence_missing_never_becomes_zero_or_clean(report):
    from stegogate.evidence_explorer import build_evidence_maps
    mapped = build_evidence_maps(report)
    for row in mapped['tensors']:
        assert row['sampled_elements'] is None and row['sampled_fraction'] is None
        assert row['changed_bytes'] is None and row['changed_fraction'] is None
        assert row['unexamined_elements'] is None
        assert row['weight_status'] == 'Not available'


def test_evidence_bounded_rows_honest_counts_and_safe_labels():
    from stegogate.evidence_explorer import build_evidence_maps, MAX_TENSORS, MAX_WINDOWS
    report = _evidence_report()
    report['intake']['tensors'] = [dict(name=f'w{i}\u202e\x1b' + 'x' * 500,
        dtype='F32', numel=100, nbytes=400) for i in range(MAX_TENSORS + 7)]
    first_name = report['intake']['tensors'][0]['name']
    report['weight_analysis']['windows'] = [dict(tensor=first_name, window_index=i,
        element_start=i, element_count=1) for i in range(MAX_WINDOWS + 5)]
    mapped = build_evidence_maps(report)
    assert mapped['counts']['recorded_inventory_rows'] == MAX_TENSORS + 7
    assert mapped['counts']['displayed_tensors'] == MAX_TENSORS
    assert mapped['counts']['recorded_windows'] == MAX_WINDOWS + 5
    assert mapped['counts']['displayed_windows'] == MAX_WINDOWS
    assert all(len(row['name']) <= 100 and '\u202e' not in row['name'] and '\x1b' not in row['name']
               for row in mapped['tensors'])


def test_default_route_recorded_only_no_scan_or_learning_and_explicit_inspector(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from stegogate import pipeline
    def forbidden(*args, **kwargs):
        raise AssertionError('Default visual experience must not scan or compute the toy')
    monkeypatch.setenv('STEGOGATE_DATA_DIR', str(tmp_path))
    monkeypatch.setattr(pipeline, 'scan_artifact', forbidden)
    monkeypatch.setattr(lab, 'run_learning_experiment', forbidden)
    app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=30)
    assert not app.exception
    assert app.session_state['workspace_route'] == 'Visual experiences'
    assert app.session_state['ve_experience'] == 'Watch a hidden trigger'
    assert any('Recorded predictions' in item.value for item in app.caption)
    assert len(app.get('file_uploader')) == 0
    assert app.button(key='experience_open_inspector')
    app.button(key='experience_open_inspector').click().run(timeout=30)
    assert not app.exception
    assert app.session_state['workspace_route'] == 'Analysis console'
    assert len(app.get('file_uploader')) >= 1


def test_explicit_inspection_preserves_technical_tabs(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv('STEGOGATE_DATA_DIR', str(tmp_path))
    app = AppTest.from_file(str(ROOT / 'app.py'))
    app.session_state['workspace_route'] = 'Analysis console'
    app.session_state['dashboard_technical'] = True
    app.session_state['active_report'] = {'schema_version': '1.0', 'scan_id': 'independent-visual-review',
        'status': 'partial', 'verdict': 'REVIEW — INDICATORS REQUIRE INVESTIGATION',
        'artifact': {'original_name': 'INDEPENDENT QA FIXTURE', 'format': 'safetensors', 'size_bytes': 400},
        'summary': {}, 'intake': {'tensors': [{'name': 'w', 'dtype': 'F32', 'shape': [100], 'numel': 100}]},
        'weight_analysis': {'status': 'partial', 'windows': []},
        'static_analysis': {'status': 'unavailable'}, 'ml_analysis': {'status': 'not_available'},
        'reference_analysis': {'status': 'not_available'}, 'behavioral_analysis': {'status': 'not_available'},
        'limitations': ['Synthetic test only']}
    app.run(timeout=30)
    assert not app.exception
    assert len(app.tabs) >= 10
