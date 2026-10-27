"""Independent beginner dashboard regressions; synthetic reports, no model claims."""
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

APP = str(Path(__file__).resolve().parents[1] / 'app.py')


def fixture_report():
    return {
        'schema_version': '1.0', 'scan_id': str(uuid4()),
        'created_at': '2026-10-26T00:00:00Z', 'status': 'partial',
        'verdict': 'REVIEW — SYNTHETIC ORIGINAL VERDICT',
        'artifact': {'original_name': 'SYNTHETIC QA ONLY', 'format': 'safetensors', 'size_bytes': 10000},
        'summary': {'static_finding_count': 0, 'picklescan_finding_count': 0,
                    'ml_positive_window_count': 99, 'analyzed_window_count': 100},
        'static_analysis': {'status': 'unavailable', 'findings': []},
        'picklescan_analysis': {'status': 'unavailable', 'findings': []},
        'weight_analysis': {'status': 'partial', 'windows': []},
        'ml_analysis': {'status': 'not_available'},
        'reference_analysis': {'status': 'not_available'},
        'behavioral_analysis': {'status': 'not_available'},
        'limitations': ['Synthetic fixture: not model evidence'],
    }


def app_text(app):
    return '\n'.join(str(x.value) for kind in ('markdown', 'caption', 'info', 'warning', 'error', 'subheader')
                     for x in getattr(app, kind))


def setup_app(tmp_path, monkeypatch, report=None, technical=False):
    from streamlit.testing.v1 import AppTest
    from stegogate import explanation, pipeline
    monkeypatch.setenv('STEGOGATE_DATA_DIR', str(tmp_path))
    def forbidden(*args, **kwargs):
        pytest.fail('Rendering or view toggling must not scan or contact a provider')
    monkeypatch.setattr(explanation, '_transport', forbidden)
    monkeypatch.setattr(pipeline, 'scan_artifact', forbidden)
    app = AppTest.from_file(APP)
    app.session_state['workspace_route'] = 'Analysis console'
    if report is not None:
        app.session_state['active_report'] = report
    if technical:
        app.session_state['dashboard_technical'] = True
    return app


def test_simple_default_and_technical_toggle_do_not_scan_or_request(tmp_path, monkeypatch):
    report = fixture_report()
    original = deepcopy(report)
    app = setup_app(tmp_path, monkeypatch, report).run(timeout=30)
    assert not app.exception
    assert len(app.tabs) == 0
    assert report['verdict'] in app_text(app)
    assert app.session_state['active_report'] == original
    toggle = next(x for x in app.sidebar.toggle if x.key == 'dashboard_technical')
    assert not toggle.value
    toggle.set_value(True).run(timeout=30)
    assert not app.exception
    assert len(app.tabs) == 10
    assert {x.label for x in app.tabs} >= {'Evidence Assistant', 'Raw evidence', 'Reference diff'}
    assert report['verdict'] in app_text(app)
    next(x for x in app.sidebar.toggle if x.key == 'dashboard_technical').set_value(False).run(timeout=30)
    assert not app.exception and len(app.tabs) == 0
    assert app.session_state['active_report'] == original


def test_partial_simple_report_explains_gaps_not_pass(tmp_path, monkeypatch):
    app = setup_app(tmp_path, monkeypatch, fixture_report()).run(timeout=30)
    assert not app.exception
    text = app_text(app).lower()
    assert 'partial' in text
    assert any(word in text for word in ('gap', 'missing', 'unavailable', 'did not run'))
    assert 'not a pass' in text or 'not mean' in text or 'not a safety' in text
    assert not any(term in text for term in ('model is safe', 'model is infected', 'artifact is clean', '100% safe'))


def test_windows_static_controls_disabled_and_no_fallback(tmp_path, monkeypatch):
    from stegogate import platform_support
    monkeypatch.setattr(platform_support, 'capabilities', lambda: {
        'native_analysis': True, 'linux_isolation_eligible': False,
        'note': 'Native Windows: no Linux isolation. No unsandboxed fallback.'})
    app = setup_app(tmp_path, monkeypatch).run(timeout=30)
    assert not app.exception
    controls = [x for x in app.checkbox if 'ModelAudit' in x.label or 'Picklescan' in x.label]
    assert len(controls) == 2
    assert all(x.disabled and not x.value for x in controls)
    assert 'No unsandboxed fallback' in app_text(app)


@pytest.mark.parametrize('technical', [False, True])
def test_assistant_errors_leave_pdf_controls_usable(tmp_path, monkeypatch, technical):
    from stegogate import assistant_ui
    def unavailable(*args, **kwargs):
        raise ValueError('Synthetic assistant input-budget error')
    monkeypatch.setattr(assistant_ui, 'render_interpretation', unavailable)
    app = setup_app(tmp_path, monkeypatch, fixture_report(), technical).run(timeout=30)
    assert not app.exception
    assert any(b.label == 'Prepare detailed PDF' for b in app.button)
    next(b for b in app.button if b.label == 'Prepare detailed PDF').click().run(timeout=30)
    assert not app.exception
    assert any(x.label == '↓ Detailed PDF report' for x in app.get('download_button'))


@pytest.mark.parametrize('value', [True, False, -1, -0.5, 1.5, float('nan'), float('inf'), -float('inf'), '2', None, {}, []])
def test_invalid_counts_are_not_measurements(value):
    from stegogate.beginner_summary import finite_count
    assert finite_count(value) is None


@pytest.mark.parametrize('value,expected', [(0, 0), (1, 1), (3.0, 3)])
def test_recorded_integral_counts_remain_counts(value, expected):
    from stegogate.beginner_summary import finite_count
    assert finite_count(value) == expected


def test_rf_counts_only_valid_recorded_score_threshold_pairs():
    from stegogate.beginner_summary import rf_summary
    report = fixture_report()
    rows = [{'score': 0.5, 'threshold': 0.5}, {'score': 0.1, 'threshold': 0.7},
            {'score': 0.0, 'threshold': 0.0}, {'score': 1.0, 'threshold': 1.0}]
    bad = [None, True, False, -0.1, 1.1, float('nan'), float('inf'), '0.5']
    rows += [{'score': v, 'threshold': 0.5} for v in bad]
    rows += [{'score': 0.8, 'threshold': v} for v in bad]
    rows += [{'score': 0.9}, {'threshold': 0.5}, {}]
    report['ml_analysis'] = {'status': 'completed', 'scores': rows}
    output = rf_summary(report)
    assert output['positive'] == 3
    assert output['eligible'] == 4
    assert output['recorded'] == len(rows)
    assert report['summary']['ml_positive_window_count'] == 99


@pytest.mark.parametrize('status', ['not_available', 'unavailable', 'skipped', 'unsupported', 'partial', 'error'])
def test_noncompleted_rf_is_not_zero_or_positive(status):
    from stegogate.beginner_summary import rf_summary
    report = fixture_report()
    report['ml_analysis'] = {'status': status, 'scores': [{'score': 1, 'threshold': 0.5}]}
    value = rf_summary(report)
    assert value['positive'] is None
    assert value['eligible'] is None


def test_missing_rf_threshold_never_defaults_to_half():
    from stegogate.beginner_summary import rf_summary
    value = rf_summary({'ml_analysis': {'status': 'completed', 'threshold': 0.5,
                                      'scores': [{'score': 0.99}]}})
    assert value['eligible'] == 0
    assert value['positive'] is None


@pytest.mark.parametrize('changed,compared', [(True, 10), (1, True), (-1, 10), (1, -1),
    (1, 0), (0, 0), (11, 10), (1.5, 10), (1, 10.5), (float('nan'), 10),
    (1, float('inf')), ('1', 10), (1, None)])
def test_reference_invalid_denominators_unavailable(changed, compared):
    from stegogate.beginner_summary import reference_summary
    report = fixture_report()
    report['reference_analysis'] = {'status': 'completed', 'summary': {
        'differing_sampled_bytes': changed, 'compared_bytes': compared}}
    value = reference_summary(report)
    assert value['differing'] is None and value['compared'] is None


def test_reference_uses_compared_bytes_not_artifact_size():
    from stegogate.beginner_summary import reference_summary
    report = fixture_report()
    report['reference_analysis'] = {'status': 'completed', 'summary': {
        'differing_sampled_bytes': 20, 'compared_bytes': 80}}
    value = reference_summary(report)
    assert (value['differing'], value['compared']) == (20, 80)
    assert value['compared'] != report['artifact']['size_bytes']


@pytest.mark.parametrize('sampled,total', [(True, 10), (1, True), (-1, 10), (1, 0),
    (0, 0), (11, 10), (1.2, 10), (1, 10.2), (float('inf'), 10), (1, float('nan')), (1, None)])
def test_sampling_invalid_denominators_unavailable(sampled, total):
    from stegogate.beginner_summary import sampling_summary
    value = sampling_summary({'weight_analysis': {'status': 'completed', 'coverage': {
        'sampled_elements': sampled, 'total_f32_elements': total}}})
    assert value['sampled'] is None and value['total'] is None


def test_sampling_uses_recorded_coverage_not_summary_windows():
    from stegogate.beginner_summary import sampling_summary
    report = fixture_report()
    report['weight_analysis'] = {'status': 'partial', 'coverage': {
        'sampled_elements': 0, 'total_f32_elements': 100}, 'windows': []}
    value = sampling_summary(report)
    assert (value['sampled'], value['total']) == (0, 100)


def test_missing_engines_and_reference_are_not_zero_cards(tmp_path, monkeypatch):
    app = setup_app(tmp_path, monkeypatch, fixture_report()).run(timeout=30)
    assert not app.exception
    metrics = {x.label: x.value for x in app.metric}
    assert metrics['RF pattern matches'] == 'Not available'
    assert metrics['Change from reference'] == 'Not available'
    assert metrics['Weight values sampled'] == 'Not available'
    text = app_text(app)
    assert 'StegoLens' in '\n'.join(x.value for x in app.title)
    assert 'Explore, compare and investigate AI model files' in text
    assert 'steganographic malware detection research' in text
    assert 'not proof of malware or safety' in text
    assert 'not a malware probability' in text


def test_missing_layers_are_coverage_gaps_and_report_unchanged():
    from stegogate.beginner_summary import beginner_summary
    report = fixture_report()
    original = deepcopy(report)
    output = beginner_summary(report)
    assert output['coverage']['completed'] == 0
    assert output['coverage']['total'] == 7
    assert len(output['coverage']['gaps']) == 7
    assert output['rf']['positive'] is None
    assert output['reference']['differing'] is None
    assert output['sampling']['sampled'] is None
    assert report == original
