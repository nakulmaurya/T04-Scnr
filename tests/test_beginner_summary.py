"""Synthetic evidence only: beginner summaries never invent a clean result."""
from copy import deepcopy

import pytest

from stegogate.beginner_summary import (
    beginner_summary, coverage_summary, finite_count, reference_summary, rf_summary,
    sampling_summary,
)


@pytest.mark.parametrize("value", [None, True, False, -1, -0.5, 1.5, "3", [], {}, float("nan"), float("inf"), float("-inf")])
def test_invalid_counts_remain_unknown(value):
    assert finite_count(value) is None


@pytest.mark.parametrize("value,expected", [(0, 0), (4, 4), (3.0, 3), (10**400, 10**400)])
def test_finite_integral_counts(value, expected):
    assert finite_count(value) == expected


def test_rf_requires_completed_engine_and_per_row_threshold():
    report = {"summary": {"ml_positive_window_count": 999}, "ml_analysis": {
        "status": "completed", "manifest": {"threshold": 0.5}, "scores": [
            {"score": 0.9, "threshold": 0.8, "predicted_label": 0},
            {"score": 0.1, "threshold": 0.2, "predicted_label": 1},
            {"score": 0.7}, {"score": float("nan"), "threshold": 0.1},
            {"score": 0.4, "threshold": True}, {"score": 1.1, "threshold": 0.8},
        ]}}
    assert rf_summary(report) == dict(status="completed", recorded=6, eligible=2, positive=1)
    report["ml_analysis"]["status"] = "partial"
    result = rf_summary(report)
    assert result["positive"] is None and result["eligible"] is None


@pytest.mark.parametrize("status", [None, "partial", "failed", "not_available", "unsupported", "skipped", "unavailable"])
def test_noncompleted_rf_never_interpreted_as_zero(status):
    result = rf_summary({"ml_analysis": {"status": status, "scores": [{"score": 0, "threshold": 0.5}]}})
    assert result["positive"] is None
    assert result["eligible"] is None


def test_empty_and_invalid_completed_rf_unknown_not_zero():
    for rows in (None, [], [{"score": 0.1}], [{"score": False, "threshold": 0.5}]):
        result = rf_summary({"ml_analysis": {"status": "completed", "scores": rows}})
        assert result["positive"] is None
        assert result["eligible"] == 0
    assert rf_summary({"ml_analysis": {"status": "completed", "scores": [{"score": 0.1, "threshold": 0.5}]}})["positive"] == 0


@pytest.mark.parametrize("bad", [None, -1, 0.5, True, "100", float("inf"), float("nan")])
def test_reference_and_sampling_invalid_counts_are_paired_unknown(bad):
    ref = reference_summary({"reference_analysis": {"status": "completed", "summary": {
        "differing_sampled_bytes": bad, "compared_bytes": 100}}})
    sampling = sampling_summary({"weight_analysis": {"status": "partial", "coverage": {
        "sampled_elements": bad, "total_f32_elements": 100}}})
    assert ref["differing"] is None and ref["compared"] is None
    assert sampling["sampled"] is None and sampling["total"] is None


@pytest.mark.parametrize("changed,total", [(1, 0), (0, 0), (101, 100), (0, True), (0, float("inf"))])
def test_impossible_population_never_shown(changed, total):
    ref = reference_summary({"reference_analysis": {"status": "completed", "summary": {
        "differing_sampled_bytes": changed, "compared_bytes": total}}})
    sampling = sampling_summary({"weight_analysis": {"status": "completed", "coverage": {
        "sampled_elements": changed, "total_f32_elements": total}}})
    assert ref["differing"] is None and ref["compared"] is None
    assert sampling["sampled"] is None and sampling["total"] is None


def test_denominators_are_recorded_populations_not_artifact_size():
    report = {"artifact": {"size_bytes": 99999}, "summary": {"analyzed_window_count": 123},
        "reference_analysis": {"status": "partial", "summary": {"differing_sampled_bytes": 5, "compared_bytes": 25}},
        "weight_analysis": {"status": "partial", "coverage": {"sampled_elements": 0, "total_f32_elements": 100}}}
    assert reference_summary(report) == dict(status="partial", differing=5, compared=25)
    assert sampling_summary(report) == dict(status="partial", sampled=0, total=100)


def test_summary_is_pure_and_only_completed_counts_as_completed():
    report = {"verdict": "ORIGINAL", "static_analysis": {"status": "completed"},
              "weight_analysis": {"status": "partial"}, "ml_analysis": {"status": "unsupported"}}
    original = deepcopy(report)
    result = beginner_summary(report)
    assert report == original
    assert result["coverage"]["completed"] == 1
    assert result["coverage"]["total"] == 7
    assert len(result["coverage"]["gaps"]) == 6
    assert coverage_summary(None)["completed"] == 0
    assert beginner_summary(None)["reference"]["compared"] is None
