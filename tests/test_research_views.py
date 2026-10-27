import math
from stegogate.research_views import (
    bitplane_matrix,
    matched_signal_rows,
    reference_change_rows,
    empirical_cdf,
    compatibility_rows,
)


def fixture():
    return {
        "weight_analysis": {
            "windows": [
                {"tensor": "a", "window_index": 0, "features": {"bit_0_one_fraction": 0.5, "entropy": 2}},
                {
                    "tensor": "a",
                    "window_index": 1,
                    "features": {"bit_0_one_fraction": float("nan"), "entropy": 4},
                },
            ]
        },
        "ml_analysis": {
            "scores": [
                {"tensor": "a", "window_index": 1, "score": 0.9, "threshold": 0.7},
                {"tensor": "a", "window_index": 0, "score": 0.1, "threshold": 0.7},
            ]
        },
    }


def test_bitplane_units_and_missing():
    matrix = bitplane_matrix(fixture())
    assert matrix["values"][0] == [50, None, None, None, None, None, None, None]
    assert matrix["values"][1][0] is None
    assert matrix["displayed_windows"] == 2


def test_window_bound():
    report = fixture()
    report["weight_analysis"]["windows"] *= 100
    assert bitplane_matrix(report)["displayed_windows"] == 128
    assert bitplane_matrix(report)["available_windows"] == 200


def test_identity_join_not_row_order():
    rows = matched_signal_rows(fixture(), "entropy")
    assert [(r["Feature value"], r["Model vote"]) for r in rows] == [(2, 0.1), (4, 0.9)]
    assert rows[0]["Recorded threshold"] == 0.7


def test_ambiguous_and_nonfinite_joins_omitted():
    report = fixture()
    report["ml_analysis"]["scores"].append(report["ml_analysis"]["scores"][0])
    assert len(matched_signal_rows(report, "entropy")) == 1
    report["weight_analysis"]["windows"][0]["features"]["entropy"] = math.inf
    assert matched_signal_rows(report, "entropy") == []


def test_reference_bounds_and_order():
    report = {
        "reference_analysis": {
            "tensors": [
                {"tensor": "a", "differing_sampled_bytes": 4, "compared_bytes": 10},
                {"tensor": "b", "differing_sampled_bytes": 9, "compared_bytes": 10},
                {"tensor": "invalid", "differing_sampled_bytes": 50, "compared_bytes": 10},
            ]
        }
    }
    assert [r["Tensor"] for r in reference_change_rows(report)] == ["b", "a"]


def test_cdf_ties_missing_and_denominator():
    report = fixture()
    report["weight_analysis"]["windows"].append(report["weight_analysis"]["windows"][0])
    cdf = empirical_cdf(report, "entropy", "A")
    assert len(cdf) == 2
    assert cdf[0]["Cumulative sampled windows (%)"] == 200 / 3
    assert cdf[-1]["Cumulative sampled windows (%)"] == 100
    assert cdf[-1]["Finite windows"] == 3
    assert empirical_cdf(report, "absent", "A") == []


def test_scope_honest():
    assert len(compatibility_rows()) == 5
    assert "Not available" in str(compatibility_rows())


def test_feature_units_are_explicit():
    from stegogate.research_views import feature_axis_label

    assert "bits" in feature_axis_label("low_byte_entropy")
    assert "fraction" in feature_axis_label("bit_0_one_fraction")
    assert "weight units" in feature_axis_label("rms")
    assert "dimensionless" in feature_axis_label("adjacent_correlation")
