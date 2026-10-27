"""Bounded, presentation-only research views. Never load models or make requests."""

from __future__ import annotations

from collections import Counter

from .ui_helpers import as_dict, finite_number, records, window_rows

MAX_PLOT_WINDOWS = 128


def bitplane_matrix(report: dict) -> dict:
    windows = window_rows(report)[:MAX_PLOT_WINDOWS]
    labels, values, identities = [], [], []
    for row, window in enumerate(windows):
        features = as_dict(window.get("features"))
        values.append(
            [
                float(features[f"bit_{bit}_one_fraction"]) * 100
                if finite_number(features.get(f"bit_{bit}_one_fraction"))
                and 0 <= features[f"bit_{bit}_one_fraction"] <= 1
                else None
                for bit in range(8)
            ]
        )
        labels.append(f"W{row + 1:03d}")
        identities.append(
            f"{str(window.get('tensor', '?'))[:256]} / window {window.get('window_index', '?')}"
        )
    return {
        "labels": labels,
        "values": values,
        "identities": identities,
        "available_windows": len(window_rows(report)),
        "displayed_windows": len(windows),
    }


def _key(row: dict):
    tensor, index = row.get("tensor"), row.get("window_index")
    if not isinstance(tensor, str) or type(index) is not int or index < 0:
        return None
    return tensor, index


def matched_signal_rows(report: dict, feature: str) -> list[dict]:
    """Join by unique recorded identities, never by row order or guessed window IDs."""
    windows = window_rows(report)
    scores = records(as_dict(report.get("ml_analysis")).get("scores"))
    window_counts, score_counts = Counter(_key(w) for w in windows), Counter(_key(s) for s in scores)
    lookup = {_key(s): s for s in scores if _key(s) is not None and score_counts[_key(s)] == 1}
    output = []
    for window in windows[:MAX_PLOT_WINDOWS]:
        key = _key(window)
        if key is None or window_counts[key] != 1 or key not in lookup:
            continue
        score = lookup[key]
        value = as_dict(window.get("features")).get(feature)
        vote = score.get("score")
        if not finite_number(value) or not finite_number(vote) or not 0 <= vote <= 1:
            continue
        output.append(
            {
                "Tensor": key[0],
                "Window": key[1],
                "Feature value": value,
                "Model vote": vote,
                "Recorded threshold": score.get("threshold"),
            }
        )
    return output


def reference_change_rows(report: dict, limit: int = 12) -> list[dict]:
    rows = []
    for row in records(as_dict(report.get("reference_analysis")).get("tensors")):
        changed, compared = row.get("differing_sampled_bytes"), row.get("compared_bytes")
        if not (finite_number(changed) and finite_number(compared) and 0 <= changed <= compared):
            continue
        rows.append(
            {
                "Tensor": str(row.get("tensor", row.get("name", "?")))[:256],
                "Differing sampled bytes": changed,
                "Compared bytes": compared,
            }
        )
    return sorted(rows, key=lambda row: (-row["Differing sampled bytes"], row["Tensor"]))[
        : max(1, min(limit, 24))
    ]


def empirical_cdf(report: dict, feature: str, identity: str) -> list[dict]:
    values = sorted(
        float(v) for w in window_rows(report) if finite_number(v := as_dict(w.get("features")).get(feature))
    )
    # Collapse ties at their upper rank; each curve uses its own observed population.
    counts = Counter(values)
    points, cumulative = [], 0
    for value, count in sorted(counts.items()):
        cumulative += count
        points.append(
            {
                "Artifact": identity,
                "Feature value": value,
                "Cumulative sampled windows (%)": 100 * cumulative / len(values),
                "Finite windows": len(values),
            }
        )
    return points


def compatibility_rows() -> list[dict]:
    return [
        {
            "Artifact": "Safetensors · F32",
            "Inventory": "Supported byte-aligned dtypes",
            "Static": "Reviewed ModelAudit adapter",
            "Weight / RF": "Sampled finite F32 windows",
            "Behavior": "No arbitrary inference",
        },
        {
            "Artifact": "Safetensors · F16 / BF16",
            "Inventory": "Supported byte-aligned dtypes",
            "Static": "Reviewed ModelAudit adapter",
            "Weight / RF": "Descriptive mantissa statistics; no F32 RF",
            "Behavior": "No arbitrary inference",
        },
        {
            "Artifact": "PyTorch ZIP / binary pickle",
            "Inventory": "Signature identification only",
            "Static": "ModelAudit + Picklescan; no deserialization",
            "Weight / RF": "Not available",
            "Behavior": "Not available",
        },
        {
            "Artifact": "GGUF / ONNX / HDF5 / TensorFlow",
            "Inventory": "No reviewed format adapter",
            "Static": "Not enabled in this build",
            "Weight / RF": "Not available",
            "Behavior": "Not available",
        },
        {
            "Artifact": "Sharded or remote repositories",
            "Inventory": "Single local file only",
            "Static": "No automatic downloads",
            "Weight / RF": "No cross-shard aggregation",
            "Behavior": "Not available",
        },
    ]


def feature_axis_label(feature: str) -> str:
    if feature == "low_byte_entropy":
        return "Low-byte entropy (bits, maximum 8)"
    if feature.endswith("_fraction"):
        return feature + " (fraction, 0–1)"
    if feature in {"mean", "std", "mean_abs", "rms", "mean_abs_difference"}:
        return feature + " (F32 weight units)"
    if feature in {"excess_kurtosis", "adjacent_correlation"}:
        return feature + " (dimensionless)"
    return feature + " (recorded units)"
