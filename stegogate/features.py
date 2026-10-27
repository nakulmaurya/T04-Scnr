"""Deterministic bounded F32 windows; exploratory features, not a detector verdict."""

from __future__ import annotations
import math
from pathlib import Path
import numpy as np
from .intake import inspect_artifact, _open_regular, _snapshot, _limit

FEATURE_NAMES = [
    "mean",
    "std",
    "mean_abs",
    "rms",
    "zero_fraction",
    "negative_fraction",
    "excess_kurtosis",
    "adjacent_correlation",
    "mean_abs_difference",
    "low_byte_entropy",
    "lsb_transition_fraction",
] + [f"bit_{b}_one_fraction" for b in range(8)]


def _window_features(values):
    x = values.astype(np.float64)
    mean = float(x.mean())
    centered = x - mean
    variance = float(np.mean(centered * centered))
    std = math.sqrt(variance)
    kurt = float(np.mean((centered / std) ** 4) - 3) if std else 0.0
    a, b = x[:-1], x[1:]
    ac, bc = a - a.mean(), b - b.mean()
    denom = float(np.linalg.norm(ac) * np.linalg.norm(bc))
    corr = float(np.dot(ac, bc) / denom) if denom else 0.0
    bits = values.view("<u4")
    low = bits & 255
    freq = np.bincount(low, minlength=256).astype(float) / len(bits)
    nonzero = freq[freq > 0]
    result = dict(
        mean=mean,
        std=std,
        mean_abs=float(np.abs(x).mean()),
        rms=float(np.sqrt(np.mean(x * x))),
        zero_fraction=float(np.mean(x == 0)),
        negative_fraction=float(np.mean(x < 0)),
        excess_kurtosis=kurt,
        adjacent_correlation=corr,
        mean_abs_difference=float(np.abs(np.diff(x)).mean()),
        low_byte_entropy=float(-np.sum(nonzero * np.log2(nonzero))),
        lsb_transition_fraction=float(np.mean((bits[:-1] & 1) != (bits[1:] & 1))),
    )
    result.update({f"bit_{i}_one_fraction": float(np.mean((bits >> i) & 1)) for i in range(8)})
    if not all(math.isfinite(v) for v in result.values()):
        raise ValueError("non-finite computed feature")
    return result


def _heuristic(f, n):
    evidence = []
    # Wide 8-sigma threshold is deliberately conservative but NOT calibrated.
    threshold = max(0.12, 8 * math.sqrt(0.25 / n))
    bias = max(abs(f[f"bit_{b}_one_fraction"] - 0.5) for b in range(8))
    if f["std"] == 0:
        evidence.append(
            "Degenerate constant window; bit statistics are not interpretable as steganography evidence."
        )
        return 0.0, evidence
    if bias > threshold:
        evidence.append(
            "Low F32 bit-plane imbalance exceeds an uncalibrated randomness heuristic; benign quantization/structure can cause this."
        )
    if f["low_byte_entropy"] < 6.0:
        evidence.append(
            "Low-byte entropy is low; natural numeric structure or precision reduction may explain it."
        )
    score = max(0.0, min(1.0, (bias - threshold) / max(0.01, 0.5 - threshold)))
    return float(score), evidence


def analyze_weights(path: str | Path, inventory: dict, config: dict | None = None) -> dict:
    out = dict(
        status="failed",
        feature_names=list(FEATURE_NAMES),
        windows=[],
        tensor_summaries=[],
        coverage={},
        warnings=[
            "Window anomaly scores are uncalibrated heuristics, not malware probabilities. Natural F32 LSBs can resemble random data."
        ],
    )
    try:
        max_windows = _limit(config, "max_windows", 128, 4096)
        window_size = _limit(config, "window_elements", 4096, 65536)
        minimum = _limit(config, "min_window_elements", 32, 65536)
        if minimum < 2:
            raise ValueError("min_window_elements must be at least 2")
        actual = inspect_artifact(path, config)
        if actual["errors"] or inventory.get("errors"):
            out["warnings"].extend(actual["errors"] or inventory["errors"])
            return out
        if inventory.get("sha256") != actual["sha256"]:
            out["warnings"].append("Inventory SHA-256 does not match artifact.")
            return out
        if actual["format"] != "safetensors":
            out["status"] = "unsupported"
            return out
        tensors = actual["tensors"]
        eligible = []
        total_f32 = sum(t["numel"] for t in tensors if t["dtype"] == "F32")
        for t in tensors:
            reason = None
            if t["dtype"] != "F32":
                reason = "Only F32 weight analysis is supported."
            elif t["numel"] == 0:
                reason = "Empty tensor has no numerical evidence."
            elif t["numel"] < minimum or window_size < minimum:
                reason = "Tensor/window too small for configured statistics."
            summary = dict(
                tensor=t["name"],
                dtype=t["dtype"],
                numel=t["numel"],
                status="skipped" if reason else "pending",
                reason=reason,
                sampled_elements=0,
                windows=0,
                rejected_windows=0,
            )
            out["tensor_summaries"].append(summary)
            if not reason:
                eligible.append((t, summary, math.ceil(t["numel"] / window_size)))
        # Fair round-robin budget assignment in canonical name order; deterministic
        # even when source header ordering differs. Windows within each tensor are
        # evenly spaced and non-overlapping (except never needed final short tail).
        eligible.sort(key=lambda item: item[0]["name"])
        quotas = [0] * len(eligible)
        budget = max_windows
        if len(eligible) > max_windows:
            # Cover the canonical tensor-name range rather than silently favoring
            # the first tensors when the tensor count itself exceeds the budget.
            indices = (
                [0]
                if max_windows == 1
                else [i * (len(eligible) - 1) // (max_windows - 1) for i in range(max_windows)]
            )
            for i in indices:
                quotas[i] = 1
            budget = 0
        while budget:
            progressed = False
            for i, (_, _, capacity) in enumerate(eligible):
                if quotas[i] < capacity and budget:
                    quotas[i] += 1
                    budget -= 1
                    progressed = True
            if not progressed:
                break
        attempted_elements = 0
        with _open_regular(path) as f:
            before = _snapshot(f)
            for (t, summary, _), quota in zip(eligible, quotas):
                if not quota:
                    summary.update(status="skipped", reason="Global max_windows budget exhausted.")
                    continue
                count = min(window_size, t["numel"])
                # ceil(capacity) may produce overlapping windows if final tensor
                # is not a multiple of window size: reduce quota to disjoint count.
                quota = min(quota, max(1, t["numel"] // count))
                positions = (
                    [0] if quota == 1 else [(i * (t["numel"] - count)) // (quota - 1) for i in range(quota)]
                )
                for index, start in enumerate(positions):
                    attempted_elements += count
                    f.seek(actual["data_start"] + t["data_offsets"][0] + start * 4)
                    raw = f.read(count * 4)
                    if len(raw) != count * 4:
                        raise ValueError("artifact truncated during feature read")
                    values = np.frombuffer(raw, dtype="<f4")
                    if not np.isfinite(values).all():
                        summary["rejected_windows"] += 1
                        summary["reason"] = "Non-finite values in sampled window; entire window excluded."
                        continue
                    feat = _window_features(values)
                    score, evidence = _heuristic(feat, count)
                    out["windows"].append(
                        dict(
                            tensor=t["name"],
                            window_index=index,
                            element_start=start,
                            element_count=count,
                            features=feat,
                            anomaly_score=score,
                            evidence=evidence,
                        )
                    )
                    summary["windows"] += 1
                    summary["sampled_elements"] += count
                summary["status"] = (
                    "partial"
                    if summary["rejected_windows"] or summary["sampled_elements"] < t["numel"]
                    else "completed"
                )
                if not summary["windows"]:
                    summary["status"] = "skipped"
            if before != _snapshot(f):
                raise ValueError("artifact changed during analysis")
        # Check hash again after sampling to detect replacement or in-place mutation.
        final = inspect_artifact(path, config)
        if final["errors"] or final["sha256"] != actual["sha256"]:
            raise ValueError("artifact identity changed during analysis")
        sampled = sum(w["element_count"] for w in out["windows"])
        out["coverage"] = dict(
            artifact_sha256=actual["sha256"],
            total_f32_elements=total_f32,
            eligible_f32_elements=sum(t["numel"] for t, _, _ in eligible),
            sampled_elements=sampled,
            attempted_elements=attempted_elements,
            sampled_fraction=sampled / total_f32 if total_f32 else 0.0,
            windows_analyzed=len(out["windows"]),
            max_windows=max_windows,
            window_elements=window_size,
            sampling="deterministic evenly-spaced, disjoint windows; single window starts at zero",
            full_coverage=sampled == total_f32 and total_f32 > 0,
        )
        incomplete = any(
            s["status"] != "completed" or s["sampled_elements"] < s["numel"] for s in out["tensor_summaries"]
        )
        out["status"] = (
            ("partial" if incomplete else "completed")
            if out["windows"]
            else ("partial" if eligible else "unsupported")
        )
        if not out["coverage"]["full_coverage"]:
            out["warnings"].append(
                "Only sampled finite F32 windows were analyzed; unsampled bytes may contain unobserved content."
            )
    except (OSError, ValueError, TypeError, OverflowError) as e:
        out["status"] = "failed"
        out["windows"] = []
        out["warnings"].append(f"{type(e).__name__}: {str(e)[:300]}")
    return out
