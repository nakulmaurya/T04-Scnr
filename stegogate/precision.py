"""Bounded descriptive half-precision analysis; explicitly NOT the F32 RF.

F16: 10 mantissa bits. BF16: 7 mantissa bits; bit 7 is exponent, not mantissa.
No conversion of raw bit features into the F32 feature schema is performed.
"""

from __future__ import annotations
import math
import numpy as np
from .intake import inspect_artifact, _open_regular, _snapshot


def describe_words(words, dtype):
    if (
        not isinstance(words, np.ndarray)
        or words.dtype != np.dtype("<u2")
        or words.ndim != 1
        or not len(words)
    ):
        raise ValueError("expected nonempty little-endian uint16 vector")
    if dtype not in ("F16", "BF16"):
        raise ValueError("unsupported precision")
    bits = 10 if dtype == "F16" else 7
    exponent = (words >> bits) & (31 if dtype == "F16" else 255)
    if np.any(exponent == (31 if dtype == "F16" else 255)):
        raise ValueError("nonfinite window")
    values = (
        words.view("<f2").astype(np.float64)
        if dtype == "F16"
        else ((words.astype("<u4") << 16).view("<f4").astype(np.float64))
    )
    mantissa = words & ((1 << bits) - 1)
    freq = np.bincount(mantissa, minlength=1 << bits).astype(float) / len(words)
    freq = freq[freq > 0]
    features = dict(
        mean=float(values.mean()),
        std=float(values.std()),
        rms=float(np.sqrt(np.mean(values * values))),
        zero_fraction=float(np.mean(values == 0)),
        negative_fraction=float(np.mean(values < 0)),
        subnormal_fraction=float(np.mean((exponent == 0) & (mantissa != 0))),
        negative_zero_fraction=float(np.mean(words == 0x8000)),
        mantissa_entropy=float(-np.sum(freq * np.log2(freq))),
    )
    features.update({f"mantissa_bit_{i}_one_fraction": float(np.mean((words >> i) & 1)) for i in range(bits)})
    if not all(math.isfinite(v) for v in features.values()):
        raise ValueError("nonfinite statistic")
    return features


def analyze_precision(path, inventory, config=None):
    cfg = config or {}
    out = dict(
        status="failed",
        windows=[],
        tensor_summaries=[],
        coverage={},
        ml_status="not_available",
        warnings=[
            "Descriptive F16/BF16 statistics only; F32 Random Forest is not applied. No calibrated anomaly or malware score."
        ],
    )
    try:
        budget = int(cfg.get("max_precision_windows", 64))
        size = int(cfg.get("window_elements", 4096))
        if not 1 <= budget <= 256 or not 256 <= size <= 65536:
            raise ValueError("invalid budget")
        actual = inspect_artifact(path, config)
        if actual["errors"] or actual["sha256"] != inventory.get("sha256"):
            raise ValueError("inventory identity mismatch")
        eligible = sorted(
            [t for t in actual["tensors"] if t["dtype"] in ("F16", "BF16") and t["numel"]],
            key=lambda t: t["name"],
        )
        if not eligible:
            out["status"] = "not_applicable"
            return out
        quotas = [0] * len(eligible)
        if len(eligible) > budget:
            indices = [0] if budget == 1 else [i * (len(eligible) - 1) // (budget - 1) for i in range(budget)]
            for i in indices:
                quotas[i] = 1
        else:
            remaining = budget
            while remaining:
                advanced = False
                for i, t in enumerate(eligible):
                    if remaining and quotas[i] < math.ceil(t["numel"] / size):
                        quotas[i] += 1
                        remaining -= 1
                        advanced = True
                if not advanced:
                    break
        attempted = rejected = 0
        with _open_regular(path) as f:
            before = _snapshot(f)
            for t, q in zip(eligible, quotas):
                count = min(size, t["numel"])
                positions = (
                    ([0] if q == 1 else [i * (t["numel"] - count) // (q - 1) for i in range(q)]) if q else []
                )
                # Equal-spacing can overlap for final short tails; report union coverage honestly.
                intervals = []
                accepted = 0
                for index, start in enumerate(positions):
                    attempted += count
                    f.seek(actual["data_start"] + t["data_offsets"][0] + 2 * start)
                    raw = f.read(2 * count)
                    if len(raw) != 2 * count:
                        raise ValueError("truncated artifact")
                    try:
                        features = describe_words(np.frombuffer(raw, dtype="<u2"), t["dtype"])
                    except ValueError:
                        rejected += 1
                        continue
                    intervals.append((start, start + count))
                    accepted += 1
                    out["windows"].append(
                        dict(
                            tensor=t["name"],
                            dtype=t["dtype"],
                            window_index=index,
                            element_start=start,
                            element_count=count,
                            mantissa_bits=10 if t["dtype"] == "F16" else 7,
                            features=features,
                        )
                    )
                unique = 0
                end = 0
                for a, b in intervals:
                    unique += max(0, b - max(a, end))
                    end = max(end, b)
                out["tensor_summaries"].append(
                    dict(
                        tensor=t["name"],
                        dtype=t["dtype"],
                        numel=t["numel"],
                        windows=accepted,
                        unique_sampled_elements=unique,
                        status="completed" if unique == t["numel"] else "partial",
                    )
                )
            if before != _snapshot(f):
                raise ValueError("artifact changed")
        final = inspect_artifact(path, config)
        if final["errors"] or final["sha256"] != actual["sha256"]:
            raise ValueError("artifact identity changed")
        unique = sum(t["unique_sampled_elements"] for t in out["tensor_summaries"])
        total = sum(t["numel"] for t in eligible)
        out["coverage"] = dict(
            artifact_sha256=actual["sha256"],
            total_half_elements=total,
            unique_sampled_elements=unique,
            attempted_elements=attempted,
            rejected_windows=rejected,
            full_coverage=unique == total,
            sampling="bounded deterministic evenly-spaced windows; overlaps possible and union counted",
        )
        out["status"] = "completed" if unique == total and not rejected else "partial"
    except (OSError, ValueError, TypeError, OverflowError):
        out.update(
            status="failed", windows=[], warnings=out["warnings"] + ["Precision analysis failed closed."]
        )
    return out
