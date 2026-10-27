"""Bounded hash-linked reference differences. A difference is not maliciousness."""

from __future__ import annotations
from pathlib import Path
import numpy as np
from .intake import inspect_artifact, _open_regular, _snapshot, _limit


def compare_reference(path: str | Path, reference_path: str | Path, config: dict | None = None) -> dict:
    out = dict(
        status="failed",
        summary={},
        tensors=[],
        warnings=[
            "Reference differences do not imply malicious changes; provenance and reference trust are not established by this comparison."
        ],
    )
    try:
        maximum = _limit(config, "max_reference_windows", 128, 4096)
        window_bytes = _limit(config, "reference_window_bytes", 65536, 1024 * 1024)
        left, right = inspect_artifact(path, config), inspect_artifact(reference_path, config)
        out["summary"] = dict(
            artifact_sha256=left["sha256"],
            reference_sha256=right["sha256"],
            identical_artifact=bool(left["sha256"] and left["sha256"] == right["sha256"]),
            compared_bytes=0,
            differing_sampled_bytes=0,
            compared_tensors=0,
            added_tensors=0,
            removed_tensors=0,
            incompatible_tensors=0,
            full_compatible_data_coverage=False,
        )
        if left["errors"] or right["errors"]:
            out["warnings"] += ["Artifact: " + e for e in left["errors"]] + [
                "Reference: " + e for e in right["errors"]
            ]
            return out
        if left["format"] != "safetensors" or right["format"] != "safetensors":
            out["status"] = "unsupported"
            out["warnings"].append(
                "Both files must be structurally valid safetensors; no unsafe deserialization is attempted."
            )
            return out
        lm = {t["name"]: t for t in left["tensors"]}
        rm = {t["name"]: t for t in right["tensors"]}
        eligible = []
        for name in sorted(lm.keys() | rm.keys()):
            a, b = lm.get(name), rm.get(name)
            if a is None or b is None:
                status = "removed" if a is None else "added"
                out["summary"][status + "_tensors"] += 1
                out["tensors"].append(dict(tensor=name, status=status, compared_bytes=0))
            elif a["dtype"] != b["dtype"] or a["shape"] != b["shape"]:
                out["summary"]["incompatible_tensors"] += 1
                out["tensors"].append(
                    dict(
                        tensor=name,
                        status="incompatible",
                        compared_bytes=0,
                        artifact_dtype=a["dtype"],
                        reference_dtype=b["dtype"],
                        artifact_shape=a["shape"],
                        reference_shape=b["shape"],
                    )
                )
            else:
                summary = dict(
                    tensor=name,
                    status="pending",
                    nbytes=a["nbytes"],
                    compared_bytes=0,
                    differing_sampled_bytes=0,
                    sample_windows=[],
                    dtype=a["dtype"],
                )
                out["tensors"].append(summary)
                eligible.append((a, b, summary))
        quotas = [0] * len(eligible)
        budget = maximum
        while budget:
            progress = False
            for i, (a, _, _) in enumerate(eligible):
                # Compare whole dtype units, even for non-F32 tensors.
                if (
                    a["nbytes"]
                    and quotas[i] < max(1, a["nbytes"] // min(a["nbytes"], window_bytes))
                    and budget
                ):
                    quotas[i] += 1
                    budget -= 1
                    progress = True
            if not progress:
                break
        with _open_regular(path) as af, _open_regular(reference_path) as bf:
            a_before, b_before = _snapshot(af), _snapshot(bf)
            for (a, b, row), quota in zip(eligible, quotas):
                if a["nbytes"] == 0:
                    row.update(status="identical_empty", full_coverage=True)
                    out["summary"]["compared_tensors"] += 1
                    continue
                if not quota:
                    row.update(status="not_compared", full_coverage=False)
                    continue
                unit = a["nbytes"] // a["numel"]
                count = min(a["nbytes"], max(unit, window_bytes // unit * unit))
                quota = min(quota, max(1, a["nbytes"] // count))
                units = (a["nbytes"] - count) // unit
                starts = [0] if quota == 1 else [(i * units // (quota - 1)) * unit for i in range(quota)]
                for start in starts:
                    af.seek(left["data_start"] + a["data_offsets"][0] + start)
                    bf.seek(right["data_start"] + b["data_offsets"][0] + start)
                    x, y = af.read(count), bf.read(count)
                    if len(x) != count or len(y) != count:
                        raise ValueError("truncated tensor during comparison")
                    difference = sum(v != w for v, w in zip(x, y))
                    win = dict(byte_start=start, byte_count=count, differing_bytes=difference)
                    if a["dtype"] == "F32":
                        nx, ny = (
                            np.frombuffer(x, dtype="<f4").astype(np.float64),
                            np.frombuffer(y, dtype="<f4").astype(np.float64),
                        )
                        finite = np.isfinite(nx) & np.isfinite(ny)
                        win["nonfinite_pairs"] = int(np.sum(~finite))
                        win["finite_pairs"] = int(np.sum(finite))
                        win["finite_mean_abs_difference"] = (
                            float(np.abs(nx[finite] - ny[finite]).mean()) if finite.any() else None
                        )
                        win["finite_max_abs_difference"] = (
                            float(np.abs(nx[finite] - ny[finite]).max()) if finite.any() else None
                        )
                    row["sample_windows"].append(win)
                    row["compared_bytes"] += count
                    row["differing_sampled_bytes"] += difference
                row["full_coverage"] = row["compared_bytes"] == a["nbytes"]
                row["status"] = (
                    ("different" if row["differing_sampled_bytes"] else "identical")
                    if row["full_coverage"]
                    else (
                        "sampled_differences" if row["differing_sampled_bytes"] else "no_sampled_difference"
                    )
                )
                out["summary"]["compared_tensors"] += 1
                out["summary"]["compared_bytes"] += row["compared_bytes"]
                out["summary"]["differing_sampled_bytes"] += row["differing_sampled_bytes"]
            if _snapshot(af) != a_before or _snapshot(bf) != b_before:
                raise ValueError("artifact changed during reference comparison")
        # Hash equality covers headers and unsampled bytes; sampled equality does not.
        for p, initial in [(path, left), (reference_path, right)]:
            final = inspect_artifact(p, config)
            if final["errors"] or final["sha256"] != initial["sha256"]:
                raise ValueError("artifact identity changed during comparison")
        full = all(row.get("full_coverage", False) for _, _, row in eligible)
        out["summary"]["full_compatible_data_coverage"] = full
        mismatched = any(
            out["summary"][k] for k in ["added_tensors", "removed_tensors", "incompatible_tensors"]
        )
        out["status"] = "completed" if full and not mismatched else "partial"
        if not full:
            out["warnings"].append(
                "Bounded sampling only; no sampled difference does not establish tensor equality."
            )
        if mismatched:
            out["warnings"].append(
                "Added, removed, or incompatible tensors were listed but not numerically compared."
            )
    except (OSError, ValueError, TypeError, OverflowError) as e:
        out["status"] = "failed"
        out["tensors"] = []
        out["warnings"].append(f"{type(e).__name__}: {str(e)[:300]}")
    return out
