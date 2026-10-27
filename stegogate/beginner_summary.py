"""Read-only beginner summaries of recorded evidence, never a safety classifier.

Counts retain their populations. Missing or invalid values stay unknown; neither
pipeline summary counts nor default decision thresholds fill evidence gaps.
"""
from __future__ import annotations

import math

LAYERS = (
    ("File-code check (ModelAudit)", "static_analysis"),
    ("Pickle-code check (Picklescan)", "picklescan_analysis"),
    ("Sampled weight statistics", "weight_analysis"),
    ("Learned pattern check (RF)", "ml_analysis"),
    ("Reference comparison", "reference_analysis"),
    ("Half-precision statistics", "precision_analysis"),
    ("Known-trigger behavior", "behavioral_analysis"),
)


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _status(section):
    value = section.get("status")
    return value if isinstance(value, str) and value else "not_available"


def finite_count(value) -> int | None:
    """Accept finite, nonnegative integral int/float counts, never bool/strings."""
    if type(value) is int:
        return value if value >= 0 else None
    if type(value) is float and math.isfinite(value) and value >= 0 and value.is_integer():
        return int(value)
    return None


def _fraction(value):
    if type(value) not in (int, float):
        return False
    # Bounds checked first, so enormous integers never need float conversion.
    return 0 <= value <= 1 and math.isfinite(value)


def coverage_summary(report) -> dict:
    report = _mapping(report)
    layers = [dict(label=label, status=_status(_mapping(report.get(key)))) for label, key in LAYERS]
    return dict(
        completed=sum(row["status"] == "completed" for row in layers),
        total=len(layers),
        gaps=[row for row in layers if row["status"] != "completed"],
        layers=layers,
    )


def sampling_summary(report) -> dict:
    section = _mapping(_mapping(report).get("weight_analysis"))
    coverage = _mapping(section.get("coverage"))
    sampled = finite_count(coverage.get("sampled_elements"))
    total = finite_count(coverage.get("total_f32_elements"))
    status = _status(section)
    if status not in ("completed", "partial") or sampled is None or total is None or total <= 0 or sampled > total:
        sampled = total = None
    return dict(status=status, sampled=sampled, total=total)


def rf_summary(report) -> dict:
    section = _mapping(_mapping(report).get("ml_analysis"))
    status = _status(section)
    raw = section.get("scores")
    rows = raw if isinstance(raw, list) else []
    eligible = [
        row for row in rows
        if isinstance(row, dict) and _fraction(row.get("score")) and _fraction(row.get("threshold"))
    ] if status == "completed" else []
    return dict(
        status=status,
        recorded=len(rows) if isinstance(raw, list) else None,
        eligible=len(eligible) if status == "completed" else None,
        positive=sum(row["score"] >= row["threshold"] for row in eligible) if eligible else None,
    )


def reference_summary(report) -> dict:
    section = _mapping(_mapping(report).get("reference_analysis"))
    summary = _mapping(section.get("summary"))
    status = _status(section)
    differing = finite_count(summary.get("differing_sampled_bytes"))
    compared = finite_count(summary.get("compared_bytes"))
    if status not in ("completed", "partial") or differing is None or compared is None or compared <= 0 or differing > compared:
        differing = compared = None
    return dict(status=status, differing=differing, compared=compared)


def beginner_summary(report) -> dict:
    """Return independent evidence summaries without mutating the original report."""
    return dict(
        coverage=coverage_summary(report),
        sampling=sampling_summary(report),
        rf=rf_summary(report),
        reference=reference_summary(report),
    )
