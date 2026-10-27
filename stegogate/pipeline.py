"""Orchestrates independent evidence engines without executing artifact code."""

from __future__ import annotations
import logging
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from .schemas import ScanConfig, ScanReport
from .platform_support import memory_snapshot, capabilities

logger = logging.getLogger(__name__)


def _failure(engine: str, error: Exception) -> dict:
    logger.exception("%s failed", engine)
    return {
        "status": "failed",
        "warnings": [f"{engine} failed ({type(error).__name__}); analysis incomplete."],
    }


def scan_artifact(path, reference_path=None, config=None) -> dict:
    from .intake import inspect_artifact
    from .features import analyze_weights
    from .reference import compare_reference
    from .static_scan import run_modelaudit
    from .ml import score_windows
    from .precision import analyze_precision
    from .picklescan_scan import run_picklescan

    started = time.perf_counter()
    cfg = ScanConfig.model_validate(config or {})
    options = cfg.model_dump()
    target = Path(path)
    limitations = [
        "Research prototype: no finding is not a safety certification.",
        "Weight anomalies do not establish concealed payloads or malicious intent.",
        "Unknown-trigger behavioral backdoors are not detected by this static pipeline.",
        "Weight-forensics coverage is limited to eligible F32 safetensors windows.",
        "Sampled analysis cannot exclude modifications outside examined windows.",
    ]
    try:
        intake = inspect_artifact(target, options)
    except Exception as exc:
        intake = {
            "format": "unknown",
            "size_bytes": 0,
            "sha256": None,
            "tensors": [],
            "errors": [f"Intake failed ({type(exc).__name__})"],
            "warnings": [],
        }
        logger.exception("Artifact intake failed")
    malformed = bool(intake.get("errors"))
    weight = {
        "status": "not_performed",
        "windows": [],
        "tensor_summaries": [],
        "coverage": {},
        "warnings": ["Invalid artifact" if malformed else "Not an eligible safetensors artifact"],
    }
    if not malformed and intake.get("format") == "safetensors":
        try:
            weight = analyze_weights(target, intake, options)
        except Exception as exc:
            weight = {**weight, **_failure("Weight analysis", exc)}
    static = {
        "status": "not_performed",
        "findings": [],
        "engine_version": None,
        "warnings": ["Static engine disabled by configuration"],
        "duration_seconds": 0.0,
    }
    if cfg.run_static and not malformed:
        try:
            static = run_modelaudit(target, options)
        except Exception as exc:
            static = {**static, **_failure("ModelAudit", exc)}
    precision = {"status": "not_performed", "windows": [], "warnings": []}
    if not malformed and intake.get("format") == "safetensors":
        precision = analyze_precision(target, intake, options)
    picklescan = {"status": "not_performed", "findings": [], "warnings": ["Disabled or invalid artifact"]}
    if cfg.run_static and cfg.run_picklescan and not malformed:
        picklescan = run_picklescan(target, options)
    reference = {
        "status": "not_performed",
        "summary": {},
        "tensors": [],
        "warnings": ["No exact reference supplied"],
    }
    if reference_path is not None and not malformed:
        try:
            reference = compare_reference(target, reference_path, options)
        except Exception as exc:
            reference = {**reference, **_failure("Reference comparison", exc)}
    from .storage import data_root

    candidate = data_root() / "detector" / "detector.json"
    detector = (
        cfg.detector_path
        or os.environ.get("STEGOGATE_DETECTOR_PATH")
        or (str(candidate) if candidate.is_file() else None)
    )
    try:
        ml = score_windows(weight.get("windows", []), detector_path=detector)
    except Exception as exc:
        ml = {"scores": [], "manifest": {}, **_failure("Learned detector", exc)}
    if ml.get("status") != "completed":
        limitations.append("No valid learned-detector result is available for this scan.")
    else:
        limitations.append(
            "Learned scores describe controlled-manipulation training patterns, not malware probabilities."
        )
    static_findings = static.get("findings", [])
    ml_positive_count = sum(row.get("predicted_label") == 1 for row in ml.get("scores", []))
    heuristic_count = sum(bool(w.get("evidence")) for w in weight.get("windows", []))
    bad_states = {
        "failed",
        "unavailable",
        "timed_out",
        "partial",
        "unsupported",
        "not_available",
        "not_performed",
    }
    # Optional absent reference is not a failed check. Every primary engine gap is explicit.
    incomplete = any(part.get("status") in bad_states for part in (weight, static, ml))
    if intake.get("format") in ("pickle", "pytorch_zip"):
        incomplete = incomplete or picklescan.get("status") in bad_states
    if precision.get("status") in ("failed", "partial"):
        incomplete = True
    if reference_path is not None:
        incomplete = incomplete or reference.get("status") in bad_states
    if not weight.get("windows"):
        incomplete = True
    if malformed:
        status, verdict = "rejected", "REJECTED — INVALID OR UNSUPPORTED STRUCTURE"
    elif static_findings or picklescan.get("findings") or heuristic_count or ml_positive_count:
        status = "partial" if incomplete else "completed"
        verdict = "REVIEW — INDICATORS REQUIRE INVESTIGATION"
    else:
        status = "partial" if incomplete else "completed"
        verdict = "NO INDICATORS FOUND — LIMITED ANALYSIS"
    original_name = Path((cfg.original_name or target.name).replace("\\", "/")).name[:200]
    report = {
        "schema_version": "1.1",
        "scan_id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact": {
            "original_name": original_name,
            "sha256": intake.get("sha256"),
            "size_bytes": intake.get("size_bytes", 0),
            "format": intake.get("format", "unknown"),
        },
        "config": {k: v for k, v in options.items() if k not in {"detector_path", "original_name"}},
        "status": status,
        "verdict": verdict,
        "summary": {
            "static_finding_count": len(static_findings),
            "picklescan_finding_count": len(picklescan.get("findings", [])),
            "heuristic_window_count": heuristic_count,
            "ml_positive_window_count": ml_positive_count,
            "tensor_count": len(intake.get("tensors", [])),
            "analyzed_window_count": len(weight.get("windows", [])),
        },
        "intake": intake,
        "weight_analysis": weight,
        "ml_analysis": ml,
        "reference_analysis": reference,
        "static_analysis": static,
        "picklescan_analysis": picklescan,
        "precision_analysis": precision,
        "behavioral_analysis": {
            "status": "not_performed",
            "warnings": ["Use isolated allowlisted demo verification; not part of artifact scan"],
        },
        "limitations": limitations,
        "runtime": {
            "device": "cpu",
            "duration_seconds": round(time.perf_counter() - started, 4),
            **memory_snapshot(),
            "platform": platform.system(),
            "capabilities": capabilities(),
            "python_version": platform.python_version(),
        },
    }
    return ScanReport.model_validate(report).model_dump(mode="json")
