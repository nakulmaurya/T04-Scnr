"""Pure presentation helpers. No model loading, network, or scan execution."""

from __future__ import annotations

import html
import json
import math
import re
from pathlib import Path
from typing import Any
from uuid import UUID

MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
ENGINE_KEYS = {
    "Artifact inspection": "intake",
    "Weight statistics": "weight_analysis",
    "ModelAudit static scan": "static_analysis",
    "Picklescan disassembly": "picklescan_analysis",
    "F16 / BF16 statistics": "precision_analysis",
    "Learned manipulation detector": "ml_analysis",
    "Reference comparison": "reference_analysis",
    "Known-trigger verification": "behavioral_analysis",
}


def as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def records(value: Any) -> list[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def valid_report_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def display_value(value: Any) -> str:
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def human_bytes(value: Any) -> str:
    if not finite_number(value) or value < 0:
        return "Not available"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:,.1f} {unit}" if unit != "B" else f"{value:,.0f} B"
        value /= 1024
    return "Not available"


def report_summary(report: dict) -> dict:
    art = as_dict(report.get("artifact"))
    weights = as_dict(report.get("weight_analysis"))
    return {
        "Scan ID": report.get("scan_id"),
        "Created": report.get("created_at"),
        "Artifact": art.get("original_name"),
        "Format": art.get("format"),
        "Size": human_bytes(art.get("size_bytes")),
        "SHA-256": art.get("sha256"),
        "Scan status": report.get("status", "not_available"),
        "Inventoried tensors": len(records(as_dict(report.get("intake")).get("tensors")))
        if isinstance(as_dict(report.get("intake")).get("tensors"), list)
        else None,
        "Reported windows": len(records(weights.get("windows")))
        if isinstance(weights.get("windows"), list)
        else None,
    }


def coverage_rows(report: dict) -> list[dict]:
    rows = []
    for title, key in ENGINE_KEYS.items():
        section = as_dict(report.get(key))
        status = section.get("status")
        if key == "intake" and section and status is None:
            status = "errors_reported" if section.get("errors") else "inventory_reported"
        rows.append(
            {
                "Analysis layer": title,
                "Status": status or "not_available",
                "Warnings": len(section.get("warnings", []))
                if isinstance(section.get("warnings"), list)
                else 0,
            }
        )
    return rows


def tensor_rows(report: dict) -> list[dict]:
    rows = []
    for tensor in records(as_dict(report.get("intake")).get("tensors")):
        rows.append({k: tensor.get(k) for k in ("name", "dtype", "shape", "numel", "nbytes", "data_offsets")})
    return rows


def window_rows(report: dict, tensor: str | None = None) -> list[dict]:
    windows = records(as_dict(report.get("weight_analysis")).get("windows"))
    return [w for w in windows if tensor is None or w.get("tensor") == tensor]


def numeric_feature_names(windows: list[dict]) -> list[str]:
    return sorted({k for w in windows for k, v in as_dict(w.get("features")).items() if finite_number(v)})


def feature_points(windows: list[dict], feature: str) -> list[dict]:
    """Missing/nonfinite features are omitted, never imputed to zero."""
    return [
        {
            "Tensor": display_value(w.get("tensor")),
            "Window": w.get("window_index"),
            "Element start": w.get("element_start"),
            "Value": as_dict(w.get("features"))[feature],
        }
        for w in windows
        if finite_number(as_dict(w.get("features")).get(feature))
    ]


def bitplane_points(features: dict) -> list[dict]:
    """Recognize explicit plane-number fields only; never infer plane values."""
    result = []
    pattern = re.compile(r"(?:bit[_-]?plane|bit|lsb)[_-]?(\d+)[_-](.+)", re.I)
    for key, value in features.items():
        match = pattern.fullmatch(str(key))
        if match and 0 <= int(match[1]) <= 7 and finite_number(value):
            result.append({"Plane": int(match[1]), "Measure": match[2], "Value": value, "Field": key})
    return sorted(result, key=lambda x: (x["Measure"], x["Plane"]))


def safe_local_json(root: Path, path: Path, max_bytes: int = MAX_JSON_BYTES) -> dict:
    """Only bounded regular JSON beneath a trusted root, including symlink resolution."""
    root, path = root.resolve(), path.resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.suffix.lower() != ".json":
        raise ValueError("JSON path is outside the prepared demo directory or invalid")
    if path.stat().st_size > max_bytes:
        raise ValueError("Prepared JSON exceeds display limit")
    # Bounded read remains bounded even if a file grows after stat.
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("Prepared JSON exceeds display limit")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


def demo_documents(root: Path, limit: int = 60) -> list[tuple[Path, dict]]:
    """Read prepared evidence, never execute it or navigate user-supplied host paths."""
    if root.is_symlink() or not root.is_dir():
        return []
    output = []
    # Known small demo tree; do not recursively inspect uploaded artifacts.
    candidates = sorted(root.glob("*.json")) + sorted(root.glob("*/*.json")) + sorted(root.glob("*/*/*.json"))
    for path in candidates[:limit]:
        try:
            output.append((path, safe_local_json(root, path)))
        except (ValueError, OSError, json.JSONDecodeError, UnicodeError):
            continue
    return output


def export_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False, default=str)


def export_html(report: dict) -> str:
    """Offline evidence document; every dynamic string is escaped; no scripts/CDN."""

    def esc(value):
        return html.escape(display_value(value), quote=True)

    summary = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in report_summary(report).items()
    )
    layers = "".join(
        f"<tr><th>{esc(r['Analysis layer'])}</th><td>{esc(r['Status'])}</td></tr>"
        for r in coverage_rows(report)
    )
    sections = "".join(
        f"<section><h2>{esc(name)}</h2><pre>{esc(export_json(as_dict(report.get(key))))}</pre></section>"
        for name, key in ENGINE_KEYS.items()
    )
    return (
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>T04-Scnr — evidence report</title><style>
body{font:16px/1.6 system-ui,sans-serif;color:#263346;background:#f8fafc;margin:0;padding:32px}
main{max-width:1100px;margin:auto}h1{font-size:32px}h2{font-size:22px;margin-top:32px}
table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;border-bottom:1px solid #dce3ec;padding:10px;overflow-wrap:anywhere}th{width:28%}
pre{background:white;border:1px solid #dce3ec;padding:20px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px}
.notice{border-left:4px solid #2783de;padding:16px;background:#e5f2fc}</style></head><body><main>
<h1>T04-Scnr / evidence report</h1><p class="notice">CPU-only prototype. No universal malware verdict. Missing analysis is not a clean result. Statistical anomalies and model votes are not malware probabilities.</p>"""
        + f"<table>{summary}</table><h2>Analysis coverage</h2><table>{layers}</table>{sections}<h2>Limitations</h2><pre>{esc(report.get('limitations', []))}</pre><h2>Complete report</h2><pre>{esc(export_json(report))}</pre></main></body></html>"
    )
