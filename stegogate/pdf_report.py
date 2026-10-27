"""Offline, presentation-only PDF export of an immutable JSON scan report.

Only ReportLab's built-in fonts and vector primitives are used. No paths or
URLs from evidence are opened. See docs/PDF_REPORT.md for limits and semantics.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import unicodedata
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    Flowable,
    LongTable,
    TableStyle,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 24
MAX_TEXT = 800
MAX_ROWS = 12
MAX_LEAVES = 650
MAX_PAGES = 48
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
GROQ_MODELS = ("openai/gpt-oss-20b", "openai/gpt-oss-120b")
WIDTH = A4[0] - 104


def _dict(value):
    return value if isinstance(value, dict) else {}


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _canonical(report):
    """Validate JSON primitives with bounded traversal before canonical encoding."""
    if type(report) is not dict:
        raise ValueError("report must be a JSON object")
    stack, nodes, chars = [(report, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("report exceeds JSON node/depth limit")
        if type(item) in (dict, list) and nodes + len(stack) + len(item) > MAX_NODES:
            raise ValueError("report exceeds JSON node limit")
        if type(item) is dict:
            for key, val in item.items():
                if type(key) is not str:
                    raise ValueError("report keys must be strings")
                chars += len(key)
                stack.append((val, depth + 1))
        elif type(item) is list:
            stack.extend((val, depth + 1) for val in item)
        elif type(item) is str:
            chars += len(item)
        elif item is not None and type(item) not in (bool, int, float):
            raise ValueError("report contains a non-JSON value")
        if chars > MAX_INPUT_BYTES:
            raise ValueError("report exceeds input text limit")
    try:
        raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("report is not finite canonical JSON") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("report exceeds canonical JSON byte limit")
    return hashlib.sha256(raw).hexdigest()


def _safe(value, limit=MAX_TEXT):
    """Literal PDF text; unsupported Unicode is visible, not a missing glyph."""
    text = str(value)
    truncated = len(text) > limit
    text = text[:limit]
    out = []
    for c in text:
        if unicodedata.category(c) in ("Cc", "Cs", "Cf"):
            out.append(" " if c in "\n\r\t" else "[U+%04X]" % ord(c))
            continue
        try:
            c.encode("cp1252")
            out.append(c)
        except UnicodeEncodeError:
            out.append("[U+%04X]" % ord(c))
    result = "".join(out)
    # Expanded Unicode escapes are bounded as well.
    if len(result) > limit:
        result, truncated = result[:limit], True
    return result + (" [text omitted: display limit]" if truncated else "")


class _Limit(Exception):
    pass


class _Buffer(io.BytesIO):
    def write(self, value):
        if self.tell() + len(value) > MAX_OUTPUT_BYTES:
            raise _Limit("PDF output byte limit")
        return super().write(value)


class _Doc(SimpleDocTemplate):
    def afterPage(self):
        if self.page > MAX_PAGES:
            raise _Limit("PDF page limit")


class _Rule(Flowable):
    def __init__(self):
        super().__init__()
        self.width, self.height = WIDTH, 12
        self.keepWithNext = True

    def draw(self):
        self.canv.setStrokeColor(colors.HexColor("#b0b0b0"))
        self.canv.line(0, 6, WIDTH, 6)


class _Writer:
    def __init__(self, digest, scale=1):
        self.digest = digest
        self.story = []
        self.remaining = int(MAX_LEAVES * scale)
        self.section_limit = max(8, int(55 * scale))
        self.row_limit = max(1, int(MAX_ROWS * scale))
        self.appendix_left = 7
        self.notes = []
        base = dict(
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#292929"),
            spaceAfter=7,
            splitLongWords=True,
            alignment=TA_LEFT,
        )
        self.styles = {
            "body": ParagraphStyle("body", **base),
            "small": ParagraphStyle("small", **{**base, "fontSize": 9, "leading": 12}),
            "context": ParagraphStyle(
                "context", **{**base, "fontSize": 9, "leading": 12, "keepWithNext": True}
            ),
            "field": ParagraphStyle("field", **{**base, "fontSize": 10, "leading": 13, "spaceAfter": 3}),
            "title": ParagraphStyle("title", **{**base, "fontSize": 32, "leading": 37, "spaceAfter": 20}),
            "h1": ParagraphStyle(
                "h1",
                **{
                    **base,
                    "fontSize": 19,
                    "leading": 24,
                    "spaceBefore": 20,
                    "spaceAfter": 12,
                    "keepWithNext": True,
                },
            ),
            "h2": ParagraphStyle(
                "h2", **{**base, "fontSize": 13, "leading": 18, "spaceBefore": 10, "keepWithNext": True}
            ),
        }

    def p(self, text, style="body"):
        self.story.append(Paragraph(escape(_safe(text)), self.styles[style]))

    def heading(self, text):
        self.p(text, "h1")
        self.story.append(_Rule())

    def fields(self, obj, path, limit=None):
        """Flatten a bounded prefix with full relative evidence paths; never execute markup."""
        allowance = min(self.remaining, self.section_limit if limit is None else limit)
        self.p("Evidence path: " + path, "context")
        used, omitted = 0, False
        rendered = []
        stack = [(path, obj)]
        if obj is None:
            self.p("Not recorded.")
            return
        while stack:
            name, val = stack.pop()
            if used >= allowance:
                omitted = True
                break
            if isinstance(val, dict) and val:
                priority = (
                    "status",
                    "engine_version",
                    "detector_sha256",
                    "artifact_sha256",
                    "reference_sha256",
                    "threshold",
                    "score_type",
                    "scope",
                    "source_description",
                    "evaluation",
                    "metrics",
                    "warnings",
                    "errors",
                    "coverage",
                )
                ordered = {**{k: val[k] for k in priority if k in val}, **val}
                stack.extend((name + "." + str(k), v) for k, v in reversed(list(ordered.items())))
                continue
            if isinstance(val, list) and val:
                stack.extend((f"{name}[{i}]", v) for i, v in reversed(list(enumerate(val))))
                continue
            if val is None:
                text = "Not recorded (null)"
            elif val == {} or val == []:
                text = "Empty recorded collection"
            else:
                text = str(val)
            # Static markup only; arbitrary labels and values are independently escaped.
            # Relative labels avoid repeating section paths on every scalar. Paragraph
            # splitting keeps long names/hashes safe without unsplittable table rows.
            label = name[len(path) :].lstrip(".") or path
            rendered.append(
                (
                    Paragraph(
                        "<b>" + escape(_safe(label)) + "</b> — " + escape(_safe(text)), self.styles["field"]
                    ),
                    max(96 if "sha256" in label.lower() else 0, len(_safe(label)) + len(_safe(text))),
                )
            )
            used += 1
        # Pair short values for audit readability; long hashes / paths span both
        # columns. Tables split by row, with every cell explicitly size-bounded.
        pairs, spans, pending = [], [], None
        for paragraph, length in rendered:
            if length > 95:
                if pending is not None:
                    pairs.append([pending, ""])
                    pending = None
                spans.append(len(pairs))
                pairs.append([paragraph, ""])
            elif pending is None:
                pending = paragraph
            else:
                pairs.append([pending, paragraph])
                pending = None
        if pending is not None:
            pairs.append([pending, ""])
        if pairs:
            table = LongTable(pairs, colWidths=[WIDTH / 2, WIDTH / 2], hAlign="LEFT")
            table.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 1),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        *[("SPAN", (0, i), (1, i)) for i in spans],
                    ]
                )
            )
            self.story.extend([table, Spacer(1, 5)])
        self.remaining -= used
        if omitted:
            self.p(
                f"Evidence omitted at {path}: field display budget reached; consult the original JSON.",
                "small",
            )
            self.notes.append(f"{path}: additional fields omitted")

    def section(self, title, report, key, caution=None, exclude=()):
        self.heading(title)
        if caution:
            self.p(caution)
        section = report.get(key)
        if not isinstance(section, dict) or not section:
            self.p("Not recorded / unavailable in this report. Absence is not a negative finding.")
            return
        self.fields({k: v for k, v in section.items() if k not in exclude}, key)

    def rows(self, report, section, collection, title):
        self.p(title, "h2")
        value = _dict(report.get(section)).get(collection)
        if not isinstance(value, list):
            self.appendix_left -= 1
            self.p("Not recorded.")
            return
        self.p(
            f"Recorded entries: {len(value)}. Displaying at most {self.row_limit} in recorded order.", "small"
        )
        collection_budget = min(self.remaining, max(22, self.remaining // self.appendix_left))
        self.appendix_left -= 1
        used_before = self.remaining
        budget_omitted = False
        for i, row in enumerate(value[: self.row_limit]):
            if used_before - self.remaining >= collection_budget:
                omitted = len(value) - i
                budget_omitted = True
                note = f"{section}.{collection}: {omitted} entries omitted by collection field budget"
                self.p(note, "small")
                self.notes.append(note)
                break
            if isinstance(row, dict):
                priority = (
                    "tensor",
                    "name",
                    "dtype",
                    "window_index",
                    "element_start",
                    "element_count",
                    "status",
                    "anomaly_score",
                    "evidence",
                    "score",
                    "threshold",
                    "predicted_label",
                    "compared_bytes",
                    "differing_sampled_bytes",
                )
                row = {**{k: row[k] for k in priority if k in row}, **row}
            self.fields(row, f"{section}.{collection}[{i}]", limit=22)
        if len(value) > self.row_limit and not budget_omitted:
            note = f"{section}.{collection}: {len(value) - self.row_limit} entries omitted by row cap"
            self.p(note, "small")
            self.notes.append(note)

    def table(self, headers, rows, widths=None):
        """Small, splittable, literal-text tables; no HTML or report code is run."""
        if not rows:
            self.p("Not recorded.")
            return
        widths = widths or [WIDTH / len(headers)] * len(headers)

        def cell(value, header=False):
            text = escape(_safe("Not recorded" if value is None else value, 320))
            return Paragraph(("<b>" + text + "</b>") if header else text, self.styles["field"])

        data = [[cell(h, True) for h in headers]]
        data += [[cell(v) for v in row] for row in rows[:32]]
        table = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ededed")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#999999")),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ]
            )
        )
        self.story.extend([table, Spacer(1, 8)])
        if len(rows) > 32:
            self.p(f"{len(rows) - 32} table rows omitted by display cap.", "small")

    def bar(self, title, values, maximum, unit, caption, thresholds=None):
        """Native vector bars with a readable scale and optional recorded thresholds."""
        if not values or not _number(maximum) or maximum <= 0:
            return
        self.p(title, "h2")
        h = 48 + 29 * len(values)
        d = Drawing(WIDTH, h)
        x0, plot = 116, WIDTH - 176
        for i in range(5):
            x = x0 + plot * i / 4
            d.add(Line(x, 25, x, h - 10, strokeColor=colors.HexColor("#e5e5e5"), strokeWidth=0.4))
            d.add(
                String(x, 11, f"{maximum * i / 4:g}", textAnchor="middle", fontName="Helvetica", fontSize=9)
            )
        for i, (label, val) in enumerate(values):
            y = h - 25 - 29 * i
            d.add(String(0, y + 1, _safe(label, 22), fontName="Helvetica", fontSize=9))
            d.add(
                Rect(
                    x0, y, plot * (val / maximum), 12, fillColor=colors.HexColor("#777777"), strokeColor=None
                )
            )
            threshold = thresholds[i] if thresholds is not None else None
            if _number(threshold) and 0 <= threshold <= maximum:
                x = x0 + plot * threshold / maximum
                d.add(Line(x, y - 3, x, y + 15, strokeColor=colors.black, strokeWidth=1.3))
            d.add(String(x0 + plot + 9, y + 1, f"{val:.4g}", fontName="Helvetica", fontSize=9))
        self.story.append(d)
        self.p("Scale: " + unit + ". " + caption, "small")

    def charts(self, report):
        self.heading("Artifact evidence • readable vector views")
        self.p(
            "These charts describe this saved artifact, not detector benchmark accuracy. Bars start at zero. Only recorded finite numeric evidence is used; missing values are never zero-filled."
        )
        charts = 0
        cov = _dict(_dict(report.get("weight_analysis")).get("coverage"))
        a, b = cov.get("sampled_elements"), cov.get("total_f32_elements")
        if _valid_ratio(a, b):
            self.bar(
                "F32 sampled coverage",
                [("F32 elements sampled", 100 * (a / b))],
                100,
                "% of total F32 elements",
                f"{_ratio(a, b, 'elements')}. Higher coverage means more recorded F32 elements examined, not a safer artifact. Non-F32 data are outside this denominator.",
            )
            charts += 1
        scores = _dict(report.get("ml_analysis")).get("scores")
        if isinstance(scores, list):
            selected = [
                (i, s)
                for i, s in enumerate(scores[:6])
                if isinstance(s, dict) and _number(s.get("score")) and 0 <= s["score"] <= 1
            ]
            if selected:
                self.bar(
                    "RF window votes • recorded threshold markers",
                    [(f"R{i + 1}", s["score"]) for i, s in selected],
                    1,
                    "model vote, 0–1 (not a probability)",
                    f"{len(selected)} valid votes from the first {min(6, len(scores))} of {len(scores)} recorded rows. Black tick = that row's recorded threshold; no tick = threshold unavailable. This is a bounded illustration, not a full score distribution.",
                    [s.get("threshold") for _, s in selected],
                )
                self.table(
                    ["Row / tensor", "Window", "Vote", "Threshold"],
                    [
                        (
                            f"R{i + 1} / {s.get('tensor', 'Not recorded')}",
                            s.get("window_index"),
                            _fmt(s["score"]),
                            _unit_interval(s.get("threshold")),
                        )
                        for i, s in selected
                    ],
                    [WIDTH * 0.49, WIDTH * 0.13, WIDTH * 0.17, WIDTH * 0.21],
                )
                charts += 1
        summary = _dict(_dict(report.get("reference_analysis")).get("summary"))
        a, b = summary.get("differing_sampled_bytes"), summary.get("compared_bytes")
        if _valid_ratio(a, b):
            self.bar(
                "Reference changes • sampled bytes",
                [("Compared bytes changed", 100 * (a / b))],
                100,
                "% of compared bytes",
                f"{_ratio(a, b, 'bytes')}. Denominator is compared bytes, not whole-file bytes. Changes may reflect ordinary training, conversion or other modifications; they do not establish maliciousness.",
            )
            charts += 1
        if not charts:
            self.p(
                "No chart generated: the report lacks the required finite numeric evidence and positive denominators. No chart values have been invented."
            )


def _explanation(explanation, digest):
    """Optional prose must never prevent deterministic export."""
    if explanation is None:
        return None, "No optional interpretation supplied."
    try:
        if type(explanation) is not dict:
            return None, "Interpretation omitted: malformed payload."
        if explanation.get("report_sha256") != digest:
            return None, "Interpretation omitted: canonical report SHA-256 mismatch."
        if explanation.get("status") != "completed" or explanation.get("mode") not in ("offline", "groq"):
            return None, "Interpretation omitted: status is not completed or mode is unsupported."
        mode = explanation["mode"]
        if (
            explanation.get("provider") != mode
            or (mode == "offline" and explanation.get("model") is not None)
            or (mode == "groq" and explanation.get("model") not in GROQ_MODELS)
        ):
            return None, "Interpretation omitted: provider/model does not match the declared mode."
        result = {
            k: explanation.get(k)
            for k in (
                "bundle_sha256",
                "mode",
                "provider",
                "model",
                "report_sha256",
                "prompt_version",
                "generated_at",
                "status",
            )
        }
        for k, v in result.items():
            if v is not None and type(v) is not str:
                return None, "Interpretation omitted: invalid metadata."
        usage = _dict(explanation.get("usage"))
        result["usage"] = {
            k: usage[k]
            for k in ("prompt_tokens", "completion_tokens", "total_tokens")
            if type(usage.get(k)) is int and 0 <= usage[k] <= 10**9
        }
        warnings = explanation.get("warnings", [])
        if not isinstance(warnings, list) or len(warnings) > 100 or any(type(v) is not str for v in warnings):
            return None, "Interpretation omitted: invalid warnings."
        result["warnings"] = warnings[:MAX_ROWS]
        result["warnings_omitted"] = max(0, len(warnings) - MAX_ROWS)
        for group in ("observations", "limitations", "next_steps"):
            rows = explanation.get(group)
            if type(rows) is not list or len(rows) > 100:
                return None, "Interpretation omitted: invalid or oversized interpretation items."
            clean = []
            for row in rows[:MAX_ROWS]:
                if (
                    type(row) is not dict
                    or type(row.get("text")) is not str
                    or type(row.get("evidence_refs")) is not list
                ):
                    return None, "Interpretation omitted: malformed item."
                refs = row["evidence_refs"]
                if len(refs) > 32 or any(type(r) is not str or len(r) > 512 for r in refs):
                    return None, "Interpretation omitted: invalid evidence references."
                # References are inert bundle JSON Pointers, never filesystem/URL targets.
                if any(
                    not re.fullmatch(r"/(?:evidence|omissions)(?:/(?:[^~/\\:\x00-\x20]|~[01])+)+", r)
                    for r in refs
                ):
                    return (
                        None,
                        "Interpretation omitted: references must be bounded sanitized-bundle JSON Pointers.",
                    )
                clean.append({"text": row["text"][:8000], "evidence_refs": refs})
            result[group] = clean
            result[group + "_omitted"] = len(rows) - len(clean)
        return result, ""
    except Exception:
        return None, "Interpretation omitted: optional appendix validation failed."


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#606060"))
    canvas.drawString(52, A4[1] - 31, "STEGOLENS  /  IMMUTABLE SCAN REPORT")
    canvas.drawString(52, 30, "Recorded evidence only • not a safety certification")
    canvas.drawRightString(A4[0] - 52, 30, f"Page {doc.page}")
    canvas.restoreState()


def _fmt(value):
    if not _number(value):
        return "Not recorded / invalid"
    if type(value) is int:
        return f"{value:,}" if abs(value) < 10**12 else f"{value:.5g}"
    return f"{value:.5g}"


def _unit_interval(value):
    return _fmt(value) if _number(value) and 0 <= value <= 1 else "Not recorded / invalid"


def _valid_ratio(a, b):
    return _number(a) and _number(b) and b > 0 and 0 <= a <= b


def _percent(fraction):
    value = 100 * fraction
    return f"{value:.3g}%" if 0 < abs(value) < 0.01 else f"{value:.2f}%"


def _ratio(a, b, unit):
    if not _valid_ratio(a, b):
        return "Not available: valid numerator / positive denominator not recorded"
    return f"{_percent(a / b)} ({_fmt(a)} / {_fmt(b)} {unit})"


def _records(value):
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _reader_summary(w, report):
    w.heading("Executive evidence summary")
    w.p(
        "Start here: what was examined, what produced indicators, and what remains unknown. Every number below concerns this artifact unless explicitly labeled benchmark or runtime. This is recorded evidence, not a verdict generated by an AI."
    )
    weight = _dict(report.get("weight_analysis"))
    cov = _dict(weight.get("coverage"))
    ref = _dict(_dict(report.get("reference_analysis")).get("summary"))
    summary = _dict(report.get("summary"))
    rows = [
        (
            "F32 elements sampled",
            _ratio(cov.get("sampled_elements"), cov.get("total_f32_elements"), "elements"),
            "Share of recorded F32 elements examined. Not whole-file coverage; eligibility may be narrower.",
        ),
        (
            "F32 windows analyzed",
            _fmt(summary.get("analyzed_window_count", cov.get("windows_analyzed"))),
            "A window is a sampled group of values, not an independent model or detection.",
        ),
    ]
    for title, key, countkey in (
        ("ModelAudit rule findings", "static_analysis", "static_finding_count"),
        ("Picklescan findings", "picklescan_analysis", "picklescan_finding_count"),
    ):
        section = _dict(report.get(key))
        count = summary.get(countkey)
        if not _number(count) and isinstance(section.get("findings"), list):
            count = len(section["findings"])
        rows.append(
            (
                title,
                _fmt(count),
                "Recorded findings / list entries. Zero is meaningful only within the engine's completed scope; findings can overlap.",
            )
        )
    scores = _records(_dict(report.get("ml_analysis")).get("scores"))
    comparable = [
        r
        for r in scores
        if _number(r.get("score"))
        and 0 <= r["score"] <= 1
        and _number(r.get("threshold"))
        and 0 <= r["threshold"] <= 1
    ]
    if comparable:
        above = sum(r["score"] >= r["threshold"] for r in comparable)
        rows.append(
            (
                "RF windows at / above threshold",
                f"{above} / {len(comparable)} comparable scored windows",
                "Derived from each row's recorded vote and threshold. Other rows are excluded, not negative. Windows may be correlated; not distinct backdoors.",
            )
        )
    else:
        rows.append(
            (
                "RF threshold comparison",
                "Not available",
                "No scored rows with valid recorded thresholds. No threshold is assumed.",
            )
        )
    rows.append(
        (
            "Heuristic-flagged windows",
            _fmt(summary.get("heuristic_window_count")),
            "Recorded heuristic count; can overlap RF flags and static findings. Do not add these counts together.",
        )
    )
    rows.append(
        (
            "Reference sampled byte changes",
            _ratio(ref.get("differing_sampled_bytes"), ref.get("compared_bytes"), "bytes"),
            "Fraction of compared bytes that differ, not fraction of all artifact bytes; differences do not imply maliciousness.",
        )
    )
    w.table(
        ["Artifact evidence", "Recorded / derived value", "How to read it"],
        rows,
        [WIDTH * 0.25, WIDTH * 0.28, WIDTH * 0.47],
    )
    w.p(
        "Counts are not independent detections. A single tensor/window may contribute to several indicators. No indicators found does not establish safety, and a higher count is not a calibrated increase in risk."
    )
    w.heading("Engine coverage • gaps matter")
    meanings = {
        "completed": "Engine reports completion within its own scope; not a safety pass.",
        "partial": "Only part of the intended evidence was analyzed; inspect sampling and warnings.",
        "failed": "No completed result from this engine; not a negative finding.",
        "not_performed": "Not tested; no negative result can be inferred.",
        "not_applicable": "Engine does not apply to this input / scope.",
        "unsupported": "No supported analysis for this input / engine.",
        "inventory_reported": "Inventory recorded, not a completed detection or safety check.",
        "errors_reported": "Intake errors were recorded; inspect the technical appendix.",
    }
    engine_rows = []
    for title, key in (
        ("Artifact inspection", "intake"),
        ("ModelAudit", "static_analysis"),
        ("Picklescan", "picklescan_analysis"),
        ("F32 statistics", "weight_analysis"),
        ("F16 / BF16 statistics", "precision_analysis"),
        ("RF detector", "ml_analysis"),
        ("Reference comparison", "reference_analysis"),
        ("Known-trigger evidence", "behavioral_analysis"),
    ):
        section = _dict(report.get(key))
        status = section.get("status")
        if key == "intake" and section and status is None:
            status = "errors_reported" if section.get("errors") else "inventory_reported"
        status = status if isinstance(status, str) and status else "status not recorded"
        engine_rows.append(
            (
                title + ": " + str(status),
                meanings.get(
                    status, "Not a completed negative finding; inspect recorded warnings and scope."
                ),
            )
        )
    w.table(["Engine: recorded status", "Meaning / limit"], engine_rows, [WIDTH * 0.4, WIDTH * 0.6])
    w.p(
        "Reading order: artifact charts and numerical descriptors; detector benchmark (separate population); metric guide; comparison limits; Appendix A source fields; Appendix B optional interpretation. A known-trigger status does not cover unknown triggers.",
        "small",
    )
    w.story.append(PageBreak())


def _artifact_metrics(w, report):
    w.heading("Artifact descriptors • not risk scores")
    windows = _records(_dict(report.get("weight_analysis")).get("windows"))
    rows = []
    for key, label, unit in (
        ("low_byte_entropy", "Low-byte entropy", "bits / sampled low byte, 0–8"),
        ("mean", "Mean", "F32 weight units"),
        ("std", "Standard deviation", "F32 weight units"),
        ("rms", "RMS", "F32 weight units"),
        ("mean_abs", "Mean absolute value", "F32 weight units"),
        ("adjacent_correlation", "Adjacent correlation", "dimensionless, -1 to 1"),
    ):
        values = [r["features"][key] for r in windows if _number(_dict(r.get("features")).get(key))]
        if values:
            rows.append(
                (
                    label,
                    f"{_fmt(min(values))} to {_fmt(max(values))}",
                    f"{len(values)} finite windows / {len(windows)} recorded rows; {unit}",
                )
            )
    w.table(
        ["F32 descriptor", "Observed window min to max", "Population / units"],
        rows,
        [WIDTH * 0.25, WIDTH * 0.27, WIDTH * 0.48],
    )
    w.p(
        "Ranges summarize recorded finite F32 windows, not all tensor values. They are not a time trend, a significance test, or a calibrated benign/malicious boundary. Feature definitions and direction-of-change cautions follow in the metric guide."
    )
    precision = _dict(report.get("precision_analysis"))
    coverage = _dict(precision.get("coverage"))
    w.p("F16 / BF16 • separate precision scope", "h2")
    w.p(
        "F16 has 10 mantissa bits; BF16 has 7. Their mantissa entropy is not the same quantity as F32 low-byte entropy. Half-precision statistics are descriptive; the F32 RF detector is not applied to them."
    )
    if precision:
        w.table(
            ["Precision evidence", "Recorded value"],
            [
                ("Engine status", precision.get("status")),
                (
                    "Unique half-precision elements sampled",
                    _ratio(
                        coverage.get("unique_sampled_elements"),
                        coverage.get("total_half_elements"),
                        "elements",
                    ),
                ),
                (
                    "Attempted elements / rejected windows",
                    _fmt(coverage.get("attempted_elements")) + " / " + _fmt(coverage.get("rejected_windows")),
                ),
            ],
            [WIDTH * 0.45, WIDTH * 0.55],
        )
        w.p(
            "Unique coverage counts the union of overlapping accepted windows. Attempted elements may be larger and are not interchangeable with unique sampled elements.",
            "small",
        )
    else:
        w.p("Not recorded: no half-precision result is inferred from the F32 analysis.")
    w.p("Runtime • resource use only", "h2")
    runtime = _dict(report.get("runtime"))
    w.table(
        ["Runtime measure", "Recorded value", "What it is not"],
        [
            (
                "Duration",
                _fmt(runtime.get("duration_seconds")) + " seconds",
                "Not detection confidence; varies with file, settings and host load.",
            ),
            (
                "Peak RSS (legacy peak_rss_mb)",
                _fmt(runtime.get("peak_rss_mb"))
                + (" MiB" if runtime.get("peak_rss_unit") == "MiB" else " (recorded field)"),
                (
                    "Recorded process memory in MiB. Source: "
                    + str(runtime.get("rss_source", "not recorded"))
                    + ". Not isolated scan peak."
                    if runtime.get("peak_rss_unit") == "MiB"
                    else "Canonical Linux scanner uses MiB (KiB / 1024). Imported report units are not independently verified. Process high-water, not isolated scan peak."
                ),
            ),
            (
                "Device / RSS scope",
                str(runtime.get("device", "Not recorded"))
                + " / "
                + str(runtime.get("rss_scope", "Not recorded")),
                "Environment provenance, not artifact evidence.",
            ),
        ],
        [WIDTH * 0.23, WIDTH * 0.33, WIDTH * 0.44],
    )


def _benchmark_metrics(w, report):
    w.heading("Detector benchmark • not this artifact's accuracy")
    manifest = _dict(_dict(report.get("ml_analysis")).get("manifest"))
    w.p(
        "The RF vote is not a calibrated malware probability. Benchmark metrics describe labeled evaluation windows used to assess this detector. They do not measure the probability that this uploaded artifact contains a backdoor. Class 1 means the recorded positive training class, not automatically malware; read its label definition below."
    )
    labels = _dict(manifest.get("label_definitions"))
    w.table(
        ["Detector context", "Recorded value"],
        [
            ("Scope", manifest.get("scope")),
            ("Class 0 definition", labels.get("0")),
            ("Class 1 definition", labels.get("1")),
            ("Manifest decision threshold", _unit_interval(manifest.get("threshold"))),
            ("Threshold selection method", _dict(manifest.get("threshold_selection")).get("method")),
        ],
        [WIDTH * 0.35, WIDTH * 0.65],
    )
    evaluation = _dict(manifest.get("evaluation"))
    if not evaluation:
        w.p(
            "No benchmark evaluation metrics recorded. No accuracy, precision, recall, F1 or AUC is inferred."
        )
    for partition in ("validation", "test"):
        metrics = _dict(evaluation.get(partition))
        if not metrics:
            continue
        w.p(partition.title() + " partition • recorded benchmark", "h2")
        rows = [
            (
                "Evaluation windows",
                _fmt(metrics.get("row_count")),
                "Rows in this benchmark partition, not independent artifacts.",
            ),
            (
                "Source lineages",
                _fmt(_dict(manifest.get("lineage_counts")).get(partition)),
                "Lineage = source ancestry group. Many windows from one lineage do not establish generalization.",
            ),
            (
                "Evaluation threshold",
                _unit_interval(metrics.get("threshold")),
                "Threshold used for these threshold-dependent metrics; not an assumed default.",
            ),
        ]
        for key, title, denominator in (
            (
                "precision",
                "Precision",
                "TP / (TP + FP): among positive predictions, how many matched the positive label.",
            ),
            (
                "recall",
                "Recall",
                "TP / (TP + FN): among truly positive benchmark rows, how many were flagged.",
            ),
            (
                "f1",
                "F1",
                "2TP / (2TP + FP + FN): harmonic balance of precision and recall; no true-negative term.",
            ),
            (
                "roc_auc",
                "ROC AUC",
                "Ranking of positives above negatives across thresholds; not accuracy at the selected threshold.",
            ),
            ("accuracy", "Accuracy", "(TP + TN) / all labeled benchmark rows; sensitive to class balance."),
        ):
            value = metrics.get(key)
            display = (
                _percent(value)
                if _number(value) and 0 <= value <= 1 and key != "roc_auc"
                else _unit_interval(value)
            )
            rows.append((title, display, denominator))
        w.table(
            ["Benchmark measure", "Recorded value", "Denominator / meaning"],
            rows,
            [WIDTH * 0.25, WIDTH * 0.2, WIDTH * 0.55],
        )
        matrix = metrics.get("confusion_matrix")
        axes = metrics.get("confusion_matrix_axes")
        valid = (
            isinstance(matrix, list)
            and len(matrix) == 2
            and all(
                isinstance(row, list) and len(row) == 2 and all(type(n) is int and n >= 0 for n in row)
                for row in matrix
            )
        )
        if valid and axes == "rows=true [0,1], columns=predicted [0,1]":
            w.p("Confusion matrix • benchmark counts, not probabilities", "h2")
            w.table(
                ["True label / predicted label", "Predicted 0", "Predicted 1"],
                [
                    ("True 0 (recorded negative class)", f"TN = {matrix[0][0]:,}", f"FP = {matrix[0][1]:,}"),
                    ("True 1 (recorded positive class)", f"FN = {matrix[1][0]:,}", f"TP = {matrix[1][1]:,}"),
                ],
                [WIDTH * 0.5, WIDTH * 0.25, WIDTH * 0.25],
            )
            w.p(
                "Rows are true classes; columns are predicted classes. FP means a negative-class row flagged positive; FN means a positive-class row missed. These are controlled benchmark labels, not verified malware outcomes.",
                "small",
            )
            if _number(metrics.get("row_count")) and sum(map(sum, matrix)) != metrics["row_count"]:
                w.p(
                    "Recorded matrix total differs from recorded row_count; do not reconcile silently. Inspect original JSON."
                )
        elif matrix is not None:
            w.p(
                "Confusion matrix axes / shape are unavailable or unrecognized; no TN/FP/FN/TP mapping is assumed. See recorded matrix in Appendix A."
            )
        undefined = _dict(metrics.get("undefined_metrics"))
        if undefined:
            w.p("Undefined metrics • recorded reasons", "h2")
            w.table(
                ["Metric", "Reason (untrusted recorded text)"],
                list(undefined.items())[:8],
                [WIDTH * 0.3, WIDTH * 0.7],
            )
    w.p(
        "Benchmark limits: validation and test are different partitions, not before/after measurements. Scores can change with class balance, source lineages, sample construction or threshold. Raising a threshold on the same fixed scores cannot increase the number of positives; it may reduce recall, while precision is not guaranteed to improve. No threshold is tuned or invented here."
    )
    warnings = manifest.get("warnings")
    if isinstance(warnings, list) and warnings:
        w.p("Recorded detector caveats", "h2")
        for warning in warnings[:6]:
            w.p(warning, "small")


def _metric_guide(w):
    w.heading("Metric guide • units, direction & limits")
    w.p(
        "Definitions below explain the scanner's recorded quantities; they are not extra scan findings. Higher or lower does not automatically mean more or less malicious. Natural training, sparsity, dtype and quantization can change the same metrics."
    )
    groups = [
        (
            "Artifact statistics • within a sampled window",
            [
                (
                    "Mean / mean_abs / RMS",
                    "Weight units. Mean is the signed average; mean_abs averages absolute values; RMS is sqrt(mean(x squared)).",
                    "A larger signed mean indicates a shift in average, not necessarily magnitude. Larger mean_abs/RMS indicates larger weights; RMS emphasizes extremes. No malware implication.",
                ),
                (
                    "Standard deviation (std)",
                    "Weight units. Population sqrt(mean((x - mean) squared)) within a window.",
                    "Higher = more numerical spread about the mean; lower = tighter values. A constant window can have zero std without a hidden payload.",
                ),
                (
                    "Mean absolute difference",
                    "Weight units. Average absolute difference of consecutive values in stored order.",
                    "Higher = larger adjacent jumps, not temporal behavior or semantic layer order. Tensor layout and ordinary training affect it.",
                ),
                (
                    "Low-byte entropy",
                    "Bits per observed F32 low byte, theoretical 0–8. Shannon entropy of its sampled byte frequencies.",
                    "Higher = more diverse / even byte frequencies; lower = concentrated frequencies. Neither randomness nor low entropy proves or excludes a payload; no universal suspicious cutoff.",
                ),
                (
                    "Mantissa entropy (F16 / BF16)",
                    "Bits per observed mantissa; theoretical maximum 10 for F16 or 7 for BF16.",
                    "Higher = more diverse mantissas at that precision. Do not compare raw half-precision mantissa entropy to F32 low-byte entropy or reuse F32 thresholds.",
                ),
                (
                    "Bit-one / transition fractions",
                    "0–1 fractions. Bit-one counts sampled words with a bit set; transition counts adjacent pairs with a changing least significant bit.",
                    "Higher = more ones / transitions, not more risk. Bit-one denominator is words; transitions use adjacent pairs. Stored ordering and precision affect both.",
                ),
                (
                    "Zero / negative / subnormal fractions",
                    "0–1 share of sampled values with the named property. Negative-zero fraction counts its exact half-precision representation.",
                    "Higher = more of that numerical property; sparsity, signed zeros and tiny values can be ordinary. They do not count independent threats.",
                ),
                (
                    "Adjacent correlation / excess kurtosis",
                    "Correlation is dimensionless, -1 to 1; kurtosis is the standardized fourth central moment minus 3.",
                    "Correlation near +1 / -1 means positive / negative adjacent association; kurtosis emphasizes tails. Degenerate constant windows use implementation conventions. Neither is a malware test.",
                ),
            ],
        ),
        (
            "Coverage, indicators & reference comparison",
            [
                (
                    "Sampled coverage",
                    "Sampled elements / recorded total elements of the same dtype population; percentages are derived only with a positive compatible denominator.",
                    "Higher = more of that population examined, not higher confidence of safety. F32 coverage is not whole-file byte coverage. Partial means evidence remains unexamined.",
                ),
                (
                    "RF vote and threshold",
                    "Vote 0–1 = mean positive-class leaf fraction across RF trees. Threshold is the recorded decision cutoff; vote >= threshold labels that window positive.",
                    "Higher vote = greater model resemblance to its training class, not malware probability. Threshold is a policy/model setting, not a score. Missing thresholds are not filled with 0.5.",
                ),
                (
                    "Anomaly score / finding counts",
                    "Anomaly score is an uncalibrated heuristic. Findings and positive windows count recorded items, not independent confirmations.",
                    "Higher may reflect numerical structure or repeated correlated evidence. Do not sum overlapping static, RF and heuristic counts or interpret them as backdoor totals.",
                ),
                (
                    "Differing sampled reference bytes",
                    "Differing sampled bytes / compared bytes. Byte-level comparison of sampled compatible tensor regions; artifact and reference hashes establish identities, not trust.",
                    "Higher = more byte mismatch in this compared sample, not greater maliciousness. A model trained or converted differently may differ. Zero sampled change does not prove full equality.",
                ),
            ],
        ),
        (
            "Benchmark measures • labeled evaluation rows only",
            [
                (
                    "Precision / recall / F1",
                    "Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN). Shown as percentages of their defined ratios.",
                    "Higher describes better performance on these labels under this evaluation setup, not this artifact's safety. A zero denominator is undefined, not manufactured zero; class balance and threshold matter.",
                ),
                (
                    "ROC AUC / accuracy",
                    "AUC is a 0–1 ranking measure across thresholds (ties receive half credit); accuracy = (TP+TN)/all labeled rows at a threshold.",
                    "Higher AUC = better ranking on this benchmark; higher accuracy = more matching labels. Neither is a per-artifact probability or guarantee on new lineages; AUC needs both classes.",
                ),
                (
                    "Confusion matrix",
                    "Rows true [0,1], columns predicted [0,1] only when those axes are explicitly recorded. TN/FP/FN/TP are counts, not rates.",
                    "Lower FP/FN is favorable only on comparable populations/settings. TP/TN counts also change with support; raw counts across different sample sizes are not a fair comparison.",
                ),
            ],
        ),
    ]
    for title, rows in groups:
        w.p(title, "h2")
        w.table(
            ["Metric", "Definition / units / denominator", "What an increase or decrease can mean"],
            rows,
            [WIDTH * 0.22, WIDTH * 0.37, WIDTH * 0.41],
        )
    w.p(
        "Runtime reminder: duration (seconds) and recorded peak RSS (legacy peak_rss_mb; canonical Linux uses MiB) describe resource use, not artifact characteristics, benchmark quality or detection confidence. Compare runtime only on comparable hardware, workloads and settings."
    )


def _story(report, digest, explanation, reason, scale=1):
    w = _Writer(digest, scale)
    w.p("T04-SCNR", "small")
    w.story.append(Spacer(1, 28))
    w.p("Artifact scan\nEvidence report", "title")
    w.p(
        "Presentation of an existing immutable scan. CPU / offline PDF generation. No model execution, inference, network lookup or rescan occurs during export."
    )
    w.heading("Recorded verdict")
    w.p(report.get("verdict", "Not recorded"), "h2")
    w.p(
        "A finding is not proof of a backdoor. No indicators found is not proof of safety. Partial, failed, unsupported and not-performed engines leave coverage gaps."
    )
    w.fields({k: report.get(k) for k in ("schema_version", "scan_id", "created_at", "status")}, "report", 4)
    w.fields(report.get("artifact"), "artifact", 8)
    w.p("Canonical report SHA-256", "h2")
    w.p(digest)
    w.p(
        "Hash covers the original complete JSON report, not this PDF, not the interpretation and not the artifact itself. Display truncation does not change the hash.",
        "small",
    )
    w.story.append(PageBreak())
    _reader_summary(w, report)
    w.charts(report)
    _artifact_metrics(w, report)
    _benchmark_metrics(w, report)
    _metric_guide(w)
    w.heading("Limitations & how to compare reports")
    w.p(
        "This report is one saved snapshot; no earlier scan is included and no time trend is claimed. Differences between reports may arise from different artifact/reference hashes, detector versions, thresholds, dtypes, window budgets, sample positions or engine availability. Compare like-for-like settings before interpreting a higher or lower number."
    )
    w.fields(report.get("limitations"), "limitations", 16)
    w.p(
        "No indicators found is not proof of safety. Sampling cannot rule out hidden content in unsampled data. No unknown-trigger discovery, arbitrary inference, malware execution or safety certification is performed by this exporter."
    )
    w.story.append(PageBreak())
    w.heading("Appendix A / Auditable technical evidence")
    w.p(
        "Read the preceding summary and metric guide first. These bounded source fields support audit and reproduction; they are not additional independent detections. Field names are literal evidence paths, not executable data."
    )
    w.p(
        f"Display limits: {MAX_TEXT} characters per value/path; {w.section_limit} scalar fields per source section; {w.row_limit} entries per appendix collection; 22 scalar fields per entry; {MAX_LEAVES} scalar fields globally. Unsupported Unicode and control characters appear as [U+XXXX]. Missing values are not negative results. Retain original JSON for complete evidence."
    )
    for title, key, exclude in (
        ("Provenance & artifact inspection", "intake", ("tensors",)),
        ("Configuration • recorded values", "config", ()),
        ("Runtime • recorded values", "runtime", ()),
        ("Summary • recorded counts", "summary", ()),
        ("ModelAudit • static rules", "static_analysis", ()),
        ("Picklescan • pickle disassembly rules", "picklescan_analysis", ()),
        ("F32 window statistics & heuristics", "weight_analysis", ("windows", "tensor_summaries")),
        ("Precision-aware F16 & BF16", "precision_analysis", ("windows", "tensor_summaries")),
        ("RF detector • provenance, metrics & thresholds", "ml_analysis", ("scores",)),
        ("Reference comparison", "reference_analysis", ("tensors",)),
    ):
        w.section(title, report, key, exclude=exclude)
    if _dict(report.get("behavioral_analysis")):
        w.section(
            "Known-trigger evidence • recorded only",
            report,
            "behavioral_analysis",
            "A not-performed status is not behavioral evidence. Known-trigger tests cannot exclude unknown triggers; this exporter performs no inference.",
        )
    for section, collection, title in (
        ("intake", "tensors", "Tensor inventory"),
        ("weight_analysis", "tensor_summaries", "F32 tensor coverage"),
        ("weight_analysis", "windows", "F32 windows • features & heuristic evidence"),
        ("precision_analysis", "tensor_summaries", "Half-precision tensor coverage"),
        ("precision_analysis", "windows", "F16 / BF16 windows • recorded dtype & statistics"),
        ("ml_analysis", "scores", "RF votes • identities & per-window thresholds"),
        ("reference_analysis", "tensors", "Reference tensor changes • sampled denominator"),
    ):
        w.rows(report, section, collection, title)
    w.heading("Display omissions & resource policy")
    w.p(
        f"Input caps: {MAX_INPUT_BYTES} canonical JSON bytes, {MAX_NODES} nodes, depth {MAX_DEPTH}. Output caps: {MAX_PAGES} pages, {MAX_OUTPUT_BYTES} bytes. Oversized input is rejected rather than silently hashed incompletely. Text truncations are marked inline. Section and row caps preserve recorded order, not risk rank. Unrecognized top-level extensions are not rendered; the canonical hash still covers them."
    )
    extra = set(report) - {
        "schema_version",
        "scan_id",
        "created_at",
        "status",
        "verdict",
        "artifact",
        "intake",
        "config",
        "runtime",
        "summary",
        "static_analysis",
        "picklescan_analysis",
        "weight_analysis",
        "precision_analysis",
        "ml_analysis",
        "reference_analysis",
        "behavioral_analysis",
        "limitations",
    }
    if extra:
        w.p("Unrendered top-level extension fields: " + ", ".join(sorted(extra)))
    if scale < 1:
        w.p(
            "Reduced display budget applied to keep this PDF within page/byte limits. Consult original JSON for omitted evidence."
        )
    for note in w.notes[:40]:
        w.p(note, "small")
    if len(w.notes) > 40:
        w.p(f"Additional omission notices: {len(w.notes) - 40}; consult original JSON.", "small")
    if explanation is not None:
        w.story.append(PageBreak())
    w.heading("Appendix B / Optional interpretation")
    if explanation is None:
        w.p(reason)
    else:
        w.p(
            "AI interpretation — unverified"
            if explanation["mode"] == "groq"
            else "Deterministic offline interpretation",
            "h2",
        )
        w.p(
            "Separate interpretation, not measured scan evidence. Hash matching links this appendix to the report; it does not verify the claims. Evidence references are JSON Pointers relative to the sanitized evidence bundle, not filesystem paths. A syntactically valid reference does not prove an interpretation true. The exporter neither retrieves that bundle nor validates reference existence or semantic support."
        )
        # Independent budget: optional prose cannot consume the deterministic report budget.
        w.remaining = 130
        w.fields(
            {
                k: explanation[k]
                for k in (
                    "mode",
                    "provider",
                    "model",
                    "report_sha256",
                    "bundle_sha256",
                    "prompt_version",
                    "generated_at",
                    "status",
                    "usage",
                    "warnings",
                )
            },
            "interpretation",
            28,
        )
        if explanation["warnings_omitted"]:
            w.p(f"{explanation['warnings_omitted']} interpretation warnings omitted by cap.", "small")
        for group in ("observations", "limitations", "next_steps"):
            w.p(group.replace("_", " ").title(), "h2")
            w.fields(explanation[group], f"interpretation.{group}", 28)
            if explanation[group + "_omitted"]:
                w.p(f"{explanation[group + '_omitted']} interpretation items omitted by row cap.", "small")
    return w.story


def build_pdf(report: dict, explanation: dict | None = None) -> bytes:
    """Return an offline A4 PDF without changing report or optional interpretation.

    Invalid/non-finite/oversized report JSON raises ValueError. Invalid optional
    interpretation is omitted visibly and never prevents deterministic export.
    """
    digest = _canonical(report)
    appendix, reason = _explanation(explanation, digest)
    for scale in (1, 0.45, 0.15):
        stream = _Buffer()
        doc = _Doc(
            stream,
            pagesize=A4,
            leftMargin=52,
            rightMargin=52,
            topMargin=52,
            bottomMargin=52,
            title="StegoLens immutable scan report",
            author="StegoLens",
            subject="Recorded artifact scan evidence",
            pageCompression=1,
            invariant=1,
        )
        try:
            doc.build(
                _story(report, digest, appendix, reason, scale), onFirstPage=_footer, onLaterPages=_footer
            )
            return stream.getvalue()
        except _Limit:
            continue
        except Exception:
            if appendix is not None:
                appendix, reason = None, "Interpretation omitted: optional appendix rendering failed."
                return _build_without_appendix(report, digest, reason)
            raise
    if appendix is not None:
        return _build_without_appendix(
            report, digest, "Interpretation omitted: optional appendix exceeded output limits."
        )
    raise ValueError("PDF exceeds output resource limits")


def _build_without_appendix(report, digest, reason):
    # Internal retry only; report has already passed canonical validation.
    for scale in (1, 0.45, 0.15):
        stream = _Buffer()
        doc = _Doc(
            stream,
            pagesize=A4,
            leftMargin=52,
            rightMargin=52,
            topMargin=52,
            bottomMargin=52,
            title="StegoLens immutable scan report",
            author="StegoLens",
            subject="Recorded artifact scan evidence",
            pageCompression=1,
            invariant=1,
        )
        try:
            doc.build(_story(report, digest, None, reason, scale), onFirstPage=_footer, onLaterPages=_footer)
            return stream.getvalue()
        except _Limit:
            continue
    raise ValueError("PDF exceeds output resource limits")
