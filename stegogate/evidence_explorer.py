"""Bounded, read-only views of recorded evidence; no artifact loading or transport."""

from __future__ import annotations

import html
import math
import unicodedata

from .ui_helpers import as_dict, display_value

MAX_TENSORS = 128
MAX_WINDOWS = 256
MAX_NAME = 100
BLUE = "#6699cc"
GRAY = "#7d8795"
ORANGE = "#e5a65b"


def _text(value, limit=MAX_NAME):
    # Do not stringify containers or giant integers supplied by an untrusted report.
    if not isinstance(value, str):
        return "Not available"
    return "".join(
        " " if unicodedata.category(c).startswith("C") else c for c in display_value(value)[:limit]
    )


def _count(value):
    # Counts must survive JSON/Plotly's finite, exact-integer range. In particular,
    # math.isfinite(10**1000) raises OverflowError in the shared helper.
    if type(value) is int:
        return value if 0 <= value <= 2**53 - 1 else None
    if type(value) is float and math.isfinite(value) and value.is_integer():
        return int(value) if 0 <= value <= 2**53 - 1 else None
    return None


def _rows(value, limit):
    return [r for r in value[:limit] if isinstance(r, dict)] if isinstance(value, list) else []


def _length(value):
    return len(value) if isinstance(value, list) else None


def _ratio(numerator, denominator):
    if numerator is None or denominator is None or denominator <= 0 or numerator > denominator:
        return None
    return numerator / denominator


def build_evidence_maps(report: dict) -> dict:
    """Return fresh, bounded presentation data using only pipeline-recorded fields.

    Counts are scoped, never an engine-vote sum. Missing rows remain unknown.
    Names are labels, not an inferred network topology. No input objects escape.
    """
    report = as_dict(report)
    intake = as_dict(report.get("intake"))
    weight = as_dict(report.get("weight_analysis"))
    reference = as_dict(report.get("reference_analysis"))
    inventory = intake.get("tensors")
    summaries = weight.get("tensor_summaries")
    references = reference.get("tensors")
    windows = weight.get("windows")
    entries = {}
    duplicates = {"inventory": set(), "weight": set(), "reference": set()}
    seen = {kind: set() for kind in duplicates}

    def duplicate(kind, name):
        if not isinstance(name, str):
            return
        if name in seen[kind]:
            duplicates[kind].add(name)
        seen[kind].add(name)

    def entry(name):
        if not isinstance(name, str) or not name:
            return None
        if name not in entries and len(entries) < MAX_TENSORS:
            entries[name] = {
                "id": len(entries),
                "name": _text(name),
                "dtype": "Not available",
                "numel": None,
                "nbytes": None,
                "inventory_recorded": False,
                "weight_status": "Not available",
                "weight_reason": "Not available",
                "sampled_elements": None,
                "population_elements": None,
                "sampled_fraction": None,
                "unexamined_elements": None,
                "reference_status": "Not available",
                "compared_bytes": None,
                "changed_bytes": None,
                "reference_population_bytes": None,
                "reference_fraction": None,
                "changed_fraction": None,
                "windows": [],
            }
        return entries.get(name)

    for source in _rows(inventory, MAX_TENSORS):
        duplicate("inventory", source.get("name"))
        row = entry(source.get("name"))
        if row is not None:
            row.update(
                dtype=_text(source.get("dtype")),
                numel=_count(source.get("numel")),
                nbytes=_count(source.get("nbytes")),
                inventory_recorded=True,
            )
    for source in _rows(summaries, MAX_TENSORS):
        duplicate("weight", source.get("tensor"))
        name = source.get("tensor")
        row = entries.get(name) if isinstance(name, str) else None
        if row is None:
            continue
        sampled, population = _count(source.get("sampled_elements")), _count(source.get("numel"))
        fraction = _ratio(sampled, population)
        # Conflicting recorded populations cannot support a coverage claim.
        if row["numel"] is not None and row["numel"] != population:
            fraction = None
        row.update(
            weight_status=_text(source.get("status")),
            weight_reason=_text(source.get("reason")),
            sampled_elements=sampled,
            population_elements=population,
            sampled_fraction=fraction,
            unexamined_elements=population - sampled if fraction is not None else None,
        )
    for source in _rows(references, MAX_TENSORS):
        duplicate("reference", source.get("tensor"))
        name = source.get("tensor")
        row = entries.get(name) if isinstance(name, str) else None
        if row is None:
            continue
        compared = _count(source.get("compared_bytes"))
        changed = _count(source.get("differing_sampled_bytes"))
        population = _count(source.get("nbytes"))
        coverage = _ratio(compared, population)
        if row["nbytes"] is not None and row["nbytes"] != population:
            coverage = None
        change = _ratio(changed, compared)
        if coverage is None:
            change = None
        row.update(
            reference_status=_text(source.get("status")),
            compared_bytes=compared,
            changed_bytes=changed,
            reference_population_bytes=population,
            reference_fraction=coverage,
            changed_fraction=change,
        )
    for source in _rows(windows, MAX_WINDOWS):
        # Windows are evidence positions, not a substitute for declared populations.
        name = source.get("tensor")
        row = entries.get(name) if isinstance(name, str) else None
        if row is not None:
            row["windows"].append(
                {
                    "window_index": _count(source.get("window_index")),
                    "element_start": _count(source.get("element_start")),
                    "element_count": _count(source.get("element_count")),
                }
            )
    for name, row in entries.items():
        row["ambiguity"] = ", ".join(kind for kind in duplicates if name in duplicates[kind])
        if name in duplicates["inventory"]:
            row.update(dtype="Ambiguous duplicate inventory", numel=None, nbytes=None)
        if name in duplicates["inventory"] or name in duplicates["weight"]:
            row.update(
                sampled_elements=None,
                population_elements=None,
                sampled_fraction=None,
                unexamined_elements=None,
            )
            row["weight_reason"] = "Duplicate recorded identity; coverage is unknown."
        if name in duplicates["inventory"] or name in duplicates["reference"]:
            row.update(
                compared_bytes=None,
                changed_bytes=None,
                reference_population_bytes=None,
                reference_fraction=None,
                changed_fraction=None,
            )
            row["reference_status"] = "Ambiguous duplicate identity"
    coverage = as_dict(weight.get("coverage"))
    artifact = as_dict(report.get("artifact"))
    total = _count(as_dict(report.get("summary")).get("tensor_count"))
    return {
        "tensors": list(entries.values()),
        "counts": {
            "declared_inventory_total": total,
            "recorded_inventory_rows": _length(inventory),
            "recorded_summary_rows": _length(summaries),
            "recorded_reference_rows": _length(references),
            "recorded_windows": _length(windows),
            "displayed_tensors": len(entries),
            "displayed_windows": sum(len(r["windows"]) for r in entries.values()),
            "tensor_limit": MAX_TENSORS,
            "window_limit": MAX_WINDOWS,
        },
        "weight_status": _text(weight.get("status")),
        "reference_status": _text(reference.get("status")),
        "sample_budget_windows": _count(coverage.get("max_windows")),
        "window_elements": _count(coverage.get("window_elements")),
        "artifact_name": _text(artifact.get("original_name")),
        "artifact_sha256": _text(artifact.get("sha256")),
    }


def _number(value):
    return "unknown" if value is None else f"{value:,}"


def _scope(numerator, denominator, ratio, unit):
    if ratio is None:
        return f"Unknown or invalid {unit} coverage; no ratio shown."
    return f"{_number(numerator)} / {_number(denominator)} {unit} ({ratio:.2%})."


def _figure(rows, mode):
    import plotly.graph_objects as go

    figure = go.Figure()
    # User text is never Plotly markup: escape its small HTML-like label grammar.
    labels = [f"{r['id'] + 1}. {html.escape(r['name'], quote=True)}" for r in rows]
    common = dict(orientation="h", y=labels, customdata=[r["id"] for r in rows])
    if mode == "Inventory":
        figure.add_trace(
            go.Bar(
                x=[1] * len(rows),
                name="Recorded tensor",
                marker_color=BLUE,
                hovertemplate="%{y}<extra>Inventory entry only</extra>",
                **common,
            )
        )
        axis = "One inventory entry per row — not network architecture"
    else:
        key = "sampled_fraction" if mode == "Weight coverage" else "changed_fraction"
        known = [r[key] for r in rows]
        first = "Sampled elements" if mode == "Weight coverage" else "Changed compared bytes"
        second = (
            "Unexamined elements (not safe)"
            if mode == "Weight coverage"
            else "Unchanged compared bytes (not safe)"
        )
        for name, values, color in (
            (
                first,
                [v if v is not None else None for v in known],
                BLUE if mode == "Weight coverage" else ORANGE,
            ),
            (
                second,
                [1 - v if v is not None else None for v in known],
                GRAY if mode == "Weight coverage" else BLUE,
            ),
            ("Unknown denominator / evidence", [1 if v is None else None for v in known], GRAY),
        ):
            figure.add_trace(
                go.Bar(
                    x=values,
                    name=name,
                    marker_color=color,
                    hovertemplate="%{y}<extra>See exact scoped counts in table</extra>",
                    **common,
                )
            )
        axis = (
            "Share of this tensor's recorded elements"
            if mode == "Weight coverage"
            else "Share of this tensor's compared bytes only — not whole-file coverage"
        )
    figure.update_layout(
        barmode="stack",
        height=max(260, 30 * len(rows) + 150),
        margin=dict(l=10, r=10, t=10, b=10),
        template="plotly_dark",
        font=dict(family="monospace"),
        xaxis_title=axis,
        yaxis=dict(autorange="reversed"),
        legend=dict(orientation="h"),
        clickmode="event+select",
    )
    figure.update_xaxes(range=[0, 1], showticklabels=False)
    return figure


def render_evidence_explorer(report: dict):
    """Render recorded maps only. No network, file access, scans, or model loading."""
    import streamlit as st

    maps = build_evidence_maps(report)
    st.subheader("Evidence explorer")
    st.caption(
        "Tensor inventory map, not a network diagram. Names do not establish architecture. "
        "Blue = recorded evidence; orange = changed compared bytes; gray = unexamined or unknown. "
        "Low coverage is a limit, not a bad result. No change does not mean safe."
    )
    st.text(f"File: {maps['artifact_name']}")
    with st.expander("File identity details"):
        st.text(f"Recorded original SHA-256: {maps['artifact_sha256']}")
        st.caption("A recorded source hash identifies bytes; it does not establish trust or authenticity.")
    counts = maps["counts"]
    st.text(
        f"Declared inventory total: {_number(counts['declared_inventory_total'])}; "
        f"recorded inventory rows: {_number(counts['recorded_inventory_rows'])}; "
        f"shown tensors: {counts['displayed_tensors']} (limit {MAX_TENSORS}). "
        f"Recorded windows: {_number(counts['recorded_windows'])}; "
        f"shown positions: {counts['displayed_windows']} (limit {MAX_WINDOWS})."
    )
    st.caption(
        "Display is bounded to the first 128 rows of each tensor source and first 256 weight windows; "
        "omitted rows are not analyzed by this view. No coverage of all file bytes is inferred."
    )
    rows = maps["tensors"]
    if not rows:
        st.info(
            "No recorded tensor evidence is available. This file may be unsupported, or analysis was not recorded. "
            "Use the recorded report details to check scope; missing evidence is not a clean result."
        )
        return
    st.text(f"Weight analysis: {maps['weight_status']}; reference comparison: {maps['reference_status']}.")
    st.text(
        f"Recorded sample budget: {_number(maps['sample_budget_windows'])} windows; "
        f"up to {_number(maps['window_elements'])} elements per window."
    )
    mode = st.radio(
        "Map",
        ["Inventory", "Weight coverage", "Reference changes"],
        horizontal=True,
        key="evidence_explorer_map",
    )
    # Keep a single viewport readable; the selector/table still cover all bounded entries.
    page = st.selectbox(
        "Map page (24 tensors per page)",
        list(range((len(rows) + 23) // 24)),
        format_func=lambda i: f"{i * 24 + 1}–{min((i + 1) * 24, len(rows))}",
        key="evidence_explorer_page",
    )
    event = st.plotly_chart(
        _figure(rows[page * 24 : (page + 1) * 24], mode),
        use_container_width=True,
        on_select="rerun",
        selection_mode="points",
        key=f"evidence_explorer_chart_{mode}_{page}",
    )
    # Chart clicks and keyboard-accessible selection share the same details panel.
    points = as_dict(as_dict(event).get("selection")).get("points", [])
    if isinstance(points, list) and points:
        selected = as_dict(points[-1]).get("customdata")
        click = (mode, page, selected)
        if (
            type(selected) is int
            and 0 <= selected < len(rows)
            and st.session_state.get("evidence_explorer_last_click") != click
        ):
            st.session_state["evidence_explorer_tensor"] = selected
            st.session_state["evidence_explorer_last_click"] = click
    if st.session_state.get("evidence_explorer_tensor", 0) not in range(len(rows)):
        st.session_state["evidence_explorer_tensor"] = 0
    selected = st.selectbox(
        "Choose a tensor",
        list(range(len(rows))),
        format_func=lambda i: f"{i + 1}. {rows[i]['name']}",
        key="evidence_explorer_tensor",
    )
    row = rows[selected]
    st.markdown("#### What it is")
    st.text(
        f"Tensor {selected + 1}: {row['name']} | dtype: {row['dtype']} | "
        f"elements: {_number(row['numel'])} | bytes: {_number(row['nbytes'])}"
    )
    st.markdown("#### What was examined")
    st.text(_scope(row["sampled_elements"], row["population_elements"], row["sampled_fraction"], "elements"))
    st.text(f"Weight status: {row['weight_status']}. Recorded reason: {row['weight_reason']}")
    st.markdown("#### What was observed")
    st.text(
        f"Reference tensor status: {row['reference_status']}; comparison status: {maps['reference_status']}."
    )
    st.text(
        "Changed / compared: "
        + _scope(row["changed_bytes"], row["compared_bytes"], row["changed_fraction"], "compared bytes")
    )
    st.text(
        "Compared / tensor bytes: "
        + _scope(row["compared_bytes"], row["reference_population_bytes"], row["reference_fraction"], "bytes")
    )
    st.markdown("#### What remains unknown")
    st.text(
        "Unexamined positions, missing comparisons, and omitted tensors remain unknown. "
        "Changes are not proof of malware; unchanged samples are not proof of safety. "
        "This view does not establish reference provenance or whole-file coverage."
    )
    st.markdown("#### Next step")
    st.text(
        "Review the recorded window positions and limitations. If more evidence is needed, "
        "request a broader bounded scan or a trusted exact reference in an isolated workflow."
    )
    if row["windows"]:
        st.caption("First recorded weight-window positions (element indices, not file offsets).")
        st.dataframe(row["windows"], use_container_width=True, hide_index=True)
    else:
        st.caption("No weight-window positions recorded in this bounded view; location is unknown.")
    with st.expander("Accessible table alternative", expanded=False):
        st.dataframe(
            [
                {
                    "Tensor": f"{r['id'] + 1}. {r['name']}",
                    "Inventory recorded": r["inventory_recorded"],
                    "Dtype": r["dtype"],
                    "Elements": _number(r["numel"]),
                    "Weight status": r["weight_status"],
                    "Sampled / population": _scope(
                        r["sampled_elements"], r["population_elements"], r["sampled_fraction"], "elements"
                    ),
                    "Reference status": r["reference_status"],
                    "Changed / compared": _scope(
                        r["changed_bytes"], r["compared_bytes"], r["changed_fraction"], "compared bytes"
                    ),
                    "Compared / tensor": _scope(
                        r["compared_bytes"], r["reference_population_bytes"], r["reference_fraction"], "bytes"
                    ),
                }
                for r in rows
            ],
            use_container_width=True,
            hide_index=True,
        )
