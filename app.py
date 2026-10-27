"""T04-Scnr CPU: local, report-driven security analysis console.
Run: streamlit run app.py --server.address 127.0.0.1
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from stegogate.ui_helpers import (
    MAX_UPLOAD_BYTES,
    as_dict,
    bitplane_points,
    coverage_rows,
    demo_documents,
    display_value,
    export_html,
    export_json,
    feature_points,
    finite_number,
    numeric_feature_names,
    records,
    report_summary,
    tensor_rows,
    valid_report_id,
    window_rows,
)

st.set_page_config(page_title="StegoLens — Visual AI Model Investigation", page_icon="◈", layout="wide")
# Static authored styling only. Never interpolate report/upload values into HTML.
st.markdown(
    """<style>
:root{color-scheme:dark}
.stApp{background:#090909;color:#ededed}
.block-container{padding-top:4rem;padding-bottom:4rem;max-width:1500px}
[data-testid="stHeader"]{background:rgba(9,9,9,.94);border-bottom:1px solid #242424}
[data-testid="stSidebar"]{background:#0d0d0d;border-right:1px solid #262626}
[data-testid="stSidebar"] .block-container{padding-top:2rem}
h1{font-size:clamp(2rem,4vw,3.2rem)!important;letter-spacing:-.065em;font-weight:650!important;line-height:1.1!important}
h2{font-size:1.6rem!important;letter-spacing:-.035em}h3{font-size:1.15rem!important;letter-spacing:-.02em}
p,[data-testid="stCaptionContainer"]{line-height:1.65}
[data-testid="stCaptionContainer"]{color:#a1a1a1!important;opacity:1!important}
[data-testid="stMetric"]{background:#111;border:1px solid #292929;border-radius:9px;padding:18px 20px;transition:border-color .18s ease,background .18s ease}
[data-testid="stMetric"]:hover{border-color:#666;background:#171717}
[data-testid="stMetricValue"]{font-size:1.85rem!important;font-variant-numeric:tabular-nums;letter-spacing:-.04em}
[data-testid="stMetricLabel"]{color:#b3b3b3}
.stTabs [data-baseweb="tab-list"]{gap:24px;border-bottom:1px solid #292929}
.stTabs [data-baseweb="tab"]{min-height:48px;font-size:14px;color:#999;background:transparent;white-space:nowrap}
.stTabs [aria-selected="true"]{color:#fff!important}
.stTabs [data-baseweb="tab-highlight"]{background:#fff}
.stButton button,.stDownloadButton button{min-height:44px;border:1px solid #3a3a3a;border-radius:6px;transition:background .18s ease,border-color .18s ease}
.stButton button:hover,.stDownloadButton button:hover{border-color:#ededed;background:#222;color:#fff}
[data-testid="stBaseButton-primary"]{background:#ededed!important;color:#111!important}
[data-testid="stBaseButton-primary"] p{color:#111!important}
[data-testid="stBaseButton-primary"]:hover{background:#d4d4d4!important;color:#111!important}
[data-testid="stBaseButton-primary"]:disabled{background:#404040!important;color:#bdbdbd!important}
[data-testid="stBaseButton-primary"]:disabled p{color:#bdbdbd!important}
[data-testid="stExpander"]{border:1px solid #303030!important;border-radius:8px}
[data-testid="stDataFrame"]{border:1px solid #292929;border-radius:8px;overflow:hidden}
[data-baseweb="select"]>div,[data-baseweb="input"]{border-color:#333!important}
hr{border-color:#252525!important}
@media(max-width:640px){.block-container{padding-left:1rem;padding-right:1rem;padding-top:4rem}.stTabs [data-baseweb="tab-list"]{gap:16px}h1{font-size:2.2rem!important}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>""",
    unsafe_allow_html=True,
)


def table(rows, **kwargs):
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", **kwargs)
    else:
        st.caption("No corresponding evidence records are present in this report.")


def notes(section: dict):
    for key in ("errors", "warnings"):
        values = section.get(key, [])
        if isinstance(values, list):
            for value in values[:30]:
                (st.error if key == "errors" else st.warning)(display_value(value))


def properties(values: dict):
    table([{"Field": k, "Value": display_value(v)} for k, v in values.items()])


def chart_style(fig, *, x_title=None, y_title=None):
    fig.update_layout(
        template="plotly_dark",
        font=dict(family="Arial, sans-serif", size=14, color="#b8b8b8"),
        colorway=["#ededed", "#777777", "#b5b5b5"],
        margin=dict(l=12, r=16, t=24, b=24),
        height=345,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis_title=x_title,
        yaxis_title=y_title,
        showlegend=False,
    )
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(gridcolor="#262626", zeroline=True)
    return fig


def render_overview(report):
    left, right = st.columns([1.15, 1], gap="large")
    with left:
        st.subheader("Provenance & execution")
        properties(report_summary(report))
        runtime = as_dict(report.get("runtime"))
        st.caption("Execution telemetry · recorded by the scan, not estimated by the interface")
        properties(runtime or {"Runtime": "Not available"})
        device = runtime.get("device")
        if device and str(device).lower() != "cpu":
            st.error("This report records a non-CPU device. It does not match the CPU-only runtime policy.")
    with right:
        st.subheader("Analysis coverage")
        table(coverage_rows(report))
        st.caption(
            "Completed means that layer ran, not that the artifact is safe. Unavailable, unsupported, partial and skipped remain distinct."
        )
        coverage = as_dict(as_dict(report.get("weight_analysis")).get("coverage"))
        if coverage:
            st.markdown("**Weight sampling scope**")
            properties(coverage)
        summary = as_dict(report.get("summary"))
        if summary:
            with st.expander("Pipeline summary · original fields"):
                st.json(summary)
    st.subheader("Interpretation boundaries")
    st.info(
        "Static indicators, sampled weight anomalies, learned manipulation votes, reference deltas and known-trigger behavior are independent evidence layers. They are not a combined probability of malware."
    )
    for limitation in report.get("limitations", []) if isinstance(report.get("limitations"), list) else []:
        st.write("• " + display_value(limitation))
    notes(as_dict(report.get("intake")))


def render_tensors(report):
    st.subheader("Tensor inventory")
    st.caption(
        "Structural metadata from artifact inspection. No uploaded code is imported; no model is instantiated."
    )
    inventory = tensor_rows(report)
    query = st.text_input("Search tensor name", placeholder="e.g. layer1, attention, weight")
    dtypes = sorted({display_value(t.get("dtype")) for t in inventory})
    chosen = st.multiselect("Dtype filter", dtypes, default=[])
    filtered = [
        r
        for r in inventory
        if query.casefold() in str(r.get("name", "")).casefold()
        and (not chosen or display_value(r.get("dtype")) in chosen)
    ]
    st.caption(f"{len(filtered):,} of {len(inventory):,} inventoried tensors shown")
    table(filtered)
    names = [r.get("name") for r in filtered if isinstance(r.get("name"), str)]
    if not names:
        return
    selected = st.selectbox("Tensor detail", names)
    rows = window_rows(report, selected)
    summaries = records(as_dict(report.get("weight_analysis")).get("tensor_summaries"))
    matched = [r for r in summaries if r.get("tensor", r.get("name")) == selected]
    if matched:
        st.markdown("**Reported tensor summaries**")
        table(matched)
    st.markdown("**Sampled windows**")
    st.caption("Only recorded windows are shown. Unscanned elements are not implicitly cleared.")
    table([{k: display_value(v) if isinstance(v, (dict, list)) else v for k, v in w.items()} for w in rows])
    if rows:
        index = st.selectbox(
            "Window detail",
            range(len(rows)),
            format_func=lambda i: (
                f"Window {rows[i].get('window_index', i)} · element {rows[i].get('element_start', '?')}"
            ),
        )
        window = rows[index]
        properties({k: v for k, v in window.items() if k != "features"})
        properties(as_dict(window.get("features")))
        planes = bitplane_points(as_dict(window.get("features")))
        if planes:
            measure = st.selectbox("Bit-plane measure", sorted({p["Measure"] for p in planes}))
            data = [dict(p) for p in planes if p["Measure"] == measure]
            units = measure
            if measure.endswith("fraction"):
                data = [dict(p, Value=p["Value"] * 100) for p in data]
                units = measure + " (%)"
                st.caption("Fraction fields are converted to percentages for this chart and its table.")
            fig = px.bar(
                data, x="Plane", y="Value", color_discrete_sequence=["#ededed"], hover_data=["Field"]
            )
            st.plotly_chart(
                chart_style(fig, x_title="F32 raw bit plane (0 = lowest)", y_title=units), width="stretch"
            )
            table(data)
        st.caption(
            "Natural low bit planes can resemble randomness. Bit-plane statistics alone do not establish hidden payloads or backdoors."
        )


def render_signals(report):
    section = as_dict(report.get("weight_analysis"))
    st.subheader("Statistical signal lab")
    st.write("Layer status: **" + str(section.get("status", "not_available")) + "**")
    notes(section)
    windows = window_rows(report)
    names = numeric_feature_names(windows)
    if not names:
        st.info(
            "No finite numeric window features are present. Statistical plots are unavailable; raw evidence remains below."
        )
        st.json(section)
        return
    preferred = next((n for n in names if "entropy" in n.lower()), names[0])
    feature = st.selectbox("Recorded feature", names, index=names.index(preferred))
    tensors = sorted({display_value(w.get("tensor")) for w in windows})
    selected = st.selectbox("Signal scope", ["All sampled tensors"] + tensors)
    scoped = (
        windows
        if selected == "All sampled tensors"
        else [w for w in windows if display_value(w.get("tensor")) == selected]
    )
    points = feature_points(scoped, feature)
    st.caption(
        f"{len(points):,} recorded feature values · missing/nonfinite values are omitted, not replaced with zero"
    )
    if points:
        frame = pd.DataFrame(points)
        axis_label = feature
        if feature.endswith("_fraction"):
            frame["Value"] = frame["Value"] * 100
            axis_label = feature + " (%)"
            st.caption(
                "Charts convert the recorded fraction to percent; evidence table below retains original fraction values."
            )
        elif feature == "low_byte_entropy":
            axis_label = "Low-byte entropy (bits; theoretical maximum 8)"
        left, right = st.columns(2, gap="large")
        with left:
            st.markdown("**Observed feature distribution**")
            fig = px.histogram(
                frame, x="Value", nbins=min(30, max(5, len(points))), color_discrete_sequence=["#ededed"]
            )
            st.plotly_chart(chart_style(fig, x_title=axis_label, y_title="Recorded windows"), width="stretch")
        with right:
            st.markdown("**Per-window values**")
            frame["Recorded row"] = range(len(frame))
            fig = px.scatter(
                frame,
                x="Recorded row",
                y="Value",
                hover_data=["Tensor", "Window", "Element start"],
                color_discrete_sequence=["#ededed"],
            )
            fig.update_traces(marker=dict(size=7))
            st.plotly_chart(
                chart_style(fig, x_title="Recorded window order (not time)", y_title=axis_label),
                width="stretch",
            )
        table(points)
    st.caption(
        "Heuristic anomaly scores are uncalibrated unless a report explicitly supplies validated calibration. Plots depict only deterministic sampled windows, not every weight."
    )


def render_static(report):
    st.caption(
        "Independent engines are shown separately. Overlapping findings are not independent detections."
    )
    for title, key in [("ModelAudit", "static_analysis"), ("Picklescan", "picklescan_analysis")]:
        section = as_dict(report.get(key))
        st.subheader(title + " · static indicators")
        properties(
            {k: section.get(k, "not_available") for k in ("status", "engine_version", "duration_seconds")}
        )
        notes(section)
        findings = records(section.get("findings"))
        if findings:
            table([{k: display_value(v) for k, v in row.items()} for row in findings])
        else:
            st.info(
                "No recorded findings. Check engine status: absent or inapplicable coverage is not a pass."
            )
        with st.expander(title + " original evidence"):
            st.json(section)


def render_precision(report):
    section = as_dict(report.get("precision_analysis"))
    st.subheader("Precision-aware F16 / BF16 evidence")
    st.write("Layer status: " + str(section.get("status", "not_available")))
    notes(section)
    st.caption(
        "F16 has 10 mantissa bits; BF16 has 7. BF16 bit 7 is exponent and is excluded from mantissa features. No F32 RF scoring or calibration is implied."
    )
    properties(as_dict(section.get("coverage")))
    table(records(section.get("tensor_summaries")))
    rows = records(section.get("windows"))
    if rows:
        dtypes = sorted({str(w.get("dtype")) for w in rows})
        selected = st.selectbox("Mantissa precision", dtypes, key="half_precision_dtype")
        chosen = [w for w in rows if w.get("dtype") == selected]
        bits = 10 if selected == "F16" else 7
        z = [
            [as_dict(w.get("features")).get(f"mantissa_bit_{i}_one_fraction") for i in range(bits)]
            for w in chosen
        ]
        fig = go.Figure(
            go.Heatmap(
                z=z,
                x=list(range(bits)),
                y=list(range(len(chosen))),
                zmin=0,
                zmax=1,
                colorscale="Greys",
                colorbar=dict(title="Ones fraction"),
            )
        )
        fig.update_layout(
            xaxis_title="Mantissa bit (0 = lowest)", yaxis_title="Recorded window index", height=400
        )
        st.plotly_chart(fig, width="stretch")
        st.caption(
            "Raw occupancy, not a payload detector. Missing values are blank; natural structure can cause bit imbalance."
        )
    table(
        [
            {
                **{
                    k: w.get(k) for k in ("tensor", "dtype", "window_index", "element_count", "mantissa_bits")
                },
                **as_dict(w.get("features")),
            }
            for w in rows
        ]
    )


def render_ml(report):
    section = as_dict(report.get("ml_analysis"))
    st.subheader("Learned controlled-manipulation detector")
    st.info(
        "Score semantics: model vote for a controlled weight-manipulation class. NOT a malware probability, backdoor probability, or model-safety verdict. Generalization depends on training lineage and manipulation scope."
    )
    st.write("Layer status: **" + str(section.get("status", "not_available")) + "**")
    notes(section)
    manifest = as_dict(section.get("manifest"))
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown("**Per-window model outputs**")
        scores = records(section.get("scores"))
        table(
            [
                {k: display_value(v) if isinstance(v, (list, dict)) else v for k, v in row.items()}
                for row in scores
            ]
        )
        if not scores:
            st.caption(
                "No detector outputs are present. Detector preparation is a separate trusted CLI operation."
            )
    with right:
        st.markdown("**Detector scope & evaluation provenance**")
        if manifest:
            st.json(manifest)
        else:
            st.warning("Training/evaluation manifest not available. Do not infer accuracy or calibration.")
    with st.expander("Original learned-detector evidence"):
        st.json(section)


def render_reference(report):
    section = as_dict(report.get("reference_analysis"))
    st.subheader("Reference differential")
    st.caption(
        "Differences identify change, not malicious intent. An earlier checkpoint is not automatically a pristine control."
    )
    st.write("Layer status: **" + str(section.get("status", "not_available")) + "**")
    notes(section)
    properties(as_dict(section.get("summary")))
    rows = records(section.get("tensors"))
    query = st.text_input("Search reference tensor", key="reference_search")
    table(
        [
            {k: display_value(v) if isinstance(v, (dict, list)) else v for k, v in row.items()}
            for row in rows
            if query.casefold() in display_value(row.get("name", row.get("tensor", ""))).casefold()
        ]
    )
    with st.expander("Original reference evidence"):
        st.json(section)


def render_research_atlas(report):
    from stegogate.research_views import (
        bitplane_matrix,
        matched_signal_rows,
        reference_change_rows,
        feature_axis_label,
    )

    st.subheader("Research atlas")
    st.caption(
        "Linked views of recorded samples. No new model inference, weight mutation, or network access."
    )
    matrix = bitplane_matrix(report)
    if matrix["values"] and any(v is not None for row in matrix["values"] for v in row):
        st.markdown("**Raw low-byte bit occupancy**")
        st.caption(
            f"Showing {matrix['displayed_windows']} of {matrix['available_windows']} recorded windows. Missing values are blank; 50% occupancy is not evidence of a payload."
        )
        fig = go.Figure(
            go.Heatmap(
                z=matrix["values"],
                x=list(range(8)),
                y=matrix["labels"],
                customdata=[[identity] * 8 for identity in matrix["identities"]],
                zmin=0,
                zmax=100,
                colorscale=[[0, "#151515"], [0.5, "#767676"], [1, "#f5f5f5"]],
                colorbar=dict(title="Ones (%)", tickvals=[0, 25, 50, 75, 100]),
                hovertemplate="%{customdata}<br>Bit %{x}: %{z:.2f}% ones<extra></extra>",
            )
        )
        fig = chart_style(fig, x_title="Raw F32 bit (0 = lowest)", y_title="Recorded window")
        fig.update_layout(height=440)
        fig.update_yaxes(autorange="reversed", nticks=10)
        st.plotly_chart(fig, width="stretch")
        with st.expander("Heatmap values and window identities"):
            table(
                [
                    {"Window": identity, **{f"Bit {bit} ones (%)": value for bit, value in enumerate(values)}}
                    for identity, values in zip(matrix["identities"], matrix["values"])
                ]
            )
    else:
        st.info("No recorded bit-plane fractions are available for a heatmap.")
    names = numeric_feature_names(window_rows(report))
    if names:
        feature = st.selectbox(
            "Feature paired with learned vote",
            names,
            index=names.index("low_byte_entropy") if "low_byte_entropy" in names else 0,
            key="atlas_feature",
        )
        matched = matched_signal_rows(report, feature)
        st.markdown("**Feature / learned-vote relationship**")
        st.caption(
            "Unique tensor + window identities only. Axes retain separate native units. Model vote is not malware probability; correlation is not causation."
        )
        if matched:
            st.caption(
                f"{len(matched)} finite matched pairs from at most the first 128 recorded windows; unmatched or ambiguous identities are omitted."
            )
            fig = px.scatter(
                matched,
                x="Feature value",
                y="Model vote",
                hover_data=["Tensor", "Window", "Recorded threshold"],
                color_discrete_sequence=["#ededed"],
            )
            fig.update_traces(marker=dict(size=8, opacity=0.75, line=dict(width=1, color="#090909")))
            fig = chart_style(
                fig, x_title=feature_axis_label(feature), y_title="RF controlled-manipulation vote"
            )
            fig.update_yaxes(range=[0, 1], dtick=0.25)
            st.plotly_chart(fig, width="stretch")
            table(matched)
        else:
            st.info(
                "No unambiguous finite feature/score pairs are available. Values are not joined by row order."
            )
    changes = reference_change_rows(report)
    st.markdown("**Largest sampled reference changes**")
    st.caption(
        "At most 12 tensors, ranked by differing sampled bytes. The denominator is compared bytes, not all artifact bytes. Ordinary training can cause these changes."
    )
    if changes:
        frame = pd.DataFrame(changes)
        frame["Label"] = frame["Tensor"].map(lambda name: name if len(name) <= 42 else name[:39] + "…")
        fig = px.bar(
            frame,
            x="Differing sampled bytes",
            y="Label",
            orientation="h",
            hover_data=["Tensor", "Compared bytes"],
            color_discrete_sequence=["#b5b5b5"],
        )
        fig = chart_style(fig, x_title="Differing sampled bytes (count)", y_title=None)
        fig.update_xaxes(rangemode="tozero")
        fig.update_yaxes(autorange="reversed")
        fig.update_layout(height=max(280, len(changes) * 30 + 80))
        st.plotly_chart(fig, width="stretch")
        table(changes)
    else:
        st.info("No valid sampled-reference byte counts are recorded.")


def render_comparison(storage):
    from stegogate.research_views import empirical_cdf, feature_axis_label

    st.subheader("Compare evidence, not verdicts")
    st.caption("Pair immutable saved reports without rescanning or executing either artifact.")
    items = saved_reports(storage)
    if len(items) < 2:
        st.info("Save at least two reports to compare them.")
        return
    by_id = {row["scan_id"]: row for row in items}
    ids = list(by_id)

    def title(value):
        row = by_id[value]
        return str(as_dict(row.get("artifact")).get("original_name", "Artifact")) + " · " + value[:8]

    left, right = st.columns(2)
    with left:
        first = st.selectbox("Report A", ids, format_func=title)
    with right:
        second = st.selectbox("Report B", ids, index=1, format_func=title)
    if first == second:
        st.info("Choose two different saved reports.")
        return
    try:
        reports = [storage.load_report(first), storage.load_report(second)]
    except (OSError, ValueError) as exc:
        st.error("A selected report could not be read: " + str(exc))
        return
    st.warning(
        "Different architectures, precision, training ancestry and sampling budgets can change feature distributions. This is an exploratory comparison, not a statistical test or proof of malicious change."
    )
    summaries = [report_summary(report) for report in reports]
    table(
        [
            {
                "Field": field,
                "Report A": display_value(summaries[0].get(field)),
                "Report B": display_value(summaries[1].get(field)),
            }
            for field in summaries[0]
        ]
    )
    common = sorted(
        set(numeric_feature_names(window_rows(reports[0])))
        & set(numeric_feature_names(window_rows(reports[1])))
    )
    if not common:
        st.info("The reports have no common recorded finite feature names.")
        return
    feature = st.selectbox(
        "Common feature",
        common,
        index=common.index("low_byte_entropy") if "low_byte_entropy" in common else 0,
    )
    points = empirical_cdf(reports[0], feature, "A") + empirical_cdf(reports[1], feature, "B")
    fig = px.line(
        points,
        x="Feature value",
        y="Cumulative sampled windows (%)",
        color="Artifact",
        markers=True,
        line_shape="hv",
        hover_data=["Finite windows"],
        color_discrete_map={"A": "#ededed", "B": "#777777"},
    )
    fig = chart_style(
        fig, x_title=feature_axis_label(feature), y_title="Observed windows at or below value (%)"
    )
    fig.update_layout(showlegend=True, legend=dict(orientation="h", y=1.12, x=0))
    fig.update_yaxes(range=[0, 100], dtick=25)
    st.plotly_chart(fig, width="stretch")
    st.caption(
        "Each empirical curve uses its own finite sampled-window denominator; no synthetic zero or interpolated observation is inserted. The table contains exact plotted values."
    )
    table(points)


def render_compatibility():
    from stegogate.research_views import compatibility_rows

    st.subheader("Model compatibility & scope")
    st.write("Architecture-agnostic file inspection is not universal model support.")
    table(compatibility_rows())
    st.info(
        "The current upload limit is 256 MiB per single file. Large or sharded LLM checkpoints and quantized GGUF weights need separate reviewed adapters. F16/BF16 have descriptive statistics only, not the F32 detector."
    )
    st.markdown("### Three different questions")
    table(
        [
            {
                "Question": "Can this serialization execute code?",
                "Current layer": "Reviewed static rules; no deserialization",
            },
            {
                "Question": "Do sampled weights resemble controlled byte manipulation?",
                "Current layer": "Heuristics + exploratory CPU Random Forest",
            },
            {
                "Question": "Does a trigger change the model's behavior?",
                "Current layer": "Known-trigger MNIST demo only; no arbitrary inference",
            },
        ]
    )
    st.markdown("### Local operation")
    st.write(
        "The dashboard already runs on loopback. On this VM, localhost refers to the VM, not your laptop. An SSH forward makes it available at your computer's localhost without opening a public app port."
    )
    st.code("ssh -N -L 8501:127.0.0.1:8501 <vm-user>@<vm-host>", language="bash")
    st.caption(
        "The Evidence Assistant offers deterministic offline interpretation and an explicit Groq-only cloud option. Scanning and PDF export remain CPU-only and offline. Cloud interpretation never changes verdicts or executes uploaded models."
    )


def render_report_controls(report):
    buttons = st.columns([1, 1, 3])
    identifier = report.get("scan_id") if valid_report_id(report.get("scan_id")) else "report"
    with buttons[0]:
        try:
            st.download_button(
                "↓ JSON evidence",
                export_json(report),
                file_name=f"{identifier}.json",
                mime="application/json",
                width="stretch",
            )
        except ValueError:
            st.warning("JSON export unavailable: report contains nonfinite data.")
    with buttons[1]:
        try:
            st.download_button(
                "↓ HTML report",
                export_html(report),
                file_name=f"{identifier}.html",
                mime="text/html",
                width="stretch",
            )
        except ValueError:
            st.warning("HTML export unavailable: report contains nonfinite data.")
    from stegogate.assistant_ui import render_pdf_controls

    render_pdf_controls(report)


def render_simple_report(report):
    from stegogate.beginner_summary import beginner_summary

    summary = beginner_summary(report)
    art = as_dict(report.get("artifact"))
    st.subheader(display_value(art.get("original_name", "Your model file")))
    st.caption("Saved scan · " + display_value(report.get("scan_id")))
    st.markdown("### Original recorded verdict")
    verdict = display_value(report.get("verdict", "No conclusion recorded"))
    if report.get("status") == "rejected":
        st.error(verdict)
    elif verdict.startswith("REVIEW"):
        st.warning(verdict)
    else:
        st.info(verdict)
    st.caption("This is the original scan wording, not a new judgment by the dashboard.")
    status = display_value(report.get("status", "not_available"))
    st.write("**Scan status: " + status + "**")
    st.info(
        "Partial means incomplete coverage: some checks or samples are missing. It is not a pass "
        "and does not by itself mean a software bug. A completed check only means it ran. "
        "No result here certifies safety or proves infection."
    )
    st.markdown("### What the saved scan tells you")
    coverage, rf, reference = (summary[key] for key in ("coverage", "rf", "reference"))
    sampling = summary["sampling"]
    a, b, c = st.columns(3, gap="large")
    with a:
        value = (
            f"{100 * sampling['sampled'] / sampling['total']:.2f}%"
            if sampling["sampled"] is not None else "Not available"
        )
        st.metric("Weight values sampled", value)
        if sampling["sampled"] is not None:
            st.caption(f"{sampling['sampled']:,} sampled / {sampling['total']:,} recorded F32 values.")
        st.caption(
            "Only the recorded 32-bit weight population, not the whole file. "
            "More examined values do not mean a safer model."
        )
    with b:
        value = f"{rf['positive']} of {rf['eligible']} windows" if rf["positive"] is not None else "Not available"
        st.metric("RF pattern matches", value)
        st.caption(
            "RF = Random Forest, a learned pattern check. Counts only recorded windows with a valid "
            "score and their own recorded threshold, both from 0 to 1, in a completed check. "
            "A match resembles controlled weight manipulation; it is not a malware probability."
        )
        st.caption(
            f"Recorded RF rows: {display_value(rf['recorded'])}; eligible rows: {display_value(rf['eligible'])}. "
            f"Layer status: {rf['status']}. Missing or invalid outputs are not zero matches."
        )
    with c:
        value = (
            f"{100 * reference['differing'] / reference['compared']:.2f}% changed"
            if reference["differing"] is not None else "Not available"
        )
        st.metric("Change from reference", value)
        if reference["differing"] is not None:
            st.caption(f"{reference['differing']:,} changed / {reference['compared']:,} compared bytes.")
        st.caption(
            "Differing bytes / compared bytes only, not all bytes in the file. "
            "An optional reference is another checkpoint you choose for comparison, not a guaranteed "
            "trusted or clean model. Ordinary training can change these bytes."
        )
        st.caption("Reference layer status: " + reference["status"] + ". Missing comparison is not zero change.")
    sampling = summary["sampling"]
    if sampling["sampled"] is not None:
        st.write(
            f"**Weight sampling:** {sampling['sampled']:,} of {sampling['total']:,} recorded F32 "
            "weight elements sampled. F32 means 32-bit floating-point weights; this population "
            "is not the whole file or other number formats."
        )
    else:
        st.write("**Weight sampling:** no valid sampled / total F32 element denominator is available.")
    st.caption("These checks answer different questions. Their counts overlap and must not be added together.")
    with st.expander("What ran, what is missing, and why it matters"):
        for layer in coverage["layers"]:
            st.write("**" + layer["label"] + ":** " + layer["status"])
        st.write(
            "Unavailable, skipped, unsupported, failed and partial checks leave coverage gaps. "
            "No missing value is treated as zero or as a clean result. Unsampled weights and "
            "unknown triggers may remain unobserved."
        )
        for limitation in report.get("limitations", []) if isinstance(report.get("limitations"), list) else []:
            st.write("• " + display_value(limitation))
    from stegogate.evidence_explorer import render_evidence_explorer

    render_evidence_explorer(report)
    st.markdown("### What to do next")
    st.write(
        "1. Check where the model came from and whether its file hash matches a source you trust.\n"
        "2. Review flagged patterns and missing checks with someone who understands the model; "
        "do not treat an absence of indicators as permission to execute it.\n"
        "3. Save the report below. Turn on **Show technical details** in the sidebar to inspect "
        "the underlying records and the original evidence."
    )
    render_report_controls(report)
    with st.expander("Evidence Assistant · optional explanation"):
        from stegogate.assistant_ui import render_interpretation

        try:
            render_interpretation(report)
        except (ValueError, TypeError):
            st.warning(
                "Evidence Assistant unavailable: this report exceeds its input budget or has unsupported values. "
                "The original report and existing evidence views are unchanged."
            )


def render_report(report):
    if st.session_state.get("dashboard_technical", False):
        render_technical_report(report)
    else:
        render_simple_report(report)


def render_technical_report(report):
    art = as_dict(report.get("artifact"))
    st.subheader(display_value(art.get("original_name", "Artifact evidence")))
    st.caption(
        "Report " + display_value(report.get("scan_id")) + " · " + display_value(report.get("created_at"))
    )
    verdict = display_value(report.get("verdict", "No conclusion recorded"))
    if str(report.get("status")) == "rejected":
        st.error(verdict)
    elif verdict.startswith("REVIEW"):
        st.warning(verdict)
    else:
        st.info(verdict)
    st.caption(
        "Report status: "
        + display_value(report.get("status"))
        + ". Indicators are not proof of malware; missing coverage is not a pass."
    )
    summary = as_dict(report.get("summary"))
    for column, (label, key) in zip(
        st.columns(5),
        [
            ("ModelAudit findings", "static_finding_count"),
            ("Picklescan findings", "picklescan_finding_count"),
            ("Heuristic windows", "heuristic_window_count"),
            ("ML-positive windows", "ml_positive_window_count"),
            ("Sampled windows", "analyzed_window_count"),
        ],
    ):
        column.metric(label, display_value(summary.get(key)))
    st.caption(
        "Window counts overlap and are not independent detections. ML votes describe controlled-manipulation patterns, not backdoor probabilities."
    )
    render_report_controls(report)
    from stegogate.assistant_ui import render_interpretation

    tabs = st.tabs(
        [
            "Overview",
            "Tensor explorer",
            "Signal lab",
            "Static indicators",
            "ML detector",
            "Reference diff",
            "Research atlas",
            "Half precision",
            "Evidence Assistant",
            "Raw evidence",
        ]
    )
    for tab, render in zip(
        tabs[:6],
        [render_overview, render_tensors, render_signals, render_static, render_ml, render_reference],
    ):
        with tab:
            render(report)
    with tabs[6]:
        render_research_atlas(report)
    with tabs[7]:
        render_precision(report)
    with tabs[8]:
        try:
            render_interpretation(report)
        except (ValueError, TypeError):
            st.warning(
                "Evidence Assistant unavailable: this report exceeds its input budget or has unsupported values. The original report and existing evidence views are unchanged."
            )
    with tabs[9]:
        st.caption(
            "Original report, including configuration, limitations, and behavioral evidence. Nothing is converted into an overall safe/unsafe label."
        )
        st.json(report)


def saved_reports(storage):
    try:
        items = storage.list_reports()
        if not isinstance(items, list):
            return []
        output = []
        for item in items:
            item = {"scan_id": item} if isinstance(item, str) else item
            if isinstance(item, dict) and valid_report_id(item.get("scan_id")):
                output.append(item)
        return output
    except Exception as exc:
        st.sidebar.warning("Saved-report listing unavailable: " + str(exc))
        return []


def render_upload(storage):
    with st.expander("Check a model file", expanded="active_report" not in st.session_state):
        st.caption(
            "One artifact, optional compatible reference. Maximum 256 MiB per file. Uploads are staged with random server-owned names; original names are display-only."
        )
        a, b = st.columns(2)
        with a:
            artifact = st.file_uploader(
                "Model file", type=None, accept_multiple_files=False, key="artifact_upload"
            )
        with b:
            reference = st.file_uploader(
                "Optional reference checkpoint", type=None, accept_multiple_files=False, key="reference_upload"
            )
        from stegogate.platform_support import capabilities

        host = capabilities()
        if not host["linux_isolation_eligible"]:
            st.info(host["note"])
        static = st.checkbox(
            "Run optional ModelAudit static engine",
            value=host["linux_isolation_eligible"],
            disabled=not host["linux_isolation_eligible"],
        )
        picklescan = st.checkbox(
            "Run independent Picklescan disassembly for pickle / ZIP",
            value=host["linux_isolation_eligible"],
            disabled=not static,
        )
        detector_path = None
        expanded = Path(storage.data_root()) / "detector-v2" / "detector.json"
        if expanded.is_file():
            profile = st.selectbox(
                "CPU Random Forest profile",
                ["Original exploratory benchmark", "Expanded nine-group benchmark"],
                key="detector_profile",
            )
            if profile == "Expanded nine-group benchmark":
                detector_path = str(expanded)
            st.caption(
                "Neither profile is calibrated for arbitrary malware or backdoors. Expanded benchmark uses two held-out groups; random-payload misses are retained. Existing saved reports do not change."
            )
        st.caption(
            "No inference, arbitrary code execution, remote download, or behavioral triggering is performed by this scan. F32 RF scoring and separate descriptive F16/BF16 statistics are available for eligible safetensors."
        )
        if st.button("Run CPU analysis", type="primary", disabled=artifact is None, width="stretch"):
            if any(
                getattr(f, "size", MAX_UPLOAD_BYTES + 1) > MAX_UPLOAD_BYTES
                for f in (artifact, reference)
                if f is not None
            ):
                st.error("File exceeds the 256 MiB per-artifact limit. Nothing was scanned.")
                return
            try:
                from stegogate.pipeline import scan_artifact

                with st.status("CPU analysis in progress", expanded=True) as status:
                    st.write("Staging bounded local artifacts…")
                    artifact.seek(0)
                    path = storage.stage_upload(artifact, artifact.name)
                    reference_path = None
                    if reference is not None:
                        reference.seek(0)
                        reference_path = storage.stage_upload(reference, reference.name)
                    st.write("Inspecting structure and running configured evidence layers…")
                    report = scan_artifact(
                        path,
                        reference_path=reference_path,
                        config={
                            "run_static": static,
                            "run_picklescan": picklescan,
                            "detector_path": detector_path,
                            "max_artifact_bytes": MAX_UPLOAD_BYTES,
                            "original_name": Path(artifact.name.replace("\\", "/")).name[:240],
                        },
                    )
                    # Original upload names are provenance only, not filesystem paths.
                    as_dict(report.get("artifact"))["original_name"] = Path(
                        artifact.name.replace("\\", "/")
                    ).name[:240]
                    st.write("Saving reproducible evidence report…")
                    storage.save_report(report)
                    st.session_state.active_report = report
                    status.update(label="Analysis report saved", state="complete", expanded=False)
                st.rerun()
            except Exception as exc:
                st.error("Analysis did not complete: " + str(exc))
                st.caption(
                    "No clean result is inferred. Review runtime configuration and engine availability."
                )


def render_demo(storage):
    st.subheader("See a prepared model example")
    st.write(
        "Explore saved evidence from a controlled example. A reference checkpoint is a comparison point, "
        "not a universally clean model. A backdoored example demonstrates a documented trigger; "
        "it does not teach this tool to find every unknown trigger."
    )
    st.info(
        "This page replays bounded, locally prepared evidence, not live model inference. Downloads, checkpoint conversion, and behavioral verification are explicit CLI preparation steps—not dashboard actions."
    )
    catalog = []
    try:
        from stegogate.demo import get_demo_catalog

        catalog = records(get_demo_catalog())
    except (ImportError, AttributeError) as exc:
        st.warning("Demo catalog module is not available: " + str(exc))
    selected_id = None
    if catalog:
        selected = st.selectbox(
            "Allowlisted demo",
            range(len(catalog)),
            format_func=lambda i: display_value(
                catalog[i].get(
                    "title", catalog[i].get("name", catalog[i].get("demo_id", catalog[i].get("id", i)))
                )
            ),
        )
        entry = catalog[selected]
        selected_id = entry.get("demo_id", entry.get("id"))
        with st.expander("Pinned source manifest · not measured evaluation", expanded=False):
            st.json(entry)
        st.caption(
            "Catalog hashes and sizes describe original source files; prepared artifact identity is recorded separately below."
        )
    st.markdown("### Known trigger ≠ unknown trigger")
    st.write(
        "Known-trigger verification asks whether a documented local trigger reproduces specified behavior. Unknown-trigger detection is a different, unsolved scope here. An unverified or unavailable behavior run does not establish absence of a backdoor."
    )
    documents = demo_documents(Path(storage.data_root()) / "demo")
    if not documents:
        st.warning(
            "No bounded prepared JSON manifests or results found under the configured demo directory. No evaluation metrics are available to display."
        )
        return
    root = Path(storage.data_root()) / "demo"
    if selected_id is not None:
        documents = [
            (path, payload)
            for path, payload in documents
            if str(path.relative_to(root)).split("/")[0] == selected_id
            or payload.get("demo_id") == selected_id
        ]
    if not documents:
        st.warning(
            "This allowlisted demo has no prepared local manifest or verification result. Preparation must be performed explicitly through the CLI."
        )
        return
    manifest = next((payload for path, payload in documents if path.name == "manifest.json"), {})
    verification = next((payload for path, payload in documents if path.name == "verification.json"), {})
    left, right = st.columns([1, 1], gap="large")
    with left:
        st.markdown("**Prepared artifact provenance**")
        properties(
            {
                key: manifest.get(key)
                for key in (
                    "status",
                    "demo_id",
                    "sha256",
                    "size_bytes",
                    "source_sha256",
                    "source_revision",
                    "architecture_status",
                    "tensor_count",
                )
            }
        )
    with right:
        st.markdown("**Local known-trigger verification**")
        if verification:
            properties(
                {
                    key: verification.get(key)
                    for key in (
                        "status",
                        "behavioral_status",
                        "sample_count",
                        "clean_correct",
                        "triggered_shifted_label_hits",
                        "inference_seconds",
                        "duration_seconds",
                        "artifact_sha256",
                    )
                    if key in verification
                }
            )
            # Rates retain their source representation. Do not invent units or percent calibration.
            for key in ("clean_accuracy", "shifted_label_attack_success"):
                if finite_number(verification.get(key)):
                    st.write(key + ": " + str(verification[key]) + " (recorded fraction)")
            if (
                verification.get("status") == "completed"
                and verification.get("behavioral_status") == "verified_known_trigger"
            ):
                observed = [
                    {"Observed measure": title, "Observed percent": 100 * verification[key]}
                    for key, title in [
                        ("clean_accuracy", "Clean classification accuracy"),
                        ("shifted_label_attack_success", "Shifted-label attack success"),
                    ]
                    if finite_number(verification.get(key)) and 0 <= verification[key] <= 1
                ]
                if observed:
                    st.caption(
                        "Measured local known-trigger evaluation · percentages of the recorded sample set"
                    )
                    fig = px.bar(
                        observed,
                        x="Observed percent",
                        y="Observed measure",
                        orientation="h",
                        color_discrete_sequence=["#ededed"],
                        text="Observed percent",
                    )
                    fig.update_traces(texttemplate="%{x:.2f}%", textposition="auto")
                    fig = chart_style(fig, x_title="Observed samples (%)", y_title=None)
                    fig.update_layout(height=230)
                    fig.update_xaxes(range=[0, 100], ticksuffix="%")
                    st.plotly_chart(fig, width="stretch")
            if verification.get("reason"):
                st.warning(display_value(verification["reason"]))
        else:
            st.warning("Not verified locally. No measured attack-success or accuracy result is available.")
        st.caption(
            "These are controlled known-trigger observations only, not unknown-trigger detection or a universal safety test."
        )
    # Only fixed prepared filenames for hardcoded IDs. Manifest artifact_path is display-only.
    if selected_id in {"mnist-epoch01", "mnist-epoch02", "cifar10-resnet18"}:
        path = root / selected_id / "model.safetensors"
        resolved = path.resolve()
        eligible = (
            resolved.is_relative_to(root.resolve())
            and path.is_file()
            and not path.is_symlink()
            and path.stat().st_size <= MAX_UPLOAD_BYTES
        )
        if st.button("Analyze prepared artifact · CPU static scan", disabled=not eligible, type="primary"):
            try:
                from stegogate.pipeline import scan_artifact

                with st.status("Scanning prepared local artifact…") as scan_status:
                    result = scan_artifact(
                        resolved, config={"original_name": selected_id + "/model.safetensors"}
                    )
                    storage.save_report(result)
                    st.session_state["demo_active_report"] = result
                    st.session_state["demo_active_id"] = selected_id
                    scan_status.update(label="Prepared artifact report saved", state="complete")
            except Exception as exc:
                st.error("Prepared artifact analysis failed: " + str(exc))
        if not eligible:
            st.caption(
                "Static analysis is enabled only for a prepared, bounded, local model.safetensors artifact."
            )
    options = {str(path.relative_to(root)): payload for path, payload in documents}
    filename = st.selectbox("Prepared local manifest / result", list(options))
    payload = options[filename]
    if payload.get("schema_version") and payload.get("scan_id") and isinstance(payload.get("artifact"), dict):
        render_report(payload)
    else:
        st.caption(
            "Original prepared document. Author-reported metrics, if present, are source claims—not measurements performed by this dashboard. Only explicit verification results establish measured behavior."
        )
        st.json(payload)
    if (
        isinstance(st.session_state.get("demo_active_report"), dict)
        and st.session_state.get("demo_active_id") == selected_id
        and not (payload.get("schema_version") and payload.get("scan_id"))
    ):
        st.divider()
        render_report(st.session_state["demo_active_report"])
    st.markdown("**Evidence handling**")
    st.caption(
        "Only bounded JSON files inside the configured demo root are read. No host-path browser, remote source execution, model loading, or preparation commands are exposed."
    )


def main():
    with st.sidebar:
        st.markdown("## StegoLens")
        st.caption("Visual AI model investigation")
        st.toggle("Show technical details", value=False, key="dashboard_technical")
        if "workspace_route" not in st.session_state:
            st.session_state["workspace_route"] = (
                "Analysis console"
                if isinstance(st.session_state.get("active_report"), dict)
                or st.session_state.get("dashboard_technical", False)
                else "Visual experiences"
            )
        route = st.radio(
            "Workspace",
            ["Visual experiences", "Analysis console", "Compare reports", "Demo & evaluation", "Compatibility & scope"],
            key="workspace_route",
            format_func=lambda route: {
                "Visual experiences": "Normal vs backdoored demo",
                "Analysis console": "Inspect a model file",
                "Compare reports": "Compare saved scans",
                "Demo & evaluation": "Prepared evidence · technical",
                "Compatibility & scope": "What this tool can check",
            }[route],
            label_visibility="collapsed",
        )
        st.divider()
        st.markdown("**Runtime policy**")
        st.write("CPU only · local artifacts")
        st.caption("Default scan: no network, no inference, no unsafe model loaders.")
    st.caption("Visual AI model investigation")
    st.title("StegoLens")
    st.markdown("**Explore, compare and investigate AI model files**")
    st.write(
        "See how hidden information and documented backdoors work. Then inspect a model file without "
        "running it. This is steganographic malware detection research—not proof of malware or safety."
    )
    if route == "Visual experiences":
        demo_mode = st.radio("Demo execution", ["Recorded results", "Live inference"],
                             horizontal=True, key="demo_execution_mode")
        if demo_mode == "Live inference":
            from stegogate.live_controlled_demo import render_live_demo

            render_live_demo()
        else:
            from stegogate.controlled_demo import render_controlled_demo

            render_controlled_demo()
        with st.expander("More learning experiments · message lab and earlier public example"):
            from stegogate.visual_experiences import render_visual_experiences

            render_visual_experiences()

        def open_inspector():
            st.session_state["workspace_route"] = "Analysis console"

        st.divider()
        st.button("Inspect a model file", on_click=open_inspector, key="experience_open_inspector")
        st.caption("File inspection reads supported model data; it does not execute the uploaded model.")
        return
    try:
        from stegogate import storage
    except ImportError as exc:
        st.error("Storage adapter unavailable: " + str(exc))
        st.info(
            "The dashboard is installed; complete the pipeline/storage modules before scanning artifacts."
        )
        return
    if route == "Demo & evaluation":
        render_demo(storage)
        return
    if route == "Compare reports":
        render_comparison(storage)
        return
    if route == "Compatibility & scope":
        render_compatibility()
        return
    with st.sidebar:
        st.markdown("**Saved reports**")
    items = saved_reports(storage)
    choices = ["Current session / new analysis"] + [r["scan_id"] for r in items]
    selected = st.sidebar.selectbox(
        "Report",
        choices,
        format_func=lambda value: (
            value
            if value == choices[0]
            else next(
                (
                    str(r.get("original_name", as_dict(r.get("artifact")).get("original_name", "Artifact")))
                    + " · "
                    + value[:8]
                    for r in items
                    if r["scan_id"] == value
                ),
                value,
            )
        ),
    )
    if selected != choices[0]:
        try:
            report = storage.load_report(selected)
            if isinstance(report, dict):
                render_report(report)
            else:
                st.error("Stored report is not a JSON object.")
        except Exception as exc:
            st.error("Could not load selected report: " + str(exc))
        return
    render_upload(storage)
    report = st.session_state.get("active_report")
    if isinstance(report, dict):
        render_report(report)
    else:
        st.divider()
        st.subheader("Start with three steps")
        st.caption("No analysis has run. Choose a file above or open a saved scan in the sidebar.")
        st.write("**1. Choose a model file.** Add one local file, up to 256 MiB. A reference checkpoint is optional.")
        st.write("**2. Run the check.** Click Run CPU analysis when you are ready. This inspects the file; it does not run the model.")
        st.write("**3. Read the evidence.** See the recorded verdict, the checks that ran, and any missing coverage.")
        st.info(
            "This tool looks for specific indicators, not a universal safe/infected answer. "
            "No indicators found is not a pass; missing checks and unknown triggers remain unknown."
        )


if __name__ == "__main__":
    main()
