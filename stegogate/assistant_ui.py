"""Explicit, session-scoped interpretation and offline PDF controls.

No network calls occur during rendering, PDF export or a scan. Groq is invoked
only by the consent-gated button. Untrusted generated text uses st.text, not HTML.
"""

from __future__ import annotations
import hashlib
import json
import time

MODELS = ["openai/gpt-oss-20b", "openai/gpt-oss-120b"]
TTL_SECONDS = 3600


def _plain(st, value):
    # Plain text only: generated Markdown/images/HTML are never interpreted.
    try:
        st.text(str(value), wrap_lines=True)
    except TypeError:  # Compatibility with older Streamlit releases.
        import textwrap

        st.text(textwrap.fill(str(value), width=76, break_long_words=False, break_on_hyphens=False))


def _bounded_cache(state, name, limit):
    cache = state.get(name, {})
    now = time.time()
    cache = {
        k: v for k, v in cache.items() if isinstance(v, dict) and now - v.get("created", 0) < TTL_SECONDS
    }
    while len(cache) > limit:
        cache.pop(next(iter(cache)))
    state[name] = cache
    return cache


def current_interpretation(report, state):
    from .explanation import PROMPT_VERSION, offline_explanation, report_digest

    digest = report_digest(report)
    if state.get("sg_mode_" + digest) == "Groq · explicit cloud request":
        model = state.get("sg_model_" + digest, MODELS[0])
        cached = _bounded_cache(state, "sg_explanations", 8).get((digest, model, PROMPT_VERSION))
        if cached and cached.get("result", {}).get("status") == "completed":
            return cached["result"]
    cache = _bounded_cache(state, "sg_offline", 8)
    key = (digest, PROMPT_VERSION)
    if key not in cache:
        cache[key] = {"created": time.time(), "result": offline_explanation(report)}
        while len(cache) > 8:
            cache.pop(next(iter(cache)))
        state["sg_offline"] = cache
    return cache[key]["result"]


def render_interpretation(report):
    import streamlit as st
    from .explanation import (
        PROMPT_VERSION,
        build_evidence_bundle,
        explain_with_groq,
        get_api_status,
        report_digest,
        offline_explanation,
    )

    digest = report_digest(report)
    st.subheader("Evidence Assistant")
    st.caption(
        "Interpretation, not detection. Explanations cannot change the saved report, run tools or certify model safety."
    )
    mode = st.radio(
        "Explanation mode",
        ["Offline · deterministic", "Groq · explicit cloud request"],
        key="sg_mode_" + digest,
    )
    if mode == "Groq · explicit cloud request":
        model = st.selectbox("Groq model", MODELS, key="sg_model_" + digest)
        st.warning(
            "Optional cloud inference: selected redacted scan evidence leaves this machine for Groq. No checkpoint or raw weights are sent. Privacy and account quota limits apply; zero retention is not promised. The app cannot verify free quota or prevent charges under a paid Groq account."
        )
        with st.expander("Preview the exact evidence bundle sent to Groq"):
            st.json(build_evidence_bundle(report))
            st.caption(
                "The request also includes fixed interpretation instructions and a JSON response schema. Artifact and tensor names, paths and free-form scanner messages are excluded from this bundle."
            )
        st.caption(
            "Groq selects and prioritizes eligible application-defined explanations; it does not author unrestricted prose. "
            "Statements must retain their exact evidence references. Numeric measurements are displayed deterministically."
        )
        with st.expander("Interpretation statements eligible for this report"):
            from .explanation import _eligible_cards

            st.json(_eligible_cards(build_evidence_bundle(report)))
        with st.expander("Interpretation context sent with the evidence"):
            from .explanation import EVIDENCE_CONTEXT

            _plain(st, EVIDENCE_CONTEXT)
            st.caption(
                "Application-owned definitions, not additional findings. Prompt version: " + PROMPT_VERSION
            )
        configured = bool(get_api_status().get("key_configured"))
        if not configured:
            st.info(
                "Groq is not configured. An operator must set the server-side GROQ_API_KEY or private Groq key file. Never paste an API key into a report or question. Offline explanations and PDF export remain available."
            )
        consent = st.checkbox(
            "Allow sending this previewed evidence bundle to Groq for this request",
            key="sg_consent_" + digest + "_" + model + "_" + PROMPT_VERSION,
        )
        cache = _bounded_cache(st.session_state, "sg_explanations", 8)
        cache_key = (digest, model, PROMPT_VERSION)
        if st.button(
            "Generate Groq interpretation", disabled=not (configured and consent), key="sg_generate_" + digest
        ):
            if cache_key in cache:
                st.info("Using the existing session-cached interpretation; no additional request was sent.")
            else:
                with st.spinner("Requesting a bounded Groq interpretation…"):
                    result = explain_with_groq(report, consent=True, model=model)
                if result.get("status") == "completed":
                    cache[cache_key] = {"created": time.time(), "result": result}
                    while len(cache) > 8:
                        cache.pop(next(iter(cache)))
                    st.session_state.sg_explanations = cache
                    st.rerun()
                else:
                    st.warning(
                        "Groq interpretation unavailable. The original report and offline interpretation are unchanged."
                    )
                    for warning in result.get("warnings", [])[:5]:
                        _plain(st, warning)
        if cache_key in cache and st.button("Clear cached Groq interpretation", key="sg_clear_" + digest):
            cache.pop(cache_key)
            st.session_state.sg_explanations = cache
            st.rerun()
        if cache_key not in cache:
            st.caption(
                "No Groq interpretation is available for this report/model. Showing the deterministic offline interpretation below."
            )
    explanation = current_interpretation(report, st.session_state)
    if explanation.get("mode") == "groq":
        st.warning(
            "AI interpretation — unverified. Existing evidence references are checked; this does not establish that the prose is factually correct."
        )
        with st.expander("Recorded facts · deterministic, not generated by Groq", expanded=True):
            for row in offline_explanation(report).get("observations", [])[:8]:
                _plain(st, row.get("text", ""))
                st.caption("Evidence: " + ", ".join(row.get("evidence_refs", [])[:8]))
    else:
        st.info("Deterministic offline interpretation — no external request.")
    st.warning(
        "Scope: sampled evidence is not complete coverage. A learned vote is not a malware/backdoor probability. No finding or explanation certifies safety; unsupported and missing layers remain unchecked."
    )
    st.caption(
        "Provider: "
        + str(explanation.get("provider"))
        + " · Model: "
        + str(explanation.get("model") or "none")
        + " · Prompt: "
        + str(explanation.get("prompt_version"))
    )
    for key, title in [
        ("observations", "Observations"),
        ("limitations", "Limitations"),
        ("next_steps", "Next inspection steps"),
    ]:
        st.markdown("**" + title + "**")
        for row in explanation.get(key, [])[:12]:
            _plain(st, row.get("text", ""))
            st.caption("Evidence: " + ", ".join(str(ref) for ref in row.get("evidence_refs", [])[:8]))
    with st.expander("Mandatory interpretation scope notes"):
        for warning in explanation.get("warnings", [])[:8]:
            _plain(st, warning)
    with st.expander("Interpretation provenance and usage"):
        st.json(
            {
                k: explanation.get(k)
                for k in (
                    "mode",
                    "status",
                    "provider",
                    "model",
                    "report_sha256",
                    "bundle_sha256",
                    "prompt_version",
                    "generated_at",
                    "usage",
                )
            }
        )
    st.caption(
        "Interpretations are cached only in this browser session for up to one hour, at most eight entries. No automatic retries, cloud fallback or other hosted provider is enabled."
    )


def render_pdf_controls(report):
    import streamlit as st
    from .explanation import report_digest

    digest = report_digest(report)
    with st.expander("Detailed PDF evidence report"):
        st.caption(
            "Generated locally on CPU. The PDF contains measured evidence, coverage, provenance, selected plots and bounded detail appendices. Full machine-readable evidence remains in the JSON export."
        )
        include = st.checkbox(
            "Include the currently selected interpretation as a separate appendix",
            value=False,
            key="sg_pdf_appendix_" + digest,
        )
        explanation = None
        if include:
            try:
                explanation = current_interpretation(report, st.session_state)
            except (ValueError, TypeError):
                st.warning(
                    "Interpretation appendix unavailable under its input limits; report-only PDF preparation remains available."
                )
        if explanation:
            st.caption(
                "Appendix: "
                + (
                    "AI interpretation — unverified"
                    if explanation.get("mode") == "groq"
                    else "Deterministic offline interpretation"
                )
                + ". Preparing a PDF does not call Groq."
            )
        appendix_hash = (
            hashlib.sha256(
                json.dumps(explanation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
            if explanation
            else "none"
        )
        cache = _bounded_cache(st.session_state, "sg_pdfs", 3)
        key = (digest, appendix_hash)
        if st.button("Prepare detailed PDF", key="sg_pdf_prepare_" + digest):
            try:
                from .pdf_report import build_pdf

                with st.spinner("Building the local evidence PDF…"):
                    payload = build_pdf(report, explanation=explanation)
                cache[key] = {"created": time.time(), "bytes": payload}
                while len(cache) > 3:
                    cache.pop(next(iter(cache)))
                st.session_state.sg_pdfs = cache
            except ImportError:
                st.warning("PDF dependency unavailable; JSON and HTML exports are unaffected.")
            except Exception:
                st.warning(
                    "PDF generation did not complete. The evidence report is unchanged; use JSON or HTML export."
                )
        if key in cache:
            st.download_button(
                "↓ Detailed PDF report",
                data=cache[key]["bytes"],
                file_name="T04-Scnr-" + digest[:12] + ".pdf",
                mime="application/pdf",
                key="sg_pdf_download_" + digest,
            )
