"""Offline, bounded learning experiences; never run a supplied model or scanner.

The recorded viewer accepts one pinned repository fixture, not arbitrary image or
JSON input. The separate toy experiment is imported only on explicit creation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import struct
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

SAMPLES_PATH = Path(__file__).resolve().parents[1] / "docs" / "visual-demo" / "samples.json"
SAMPLES_SHA256 = "7efda6978fdb3ed15314443b59a6a430c72db2afcf8152fcc3689496ac335e8f"
MAX_RECORD_BYTES = 65_536
MAX_MESSAGE_BYTES = 128
MODEL_HASHES = (
    "88ebce334a81ad59fe59dc809165f25ba2ff3520bfd3701ba644dfe1720a78bf",
    "6d33d1dcfe4a81ad0b0636bec59e724b748c6e9b61db1d6e2d0c67e090da8d19",
)
DATASET_HASHES = (
    "8d422c7b0a1c1c79245a5bcf07fe86e33eeafee792b84584aec276f5a2dbc4e6",
    "f7ae60f92e00ec6debd23a6088c31dbd2371eca3ffa0defaefb259924204aec6",
)
SOURCE_COMMIT = "8ddce8ea2620d7fdaeaf625ad4b9f1e36c994fa7"
TRIGGER_PIXELS = ((24, 26), (25, 25), (26, 24), (26, 26))
EXPERIENCES = (
    "Watch a hidden trigger",
    "Hide and reveal a message",
    "How to investigate a file",
)


class RecordedDataError(ValueError):
    """The bundled evidence cannot safely be displayed."""


@dataclass(frozen=True)
class RecordedSample:
    index: int
    true_label: int
    attack_target: int
    normal_png: bytes
    triggered_png: bytes
    epoch1_normal: int
    epoch1_triggered: int
    epoch2_normal: int
    epoch2_triggered: int


@dataclass(frozen=True)
class RecordedEvidence:
    samples: tuple[RecordedSample, ...]
    generated_at: str
    selection: str
    inference: str
    limitations: tuple[str, ...]


def _validated_png(encoded: str) -> bytes:
    """Validate byte bounds and 28x28 grayscale PNG header before any decoder."""
    if not isinstance(encoded, str) or len(encoded) > 4096:
        raise RecordedDataError("Invalid image bounds")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RecordedDataError("Invalid image encoding") from exc
    if (
        len(raw) < 45
        or raw[:8] != b"\x89PNG\r\n\x1a\n"
        or raw[8:16] != b"\x00\x00\x00\rIHDR"
        or struct.unpack(">IIBBBBB", raw[16:29]) != (28, 28, 8, 0, 0, 0, 0)
    ):
        raise RecordedDataError("Expected a 28 by 28 grayscale PNG")
    from PIL import Image

    try:
        with Image.open(io.BytesIO(raw)) as image:
            image.verify()
        with Image.open(io.BytesIO(raw)) as image:
            image.load()
            if image.size != (28, 28) or image.mode != "L":
                raise RecordedDataError("Unexpected decoded image")
    except (OSError, SyntaxError, ValueError) as exc:
        raise RecordedDataError("Invalid image data") from exc
    return raw


def load_recorded_evidence() -> RecordedEvidence:
    """Return immutable records only after pinning the complete bounded source."""
    try:
        with SAMPLES_PATH.open("rb") as source:
            raw = source.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES or hashlib.sha256(raw).hexdigest() != SAMPLES_SHA256:
            raise RecordedDataError("Recorded source integrity mismatch")
        data = json.loads(raw)
        if (
            data["source_commit"] != SOURCE_COMMIT
            or tuple(data["model_sha256"].values()) != MODEL_HASHES
            or tuple(data["dataset_sha256"].values()) != DATASET_HASHES
            or data["trigger"] != {
                "pixels_row_column_0_based": [list(p) for p in TRIGGER_PIXELS],
                "white_uint8": 255,
                "target": "(true_label + 1) % 10",
            }
            or len(data["samples"]) != 12
        ):
            raise RecordedDataError("Unexpected evidence provenance")
        samples = []
        for index, row in enumerate(data["samples"]):
            integer_fields = (
                "true_label", "attack_target", "epoch1_normal", "epoch1_triggered",
                "epoch2_normal", "epoch2_triggered",
            )
            if row["index"] != index or any(
                type(row[key]) is not int or not 0 <= row[key] <= 9 for key in integer_fields
            ) or row["attack_target"] != (row["true_label"] + 1) % 10:
                raise RecordedDataError("Unexpected sample labels")
            samples.append(RecordedSample(
                index=index,
                normal_png=_validated_png(row["normal_png_base64"]),
                triggered_png=_validated_png(row["triggered_png_base64"]),
                **{key: row[key] for key in integer_fields},
            ))
        return RecordedEvidence(
            tuple(samples), data["generated_at"], data["sample_selection"],
            data["inference"], tuple(data["limitations"]),
        )
    except RecordedDataError:
        raise
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        raise RecordedDataError("Recorded evidence unavailable") from exc


def _pixel_image(raw: bytes, *, crop: bool = False):
    # Called only with immutable validated fixture bytes, never an upload or URL.
    from PIL import Image

    with Image.open(io.BytesIO(raw)) as image:
        pixels = image.crop((20, 20, 28, 28)) if crop else image.copy()
    return pixels.resize((112, 112) if crop else (224, 224), Image.Resampling.NEAREST)


def _recorded_card(sample: RecordedSample, epoch: int, triggered: bool) -> None:
    with st.container(border=True):
        st.subheader("Earlier reference" if epoch == 1 else "Published backdoored")
        st.caption(f"Epoch {epoch} · recorded checkpoint")
        raw = sample.triggered_png if triggered else sample.normal_png
        state = "known trigger added" if triggered else "normal image"
        st.image(
            _pixel_image(raw), width=224,
            caption=f"Actual MNIST digit {sample.true_label}; {state}. Nearest-neighbor enlargement.",
        )
        baseline = getattr(sample, f"epoch{epoch}_normal")
        prediction = getattr(sample, f"epoch{epoch}_{'triggered' if triggered else 'normal'}")
        st.caption("Input → model checkpoint → recorded prediction")
        st.metric("Predicted digit", str(prediction))
        if triggered and prediction != baseline:
            st.warning(f"Prediction changed: {baseline} → {prediction}. Not an infection verdict.")
        else:
            st.info(f"Prediction unchanged from normal input: {baseline}.")
        st.caption(
            "Not independently clean-trained; not a safety certificate."
            if epoch == 1 else "Known-trigger behavior of this exact checkpoint only."
        )


def _render_recorded(technical: bool) -> None:
    st.header("Same digit. A small pattern. A different answer.")
    st.caption("Recorded predictions — no model runs here")
    st.write(
        "Choose a handwritten digit, then add the documented four-pixel pattern. "
        "Watch the recorded answers—not a live model or a file scan."
    )
    try:
        evidence = load_recorded_evidence()
    except RecordedDataError:
        st.warning(
            "The bundled recorded examples are missing or failed validation. "
            "No images or predictions were displayed. Restore the original "
            "docs/visual-demo/samples.json to use this experience. The other experiences remain available."
        )
        return
    index = st.selectbox(
        "Choose a sample · all 12, original test order", range(12),
        format_func=lambda i: f"Sample {i} — handwritten {evidence.samples[i].true_label}",
        key="ve_sample",
    )
    triggered = st.checkbox("Add the known trigger", key="ve_trigger")
    sample = evidence.samples[index]
    st.write(
        f"**True digit: {sample.true_label}** · **Attack target: {sample.attack_target}** · "
        f"Input: {'known trigger added' if triggered else 'normal image'}"
    )
    for column, epoch in zip(st.columns(2), (1, 2)):
        with column:
            _recorded_card(sample, epoch, triggered)
    with st.expander("Look closely at the four pixels", expanded=triggered):
        raw = sample.triggered_png if triggered else sample.normal_png
        st.image(_pixel_image(raw, crop=True), width=112,
                 caption="Actual lower-right 8 × 8 input region, enlarged without smoothing.")
        st.write(
            "The trigger sets four pixels to white (255). Zero-based (row, column): "
            "(24, 26), (25, 25), (26, 24), (26, 26). The true digit label does not change. "
            "The documented attack target is (true digit + 1) modulo 10, so 9 wraps to 0."
        )
    with st.expander("Why does this matter?"):
        st.write(
            "A model may recognize ordinary inputs yet behave differently on a special pattern. "
            "This example shows a known backdoor's recorded behavior. It does not show malware "
            "spreading, prove any file is safe, or discover an unknown trigger. "
            "A pattern is a signal to investigate, not proof on its own."
        )
    with st.expander("How was this obtained?", expanded=technical):
        st.write(evidence.selection)
        st.write(evidence.inference)
        st.write(
            "Epoch 1 is an earlier checkpoint, not an independent clean-trained control. "
            "Epoch 2 is the published backdoored checkpoint. Training stage differs too; "
            "this is not a controlled claim that the trigger caused all weight differences."
        )
        st.caption(f"Recorded {evidence.generated_at} · pinned repository fixture, checked before display.")
        st.write("Source: [Authentrics MNIST BadNets](https://huggingface.co/authentrics/mnist-badnets-poisoned) "
                 "· [Reviewed behavior demo](https://github.com/Authentrics-ai/trojai-authentrics-demo). "
                 "Source model attribution/license: Apache-2.0; see upstream repository.")
        st.write("Model SHA-256 (epoch 1, epoch 2)")
        st.code("\n".join(MODEL_HASHES), language=None, wrap_lines=True)
        st.write("Canonical MNIST test image / label archive SHA-256")
        st.code("\n".join(DATASET_HASHES), language=None, wrap_lines=True)
        st.caption(f"Source commit: {SOURCE_COMMIT} · samples.json SHA-256: {SAMPLES_SHA256}")
    with st.expander("All 12 recorded examples · technical table", expanded=technical):
        st.caption("First 12 canonical MNIST test samples, unfiltered. Illustrations, not an accuracy estimate.")
        st.dataframe([
            {"Sample": s.index, "True digit": s.true_label, "Attack target": s.attack_target,
             "Epoch 1 normal → trigger": f"{s.epoch1_normal} → {s.epoch1_triggered}",
             "Epoch 2 normal → trigger": f"{s.epoch2_normal} → {s.epoch2_triggered}"}
            for s in evidence.samples
        ], hide_index=True, use_container_width=True)
    with st.expander("Separate recorded evaluation · 10,000 images"):
        st.caption("Prior full-test verification documented in docs/visual-demo/SEE-THE-DEMO.html. "
                   "These are NOT StegoLens scanner detection accuracy or results from these 12 examples.")
        st.write(
            "Epoch 1: 9,431 / 10,000 normal predictions correct; 41 / 10,000 triggered inputs "
            "matched the shifted attack target.\n\n"
            "Epoch 2: 9,664 / 10,000 normal predictions correct; 9,489 / 10,000 triggered inputs "
            "matched the shifted attack target.\n\n"
            "These counts apply only to the documented checkpoints, dataset and known trigger. "
            "No full-test evaluation runs on this page."
        )


def _clear_learning_result() -> None:
    st.session_state.pop("ve_lab_result", None)
    st.session_state.pop("ve_lab_source_message", None)
    st.session_state.pop("ve_lab_revealed", None)


def _learning_message_changed() -> None:
    st.session_state["ve_message_saved"] = st.session_state["ve_message"]
    _clear_learning_result()



def bit_figure(original: str, modified: str):
    """A fixed 2×32 categorical bit comparison; never a numeric-magnitude map."""
    if any(type(bits) is not str or len(bits) != 32 or set(bits) - {"0", "1"}
           for bits in (original, modified)):
        raise ValueError("Expected two exact 32-bit binary strings")
    import plotly.graph_objects as go

    changed = [a != b for a, b in zip(original, modified)]
    positions = list(range(31, -1, -1))
    rows = (original, modified)
    figure = go.Figure(go.Heatmap(
        x=positions, y=["Original", "Message copy"],
        z=[[2 if changed[i] else int(bit) for i, bit in enumerate(bits)] for bits in rows],
        text=[list(bits) for bits in rows], texttemplate="%{text}",
        textfont={"size": 11, "color": "#2C2C2B"},
        customdata=[[["changed" if changed[i] else "unchanged"] for i in range(32)] for _ in rows],
        hovertemplate=("%{y}<br>Bit position %{x}<br>Value %{text}"
                       "<br>Position %{customdata[0]} across pair<extra></extra>"),
        zmin=0, zmax=2, showscale=False, xgap=1, ygap=4,
        colorscale=[[0, "#F0EFED"], [0.249, "#F0EFED"],
                    [0.25, "#E5F2FC"], [0.749, "#E5F2FC"],
                    [0.75, "#FBEBDE"], [1, "#FBEBDE"]],
    ))
    figure.update_layout(
        height=205, margin={"l": 85, "r": 10, "t": 12, "b": 45},
        font={"size": 12}, dragmode=False,
        xaxis={"range": [31.5, -0.5], "tickvals": [31, 24, 16, 8, 0],
               "title": {"text": "Bit position · LSB 0 at right", "font": {"size": 11}},
               "fixedrange": True, "showgrid": False, "zeroline": False},
        yaxis={"autorange": "reversed", "fixedrange": True, "showgrid": False,
               "zeroline": False},
    )
    return figure


def _render_learning_result(result: dict, technical: bool) -> None:
    st.subheader("One original. One demo copy.")
    st.caption(str(result["source_label"]))
    for column, title, count in zip(
        st.columns(3), ("Message bytes", "Changed weights", "Changed bits"),
        (result["message_bytes"], result["changed_weights"], result["changed_bits"]),
    ):
        with column:
            st.metric(title, count)
    st.write("The original stays unchanged. The copy carries plain text in selected low-order weight bits.")
    if st.button("Reveal the message", key="ve_reveal"):
        st.session_state["ve_lab_revealed"] = True
    if st.session_state.get("ve_lab_revealed"):
        st.write("**Recovered plain text**")
        st.code(result["recovered_message"], language=None, wrap_lines=True)
        st.caption("Text is displayed as text, never executed. This is not malware embedding or a detector verdict.")
    st.subheader("Three copies, three explanations")
    comparisons = {item["kind"]: item for item in result["comparisons"]}
    for column, key, title in zip(
        st.columns(3), ("baseline", "ordinary_change", "embedded"),
        ("Original baseline", "Ordinary numeric change", "Message embedded"),
    ):
        with column, st.container(border=True):
            comparison = comparisons[key]
            st.markdown(f"**{title}**")
            st.write(f"{comparison['changed_weights']} / {comparison['total_weights']} weights changed")
            st.write("Message recovered: " + ("yes" if comparison["message_recovered"] else "no"))
            st.caption(str(comparison["scope"]))
    st.info(
        "Different does not mean malicious. The ordinary change is illustrative—not actual fine-tuning. "
        "This toy experiment does not promise unchanged predictions or classify a model as safe or unsafe."
    )
    predictions = result.get("predictions")
    if predictions:
        st.subheader("Did the toy answers change?")
        st.metric("Observed class changes on the fixed toy grid",
                  f"{predictions['changed_count']} / {predictions['denominator']}")
        st.caption("Actual NumPy forward passes on 25 fixed illustrative inputs. This is not accuracy, "
                   "a MNIST evaluation, or a promise that other inputs or models would behave the same.")
        with st.expander("See the computed toy comparison", expanded=technical):
            st.write(str(predictions["label"]))
            st.dataframe([
                {"Input": str(point), "Original class": before, "Message-copy class": after,
                 "Ordinary-change class": ordinary}
                for point, before, after, ordinary in zip(
                    predictions["inputs"][:25], predictions["before"][:25],
                    predictions["after"][:25], predictions["ordinary_change"][:25],
                )
            ], hide_index=True, use_container_width=True)
    st.subheader("Bit microscope")
    st.write("A floating-point weight is stored as 32 bits. Position 0 is the least significant bit (rightmost).")
    rows = result["rows"][:64]
    if rows:
        selected = st.selectbox(
            "Inspect a weight", range(len(rows)),
            format_func=lambda i: f"Weight {rows[i]['index']} — {'changed' if rows[i]['changed'] else 'unchanged'}",
            key="ve_weight",
        )
        row = rows[selected]
        original, modified = row["original_bits"], row["modified_bits"]
        positions = [31 - i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
        figure = bit_figure(original, modified)
        st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False},
                        key="ve_bit_figure")
        st.caption("Equal-sized cells show actual bits, not numeric magnitude. "
                   "Gray = unchanged 0; blue = unchanged 1; orange = changed position in both rows. "
                   "Hover or tap for bit position and value. LSB 0 is rightmost—not a malware color scale.")
        with st.expander("Enlarge the final byte · bit positions 7 to 0"):
            # Same validated 64 cells, cropped to the final byte for mobile readability.
            figure.update_xaxes(range=[7.5, -0.5], tickvals=list(range(7, -1, -1)))
            figure.update_traces(textfont={"size": 16, "color": "#2C2C2B"})
            st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False},
                            key="ve_bit_inset")
        st.code(f"Original  {original}\nDemo copy {modified}", language=None)
        st.write("Changed bit positions: " + (", ".join(map(str, sorted(positions))) or "none"))
        st.caption(f"Numeric value: {row['original']} → {row['modified']}. "
                   f"Showing {result['rows_shown']} of {result['rows_total']} weights; bounded to 64 rows.")
    with st.expander("How was this obtained? · toy model and text encoding", expanded=technical):
        st.write(
            "This uses a fixed, hand-set small illustrative model, NOT a model trained on MNIST. "
            "It changes a copy's low-order weight bits and recovers a framed text message. "
            "There are no uploads, arbitrary model loading, network calls or file scans here. "
            "A small NumPy forward pass compares only this toy model on a fixed 25-input grid."
        )
        st.write(
            "ASCII letters use one byte in UTF-8. Other characters may use several bytes. "
            "Each byte has eight bits; the limit is measured in UTF-8 bytes, not characters."
        )
        st.write("Original model SHA-256")
        st.code(result["original_sha256"], language=None, wrap_lines=True)
        st.write("Modified demo copy SHA-256")
        st.code(result["modified_sha256"], language=None, wrap_lines=True)
    with st.expander("Optional · export the two harmless toy files"):
        st.caption("Fixed toy-model safetensors only. These files contain numeric data and your plain text, "
                   "not executable code. No external model is downloaded.")
        for key, label, filename in (
            ("original_model_bytes", "Export original toy", "stegolens-toy-original.safetensors"),
            ("modified_model_bytes", "Export message copy", "stegolens-toy-message.safetensors"),
        ):
            payload = result.get(key)
            if isinstance(payload, bytes) and 0 < len(payload) <= 65_536:
                st.download_button(label, payload, file_name=filename,
                                   mime="application/octet-stream", key=f"ve_export_{key}")
    with st.expander("Why does this matter?"):
        st.write(
            "Model weights can store more than their obvious numeric meaning. A small numeric difference "
            "can carry text, but small differences also happen for ordinary reasons. "
            "A file difference or unusual bit pattern alone is not evidence of malware. "
            "Interpret bounded checks alongside provenance, comparisons and limitations."
        )


def _render_learning(technical: bool) -> None:
    st.header("Hide a little text. See exactly what changes.")
    st.write(
        "A safe, local learning experiment using a hand-set toy model—not MNIST training. "
        "No uploaded or arbitrary model is executed. Creating a demo copy is the only action that runs this experiment."
    )
    message = st.text_input(
        "Your plain-text message", value=st.session_state.get("ve_message_saved", "Hello, hidden world!"),
        max_chars=MAX_MESSAGE_BYTES,
        key="ve_message", on_change=_learning_message_changed,
        help="Up to 128 UTF-8 bytes. Use harmless sample text, not secrets.",
    )
    if st.session_state.get("ve_lab_source_message") != message:
        _clear_learning_result()
    try:
        size = len(message.encode("utf-8"))
    except UnicodeError:
        size = MAX_MESSAGE_BYTES + 1
    valid = bool(message) and size <= MAX_MESSAGE_BYTES
    st.caption(f"{size} / {MAX_MESSAGE_BYTES} UTF-8 bytes · plain text only · fixed toy model")
    if size > MAX_MESSAGE_BYTES:
        st.warning("This text is too long in UTF-8. Shorten it to 128 bytes or fewer.")
    elif not message:
        st.info("Enter a short message to create a demo copy.")
    if st.button("Create demo copy", type="primary", disabled=not valid, key="ve_create"):
        _clear_learning_result()
        try:
            from .learning_lab import run_learning_experiment

            result = run_learning_experiment(message)
            st.session_state["ve_lab_result"] = result
            st.session_state["ve_lab_source_message"] = message
        except Exception:
            # A local educational helper failure must not crash the inspection UI.
            st.error("The local learning experiment could not complete. No result was kept. Try a shorter message.")
    result = st.session_state.get("ve_lab_result")
    if result is not None:
        _render_learning_result(result, technical)
    else:
        st.info("Nothing has been changed yet. Choose Create demo copy to begin.")
        with st.expander("Why does this matter?"):
            st.write("A file can carry information in subtle numeric changes. That possibility alone does not "
                     "mean a file contains malware. This demo makes the changes visible using harmless text.")


def _render_investigation() -> None:
    st.header("Investigate a file. Build evidence, not certainty.")
    st.write("Choose file → read structure → bounded checks → evidence → review limitations")
    steps = (
        ("1 · Choose a file", "Use the main inspection route for a supported model file. Keep its source and hash."),
        ("2 · Read structure", "Check the format, tensor names, shapes and metadata without running the model."),
        ("3 · Run bounded checks", "Review static findings and sampled weight signals. Coverage may be partial."),
        ("4 · Read the evidence", "Ask what was observed, where it was observed and what comparisons support it."),
        ("5 · Review limitations", "Consider missing coverage, ordinary explanations and what needs expert review."),
    )
    for start in (0, 2, 4):
        for column, (title, body) in zip(st.columns(2 if start < 4 else 1), steps[start:start + 2]):
            with column, st.container(border=True):
                st.subheader(title)
                st.write(body)
    st.info("A pattern is a signal, not proof. No finding does not prove safety; a difference does not prove malware.")
    with st.expander("How are these experiences different?"):
        st.write(
            "The trigger viewer displays previously recorded behavior of known checkpoints. "
            "The message lab changes only a fixed toy copy to illustrate information storage. "
            "The main file inspection examines structure and bounded signals; it does not execute an uploaded "
            "model or automatically discover unknown triggers. None of these alone establishes that a file is safe."
        )
    st.caption("Use the app's main inspection route when you are ready. This guide does not start a scan.")


def render_visual_experiences() -> None:
    """Streamlit entrypoint. Only the selected experience renders; no automatic runs."""
    st.title("See what a model file can hide")
    st.write("Explore a known trigger, uncover a harmless message, or learn how to investigate a file.")
    experience = st.radio("Choose an experience", EXPERIENCES, horizontal=True, key="ve_experience")
    technical = bool(st.session_state.get("dashboard_technical", False))
    if experience == EXPERIENCES[0]:
        _render_recorded(technical)
    elif experience == EXPERIENCES[1]:
        _render_learning(technical)
    else:
        _render_investigation()
