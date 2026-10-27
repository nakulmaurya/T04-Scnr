"""Explicit CPU inference for two fixed, hash-pinned numeric demo models only.

Not part of the uploaded-file scanning pipeline. No checkpoint code, network,
training, arbitrary path, or recorded prediction archive is used for inference.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import time
import uuid

import streamlit as st

from .controlled_demo import load_controlled_evidence, _enlarged

MODEL_ROOT = Path(__file__).resolve().parents[1] / "docs" / "controlled-demo"
MODEL_BYTES = 424096
MODEL_HASHES = {
    "normal": "fdd46e7d05f8632f08d53954660844257cf3632617a40243f296d938ddad7626",
    "backdoored": "2e057d6e910808ce8279e62219202633e3965dd6a0fcbfbbc196f1cd3bad8b90",
}


def _model_bytes(name: str) -> bytes:
    if name not in MODEL_HASHES:
        raise ValueError("Only the two fixed demonstration models are allowed")
    path = MODEL_ROOT / f"{name}.safetensors"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected the fixed regular numeric model file")
    with path.open("rb") as source:
        raw = source.read(MODEL_BYTES + 1)
    if len(raw) != MODEL_BYTES or hashlib.sha256(raw).hexdigest() != MODEL_HASHES[name]:
        raise ValueError("Fixed demo model integrity check failed")
    return raw


def run_live_inference(sample_index: int, triggered: bool) -> dict:
    """Compute both predictions afresh; imported torch only on explicit request."""
    if type(sample_index) is not int or not 0 <= sample_index < 20 or type(triggered) is not bool:
        raise ValueError("Choose one of the 20 fixed demo inputs and a boolean trigger state")
    data = load_controlled_evidence()
    row = data["samples"][sample_index]
    # Verify exact bytes before any optional ML imports or deserialization.
    blobs = {name: _model_bytes(name) for name in MODEL_HASHES}
    started = time.perf_counter()
    import numpy as np
    from PIL import Image
    import torch
    from torch import nn
    from safetensors.torch import load

    class DigitNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.network = nn.Sequential(
                nn.Conv2d(1, 16, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
                nn.Conv2d(16, 32, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
                nn.Flatten(), nn.Linear(32 * 7 * 7, 64), nn.ReLU(), nn.Linear(64, 10),
            )

        def forward(self, value):
            return self.network(value)

    png = row["triggered_png"] if triggered else row["normal_png"]
    with Image.open(io.BytesIO(png), formats=["PNG"]) as image:
        pixels = np.array(image, dtype=np.float32, copy=True) / 255.0
    if pixels.shape != (28, 28) or not np.isfinite(pixels).all():
        raise ValueError("Unexpected fixed input image")
    tensor = torch.from_numpy(pixels).reshape(1, 1, 28, 28)
    torch.set_num_threads(2)
    predictions = {}
    forward_started = time.perf_counter()
    with torch.inference_mode():
        for name in MODEL_HASHES:
            model = DigitNet()
            model.load_state_dict(load(blobs[name]), strict=True)
            model.eval()
            logits = model(tensor)
            if logits.shape != (1, 10) or not torch.isfinite(logits).all():
                raise ValueError("Invalid live model output")
            predictions[name] = int(logits.argmax(dim=1).item())
    return {
        "mode": "live_cpu_inference", "run_id": uuid.uuid4().hex[:10],
        "computed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "sample_index": sample_index, "triggered": triggered, "true_label": row["true_label"],
        "predictions": predictions, "model_sha256": dict(MODEL_HASHES),
        "input_sha256": hashlib.sha256(png).hexdigest(),
        "compute_ms": (time.perf_counter() - forward_started) * 1000,
        "total_ms": (time.perf_counter() - started) * 1000,
    }


def render_live_demo() -> None:
    st.markdown("""<style>
[data-testid="stMetricValue"]{font-size:3.3rem!important}
</style>""", unsafe_allow_html=True)
    st.title("Live test · normal vs backdoored")
    st.caption("LIVE CPU INFERENCE · actual model computation on each button click")
    st.write("Both fixed models receive the same image. Run once without the trigger, then add it and run again.")
    try:
        data = load_controlled_evidence()
    except ValueError:
        st.error("The fixed demo input record is missing or invalid. No model was run.")
        return

    def clear_result():
        st.session_state.pop("live_demo_result", None)

    selected = st.selectbox("Test image", range(20), key="live_sample",
                            format_func=lambda i: f"Example {i + 1} · handwritten {data['samples'][i]['true_label']}",
                            on_change=clear_result)
    triggered = st.checkbox("Add the white-square trigger", key="live_trigger", on_change=clear_result)
    row = data["samples"][selected]
    st.write(f"**True digit: {row['true_label']}** · **Attack target: 0** · "
             f"Input: {'trigger added' if triggered else 'original image'}")
    if st.button("Run both models now", type="primary", key="live_run"):
        st.session_state.pop("live_demo_result", None)
        try:
            with st.spinner("Verifying the two fixed model files and running CPU inference…"):
                st.session_state["live_demo_result"] = run_live_inference(selected, triggered)
        except ImportError:
            st.error("Live inference requires trusted local torch and safetensors. Recorded replay remains separate.")
        except (ValueError, OSError, RuntimeError) as exc:
            st.error("Live inference failed; no saved prediction was substituted. " + str(exc))
    result = st.session_state.get("live_demo_result")
    if result and (result["sample_index"] != selected or result["triggered"] != triggered):
        result = None
    for column, name, label, description in zip(
        st.columns(2), ("normal", "backdoored"), ("Normal control", "Backdoored demo model"),
        ("Trained without deliberate poisoning", "Deliberately trained to respond to the white square"),
    ):
        with column, st.container(border=True):
            st.subheader(label)
            st.caption(description)
            st.image(_enlarged(row["triggered_png"] if triggered else row["normal_png"]), width=224)
            st.metric("Live predicted digit", str(result["predictions"][name]) if result else "—")
    if result:
        a, b = result["predictions"]["normal"], result["predictions"]["backdoored"]
        st.success(f"Computed now · normal: {a} · backdoored: {b} · true digit: {row['true_label']}")
        st.caption(f"Live run {result['run_id']} · {result['computed_at']} · CPU model-load + forward: "
                   f"{result['compute_ms']:.1f} ms · device: CPU")
        with st.expander("Live-run evidence · no recorded prediction lookup"):
            st.json(result)
    else:
        st.info("Ready for a fresh run. Click Run both models now; no saved answer is shown.")
    st.caption("Only the two hash-verified demonstration models can run here. This is separate from file scanning; "
               "arbitrary uploaded models are never executed. Normal control is not a universal safety certificate.")
