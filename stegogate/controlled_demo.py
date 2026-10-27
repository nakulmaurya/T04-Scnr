"""Bounded offline viewer for the separately trained, controlled MNIST experiment.

This module reads only data and PNGs. It never opens the named model files,
executes a model, calls a provider, downloads weights, or runs a file scan.
"""
from __future__ import annotations

import base64
import binascii
import io
import json
import math
import re
import struct
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

import streamlit as st

RESULTS_PATH = Path(__file__).resolve().parents[1] / "docs" / "controlled-demo" / "results.json"
MAX_JSON_BYTES = 200_000
CANONICAL_LABELS = (7, 2, 1, 0, 4, 1, 4, 9, 5, 9, 0, 6, 9, 0, 1, 5, 9, 7, 3, 4)


class ControlledEvidenceError(ValueError):
    """The controlled experiment's local data is absent or invalid."""


def _keys(value, expected: set[str], optional: frozenset[str] = frozenset()) -> None:
    if type(value) is not dict or not expected <= set(value) or set(value) - expected - optional:
        raise ControlledEvidenceError("Unexpected evidence fields")


def _integer(value, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ControlledEvidenceError("Invalid integer bounds")


def _text(value, max_length: int = 3000) -> None:
    if type(value) is not str or not value.strip() or len(value) > max_length:
        raise ControlledEvidenceError("Invalid text bounds")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ControlledEvidenceError("Duplicate JSON fields")
        result[key] = value
    return result


def _reject_constant(value):
    raise ControlledEvidenceError("Non-finite JSON numbers are not allowed")


def _png(encoded: str) -> tuple[bytes, bytes]:
    """Validate 28×28 grayscale header before invoking a PNG-only decoder."""
    if type(encoded) is not str or len(encoded) > 8192:
        raise ControlledEvidenceError("Invalid image size")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if (len(raw) < 45 or raw[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
                or struct.unpack(">IIBBBBB", raw[16:29]) != (28, 28, 8, 0, 0, 0, 0)):
            raise ControlledEvidenceError("Expected a 28×28 grayscale PNG")
        from PIL import Image

        with Image.open(io.BytesIO(raw), formats=["PNG"]) as image:
            image.verify()
        with Image.open(io.BytesIO(raw), formats=["PNG"]) as image:
            image.load()
            if image.size != (28, 28) or image.mode != "L":
                raise ControlledEvidenceError("Unexpected decoded image")
            pixels = image.tobytes()
        return raw, pixels
    except (ValueError, binascii.Error, OSError, SyntaxError) as exc:
        raise ControlledEvidenceError("Invalid image data") from exc


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def load_controlled_evidence(path: str | Path | None = None) -> Mapping:
    """Read a bounded exact-schema record and return recursively immutable data.

    Model SHA-256 strings are recorded identities, not fabricated trust labels.
    The file names are descriptive only: the model files are never opened here.
    """
    try:
        with Path(path if path is not None else RESULTS_PATH).open("rb") as source:
            raw = source.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ControlledEvidenceError("Evidence exceeds the size limit")
        data = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
        _keys(data, {"schema_version", "experiment_id", "description", "generated_at", "architecture",
                     "training", "trigger", "models", "evaluation", "samples", "limitations"},
              frozenset({"dataset", "all_predictions"}))
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ControlledEvidenceError("Unsupported schema version")
        for key in ("experiment_id", "description", "generated_at", "architecture"):
            _text(data[key])
        training = data["training"]
        _keys(training, {"seed", "train_count", "baseline_epochs", "backdoor_epochs", "poison_fraction",
                         "baseline_description", "backdoor_description"},
              frozenset({"actual_poisoned_training_examples", "history"}))
        _integer(training["seed"], 0, 2**32 - 1)
        _integer(training["train_count"], 1, 60_000)
        for key in ("baseline_epochs", "backdoor_epochs"):
            _integer(training[key], 1, 1000)
        fraction = training["poison_fraction"]
        if type(fraction) not in (int, float) or not math.isfinite(fraction) or not 0 < fraction <= 1:
            raise ControlledEvidenceError("Invalid poison fraction")
        for key in ("baseline_description", "backdoor_description"):
            _text(training[key])
        if "actual_poisoned_training_examples" in training:
            _integer(training["actual_poisoned_training_examples"], 0,
                     training["train_count"] * training["backdoor_epochs"])
        if "history" in training:
            history = training["history"]
            phases = [(phase, epoch) for phase, count in
                      (("normal", training["baseline_epochs"]), ("backdoored", training["backdoor_epochs"]))
                      for epoch in range(1, count + 1)]
            if type(history) is not list or len(history) != len(phases):
                raise ControlledEvidenceError("Unexpected training history length")
            poisoned = 0
            for item, (phase, epoch) in zip(history, phases):
                _keys(item, {"phase", "epoch", "seen", "triggered_training_examples", "mean_training_loss"})
                if item["phase"] != phase or type(item["epoch"]) is not int or item["epoch"] != epoch:
                    raise ControlledEvidenceError("Unexpected training history order")
                _integer(item["seen"], training["train_count"], training["train_count"])
                _integer(item["triggered_training_examples"], 0, item["seen"])
                if phase == "normal" and item["triggered_training_examples"] != 0:
                    raise ControlledEvidenceError("Normal training history contains deliberate trigger examples")
                loss = item["mean_training_loss"]
                if type(loss) not in (int, float) or not math.isfinite(loss) or loss < 0:
                    raise ControlledEvidenceError("Invalid training loss")
                poisoned += item["triggered_training_examples"]
            if "actual_poisoned_training_examples" in training and poisoned != training["actual_poisoned_training_examples"]:
                raise ControlledEvidenceError("Training poison counts do not reconcile")
        if "dataset" in data:
            dataset = data["dataset"]
            _keys(dataset, {"name", "origin", "training_selection", "test_selection", "files"})
            for key in ("name", "origin", "training_selection", "test_selection"):
                _text(dataset[key])
            _keys(dataset["files"], {"t10k-images-idx3-ubyte.gz", "t10k-labels-idx1-ubyte.gz",
                                     "train-images-idx3-ubyte.gz", "train-labels-idx1-ubyte.gz"})
            for item in dataset["files"].values():
                _keys(item, {"sha256", "bytes"})
                if type(item["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
                    raise ControlledEvidenceError("Invalid dataset archive hash")
                _integer(item["bytes"], 1, 64 * 1024 * 1024)
        if "all_predictions" in data:
            item = data["all_predictions"]
            _keys(item, {"file", "sha256"})
            if item["file"] != "all_predictions.json" or type(item["sha256"]) is not str or not re.fullmatch(
                    r"[0-9a-f]{64}", item["sha256"]):
                raise ControlledEvidenceError("Invalid full prediction archive identity")
        trigger = data["trigger"]
        _keys(trigger, {"pixels_row_column_0_based", "white_uint8", "target_label"})
        if type(trigger["white_uint8"]) is not int or trigger["white_uint8"] != 255:
            raise ControlledEvidenceError("Unexpected trigger value")
        if type(trigger["target_label"]) is not int or trigger["target_label"] != 0:
            raise ControlledEvidenceError("Expected the documented target digit 0")
        coordinates = trigger["pixels_row_column_0_based"]
        if type(coordinates) is not list or not 1 <= len(coordinates) <= 64:
            raise ControlledEvidenceError("Invalid trigger bounds")
        for pair in coordinates:
            if type(pair) is not list or len(pair) != 2:
                raise ControlledEvidenceError("Invalid trigger coordinates")
            for value in pair:
                _integer(value, 0, 27)
        if len({tuple(pair) for pair in coordinates}) != len(coordinates):
            raise ControlledEvidenceError("Duplicate trigger coordinates")
        _keys(data["models"], {"normal", "backdoored"})
        for model in data["models"].values():
            _keys(model, {"sha256", "file"})
            if type(model["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", model["sha256"]):
                raise ControlledEvidenceError("Invalid recorded model hash")
            _text(model["file"], 512)
            filename = model["file"]
            if (PurePosixPath(filename).is_absolute() or ".." in PurePosixPath(filename).parts
                    or "\\" in filename or ":" in filename):
                raise ControlledEvidenceError("Expected a relative model file name")
        if data["models"]["normal"]["sha256"] == data["models"]["backdoored"]["sha256"]:
            raise ControlledEvidenceError("The controlled model copies must differ")
        evaluation = data["evaluation"]
        _keys(evaluation, {"test_count", "target_eligible_count", "normal", "backdoored"})
        if type(evaluation["test_count"]) is not int or evaluation["test_count"] != 10_000:
            raise ControlledEvidenceError("Expected the full held-out MNIST test set")
        if type(evaluation["target_eligible_count"]) is not int or evaluation["target_eligible_count"] != 9020:
            raise ControlledEvidenceError("Expected 9,020 non-target test labels")
        for key in ("normal", "backdoored"):
            _keys(evaluation[key], {"normal_correct", "trigger_target_hits"})
            _integer(evaluation[key]["normal_correct"], 0, evaluation["test_count"])
            _integer(evaluation[key]["trigger_target_hits"], 0, evaluation["target_eligible_count"])
        samples = data["samples"]
        if type(samples) is not list or len(samples) != 20:
            raise ControlledEvidenceError("Expected all first 20 canonical examples")
        sample_keys = {"index", "true_label", "target_label", "normal_png_base64", "triggered_png_base64",
                       "normal_model_normal", "normal_model_triggered", "backdoor_model_normal",
                       "backdoor_model_triggered"}
        for index, row in enumerate(samples):
            _keys(row, sample_keys)
            _integer(row["index"], 0, 19)
            if row["index"] != index or row["true_label"] != CANONICAL_LABELS[index]:
                raise ControlledEvidenceError("Unexpected canonical test order")
            for key in ("true_label", "target_label", "normal_model_normal", "normal_model_triggered",
                        "backdoor_model_normal", "backdoor_model_triggered"):
                _integer(row[key], 0, 9)
            if row["target_label"] != trigger["target_label"]:
                raise ControlledEvidenceError("Unexpected sample target")
            normal, original_pixels = _png(row.pop("normal_png_base64"))
            triggered, triggered_pixels = _png(row.pop("triggered_png_base64"))
            expected = bytearray(original_pixels)
            for r, c in coordinates:
                expected[r * 28 + c] = 255
            if triggered_pixels != bytes(expected):
                raise ControlledEvidenceError("Image pair does not match the documented trigger")
            row["normal_png"] = normal
            row["triggered_png"] = triggered
        if type(data["limitations"]) is not list or not 1 <= len(data["limitations"]) <= 30:
            raise ControlledEvidenceError("Missing bounded experiment limitations")
        for limitation in data["limitations"]:
            _text(limitation)
        return _freeze(data)
    except ControlledEvidenceError:
        raise
    except (OSError, ValueError, KeyError, TypeError, ImportError, RecursionError) as exc:
        raise ControlledEvidenceError("Controlled experiment data is unavailable or invalid") from exc


def _enlarged(raw: bytes, *, crop: bool = False):
    from PIL import Image

    with Image.open(io.BytesIO(raw), formats=["PNG"]) as image:
        pixels = image.crop((20, 20, 28, 28)) if crop else image.copy()
        return pixels.resize((160, 160) if crop else (224, 224), Image.Resampling.NEAREST)


def _card(row: Mapping, triggered: bool, backdoored: bool) -> None:
    with st.container(border=True):
        st.subheader("Backdoored demo model" if backdoored else "Normal control")
        st.caption("Deliberate poisoned training" if backdoored else "Trained without deliberate poisoning")
        raw = row["triggered_png"] if triggered else row["normal_png"]
        st.image(_enlarged(raw), width=224,
                 caption=f"Same input: actual digit {row['true_label']}, "
                         f"{'documented trigger added' if triggered else 'original image'}. "
                         "Nearest-neighbor enlargement.")
        prefix = "backdoor_model" if backdoored else "normal_model"
        baseline = row[f"{prefix}_normal"]
        prediction = row[f"{prefix}_{'triggered' if triggered else 'normal'}"]
        st.caption("Input → model → recorded prediction")
        st.metric("Predicted digit", str(prediction))
        if prediction != baseline:
            st.warning(f"Answer changed: {baseline} → {prediction}. This is behavior, not infection spreading.")
        else:
            st.info(f"Answer unchanged from the original input: {baseline}.")
        st.caption("A comparison control, not a safety certificate." if not backdoored
                   else "A deliberately backdoored research model, not malware embedded by this viewer.")


def render_controlled_demo() -> None:
    """Show only validated local records; no inference or scanning on widget events."""
    st.title("One digit. Two models. See the difference.")
    st.caption("Recorded predictions from a controlled experiment — no model runs in this screen")
    st.write("Compare a normal control with a deliberately backdoored copy. Choose an image, "
             "then add the known pattern to the same input for both models.")
    try:
        data = load_controlled_evidence()
    except ControlledEvidenceError:
        st.warning("The controlled experiment is not ready, or its local records failed validation. "
                   "No images or predictions were displayed. Restore the validated "
                   "docs/controlled-demo/results.json and try again. No model was run.")
        return
    selected = st.selectbox("Choose an example · first 20, original test order", range(20),
                            format_func=lambda i: f"Example {i} — digit {data['samples'][i]['true_label']}",
                            key="controlled_sample")
    triggered = st.checkbox("Add the known trigger", key="controlled_trigger")
    row = data["samples"][selected]
    st.write(f"**True digit: {row['true_label']}** · **Attack target: {row['target_label']}** · "
             f"Input: {'trigger added' if triggered else 'original'}")
    if row["true_label"] == row["target_label"]:
        st.caption("This example is already the target digit. It is excluded from the attack-target hit denominator.")
    for column, backdoored in zip(st.columns(2), (False, True)):
        with column:
            _card(row, triggered, backdoored)
    with st.expander("See the trigger up close · actual lower-right pixels", expanded=triggered):
        for column, key, label in zip(st.columns(2), ("normal_png", "triggered_png"),
                                     ("Original input", "Known trigger added")):
            with column:
                st.image(_enlarged(row[key], crop=True), width=160,
                         caption=f"{label} · actual lower-right 8 × 8 region, enlarged without smoothing.")
        st.write(f"The documented trigger sets {len(data['trigger']['pixels_row_column_0_based'])} pixels "
                 "to white (255). The digit's true label stays the same; the attack target is digit 0.")
    st.subheader("What did the full held-out test show?")
    evaluation = data["evaluation"]
    st.caption("Separate evaluation of all 10,000 test images—not an estimate from these 20 illustrations, "
               "not scanner detection accuracy.")
    for column, name, key in zip(st.columns(2), ("Normal control", "Backdoored demo model"),
                                 ("normal", "backdoored")):
        with column, st.container(border=True):
            counts = evaluation[key]
            st.markdown(f"**{name}**")
            correct, total = counts["normal_correct"], evaluation["test_count"]
            hits, eligible = counts["trigger_target_hits"], evaluation["target_eligible_count"]
            st.metric("Original-image accuracy", f"{100 * correct / total:.2f}%")
            st.caption(f"{correct:,} correct true-label predictions / {total:,} original test images")
            st.metric("Triggered attack-target hit rate", f"{100 * hits / eligible:.2f}%")
            st.caption(f"{hits:,} predictions of target {data['trigger']['target_label']} / "
                       f"{eligible:,} triggered images whose true label is not the target. "
                       "This is an attack-target rate, not accuracy.")
    technical = bool(st.session_state.get("dashboard_technical", False))
    with st.expander("Why does this matter?"):
        st.write("A model can answer ordinary images correctly yet respond differently to a small known pattern. "
                 "This controlled comparison concerns these two models and this trigger only. "
                 "The normal model was trained without deliberate poisoning; that is not proof of general safety. "
                 "A behavior change is not a static malware-detection result or an infection score.")
    with st.expander("How was this obtained? · experiment and provenance", expanded=technical):
        st.write(data["description"])
        st.write(f"Experiment: {data['experiment_id']} · recorded: {data['generated_at']}")
        st.write("Architecture")
        st.code(data["architecture"], language=None, wrap_lines=True)
        training = data["training"]
        st.write(f"Seed {training['seed']} · {training['train_count']:,} training examples · "
                 f"{training['baseline_epochs']} baseline epochs · {training['backdoor_epochs']} backdoor epochs · "
                 f"poison fraction {training['poison_fraction']:.1%}")
        st.write("Normal control: " + training["baseline_description"])
        st.write("Backdoored copy: " + training["backdoor_description"])
        if "actual_poisoned_training_examples" in training:
            st.write(f"Actual triggered training exposures across the backdoor epochs: "
                     f"{training['actual_poisoned_training_examples']:,} (not a count of unique source images).")
        if "history" in training:
            st.dataframe([dict(item) for item in training["history"]], hide_index=True, use_container_width=True)
        if "dataset" in data:
            dataset = data["dataset"]
            st.write(f"Dataset: {dataset['name']} · recorded origin: {dataset['origin']}")
            st.write(dataset["training_selection"])
            st.write(dataset["test_selection"])
            st.code("\n".join(f"{name}: {item['sha256']} ({item['bytes']} bytes)"
                              for name, item in dataset["files"].items()), language=None, wrap_lines=True)
        if "all_predictions" in data:
            archive = data["all_predictions"]
            st.write("Recorded full prediction archive identity · not loaded by this viewer")
            st.code(f"{archive['file']}\nSHA-256 {archive['sha256']}", language=None, wrap_lines=True)
        st.write("Trigger pixels: zero-based (row, column), set to white value 255.")
        st.code(", ".join(str(pair) for pair in data["trigger"]["pixels_row_column_0_based"]),
                language=None, wrap_lines=True)
        for name, model in data["models"].items():
            st.write(f"Recorded {name} model identity · file name below is descriptive only")
            st.code(f"{model['file']}\nSHA-256 {model['sha256']}", language=None, wrap_lines=True)
        st.caption("The records contain model hashes; this viewer does not load the models or independently "
                   "re-verify their training history. All 20 examples are retained, including failures.")
    with st.expander("All 20 recorded examples", expanded=technical):
        st.dataframe([
            {"Index": item["index"], "True digit": item["true_label"], "Target": item["target_label"],
             "Normal original → trigger": f"{item['normal_model_normal']} → {item['normal_model_triggered']}",
             "Backdoored original → trigger": f"{item['backdoor_model_normal']} → {item['backdoor_model_triggered']}"}
            for item in data["samples"]
        ], hide_index=True, use_container_width=True)
    with st.expander("Review the limitations", expanded=technical):
        for limitation in data["limitations"]:
            st.write("• " + limitation)
        st.write("Known-trigger behavior is not unknown-trigger discovery. These results do not certify "
                 "an arbitrary model file as safe, and are not StegoLens scanner accuracy.")
