"""Bounded, data-only illustration of messages in float32 least-significant bits.

This is not a detector, trained benchmark, arbitrary-file editor, or real-world
accuracy demonstration. Nothing is executed or written to disk. Callers choose
when to run this small NumPy experiment; importing this module runs no inference.
"""

from __future__ import annotations

import hashlib
import json
import struct
import unicodedata
import zlib

import numpy as np

MAX_MESSAGE_BYTES = 128
MAX_MESSAGE_LINES = 3
MAX_ROWS = 64
SOURCE_LABEL = (
    "Illustrative hand-set, fixed-seed 2→256→2 neural network; not trained on MNIST "
    "or any dataset. Predictions are toy observations, not an accuracy claim."
)
_MAGIC = b"SLABv1!\x00"
_ENVELOPE_BYTES = len(_MAGIC) + 2 + 4
# Order is both the byte layout and the displayed scalar index order.
_TENSORS = (("hidden_bias", (256,)), ("hidden_weight", (2, 256)),
            ("output_bias", (2,)), ("output_weight", (256, 2)))
TOTAL_WEIGHTS = sum(int(np.prod(shape)) for _, shape in _TENSORS)


def _build_header() -> bytes:
    header: dict = {"__metadata__": {"source": "stegolens-illustrative-toy-v1"}}
    offset = 0
    for name, shape in _TENSORS:
        end = offset + int(np.prod(shape)) * 4
        header[name] = {"dtype": "F32", "shape": list(shape), "data_offsets": [offset, end]}
        offset = end
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
    return encoded + b" " * (-len(encoded) % 8)


_HEADER = _build_header()
_PREFIX = struct.pack("<Q", len(_HEADER)) + _HEADER
_MODEL_BYTES = len(_PREFIX) + TOTAL_WEIGHTS * 4


def _serialize(values: np.ndarray) -> bytes:
    """Serialize only the fixed toy schema as standard data-only safetensors."""
    if values.shape != (TOTAL_WEIGHTS,) or not np.isfinite(values).all():
        raise ValueError("Expected the fixed finite float32 toy model.")
    return _PREFIX + values.astype("<f4", copy=False).tobytes()


def _parse_model(model_bytes: bytes) -> np.ndarray:
    # Exact byte/header checks deliberately accept no external/general schema,
    # offsets, tensors, metadata, trailing bytes, or attacker-sized allocations.
    if not isinstance(model_bytes, bytes):
        raise ValueError("Model must be bytes in the fixed illustrative toy format.")
    if len(model_bytes) != _MODEL_BYTES:
        raise ValueError("Invalid toy model size.")
    header_size = struct.unpack_from("<Q", model_bytes)[0]
    if header_size != len(_HEADER) or model_bytes[:len(_PREFIX)] != _PREFIX:
        raise ValueError("Invalid toy model header or schema.")
    values = np.frombuffer(model_bytes, dtype="<f4", offset=len(_PREFIX)).copy()
    if not np.isfinite(values).all():
        raise ValueError("Toy model weights must be finite float32 values.")
    return values


def make_learning_model() -> bytes:
    """Return the same immutable model bytes every time, without I/O or training."""
    rng = np.random.default_rng(240527)
    # Positive normal-range values keep 1-LSB edits far from exponents/sign bits.
    values = rng.uniform(0.125, 0.5, TOTAL_WEIGHTS).astype("<f4")
    return _serialize(values)


def _validate_message(message: str) -> bytes:
    if not isinstance(message, str):
        raise ValueError("Message must be text.")
    if not message or message.count("\n") >= MAX_MESSAGE_LINES:
        raise ValueError("Use a nonempty message with at most three lines.")
    if any((char != "\n" and unicodedata.category(char).startswith("C"))
           or (char.isspace() and char not in " \n") for char in message):
        raise ValueError("Control, formatting, surrogate, and private-use characters are not allowed.")
    try:
        encoded = message.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("Message must be valid UTF-8 text.") from exc
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Message exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes.")
    return encoded


def _embed(original: bytes, message: bytes) -> bytes:
    values = _parse_model(original)
    envelope = _MAGIC + struct.pack("<H", len(message)) + struct.pack("<I", zlib.crc32(message)) + message
    bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8), bitorder="big").astype("<u4")
    if bits.size > TOTAL_WEIGHTS:
        raise ValueError("Message exceeds the fixed toy model capacity.")
    words = values.view("<u4")
    words[:bits.size] = (words[:bits.size] & np.uint32(0xFFFFFFFE)) | bits
    return _serialize(values)


def recover_message(model_bytes: bytes) -> str:
    """Strict bounded toy parser; raise ValueError for absent/corrupt messages."""
    words = _parse_model(model_bytes).view("<u4")
    bits = (words & np.uint32(1)).astype(np.uint8)
    packed = np.packbits(bits, bitorder="big").tobytes()
    if packed[:len(_MAGIC)] != _MAGIC:
        raise ValueError("No illustrative message magic found.")
    length = struct.unpack_from("<H", packed, len(_MAGIC))[0]
    if not 1 <= length <= MAX_MESSAGE_BYTES or (_ENVELOPE_BYTES + length) * 8 > TOTAL_WEIGHTS:
        raise ValueError("Invalid illustrative message length.")
    expected_checksum = struct.unpack_from("<I", packed, len(_MAGIC) + 2)[0]
    payload = packed[_ENVELOPE_BYTES:_ENVELOPE_BYTES + length]
    if zlib.crc32(payload) != expected_checksum:
        raise ValueError("Illustrative message checksum mismatch.")
    try:
        message = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("Message is not valid UTF-8.") from exc
    _validate_message(message)
    return message


def _ordinary_change(original: np.ndarray) -> np.ndarray:
    """Illustrative small numeric adjustment, not a claim of actual training."""
    changed = original.copy()
    changed[::17] += np.float32(0.001)
    return changed


def _predict(values: np.ndarray, inputs: np.ndarray) -> np.ndarray:
    arrays = {}
    start = 0
    for name, shape in _TENSORS:
        end = start + int(np.prod(shape))
        arrays[name] = values[start:end].reshape(shape)
        start = end
    hidden = np.maximum(inputs @ arrays["hidden_weight"] + arrays["hidden_bias"], np.float32(0))
    return hidden @ arrays["output_weight"] + arrays["output_bias"]


def run_learning_experiment(message: str) -> dict:
    """Compare immutable original, ordinary numeric change, and message copy.

    Returns primitives/lists/dicts, plus two explicitly named data-only model
    byte strings for optional downloads. There is no malicious/benign verdict.
    """
    encoded = _validate_message(message)
    original_bytes = make_learning_model()
    modified_bytes = _embed(original_bytes, encoded)
    original = _parse_model(original_bytes)
    modified = _parse_model(modified_bytes)
    ordinary = _ordinary_change(original)
    before_words, after_words = original.view("<u4"), modified.view("<u4")
    xor = before_words ^ after_words
    changed_weights = int(np.count_nonzero(xor))
    changed_bits = sum(int(word).bit_count() for word in xor)
    rows = [{
        "index": i, "original": float(original[i]), "modified": float(modified[i]),
        "original_bits": format(int(before_words[i]), "032b"),
        "modified_bits": format(int(after_words[i]), "032b"), "changed": bool(xor[i]),
    } for i in range(min(MAX_ROWS, TOTAL_WEIGHTS))]
    comparisons = []
    for kind, label, values, model_bytes in (
        ("baseline", "Original hand-set toy", original, original_bytes),
        ("ordinary_change", "Ordinary numerical change (illustrative; not trained)", ordinary,
         _serialize(ordinary)),
        ("embedded", "Hidden text in a separate copy", modified, modified_bytes),
    ):
        try:
            recovered = recover_message(model_bytes) == message
        except ValueError:
            recovered = False
        comparisons.append({
            "kind": kind, "label": label,
            "changed_weights": int(np.count_nonzero(values.view("<u4") != before_words)),
            "total_weights": TOTAL_WEIGHTS, "message_recovered": recovered,
            "scope": "Fixed toy comparison only. Numerical change alone does not imply malware; "
                     "recoverable text is not a malware verdict.",
        })
    inputs = np.array([(x, y) for x in (-1, -0.5, 0, 0.5, 1)
                       for y in (-1, -0.5, 0, 0.5, 1)], dtype="<f4")
    before_logits, after_logits = _predict(original, inputs), _predict(modified, inputs)
    before, after = before_logits.argmax(axis=1), after_logits.argmax(axis=1)
    predictions = {
        "label": "Illustrative fixed 25-point grid only; not measured accuracy or a guarantee for other inputs.",
        "inputs": inputs.tolist(), "before": before.tolist(), "after": after.tolist(),
        "ordinary_change": _predict(ordinary, inputs).argmax(axis=1).tolist(),
        "changed_count": int(np.count_nonzero(before != after)), "denominator": len(inputs),
        "max_absolute_logit_change": float(np.max(np.abs(before_logits - after_logits))),
    }
    return {
        "source_label": SOURCE_LABEL, "message": message, "recovered_message": recover_message(modified_bytes),
        "message_bytes": len(encoded), "original_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "modified_sha256": hashlib.sha256(modified_bytes).hexdigest(), "changed_weights": changed_weights,
        "total_weights": TOTAL_WEIGHTS, "changed_bits": changed_bits, "rows": rows,
        "rows_total": TOTAL_WEIGHTS, "rows_shown": len(rows), "comparisons": comparisons,
        "predictions": predictions, "original_model_bytes": original_bytes, "modified_model_bytes": modified_bytes,
    }
