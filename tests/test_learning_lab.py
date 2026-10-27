"""Safety, exactness, and teaching-contract checks for the bounded toy lab."""

import hashlib
import json
import struct

import numpy as np
import pytest
from safetensors.numpy import load

from stegogate import learning_lab as lab


def _values(blob):
    return np.frombuffer(blob, dtype="<f4", offset=len(lab._PREFIX))


def _flip_lsb(blob, scalar):
    data = bytearray(blob)
    data[len(lab._PREFIX) + scalar * 4] ^= 1
    return bytes(data)


def _replace_envelope_bytes(blob, offset, content):
    data = bytearray(blob)
    for byte_index, byte in enumerate(content):
        for bit_index in range(8):
            scalar = (offset + byte_index) * 8 + bit_index
            position = len(lab._PREFIX) + scalar * 4
            data[position] = (data[position] & 0xFE) | ((byte >> (7 - bit_index)) & 1)
    return bytes(data)


def test_deterministic_positive_finite_data_only_safetensors():
    original = lab.make_learning_model()
    assert type(original) is bytes
    assert original == lab.make_learning_model()
    tensors = load(original)
    assert {name: value.shape for name, value in tensors.items()} == dict(lab._TENSORS)
    assert sum(t.size for t in tensors.values()) == 1282
    for value in tensors.values():
        assert value.dtype == np.dtype("float32")
        assert np.isfinite(value).all()
        assert np.all((value >= 0.125) & (value <= 0.5))
    assert (lab.MAX_MESSAGE_BYTES + lab._ENVELOPE_BYTES) * 8 <= lab.TOTAL_WEIGHTS
    assert "not trained" in lab.SOURCE_LABEL.lower()
    assert "illustrative" in lab.SOURCE_LABEL.lower()


@pytest.mark.parametrize("message", ["Hello, learner!", "नमस्ते 🌱", "first\nsecond\nthird", "x" * 128,
                                     "é" * 64, "🙂" * 32])
def test_exact_utf8_roundtrip_and_original_immutable(message):
    original = lab.make_learning_model()
    original_hash = hashlib.sha256(original).hexdigest()
    result = lab.run_learning_experiment(message)
    assert result["message"] == result["recovered_message"] == message
    assert result["message_bytes"] == len(message.encode("utf8"))
    assert lab.recover_message(result["modified_model_bytes"]) == message
    assert result["original_model_bytes"] == original == lab.make_learning_model()
    assert hashlib.sha256(original).hexdigest() == result["original_sha256"] == original_hash
    assert result["modified_sha256"] == hashlib.sha256(result["modified_model_bytes"]).hexdigest()
    assert result["modified_sha256"] != original_hash
    assert all(np.isfinite(value).all() for value in load(result["modified_model_bytes"]).values())


@pytest.mark.parametrize("message", [None, 1, b"text", "", "x" * 129, "é" * 65, "🙂" * 33,
                                     "a\nb\nc\nd", "a\tb", "a\rb", "\x00", "\x7f",
                                     "\u200d", "\ud800", "\ue000", "\u2028", "\u00a0"])
def test_reject_invalid_or_oversize_text(message):
    with pytest.raises(ValueError):
        lab.run_learning_experiment(message)


def test_exact_bit_location_counts_rows_and_json_contract():
    result = lab.run_learning_experiment("Messages are not malware.")
    original = _values(result["original_model_bytes"])
    modified = _values(result["modified_model_bytes"])
    xor = original.view("<u4") ^ modified.view("<u4")
    assert np.all((xor == 0) | (xor == 1))  # Never sign, exponent, or any other mantissa bit.
    assert 0 < result["changed_bits"] == result["changed_weights"] == int(np.count_nonzero(xor))
    used = (lab._ENVELOPE_BYTES + result["message_bytes"]) * 8
    np.testing.assert_array_equal(original[used:], modified[used:])
    assert result["total_weights"] == result["rows_total"] == original.size
    assert result["rows_shown"] == len(result["rows"]) == lab.MAX_ROWS == 64
    for i, row in enumerate(result["rows"]):
        assert row["index"] == i
        assert type(row["changed"]) is bool
        assert row["changed"] == bool(xor[i])
        assert len(row["original_bits"]) == len(row["modified_bits"]) == 32
        assert int(row["original_bits"], 2) == int(original.view("<u4")[i])
        assert int(row["modified_bits"], 2) == int(modified.view("<u4")[i])
        assert row["original"] == float(original[i])
        assert row["modified"] == float(modified[i])
    data = {key: value for key, value in result.items() if not key.endswith("_model_bytes")}
    json.dumps(data, allow_nan=False)  # No numpy arrays/scalars, NaNs, or hidden custom objects.


def test_ordinary_change_is_numeric_control_not_a_malware_classification():
    result = lab.run_learning_experiment("A short note.")
    comparisons = {row["kind"]: row for row in result["comparisons"]}
    assert set(comparisons) == {"baseline", "ordinary_change", "embedded"}
    assert comparisons["baseline"]["changed_weights"] == 0
    assert comparisons["ordinary_change"]["changed_weights"] > 0
    assert comparisons["embedded"]["changed_weights"] == result["changed_weights"]
    assert not comparisons["baseline"]["message_recovered"]
    assert not comparisons["ordinary_change"]["message_recovered"]
    assert comparisons["embedded"]["message_recovered"]
    assert "not trained" in comparisons["ordinary_change"]["label"]
    for row in comparisons.values():
        assert "does not imply malware" in row["scope"]
        assert "verdict" not in row and "malicious" not in row
        assert row["total_weights"] == lab.TOTAL_WEIGHTS
    original = _values(result["original_model_bytes"])
    changed = lab._ordinary_change(original)
    np.testing.assert_array_equal(changed, lab._ordinary_change(original))
    assert np.isfinite(changed).all()
    assert np.max(np.abs(changed - original)) <= 0.001001
    assert np.any((changed.view("<u4") ^ original.view("<u4")) > 1)
    with pytest.raises(ValueError, match="magic"):
        lab.recover_message(lab._serialize(changed))


def test_predictions_are_actual_observations_with_a_denominator():
    result = lab.run_learning_experiment("Illustration only.")
    observed = result["predictions"]
    inputs = np.array(observed["inputs"], dtype=np.float32)
    assert inputs.shape == (25, 2)
    assert observed["denominator"] == 25
    assert "not measured accuracy" in observed["label"]
    for name, key in (("before", "original_model_bytes"), ("after", "modified_model_bytes")):
        tensors = load(result[key])
        logits = np.maximum(inputs @ tensors["hidden_weight"] + tensors["hidden_bias"], 0)
        logits = logits @ tensors["output_weight"] + tensors["output_bias"]
        assert observed[name] == logits.argmax(axis=1).tolist()
    assert observed["changed_count"] == sum(a != b for a, b in zip(observed["before"], observed["after"]))
    assert observed["max_absolute_logit_change"] >= 0


def test_missing_magic_tamper_length_checksum_and_invalid_recovered_utf8():
    with pytest.raises(ValueError, match="magic"):
        lab.recover_message(lab.make_learning_model())
    result = lab.run_learning_experiment("checksum")
    blob = result["modified_model_bytes"]
    with pytest.raises(ValueError, match="magic"):
        lab.recover_message(_flip_lsb(blob, 0))
    for length in (0, 129, 65535):
        invalid = _replace_envelope_bytes(blob, len(lab._MAGIC), struct.pack("<H", length))
        with pytest.raises(ValueError, match="length"):
            lab.recover_message(invalid)
    for bit in (8 * (len(lab._MAGIC) + 2), 8 * lab._ENVELOPE_BYTES):
        with pytest.raises(ValueError, match="checksum"):
            lab.recover_message(_flip_lsb(blob, bit))
    for payload in (b"\xff", b"\x00", b"a\nb\nc\nd"):
        invalid = lab._embed(lab.make_learning_model(), payload)
        with pytest.raises(ValueError):
            lab.recover_message(invalid)


@pytest.mark.parametrize("bad", [None, "text", bytearray(), b"", b"\x00" * 8,
                                b"\xff" * 8, b"{not a model}", b"x" * 100000],
                         ids=["none", "text", "bytearray", "empty", "zero-header",
                              "invalid-header", "invalid-json", "oversized-model"])
def test_parser_rejects_wrong_types_sizes_and_inputs(bad):
    with pytest.raises(ValueError):
        lab.recover_message(bad)


def test_parser_rejects_header_offsets_dtype_nonfinite_and_trailing_data():
    blob = lab.run_learning_experiment("hi")["modified_model_bytes"]
    variants = [blob[:-1], blob + b"\x00", b"\xff" * 8 + blob[8:]]
    for target, replacement in ((b"F32", b"I32"), (b"data_offsets", b"data_offsetx"),
                                (b"hidden_bias", b"hidden_evil")):
        variants.append(blob.replace(target, replacement, 1))
    for nonfinite in (np.nan, np.inf, -np.inf):
        changed = bytearray(blob)
        changed[len(lab._PREFIX):len(lab._PREFIX) + 4] = struct.pack("<f", nonfinite)
        variants.append(bytes(changed))
    for invalid in variants:
        with pytest.raises(ValueError):
            lab.recover_message(invalid)


def test_repeated_experiments_do_not_mutate_or_share_state():
    first = lab.run_learning_experiment("one")
    second = lab.run_learning_experiment("two")
    again = lab.run_learning_experiment("one")
    assert first == again
    assert first["original_sha256"] == second["original_sha256"]
    assert first["modified_sha256"] != second["modified_sha256"]
    first["rows"][0]["original"] = -100
    assert lab.run_learning_experiment("one") == again
