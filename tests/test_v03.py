"""Regression checks for independent disassembly and precision semantics."""

import json
import struct
import numpy as np
import pytest
from stegogate.intake import inspect_artifact
from stegogate.precision import analyze_precision, describe_words
from stegogate.picklescan_scan import run_picklescan


def half_file(path, dtype, words):
    raw = np.asarray(words, dtype="<u2").tobytes()
    header = json.dumps(
        {"weights": dict(dtype=dtype, shape=[len(words)], data_offsets=[0, len(raw)])}
    ).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header + raw)
    return path


@pytest.mark.parametrize("dtype,bits,one", [("F16", 10, 0x3C00), ("BF16", 7, 0x3F80)])
def test_precision_bit_geometry(dtype, bits, one):
    x = np.array([0, 0x8000, 1, one], dtype="<u2")
    f = describe_words(x, dtype)
    assert f["zero_fraction"] == 0.5
    assert f["negative_zero_fraction"] == 0.25
    assert f["subnormal_fraction"] == 0.25
    assert len([k for k in f if k.startswith("mantissa_bit")]) == bits
    assert f["mantissa_bit_0_one_fraction"] == 0.25
    assert f["mean"] >= 0.25


def test_bf16_exponent_not_mantissa():
    f = describe_words(np.array([0x3F00, 0x3F80], dtype="<u2"), "BF16")
    assert f["mantissa_entropy"] == 0
    assert "mantissa_bit_7_one_fraction" not in f
    assert f["mean"] == 0.75


@pytest.mark.parametrize("dtype,word", [("F16", 0x7C00), ("F16", 0x7E00), ("BF16", 0x7F80), ("BF16", 0x7FC0)])
def test_nonfinite_rejected(dtype, word):
    with pytest.raises(ValueError):
        describe_words(np.array([word], dtype="<u2"), dtype)


def test_bounded_half_coverage(tmp_path):
    p = half_file(tmp_path / "x", "F16", np.arange(1000, dtype=np.uint16))
    inv = inspect_artifact(p)
    a = analyze_precision(p, inv, {"max_precision_windows": 2, "window_elements": 256})
    assert a == analyze_precision(p, inv, {"max_precision_windows": 2, "window_elements": 256})
    assert a["status"] == "partial"
    assert len(a["windows"]) == 2
    assert a["coverage"]["unique_sampled_elements"] == 512
    assert a["ml_status"] == "not_available"
    assert "anomaly_score" not in a["windows"][0]
    assert a["windows"][1]["element_start"] == 744


def test_half_overlap_union(tmp_path):
    p = half_file(tmp_path / "x", "BF16", [0] * 300)
    a = analyze_precision(p, inspect_artifact(p), {"window_elements": 256})
    assert a["coverage"]["unique_sampled_elements"] == 300
    assert a["coverage"]["attempted_elements"] == 512
    assert a["status"] == "completed"


def test_nonfinite_coverage(tmp_path):
    p = half_file(tmp_path / "x", "BF16", [0x7F80] * 300)
    a = analyze_precision(p, inspect_artifact(p))
    assert a["status"] == "partial" and not a["windows"]
    assert a["coverage"]["rejected_windows"] == 1


def test_stale_inventory(tmp_path):
    p = half_file(tmp_path / "x", "F16", [0] * 300)
    inv = inspect_artifact(p)
    half_file(p, "F16", [1] * 300)
    assert analyze_precision(p, inv)["status"] == "failed"


def test_picklescan_safetensors_inapplicable(tmp_path):
    p = half_file(tmp_path / "x", "F16", [0] * 300)
    assert run_picklescan(p)["status"] == "not_applicable"


@pytest.mark.parametrize("raw,expected", [(b"\x80\x02N.", False), (b"\x80\x02cposix\nsystem\n.", True)])
def test_real_disassembly(tmp_path, raw, expected):
    p = tmp_path / "x"
    p.write_bytes(raw)
    r = run_picklescan(p)
    if r["engine_version"] is None:
        pytest.skip("Picklescan absent")
    assert r["status"] == "completed", r
    assert bool(r["findings"]) == expected
    if expected:
        assert r["findings"][0]["rule"] == "PICKLESCAN_DANGEROUS_GLOBAL"


def test_pickle_malformed_not_clean(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"\x80\x02invalid")
    r = run_picklescan(p)
    if r["engine_version"] is None:
        pytest.skip("Picklescan absent")
    assert r["status"] == "partial"


def test_zip_traversal_fails(tmp_path):
    import zipfile

    p = tmp_path / "x"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("../data.pkl", b"\x80\x02N.")
    r = run_picklescan(p)
    if r["engine_version"] is None:
        pytest.skip("Picklescan absent")
    assert r["status"] == "failed"


def test_hostile_reduce_no_execution(tmp_path):
    import zipfile

    marker = tmp_path / "EXECUTED"
    # Build inert protocol2 bytes, never deserialize or create a reduce-capable object.
    command = ("touch " + str(marker)).encode()
    raw = b"\x80\x02cposix\nsystem\nX" + struct.pack("<I", len(command)) + command + b"\x85R."
    p = tmp_path / "x"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/data.pkl", raw)
    r = run_picklescan(p)
    if r["engine_version"] is None:
        pytest.skip("Picklescan absent")
    assert r["status"] == "completed" and r["findings"], r
    assert not marker.exists()


@pytest.mark.parametrize(
    "partition",
    [
        {"train": ["a"], "validation": ["a"], "test": ["c"]},
        {"train": ["a"], "validation": ["b"], "test": ["unknown"]},
        {"train": ["a"], "validation": [], "test": ["b", "c"]},
        {"train": ["a"], "validation": ["b"]},
    ],
)
def test_explicit_partition_rejected(tmp_path, monkeypatch, partition):
    from stegogate.ml import train_detector

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    rows = [
        dict(lineage=lineage, label=n, features={"x": float(n)})
        for lineage in ("a", "b", "c")
        for n in (0, 1)
    ]
    with pytest.raises(ValueError):
        train_detector(rows, tmp_path / "detector", {"lineage_partition": partition})
    assert not (tmp_path / "detector").exists()


def test_explicit_partition_roundtrip(tmp_path, monkeypatch):
    from stegogate.ml import train_detector, score_windows

    monkeypatch.setenv("STEGOGATE_DATA_DIR", str(tmp_path))
    rows = [
        dict(lineage=lineage, label=n, features={"x": float(n)})
        for lineage in ("a", "b", "c")
        for n in (0, 1)
        for _ in range(3)
    ]
    split = {"train": ["a"], "validation": ["b"], "test": ["c"]}
    result = train_detector(rows, tmp_path / "detector", {"lineage_partition": split, "n_estimators": 4})
    assert result["manifest"]["split"] == split
    assert result["manifest"]["threshold"] == 0.5
    assert (
        score_windows(
            [dict(tensor="x", window_index=0, features={"x": 0.0})], tmp_path / "detector/detector.json"
        )["status"]
        == "completed"
    )


def test_pickle_zip_bomb_budget(tmp_path):
    import zipfile

    p = tmp_path / "x"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("data.pkl", b"\x80\x02" + b"N" * 100000 + b".")
    r = run_picklescan(p)
    if r["engine_version"] is None:
        pytest.skip("Picklescan absent")
    assert r["status"] == "failed"


def test_pickle_timeout_explicit(tmp_path, monkeypatch):
    import stegogate.picklescan_scan as adapter

    monkeypatch.setattr(adapter.importlib.metadata, "version", lambda name: "1.0.5")
    monkeypatch.setattr(adapter, "_run_bounded", lambda *a, **kw: dict(state="timed_out", returncode=-9))
    p = tmp_path / "x"
    p.write_bytes(b"\x80\x02N.")
    assert run_picklescan(p)["status"] == "timed_out"


@pytest.mark.parametrize(
    "words", [np.array([], dtype="<u2"), np.array([1.0], dtype="<f4"), np.zeros((2, 2), dtype="<u2")]
)
def test_precision_vector_contract(words):
    with pytest.raises(ValueError):
        describe_words(words, "F16")
