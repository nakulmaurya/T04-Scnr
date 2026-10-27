"""Core security regression tests. Run with unittest or pytest; no downloads."""

import json
import math
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import numpy as np

from stegogate.intake import inspect_artifact
from stegogate.features import analyze_weights, FEATURE_NAMES
from stegogate.reference import compare_reference
from stegogate.static_scan import run_modelaudit, _run_bounded, _normalize, _BOOTSTRAP


def artifact(path, tensors, metadata=None):
    """Generate test-only numeric data; no serialization frameworks."""
    header, data = {}, bytearray()
    for name, array in tensors.items():
        array = np.asarray(array)
        dtype = {"float32": "F32", "float64": "F64", "int32": "I32", "uint8": "U8"}[str(array.dtype)]
        payload = array.tobytes()
        header[name] = dict(
            dtype=dtype, shape=list(array.shape), data_offsets=[len(data), len(data) + len(payload)]
        )
        data.extend(payload)
    if metadata is not None:
        header["__metadata__"] = metadata
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + data)
    return path


class CoreCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "weights.safetensors"

    def tearDown(self):
        self.temp.cleanup()

    def raw(self, header, data=b""):
        if isinstance(header, dict):
            header = json.dumps(header).encode()
        self.path.write_bytes(struct.pack("<Q", len(header)) + header + data)
        return inspect_artifact(self.path)

    def tensor(self, shape, offsets, dtype="F32"):
        return dict(dtype=dtype, shape=shape, data_offsets=offsets)

    def make(self, n=2048):
        return artifact(self.path, {"weight": np.random.default_rng(19).normal(size=n).astype("float32")})


class IntakeTests(CoreCase):
    def test_valid_f32_inventory_and_hash(self):
        self.make()
        result = inspect_artifact(self.path)
        self.assertEqual(result["format"], "safetensors")
        self.assertFalse(result["errors"])
        self.assertEqual(result["tensors"][0]["numel"], 2048)
        self.assertEqual(len(result["sha256"]), 64)

    def test_duplicate_tensor_names(self):
        self.assertTrue(
            self.raw(
                b'{"w":{"dtype":"F32","shape":[0],"data_offsets":[0,0]},"w":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}'
            )["errors"]
        )

    def test_nested_duplicate_keys(self):
        self.assertTrue(
            self.raw(b'{"w":{"dtype":"F32","dtype":"I32","shape":[0],"data_offsets":[0,0]}}')["errors"]
        )

    def test_metadata_duplicate(self):
        self.assertTrue(self.raw(b'{"__metadata__":{"x":"a","x":"b"}}')["errors"])

    def test_overlap(self):
        self.assertTrue(
            self.raw({"a": self.tensor([2], [0, 8]), "b": self.tensor([2], [4, 12])}, b"0" * 12)["errors"]
        )

    def test_gap(self):
        self.assertTrue(self.raw({"a": self.tensor([1], [4, 8])}, b"0" * 8)["errors"])

    def test_trailing_data(self):
        self.assertTrue(self.raw({"a": self.tensor([1], [0, 4])}, b"0" * 8)["errors"])

    def test_negative_or_bool_shapes(self):
        for shape in [[-1], [True], [1.0], ["1"]]:
            with self.subTest(shape=shape):
                self.assertTrue(self.raw({"a": self.tensor(shape, [0, 0])})["errors"])

    def test_huge_zero_shape_rejected(self):
        self.assertTrue(self.raw({"a": self.tensor([0, 1 << 41], [0, 0])})["errors"])

    def test_zero_sized_valid_at_boundary(self):
        r = self.raw(
            {"z": self.tensor([0, 9], [4, 4]), "a": self.tensor([1], [0, 4]), "b": self.tensor([0], [0, 0])},
            b"0" * 4,
        )
        self.assertFalse(r["errors"])
        self.assertEqual(len(r["tensors"]), 3)

    def test_zero_sized_interior_rejected(self):
        self.assertTrue(
            self.raw({"a": self.tensor([2], [0, 8]), "z": self.tensor([0], [4, 4])}, b"0" * 8)["errors"]
        )

    def test_zero_shape_checks_other_dimensions(self):
        self.assertTrue(self.raw({"a": self.tensor([0, -2], [0, 0])})["errors"])

    def test_scalar_valid(self):
        r = self.raw({"a": self.tensor([], [0, 4])}, b"0" * 4)
        self.assertFalse(r["errors"])
        self.assertEqual(r["tensors"][0]["numel"], 1)

    def test_offsets_boolean_and_negative(self):
        for offsets in [[False, 0], [-1, 3], [4, 0], [0, 99]]:
            with self.subTest(offsets=offsets):
                self.assertTrue(self.raw({"a": self.tensor([1], offsets)}, b"0" * 4)["errors"])

    def test_bad_header_and_size(self):
        for raw in [
            b"",
            b"[]",
            b' {"x":0}',
            b"{",
            b"{}\t",
            b"{}\n",
            b'{"__metadata__":{"x":NaN}}',
            b"\xff{}",
        ]:
            with self.subTest(raw=raw):
                self.assertTrue(self.raw(raw)["errors"])
        self.path.write_bytes(struct.pack("<Q", 2**63) + b"{}")
        self.assertTrue(inspect_artifact(self.path)["errors"])

    def test_unknown_dtype_metadata_extra_keys(self):
        self.assertTrue(self.raw({"a": self.tensor([0], [0, 0], "MAGIC")})["errors"])
        self.assertTrue(self.raw({"__metadata__": {"x": 1}})["errors"])
        t = self.tensor([0], [0, 0])
        t["extra"] = True
        self.assertTrue(self.raw({"a": t})["errors"])

    def test_unpaired_surrogate_tensor_name(self):
        self.assertTrue(self.raw(b'{"\\ud800":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}')["errors"])

    def test_unpaired_surrogate_metadata(self):
        for h in [b'{"__metadata__":{"x":"\\ud800"}}', b'{"__metadata__":{"\\udfff":"x"}}']:
            self.assertTrue(self.raw(h)["errors"])

    def test_empty_tensor_header_valid(self):
        self.assertFalse(self.raw({})["errors"])

    def test_artifact_cap(self):
        self.make()
        r = inspect_artifact(self.path, {"max_artifact_bytes": 64})
        self.assertTrue(r["errors"])
        self.assertFalse(r["sha256"])

    def test_symlink_and_fifo(self):
        self.make()
        link = self.root / "link.safetensors"
        link.symlink_to(self.path)
        self.assertTrue(inspect_artifact(link)["errors"])
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.assertTrue(inspect_artifact(fifo)["errors"])

    def test_deep_json_bounded(self):
        self.assertTrue(self.raw(b'{"a":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}")["errors"])

    def test_non_safetensors_never_executed(self):
        self.path = self.root / "model.pkl"
        self.path.write_bytes(b"\x80\x04cos\nsystem\nX\x00\x00\x00\x00\x85R.")
        r = inspect_artifact(self.path)
        self.assertEqual(r["format"], "pickle")
        self.assertFalse(r["tensors"])

    def test_invalid_safetensors_not_reclassified_as_zip(self):
        self.path.write_bytes(b"PK\x03\x04malformed")
        r = inspect_artifact(self.path)
        self.assertEqual(r["format"], "safetensors")
        self.assertTrue(r["errors"])

    def test_invalid_config(self):
        self.make()
        self.assertTrue(inspect_artifact(self.path, {"max_header_bytes": True})["errors"])


class FeatureTests(CoreCase):
    def test_features_finite_stable_names(self):
        self.make()
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertEqual(r["status"], "completed")
        self.assertEqual(set(r["windows"][0]["features"]), set(FEATURE_NAMES))
        self.assertTrue(all(math.isfinite(x) for x in r["windows"][0]["features"].values()))
        json.dumps(r, allow_nan=False)

    def test_empty_tiny_unsupported(self):
        artifact(
            self.path,
            {
                "empty": np.empty((0,), dtype="float32"),
                "tiny": np.zeros(3, dtype="float32"),
                "other": np.ones(90, dtype="float64"),
            },
        )
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertEqual(r["status"], "unsupported")
        self.assertEqual(len(r["tensor_summaries"]), 3)
        self.assertFalse(r["windows"])

    def test_degenerate_not_claimed_steganography(self):
        artifact(self.path, {"z": np.zeros(128, dtype="float32"), "c": np.full(128, 1.25, dtype="float32")})
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertEqual(len(r["windows"]), 2)
        for w in r["windows"]:
            self.assertEqual(w["anomaly_score"], 0)
            self.assertIn("Degenerate", w["evidence"][0])

    def test_nan_inf_windows_excluded(self):
        x = np.ones(128, dtype="float32")
        x[0] = np.nan
        x[-1] = np.inf
        artifact(self.path, {"bad": x, "good": np.ones(128, dtype="float32")})
        r = analyze_weights(self.path, inspect_artifact(self.path), {"window_elements": 128})
        self.assertEqual(r["status"], "partial")
        self.assertEqual(len(r["windows"]), 1)
        self.assertEqual(sum(s["rejected_windows"] for s in r["tensor_summaries"]), 1)
        json.dumps(r, allow_nan=False)

    def test_all_nonfinite_is_partial_not_completed(self):
        artifact(self.path, {"bad": np.full(64, np.nan, dtype="float32")})
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertEqual(r["status"], "partial")
        self.assertFalse(r["windows"])
        self.assertEqual(r["coverage"]["sampled_fraction"], 0)

    def test_extreme_finite_f32_values(self):
        x = np.array([np.finfo("float32").max, -np.finfo("float32").max] * 64, dtype="float32")
        artifact(self.path, {"w": x})
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertTrue(r["windows"])
        json.dumps(r, allow_nan=False)

    def test_sampling_bounded_deterministic_spans(self):
        self.make(20000)
        inv = inspect_artifact(self.path)
        cfg = {"max_windows": 3, "window_elements": 256}
        a = analyze_weights(self.path, inv, cfg)
        b = analyze_weights(self.path, inv, cfg)
        self.assertEqual(a, b)
        self.assertEqual(len(a["windows"]), 3)
        self.assertEqual([w["element_start"] for w in a["windows"]], [0, 9872, 19744])
        self.assertEqual(a["coverage"]["sampled_elements"], 768)
        self.assertEqual(a["status"], "partial")

    def test_no_overlapping_sample_coverage(self):
        self.make(4097)
        r = analyze_weights(self.path, inspect_artifact(self.path), {"window_elements": 4096})
        self.assertLessEqual(r["coverage"]["sampled_elements"], 4097)
        self.assertEqual(len(r["windows"]), 1)

    def test_many_tensors_respects_budget(self):
        artifact(self.path, {f"w{i:03d}": np.ones(64, dtype="float32") for i in range(150)})
        r = analyze_weights(self.path, inspect_artifact(self.path))
        self.assertEqual(len(r["windows"]), 128)
        self.assertEqual(r["status"], "partial")

    def test_stale_inventory_and_malformed_fail(self):
        self.make()
        inv = inspect_artifact(self.path)
        self.make(100)
        self.assertEqual(analyze_weights(self.path, inv)["status"], "failed")
        self.path.write_bytes(b"bad")
        self.assertEqual(analyze_weights(self.path, inv)["status"], "failed")

    def test_bitplanes_use_ieee_f32_not_numeric_cast(self):
        bits = np.tile(np.array([0x3F800000, 0x3F800001], dtype="<u4"), 64)
        artifact(self.path, {"w": bits.view("<f4")})
        r = analyze_weights(self.path, inspect_artifact(self.path))
        f = r["windows"][0]["features"]
        self.assertEqual(f["bit_0_one_fraction"], 0.5)
        self.assertEqual(f["bit_1_one_fraction"], 0)

    def test_unrecognized_format_unsupported(self):
        p = self.root / "unknown.bin"
        p.write_bytes(b"nothing")
        self.assertEqual(analyze_weights(p, inspect_artifact(p))["status"], "unsupported")


class ReferenceTests(CoreCase):
    def test_identical_reference_hash_and_coverage(self):
        self.make()
        r = compare_reference(self.path, self.path)
        self.assertEqual(r["status"], "completed")
        self.assertTrue(r["summary"]["identical_artifact"])
        self.assertEqual(r["summary"]["differing_sampled_bytes"], 0)
        self.assertTrue(r["summary"]["full_compatible_data_coverage"])

    def test_numeric_changes_not_malicious_claim(self):
        self.make(100)
        q = self.root / "ref.safetensors"
        artifact(q, {"weight": np.zeros(100, dtype="float32")})
        r = compare_reference(self.path, q)
        self.assertEqual(r["status"], "completed")
        self.assertGreater(r["summary"]["differing_sampled_bytes"], 0)
        self.assertIn("do not imply malicious", r["warnings"][0])
        json.dumps(r, allow_nan=False)

    def test_incompatible_added_removed(self):
        artifact(
            self.path, {"different": np.ones(100, dtype="float32"), "added": np.ones(5, dtype="float32")}
        )
        q = self.root / "ref.safetensors"
        artifact(q, {"different": np.ones(50, dtype="float32"), "removed": np.zeros(1, dtype="float32")})
        r = compare_reference(self.path, q)
        self.assertEqual(r["status"], "partial")
        for k in ["incompatible_tensors", "added_tensors", "removed_tensors"]:
            self.assertEqual(r["summary"][k], 1)

    def test_reference_sampling_bound(self):
        self.make(100000)
        r = compare_reference(
            self.path, self.path, {"max_reference_windows": 3, "reference_window_bytes": 1024}
        )
        self.assertEqual(r["summary"]["compared_bytes"], 3072)
        self.assertEqual(r["status"], "partial")
        starts = [x["byte_start"] for x in r["tensors"][0]["sample_windows"]]
        self.assertEqual(starts[0], 0)
        self.assertEqual(starts[-1], 400000 - 1024)

    def test_reference_nonfinite_honest(self):
        artifact(self.path, {"w": np.full(64, np.nan, dtype="float32")})
        r = compare_reference(self.path, self.path)
        w = r["tensors"][0]["sample_windows"][0]
        self.assertEqual(w["nonfinite_pairs"], 64)
        self.assertIsNone(w["finite_mean_abs_difference"])
        json.dumps(r, allow_nan=False)

    def test_reference_empty(self):
        artifact(self.path, {"w": np.empty(0, dtype="float32")})
        r = compare_reference(self.path, self.path)
        self.assertEqual(r["status"], "completed")
        self.assertTrue(r["tensors"][0]["full_coverage"])

    def test_reference_malformed_failed(self):
        self.make()
        q = self.root / "bad.safetensors"
        q.write_bytes(b"bad")
        self.assertEqual(compare_reference(self.path, q)["status"], "failed")


class StaticTests(CoreCase):
    def help_result(self):
        return dict(
            state="finished",
            returncode=0,
            stderr="",
            stdout="--format --no-cache --no-whitelist --scanners --timeout --max-size",
        )

    def test_unavailable(self):
        self.make()
        with patch("stegogate.static_scan.importlib.util.find_spec", return_value=None):
            r = run_modelaudit(self.path)
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["findings"], [])

    def test_timeout_propagation(self):
        self.make()
        with (
            patch("stegogate.static_scan.importlib.util.find_spec", return_value=object()),
            patch(
                "stegogate.static_scan._run_bounded",
                side_effect=[
                    self.help_result(),
                    dict(state="timed_out", returncode=-9, stdout="", stderr=""),
                ],
            ),
        ):
            r = run_modelaudit(self.path)
        self.assertEqual(r["status"], "timed_out")

    def test_unsafe_cli_not_used(self):
        self.make()
        with (
            patch("stegogate.static_scan.importlib.util.find_spec", return_value=object()),
            patch(
                "stegogate.static_scan._run_bounded",
                return_value=dict(state="finished", returncode=0, stdout="--format", stderr=""),
            ) as runner,
        ):
            r = run_modelaudit(self.path)
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(runner.call_count, 1)

    def test_static_normalization_and_fixed_flags(self):
        self.make()
        payload = dict(
            success=True,
            files_scanned=1,
            issues=[dict(severity="critical", message="Executable opcode", rule_code="S101")],
            checks=[],
        )
        with (
            patch("stegogate.static_scan.importlib.util.find_spec", return_value=object()),
            patch(
                "stegogate.static_scan._run_bounded",
                side_effect=[
                    self.help_result(),
                    dict(state="finished", returncode=1, stdout=json.dumps(payload), stderr=""),
                ],
            ) as runner,
        ):
            r = run_modelaudit(self.path)
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["findings"][0]["severity"], "critical")
        cmd = runner.call_args_list[1].args[0]
        self.assertIn("--no-whitelist", cmd)
        self.assertIn("--scanners", cmd)
        self.assertNotIn("--trust-loaders", cmd)

    def test_mirrored_issue_check_deduplicated(self):
        issue = dict(severity="critical", message="indicator", location="x", rule_code="S101")
        check = dict(severity="critical", message="indicator", location="x", status="failed")
        status, findings, _ = _normalize(
            dict(success=True, files_scanned=1, issues=[issue], checks=[check]), 1
        )
        self.assertEqual(status, "completed")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_code"], "S101")

    def test_zero_exit_no_coverage_not_pass(self):
        status, findings, warnings = _normalize({}, 0)
        self.assertEqual(status, "partial")
        self.assertFalse(findings)

    def test_skipped_checks_partial(self):
        status, _, _ = _normalize(
            dict(
                success=True,
                files_scanned=1,
                issues=[],
                checks=[dict(status="skipped", message="missing dependency")],
            ),
            0,
        )
        self.assertEqual(status, "partial")

    def test_preserve_severity_without_downgrading(self):
        status, findings, _ = _normalize(
            dict(
                success=False,
                files_scanned=1,
                issues=[dict(severity="HIGH", message="x", details={"original_severity": "CRITICAL"})],
            ),
            1,
        )
        self.assertEqual(status, "partial")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["original_severity"], "CRITICAL")

    def test_output_limit(self):
        self.make()
        with (
            patch("stegogate.static_scan.importlib.util.find_spec", return_value=object()),
            patch(
                "stegogate.static_scan._run_bounded",
                side_effect=[
                    self.help_result(),
                    dict(state="output_limit", returncode=-9, stdout="", stderr=""),
                ],
            ),
        ):
            self.assertEqual(run_modelaudit(self.path)["status"], "partial")

    def test_malformed_json(self):
        self.make()
        with (
            patch("stegogate.static_scan.importlib.util.find_spec", return_value=object()),
            patch(
                "stegogate.static_scan._run_bounded",
                side_effect=[
                    self.help_result(),
                    dict(state="finished", returncode=0, stdout="not JSON", stderr=""),
                ],
            ),
        ):
            self.assertEqual(run_modelaudit(self.path)["status"], "failed")

    def test_bounded_process_timeout_and_output(self):
        cmd = [sys.executable, "-c", "import time;time.sleep(3)"]
        r = _run_bounded(cmd, timeout=0.1, max_output=1024, env=os.environ.copy(), cwd=self.root)
        self.assertEqual(r["state"], "timed_out")
        cmd = [sys.executable, "-c", 'import sys;sys.stdout.write("x"*1000000);sys.stdout.flush()']
        r = _run_bounded(cmd, timeout=2, max_output=1024, env=os.environ.copy(), cwd=self.root)
        self.assertEqual(r["state"], "output_limit")
        self.assertLessEqual(len(r["stdout"]), 1024)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux")
    def test_bootstrap_blocks_network_and_unsafe_loaders(self):
        probe = """
import socket
try: socket.socket()
except PermissionError: print('network-blocked')
else: raise RuntimeError('network was not blocked')
try: pickle.loads(b'N.')
except RuntimeError: print('loader-blocked')
else: raise RuntimeError('loader was not blocked')
try: import torch
except ImportError: print('framework-blocked')
else: raise RuntimeError('framework was not blocked')
"""
        source = _BOOTSTRAP.replace("runpy.run_module('modelaudit', run_name='__main__')", probe)
        r = _run_bounded(
            [sys.executable, "-I", "-c", source, "3", str(1024**3), str(self.path)],
            timeout=3,
            max_output=8192,
            env=os.environ.copy(),
            cwd=self.root,
        )
        self.assertEqual(r["returncode"], 0, r["stderr"])
        self.assertIn("network-blocked", r["stdout"])
        self.assertIn("loader-blocked", r["stdout"])
        self.assertIn("framework-blocked", r["stdout"])


if __name__ == "__main__":
    unittest.main()
