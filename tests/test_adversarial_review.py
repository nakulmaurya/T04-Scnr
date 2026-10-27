"""Independent hostile-input regressions; unittest-compatible and pytest-collectable.

No network, optional ML libraries, downloaded models, or unsafe loaders needed.
Fixtures use a minimal safetensors writer rather than safetensors/torch packages.
"""

from __future__ import annotations
import builtins
import io
import json
import os
from pathlib import Path
import pickle
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from stegogate import intake, features, reference, static_scan, ml, storage, ui_helpers
from stegogate.pipeline import scan_artifact


def artifact(path, header, data=b""):
    raw = header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":")).encode()
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + data)
    return path


def f32(path, values, shape=None, name="weight"):
    return artifact(
        path,
        {name: {"dtype": "F32", "shape": shape or [len(values)], "data_offsets": [0, 4 * len(values)]}},
        struct.pack("<" + "f" * len(values), *values),
    )


class AdversarialReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"STEGOGATE_DATA_DIR": str(self.root / "state")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_duplicate_keys_nested_and_top_level_are_rejected(self):
        for raw in [
            b'{"x":{},"x":{}}',
            b'{"x":{"dtype":"U8","dtype":"F32","shape":[1],"data_offsets":[0,1]}}',
            b'{"__metadata__":{"author":"a","author":"b"}}',
        ]:
            with self.subTest(raw=raw):
                result = intake.inspect_artifact(artifact(self.root / "x.safetensors", raw))
                self.assertTrue(result["errors"])
                self.assertEqual(result["tensors"], [])

    def test_unpaired_surrogate_name_is_structural_rejection_not_exception(self):
        raw = b'{"\\ud800":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
        result = intake.inspect_artifact(artifact(self.root / "x.safetensors", raw, b"\0"))
        self.assertTrue(result["errors"])
        self.assertEqual(result["tensors"], [])

    def test_deep_header_rejected_without_uncaught_recursion(self):
        raw = b'{"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"
        self.assertTrue(intake.inspect_artifact(artifact(self.root / "x.safetensors", raw))["errors"])

    def test_bad_shape_offsets_dtype_and_metadata(self):
        records = [
            {"dtype": "F32", "shape": [True], "data_offsets": [0, 4]},
            {"dtype": "F32", "shape": [-1], "data_offsets": [0, 4]},
            {"dtype": "F32", "shape": [0, 2**50], "data_offsets": [0, 0]},
            {"dtype": "F32", "shape": [1], "data_offsets": [False, 4]},
            {"dtype": "F32", "shape": [1], "data_offsets": [0, 3]},
            {"dtype": "EVIL", "shape": [1], "data_offsets": [0, 4]},
        ]
        for record in records:
            with self.subTest(record=record):
                self.assertTrue(
                    intake.inspect_artifact(artifact(self.root / "x.safetensors", {"x": record}, b"\0" * 4))[
                        "errors"
                    ]
                )
        self.assertTrue(
            intake.inspect_artifact(artifact(self.root / "x.safetensors", {"__metadata__": {"x": 1}}))[
                "errors"
            ]
        )

    def test_overlap_gap_unclaimed_and_header_cap(self):
        for offsets in [([0, 2], [1, 3]), ([0, 1], [2, 3]), ([0, 1], [1, 2])]:
            header = {
                name: {"dtype": "U8", "shape": [end - start], "data_offsets": [start, end]}
                for name, (start, end) in zip(["a", "b"], offsets)
            }
            self.assertTrue(
                intake.inspect_artifact(artifact(self.root / "x.safetensors", header, b"123"))["errors"]
            )
        path = self.root / "x.safetensors"
        path.write_bytes(struct.pack("<Q", 2**63))
        self.assertTrue(intake.inspect_artifact(path)["errors"])

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_fifo_and_symlink_never_read(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.assertTrue(intake.inspect_artifact(fifo)["errors"])
        regular = self.root / "target"
        regular.write_bytes(b"abc")
        alias = self.root / "alias"
        alias.symlink_to(regular)
        self.assertTrue(intake.inspect_artifact(alias)["errors"])

    def test_pickle_payload_never_executed_and_no_framework_import(self):
        marker = self.root / "EXECUTED"

        class Payload:
            def __reduce__(self):
                return (os.system, (f"touch {marker}",))

        path = self.root / "exploit.pt"
        path.write_bytes(pickle.dumps(Payload()))
        real_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name.split(".")[0] in {"torch", "tensorflow", "sklearn", "joblib", "dill", "cloudpickle"}:
                raise AssertionError(f"unsafe runtime import: {name}")
            return real_import(name, *args, **kwargs)

        with (
            patch("builtins.__import__", side_effect=guarded),
            patch("pickle.load", side_effect=AssertionError("pickle load")),
            patch("pickle.loads", side_effect=AssertionError("pickle loads")),
        ):
            report = scan_artifact(path, config={"run_static": False})
        self.assertFalse(marker.exists())
        self.assertEqual(report["behavioral_analysis"]["status"], "not_performed")
        self.assertEqual(report["runtime"]["device"], "cpu")
        self.assertEqual(report["ml_analysis"]["status"], "not_available")
        self.assertNotIn("TRUSTED", report["verdict"])

    def test_default_scan_no_network_and_optional_static_absence_explicit(self):
        import socket

        path = f32(self.root / "x.safetensors", [i / 64 for i in range(64)])
        with (
            patch.object(static_scan.importlib.util, "find_spec", return_value=None),
            patch.object(socket.socket, "connect", side_effect=AssertionError("network connection")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network connection")),
        ):
            result = scan_artifact(path)
        self.assertEqual(result["static_analysis"]["status"], "unavailable")
        self.assertEqual(result["ml_analysis"]["status"], "not_available")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["behavioral_analysis"]["status"], "not_performed")

    def test_unknown_with_all_engines_missing_not_completed(self):
        path = self.root / "unknown"
        path.write_bytes(b"not a model")
        result = scan_artifact(path, config={"run_static": False})
        self.assertNotEqual(
            result["status"], "completed", "zero actual analyses must not be presented as completed coverage"
        )

    def test_nonfinite_weights_excluded_and_finite_json(self):
        path = f32(self.root / "bad.safetensors", [float("nan")] * 64)
        result = features.analyze_weights(path, intake.inspect_artifact(path))
        self.assertNotEqual(result["status"], "completed")
        self.assertEqual(result["windows"], [])
        self.assertFalse(result["coverage"]["full_coverage"])
        json.dumps(result, allow_nan=False)

    def test_window_budget_deterministic_and_no_name_features(self):
        path = f32(self.root / "finite.safetensors", [i / 100 for i in range(1024)])
        inventory = intake.inspect_artifact(path)
        a = features.analyze_weights(path, inventory, {"max_windows": 2, "window_elements": 64})
        self.assertEqual(
            a, features.analyze_weights(path, inventory, {"max_windows": 2, "window_elements": 64})
        )
        self.assertLessEqual(len(a["windows"]), 2)
        self.assertEqual(a["status"], "partial")
        self.assertTrue(all(not (set(w["features"]) & ml.IDENTITY_FEATURES) for w in a["windows"]))
        json.dumps(a, allow_nan=False)

    def test_spoofed_inventory_is_not_trusted(self):
        path = f32(self.root / "x.safetensors", [1.0] * 64)
        inventory = intake.inspect_artifact(path)
        inventory["sha256"] = "0" * 64
        self.assertEqual(features.analyze_weights(path, inventory)["status"], "failed")

    def test_reference_equal_bytes_incompatible_shapes_never_compared(self):
        a = f32(self.root / "a.safetensors", [1.0] * 64, shape=[8, 8])
        b = f32(self.root / "b.safetensors", [1.0] * 64, shape=[64])
        result = reference.compare_reference(a, b)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["summary"]["incompatible_tensors"], 1)
        self.assertEqual(result["summary"]["compared_bytes"], 0)
        self.assertNotEqual(result["tensors"][0]["status"], "identical")

    def test_reference_sample_equality_not_full_equality(self):
        a = f32(self.root / "a.safetensors", [1.0] * 1024)
        values = [1.0] * 1024
        values[-1] = 2.0
        b = f32(self.root / "b.safetensors", values)
        result = reference.compare_reference(a, b, {"max_reference_windows": 1, "reference_window_bytes": 64})
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["summary"]["identical_artifact"])
        self.assertFalse(result["summary"]["full_compatible_data_coverage"])
        self.assertEqual(result["tensors"][0]["status"], "no_sampled_difference")

    def test_lineages_disjoint_and_variants_do_not_drive_split(self):
        lineages = [f"base-{i}" for i in range(20)]
        split = ml._partition(lineages * 4, 42)
        groups = [set(split[k]) for k in ["train", "validation", "test"]]
        self.assertEqual(set.union(*groups), set(lineages))
        self.assertFalse(groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])
        self.assertEqual(split, ml._partition(lineages[::-1], 42))
        with self.assertRaises(ValueError):
            ml._partition(["a", "a", "b"], 42)
        for name in ml.IDENTITY_FEATURES:
            with self.assertRaises(ValueError):
                ml._feature_names({"normal": 1, name: 2})

    def test_malicious_tree_cycle_refused_without_inference(self):
        model = {
            "schema_version": ml.SCHEMA,
            "classes": [0, 1],
            "feature_names": ["x"],
            "trees": [
                {"left": [0], "right": [0], "feature": [0], "threshold": [0.0], "positive_fraction": [1.0]}
            ],
        }
        with self.assertRaises(ValueError):
            ml._validate_detector(model)
        self.assertEqual(ml.score_windows([], self.root / "outside" / "detector.json")["status"], "failed")

    def test_storage_filename_traversal_and_symlink_directories(self):
        staged = storage.stage_upload(io.BytesIO(b"bytes"), "../../attack.py")
        self.assertEqual(staged.parent, storage.data_root() / "uploads")
        self.assertFalse((self.root / "attack.py").exists())
        reports = storage.data_root() / "reports"
        reports.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            storage.load_report("11111111-1111-4111-8111-111111111111")
        for identifier in ["../outside", "/etc/passwd", "1" * 36]:
            with self.assertRaises(ValueError):
                storage._scan_id(identifier)

    def test_html_all_attacker_fields_escaped(self):
        payload = "</pre><script>alert(1)</script><img src=x onerror=alert(2)>"
        report = {
            "artifact": {"original_name": payload},
            "limitations": [payload],
            "weight_analysis": {"windows": [{"tensor": payload, "evidence": [payload]}]},
            "static_analysis": {"findings": [{"message": payload}]},
        }
        html = ui_helpers.export_html(report)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("default-src", html)

    def test_scanner_exit_zero_is_not_completion(self):
        for payload in [{}, {"success": True}, {"success": True, "files_scanned": 0}]:
            self.assertEqual(static_scan._normalize(payload, 0)[0], "partial")
        result = static_scan._normalize(
            {"success": True, "files_scanned": 1, "checks": [{"status": "skipped", "name": "scan"}]}, 0
        )
        self.assertEqual(result[0], "partial")
        self.assertEqual(result[1], [])

    @unittest.skipUnless(sys.platform == "linux", "Linux seccomp policy")
    def test_static_bootstrap_kernel_network_process_and_loader_denials(self):
        # Exercise the actual trusted bootstrap, replacing only scanner dispatch.
        probe = """
import socket, pickle
blocked=[]
for name, action in [('network',lambda:socket.socket()),
                     ('process',lambda:os.fork()),
                     ('pickle',lambda:pickle.loads(b'N.'))]:
    try:
        action()
    except (PermissionError,RuntimeError):
        blocked.append(name)
print(','.join(blocked))
"""
        bootstrap = static_scan._BOOTSTRAP.replace(
            "runpy.run_module('modelaudit', run_name='__main__')", probe
        )
        result = static_scan._run_bounded(
            [sys.executable, "-I", "-c", bootstrap, "5", str(512 * 1024**2), str(self.root / "upload")],
            timeout=8,
            max_output=8192,
            env={"PATH": os.defpath},
            cwd=self.root,
        )
        self.assertEqual(result["state"], "finished")
        self.assertEqual(result["returncode"], 0, result["stderr"])
        self.assertEqual(result["stdout"].strip(), "network,process,pickle")

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_scanner_fixed_arguments_allowlisted_environment_and_no_network_flags(self):
        path = f32(self.root / "input.safetensors", [1.0] * 64)
        helps = " ".join(
            ["--format", "--no-cache", "--no-whitelist", "--scanners", "--timeout", "--max-size"]
        )
        calls = []

        def run(command, **kw):
            calls.append((command, kw))
            payload = helps if "--help" in command else json.dumps({"success": True, "files_scanned": 1})
            return {"state": "finished", "returncode": 0, "stdout": payload, "stderr": ""}

        with (
            patch.object(static_scan.importlib.util, "find_spec", return_value=object()),
            patch.object(static_scan.importlib.metadata, "version", return_value="test"),
            patch.object(static_scan, "_run_bounded", side_effect=run),
            patch.dict(os.environ, {"SECRET_TOKEN": "do-not-inherit", "PYTHONPATH": "untrusted"}),
        ):
            result = static_scan.run_modelaudit(path)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(calls), 2)
        command, kw = calls[1]
        self.assertIn("-I", command)
        self.assertEqual(command[command.index("--scanners") + 1], "safetensors")
        self.assertEqual(command[-2:], ["--", str(path.resolve())])
        self.assertNotIn("SECRET_TOKEN", kw["env"])
        self.assertNotIn("PYTHONPATH", kw["env"])
        self.assertEqual(kw["env"]["CUDA_VISIBLE_DEVICES"], "")
        self.assertNotIn("--allow-unsafe", command)

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_scanner_output_and_timeout_bounded(self):
        env = {"PATH": os.defpath}
        result = static_scan._run_bounded(
            [sys.executable, "-I", "-c", 'import sys;sys.stdout.write("x"*200000)'],
            timeout=5,
            max_output=1024,
            env=env,
            cwd=self.root,
        )
        self.assertEqual(result["state"], "output_limit")
        self.assertLessEqual(len(result["stdout"].encode()) + len(result["stderr"].encode()), 1024)
        result = static_scan._run_bounded(
            [sys.executable, "-I", "-c", "import time;time.sleep(5)"],
            timeout=0.15,
            max_output=1024,
            env=env,
            cwd=self.root,
        )
        self.assertEqual(result["state"], "timed_out")


if __name__ == "__main__":
    unittest.main()
