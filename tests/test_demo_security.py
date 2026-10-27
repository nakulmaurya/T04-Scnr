"""Dependency-light contract/security tests; no network or pickle execution."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

# Test loading independently of the application/package dependencies.
SOURCE = Path(__file__).resolve().parents[1] / "stegogate" / "demo.py"
spec = importlib.util.spec_from_file_location("demo_under_test", SOURCE)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoSecurityTests(unittest.TestCase):
    def test_catalog_allowlist_and_copy(self):
        catalog = demo.get_demo_catalog()
        self.assertEqual(
            {r["demo_id"] for r in catalog}, {"mnist-epoch01", "mnist-epoch02", "cifar10-resnet18"}
        )
        for row in catalog:
            self.assertRegex(row["revision"], r"^[0-9a-f]{40}$")
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
        catalog[0]["author_metrics"]["clean_accuracy"] = 999
        self.assertNotEqual(demo.get_demo_catalog()[0]["author_metrics"]["clean_accuracy"], 999)
        for unknown in ["../escape", "/tmp/model.pt", "https://bad.example/model", "mnist-epoch03", None]:
            with self.assertRaises(ValueError):
                demo.prepare_demo(unknown, Path("/tmp"), {"opt_in": True})
            with self.assertRaises(ValueError):
                demo.verify_behavior(unknown, Path("/tmp"), {"opt_in": True})

    def test_optin_and_sample_bounds(self):
        for config in [None, {}, {"opt_in": False}, {"opt_in": 1}]:
            with self.assertRaises(ValueError):
                demo.prepare_demo("mnist-epoch02", Path("/tmp"), config)
            with self.assertRaises(ValueError):
                demo.verify_behavior("mnist-epoch02", Path("/tmp"), config)
        for n in [0, -1, 10001]:
            with self.assertRaises(ValueError):
                demo.verify_behavior("mnist-epoch02", Path("/tmp"), {"opt_in": True, "sample_count": n})

    def test_no_torch_load_in_runtime_or_import_scope(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Attribute)
                        and isinstance(child.func.value, ast.Name)
                        and child.func.value.id == "torch"
                        and child.func.attr == "load"
                    ):
                        calls.append((node.name, child))
        self.assertEqual(len(calls), 1)
        owner, call = calls[0]
        self.assertEqual(owner, "_prepare_worker")
        self.assertTrue(
            any(
                k.arg == "weights_only" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in call.keywords
            )
        )
        self.assertNotIn("add_safe_globals", SOURCE.read_text(encoding="utf-8"))
        self.assertFalse(
            any(
                isinstance(n, ast.Import) and any(a.name.startswith("torch") for a in n.names)
                for n in tree.body
            )
        )
        prep = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_prepare_worker")
        checks = [
            n.lineno
            for n in ast.walk(prep)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_check"
        ]
        self.assertLess(min(checks), call.lineno)

    def test_hash_mismatch_and_size_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "model"
            p.write_bytes(b"abc")
            h = hashlib.sha256(b"abc").hexdigest()
            demo._check(p, 3, h)
            with self.assertRaises(ValueError):
                demo._check(p, 4, h)
            with self.assertRaises(ValueError):
                demo._check(p, 3, "0" * 64)
            with patch.object(
                demo.urllib.request, "urlopen", side_effect=AssertionError("must not redownload")
            ):
                with self.assertRaises(ValueError):
                    demo._download("https://example.invalid", p, 3, "0" * 64)

    def test_path_components_reject_traversal(self):
        for component in ["..", "../escape", "/tmp/model", "a/b", "a\\b", ""]:
            with self.assertRaises(ValueError):
                demo._file(Path("/tmp/demo"), component)

    def test_symlink_root_child_and_parent_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "demo"
            root.mkdir()
            outside = Path(d) / "outside"
            outside.mkdir()
            (root / "mnist-epoch02").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                demo._file(root, "mnist-epoch02", "model.safetensors")
            link = Path(d) / "alias"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                demo._file(link, "mnist-epoch01")
            with self.assertRaises(ValueError):
                demo._file(link / "deep", "model.safetensors")

    def test_preparation_manifest_is_not_trusted_for_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            folder = root / "mnist-epoch02"
            folder.mkdir()
            artifact = folder / "model.safetensors"
            artifact.write_bytes(b"original")
            digest = hashlib.sha256(b"original").hexdigest()
            e = demo._entry("mnist-epoch02")
            manifest = {
                "demo_id": "mnist-epoch02",
                "sha256": digest,
                "size_bytes": 8,
                "source_sha256": e["sha256"],
                "source_revision": e["revision"],
            }
            path = folder / "manifest.json"
            path.write_text(json.dumps(manifest))
            with patch.dict(demo._CONVERTED_HASHES, {"mnist-epoch02": digest}):
                self.assertEqual(demo._prepared("mnist-epoch02", root)[0], artifact)
                artifact.write_bytes(b"tampered")
                with self.assertRaises(ValueError):
                    demo._prepared("mnist-epoch02", root)
                manifest["sha256"] = hashlib.sha256(b"tampered").hexdigest()
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    demo._prepared("mnist-epoch02", root)
                manifest["source_revision"] = "0" * 40
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    demo._prepared("mnist-epoch02", root)

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_subprocess_no_shell_and_isolation(self):
        with patch.object(
            demo, "_run_bounded", return_value=("completed", b'{"status":"completed"}', b"", 0)
        ) as run:
            demo.verify_behavior("mnist-epoch02", Path("/tmp/demo"), {"opt_in": True, "sample_count": 20})
            command, env, timeout = run.call_args.args
            self.assertIn("-I", command)
            self.assertIn("--worker", command)
            self.assertEqual(env["HF_HUB_OFFLINE"], "1")
            self.assertNotIn("PYTHONPATH", env)
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        launch = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "Popen"
        )
        options = {k.arg: k.value for k in launch.keywords}
        self.assertIs(options["shell"].value, False)
        self.assertIs(options["start_new_session"].value, True)

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_stream_output_limit_shared_across_both_pipes(self):
        command = [demo.sys.executable, "-I", "-c", "import os;os.write(1,b'a'*40000);os.write(2,b'b'*40000)"]
        with patch.object(demo.os, "killpg", wraps=demo.os.killpg) as kill:
            state, out, err, code = demo._run_bounded(command, dict(demo.os.environ), 5)
        self.assertEqual(state, "output_limit")
        self.assertLessEqual(len(out) + len(err), 65536)
        kill.assert_called_once()

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_stream_timeout_kills_process_group(self):
        command = [demo.sys.executable, "-I", "-c", "import time;time.sleep(20)"]
        with patch.object(demo.os, "killpg", wraps=demo.os.killpg) as kill:
            state, out, err, code = demo._run_bounded(command, dict(demo.os.environ), 0.1)
        self.assertEqual(state, "timed_out")
        self.assertIsNotNone(code)
        kill.assert_called_once()

    @unittest.skipUnless(sys.platform == "linux", "Linux-only isolation/process contract; portable Windows paths have separate tests")
    def test_stream_normal_output_and_abnormal_exit(self):
        command = [demo.sys.executable, "-I", "-c", "print('small output')"]
        state, out, err, code = demo._run_bounded(command, dict(demo.os.environ), 5)
        self.assertEqual((state, out, err, code), ("completed", b"small output\n", b"", 0))
        with patch.object(
            demo, "_run_bounded", return_value=("completed", b'{"status":"completed"}', b"", 9)
        ):
            self.assertEqual(
                demo.verify_behavior("mnist-epoch02", Path("/tmp/demo"), {"opt_in": True})["status"], "failed"
            )

    def test_worker_resource_caps_before_model_import(self):
        source = SOURCE.read_text(encoding="utf-8")
        for name in ["RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_NOFILE", "RLIMIT_FSIZE", "RLIMIT_CORE"]:
            self.assertIn(name, source)
        tree = ast.parse(source)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_main")
        nodes = list(ast.walk(main))
        calls = [node for node in nodes if isinstance(node, ast.Call)]
        caps = [
            node.lineno
            for node in calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == "setrlimit"
        ]
        workers = [
            node.lineno
            for node in calls
            if isinstance(node.func, ast.Name) and node.func.id in {"_prepare_worker", "_verify_worker"}
        ]
        self.assertEqual(len(caps), 5)
        self.assertEqual(len(workers), 2)
        self.assertLess(max(caps), min(workers))

    def test_source_manifest_matches_catalog(self):
        manifest = json.loads((SOURCE.parents[1] / "docs" / "demo_sources.json").read_text(encoding="utf-8"))
        for row in demo.get_demo_catalog():
            record = manifest["artifacts"][row["demo_id"]]
            for key in ["sha256", "revision", "size_bytes", "repository", "filename"]:
                self.assertEqual(record[key], row[key])


if __name__ == "__main__":
    unittest.main()
