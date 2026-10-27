"""Synthetic fixtures exercise mechanics only, never real efficacy claims."""

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from stegogate import ml
from scripts.train_detector import load_rows


def training_fixture(lineages=12, per_class=12):
    """Controlled numeric signal; all variants/windows share their lineage."""
    rng = random.Random(71)
    return [
        {
            "lineage": f"independent-base-{g}",
            "variant": f"control-or-manipulated-{label}",
            "label": label,
            "features": {"low_bit_bias": label + rng.uniform(-0.1, 0.1), "entropy": rng.random()},
        }
        for g in range(lineages)
        for label in (0, 1)
        for _ in range(per_class)
    ]


class MLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"STEGOGATE_DATA_DIR": str(self.root)})
        self.env.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.env.stop)

    def artifact(self):
        directory = self.root / "manual"
        directory.mkdir()
        # A hand-authored valid tree checks safe inference without sklearn.
        tree = {
            "left": [1, -1, -1],
            "right": [2, -1, -1],
            "feature": [0, -2, -2],
            "threshold": [0.5, -2.0, -2.0],
            "positive_fraction": [0.5, 0.0, 1.0],
        }
        model = {"schema_version": ml.SCHEMA, "classes": [0, 1], "feature_names": ["bias"], "trees": [tree]}
        self.write_model(directory, model)
        return directory, model

    def write_model(self, directory, model):
        raw = json.dumps(model).encode()
        (directory / "detector.json").write_bytes(raw)
        (directory / "detector_manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": ml.SCHEMA,
                    "feature_names": model["feature_names"],
                    "detector_sha256": hashlib.sha256(raw).hexdigest(),
                    "threshold": 0.5,
                }
            )
        )

    def window(self, value=0.75):
        return {"tensor": "layer.weight", "window_index": 0, "features": {"bias": value}}

    def test_missing_artifact(self):
        self.assertEqual(ml.score_windows([])["status"], "not_available")
        self.assertEqual(
            ml.score_windows([], self.root / "missing" / "detector.json")["status"], "not_available"
        )

    def test_group_disjointness_and_determinism(self):
        rows = training_fixture()
        a = ml._partition([r["lineage"] for r in rows], 42)
        b = ml._partition([r["lineage"] for r in reversed(rows)], 42)
        self.assertEqual(a, b)
        self.assertFalse(set(a["train"]) & set(a["validation"]))
        self.assertFalse(set(a["test"]) & set(a["validation"]))
        self.assertFalse(set(a["test"]) & set(a["train"]))
        self.assertEqual(set().union(*map(set, a.values())), {r["lineage"] for r in rows})

    def test_insufficient_lineages(self):
        for n in (1, 2):
            with self.assertRaisesRegex(ValueError, "at least 3"):
                ml.train_detector(training_fixture(n), self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_single_class_rejected_before_dependencies(self):
        rows = [r for r in training_fixture() if r["label"] == 0]
        with self.assertRaisesRegex(ValueError, "both classes"):
            ml.train_detector(rows, self.root / "output")

    def test_honest_labels(self):
        rows = training_fixture()
        rows[0]["label"] = "modelA"
        with self.assertRaisesRegex(ValueError, "label"):
            ml.train_detector(rows, self.root / "output")

    def test_safe_prediction(self):
        directory, _ = self.artifact()
        result = ml.score_windows([self.window(0.25), self.window(0.75)], directory)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([s["score"] for s in result["scores"]], [0.0, 1.0])
        self.assertEqual(result["scores"][0]["score_type"], ml.SCORE_TYPE)

    def test_missing_or_extra_features_fail_all_windows(self):
        directory, _ = self.artifact()
        for features in ({}, {"bias": 1, "unseen": 2}, {"renamed": 1}):
            result = ml.score_windows([self.window(), {**self.window(), "features": features}], directory)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["scores"], [])

    def test_nonfinite_nonnumeric_and_shape_rejected(self):
        directory, _ = self.artifact()
        for value in (math.nan, math.inf, -math.inf, 1e100, "0.8", [0.8], True, None):
            self.assertEqual(ml.score_windows([self.window(value)], directory)["status"], "failed")

    def test_malformed_topology_and_dimensions(self):
        directory, model = self.artifact()
        for field, values in (
            ("left", [0, -1, -1]),
            ("right", [2]),
            ("feature", [22, -2, -2]),
            ("positive_fraction", [0.5, 0, 1.01]),
            ("threshold", [math.nan, -2, -2]),
        ):
            old = model["trees"][0][field]
            model["trees"][0][field] = values
            self.write_model(directory, model)
            self.assertEqual(ml.score_windows([self.window()], directory)["status"], "failed", field)
            model["trees"][0][field] = old

    def test_corrupt_hash_missing_manifest_and_duplicate_json(self):
        directory, model = self.artifact()
        (directory / "detector.json").write_text('{"schema_version":"bad","schema_version":"duplicate"}')
        self.assertEqual(ml.score_windows([], directory)["status"], "failed")
        self.write_model(directory, model)
        (directory / "detector.json").write_text(json.dumps({**model, "extra": 1}))
        self.assertEqual(ml.score_windows([], directory)["status"], "failed")
        (directory / "detector_manifest.json").unlink()
        self.assertEqual(ml.score_windows([], directory)["status"], "not_available")

    def test_path_outside_app_storage_fails(self):
        self.assertEqual(ml.score_windows([], self.root.parent / "detector.json")["status"], "failed")
        with self.assertRaisesRegex(ValueError, "app-owned"):
            ml.train_detector(training_fixture(), self.root.parent / "not-owned")

    def test_training_schema_derived_from_train_only(self):
        rows = training_fixture()
        test_ids = ml._partition([r["lineage"] for r in rows], 42)["test"]
        for row in rows:
            if row["lineage"] in test_ids:
                row["features"]["test_only"] = 1
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            ml.train_detector(rows, self.root / "output")

    def test_recorded_threshold_used_and_invalid_threshold_fails(self):
        directory, _ = self.artifact()
        path = directory / "detector_manifest.json"
        manifest = json.loads(path.read_text())
        # Leaf vote is 1.0: strict positive class includes equality at threshold.
        manifest["threshold"] = 1.0
        path.write_text(json.dumps(manifest))
        row = ml.score_windows([self.window()], directory)["scores"][0]
        self.assertEqual(row["threshold"], 1.0)
        self.assertEqual(row["predicted_label"], 1)
        for bad in (None, True, -0.01, 1.01, "0.5"):
            manifest["threshold"] = bad
            path.write_text(json.dumps(manifest))
            self.assertEqual(ml.score_windows([self.window()], directory)["status"], "failed")

    @unittest.skipUnless(
        importlib.util.find_spec("sklearn"), "scikit-learn is installed by parent on test VM"
    )
    def test_validation_only_threshold_and_single_class_fallback(self):
        threshold, selection = ml._choose_threshold([0, 0, 1, 1], [0.1, 0.2, 0.3, 0.4], "validation_f1")
        self.assertEqual(threshold, 0.3)
        self.assertEqual(selection["data_partition"], "validation")
        self.assertEqual(selection["validation_selection_f1"], 1.0)
        threshold, selection = ml._choose_threshold([0, 0], [0.1, 0.2], "validation_f1")
        self.assertEqual(threshold, 0.5)
        self.assertIn("single-class", selection["reason"])
        threshold, selection = ml._choose_threshold([0, 1], [0.1, 0.2], "fixed")
        self.assertEqual(threshold, 0.5)
        self.assertIsNone(selection["data_partition"])

    def test_cli_input_parsing(self):
        for suffix in ("json", "jsonl"):
            path = self.root / ("input." + suffix)
            rows = training_fixture(3, 1)
            path.write_text(json.dumps(rows) if suffix == "json" else "\n".join(map(json.dumps, rows)))
            self.assertEqual(load_rows(path), rows)
        path.write_text('{"label":0,"label":1}\n')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_rows(path)
        path.write_text('{"features":{"x":NaN}}\n')
        with self.assertRaisesRegex(ValueError, "non-finite"):
            load_rows(path)

    @unittest.skipUnless(
        importlib.util.find_spec("sklearn"), "scikit-learn is installed by parent on test VM"
    )
    def test_train_safe_roundtrip_and_sklearn_parity(self):
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier

        rows = training_fixture()
        result = ml.train_detector(
            rows,
            self.root / "trained",
            {"n_estimators": 8, "max_depth": 4, "threshold_selection": "validation_f1"},
        )
        self.assertEqual(result["status"], "completed")
        manifest = result["manifest"]
        model = json.loads((self.root / "trained" / "detector.json").read_text())
        self.assertEqual(manifest["test_evaluations"], 1)
        self.assertEqual(manifest["threshold_selection"]["data_partition"], "validation")
        self.assertEqual(manifest["evaluation"]["test"]["threshold"], manifest["threshold"])
        self.assertEqual(
            manifest["row_counts"]["test"], sum(r["lineage"] in manifest["split"]["test"] for r in rows)
        )
        names = model["feature_names"]
        train = [r for r in rows if r["lineage"] in manifest["split"]["train"]]
        rf = RandomForestClassifier(**manifest["hyperparameters"])
        rf.fit(
            np.asarray([[r["features"][k] for k in names] for r in train], dtype=np.float32),
            [r["label"] for r in train],
        )
        windows = [
            {"tensor": "fixture", "window_index": i, "features": row["features"]}
            for i, row in enumerate(rows)
        ]
        scored = ml.score_windows(windows, result["detector_path"])
        expected = rf.predict_proba(
            np.asarray([[r["features"][k] for k in names] for r in rows], dtype=np.float32)
        )[:, 1]
        for actual, predicted in zip(scored["scores"], expected):
            self.assertAlmostEqual(actual["score"], predicted, places=12)
            self.assertEqual(actual["predicted_label"], int(predicted >= manifest["threshold"]))
        self.assertTrue(manifest["exploratory"])
        self.assertFalse(list((self.root / "trained").glob("*.pkl")))
        with self.assertRaisesRegex(ValueError, "already exists"):
            ml.train_detector(rows, self.root / "trained")

    @unittest.skipUnless(
        importlib.util.find_spec("sklearn"), "scikit-learn is installed by parent on test VM"
    )
    def test_undefined_metrics_not_fake_zero(self):
        metrics = ml._metrics([0, 0], [0.1, 0.2])
        for key in ("precision", "recall", "f1", "roc_auc"):
            self.assertIsNone(metrics[key])
            self.assertIn(key, metrics["undefined_metrics"])
        metrics = ml._metrics([1, 1], [0.1, 0.2])
        self.assertEqual(metrics["recall"], 0.0)
        self.assertEqual(metrics["f1"], 0.0)
        self.assertIsNone(metrics["precision"])
        self.assertIsNone(metrics["roc_auc"])


if __name__ == "__main__":
    unittest.main()
