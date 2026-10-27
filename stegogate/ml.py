"""Supervised controlled-hidden-byte detector; JSON-only, CPU inference.

This is not an arbitrary backdoor or malware detector. Runtime inference does
not import sklearn, numpy, pickle, torch, or uploaded Python code.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import struct
from typing import Any

SCHEMA = "stegogate-rf-v1"
MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 200_000
MAX_FEATURES = 512
MAX_FEATURE_VALUES = 4_000_000
MAX_TREES = 256
MAX_NODES = 250_000
SCOPE = "Exploratory supervised detection of controlled hidden-byte manipulation, not arbitrary backdoors or malware."
SCORE_TYPE = "controlled_manipulation_model_vote"
# These metadata fields must never become training inputs.
IDENTITY_FEATURES = {
    "lineage",
    "label",
    "variant",
    "model_id",
    "tensor",
    "tensor_name",
    "window_index",
    "element_start",
    "sample_index",
    "model_name",
}


def _root() -> Path:
    return (
        Path(os.environ.get("STEGOGATE_DATA_DIR", str(Path.cwd() / "data" / "runtime")))
        .expanduser()
        .resolve()
    )


def _owned(path: str | Path) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_relative_to(_root()):
        raise ValueError("detector files must be under STEGOGATE_DATA_DIR (app-owned storage)")
    return p


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _read_json(path: Path, max_bytes: int = MAX_BYTES):
    with path.open("rb") as f:
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("JSON artifact exceeds size limit")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant), raw


def _finite(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("features must be finite numeric scalars, not booleans or strings")
    try:
        number = float(value)
        # sklearn's trees consume float32. Match that rounding at inference.
        rounded = struct.unpack("<f", struct.pack("<f", number))[0]
    except (ValueError, TypeError, OverflowError, struct.error):
        raise ValueError("feature outside finite float32 range") from None
    if not math.isfinite(rounded):
        raise ValueError("features must be finite float32 values")
    return rounded


def _feature_names(features: Any) -> list[str]:
    if not isinstance(features, dict) or not 1 <= len(features) <= MAX_FEATURES:
        raise ValueError("features must be a nonempty bounded mapping")
    if any(not isinstance(k, str) or not k or len(k) > 160 for k in features):
        raise ValueError("invalid feature names")
    if set(features) & IDENTITY_FEATURES:
        raise ValueError("identity/position metadata cannot be used as features")
    return sorted(features)


def _vector(features: Any, names: list[str]) -> list[float]:
    if not isinstance(features, dict) or set(features) != set(names):
        raise ValueError("feature schema mismatch: missing or unexpected features")
    return [_finite(features[k]) for k in names]


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


def _partition(lineages: list[str], seed: int) -> dict[str, list[str]]:
    """Split groups before deriving the feature schema or fitting anything."""
    groups = sorted(set(lineages), key=lambda s: (hashlib.sha256(f"{seed}\0{s}".encode()).hexdigest(), s))
    if len(groups) < 3:
        raise ValueError("at least 3 independent lineages required for train/validation/held-out test")
    n_test = max(1, len(groups) // 5)
    n_val = max(1, len(groups) // 5)
    return {
        "train": sorted(groups[n_test + n_val :]),
        "validation": sorted(groups[n_test : n_test + n_val]),
        "test": sorted(groups[:n_test]),
    }


def _metrics(y: list[int], scores: list[float], threshold: float = 0.5) -> dict:
    """Undefined metrics remain null, never a manufactured zero."""
    from sklearn.metrics import roc_auc_score

    predicted = [int(s >= threshold) for s in scores]
    tn = sum(a == 0 and b == 0 for a, b in zip(y, predicted))
    fp = sum(a == 0 and b == 1 for a, b in zip(y, predicted))
    fn = sum(a == 1 and b == 0 for a, b in zip(y, predicted))
    tp = sum(a == 1 and b == 1 for a, b in zip(y, predicted))
    undefined = {}
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    auc = float(roc_auc_score(y, scores)) if len(set(y)) == 2 else None
    if precision is None:
        undefined["precision"] = "no positive predictions"
    if recall is None:
        undefined["recall"] = "no actual positive rows"
    if f1 is None:
        undefined["f1"] = "no actual or predicted positives"
    if auc is None:
        undefined["roc_auc"] = "requires both actual classes"
    return {
        "row_count": len(y),
        "class_support": {"0": y.count(0), "1": y.count(1)},
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "confusion_matrix_axes": "rows=true [0,1], columns=predicted [0,1]",
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": auc,
        "undefined_metrics": undefined,
    }


def _choose_threshold(y: list[int], scores: list[float], method: str) -> tuple[float, dict]:
    """Tune only on validation, never test; deterministic ties nearest 0.5."""
    selection = {"method": method, "data_partition": None, "objective": None, "threshold": 0.5}
    if method == "fixed":
        selection["reason"] = "fixed a priori; no threshold tuning"
        return 0.5, selection
    selection.update(
        data_partition="validation",
        objective="maximize positive-class F1; ties nearest 0.5, then smaller threshold",
    )
    if len(set(y)) != 2:
        selection["reason"] = "single-class validation; tuning refused, fixed 0.5 fallback"
        return 0.5, selection
    from sklearn.metrics import precision_recall_curve

    precision, recall, thresholds = precision_recall_curve(y, scores)
    candidates = []
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        f1 = float(2 * p * r / (p + r)) if p + r else 0.0
        candidates.append((f1, -abs(float(t) - 0.5), -float(t), float(t)))
    tp = sum(a == 1 and b >= 0.5 for a, b in zip(y, scores))
    fp = sum(a == 0 and b >= 0.5 for a, b in zip(y, scores))
    fn = sum(a == 1 and b < 0.5 for a, b in zip(y, scores))
    candidates.append((2 * tp / (2 * tp + fp + fn), 0.0, -0.5, 0.5))
    best = max(candidates)
    selection.update(
        threshold=best[3],
        validation_selection_f1=best[0],
        reason="selected on validation only, locked before test evaluation",
    )
    return best[3], selection


def _validate_detector(model: Any) -> tuple[list[str], list[dict]]:
    if (
        not isinstance(model, dict)
        or model.get("schema_version") != SCHEMA
        or model.get("classes") != [0, 1]
        or any(type(c) is not int for c in model.get("classes", []))
    ):
        raise ValueError("unsupported detector schema/classes")
    names = model.get("feature_names")
    if not isinstance(names, list) or any(not isinstance(k, str) for k in names):
        raise ValueError("invalid detector feature schema")
    if names != _feature_names(dict.fromkeys(names)) or len(set(names)) != len(names):
        raise ValueError("invalid detector feature schema")
    trees = model.get("trees")
    if not isinstance(trees, list) or not 1 <= len(trees) <= MAX_TREES:
        raise ValueError("invalid tree count")
    total = 0
    for tree in trees:
        if not isinstance(tree, dict):
            raise ValueError("invalid tree")
        left, right, feature, threshold, positive = (
            tree.get(k) for k in ("left", "right", "feature", "threshold", "positive_fraction")
        )
        arrays = [left, right, feature, threshold, positive]
        if any(not isinstance(a, list) for a in arrays):
            raise ValueError("invalid tree arrays")
        n = len(left)
        total += n
        if n == 0 or total > MAX_NODES or any(len(a) != n for a in arrays):
            raise ValueError("invalid tree array shape/size")
        parents = [0] * n
        for i in range(n):
            left_child = _integer(left[i], -1, n - 1, "left child")
            right_child = _integer(right[i], -1, n - 1, "right child")
            f = _integer(feature[i], -2, len(names) - 1, "feature index")
            for val in (threshold[i], positive[i]):
                if type(val) not in (int, float) or not math.isfinite(val):
                    raise ValueError("non-finite tree value")
            if not 0 <= positive[i] <= 1:
                raise ValueError("invalid class fraction")
            if left_child == right_child == -1:
                if f != -2:
                    raise ValueError("invalid leaf feature")
            elif left_child <= i or right_child <= i or left_child == right_child or f < 0:
                raise ValueError("invalid tree topology")
            else:
                parents[left_child] += 1
                parents[right_child] += 1
        if parents[0] != 0 or any(p != 1 for p in parents[1:]):
            raise ValueError("tree is disconnected or has shared children")
    return names, trees


def _predict(x: list[float], trees: list[dict]) -> float:
    votes = []
    for tree in trees:
        node = 0
        while tree["left"][node] != -1:
            node = (
                tree["left"][node]
                if x[tree["feature"][node]] <= tree["threshold"][node]
                else tree["right"][node]
            )
        votes.append(tree["positive_fraction"][node])
    return math.fsum(votes) / len(votes)


def _dump(path: Path, value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("serialized detector exceeds size limit")
    # Exclusive creation: a live artifact is never overwritten in place.
    with path.open("xb") as f:
        f.write(raw)
    return raw


def train_detector(rows: list[dict], output_dir: str | Path, config: dict | None = None) -> dict:
    """Fit one fixed RF configuration; evaluate each holdout once; save JSON.

    Raises ValueError for invalid data; no artifact on validation/training error.
    A new output directory under app-owned storage is required.
    """
    config = {} if config is None else config
    allowed = {
        "seed",
        "n_estimators",
        "max_depth",
        "min_samples_leaf",
        "source_description",
        "threshold_selection",
        "lineage_partition",
    }
    if not isinstance(config, dict) or set(config) - allowed:
        raise ValueError("unknown training configuration")
    seed = _integer(config.get("seed", 42), 0, 2**32 - 1, "seed")
    n_trees = _integer(config.get("n_estimators", 64), 1, MAX_TREES, "n_estimators")
    depth = _integer(config.get("max_depth", 10), 1, 16, "max_depth")
    leaf = _integer(config.get("min_samples_leaf", 2), 1, MAX_ROWS, "min_samples_leaf")
    source = config.get(
        "source_description",
        "Caller-supplied controlled-manipulation rows; provenance not independently verified.",
    )
    if not isinstance(source, str) or not 1 <= len(source) <= 4000:
        raise ValueError("invalid source_description")
    selection_method = config.get("threshold_selection", "fixed")
    if selection_method not in ("fixed", "validation_f1"):
        raise ValueError("threshold_selection must be fixed or validation_f1")
    out = _owned(output_dir)
    if out.exists():
        raise ValueError("output directory already exists; use a new app-owned version directory")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
        raise ValueError("rows must be a bounded nonempty list")
    for row in rows:
        if not isinstance(row, dict) or type(row.get("label")) is not int or row["label"] not in (0, 1):
            raise ValueError(
                "label must be integer 0 (control) or 1 (controlled manipulation), never a model ID"
            )
        if set(row) - {"features", "label", "lineage", "variant"}:
            raise ValueError("unknown training row fields")
        lineage = row.get("lineage")
        if not isinstance(lineage, str) or not lineage.strip() or len(lineage) > 256:
            raise ValueError("every row requires a nonempty bounded independent-lineage ID")
        if "variant" in row and (not isinstance(row["variant"], str) or len(row["variant"]) > 256):
            raise ValueError("invalid variant")
    split = _partition([r["lineage"] for r in rows], seed)
    if "lineage_partition" in config:
        explicit = config["lineage_partition"]
        if not isinstance(explicit, dict) or set(explicit) != {"train", "validation", "test"}:
            raise ValueError("invalid explicit lineage partition")
        flat = []
        for groups in explicit.values():
            if not isinstance(groups, list) or not groups or any(not isinstance(g, str) for g in groups):
                raise ValueError("empty or invalid lineage partition")
            flat.extend(groups)
        if len(flat) != len(set(flat)) or set(flat) != {r["lineage"] for r in rows}:
            raise ValueError("lineage partition must be disjoint and exhaustive")
        split = {k: sorted(v) for k, v in explicit.items()}
    group_sets = {k: set(groups) for k, groups in split.items()}
    buckets = {k: [r for r in rows if r["lineage"] in groups] for k, groups in group_sets.items()}
    if {r["label"] for r in buckets["train"]} != {0, 1}:
        raise ValueError(
            "training partition must contain both classes; collect more independent lineages (no holdout-driven reseeding)"
        )
    # The schema is derived ONLY from training, never the union of all rows.
    names = _feature_names(buckets["train"][0].get("features"))
    if len(rows) * len(names) > MAX_FEATURE_VALUES:
        raise ValueError("training matrix exceeds bounded feature-value budget")
    maximum_nodes_per_tree = min(2 ** (depth + 1) - 1, 2 * len(buckets["train"]) - 1)
    if n_trees * maximum_nodes_per_tree > MAX_NODES:
        raise ValueError(
            "requested forest capacity exceeds node budget; reduce trees/depth before evaluation"
        )
    vectors = {k: [_vector(r.get("features"), names) for r in group] for k, group in buckets.items()}
    labels = {k: [r["label"] for r in group] for k, group in buckets.items()}
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        import sklearn
    except ImportError as e:
        raise RuntimeError("training requires numpy and scikit-learn; runtime JSON inference does not") from e
    # No learned preprocessing, resampling, tuning, or test-based selection.
    model = RandomForestClassifier(
        n_estimators=n_trees,
        max_depth=depth,
        min_samples_leaf=leaf,
        random_state=seed,
        n_jobs=1,
        class_weight="balanced",
        max_features="sqrt",
    )
    model.fit(np.asarray(vectors["train"], dtype=np.float32), labels["train"])
    trees = []
    for estimator in model.estimators_:
        t = estimator.tree_
        values = t.value[:, 0, :]
        fractions = values[:, 1] / values.sum(axis=1)
        trees.append(
            {
                "left": t.children_left.tolist(),
                "right": t.children_right.tolist(),
                "feature": t.feature.tolist(),
                "threshold": t.threshold.tolist(),
                "positive_fraction": fractions.tolist(),
            }
        )
    detector = {
        "schema_version": SCHEMA,
        "feature_names": names,
        "classes": [0, 1],
        "score_type": SCORE_TYPE,
        "trees": trees,
    }
    _validate_detector(detector)
    # Evaluate the actual serialized inference implementation, once per holdout.
    validation_scores = [_predict(x, trees) for x in vectors["validation"]]
    threshold, threshold_selection = _choose_threshold(
        labels["validation"], validation_scores, selection_method
    )
    metrics = {"validation": _metrics(labels["validation"], validation_scores, threshold)}
    # Threshold is now locked; the test partition is consulted exactly once.
    metrics["test"] = _metrics(labels["test"], [_predict(x, trees) for x in vectors["test"]], threshold)
    warnings = [
        SCOPE,
        "Lineage independence is caller-asserted, not automatically proven.",
        "Window-level metrics are correlated within lineage; no confidence intervals or population-generalization claims.",
        "Forest hyperparameters fixed before holdout evaluation; threshold selection is recorded in manifest.",
    ]
    if len(set(r["lineage"] for r in rows)) < 10:
        warnings.append(
            "LOW LINEAGE COUNT: fewer than 10 independent lineages; held-out metrics are highly unstable and cannot establish generalization."
        )
    if any(len({r["lineage"] for r in buckets[k]}) < 2 for k in ("validation", "test")):
        warnings.append("At least one holdout has only one lineage; it measures that lineage only.")
    canonical = json.dumps(
        sorted(rows, key=lambda r: json.dumps(r, sort_keys=True, allow_nan=False)),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    manifest = {
        "schema_version": SCHEMA,
        "scope": SCOPE,
        "exploratory": True,
        "source_description": source,
        "label_definitions": {"0": "unmodified control", "1": "controlled hidden-byte manipulation"},
        "feature_names": names,
        "score_type": SCORE_TYPE,
        "score_semantics": "Mean positive-class leaf fraction across random-forest trees; not calibrated, not a malware/backdoor probability.",
        "split": split,
        "split_method": "caller predeclared disjoint exhaustive whole-lineage partition"
        if "lineage_partition" in config
        else "SHA256(seed + NUL + lineage), 20% test, 20% validation (floor; minimum one each), remainder training; whole lineages only",
        "split_seed": seed,
        "row_counts": {k: len(v) for k, v in buckets.items()},
        "lineage_counts": {k: len(v) for k, v in split.items()},
        "training_rows_sha256": hashlib.sha256(canonical).hexdigest(),
        "hyperparameters": {
            "n_estimators": n_trees,
            "max_depth": depth,
            "min_samples_leaf": leaf,
            "n_jobs": 1,
            "class_weight": "balanced",
            "max_features": "sqrt",
            "random_state": seed,
        },
        "sklearn_version": sklearn.__version__,
        "evaluation": metrics,
        "warnings": warnings,
        "test_evaluations": 1,
        "threshold": threshold,
        "threshold_selection": threshold_selection,
    }
    # Construct bytes before creating the directory to avoid validation debris.
    detector_raw = json.dumps(detector, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(detector_raw) > MAX_BYTES:
        raise ValueError("serialized detector exceeds size limit")
    manifest["detector_sha256"] = hashlib.sha256(detector_raw).hexdigest()
    if len(json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) > MAX_BYTES:
        raise ValueError("serialized manifest exceeds size limit")
    out.mkdir(parents=True, exist_ok=False)
    _dump(out / "detector.json", detector)
    _dump(out / "detector_manifest.json", manifest)
    return {
        "status": "completed",
        "detector_path": str(out / "detector.json"),
        "manifest_path": str(out / "detector_manifest.json"),
        "metrics": metrics,
        "scope": SCOPE,
        "manifest": manifest,
        "warnings": warnings,
    }


def score_windows(windows: list[dict], detector_path: str | Path | None = None) -> dict:
    result = {"status": "not_available", "scores": [], "manifest": {}, "warnings": []}
    if detector_path is None:
        result["warnings"] = ["No controlled-manipulation detector configured; not analyzed."]
        return result
    try:
        path = _owned(detector_path)
        if path.is_dir():
            path = path / "detector.json"
        if path.name != "detector.json":
            raise ValueError("expected app-owned detector.json")
        manifest_path = _owned(path.with_name("detector_manifest.json"))
        if not path.is_file() or not manifest_path.is_file():
            result["warnings"] = ["Detector artifact or manifest missing; not analyzed."]
            return result
        detector, raw = _read_json(path)
        manifest, _ = _read_json(manifest_path)
        names, trees = _validate_detector(detector)
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != SCHEMA
            or manifest.get("feature_names") != names
            or manifest.get("detector_sha256") != hashlib.sha256(raw).hexdigest()
        ):
            raise ValueError("detector manifest/schema/hash mismatch")
        threshold = manifest.get("threshold")
        if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("invalid recorded threshold")
        if not isinstance(windows, list) or len(windows) > MAX_ROWS:
            raise ValueError("windows must be a bounded list")
        scores = []
        for row in windows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("tensor"), str)
                or len(row["tensor"]) > 4096
            ):
                raise ValueError("invalid tensor identifier")
            idx = _integer(row.get("window_index"), 0, 2**63 - 1, "window_index")
            x = _vector(row.get("features"), names)
            score = _predict(x, trees)
            scores.append(
                {
                    "tensor": row["tensor"],
                    "window_index": idx,
                    "score": score,
                    "score_type": SCORE_TYPE,
                    "threshold": threshold,
                    "predicted_label": int(score >= threshold),
                }
            )
        return {
            "status": "completed",
            "scores": scores,
            "manifest": manifest,
            "warnings": [SCOPE, "Model vote is not a calibrated probability of malware or a backdoor."],
        }
    except (ValueError, TypeError, OSError, OverflowError, RecursionError) as e:
        # Never return partially scored data as a successful assessment.
        return {
            "status": "failed",
            "scores": [],
            "manifest": {},
            "warnings": [f"Detector scoring failed safely: {type(e).__name__}: {str(e)[:300]}"],
        }
