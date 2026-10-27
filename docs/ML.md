# Controlled-manipulation detector (exploratory)

This module trains a genuine **CPU scikit-learn RandomForestClassifier** on
numeric window features. The threat modeled is **controlled hidden-byte
manipulation of weights**. It does not identify arbitrary training backdoors,
malware, payload intent, or behavioral compromise. A backdoored model without
these manipulation signatures can score low. Benign distributions can score
high. No trustworthy/safe verdict or combined malware probability is produced.
No trained detector, real performance claim, or synthetic benchmark result is
shipped. Absence of an artifact means **not analyzed**, not no finding.

## Training data contract

Each JSON array element / JSONL line is a row:

```json
{"features":{"bit_bias":0.12,"byte_entropy":7.9},"label":1,"lineage":"independent-source-A","variant":"controlled-lsb-edit"}
```

`label` is integer 0 for an unmodified control, 1 for a controlled hidden-byte
manipulation; **never use model IDs as labels**. `variant` is optional metadata,
not a feature. Feature values must be finite scalar numbers representable as
float32; booleans/strings/vectors/NaNs/infinities fail. All rows must have the
exact feature schema derived from the **training partition only**. Missing or
extra features fail rather than silently imputing or dropping them. A known
list of metadata/position names is rejected as features. Callers must also
exclude custom model-identity/name/absolute-position encodings: arbitrary
numeric names cannot automatically be certified free of identity information.

### Independence and limits

A lineage identifies an independently sourced ancestral model, not a tensor,
window, manipulation version, random seed, renamed file, epoch, or fine-tune.
All checkpoints, derivatives, clean and manipulated variants, and windows from
one ancestry **must share one lineage**. Caller assertions cannot be verified
from numeric rows. Grouping model names instead of shared ancestry leaks data.

The deterministic split sorts unique lineages by SHA256(seed + NUL + lineage),
reserving floor(20%) (at least one) for test, the next floor(20%) (at least one)
for validation, and the remainder for training. It never searches seeds/splits
for better class balance or scores. It runs **before** schema derivation,
preprocessing, or fitting. The manifest lists every group, counts, seed,
hyperparameters, data fingerprint, and resulting evaluations.

**Fewer than three independent lineages are refused outright.** Three is only
a structural minimum, not evidence of statistical adequacy. The training
partition must have both classes; no holdout-driven reseeding is allowed.
Validation/test can be single-class, making some metrics undefined. Fewer than
ten lineages gets a prominent warning; a one-lineage holdout is explicitly
identified. All artifacts remain exploratory regardless of count. Row-level
window metrics are correlated within ancestry and are not independent sample
estimates. Obtain many representative independent ancestries and manipulation
families before drawing generalization conclusions.

There is no fitted normalization, feature selection, resampling, calibration,
or forest-hyperparameter tuning. Fixed defaults are 64 trees, depth 10, min leaf 2, balanced class
weights, sqrt feature sampling, single CPU worker, seed 42, threshold 0.5.
Configuration must be chosen before viewing test results. By default threshold
0.5 is fixed a priori. Optional `--threshold-selection validation_f1` selects a
threshold on validation only, maximizing positive-class F1 with deterministic
ties nearest 0.5 then smaller threshold. Single-class validation refuses tuning
and records a fixed-0.5 fallback. The manifest records selection method,
partition, value, objective and reason. Validation scores used for selection
are optimistic, not an unbiased performance estimate. The threshold is locked
before evaluating test once. Reported validation/test metrics use the actual
JSON inference implementation and the recorded threshold. Do not repeatedly retrain against the same test set; reserve
new untouched lineages after making any design or hyperparameter changes.
The code can record a single evaluation per invocation, not police historical
reuse of externally supplied datasets.

## Commands and app-owned storage

Parent project dependencies must include `numpy` and `scikit-learn` for
training. Inference needs only the Python standard library. No import or
execution of uploaded model code is involved.

```bash
export STEGOGATE_DATA_DIR=/absolute/app-owned/data
python scripts/train_detector.py rows.jsonl "$STEGOGATE_DATA_DIR/detectors/run-001" \
  --source-description 'Describe actual sources, provenance and manipulation recipe'
python -m unittest discover -s tests -p 'test_ml*.py' -v
```

Training requires a **new version directory** under configured app-owned
storage. Default storage matches the app: `data/runtime` under the current working
directory; setting an absolute `STEGOGATE_DATA_DIR` is recommended. Artifacts cannot
be loaded from outside that resolved root, including symlink escapes. The UI
must never let an upload select or overwrite the trusted detector location.
Use a separate detector directory, not an upload directory, with filesystem
write permissions reserved to the operator/app. Hashes detect mismatch, not
authenticity; they do not protect against an actor able to replace both files.
No arbitrary uploaded pickle/joblib is loaded under any circumstances.

CLI input is capped at 64 MiB and 200,000 rows; JSONL lines at 1 MiB. Duplicate
JSON keys and NaN/Infinity constants are rejected. Features are limited to
512 and names to 160 characters. The training matrix is capped at 4 million
feature values. Requested forest capacity is checked against the node budget
before fitting (conservative depth/sample-count upper bound). Output JSON files are capped at 32 MiB,
256 trees, and 250,000 nodes total. Input validation does not prove meaningful
features, valid labels, genuinely independent lineages, or representative data.
The library entry point also validates its row list and numeric shape.

## Safe artifact and inference contract

`train_detector(rows, output_dir, config=None)` returns JSON-safe status,
paths, scope, metrics, warnings, and manifest; invalid training requests raise
`ValueError`, unavailable training dependencies raise `RuntimeError`.
It saves two data-only JSON files:

- `detector.json`: sorted names, class order [0,1], child/feature/threshold
  arrays, and positive-class leaf fractions for every genuine fitted RF tree.
- `detector_manifest.json`: SHA256 of detector bytes, provenance description,
  feature schema, explicit label definitions, whole-lineage partitions, dataset
  fingerprint, sklearn version, fixed parameters, scope, limits, and evaluation.

Runtime parses bounded JSON with duplicate-key/nonfinite rejection, checks the
hash/schema, array sizes, finite values, class fractions, valid feature indices,
rooted topology and acyclicity. Inputs are rounded to float32 to match sklearn
split semantics; overflow fails. No pickle, joblib, dynamic imports from
artifacts, or executable serialization is used. Malformed detectors fail
closed with no partial scores. Storage/version directories are operator-owned;
artifacts are not a generic untrusted serialization format for uploads.

`score_windows(windows, detector_path=None)` returns
`{status, scores, manifest, warnings}`. `None`, or a missing detector/manifest,
returns `not_available`. Bad artifacts, out-of-root paths, wrong features, or
nonfinite inputs return `failed`, empty scores, and a reason. Valid score rows
contain `tensor`, `window_index`, `score`, recorded `threshold`,
`predicted_label` (0/1, not a security verdict), and
`score_type="controlled_manipulation_model_vote"`. The score is the mean
positive-class leaf fraction across fitted RF trees. It is **not calibrated**
and must not be presented as malware or backdoor probability. An empty window
list is valid and produces no findings; the caller must retain coverage limits.

## Evaluation reporting

Validation and test each report true/predicted confusion matrix in [0,1] class
order, class support, row count, precision, recall, F1 and ROC-AUC with the
recorded threshold (default 0.5). ROC-AUC remains threshold independent. Undefined values are JSON `null` with explicit `undefined_metrics` reasons:
precision without positive predictions; recall without actual positives; F1
when neither actual nor predicted positives exist; ROC-AUC without both true
classes. Genuine zero recall/F1 remains zero when mathematically defined.
Do not conflate undefined with zero, or synthetic fixtures with actual evidence.

`tests/test_ml.py::training_fixture` creates synthetic numeric rows solely for
mechanics tests. It is **not** a genuine model-weight feature dataset and must
never be used to claim real security performance. Tests cover lineage separation,
minimum-group guards, single-class training refusal, train-only feature schema,
malformed data-only artifacts, safe inference, missing features/artifacts,
undefined metrics, and sklearn/JSON-inference agreement when sklearn exists.
