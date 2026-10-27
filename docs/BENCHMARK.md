# Real-weight exploratory controlled-byte benchmark

This preparation uses **three actual published weight sources**, not synthetic
feature vectors: the preceding MNIST epoch-01 checkpoint, the published CIFAR
ResNet-18 backdoor checkpoint, and pinned Google MobileNet V2 weights. Each
source ancestry is one indivisible group. Epoch-02 is deliberately excluded,
not counted as a second independent MNIST model.

**The target is added harmless low-mantissa-byte manipulation. Label 0 means
NO ADDED BENCHMARK PAYLOAD, not safe, trusted, clean, or backdoor-free.** The
ResNet source is explicitly published as backdoored, and the MNIST checkpoint
comes from backdoor-training material. Their original behavioral properties
are unrelated to the added-byte label and are not assessed by this benchmark.

## Reproducible preparation

Run explicitly on the CPU dependency environment; default app data root is
`data/runtime`. Preparation refuses an existing benchmark or detector directory
to preserve evidence and avoid accidental test-set reuse.

```bash
export STEGOGATE_DATA_DIR="$PWD/data/runtime"
.venv/bin/python scripts/build_benchmark.py --fetch-mobilenet
```

The existing MNIST/ResNet demo preparation must already have completed. No
`.pt`, pickle, joblib, model code, or uploaded executable is loaded by this
script. Pinned MobileNet metadata and safetensors are fetched only with explicit
`--fetch-mobilenet`; scans and RF inference remain offline. No model inference
is run. MobileNet source metadata declares license `other`; review upstream
terms before redistributing weights. Upstream revision, LFS SHA256, and byte
size must match hardcoded identities; existing demo conversion identity is
also checked exactly. Source artifacts are capped at 256 MiB.

For each source the script writes three scanable safetensors variants:

- `no_added_payload`: exact original bytes, identical SHA256.
- `text`: repeating clearly harmless ASCII demonstration phrase replaces the
  lowest eight mantissa bits of every F32 element.
- `seeded_random`: seeded random byte values replace the same low bits. These
  bytes are **random, not encrypted**, and contain no program or malware.

The sign, exponent, higher mantissa bits, non-F32 tensors, header and structure
are preserved. A bitwise invariant is verified during mutation. Low-bit
modification does **not** establish behavioral equivalence; none is claimed.
Natural weight LSBs can already resemble random bytes, so random-payload
misses are a meaningful expected limitation, not a reason to tune the test.

Feature extraction uses the same scanner as production (up to 128 deterministic
windows, 4096 elements/window, minimum 32); only its numeric 19-feature mapping
enters training. Names/positions, source identifiers and variant names remain
metadata. `rows.jsonl` contains training rows; `row_provenance.jsonl` separately
maps them to tensor windows/artifacts for audit. The benchmark manifest records
source hashes, coverage, labels, exact mutation settings, feature profile,
row-count checks, evaluation and artifact summaries.

## Predeclared experiment and uncertainty

Before reading metrics the code fixes seed 42, 64 trees, depth 10, minimum leaf
2, balanced class weights, single CPU worker and threshold 0.5. Threshold
selection is `fixed`; no tuning, split retries, source/variant filtering or
performance cherry-picking is performed. Whole-lineage SHA256 splitting gives
one source each to training, validation and test. All windows, control and
modified variants of a source stay together. Validation/test metrics are
computed only after fitting; test results cannot influence the model.

**ONLY THREE INDEPENDENT CHECKPOINTS**: this is a working mechanics demo, not
evidence of generalization to arbitrary models, payloads or malware. Counts of
windows and derived files do not increase the independent checkpoint count.
Ancestry independence is inferred from distinct architectures/source
repositories, not proven absence of every shared influence. Each holdout
contains exactly one lineage, so no meaningful lineage-level confidence
interval can be estimated.

The artifact summaries use the predeclared mean window vote and threshold 0.5
per derived file. The three files in a holdout are correlated variants of the
same source, **not three independent models**. Window confusion matrices,
precision/recall/F1 and ROC-AUC are descriptive only. Undefined values stay
`null` with reasons. Validation is diagnostic, not a tuning loop. Artifact
summaries are audit re-scoring with the already locked model, never additional
training or model selection; train summaries are resubstitution. Source family,
original quantization and training history may drive behavior; this tiny
benchmark cannot disentangle those factors.

## Outputs and inspection

- `data/runtime/benchmark/benchmark_manifest.json`: single computed evidence
  object, provenance, manifest, audit profile and descriptive evaluations.
- `data/runtime/benchmark/rows.jsonl` and `row_provenance.jsonl`.
- `data/runtime/benchmark/<lineage>/*.safetensors`: nine prepared scanable files.
- `data/runtime/benchmark/sources/`: pinned MobileNet source and metadata.
- `data/runtime/detector/detector.json` and `detector_manifest.json`: trained
  data-only RF tree artifact plus split/feature/evaluation manifest.

The parent review must occur before exposing these variants in the dashboard.
Never replace labels with "safe/malicious" or present votes as calibrated
malware/backdoor probability. No expected metric or success result is hardcoded;
actual measurements live in the generated evidence object, including failures.
