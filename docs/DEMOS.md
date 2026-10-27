# Pinned public research demos

These are **actual publicly released small image classifiers**, not generated substitutes. This module never trains or constructs attack models. It reproduces a known image trigger on a public test dataset to demonstrate one tightly scoped behavioral check, not universal backdoor detection. Static scanning remains independent and never calls this preparation loader or performs inference.

## Fixed catalog and filesystem contract

`get_demo_catalog()` is metadata-only and imports no torch or downloaded code. Its only IDs are:

- `mnist-epoch01`: Authentrics published preceding epoch-1 checkpoint. **Not** a separately trained final pristine control.
- `mnist-epoch02`: Authentrics published poisoned epoch-2 checkpoint.
- `cifar10-resnet18`: Hugo0076 published BadNets ResNet-18; trigger geometry not sufficiently documented for a measured behavioral claim.

Both APIs accept the **demo directory itself**, e.g. `root = storage.data_root() / 'demo'`. They require `config={'opt_in': True}`. CLI defaults to `data/demo`; deployments should supply their configured root explicitly.

```
<configured-data-root>/demo/
  mnist-epoch01/
    epoch_01.pt              # original pinned input; preparation only
    model.safetensors        # validated deterministic F32 export
    manifest.json
    verification.json
  mnist-epoch02/
    epoch_02.pt
    model.safetensors
    manifest.json
    verification.json
  cifar10-resnet18/
    model.safetensors        # original publisher file, unmodified
    manifest.json
    verification.json       # not_verified, not a made-up ASR
  mnist-test/
    t10k-images-idx3-ubyte.gz
    t10k-labels-idx1-ubyte.gz
```

Catalog entries include `artifact_relative_path`, `manifest_relative_path`, and `verification_relative_path`, all fixed ID/name combinations. Manifest `sha256` identifies the prepared artifact; catalog `sha256` identifies the original source. Use fixed root/ID/name paths for UI reads: `artifact_path` in the preparation manifest is advisory and may reflect the machine where it was prepared. Do not use it as an arbitrary filesystem selector.

The UI should display prepared results only. It must not initiate downloads, checkpoint deserialization, inference, or arbitrary model code execution.

## Explicit preparation and offline verification

Run in an environment with trusted installed CPU `torch` and `safetensors`; trusted installed `transformers` is additionally needed for ResNet architecture validation. No Authentrics SDK, API, credentials, downloaded repository import, or training is needed.

```bash
python scripts/prepare_demos.py --opt-in --root data/demo \
  --demo-id mnist-epoch01 --demo-id mnist-epoch02 --download-test-data
python scripts/prepare_demos.py --opt-in --root data/demo \
  --demo-id cifar10-resnet18
python scripts/validate_demos.py --opt-in --root data/demo \
  --demo-id mnist-epoch01 --demo-id mnist-epoch02 --demo-id cifar10-resnet18
```

For the deployment default root, substitute `--root data/runtime/demo`. The preparation command is the only online acquisition operation; `--download-test-data` explicitly retrieves **only the MNIST test files**, never the training set. Existing source artifacts must match their pinned size and SHA256; mismatch fails instead of replacing a suspicious file. Interrupted `.download`, `.converting`, or `.json.tmp` files may require explicit operator cleanup after inspection.

`verify_behavior()` never downloads files. Missing packages/data/manifests produce unavailable/failed states, never a false clean finding. `--samples 10000` defaults to the full canonical test set; smaller values select the first N records in fixed public test order and are labeled accordingly. This is not random sampling or a new independent test collection.

## Reviewed architecture, trigger, and metric

Reviewed source is `Authentrics-ai/trojai-authentrics-demo` at commit `86feb8f8cf416286e6cae0791bc73713d20ddc5c`:

- `demo/architecture.py`: input `N×1×28×28`; conv kernels 1,5,5 with channels 1→6→16→120; ReLU and two 2×2 max-pools; fully connected 120→84→10 with log-softmax.
- `demo/trojai_attack.py`: reverse-lambda mask at top-left coordinate (24,24), **not** a filled 3×3 white square. White pixels are exactly `(24,26), (25,25), (26,24), (26,26)` in zero-based (row,column) coordinates. Every other pixel is unchanged.
- `demo/training_utils.py`: `ToTensor` MNIST input scaled to [0,1], no additional normalization. Trigger white value is 1.0 in this space.

The small architecture is implemented locally from the reviewed topology, not imported from the downloaded source. Source text snapshots and Apache-2.0 license/NOTICE are retained in `data/demo/review/` for review and attribution. Original upstream architecture and trigger definitions derive from TrojAI (Apache-2.0). No SDK pipeline or training code is executed.

Measured clean accuracy is `count(clean_prediction == true_label)/N`. Measured shifted-label attack success is `count(triggered_prediction == (true_label+1)%10)/N`, across **all** N images. Target labels differ from true labels for every image. The test processes clean and triggered batches separately on CPU under inference mode, batch size 256, two torch threads. It independently recounts both headline numerators using Python lists before serializing the result.

## Measured reproduction

The following table is generated from actual `data/demo/<id>/verification.json` evidence, not copied from the publisher model card. Both checkpoints use the same full canonical MNIST test set and the fixed source-documented trigger; there was no trigger search, calibration tuning, or held-out confirmation selection.

| Checkpoint | N | Clean correct | Shifted-label trigger hits | Inference | Worker duration |
|---|---:|---:|---:|---:|---:|
| mnist-epoch01 | 10,000 | 9,431 / 10,000 (94.31%) | 41 / 10,000 (0.41%) | 1.012 s | 2.295 s |
| mnist-epoch02 | 10,000 | 9,664 / 10,000 (96.64%) | 9,489 / 10,000 (94.89%) | 1.054 s | 2.262 s |

`duration_seconds` covers worker verification from its function entry, including dependency imports, artifact validation and input loading, but excludes interpreter startup/parent subprocess overhead. `inference_seconds` measures just the batched clean+triggered forward passes. Wall times are machine-dependent, not a latency guarantee. Evidence records CPU device, torch version, dataset hashes, sample count, numerator counts, trigger pixels and artifact hashes.

The observed rates reproduce the author-reported epoch-1/epoch-2 rates, but author metrics remain explicitly separate under `author_metrics`. Epoch 1 is a preceding checkpoint, not evidence that a final model was ever pristine. A successful reproduction is evidence for this known-trigger behavior of these exact files; it says nothing about unknown triggers or safety of another artifact.

## Hashes and provenance

Full pinned source URLs, revisions, bytes, SHA256 values, reviewed source hashes, dataset hashes, converted export hashes and measured results are in `docs/demo_sources.json`.

| Artifact | SHA256 |
|---|---|
| mnist-epoch01 source | `6c0b5fe0c5f794678020292d2184b84029527e3fff86a62a3571dacb75ae117d` |
| mnist-epoch01 F32 export | `88ebce334a81ad59fe59dc809165f25ba2ff3520bfd3701ba644dfe1720a78bf` |
| mnist-epoch02 source | `ded215b9d3583d7e386e47680345b5be32a8400fe190cb6fb758b4dca8a092db` |
| mnist-epoch02 F32 export | `6d33d1dcfe4a81ad0b0636bec59e724b748c6e9b61db1d6e2d0c67e090da8d19` |
| cifar10-resnet18 source | `f8389e3312359d4db7d6cbd7a999e3bc9213092d7abb2ce002f3ea88fc79e161` |

MNIST original files are each 250,453 bytes; exported files are each 247,016 bytes with ten F32 tensors. The ResNet publisher artifact is 44,780,752 bytes and contains **102 F32 tensors plus 20 I64 scalar batch-normalization counters**. It is not cast or rewritten; F32-only statistical analysis should report skipped counters, not silently convert them.

Sources:

- https://huggingface.co/authentrics/mnist-badnets-poisoned/tree/42b52757ec703365710e27865c8fe57e9db35a4d
- https://github.com/Authentrics-ai/trojai-authentrics-demo/tree/86feb8f8cf416286e6cae0791bc73713d20ddc5c
- https://huggingface.co/hugo0076/cifar10-badnets-backdoor-resnet18/tree/b68ac7c29824b0eef7d38176eb5e19cfde20c4c6
- https://ossci-datasets.s3.amazonaws.com/mnist/t10k-images-idx3-ubyte.gz
- https://ossci-datasets.s3.amazonaws.com/mnist/t10k-labels-idx1-ubyte.gz

MNIST artifacts/source declare Apache-2.0. The CIFAR publisher declares MIT, while its named `microsoft/resnet-18` base model card declares Apache-2.0 (reviewed 2026-10-26, snapshot in review directory). Preserve attribution and review inherited obligations before redistributing; the publisher license tag is not a legal determination about the entire lineage. The reviewed snapshots are not executed.

## ResNet limitations — deliberate not_verified result

The trusted installed `ResNetConfig` and `ResNetForImageClassification` implementation validates exact state-dictionary keys, tensor shapes, dtypes and finite floating values. No Auto class, remote custom code, `trust_remote_code`, or downloaded Python is used. If that installed implementation is unavailable, the architecture/behavior result explicitly says unavailable.

The model card supplies only “white square trigger”, target 0 (airplane), and author-reported 81.40% clean accuracy / 81.90% attack success on 10,000 images. It does not specify exact patch position, size, insertion stage, or complete matching evaluation pipeline. The included preprocessor configuration alone does not resolve those gaps. Therefore this implementation performs **no trigger search or CIFAR inference**, reports `status='not_verified'`, and never presents author-reported figures as measurements. Any future exploratory search must be limited to a calibration split and separately confirmed on held-out samples before a reproducibility claim.

## Security boundaries and checks

- Default scanning never calls demo preparation/behavior, `torch.load`, or pickle.
- Exactly two pinned `.pt` inputs can be deserialized, **only in explicit preparation subprocesses** using `torch.load(..., map_location='cpu', weights_only=True)` after size+hash validation. No allowlist-global additions, no fallback unsafe loader, no custom-object acceptance.
- Loaded objects must be exact plain dictionaries/OrderedDicts of exact torch Tensor objects with expected keys/shapes/dtypes and finite F32 weights. Local reviewed architecture must load them strictly before safetensors export.
- Deterministic exported hashes are pinned in application code. Editing a local manifest to bless tampered weights cannot bypass that check. Runtime behavior reads safetensors only.
- Root and child symlinks are rejected. Unknown catalog IDs and missing explicit opt-in are rejected before acquisition or loading. Hashes and size limits apply to downloads; MNIST gzip and IDX lengths/magic/dimensions/labels are validated.
- Worker launch uses the current interpreter in isolated mode (`-I`), fixed script/arguments, no shell and a new process session. Nonblocking selector-driven drains share a strict **64 KiB combined stdout/stderr budget**, checked before accumulating each chunk; no `capture_output`/unbounded `communicate` allocation occurs. Output overflow or wall deadline kills the whole process group; descendants are also cleaned up on ordinary completion. Worker limits are installed before model-library imports: **8 GiB address space**, **180/185-second soft/hard CPU budget**, **128 open file descriptors**, **128 MiB output-file size**, and **zero core dump size**. Required limit-setting failures fail closed. Offline HF flags and CPU thread/device settings are set.
- Workers deny Python socket connections, address resolution and datagram/message sends. **This is application-layer network denial, not an OS/container sandbox claim.** Only trusted installed libraries and fixed reviewed code run; uploaded code is never executed. For a hostile multi-tenant deployment, add an OS network namespace/seccomp/container boundary rather than treating Python monkeypatching as comprehensive isolation.

Tests: `python -m pytest -q tests/test_demo*.py`. Dependency-light security tests cover fixed catalog, unknown IDs, opt-in, symlink paths, pinned hashes, manifest tampering, isolated/no-shell worker launch, real combined-pipe output overflow, wall-time termination/process-group cleanup, normal/abnormal exits, resource-cap presence, and AST enforcement of the sole preparation-only restricted torch loader. Optional CPU tests cover reviewed topology, invalid/custom state dictionaries and a tampered checkpoint failing before the torch loader is called.

### Post-QA hardening validation

The worker hardening passed **16 CPU demo tests** and explicit preparation plus 100-sample verification API calls for both MNIST checkpoints under the new limits. The fixed first-100 sample smoke results were epoch 1: 95/100 clean correct and 0/100 shifted-label trigger hits; epoch 2: 98/100 clean correct and 97/100 shifted-label trigger hits. These are smoke-test subsets, not replacements for the full-set measurements. Smoke outputs live under `data/demo/hardening-smoke/` on the CPU validation host (JSON evidence also copied locally); these deliberately do not overwrite the authoritative full-10,000-image evidence above.
