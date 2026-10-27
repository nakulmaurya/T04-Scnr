# T04-Scnr CPU v0.3

## Implemented additions

### Independent Picklescan adapter

MIT Picklescan **1.0.5**, wheel SHA256
`2abb3d4959a7ee9ccb1e1296db7c56f624bf6d345b93a0a9cf4185bc650dc2fd`.
Only `scan_pickle_bytes` is used, after a separate bounded syntax pass. No
pickle loading, URL helper, extraction or nested archive scanning is used.
ModelAudit and Picklescan findings stay separate; overlap is not evidence of
independent accuracy gain. Safetensors is explicitly not applicable to Picklescan.

The trusted scanner worker uses the existing mandatory Linux seccomp network and
process restrictions, unsafe-loader/framework guards, a 1 GiB address-space cap,
CPU/wall deadline and 128 KiB shared stdout/stderr cap. Raw/member pickle <=16 MiB,
ZIP pickle total <=32 MiB, <=4096 ZIP entries, compression ratio <=200,
<=250,000 syntax opcodes and <=200 findings. Resource failures do not mean clean.
Encrypted, traversal/duplicate members and unsupported forms fail closed. Binary
pickle and PyTorch ZIP signatures are supported; arbitrary protocol-0 text files
and nested/7z/numpy archives are not added as supported formats.

Incremental coverage established here is **separate rule provenance and a real
second disassembler**, not a measured increase in malware detection. Further
paired corpora are required to establish incremental efficacy. Malformed or
oversized streams may stop before producing findings; partial/failure is explicit.

### Precision-aware half statistics

F16 and BF16 remain separate from the existing 19-feature F32 Random Forest.
F16's 10 mantissa bits and BF16's 7 mantissa bits are measured directly from raw
little-endian words. In particular, BF16 bit 7 is exponent, not mantissa. Numeric
decoding is used only for descriptive moments, never to pretend half precision
has F32 low-byte statistics. Nonfinite windows are excluded with explicit counts.

Separate 64-window default budget (maximum 256). Sampling is deterministic;
window overlap, when needed, is disclosed and **unique union** element coverage
is counted. There is no trained half-precision detector, anomaly threshold,
malware probability or behavioral test. The dashboard has a separate precision
tab and mantissa-occupancy heatmap. Integers have inventory support only.

### Broader benchmark, preserving v1

`docs/benchmark_v2_policy.json` was locked before downloading new weights,
extracting features or evaluating. SHA256:
`68451d7f5a75622733d9031771eaccde6f5301157c783be86f706a8b161d825c`.

Nine published parameter groups, 27 harmless variants, 3,117 sampled rows. Original
three already-evaluated groups are training-only. Six new groups include DeiT,
RepVGG, RegNet, Swin, ConvNeXt and EfficientNet. Public source pins/licenses are in
the policy. Distinct source architectures are an ancestry assumption, not an
independent audit of training genealogy; shared datasets are not ruled out.

- Train: original MNIST/ResNet/MobileNet groups plus DeiT and RepVGG.
- Validation: RegNet and Swin.
- Test: ConvNeXt and EfficientNet.
- Fixed CPU RF64/depth10/leaf2/seed42, threshold0.5. No tuning after test.
- Feature profiler run before fit: 3,117 rows, 22 columns including 19 features,
  no missing values; 8 duplicate full rows retained as correlated windows;
  `zero_fraction` constant. Full profile and preparation hashes retained.
- Test window confusion **[[250,6],[244,268]]** (rows=true0/1, columns=predicted0/1).
- Test artifact mean-vote confusion **[[2,0],[2,2]]**: both no-added-payload variants
  negative, both text variants positive, **both random-payload variants missed**.
- Independent JSON inference confusion recount matched the trainer result.

Only two held-out parameter groups: still exploratory, not generalization proof.
Windows and the three variants from one group are correlated. Label0 means no
added benchmark payload, never safe/backdoor-free. No inference or preservation
of classification behavior is claimed. Version1 and version2 metrics are not
comparable as a controlled improvement experiment (different train/test sets).

The original default `data/runtime/detector/` and benchmark remain untouched.
Expanded files live in `benchmark-v2/` and `detector-v2/`. The upload form offers an
explicit trusted CPU RF profile choice when v2 exists; original remains default.
No arbitrary filesystem detector picker or automatic downloads are introduced.

Reproduction: `scripts/build_expanded_benchmark.py prepare --allow-network`, run
and inspect a data profile into benchmark-v2/data_profile.txt, then `... fit`.
Existing output directories fail rather than overwrite/retrain. Preparation may
leave incomplete files on failure; inspect them, do not silently reuse them.

## Compatibility and local AI

New reports are schema1.1 with separate `picklescan_analysis` and
`precision_analysis` fields. Version1.0 reports remain readable; old evidence is
not rescanned or rewritten. CPU-only runtime remains mandatory.

Local-language explanation is **design-only**, not an installed server or claimed
feature. See `LOCAL_EXPLAINER_DESIGN.md`. It would interpret bounded saved JSON,
not execute a scanned checkpoint or replace deterministic scan evidence.

## Validation boundaries

Numeric half-precision correctness is covered by controlled bit-pattern fixtures
(zeros/sign/subnormals/exponent exclusion/nonfinite/coverage), not evidence of
malicious-content detection on a half-precision model population. Real isolated
Picklescan and ModelAudit runs both completed on an inert dangerous-global fixture;
a separate REDUCE fixture test verified that its marker was not created.
Desktop/mobile staging rendering was checked using a private SSH tunnel and local
headless Chromium; no public service port or external inference was enabled.
