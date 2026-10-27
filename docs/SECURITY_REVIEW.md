# Independent adversarial review — T04-Scnr CPU

Review date: 2026-10-26. Scope: bounded static artifact intake, sampled F32
forensics, reference compatibility, JSON RF inference boundaries, storage/UI
handling, optional static scanner isolation, and explicit demo preparation.
This is a prototype review of a changing build, **not a complete audit, security
certification, malware-detection validation, or proof of absence of backdoors**.

Reviewer modified only `tests/test_adversarial_review.py` and this document.
Implementation fixes were made by their owning agents. No dependencies were
installed or modified by this reviewer; no git commits were made.

## Execution evidence

- Local Python 3.13: the independent suite runs using `unittest` without pytest,
  torch, sklearn, scipy, safetensors or ModelAudit installed; numpy and pydantic
  are available. Initial 19-test run: 18 passed, one coverage-status failure.
  Final 22-test suite passed locally after the owner fixed that status bug.
- VM: Python from the existing project `.venv`, pytest, actual installed
  ModelAudit **0.2.54**. First independent VM run reproduced the old status bug.
  Final 22-test suite passed after owner synchronization. Subtests additionally
  exercise malformed tensor records, duplicate keys and other parameter sets.
- Real VM ModelAudit smoke, valid minimal 64-element F32 safetensors:
  `status=completed`, `findings=[]`, `warnings=[]`, approximately 4.69 seconds.
  This establishes adapter functionality for that fixture, not model safety.
- Real VM ModelAudit smoke, a locally generated pickle whose `__reduce__`
  returns `os.system('touch <temporary marker>')`: `status=completed`, critical
  static rule **S201**, “REDUCE opcode invoking dangerous global: posix.system”.
  The marker did **not** exist afterward. Approximately 4.99 seconds.
  This is a genuine static code-execution indicator, not a backdoor finding.
- The test of the actual Linux static bootstrap denied socket creation, fork
  and `pickle.loads`; only scanner dispatch was replaced with a test probe.
  Bounded subprocess output and timeout termination were also exercised.

Re-run (from repository root):

```sh
python -m unittest discover -s tests -p test_adversarial_review.py -v
# Or, in an existing environment containing pytest:
.venv/bin/python -m pytest -q tests/test_adversarial_review.py
```

## Findings and disposition

### Medium — missing engine coverage incorrectly summarized as completed (fixed)

**Repro:** write `b'not a model'` to a file, then call
`scan_artifact(path, config={'run_static': False})` without a detector.
The old pipeline returned `status='completed'` with no eligible weight windows,
no static scan, and no learned result. The verdict was already qualified as
limited analysis, but the completion status overstated analysis coverage.

**Fix observed:** primary-engine gaps include `not_available`, `not_performed`
and unsupported states; no weight windows forces partial coverage. An absent
optional reference is distinguished from a requested incomplete comparison.
`test_unknown_with_all_engines_missing_not_completed` passes locally and on VM.
No categorical TRUSTED verdict was observed.

### Medium — CLI demo actions omitted the required explicit opt-in (fixed by owner)

**Repro before fix:** `stegogate demo prepare mnist-epoch02` and
`stegogate demo verify mnist-epoch02` called the API without `opt_in=True`, so
both rejected the request before preparation/verification. This was a functional
blocker, not an unsafe-loader bypass.

**Fix observed in code:** explicit CLI actions pass `opt_in=True`; preparation
also exposes `--download-test-data`. Full download/inference is owned by the demo
agent and is not independently reproduced by this reviewer. Converted MNIST
export hashes were initially absent and are now pinned in the reviewed code.
Do not conflate observing those constants with independently verifying exports.

### Fixed after review — bounded demo output and worker resource limits

The initial review found post-capture output checks and no worker address-space
cap. The demo owner subsequently replaced capture with nonblocking selector-driven
draining enforcing a shared 64 KiB stdout/stderr budget before accumulation.
Overflow/deadline kills the process group, with descendant cleanup on completion.
Workers fail closed if resource limits cannot be installed before model imports:
8 GiB address space, 180/185 s CPU, 128 descriptors, 128 MiB file size, no core dumps.

The owner reports 16 passing CPU demo tests and explicit preparation plus
100-image verification under these limits. These are follow-up implementation and
test evidence, not a destructive memory-exhaustion certification. Full 10,000-image
measurements remain separate from the hardening smoke results.

### Low residual — demo network policy is Python-level, not an OS sandbox

Demo workers deny common Python socket connection functions and set offline
library variables. Native library syscalls or alternate socket APIs are not
proved blocked. Code and emitted reports explicitly describe that limit.
The static scanner's Linux seccomp network filter is separate and was tested.
A future stronger “offline sandbox” claim for demos requires kernel enforcement.

### Low residual — local-storage race and availability hardening remain

Intake rejects final-component symlinks and non-regular files using no-follow,
nonblocking open plus `fstat`. Storage/UI helpers validate paths and containment,
but several check-then-open/stat sequences assume app-owned directories are not
concurrently modified by an adversarial local process. Saved report reads use a
stat size check followed by `read_bytes`; concurrent file growth is not bounded
at the read operation. Report listing also sorts the full directory before its
100-result cap. Uploaded default artifacts cannot select those report paths.

Keep the app under a dedicated local account and private data directory; this
review does not establish safety for hostile same-user filesystem writers or
large multi-user deployments. Descriptor-relative/no-follow opens, bounded
report reads, and storage quotas would improve that boundary.

## Tested boundaries

- Duplicate JSON keys, including nested records/metadata; excessive/deep
  headers; unpaired-surrogate tensor names; invalid dtype, boolean/negative/
  oversized dimensions; invalid offsets; overlap, gaps and unclaimed bytes.
  Surrogate-name rejection already worked: UnicodeEncodeError is a ValueError;
  the preliminary suspected uncaught exception was **not** reproduced.
- FIFO/symlink refusal without blocking; no uploaded pickle execution or
  torch/tensorflow/sklearn/joblib/dill/cloudpickle imports on the tested default
  path; explicit missing ModelAudit/learned-model statuses and no socket calls.
- Nonfinite sampled F32 exclusion, finite JSON output, deterministic bounded
  windows, partial sampled coverage, rejection of spoofed inventory hashes.
- Equal data bytes with incompatible reference shapes are not numerically
  compared; a difference outside a sampled reference window cannot be called
  full equality. Difference does not imply maliciousness.
- Whole-lineage split disjointness and determinism; metadata/identity feature
  denylist; malformed/cyclic JSON trees rejected before traversal; detector
  path outside app-owned root rejected. Caller-supplied lineage truth and
  arbitrary identity encodings cannot be certified by a field-name denylist.
- Upload filename traversal does not determine staged path; report ID traversal
  and symlink report-directory rejection; exported HTML escapes attacker
  filenames/tensor names/findings/limitations and carries a restrictive CSP.
- Static completion requires structured evidence rather than exit code zero;
  skipped checks stay partial. Fixed command/scanner selection, isolated Python,
  credential/PYTHONPATH exclusion, CPU visibility, kernel socket/fork denial,
  bounded subprocess output and timeout behavior.

## Code-reviewed, not fully independently exercised

- Only pinned, size/hash-checked, allowlisted MNIST `.pt` inputs reach the
  explicit preparation worker's `torch.load(..., map_location='cpu',
  weights_only=True)`. No unsafe fallback or extra safe globals observed.
  Runtime verification loads prepared safetensors, not publisher pickle.
- The default pipeline never invokes behavior verification. CIFAR trigger
  geometry remains unverified rather than fabricating measured success.
  MNIST preceding checkpoint is not presented as a pristine final control.
- RF scores are controlled-manipulation model votes, explicitly not malware or
  backdoor probabilities. Training schema is derived after whole-lineage split;
  validation-only optional threshold selection is locked before test metrics.
  Actual model fitting/metrics, prepared-model behavior, and publisher claims
  were not independently validated by this reviewer.
- Latest prepared-demo UI scan paths are constructed from fixed allowlisted IDs
  and filenames, checked for root containment, size and final symlink status;
  manifest-provided artifact paths are display-only. No arbitrary host browser
  or model-download action was observed in the UI.
- Dashboard launch script binds `127.0.0.1`, not a public interface. UI dynamic
  data are not interpolated into the one authored unsafe-HTML styling block.
  Browser execution, Plotly rendering and browser-assisted XSS testing were not
  performed by this reviewer.

## Explicit limitations / release boundary

No exhaustive fuzzing, native dependency exploit testing, race exploitation,
full filesystem sandbox, cross-platform sandbox verification, GPU hardware
verification, dependency/license audit, network capture, large-scale DoS test,
or independent full-dataset behavioral reproduction was performed. The static
worker still runs trusted installed code with the application's OS-account
filesystem permissions; network/loader/process guardrails are not a complete
container or filesystem sandbox. Native-code compromise of a dependency is
outside what these passing regression tests establish.

The tested blockers above were fixed; residual hardening items remain. Preserve
localhost-only operation and separate “not analyzed” from “no indicators.” Do
not market the result as universally detecting steganography, malware, or unknown
backdoors, or as certifying a model safe.
