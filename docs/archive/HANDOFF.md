# T04-Scnr CPU — integrated build handoff

## Delivered on the VM

Project: `<project-root>`.
App-owned runtime state: `data/runtime`.
Dashboard: loopback `127.0.0.1:8501`, running in tmux session `stegogate`.
This is a research prototype, not production security certification.

The build uses installed ModelAudit, safetensors, scikit-learn, Streamlit and
Plotly APIs, plus reviewed pinned Hugging Face research artifacts. It does not
merge upstream repository trees or depend on a proprietary scanning SDK.
Exact provenance is in ATTRIBUTION.md, DEMOS.md, demo_sources.json and BENCHMARK.md.

## Start, stop and connect

```bash
cd ~/projects/stegogate
# Existing deployment log and session:
tmux ls
tail -f /tmp/stegogate-dashboard.log
# Stop only this dashboard when wanted:
tmux kill-session -t stegogate
# Restart, keeping it on loopback:
tmux new-session -d -s stegogate 'cd ~/projects/stegogate && ./scripts/run_dashboard.sh >>/tmp/stegogate-dashboard.log 2>&1'
```

On your own computer using your existing VM SSH access:

```bash
ssh -N -L 8501:127.0.0.1:8501 <vm-user>@<vm-host>
```

Open http://localhost:8501. Do not expose port 8501 publicly: this build has no
multi-user authentication or production deployment review. A firewall change is
not necessary for SSH tunnelling.

## Demonstration sequence

1. Analysis console → Saved reports → select the MNIST epoch02 report. Inspect
   provenance, explicit partial coverage, ModelAudit results, tensor/window
   evidence, learned votes, and reference comparison against epoch01.
2. Signal lab → inspect recorded entropy and bit-plane features. These are
   statistics, not proof of hidden malware.
3. ML detector → inspect recorded threshold, per-window predictions and the
   small-lineage training manifest. No model loading is needed to score uploads.
4. Demo & evaluation → select MNIST epoch01 and epoch02. These show **separately
   prepared known-trigger behavioral evidence**, not automatic static backdoor
   discovery. Full canonical MNIST test set: 10,000 images/checkpoint, CPU only.
5. Show CIFAR ResNet's honest `not_verified` behavioral state rather than
   attributing publisher metrics to our measurement.
6. Export the original JSON and escaped offline HTML evidence.

| Prepared checkpoint | Clean correct | Shifted-label trigger hits |
| --- | ---: | ---: |
| MNIST epoch01, preceding checkpoint | 9,431/10,000 (94.31%) | 41/10,000 (0.41%) |
| MNIST epoch02, poisoned checkpoint | 9,664/10,000 (96.64%) | 9,489/10,000 (94.89%) |

The preceding checkpoint is not safety-certified. Ordinary epoch training also
changes weights. A scan's ML-positive windows do **not** prove detection of the
behavioral backdoor. Static file threats, controlled weight manipulation and
known-trigger behavior are separate demonstrations.

## Experimental learned detector

A real CPU Random Forest was trained on 813 sampled feature rows from three
source ancestries and nine original/controlled variants. Whole-lineage split:
MNIST train, CIFAR validation, MobileNet test. There is only one lineage in each
partition; this is exploratory and cannot establish generalization accuracy.
No-added-payload labels do not mean safe or backdoor-free. The held-out random
payload artifact was missed by mean-vote aggregation. Reports retain false
positives and misses; there was no test-informed refit or threshold selection.

Evidence: `data/runtime/benchmark`, `data/runtime/detector`, and twelve prepared
saved scan reports indexed by `data/runtime/demo_scan_index.json`. These model
and dataset files are intentionally not committed to source Git history.

## Validation and remaining boundaries

- Complete merged test suite: 139 passed, 25 subtests passed.
- Ruff lint and format checks passed; `pip check` passed.
- Canonical environment: Debian 13, Python 3.13.5, CPU-only PyTorch 2.14.1+cpu;
  CUDA unavailable. The static/default pipeline does not import PyTorch.
- Actual ModelAudit 0.2.54 benign and hostile-pickle smoke tests completed;
  the hostile payload was detected without execution.
- Demo workers have incrementally bounded output, process-group cleanup,
  resource caps before model imports, and explicit hash-pinned preparation.
  Demo network restriction is application-level, not an OS sandbox.
- Unknown-trigger behavioral detection, exhaustive steganalysis, automated
  repair, arbitrary uploaded-model execution, and production isolation are
  out of scope. Sampling, narrow F32 support, natural training variation and
  random payloads limit conclusions.
- Review third-party artifact redistribution terms before publishing weights.
  The overall project license remains for the owner to select.

The VM environment freeze is `requirements-vm.lock.txt`; it is a machine snapshot,
not a portable hash-locked requirements file. It contains the local editable
project path and CPU-wheel versions. Use README setup instructions when rebuilding.

## Research console 0.2 update

The live console uses the authored monochrome dark theme. New navigation includes
Compare reports and Compatibility & scope; saved reports also have a Research
atlas tab. Original immutable JSON reports and prepared demo measurements are
unchanged. The source release 0.1 remains in releases for rollback. The upgrade
does not install or call a localhost LLM. See UPGRADE_V02.md and
INTEGRATION_REVIEW.md for the implemented scope and pending server clarification.
