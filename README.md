<p align="center"><img src="docs/assets/banner.svg" alt="T04-Scnr — Inspect the artifact. Question the evidence." width="100%"></p>

<p align="center"><a href="https://github.com/nakulmaurya/T04-Scnr/actions/workflows/ci.yml"><img src="https://github.com/nakulmaurya/T04-Scnr/actions/workflows/ci.yml/badge.svg" alt="CI"></a></p>

<p align="center"><strong>A local-first research console for model-artifact forensics.</strong><br>Inspect structure, investigate sampled weight signals, compare evidence and export reports that explain their numbers.</p>

<p align="center"><a href="#quick-start">Quick start</a> · <a href="docs/GETTING_STARTED.md">Setup guide</a> · <a href="docs/ARCHITECTURE.md">Architecture</a> · <a href="docs/PDF_REPORT.md">PDF reports</a> · <a href="docs/SUBMISSION.md">Reviewer guide</a></p>

> **Research prototype—not a safety certificate.** No finding does not establish safety. Static indicators, numerical anomalies, learned manipulation votes and known-trigger behavior answer different questions. T04-Scnr does not universally detect malware or unknown-trigger backdoors.

## Submission report

Read the illustrated [project report](docs/PROJECT_REPORT.md) or download the [formatted PDF](docs/T04-Scnr_Project_Report.pdf): **Problem Statement, Our Solution, Approach and Conclusion**, with actual dashboard and report screenshots.

## What it does

| Capability | What you get | Scope boundary |
| --- | --- | --- |
| Artifact inspection | Strict safetensors inventory, format and provenance | No arbitrary uploaded-model execution |
| Static rules | Optional ModelAudit and Picklescan adapters, reported separately | Findings can overlap; completion is not a pass |
| Weight investigation | Sampled F32 features, entropy and bit-plane views | Statistical irregularity is not proof of a payload |
| Precision-aware evidence | Separate descriptive F16/BF16 statistics | No silent reuse of F32 detector thresholds |
| Controlled-manipulation detector | CPU Random Forest with transparent JSON inference | A benchmark-class vote—not a malware probability |
| Reference comparison | Compatible-tensor sampled byte differences | Change does not establish malicious intent or reference trust |
| Evidence Assistant | Offline interpretation or optional Groq-selected grounded explanation cards | Cloud requires explicit consent; it does not change the scan verdict |
| Explainable reports | Offline PDF with executive summary, units, denominators, charts and bounded audit appendix | Full JSON remains the machine-readable record |

## Console preview

![T04-Scnr analysis console with explicit local-scan controls](docs/assets/console.png)

*Actual empty-state dashboard; no private report or model data included.*

## Quick start

**Python 3.11+; Linux is the reviewed platform for isolated scanner adapters.**

```bash
git clone https://github.com/nakulmaurya/T04-Scnr.git
cd T04-Scnr
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[security,dev]'
.venv/bin/t04-scnr doctor
./scripts/run_dashboard.sh
```

Open **http://localhost:8501**. The dashboard binds to loopback by default. It has no multi-user authentication; do not expose the port publicly. Optional demo inference dependencies and Windows/macOS caveats are in the [setup guide](docs/GETTING_STARTED.md).

### Scan a local artifact

```bash
.venv/bin/t04-scnr scan path/to/model.safetensors --save
.venv/bin/t04-scnr scan modified.safetensors --reference original.safetensors --save
.venv/bin/t04-scnr reports
```

Use artifacts you are authorized to inspect. Uploads are staged with server-owned names. The default upload cap is 256 MiB and the default window budget is bounded; [compatibility and coverage](docs/GETTING_STARTED.md#compatibility) are explicit.

### Export and understand a report

```bash
.venv/bin/t04-scnr explain SCAN_UUID
.venv/bin/t04-scnr report-pdf SCAN_UUID --output evidence.pdf --offline-appendix
```

In the dashboard, choose **Detailed PDF evidence report → Prepare detailed PDF**. The reader path explains artifact measurements separately from detector benchmark metrics and runtime. Export performs no rescan, inference or provider call.

### Optional cloud assistance

Offline interpretation needs no key. Groq is opt-in: review the redacted evidence and eligible statements, grant consent, then explicitly generate. Groq selects/prioritizes application-defined qualitative statements; exact text and evidence references are validated locally. It does not author unrestricted diagnostic prose.

**Never put credentials in the repository, a report, an issue or chat.** Configure a server-side `GROQ_API_KEY` or the owner-only key file described in [Evidence Assistant](docs/EVIDENCE_ASSISTANT.md). Quotas and data policies apply. There is no automatic provider fallback; OpenRouter is not enabled.

## Reproducibility and evaluation

```bash
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
```

The completed v0.4.2 submission passed **332 tests plus 91 subtests** on the reviewed Debian/Python VM, with clean Ruff lint and dependency checks. See the [submission validation](docs/SUBMISSION_VALIDATION.md). The preceding v0.4.1 build passed the same full suite. A public-demo Groq 20b request passed both validation layers; that is an integration check, not a general quality or availability guarantee. See [validation evidence](docs/VALIDATION_V041.md), [independent review](docs/REVIEW_V04.md) and the [benchmark protocol](docs/BENCHMARK.md).

GitHub CI passed on Python **3.11 and 3.13** for the initial submission. CI runs synthetic, mocked-network tests; it does not need API keys or downloaded model weights. Exact benchmark/dependency context matters. `requirements-vm.lock.txt` is the validated VM snapshot, not a universal cross-platform lockfile.

## Project layout

```text
app.py                Streamlit research console
stegogate/            Inspection, isolated adapters, features, detector, explanation, PDF
scripts/              Local launch and explicit benchmark/demo preparation
tests/                Unit, security-boundary, UI and integration tests
docs/                 Setup, contracts, scope, evaluation and attribution
data/                 Ignored local runtime state (empty placeholder only)
artifacts/            Ignored generated outputs (empty placeholder only)
```

The internal Python namespace `stegogate`, legacy `stegogate` CLI alias and `STEGOGATE_*` configuration names are retained for compatibility. The public project and installed distribution are **T04-Scnr / t04-scnr**. There is no detector or schema change implied by the rename.

## Documentation

Start with the [documentation index](docs/README.md), [reviewer guide](docs/SUBMISSION.md), [security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md). Historical build notes are clearly separated from current setup instructions.

## Attribution and licensing

Dependency APIs are used without merging upstream repository source trees. See [third-party attribution](docs/ATTRIBUTION.md) and [pinned demo provenance](docs/DEMOS.md). Model weights and runtime reports are not bundled.

**The owner has not yet selected a license for this repository.** No project-wide open-source license is implied; dependency and artifact licenses remain separate. Select a license and review redistribution rights before public distribution.
