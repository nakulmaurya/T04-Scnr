# v0.4 validation and release record

## Scope
Groq-only optional interpretation plus deterministic offline interpretation and offline PDF export. Scanner evidence, Random Forest inference, verdict logic, existing saved reports and original detector are not changed by this feature. Source changes include dashboard/CLI integration, safe server-key loading, documentation and tests.

## Staging validation
Canonical Debian 13 / Python 3.13 CPU VM, installed application virtual environment:
- Full suite: **289 passed, 91 subtests passed** (15.25 seconds, final staging run).
- `ruff check .`: all checks passed; source formatted with Ruff.
- Independent review: 77 cases, plus owned explanation/PDF tests and dashboard/CLI/key-loader integration regressions. See REVIEW_V04.md.
- ReportLab 4.5.1 and pypdf 6.21.2 installed; no Groq SDK required.

All Groq responses were mocked. Tests cover fixed TLS endpoint, literal opt-in, model allowlist, redaction, controlled reference validation, hash binding, deadlines, bounded responses, sanitized failure handling and session cache isolation. Conservative prose rejection is not semantic factuality verification.

## Actual report and interface checks
- Rendered actual saved MNIST epoch02 and MobileNet seeded-random reports with deterministic offline appendices: **26 pages / 43,144 bytes** and **27 pages / 45,256 bytes**. Both contain their canonical source-report hash and offline interpretation label. No rescan or provider call occurred.
- Visually reviewed selected actual-report cover, engine coverage, recorded-evidence chart and appendix pages; all synthetic compact sample pages were reviewed by the PDF owner. Not every actual-report page was visually inspected.
- Private staging dashboard tested through an SSH tunnel: desktop 1600x1100 and mobile 390x844; no page errors or Streamlit exceptions. Verified Groq generation disabled without a server key; downloaded the real MNIST PDF through the UI (43,146 bytes with session timestamp provenance). PDF preparation/download made no Groq call.
- Original legacy reports correctly show missing Picklescan evidence as unavailable, not a zero-findings pass.

## Release gates
Promotion requires source backup, clean lint, full suite rerun in the live project, package version 0.4.0, unchanged SHA256 checks for pre-existing report/detector JSON files, and health check on loopback port 8501. The lockfiles record the installed environment; they are not a claim of cross-platform reproducibility.

## Completed live promotion
- Pre-upgrade source backup saved on the VM before promotion.
- Live project full suite: **289 passed, 91 subtests passed** (15.41 seconds).
- Package dependency check: no broken requirements. Imported and installed package versions both **0.4.0**.
- All pre-existing report/detector JSON checksums passed unchanged.
- Restarted private dashboard: health `ok`, listening only on `127.0.0.1:8501`.
- Staging dashboard stopped after promotion. No real Groq API request was performed.

## Remaining limitations
No live Groq credentials or authenticated provider request were exercised. Account access, quotas, latency, cost and actual explanation quality remain operator validation tasks. Hosted interpretation is optional cloud assistance, not fully offline operation. Neither strict JSON/ref checks nor conservative regex rejection prove every generated sentence follows from its evidence. Mandatory deterministic caveats remain visible.

PDF display is bounded (including row/text/page caps); full JSON remains the authoritative machine-readable record. Canonical JSON hash is not a PDF-file hash or a hash of original JSON whitespace. Standalone PDF appendix validation checks reference syntax, not reference existence or semantic entailment. Detailed appendices can be lengthy. No detection-accuracy improvement or universal model support is claimed.
