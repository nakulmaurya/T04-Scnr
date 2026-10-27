# Submission and reviewer guide

## Recommended review order
1. README.md: purpose, capabilities and explicit non-goals.
2. GETTING_STARTED.md: fresh environment, localhost UI and compatibility.
3. ARCHITECTURE.md and CONTRACT.md: evidence flow and trust boundaries.
4. PDF_REPORT.md: metric semantics, denominators, source hashes and bounded presentation.
5. BENCHMARK.md and ML.md: controlled labels, independent-lineage splits and limitations.
6. SECURITY_REVIEW.md and REVIEW_V04.md: isolation, privacy and regression evidence.

## Minimal reproducibility check
Create a fresh venv; install `.[security,dev]`; run Ruff and pytest. These are synthetic/mocked-network checks and need no Groq key. Demo downloads and benchmark training are explicit optional operations, not required for a basic review.

## What is and is not submitted
Source, tests, documentation, portable configuration, an illustrated project report and actual documentation screenshots are included. Credentials, SSH material, generated scans/PDFs, local authentication state, trained detectors, downloaded checkpoints, datasets and virtual environments are excluded. Runtime directories contain empty placeholders only.

## Claims a reviewer should challenge
A finding is not proof of malware. An RF vote is not a calibrated malware probability. A completed engine did not necessarily cover every byte. A reference is not automatically trusted. A single-lineage holdout is not a population generalization claim. Known-trigger demos do not discover unknown triggers. Cloud card selection adds interpretation, not detector accuracy.

## Licensing decision
The repository is public at the owner's request. A project-wide license has not been selected; redistribution rights still require review. Third-party licenses/provenance are recorded separately. No proprietary SDK or upstream model-scanner source tree is claimed as original project code.
