# Submission validation — v0.4.2

## Scope
Public project: **T04-Scnr**. Installed distribution and primary CLI: `t04-scnr`. Internal `stegogate` namespace, legacy CLI alias and `STEGOGATE_*` configuration remain compatible. The rename does not change detection logic, report schemas or thresholds.

## Completed pre-push validation
- Full regression suite on the existing reviewed Debian/Python 3.13 CPU VM: **332 passed, 91 subtests passed**, 22.27 seconds (including three submission-document tests).
- Ruff: **all checks passed**.
- Dependency consistency: **no broken requirements**.
- Brand/context rendering regression fixed without weakening validation: older Streamlit text wrapping now preserves complete hyphenated words.
- Dashboard preview runs separately on loopback; T04-Scnr branding and empty-state workflow reviewed. No API call or artifact execution is needed for this preview.
- Source checked for credential-shaped values, private key blocks, hardcoded VM addresses and private project paths. Runtime reports, model files, credentials, SSH configuration, caches and virtual environments are excluded from version control.
- Relative Markdown links validated. Dependency and model provenance retained; historical working notes are separated under `docs/archive/`.

## Independent evidence and limits
The preceding [v0.4.1 validation](VALIDATION_V041.md) records successful prompt3 Groq integration and reader-PDF review. No additional live provider request is necessary for this submission cleanup. Synthetic and mocked tests are not a guarantee against all security issues or cloud failures.

GitHub Actions runs separately for Python 3.11 and 3.13; the workflow is not evidence of a passing run until GitHub reports success. Fresh-run optional-dependency skips, if any, differ from the fully provisioned VM suite above.

## Publication boundary
The repository is public at the owner's explicit request. No project-wide license has been selected or invented. Third-party licensing remains separate. Publishing is via a repository-scoped VM deploy key, not an account-wide password or token. Private runtime state is retained outside the submission.

## Completed promotion and CI
- Installed distribution/import and primary command verified at **0.4.2**. Post-install suite: **329 passed, 91 subtests passed**, 24.09 seconds.
- Renamed dashboard healthy on **127.0.0.1:8501**. All **60 existing local JSON files** checked unchanged against their pre-transition checksums; runtime state remains outside the public submission.
- GitHub CI at commit `f6ddc45` completed successfully for Python **3.11 and 3.13**: [workflow run](https://github.com/nakulmaurya/T04-Scnr/actions/runs/40447818231). Later documentation commits have their own runs.
- Illustrated project report includes actual empty-state UI and public-MNIST PDF figures; all ten report pages reviewed as a contact sheet.
