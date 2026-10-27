# Contributing

Use Python3.11+, a virtual environment and `pip install -e '.[security,dev]'`. Run `ruff check .` and `python -m pytest -q` before proposing changes.

- Keep tests synthetic and network-mocked unless an external operation is explicitly requested.
- Preserve immutable report schemas, canonical hashes and distinct engine statuses.
- Never reinterpret missing/failed/partial coverage as a negative result.
- Keep statistical indicators separate from malware/behavioral claims.
- Preserve consent, credential isolation, fixed provider routing, bounds and fail-closed validation.
- Document units, denominators, class definitions and benchmark limitations.
- Do not bundle model weights, credentials, operational reports or unreviewed upstream source.

Describe behavior changes, tests, limitations and third-party provenance in a pull request. Selecting a project license remains an owner decision; dependency licenses do not grant a project-wide license.
