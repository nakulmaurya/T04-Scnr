# T04-Scnr CPU v0.4 — Groq-only Evidence Assistant and detailed PDF

## Scope

No scanner/model-training or verdict changes. No new hosted providers besides
Groq. Default scanning, offline interpretation and PDF export are local CPU work.
Cloud explanation is optional and explicitly discloses data egress.

### Evidence Assistant

Open a saved report, then **Evidence Assistant**. Offline mode uses deterministic
phrasing grounded in report fields and requires no API key. Groq mode allows only
reviewed strict-output models (`openai/gpt-oss-20b` and `openai/gpt-oss-120b`), shows
the exact allowlisted bundle, and requires consent for the selected report/model
and prompt version before the generation action. No request occurs just by
opening the tab, checking a box, scanning or exporting a PDF.

The allowlist deliberately excludes original filenames, tensor names, filesystem
paths, artifact hashes, credentials, free-form scanner messages and metadata.
It does not guarantee anonymity: retained statistics may still be sensitive.
Do not send confidential evidence unless approved under your data policy.

Strict JSON and existing evidence references do not prove that model prose is
true. Clear overclaims and unsupported numeric text are conservatively rejected;
other factual errors remain possible. Mandatory caveats stay visible. There is
no tools/shell/model execution, arbitrary endpoint, provider fallback or automatic
retry. Groq quota/outage/refusal/validation failure leaves the report unchanged.

Groq documents inference non-retention by default with reliability/abuse and
other exceptions. Do not promise zero retention or unlimited free inference.
https://console.groq.com/docs/your-data
https://console.groq.com/docs/rate-limits
https://console.groq.com/docs/structured-outputs

### Private operator configuration

Never paste an API key in chat, a report, source or a dashboard question. The API
adapter reads **GROQ_API_KEY** from the server environment. The dashboard launcher
can optionally load an owner-only regular, non-symlink key file, <=1024 bytes:
`~/.config/stegogate/groq.key` with mode 600 or 400. Invalid file permissions are
reported without reading/printing the key; offline dashboard remains usable.

On the VM, use an interactive shell (input is hidden, not a literal in history):

```bash
install -d -m 700 "$HOME/.config/stegogate"
read -r -s -p 'Groq API key: ' GROQ_API_KEY; printf '\n'
(umask 077; printf '%s' "$GROQ_API_KEY" > "$HOME/.config/stegogate/groq.key")
unset GROQ_API_KEY
```

Then restart the loopback dashboard using the normal launcher. The launcher
never executes key-file content. CLI commands read the current process's
GROQ_API_KEY; they do not automatically load the dashboard key file.
There is no public authentication or secret-entry endpoint added by this feature.

Session cache: up to eight Groq and eight offline interpretations, scoped to
canonical report digest/model/prompt; one-hour TTL checked on access. No global
cross-user cache or persistent explanation store. A completed interpretation can
be cleared from the session. Existing cached prose is not a new provider call.

### Detailed PDF

Use **Detailed PDF evidence report → Prepare detailed PDF → Download**.
No Groq key is needed. Measured sections, per-engine statuses, numeric charts,
provenance, sampling limits and bounded appendices are generated with ReportLab.
The original JSON is still the complete machine-readable evidence artifact.

Optional interpretation appendix is unchecked by default. When selected, the
currently selected completed interpretation must match the canonical report
hash. Groq prose is labelled **AI interpretation — unverified**, not blended
with measured findings. An unavailable/invalid appendix never makes a clean
result and does not prevent a report-only PDF.

Prepared PDF cache is session-local, at most three entries, one-hour TTL; keyed
by canonical report digest and selected appendix digest. Existing report files
are not edited. PDF input/output/page caps and omitted rows/text are disclosed.
Unsupported characters may be represented safely rather than rendered exactly.

### CLI

```bash
stegogate explain SCAN_UUID                    # offline, no request
stegogate explain SCAN_UUID --groq --consent-cloud --model openai/gpt-oss-20b
stegogate report-pdf SCAN_UUID --output report.pdf
stegogate report-pdf SCAN_UUID --output report-with-notes.pdf --offline-appendix
```

The UUID must identify a saved app-owned report. Outputs refuse overwrite.
Groq explanations can optionally be written as JSON with `--output`. No API
key argument is accepted. PDF CLI never invokes cloud inference.

## Validation distinction

Mocked Groq transport tests validate integration/error/security properties, not
actual provider quality, latency, access or free quota. A real authenticated
provider smoke requires an operator-configured key and explicit consent. PDF
rendering and extraction are tested with real local ReportLab output.

## v0.4.1: contextual interpretation and reader-focused PDF

The cloud task is now constrained selection/prioritization of eligible, application-owned qualitative statements, not unrestricted AI-authored prose. Eligibility is derived from the transmitted evidence; exact text/reference associations are checked locally. This reduces the scope for unsupported restatement but does not independently verify source-report authenticity or completeness. Prompt versions isolate caches. Measurements remain deterministic in the UI/PDF.

The PDF starts with a readable executive summary, units/denominators, coverage and reference-change percentage charts, per-row recorded RF threshold markers, and an artifact-statistics guide. Benchmark precision/recall/F1/AUC and confusion matrices are explicitly separate from artifact measurements and runtime. Definitions describe how a quantity changes, not invented malware danger thresholds.

The contextual Groq request uses deduplicated strict schema definitions, bounded sample rows, a local request-byte cap, low reasoning effort and final answers only. Byte caps are not exact token counts and cannot guarantee account quota availability. HTTP413/request-limit errors remain fail-closed without automatic retry.

OpenRouter free routing was approved by the user as a possible backup, but is not enabled in this release. It requires a separate credential, explicit provider consent and review of upstream provider/data policies; the Groq credential must never be sent there. A randomly selected free model would need actual-provider provenance and independent output-contract testing before use.
