# Evidence assistant — implemented offline templates and optional Groq inference

Prompt version **`evidence-assistant-3`** uses Groq only to select and prioritize
application-owned, prevalidated qualitative statements. It does **not** ask the
LLM to author unrestricted explanations or measurements.

This document describes `stegogate/explanation.py`, not a proposed local-model
service. It supersedes the local-explainer proposal for the supported assistant
path. Ollama, LM Studio, loopback model servers and other hosted providers are
**not supported**. No checkpoint is sent to a language model or loaded by this
module. The CPU scanner and its recorded verdict remain authoritative scan
outputs; an explanation is not another detector vote.

## Implemented APIs

```python
from stegogate.explanation import (
    PROMPT_VERSION,
    report_digest,
    build_evidence_bundle,
    offline_explanation,
    explain_with_groq,
    get_api_status,
)

# Always works without credentials or network for a valid, bounded JSON report.
local_explanation = offline_explanation(report)

# Preview exactly the data projection eligible to leave the process.
bundle = build_evidence_bundle(report)

# Call only after explicit user consent for this report and cloud request.
cloud_explanation = explain_with_groq(
    report,
    consent=True,
    model="openai/gpt-oss-20b",
)
```

- `report_digest(report)` hashes UTF-8 `json.dumps(report, sort_keys=True,
  separators=(',', ':'), allow_nan=False)` using SHA256. JSON's default ASCII
  escaping is retained. It is an identity check, not a signature or evidence of
  artifact authenticity. It has no timestamp or provider dependency.
- `build_evidence_bundle(report)` returns a deterministic dictionary, at most
  **24 KiB in canonical serialized UTF-8 form**. Sparse legacy dictionaries are
  accepted; there is no `ScanReport` validation prerequisite. Nonfinite JSON,
  cycles, excessive nesting and nonserializable values fail before network
  access. Explanation input is limited to **16 MiB canonical JSON**. This limit
  is enforced while iterating canonical JSON encoding, without constructing a
  complete serialized report copy. A single large source string can still
  require an encoded string chunk; this is not a streaming input parser.
- `offline_explanation(report)` uses fixed, deterministic templates and the
  allowlisted bundle. It explains recorded status, unchanged verdict, finding
  and window counts, incomplete engines, eligible-element coverage and next
  review steps. Generic scope cautions do not claim report-specific evidence.
  It never reads credentials or accesses the network. Generation timestamps vary;
  report/bundle identities and template content are stable for the same input.
- `explain_with_groq(report, *, consent=False,
  model='openai/gpt-oss-20b')` returns unavailable without **literal `True`**
  consent, a configured credential and an allowlisted model. It never retries,
  changes providers or falls back automatically. Invalid reports raise
  `ValueError`/`TypeError`; configuration and provider failures use the result
  contract below.
- `get_api_status()` returns only `{'key_configured': bool}`. It does not check
  validity, quota, account status or provider availability.

Neither API mutates the supplied report. No filesystem cache, output file or log
is created. The parent application owns any UI, CLI, session cache and exports.

## Boundary: what may leave the process

The bundle is a **positive allowlist projection**, not a copy of the report with
selected strings scrubbed. It has these top-level fields:

- `schema_version`: the bundle schema version.
- `evidence`: a flat map with literal, controlled keys. Values are bounded finite
  numbers, booleans, exact allowlisted engine states/verdicts/formats/dtypes, or
  generated opaque aliases. Unknown strings and unknown field names are not
  copied.
- `omissions`: source scalar counts, copied and not-copied scalar counts, source/
  included/omitted record counts, source limitation count, and explicit false
  flags for raw identifiers and raw messages.

Evidence includes available summary counts, engine states, warning/finding
**counts only**, eligible-data coverage counts/booleans, reference-comparison
summary counts, detector threshold/exploratory flag and train/validation/test
row/lineage counts. Window records include selected positions/counts, numeric
heuristic or learned scores, recorded thresholds, predicted labels and supported
dtypes when available. Negative or inconsistent source measurements are not
silently reinterpreted as valid detection results; this is a projection, not a
replacement report validator.

Tensor and window identities become encounter-order aliases such as `t0001` and
`w0001`. The same source tensor/window pair gets the same alias across selected
engine rows. No original-name-to-alias map leaves the module. Aliases have meaning
only within that bundle; they are not artifact hashes or cross-report identities.
Rows receive `r001`-style local labels. Example evidence keys:

```text
summary.ml_positive_window_count
weight_analysis.coverage.full_coverage
ml_analysis.scores.r001.score
ml_analysis.scores.r001.threshold
ml_analysis.scores.r001.tensor_alias
ml_analysis.scores.r001.window_alias
```

The module excludes raw filenames, paths, artifact/reference/training hashes,
scan IDs/timestamps, tensor names, scanner findings text, warnings text,
limitations text, detector descriptions, feature vectors, raw weights and
checkpoint bytes. An arbitrary string containing prompt injection in any such
field is never part of the request. Even allowlisted fields copy a string only
when it exactly equals one of the fixed enum values.

Deterministic omission policy:

1. Fixed summaries and engine fields are projected first.
2. Inspect at most the first **8 source rows per collection**, in this order:
   weight windows, learned scores, precision windows. There is no ranking by
   score, filename or tensor name. Missing/invalid fields are omitted.
3. Admit whole projected rows only while the evidence map remains at most
   **5 KiB** (including projected summary fields), reserving space for omission disclosure. If a collection reaches
   its budget, later rows in that collection are omitted. Omitted records
   include malformed/unprojectable rows, budget exclusions and rows beyond the
   inspection cap. A later collection can contribute smaller rows if room remains.
4. Record exact source/included/omitted record counts for each collection. Scalar
   counts describe original leaf values copied verbatim versus not copied;
   generated aliases and derived counts are not counted as copied source leaves.
   They are disclosure counts, not a claim of exhaustive tensor coverage.
5. Verify the final canonical serialized bundle is no more than 24 KiB.

The full report SHA256 and bundle SHA256 are returned locally but **not added to
the hosted prompt**. Review the bundle before consent. Numeric measurements and
coverage patterns may themselves be sensitive despite identifier removal.

## Groq request and resource controls

The only credential source inside the module is **`GROQ_API_KEY` in the process
environment**. No API argument, file loader, alternate environment key or browser
credential fallback exists. Operator launchers may provision this environment
outside the module; never paste a key into a report, UI, chat, session cache or
export. Authentication is used only as the outbound Authorization header. It is
not returned in status, explanation, warnings or usage. Raw provider diagnostics
and exceptions are never logged or included in results. Parent code must not log
request objects or environment values.

Network transport uses Python's standard-library `http.client.HTTPSConnection`
with a verified TLS context and fixed host/port/path:

```text
POST https://api.groq.com:443/openai/v1/chat/completions
```

There is no configurable URL, proxy support, environment-proxy discovery,
redirect following, tool/function capability, model installation/loading, SDK
retry behavior or provider fallback. HTTP non-success responses are not read;
401/403 and 429 become fixed sanitized errors. No response header/body is copied
into errors. Compressed responses are rejected.

- **20 seconds total caller wall deadline**, covering DNS, connection, TLS,
  request, headers and body, plus negligible local scheduling overhead.
- **5 seconds maximum socket timeout**, reduced to the remaining wall budget
  at operation boundaries. A separate caller deadline prevents slow-drip
  responses and blocking OS DNS resolution from extending the caller wait.
- **64 KiB raw response cap**, enforced from declared length and incremental
  reads; mismatched declared lengths are rejected. JSON content is additionally
  capped at **24 KiB**, and requested completion budget is **2048 tokens**.
  Requests use `reasoning_effort=low` and `include_reasoning=false`; reasoning is
  never displayed. The **entire canonical request**, including the glossary,
  eligible-card catalog and deduplicated schema, is limited to **24 KiB before
  any HTTP call**. Byte limits do not guarantee a provider token or free-quota
  budget; rate-limit and model availability failures still fail closed.
- Only **one outstanding daemon transport worker**. If the OS resolver cannot be
  interrupted after timeout, the worker may outlive the caller. It cannot send a
  request after its deadline; subsequent requests fail busy until it exits.
  No unbounded worker accumulation occurs. An indefinitely stuck resolver may
  require an operator process restart. Timeout does not prove the provider never
  received a request that was already sent.
- No automatic retry, not even on timeout or rate limit. The user must explicitly
  initiate a new attempt. Free quota, availability and pricing are not promised.

Only `openai/gpt-oss-20b` (default) and `openai/gpt-oss-120b` are accepted. The
official Groq documentation lists both as supporting strict structured outputs:
https://console.groq.com/docs/structured-outputs . Other models remain rejected
even if the provider supports them. This module makes no claim to have tested a
live account, key, model or quota when only mocked tests have run.

CPU-only scanning remains separate from **optional hosted cloud inference**.
Calling Groq does not mean the explanation ran locally or on CPU; Groq's hosting
hardware is outside this application. Offline templates do no LLM inference.

## Qualitative-card selection, references and truth limits

Groq now **selects and prioritizes prevalidated application statements**, not
unrestricted prose. This is a deliberate capability restriction, not a claim
that prompt wording or a larger model solves hallucination. Neither numeric
allowances nor post-generation word removal are used to force acceptance.

The pure private helper `_eligible_cards(build_evidence_bundle(report))` returns
a per-section catalog of eligible `{'text': str, 'evidence_refs': list[str]}`
items. The parent UI needs no interface changes. Applications and tests can
inspect this helper without credentials or HTTP calls. Its statements are
application-owned English templates, never report strings or scanner messages.
Every eligible item is checked by the unchanged original text/reference
validator **before** it can be offered to the model.

Conservative eligibility rules:

- A scan-status statement requires an exact allowlisted recorded scan status.
  A completed engine statement means only that the recorded task finished; it
  does not mean a model passed a check or an engine examined an entire artifact.
- An incomplete-engine statement requires that engine's exact recorded status.
  Missing or invalid engine states produce a conservative “Not established by
  this evidence” statement citing the omission disclosure, not a fabricated
  completed negative check. A derived finding count of zero cannot establish
  engine completion or absence of findings.
- Sampling-scope statements require a completed/partial recorded engine state
  and an explicit false coverage flag; they do not infer that a positive number
  of eligible elements was missed. Reference-trust and learned-detector-scope
  reminders require the corresponding completed/partial recorded engine state.
- No card infers threshold crossings, alert classes, clean checks, equality,
  confidence, detector quality, behavioral mechanisms, malicious intent or
  deployment suitability from numeric rows/counts. Contradictory score/threshold/
  predicted-label combinations therefore cannot license such claims. Numeric
  facts remain deterministic source evidence, displayed separately.
- The catalog is deliberately small and **not exhaustive**: at most **4 eligible
  observations, 6 limitations and 3 next steps**, with stable priority given to
  recorded scan/engine states before supplementary scope reminders. Missing
  engine-state cautions are consolidated. Selection does not imply that omitted
  eligible statements, engine gaps or source evidence are unimportant.

The request includes the unchanged static `EVIDENCE_CONTEXT` glossary as
application-owned definitions, explicitly not additional case facts. It describes
static adapters, numerical/precision checks, controlled-manipulation benchmark
scope, references, behavioral limits, status semantics and coverage denominators.
The small eligible catalog is appended to the system instructions. The user
message is still **exactly the canonical evidence bundle**, so the existing
`bundle_sha256` remains the identity of the supplied evidence. Prompt-version
identity covers the glossary, catalog policy and selection/validation contract;
version three invalidates older cached unrestricted-prose results.

The request uses `response_format.type = 'json_schema'`, `strict = True`, closed
objects (`additionalProperties = False`) and all required fields. Its three
sections remain `observations`, `limitations` and `next_steps`, with the same
public item keys. Per-section text **enums** admit only eligible statement text.
`$defs` deduplicates item definitions and a **single global reference enum**
containing only references used by eligible cards. Each section requests **1–3
selected items**. The small schema deliberately avoids a repeated per-card
branch tree; exact text/reference association is independently enforced locally.

Local validation remains independent of provider schema promises:

- The original validator is unchanged: three exact sections; 1–8 items per
  section; exact item keys; 1–600 text characters; 1–8 distinct references per
  item; existing numeric/safety/Unicode/reference rejection. The new card layer
  is strictly additional and limits selected cards to 1–3 per section.
- `_validate_cards` then requires **exact eligible text in its own section and
  its entire exact ordered reference list**. A different valid pointer, omitted
  pointer, extra pointer, reordered list, paraphrase, wrong-section statement,
  repeated selected card or stale state-dependent statement fails closed. Valid
  reference existence alone is insufficient. No partial reference sets pass.
- References are JSON Pointer **bundle leaf fields**, never original-report
  fields, wildcard paths or containers. Examples:
  `/evidence/weight_analysis.status` and
  `/omissions/not_copied_source_scalar_count`.
- Duplicate JSON keys, nonfinite JSON, malformed output, refusals, tool/function
  calls and any finish reason other than `stop` fail closed, with empty prose.
- Unicode controls (`Cc`), formatting characters (`Cf`, including bidi/invisible
  formatting), surrogates (`Cs`), angle brackets and backticks remain rejected.
  The original validator still supports ordinary Unicode letters; hosted output
  additionally must match the application-owned statement vocabulary exactly.
- Digits, percentages, common spelled-out quantities and conservative dangerous-
  claim/execution-advice rejection remain unchanged. The regex filters are not
  factuality or entailment proofs. Exact card matching narrows output authority;
  application eligibility predicates and their templates still require review.
- Deterministic safety/scope caveats remain in `warnings`, including completed
  hosted results. Display them alongside the selected statements, not hidden in
  a tooltip. Display deterministic numeric facts separately.

An accepted response proves that a model selected eligible statement/reference
pairs, **not** that it selected the most useful statements, covered every caveat,
found new evidence or independently verified the report. The application-owned
eligibility logic can contain bugs and reports may be incomplete or inconsistent.
Selection has no authority to change a report, execute a model, decide deployment
approval or certify safety. There is no repair call, automatic retry, model
switch or post-hoc rewriting to turn a rejected response into a successful one.

Render selected text as **untrusted plain text**, never HTML/Markdown execution,
template interpolation, terminal input, URL actions or agent instructions. Label
it as **“AI-selected qualitative statements — unverified prioritization”**, not
“AI-authored explanation.” Existing report/PDF labels may use the parent
interpretation heading if they also disclose this selection-only behavior.

## Shared result contract and parent integration

Both modes return:

```text
schema_version: '1.0'
mode: 'offline' | 'groq'
status: 'completed' | 'unavailable' | 'failed'
provider: 'offline' | 'groq'
model: allowlisted model string | null
report_sha256: canonical source report digest
bundle_sha256: canonical supplied bundle digest
prompt_version: PROMPT_VERSION
generated_at: timezone-aware ISO timestamp
observations, limitations, next_steps: arrays of {text, evidence_refs}
usage: allowlisted nonnegative integer token counts only
warnings: fixed, sanitized strings including mandatory scope caveats
```

`generated_at` is a generation metadata field, not part of report/bundle identity.
Unknown usage fields, time measurements, provider IDs and headers are discarded.
Failure results retain identities and metadata, but no model prose. Never show
failed output as if it were a completed explanation. Invalid model names are not
echoed in results; `model` is null in that case.

The parent application may use a **per-report, per-model, per-PROMPT_VERSION**
session-state cache with TTL and a small entry cap. It must recheck explicit
consent **before either a hosted request or returning a cached hosted result**.
A key's presence is not consent. Cached content must not include the key,
authentication headers, raw provider envelope or exception text. Do not share
hosted responses across users/sessions or mutate saved scan JSON to store them.
Offline explanation caching may omit the model component. All cache and export
retention/access controls belong to the parent application.

For local inspection/export, rebuild the same deterministic bundle and resolve
references against it. Label hosted content **“AI-selected qualitative statements — unverified prioritization”**
and offline content **“Offline template explanation”**. Keep the source verdict,
provenance, coverage gaps, deterministic numeric facts and mandatory caveats
visually separate from the model-selected application statements. Any PDF appendix should preserve
these distinctions and the report/bundle digests, model, prompt version and date.

## Cloud privacy and retention

Identifier stripping does **not** make hosted inference local or anonymous. On
consent, the bundle is transmitted to Groq. Provider usage metadata and network
metadata may also be processed. Review the current provider policy before use:
https://console.groq.com/docs/your-data .

The official policy states that usage metadata is always retained and does not
contain customer input/output. Inference customer data is not retained **by
default**, but there are important exceptions: reliability troubleshooting and
abuse investigations can temporarily retain inputs/outputs for **up to 30 days**,
or longer where legally required. Features such as batch and fine-tuning have
separate application-state retention; this module does not use those endpoints.
Organization admins can review Data Controls and enable eligible Zero Data
Retention settings; this code does not enable, verify or promise those settings.
The policy states customer data retention uses GCP storage in the United States.
Provider terms/settings may change. Do not claim “never retained” or “nothing
leaves the VM” for the hosted explanation path.

Offline templates transmit nothing and require no provider account. Existing
scanner reports, parent-session caches, downloaded exports and operator/system
logs remain subject to their own storage and access policies.

## Verification

Run without pytest or an API key:

```bash
python -m unittest discover -s tests -p test_explanation.py
```

The suite mocks all HTTP/TLS operations. It covers canonical identity, sparse
reports, input rejection, no mutation, injection redaction, opaque aliases,
budget/omission counts, consent and credential zero-call checks, exact model and
TLS endpoint, strict-schema requests, key non-disclosure, unsafe claims, eligibility and exact text/reference binding,
stale-state/duplicate-card rejection, bounded catalogs, shape/reference validation, refusal/truncation, response caps, socket/total deadlines,
redirects, 401/403/429, sanitization, no retries and no implicit fallback. No live
Groq request is made by the suite. Live verification requires an operator-supplied
key and explicit user consent; a mocked pass is not evidence of live availability.
