# v0.4 independent review — Groq evidence assistant and PDF export

## Outcome and scope

The independent regression file contains **108 passing local tests** against the
implemented assistant, PDF exporter, UI cache/consent controls and offline scan
boundary. The observed matching-appendix integration defect was fixed by its
implementation owner and both offline and mocked-Groq appendix regressions pass.
This is **not a live-provider, production deployment, or general factuality
certification**.

Reviewer implementation ownership was limited to `tests/test_v04_review.py` and
this file. No implementation edits, package installs, commits, SSH/VM access,
real API requests, real credentials, or model downloads were performed. All
provider responses and credential markers are synthetic. A per-test socket
tripwire blocks accidental external access. Test-local HTTP doubles replace
`HTTPSConnection`; they exercise the real transport wrapper without DNS/TLS or
provider contact. The PDF download UI test substitutes a small synthetic byte
payload only to test caching; separate tests build and parse actual ReportLab
PDFs.

## Reproduce

Using the already available local dependency directory:

```bash
cd <project-root>
PYTHONPATH=<local-test-environment> python -m pytest tests/test_v04_review.py -q
```

In a normally installed parent/VM environment:

```bash
python -m pytest tests/test_v04_review.py -q
```

Dependencies used: pytest, ReportLab, pypdf; NumPy/Pydantic for the offline scan
integration test; Streamlit for the two UI AppTests. UI AppTests skip if
Streamlit is unavailable. Nothing was installed by this reviewer. Default local
Python had no pytest, so omitting the existing dependency directory was not a
valid baseline run.

Recorded final independent result: **108 passed in 5.06s**. Timing is one local run, not
a performance benchmark. The subsequent full-suite result is recorded below.

## Coverage matrix

| Boundary | Evidence exercised |
| --- | --- |
| Report identity | Canonical key-order invariance; changed evidence changes digest; different private names retain different report hashes even if redacted bundles coincide; no report mutation |
| Outbound privacy / prompt injection | Synthetic private path/auth/instruction markers planted in filenames, tensor names, scanner findings/warnings, intake metadata, detector manifest, config, limitations and runtime are absent from the outbound allowlist projection |
| Bundle scope | Bounded canonical bundle; exact source/included/omitted row counts; at most eight inspected records per collection with a shared byte budget; shared opaque tensor/window aliases across selected engine rows; references inventoried independently as JSON Pointers |
| Opt-in | Literal `True` required; absent key/unknown model/invalid synthetic credential rejected before connection; rendering, scans, preview, PDF preparation and rerenders do not invoke Groq |
| Provider routing | Fixed `api.groq.com:443` and fixed POST path despite synthetic proxy/base URL environment values; TLS context has hostname checking; no tools/functions in payload; strict response schema; no stream |
| Provider failure | Redirects/auth/rate limit/server errors cause one attempt only; connection errors/timeouts, response byte limit, oversized Content-Length and unsupported compression fail closed; private response bodies/exceptions/key markers are absent from result and captured logs |
| Wall-clock/resource bounds | Small synthetic hard deadline returns despite blocked connection; an outstanding operation prevents another connection; cleanup releases the slot; no automatic retry |
| Output integrity | Unknown/empty/duplicate refs, unsupported extra fields/sections, numerical assertions, selected categorical safety/backdoor claims, markup, overlong text, empty sections, refusal/tool calls, truncated/multiple choices, malformed/duplicate/nonfinite JSON and echoed key are rejected |
| Provenance/usage | Report/bundle digests match local inputs; model/provider/prompt/time fields present; usage retains bounded known token counts and drops arbitrary provider fields |
| Session cache | No reuse across report, model, prompt version or independent session state; TTL and entry caps; offline generation metadata stable across rerenders; model change resets consent; explicit request sends once and then uses cache |
| PDF bytes/safety | Actual PDF parses, stays bounded, preserves input, shows partial/not-performed coverage and sampled denominator; missing evidence stays unavailable; untrusted markup is literal; no active link actions or document/page automatic actions observed |
| PDF appendix | Matching actual offline and mocked-Groq explanations included; cross-report appendix visibly omitted; no provider request during export; correct prepared appendix survives rerender and wrong selection does not expose cached download |
| PDF limits/Unicode | Long multilingual/control/markup-like input bounded; unsupported Unicode represented through visible code-point substitution; nonfinite/deep/oversized/non-JSON report input rejected |
| Scanner isolation | A synthetic F32 safetensors scan remains offline even with a synthetic Groq key; no explanation call and no behavioral test occur |

No test deserializes an uploaded model with pickle/torch or executes uploaded code.

## Findings and disposition

### Fixed during review

1. **High — valid interpretation appendices were always omitted.** The exporter
   initially rejected any evidence reference starting `/`, while the assistant
   emits JSON Pointer refs such as `/evidence/scan.status`. End-to-end matching
   offline and mocked-Groq tests initially failed; the owner accepted bounded
   bundle JSON Pointers, and both tests now pass. Cross-report omission still
   passes. References remain inert text, never filesystem targets.
2. **Consent scope.** The initial checkbox key covered only the report. Parent
   now binds it to report/model/prompt; AppTest confirms switching model requires
   a new checkbox choice before a request.
3. **PDF download instability.** Fresh offline `generated_at` on each render
   changed the appendix cache identity. Parent now caches offline interpretation
   provenance per report/prompt; the download persists across rerenders without
   a new build or cloud call.
4. **Unsupported categorical prose / displaced caveats.** Initial validation
   allowed obvious safety/backdoor certainty statements if accompanied by an
   existing ref. Conservative rejection and always-visible deterministic scope
   cautions were added. Tested categorical examples now fail. This does **not**
   solve general semantic correctness.

### Remaining risks / nonblocking follow-ups

- **Reference validity is not evidence authenticity.** Prompt-v3 supersedes the
  earlier free-prose path: output must match an eligible application-owned card
  and its exact ordered references. Remaining risks include inaccurate source
  records, bugs in template eligibility, incomplete coverage and unhelpful model
  prioritization. Selection is not independent fact verification. Fixed caveats
  and unchanged deterministic source evidence must remain visible.
- **Standalone PDF appendix trust is weaker than API validation.** The exporter
  checks report hash/status/mode and pointer syntax, but does not independently
  prove referenced fields exist or support text. Arbitrary caller-supplied
  explanation dictionaries are not authenticated merely by sharing a hash.
  Exporter wording discloses this limitation.
- **Provenance metadata follow-up addressed:** the owner added bundle hash,
  bounded token usage and warnings to appendix metadata after notification, and
  rejects provider/model values inconsistent with the declared offline/Groq
  mode. These are local identity/audit fields, not provider authentication.
- **External disclosure still exists.** Identifier stripping does not make
  numeric evidence/coverage patterns non-sensitive. Groq account retention,
  quota, policy and actual request pricing are outside these tests. Preview and
  explicit consent remain required; no promise of zero retention is justified.
- **Conservative output rejection may reduce usability.** Real completions may
  use numbers, disallowed words, unsupported response formats or exceed limits.
  This should produce a clear failed result, not silent retries, automatic
  provider fallback, or relaxation of validation.
- **PDF readability:** a one-window synthetic report with offline appendix before the
  final metadata additions was 13 pages / 19,986 bytes. Cover and final continuation page were rasterized and
  inspected locally: text was readable with no obvious clipping, but the final
  page was sparse and split a next-step/value/ref group. Compact layout and
  keep-together grouping would improve polish. This was not a full-document,
  multilingual typographic review; visible code-point substitution is the
  intended Unicode fallback, not native multilingual shaping.
- **Documentation drift:** initial `LOCAL_EXPLAINER_DESIGN.md` claimed an
  unimplemented loopback-only assistant; `CONTRACT.md` limited all network to
  preparation and `DASHBOARD.md` listed JSON/HTML only. Parent was notified and
  owns synchronization to the Groq-only, explicit-consent exception and detailed
  PDF path. This reviewer did not edit or certify those documents.
- The scan test disables optional external static engines. This review does not
  recertify sandboxing of ModelAudit/Picklescan, model accuracy, hidden-payload
  detection, unknown-trigger behavior or security of concurrent deployments.

## Untested / release checks reserved for parent

- **No real Groq API call or configured real key was available to this reviewer.**
  Model availability, strict-schema support, TLS/DNS/proxy behavior on the real
  network, live auth/rate limits, token billing and output quality remain
  unverified. Mocked provider success is not actual provider success.
- No VM, public deployment, SSH, reverse proxy, browser visual/responsive review,
  concurrent multi-user deployment, server log-retention inspection or installed
  dependency verification was performed here.
- AppTest validates Streamlit behavior, not physical browser downloads or
  production session isolation. Browser-session storage clearing, browser back/
  refresh behavior and authenticated multi-user sessions require deployment QA.
- The hard-deadline test uses a short in-process stalled connection. It does not
  induce real kernel DNS/TLS stalls, packet slow-drip, resolver leakage or stress
  test thread/resource exhaustion on the target host.
- Report hash is an identity binding, not a signature, artifact trust proof or
  statement that a supplied source report is honest.

## Local full-suite baseline

Before v0.4 additions, the local environment returned **151 passed, 25 subtests
passed, 12 skipped, 3 failed**. Two failures lacked `safetensors`; one lacked
`scikit-learn`. Optional trusted model and Picklescan checks were skipped. The
reported authoritative VM baseline of 166 tests + 25 subtests was provided by the
parent and was **not independently rerun on the VM**. No new dependency was
installed to hide these local environment gaps.

Final reviewer-local full-suite result: **250 passed, 57 subtests passed, 12
skipped, 3 failed in 7.06s**, with the same missing safetensors/sklearn failures.
This includes the 75 independent QA cases plus owner-added tests available at
that run. Parent separately reported staging **265 passed, 57 subtests passed in
11.72s, lint clean**; that is parent-provided evidence, not this reviewer's VM
run. Parent owns real CPU PDF visual checks and the installed VM full suite.

Final metadata follow-up: the two added regressions verify that the PDF includes
the exact bundle hash and bounded token usage without arbitrary provider usage
fields, and visibly omits a provider/mode mismatch. All **77 independent cases**
pass after this follow-up. The full-suite counts above predate these two tests.

### Compact-layout follow-up

The PDF owner changed repeated full scalar paths into a section-level
`Evidence path: interpretation` prefix plus relative labels such as
`usage.prompt_tokens`. One staging assertion expected the former contiguous
string, although token usage remained present. The regression now checks the
interpretation prefix and all three exact labeled values (prompt 12, completion
9, total 21 in the synthetic fixture), plus bundle hash and absence of arbitrary
provider usage metadata. No usage audit was removed. Reviewer-local retest:
**77 passed in 3.16s**. Parent's newer full-suite/actual-artifact layout results
remain parent-owned evidence; the earlier raster observations describe the
pre-compaction PDF, not the new layout.

## Reader-oriented PDF / compact-prompt follow-up

### PDF semantics and presentation

The revised PDF puts an executive evidence summary, engine gaps, readable
artifact charts, numerical descriptor ranges, a separate detector-benchmark
section and a metric guide before the technical appendices. Independent
reader-focused cases exercise:

- Percent charts retain **256 / 1,024 F32 elements = 25%**, not eligible-only
  512-element or whole-file coverage. Reference change retains **75 / 300
  compared bytes = 25%**, not a 4,096-byte artifact denominator.
- RF bars retain actual recorded votes on a 0–1 model-vote scale. Marker geometry
  uses an explicit row threshold of 0.77; missing/invalid row thresholds do not
  acquire a default 0.5 or inherit a manifest threshold. Missing rows are not
  negative results, zeros stay zero, and a tiny positive ratio is not displayed
  as a false zero.
- Guide definitions distinguish weight units, population standard deviation,
  signed mean vs magnitude, stored-order differences, F32 low-byte entropy in
  bits (maximum eight), F16/BF16 mantissa bounds, fractions vs percentages,
  transition-pair vs word denominators, dimensionless correlation and excess
  kurtosis (subtract three). No universal danger cutoff is introduced.
- Benchmark precision/recall/F1 formulas, confusion-matrix axes and counts,
  partition populations, lineage caveats and undefined metrics are explicit.
  Unknown axes are not reinterpreted; matrix/row-count disagreement is disclosed.
  Benchmark performance is not an artifact-confidence estimate. Threshold
  direction statements correctly avoid promising improved precision.
- Public PDF assertions normalize only presentation whitespace where cells
  reflow prose and hashes. They still require the complete exact bundle hash,
  generated text and all labeled token-usage values. Comma-grouped thousands are
  normalized only for the denominator check; no missing evidence is waived.

A synthetic enriched report with offline appendix produced **17 pages / 34,958
bytes** in the inspected revision. All pages were rasterized into a contact
sheet; chart, benchmark and metric-guide pages were inspected at higher
resolution. Text-span geometry found **zero spans outside page boundaries**.
Charts show legible scales, units, raw denominators, row identities and recorded
thresholds; benchmark and artifact populations are visually separated. No
obvious clipping or arbitrary danger coloring was observed. This is synthetic
local visual QA, not a VM/actual-artifact or all-language typography guarantee.

Pre-card-transition combined run: **116 passed + 27 subtests in 11.87s** for
`tests/test_v04_review.py tests/test_pdf_report.py`, including **97 independent
QA cases**. The later eligible-card transition requires a fresh result below.

### Compact Groq request controls

Prompt-context tests derive the current application-owned glossary and prompt
version rather than snapshotting prose. They check preview-without-request,
strict closed response objects, local schema references, exact evidence-pointer
inventory, at most eight inspected rows per collection and exact omission
counts. A shared record-byte budget can legitimately omit all rows from a later
collection; tests do not require misleading minimum coverage.

The request now has a 24 KiB local byte guard and a 5 KiB early record-projection
budget. A bounded test lowers the request guard and proves oversized requests
return unavailable **before `_transport` is called**. Numerical assertion
rejection still covers both digits and words, including an explicit `four
findings` response. HTTP 413 is covered as a redacted, single-attempt failure.
Byte limits are not tokenizer/account-TPM guarantees.

No real key or provider call was used by this reviewer. Parent separately
reported real transport attempts: an earlier request hit HTTP 413, another strict
completion hit HTTP 400, and low-reasoning compact inference reached HTTP 200 /
`stop` but was rejected locally for a spelled-out numerical assertion. Transport
success is **not** application acceptance or evidence of explanation quality.
The parent subsequently requested eligible application-owned qualitative cards
instead of free prose; that transition is reviewed separately below. A user-
permitted conditional OpenRouter backup was not part of this reviewed
implementation; no Groq credential was routed elsewhere by these tests.

### Eligible-card transition — reviewed

The parent and explanation owner agreed to prompt-v3 application-owned,
condition-gated qualitative cards. The model selects/prioritizes eligible
statements instead of writing arbitrary prose. Successful mock fixtures now
select current `_eligible_cards(build_evidence_bundle(report))` items dynamically;
they do not snapshot old text or weaken numerical/reference checks. Closed-schema
checks resolve current section text enums and local shared evidence-reference
schema definitions, while malicious numerical, unknown-pointer, categorical
certainty, refusal and truncated-output tests remain.

Added adversarial targets include paraphrases, wrong sections, substituted
existing references, duplicate cards, different-state/stale cards whose pointers
still exist, and stale prompt-version session cache entries. A bounded traversal
of all cards for the synthetic report checks that each genuinely passes the
original validator and the public success path. The model's selection is still
not independent detection, new factual evidence or a safety verdict.


### Final independent transition result

**108 independent cases passed in 5.06s** against current prompt-v3 and the
reader-oriented PDF. The immediately preceding combined independent/exporter
run was **126 passed + 27 subtests in 11.89s** (107 independent cases plus the
exporter's cases); one additional numeric-contradiction case was then added and
included in the final 108-case run. No package installation or implementation
edit was needed.

The final additions prove that subset, superset and reordered multiple-reference
lists fail even though every supplied pointer exists. Wrong-state eligible text,
valid-but-substituted refs, wrong sections, paraphrases, repeated cards and stale
prompt cache entries fail closed. Conflicting score/threshold/label/count values
do not create new qualitative card claims while status facts stay fixed. Each
eligible card for the synthetic report passes the unchanged original validator
and public mocked success path. The exact association check is additional to,
not a replacement for, the prior language/reference validator.

Catalog limitations remain: selection is bounded and status-first, not an
exhaustive account of every engine or fact. Application-owned template wording
and gating rules still need maintenance. A model may prioritize poorly, omit an
important eligible card, or fail structured validation. Cards do not derive
per-score threshold crossings, counts, clean-check conclusions, trust,
behavioral results or danger levels; deterministic evidence/coverage displays
remain necessary. Standalone PDF appendix syntax/hash checks are still weaker
than the producing API's eligibility checks.

### Parent-reported real-provider integration — separate evidence

After the independent mocked tests, the parent reported an accepted **public
MNIST Groq `openai/gpt-oss-20b` prompt-v3** request: HTTP 200, finish reason `stop`,
both `_validate` and `_validate_cards` passed, with three eligible exact cards in
each of the three sections and correct state-associated references. Reported
usage was **3,073 prompt / 330 completion / 3,403 total tokens**, with **0.89s**
latency for that one request. The parent reported no numerical assertions, no key
persistence, and no credential disclosure to reviewers.

This is **parent-reported live integration evidence**, not a request or key
inspection performed by this reviewer. It supersedes the earlier parent-reported
HTTP 200-but-local-rejection case only for that specific accepted prompt-v3
integration. It is not a broad quality, availability, billing, free-tier,
performance, correctness or security guarantee. The parent owns subsequent full
VM/staging test results, deployment and actual-artifact PDF validation. No
OpenRouter backup was integrated or reviewed here.
