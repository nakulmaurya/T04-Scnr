# v0.4.1 validation — contextual interpretation and readable reports

## Reason for revision
The original PDF was detailed but too difficult to interpret without a glossary. The revision adds an executive evidence summary, unit/denominator tables, explicit benchmark-vs-artifact-vs-runtime scopes, threshold markers, metric definitions and direction-of-change cautions. It does not invent universal danger cutoffs or infer trends from a single snapshot.

Initial real-provider testing of prompt2 identified two integration gaps: a large repeated reference schema exceeded the account token budget, and models returned numerical prose despite prompt instructions. Those responses failed closed; they were not accepted explanations. Merely adding context or changing models was not considered a sufficient safety fix.

## Revised cloud contract
Prompt3 gives an application-owned scanner glossary and eligible qualitative explanation cards. Groq selects/prioritizes cards rather than authoring unrestricted prose. Cards are deterministically gated on supplied evidence; both exact text and exact permitted references are checked locally, in addition to the existing strict parsing, number/overclaim/control-character validation. Missing or contradictory evidence is not converted into a completed negative finding.

The request retains a fixed Groq TLS endpoint, explicit consent, no tools, no automatic repair/retry/fallback, a controlled model allowlist, redacted input, bounded row projection and local byte caps. Byte caps are not a tokenizer or a promise of free-tier capacity. Credentials are not persisted in source, PDF, evidence, results, application logs or the dashboard session. The user-supplied temporary credential was passed only to short-lived test processes and must be revoked because it appeared in chat.

## Evidence to complete before promotion
Final test counts, lint, actual-provider acceptance, selected-page visual inspection, report preservation checks and dashboard health are recorded below when complete. No success is inferred merely from HTTP200: output must pass application validation.

## OpenRouter
The user permits a free-router backup if needed. Official documentation describes dynamic selection among available free models, variable availability and rate limits. No OpenRouter credential was supplied and it is not enabled in this release; no Groq key was sent to OpenRouter. A future integration needs separate explicit provider consent, credential isolation, upstream model/provider provenance, and output-contract tests.

Sources: https://openrouter.ai/docs/guides/routing/routers/free-models-router ; https://openrouter.ai/docs/limits ; https://console.groq.com/docs/structured-outputs ; https://console.groq.com/docs/reasoning

## Selected-page visual review
Parent inspected actual MNIST reader PDF pages 2 (executive summary), 4 (coverage and recorded per-row RF threshold charts) and 9 (metric glossary). Tables, units, denominators and chart legends were readable with no observed clipping. The PDF owner independently reviews sample pages; this is not a claim that every page of every possible report is visually verified.

## Completed staging validation
- Full canonical VM suite: **329 passed, 91 subtests passed** (22.80 seconds).
- Final Ruff lint: clean (checked separately before promotion).
- Independent review: **108 cases passed**; explanation owner: **24 mocked cases**; PDF owner retains prior security tests plus reader-focused regressions.
- Live public-MNIST Groq `openai/gpt-oss-20b`, prompt3: HTTP200, finish_reason stop, original language/ref validation and exact eligible-card validation passed. Latency0.89s; prompt3073/completion330/total3403 tokens. This is one integration case, not a broad quality/availability or quota guarantee.
- No temporary key was left in the dashboard configuration. All provider responses containing invalid numeric prose were rejected; no automatic retry or provider/model fallback was added. Diagnostic tests were manually initiated during implementation.
- Private staging browser: desktop/mobile checked; zero page errors and Streamlit exceptions; real PDF downloaded with deterministic offline appendix, **27 pages /55,082bytes**. Revised executive summary, chart and metric-guide pages inspected from this actual download, with no observed clipping.

## Completed live promotion
- Source backup saved before promotion; pre-existing report/detector JSON checksum checks all passed unchanged.
- Live full suite: **329 passed, 91 subtests passed** (22.22 seconds); Ruff clean and no broken dependencies.
- Imported and installed versions both **0.4.1**. Restarted dashboard healthy, listening only on **127.0.0.1:8501**.
- Staging dashboard stopped; no credential file installed. Dashboard remains offline-capable with Groq disabled until an operator configures a fresh key.
