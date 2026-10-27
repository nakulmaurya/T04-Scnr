# Evidence Assistant direction — superseded local-server proposal

The earlier local Ollama/LM Studio proposal was not installed. The user selected
**Groq only** as the hosted provider for v0.4. There is no Ollama, Gemini,
OpenRouter or other hosted-provider integration in this release.

Current implementation and controls: `EVIDENCE_ASSISTANT.md`. PDF export:
`PDF_REPORT.md`. Operator setup and limitations: `UPGRADE_V04.md`.

Offline deterministic explanations remain available without a key. The Groq
feature is a separate, explicit cloud interpretation request after a scan, never
model execution or a replacement for the CPU detector. It sends only a bounded
allowlisted evidence bundle after consent; immutable reports/verdicts stay local
and unchanged. Cloud-generated prose remains unverified.
