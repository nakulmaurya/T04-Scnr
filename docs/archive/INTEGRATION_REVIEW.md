# Integration review — CPU research console upgrade

This is an integration decision record, not a claim that all candidates run in
T04-Scnr. No upstream research source was copied in this upgrade. Public
repository descriptions and declared licenses were checked on 2026-10-26;
formal legal review is still needed before redistribution.

| Candidate | What it contributes | Current decision |
| --- | --- | --- |
| Promptfoo ModelAudit | Installed static artifact scanner | Already integrated under restricted subprocess policy; preserve per-engine evidence |
| mmaitre314/picklescan | Independent static suspicious-pickle checks; declares MIT | Strong next adapter candidate: local files only, same isolation/output/resource bounds; prove incremental rule coverage before adding |
| trailofbits/fickling | Pickle decompilation and static safety analysis; declares LGPL-3.0 | Candidate static-only dependency adapter with license review; never use its loading/injection APIs or claim combined independent accuracy |
| danigil/ModelXRay | Few-shot weight-steganography research and representations | Research reference only: declares CC BY-NC-ND 4.0 plus patent notice; no copied or modified source without permission and review |
| danigil/NeuPerm | Architecture-specific weight permutation to disrupt extraction | Not a detector; would mutate artifacts and require function-preservation validation. Declares CC BY-NC-ND 4.0 and patent notice; not integrated |
| FreeEagle paper | Behavioral neural-trojan detection research | Separate future opt-in behavioral research, not a default static engine. Exact official implementation, license, CPU costs and trusted architecture support must be established first |

Sources:
- https://github.com/promptfoo/modelaudit
- https://github.com/mmaitre314/picklescan
- https://github.com/trailofbits/fickling
- https://github.com/danigil/ModelXRay
- https://github.com/danigil/NeuPerm
- https://www.usenix.org/conference/usenixsecurity23/presentation/fu-chong

## Gates for any new engine

1. Confirm exact repository identity: unrelated projects can share names.
2. Review license, pinned revision, dependency footprint and known limits.
3. Identify a concrete capability gap; do not add a second name for the same rule.
4. CPU-only benchmark under explicit budgets; no uploaded-code execution.
5. Keep parser and arbitrary artifact scanning isolated and offline by default.
6. Preserve independent engine states/rules. Do not sum correlated findings into
   a probability or let an unavailable engine imply a clean result.
7. Test benign fixtures, inert hostile fixtures, timeouts, malformed archives,
   resource limits and false positives. Keep published claims separate from
   reproduced evidence.

## Local interpretation server — pending user clarification

A localhost LLM server (Ollama, LM Studio or an OpenAI-compatible local endpoint)
would explain reports, not replace the RF classifier. It is not implemented or
installed by this upgrade. Confirm whether the user meant local AI interpretation
or local dashboard hosting before choosing the feature.

If requested, it needs explicit CPU configuration and a chosen model/budget,
opt-in requests, loopback-only endpoints by default, no arbitrary URL fetches,
no raw weights or secrets sent by default, bounded/redacted report evidence,
timeouts, response-size caps, prompt-injection handling for artifact names and
findings, and no power to execute actions or change scanner verdicts. The model's
text must be labeled unverified interpretation; deterministic evidence remains
available when the server is offline. A laptop's localhost is not the VM's
localhost; a separate connection method is needed when they are different hosts.
