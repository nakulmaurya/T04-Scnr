# StegoLens v0.6.0 review notes

The display name is **StegoLens — Steganographic Malware Detection in AI Model Files**. This is a research problem title, not a claim of universal malware detection. Hidden-data indicators, unsafe-loading warnings and behavioral backdoors remain distinct evidence types.

## Included

- Simple-view dashboard by default, three-step empty state and reversible technical-view toggle.
- Original recorded verdict and immutable evidence preserved; unavailable values are not zero or clean results.
- RF row eligibility requires that row’s valid recorded score and threshold; no default cutoff is introduced.
- Reference percentage names compared bytes, with its exact counts in a wrapping caption.
- Six-page editable supervisor report plus fixed-layout PDF, conceptual architecture and working diagrams, four team members, and accurately scoped recorded results.
- Offline known-trigger visual demo with 12 first canonical MNIST test samples, unfiltered, actual recorded CPU predictions, model/data hashes, and explicit replay labels.
- Retained historical reports and old v0.5.0 demo release; no silent replacement of prior assets.
- Compatible repository URL, internal package, configuration and commands; added `stegolens` CLI alias.

## Validation scope

The integrated changes receive the full Linux regression suite, Ruff, dependency consistency and whitespace checks. An independent reviewer added 56 beginner-view regression cases. Local browser checks cover empty/default state, 390-pixel layout without horizontal overflow, an explicit prepared-artifact/reference scan, exact result populations, and all ten technical tabs. The offline visual demo has 12 rows, no page errors or automatic HTTP requests, and verified sample/trigger image differences.

The Word report has five explicit page breaks and three embedded figures. Its LibreOffice-rendered PDF has exactly six A4 pages and was visually reviewed. Microsoft Word layout can vary with fonts/printer settings; the PDF is the fixed six-page version. All four names match the supplied report; the excluded member is absent. The historical F32 ratio is 56,692 / 61,562 **total recorded** elements, not the narrower eligible population.

Native Windows confirmation is supplied separately by the GitHub Actions Windows matrix. Linux skips of Windows-only tests are not native-Windows validation. New CMD wrapper orchestration in a demo pack must not be described as independently executed on Windows unless actually run there.

## Known limits

The verified MNIST pair is earlier-reference versus published-backdoored checkpoints, not an independent clean-trained control. Separate clean/BadNets DistilBERT repositories are research candidates only; exact trigger, poisoning provenance and license were not established, and their behavior was not verified. No replacement paired model is silently integrated. The project does not modify, repair, certify or execute uploaded models during ordinary scanning. Optional hosted explanation remains consent-gated and selection-only.

### Reviewed VM result

After final report and layout integration: **446 passed, 12 skipped, 91 subtests passed** in 25.54 seconds. The 12 skips are native-Windows adapter cases on Linux. Full Ruff, dependency consistency (`pip check`) and `git diff --check` passed. This is a Linux VM result, not a claim of native Windows execution. GitHub Actions publishes the separate platform matrix for each commit.
