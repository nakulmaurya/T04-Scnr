# StegoLens visual-experience preview (0.7.0)

This review branch adds three visual journeys, a bounded harmless-message learning lab, an actual bit microscope, and a scoped file-evidence explorer. It does not change the detector's scientific validation or certify malware detection. Main/live deployment is separate.

## Validation

- Full Linux suite: **588 passed, 12 skipped, 91 subtests passed**. Skips are native-Windows-only adapter tests, not successful Windows execution.
- Whole-repository Ruff, dependency consistency and whitespace checks passed.
- Independent QA added 53 regression tests; pure engine and UI/module tests also pass.
- Local Chromium desktop 1440×1100 and mobile 390×844: recorded normal/triggered predictions, explicit toy creation/recovery, actual bit chart, safe toy exports, stale-result removal, and no horizontal page overflow checked.
- Actual prepared-model/reference inspection verified in isolated preview: 56,692 / 61,562 recorded F32 values, 4 / 17 RF windows, 143,865 / 185,320 compared-byte changes. These are scoped evidence, not infection probabilities.
- Coverage and reference maps manually selectable; no browser page errors in the interaction test.
- Ordinary file inspection does not execute the uploaded model. Explicit lab creation performs only fixed toy NumPy calculations. Recorded trigger view performs no inference.

## Limits

The trigger is replayed evidence from published checkpoints; epoch 1 is an earlier reference, not independently clean-trained. The toy is hand-set, not trained. Its known decoder is not an arbitrary hidden-content detector. Current scientific generalization limits remain unchanged. These checks are not a formal usability study, native Word review, or native Windows launcher validation. Historical reports retain their source provenance and predate this visual preview.
