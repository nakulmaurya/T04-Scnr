# Immutable scan PDF export

`stegogate.pdf_report.build_pdf(report: dict, explanation: dict | None = None) -> bytes`
creates a paginated, paper-friendly A4 PDF using ReportLab. It presents **existing
recorded evidence**; it does not scan, load a checkpoint, execute uploaded code,
run inference, contact Groq, open a report-provided path, or fetch remote resources.
The exporter uses built-in Helvetica fonts and native vector drawings only.
ReportLab is a runtime dependency; pypdf is needed only for exporter tests. App,
CLI and dependency wiring are maintained separately from this module.

```python
from stegogate.pdf_report import build_pdf

pdf_bytes = build_pdf(saved_report)
# The caller decides where to save/download these bytes.
# Optional: build_pdf(saved_report, already_generated_explanation)
```

## Identity and integrity

The canonical report digest is exactly:

```python
hashlib.sha256(
    json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
).hexdigest()
```

This is the digest of the **complete loaded JSON object**, not the source file's
original whitespace/bytes, not the generated PDF, not the artifact, and not the
optional interpretation. `ensure_ascii` uses Python's default `True`. Display
truncation does not affect hashing. Artifact SHA-256 is reproduced separately.
Neither the digest nor the PDF authenticates who created the report.

The report and explanation are not modified. Identical inputs produce identical
bytes in the same ReportLab environment (`invariant=1`), without a new export-time
stamp. Cross-version binary PDF identity is not promised. Unsupported Unicode,
including unpaired surrogates, bidi/control characters and non-font glyphs, is
shown as `[U+XXXX]`; values are escaped as literal Paragraph text. URLs, markup,
paths and instructions in report strings remain inert text, not links/actions.

## Reader-first structure and metric context

The PDF supports schema 1.0 and 1.1, empty/sparse dictionaries and missing optional
sections without strict ScanReport validation. It separates three populations:

- **Artifact evidence:** this report's sampled tensors, scores, engine statuses,
  rule findings and reference comparisons. Counts can overlap and are not
  independent confirmations or a number of backdoors.
- **Detector benchmark:** recorded validation/test metrics on labeled evaluation
  windows. They are not this uploaded artifact's accuracy, confidence or safety
  probability. Recorded class definitions, row/lineage counts, thresholds,
  confusion axes and undefined-metric reasons are retained.
- **Runtime:** duration and recorded RSS describe CPU/resource use, not detection
  quality or artifact properties. The legacy `peak_rss_mb` key is unchanged:
  canonical Linux scanning divides KiB by 1024, so its displayed unit is MiB;
  imported report units are not independently verified. A process high-water mark is not an isolated
  per-scan memory peak.

Reading order:

1. Cover with original identity/verdict, canonical report hash and disclaimer.
2. **Executive evidence summary:** coverage with denominators, static findings,
   comparable RF threshold counts, heuristic counts and reference byte changes;
   followed by an engine coverage/status table explaining gaps.
3. Artifact charts, finite F32 feature ranges, separate precision-aware F16/BF16
   context, and a clearly labeled runtime table.
4. Detector benchmark tables: validation/test are separate populations, not a
   before/after time series. A TN/FP/FN/TP matrix is shown only when its shape and
   explicitly recorded axes support that mapping; otherwise no axes are assumed.
5. **Metric guide:** definitions, units, denominators, possible meaning of
   increases/decreases, and what cannot be inferred. Covers mean, standard
   deviation, mean absolute value, RMS, adjacent differences/correlation,
   kurtosis, F32 low-byte entropy, F16/BF16 mantissa entropy, bit/transition and
   numerical fractions, RF vote versus probability, recorded decision thresholds,
   coverage, overlapping counts, reference changes, precision/recall/F1/AUC,
   accuracy and confusion matrices. No suspicious cutoffs are invented.
6. Snapshot/comparison caveats and recorded limitations. A single report contains
   no earlier scan and claims no time trend. Compare hashes, dtypes, sample
   budgets/positions, engine availability, detector versions and thresholds before
   interpreting changed numbers.
7. **Appendix A:** bounded literal source fields for provenance/config/runtime,
   separate ModelAudit/Picklescan evidence, statistics, RF manifest and references;
   then tensor/window/score records and explicit omission notices.
8. **Appendix B:** validated optional interpretation, never mixed into evidence.

Curated values are paired with meanings, rather than exposing free-form scanner
paths as the main reading experience. Exact source values remain in the bounded
appendix and original JSON. Raw short scalar pairs share a row; hashes and long
paths span full width. Evidence-path prefixes identify source sections. Core
canonical identity and all previous evidence/output caps are retained.

### Derivation and display rules

- Coverage = recorded sampled elements / recorded total F32 elements, not file
  byte coverage. Half-precision coverage uses its own unique-union population.
- Reference change = differing sampled bytes / compared bytes, not artifact size.
- RF above-threshold count uses each valid score row's **own recorded threshold**;
  rows lacking either value are excluded, never treated as negative or assigned
  a default threshold. Do not sum RF, heuristic and static counts.
- Artifact feature ranges are min/max across recorded finite F32 window features;
  displayed counts name the finite-window and recorded-row populations. No full-
  tensor average, temporal trend, feature threshold or risk ranking is inferred.
- Benchmark metrics are copied, not recomputed to hide inconsistencies. Ratios in
  [0,1] may be formatted as percentages with the formula/denominator stated;
  ROC AUC stays dimensionless. Null/invalid/undefined values never become zero.
  If an explicitly oriented matrix sum disagrees with row_count, a warning is
  shown rather than silently fixing it.
- Percentages are calculated only with compatible finite positive denominators
  and 0 <= numerator <= denominator. Full precision is retained for calculations;
  normal percentages display two decimal places and small nonzero percentages
  use significant digits rather than becoming a manufactured displayed zero.

### Vector charts

Native ReportLab Drawing/Rect/Line/String primitives create at most three charts:

1. F32 sampled coverage on a zero-based 0–100% scale, with exact sampled/total
   element counts alongside the explanation.
2. RF votes from the **first six recorded score rows**, valid rows only, with
   row IDs and a neighboring tensor/window identity + vote/threshold table.
   A black per-row marker shows that row's valid recorded threshold; no marker
   means missing/invalid threshold. The axis is 0–1 model vote, not probability.
   This is explicitly a bounded illustration, **not a full score distribution**.
3. Differing sampled reference bytes on a 0–100% compared-byte scale, with the
   exact changed/compared denominator and non-maliciousness caveat.

No values are fabricated, missing values are not zero-filled, and booleans are
not numbers. Zero observations remain zero-length bars. Missing eligible numeric
evidence produces a no-chart notice. There are no browser/HTML renderers, images,
external assets, arbitrary fonts or executable report-provided source paths.

## Optional interpretation appendix

Interpretation is **separate from measured evidence**, placed after the
canonical report sections. Export never generates interpretation or sends data.
Callers should default to no interpretation and obtain consent before any
separate external-provider operation.

Only `status == "completed"`, `mode in {"offline", "groq"}` with exact canonical
`report_sha256` matching is accepted. `provider` must equal mode; offline `model`
must be null; Groq `model` must be `openai/gpt-oss-20b` or
`openai/gpt-oss-120b` (the shared explanation schema's current allowlist). Any
allowlist change must be coordinated with the explanation implementation.

Shared fields are `mode`, `provider`, `model`, `report_sha256`, `bundle_sha256`,
`prompt_version`, `generated_at`, `status`, `observations`, `limitations`,
`next_steps`, `usage`, and `warnings`. Each prose array contains
`{text: str, evidence_refs: list[str]}`. Audit metadata includes the recorded
sanitized-bundle hash, bounded prompt/completion/total token counts (integer
0–1,000,000,000 only), and bounded warnings. Missing optional audit fields are
explicitly shown as unrecorded, not invented.

Labels are **AI interpretation — unverified** (Groq) or **Deterministic offline
interpretation** (offline). Evidence references are bounded inert JSON Pointers
beginning `/evidence/` or `/omissions/`, relative to the sanitized evidence bundle;
RFC 6901 `~0` and `~1` escapes are supported. They are never filesystem paths or
URL targets. PDF validation checks syntax only, **not pointer existence, bundle
hash integrity or semantic support**. The producing explanation API validates
references against its bundle; neither valid references nor hash association
prove LLM prose true. This limitation is visible inside the appendix.

Mismatched, failed, unsupported, malformed or oversized optional interpretation
is visibly omitted without blocking deterministic PDF export. Unexpected optional
appendix-rendering failures retry without the appendix, with an omission notice.
No interpretation is merged into the verdict, scanner findings or charts.

## Resource and fidelity limits

| Limit | Value / behavior |
| --- | --- |
| Canonical input JSON | 8 MiB; larger inputs raise ValueError before rendering |
| JSON nodes / nesting | 100,000 nodes / 24 levels; excess rejected |
| Report input types | JSON dict/list/str/int/finite float/bool/null; non-string keys, tuples, objects, nonfinite numbers rejected |
| Single displayed path/value | 800 characters (including expansion budget), then inline omission marker |
| Source section fields | 55 scalar leaves, unless explicitly smaller |
| Curated table values | 320 displayed characters per cell, 32 data rows maximum; omissions marked |
| Global measured-evidence fields | 650 scalar leaves |
| Appendix collection rows | At most 12 per collection, in recorded order |
| Appendix entry fields | At most 22 leaves, with fair collection/global budgets |
| Interpretation items | At most 100 input items per group; first 12 considered for display; additional bounded field budgets apply |
| Interpretation references | At most 32 per item, 512 characters each; syntax validated |
| Interpretation warnings | At most 100 input; first 12 considered for display |
| PDF | At most 48 pages and 4 MiB output |

If output caps are exceeded, rendering retries at reduced display budgets (45%,
then 15%) and visibly discloses the reduction. Optional interpretation has an
independent bounded budget; it cannot consume measured-evidence fields. A byte-
bounded in-memory sink rejects over-limit output. If deterministic output cannot
fit even reduced budgets, ValueError is raised. Keep the original JSON for all
omitted fields, entries and unsupported extensions. Input objects should already
be loaded JSON; the exporter does not implement an untrusted file loader.

## Tests and sample QA

Run without pytest or model/scanner dependencies:

```sh
python -m unittest discover -s tests -p test_pdf_report.py -v
```

Tests use pypdf to inspect text, A4 dimensions, headers/footers/page numbering,
absence of link annotations/images, canonical digest, immutable inputs,
reproducible bytes, sparse/legacy/malformed reports, Unicode/control/markup
injection, invalid charts, limits and optional-appendix failure isolation. Reader
regressions cover summary ordering, exact denominator arithmetic, benchmark axis
mapping, undefined metrics, no invented RF thresholds and malformed metrics. The
real deterministic `offline_explanation(report)` path is tested end to end.
Network connection functions and report filesystem-path opens are blocked in the
injection fixture. Synthetic fixtures are explicitly labeled: their numerical
values are not a real scan, detector benchmark or production evidence.

Synthetic QA samples may be written under `<qa-output-directory>` outside the
source tree. Render every sample PDF page for visual inspection; inspect cover,
chart labels, long paths/tensor names, appendix separation and page boundaries.
