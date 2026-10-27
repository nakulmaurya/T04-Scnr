# Visual integration checks

A sandbox-local Chromium preview connected to the VM's loopback dashboard through
an SSH forward. Rendered PNGs were opened and inspected individually; successful
rendering alone was not treated as visual approval.

Checked: empty console, populated MNIST report overview, tensor inventory,
statistical signal lab, ModelAudit results, learned detector evidence, reference
differential, raw JSON, 390px narrow layout, prepared poisoned MNIST model and
its measured known-trigger chart. No Streamlit exceptions or document-level
horizontal overflow were recorded for these final checked states.

The review corrected initial top-caption clipping by increasing top padding,
removed an unsupported decorative sidebar glyph, and added a prominent report
verdict, coverage status and non-additive window counts. Tables remain internally
scrollable for long hashes and wide technical evidence. The observed-percent
chart is explicitly bounded 0–100 and distinguishes measured behavior from static
scan conclusions. This review is not an accessibility certification, browser
compatibility guarantee or security audit.

Local QA images are retained outside source history under artifacts/qa. They do
not contain a new scan or fabricated metrics; prepared measurements remain in the
original JSON evidence on the VM.

## Monochrome research-console upgrade

The v0.2 staging review covers the new dark empty/populated console, research
atlas heatmap and matched scatter, report comparison and empirical curves,
compatibility table, and 390px layout. Review found native caption opacity was
reducing contrast; the authored theme now sets caption opacity to 1 and uses
#a1a1a1 text. The static theme honors reduced-motion preferences. The single-file
upload limit is configured as 256 MiB in both the launcher and theme config.
No upstream Next.js site source or restricted research code was copied.
