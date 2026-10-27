# T04-Scnr technical dashboard

## Run locally

```bash
streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.maxUploadSize 256
```

Set `STEGOGATE_DATA_DIR` to app-owned state before launch. Default is storage's configured local root. Bind localhost unless the deployment has an explicitly reviewed access-control boundary. The interface is a CPU-only prototype evidence console, not a malware verdict service.

## Workflow and evidence views

- **New static analysis:** one bounded artifact and optional reference, explicit scan button. Uses `storage.stage_upload` (random names) and `pipeline.scan_artifact`, then `storage.save_report`. The UI does not read the entire uploaded artifact into a second byte buffer. Per-file policy cap is 256 MiB; the Streamlit server may enforce a lower limit unless configured as above. Reference doubles the maximum aggregate upload to 512 MiB. The scan never initiates demo downloads or behavioral execution.
- **Saved reports:** only UUID-validated IDs returned by `storage.list_reports`; loaded through `storage.load_report`. No arbitrary report paths or host-directory input.
- **Overview:** provenance/hash, file format/size, recorded runtime telemetry, per-engine statuses, explicit sampling scope and limitations. No invented timing or percent coverage. Empty engines are unavailable, never clean.
- **Tensor explorer:** searchable metadata/dtype table, tensor summaries, window selectors, raw feature evidence and actual bit-plane fields when recognized.
- **Signal lab:** introspects finite numeric feature keys from reported windows. Histogram of actual recorded values and scatter by recorded order (explicitly not time). Missing values are omitted, never imputed. All plotted data also has a visible table. Figures are Streamlit-native Plotly per the application requirement; no external chart CDN or generated image is needed.
- **Static indicators:** findings plus engine/version/status/timeout warnings; no safety implication from exit code or absent findings.
- **ML detector:** model-vote semantics, raw per-window scores and original detector manifest. Not malware/backdoor probability. No manufactured accuracy metrics. Training scope remains explicit.
- **Reference diff:** original comparison summary and tensor evidence; differences do not imply malice and a preceding checkpoint is not a pristine control.
- **Raw evidence:** complete report/configuration and behavioral evidence without fabricated inference.
- **Demo & evaluation:** optional `demo.get_demo_catalog()` sources plus bounded prepared JSON under `data_root()/demo` (root, child and grandchild files). Source manifests are marked not measured evaluation. Unknown triggers are distinct from known-trigger verification. An explicit button can run the same CPU static pipeline on a fixed allowlisted prepared `model.safetensors`; no preparation, conversion, remote downloads or behavioral model execution is exposed.

## Exports and safety

Both JSON and standalone HTML are generated automatically from the active report and downloaded through Streamlit. HTML escapes **all** dynamic content, has no JavaScript/network resources, and includes a restrictive CSP. Nonfinite JSON is refused. Report/upload content is never interpolated into `unsafe_allow_html`; the only such use is a fixed authored CSS block. Demo JSON reads are bounded to 8 MiB, limited to 60 candidates and confined under the resolved demo root (symlink escapes rejected).

Upload filename is passed as a sanitized display-only original name; staging uses storage-generated paths. The UI has no shell commands, path text fields, model deserialization, remote-code imports, or model inference. Pipeline and storage remain the authoritative enforcement layer. Uploaded files follow storage's retention policy; the UI does not silently delete parent-owned staged evidence.

## Interfaces assumed

`scan_artifact(path, reference_path=None, config=None)`; `stage_upload(fileobj, original_name)`; `save_report(report)`; `list_reports()` returning summaries with `scan_id` and nested `artifact`; `load_report(scan_id)`; `data_root()`. Report schema is `docs/CONTRACT.md`, sections JSON dictionaries, tensors/windows lists. Missing sections are handled as unavailable. Demo catalog is optional; prepared document browser requires only bounded local JSON. The default weight heuristics are uncalibrated. Charts use actual finite features only.

## QA

```bash
python -m pytest tests/test_ui_helpers.py tests/test_ui_app.py -q
```

Helper tests cover UUID/path validation, XSS escaping, offline exports, missing/nonfinite values, status semantics, bit-plane introspection and bounded local manifest reading. AppTest exercises an empty console, demo route, populated synthetic report and tensor search. Synthetic fixtures are explicitly labeled and never installed into runtime data. Deployment screenshots must be captured against the real installed application; AppTest does not establish browser visual QA.

### Implementation validation

Canonical VM: 10 helper/AppTest tests passed. Additional AppTest against a real pipeline report for the prepared MNIST epoch-2 safetensors (8 actual sampled windows) rendered all 7 report tabs with zero exceptions. Prepared MNIST epoch-1, epoch-2 and ResNet demo routes each rendered with zero exceptions; only bounded fixed prepared artifacts enable the static-analysis button. These checks validate UI execution, not detector accuracy. Desktop/mobile screenshot inspection remains a deployment QA step; this worker's local environment did not expose the advertised browser-rendering packages.

Chart units: reported `*_fraction` feature fields are converted to percentages for plots, with explicit labels; signal raw-evidence tables retain original fractions. Low-byte entropy axis is labeled in bits. Locally verified behavioral rates are plotted only from `completed` / `verified_known_trigger` results, never from author catalog metrics.


## v0.4 controls
The Evidence Assistant tab offers deterministic offline interpretation and explicit Groq-only requests. A preview, per-report/model/prompt consent, server-side-key configured check and generate action precede egress. Plain-text output, mandatory caveats and scoped session caches prevent narrative from becoming scan evidence. The detailed PDF expander prepares a local downloadable report on demand; optional interpretation appendix is off by default. PDF generation never invokes Groq. JSON remains the complete evidence export; PDF bounds/omissions are disclosed.

## Native Windows v0.5
Launch with `scripts\run_dashboard.cmd` from PowerShell or use the direct Python command in WINDOWS.md. The upload form disables Linux-only static controls and explains the gap. Reading prepared demo evidence is available, but native demo preparation/behavior workers refuse before download or launch. Core scans, reference comparison and exports stay available.
