# Getting started

## Choose your operating system
Use [WINDOWS.md](WINDOWS.md) for native PowerShell installation. Do not run `.venv/bin` or `.sh` commands in Windows PowerShell. Native Windows has explicit Linux-only scanner/demo gaps; no unsafe adapter fallback is provided.

## Requirements
Python3.11+ and a local virtual environment. Linux is the reviewed environment for scanner isolation. Core inspection/PDF/UI portability does not establish that every security adapter works on every OS. Unsupported isolation prerequisites are explicit failures, not passes.

Install `.[security,dev]` for the scanner adapters and tests. Install `.[demo]` plus explicitly CPU-only PyTorch/torchvision wheels only if you need allowlisted behavioral demo preparation. Default artifact scans do not execute uploaded models.

## Launch and storage
Run `./scripts/run_dashboard.sh`, then open http://localhost:8501. Linux runtime state defaults to `data/runtime`; native Windows defaults to `%LOCALAPPDATA%\T04-Scnr\runtime`; set the legacy `STEGOGATE_DATA_DIR` to choose another application-owned state root. `STEGOGATE_PORT` changes the loopback port. Do not commit runtime state or credentials.

Remote VM access uses a private tunnel; substitute your own host:
```bash
ssh -N -L 8501:127.0.0.1:8501 <vm-user>@<vm-host>
```

## Compatibility
- Safetensors F32: structural inventory plus bounded eligible-window statistics and optional trained detector.
- Safetensors F16/BF16: structural inventory and separate descriptive precision statistics; no F32 model scoring.
- Pickle/PyTorch serialization: reviewed static identification/disassembly paths only; no arbitrary deserialization.
- GGUF/ONNX/HDF5/TensorFlow, quantized or multi-shard LLM checkpoints: do not assume reviewed universal support.
- Known-trigger behavioral verification is limited to explicitly prepared allowlisted demos; not arbitrary inference or unknown-trigger discovery.

## First useful workflow
1. Inspect a local artifact and save the scan.
2. Read the engine coverage and sampling warnings before indicators.
3. Review tensor/window evidence and any trusted compatible reference.
4. Use offline interpretation or explicitly consent to Groq card selection.
5. Export a PDF for reading and JSON for complete machine-readable evidence.

No sample reports or trained detector files are silently manufactured on installation. Benchmark generation, training and demo downloads are explicit operations documented in BENCHMARK.md, ML.md and DEMOS.md.

## Optional Groq
See EVIDENCE_ASSISTANT.md for privacy, fixed endpoint, closed output contract, quota handling and private key setup. `.env.example` documents environment names only; it is not automatically loaded. Do not use the API key from an exposed chat message.

## Troubleshooting
Use `t04-scnr doctor`. Missing optional engines are not clean results. Preserve original JSON; PDF display is bounded. If cloud output is unavailable or rejected, offline interpretation and PDF remain usable. Never fix an isolation error by allowing arbitrary model execution.
