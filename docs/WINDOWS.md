# Native Windows setup (v0.5.0)

Python 3.11 or 3.13 is recommended; both are covered by native Windows CI. No WSL, Bash, administrator privileges or virtual-environment activation is needed for the native application.

## PowerShell quick start
Use a local folder outside OneDrive/network shares, for example `C:\Projects`. If already cloned, open PowerShell in that repository and run `git pull --ff-only` first.

```powershell
cd C:\Projects
git clone https://github.com/nakulmaurya/T04-Scnr.git
cd T04-Scnr
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e "."
.\.venv\Scripts\t04-scnr.exe doctor
.\scripts\run_dashboard.cmd
```

If `python` is unavailable but the Python launcher is installed, use `py -3 -m venv .venv`. Check the interpreter version before installing. Extras are written `.[dev]`, **not** `.[security\,dev]` or `.\[security,dev\]`.

The `.cmd` wrapper starts the local PowerShell launcher without changing machine/user execution policy. If enterprise policy prohibits that, do not disable it: use the direct Python command below or ask your administrator. The launcher accepts `-Check` for diagnostics. No script sources `.env` or executes credential-file contents.

Open **http://localhost:8501** in a browser. Ctrl+C stops the dashboard. It binds only to loopback and has no multi-user authentication.

## What is supported natively?
| Capability | Native Windows |
| --- | --- |
| Local UI, inventory and SHA-256 | Supported for regular local disk files |
| Bounded F32 / separate F16-BF16 statistics | Supported |
| JSON RF inference / CPU training tools | Supported when valid detector/training data are supplied |
| Reference comparison and JSON/HTML/PDF | Supported |
| Offline explanation / explicit Groq request | Supported; cloud uses server-side environment key |
| Reading already prepared demo evidence | Supported |
| ModelAudit / Picklescan isolated workers | **Unavailable natively**: mandatory Linux seccomp is not replaced with an unsafe fallback |
| Download/conversion and behavioral demo workers | **Unavailable natively**: reviewed Linux resource/process isolation is required |

Use a Linux/WSL2 environment for those isolated workers. Windows `doctor`, UI and scan warnings explain these coverage gaps. An unavailable scanner never becomes a successful negative check. This release does not claim a Windows sandbox or full Linux feature parity.

## Direct launch without scripts
```powershell
$env:PYTHONUTF8 = "1"
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.maxUploadSize 256 --browser.gatherUsageStats false
```

## Native command-line examples
Run these inside the repository, after installation:
```powershell
.\.venv\Scripts\t04-scnr.exe scan C:\Models\model.safetensors --save
.\.venv\Scripts\t04-scnr.exe scan C:\Models\modified.safetensors --reference C:\Models\original.safetensors --save
.\.venv\Scripts\t04-scnr.exe reports
.\.venv\Scripts\t04-scnr.exe report-pdf SCAN_UUID --output evidence.pdf --offline-appendix
```
Replace the example paths and `SCAN_UUID` with your own authorized local files and saved scan ID. Fresh clones do not include a trained detector; a missing detector is an explicit coverage gap, not a negative result.

## Local state and file protections
Windows defaults to `%LOCALAPPDATA%\T04-Scnr\runtime`, outside the clone and OneDrive. `STEGOGATE_DATA_DIR` explicitly overrides it. Linux retains its existing default. Use an app-owned local NTFS/ReFS directory supporting hard links for immutable report publication; do not grant other users write access.

Intake uses a native binary Win32 disk-file handle. It rejects UNC/device paths, alternate data streams, directories and reparse points (including parent junctions). It denies concurrent writes/deletion while the handle is open. These protections are not a hostile multi-user filesystem sandbox. OneDrive placeholder/reparse files should be copied to a normal local folder first. Uploads are staged as regular app-owned files.

New reports explicitly label process peak memory in **MiB**, including measurement source and lifetime scope. It is not an isolated per-scan memory peak. Unavailable telemetry is null, not a manufactured zero.

## Optional Groq configuration
Offline features do not require a key. Native Windows uses `GROQ_API_KEY` only when set in the launching process environment. Never paste credentials into tracked files, screenshots, reports or chat. The POSIX private-file launcher is not emulated through unreliable Windows mode bits. Existing evidence preview and explicit consent are still required; configuring a key does not send a request.

## Fresh clone versus the prepared VM
The repository does not bundle checkpoints, datasets, trained detectors or saved scans. Their absence is explicitly reported, not silently filled with examples. Prepare Linux-only demo assets in the reviewed Linux environment if needed, then transfer only reviewed prepared evidence/artifacts with their provenance. Do not copy a Linux `.venv` onto Windows.

## Developer checks
```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m pytest -q
```
Linux-only process, FIFO, seccomp and Bash tests are explicitly skipped on Windows. Dedicated Windows tests cover binary intake, file restrictions, partial scans, reports, platform diagnostics and PowerShell launch. Optional CPU torch tests skip when that optional package is not installed. Native runner results must be checked on Actions; Linux simulations alone do not establish Windows compatibility.
