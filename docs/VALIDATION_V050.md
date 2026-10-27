# v0.5.0 Windows support validation

## Support boundary
Native Windows runs the dashboard, bounded regular-file intake, F32/F16/BF16 descriptive analysis, JSON detector inference, reference comparison, immutable storage/export and optional consent-gated Groq interpretation. Linux-only static scanner and demo isolation is not weakened or emulated. Unsupported workers remain explicit coverage gaps. Native Windows is not full Linux feature parity or a Windows process sandbox.

## Executed validation
Implementation revision: `afe2837f68d6f37c6e397b87f593a593f5c7cbc2` (the documentation-completion revision follows it).

[GitHub workflow 40458641786](https://github.com/nakulmaurya/T04-Scnr/actions/runs/40458641786) completed successfully:

| Runner | Python | Result |
| --- | --- | --- |
| Native `windows-latest` | 3.11 | Ruff passed; 329 tests + 91 subtests passed; 31 intentional skips; PowerShell launcher diagnostics passed |
| Native `windows-latest` | 3.13 | Ruff passed; 329 tests + 91 subtests passed; 31 intentional skips; PowerShell launcher diagnostics passed |
| `ubuntu-latest` | 3.11 | Lint and full regression job passed |
| `ubuntu-latest` | 3.13 | Ruff passed; 345 tests + 91 subtests passed; 15 intentional skips |
| Provisioned Debian CPU VM | 3.13 | Ruff and dependency consistency passed; 348 tests + 91 subtests passed; 12 Windows-only skips |

Windows tests executed the real Win32 adapter: binary bytes/hash preservation; rejection of UNC/device paths, alternate streams and parent junctions; denial of concurrent writes; handle cleanup; scan/reference/save/PDF integration; disabled unsupported-worker controls; no demo downloads/subprocesses; local-state defaults; and PowerShell diagnostics/invalid-port rejection. Dashboard rendering used Streamlit AppTest. This is native runner evidence, not only mocked platform values.

The Windows skips comprise Linux-specific process/FIFO/seccomp/Bash contracts, installed-Picklescan disassembly tests and three optional CPU torch tests. The Ubuntu jobs retain Linux isolation checks; their skips comprise twelve native-Windows cases and three optional torch tests. The provisioned VM has those optional dependencies and skips only native-Windows cases. Skips are not claimed as passes or feature support.

## Cross-platform test-harness corrections
The initial native run exposed two fixture assumptions. TLS transport tests now construct a real verifying SSL context before clearing the process environment, avoiding Windows certificate-store environment dependencies inside tiny mocked transport deadlines. The UI network tripwire permits only literal loopback connects needed by Windows asyncio's socketpair; external addresses/DNS names and `socket.create_connection` remain blocked and have an explicit regression. Production TLS verification, fixed endpoint, consent, numerical/card validation and deadlines are unchanged.

## Reproduction and limits
Follow [WINDOWS.md](WINDOWS.md) for native commands and capability details. CI creates a native virtual environment, installs development dependencies, runs Ruff/full pytest and invokes the PowerShell launcher in diagnostic mode. No API keys, provider calls, checkpoint downloads or unsafe uploaded-model execution are required. Hosted-provider responses in tests are mocked; this update does not assert a new live-provider success.

Historical v0.4.2 submission reports remain historical records. They do not silently acquire Windows coverage. Later commits and the promoted main branch have their own runs on the repository's Actions page.
