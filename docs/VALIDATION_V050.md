# v0.5.0 Windows support validation

## Intended support boundary
Native Windows runs the UI, bounded regular-file intake, F32/F16/BF16 descriptive analysis, JSON detector inference, reference comparison, storage/export and optional consent-gated Groq interpretation. Linux-only static scanner and demo isolation is not weakened or emulated. Unsupported workers are explicit gaps.

## Validation record
Native GitHub-hosted Windows and Ubuntu Python 3.11/3.13 jobs are required before promotion. Linux-only FIFO/process/seccomp/Bash tests remain in Linux CI; Windows-specific Win32 intake, junction/device/ADS rejection, process-peak telemetry, unavailable-worker and PowerShell tests run on Windows. Optional missing dependency skips are disclosed separately. A Linux-only mock is not evidence of native Windows execution.

Final job results, VM regression counts and promotion checks are recorded after execution. This record must not be interpreted as a passed result before those entries are present. No credentials or checkpoint downloads are required for CI.
