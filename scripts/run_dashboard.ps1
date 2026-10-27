# Native Windows launcher. No activation, Bash, key files or administrator rights required.
[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $project
$python = Join-Path $project '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Virtual environment missing. Run: python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e .'
}
if (-not $env:STEGOGATE_DATA_DIR) {
    if ($env:LOCALAPPDATA) { $env:STEGOGATE_DATA_DIR = Join-Path $env:LOCALAPPDATA 'T04-Scnr\runtime' }
    else { $env:STEGOGATE_DATA_DIR = Join-Path $project 'data\runtime' }
}
if (-not $env:STEGOGATE_PORT) { $env:STEGOGATE_PORT = '8501' }
$port = 0
if (-not [int]::TryParse($env:STEGOGATE_PORT, [ref]$port) -or $port -lt 1024 -or $port -gt 65535) {
    throw 'STEGOGATE_PORT must be an integer from 1024 to 65535.'
}
$env:PYTHONUTF8 = '1'
$env:CUDA_VISIBLE_DEVICES = ''
if (-not $env:OMP_NUM_THREADS) { $env:OMP_NUM_THREADS = '4' }
if (-not $env:MKL_NUM_THREADS) { $env:MKL_NUM_THREADS = '4' }
# GROQ_API_KEY is used only if explicitly present in this process environment.
# Do not source .env, read a POSIX key file, print secrets or invoke a shell string.
if ($Check) {
    & $python -m stegogate.cli doctor
} else {
    & $python -m streamlit run (Join-Path $project 'app.py') --server.address 127.0.0.1 --server.port $port --server.headless true --server.maxUploadSize 256 --browser.gatherUsageStats false
}
exit $LASTEXITCODE
