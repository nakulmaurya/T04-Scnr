#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Optional private Groq key: never source/execute its contents or echo it.
keyfile="$HOME/.config/stegogate/groq.key"
if [ -z "${GROQ_API_KEY:-}" ] && [ -e "$keyfile" ]; then
    if [ ! -L "$keyfile" ] && [ -f "$keyfile" ] && [ "$(stat -c %s "$keyfile")" -le 1024 ] && [ "$(stat -c %u "$keyfile")" = "$(id -u)" ] && { [ "$(stat -c %a "$keyfile")" = "600" ] || [ "$(stat -c %a "$keyfile")" = "400" ]; }; then
        GROQ_API_KEY="$(cat "$keyfile")"
        export GROQ_API_KEY
    else
        printf '%s\n' 'Groq key file ignored: require owned regular non-symlink mode 600 or 400.' >&2
    fi
fi
export CUDA_VISIBLE_DEVICES=""
export STEGOGATE_DATA_DIR="${STEGOGATE_DATA_DIR:-$PWD/data/runtime}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-4}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-4}"
exec .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --server.port "${STEGOGATE_PORT:-8501}" --server.headless true --server.maxUploadSize 256 --browser.gatherUsageStats false
