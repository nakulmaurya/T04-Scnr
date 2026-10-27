#!/usr/bin/env python3
"""Train the CPU controlled-manipulation RF from bounded JSON/JSONL rows."""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stegogate.ml import MAX_ROWS, _pairs, _reject_constant, train_detector

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024


def load_rows(path: Path) -> list[dict]:
    # Stream JSONL; bound JSON arrays before parsing. Duplicate keys are errors.
    kwargs = {"object_pairs_hook": _pairs, "parse_constant": _reject_constant}
    if path.suffix.lower() == ".jsonl":
        rows, total = [], 0
        with path.open("rb") as f:
            while True:
                line = f.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > MAX_LINE_BYTES or total > MAX_INPUT_BYTES:
                    raise ValueError("JSONL input exceeds byte limits")
                if line.strip():
                    rows.append(json.loads(line, **kwargs))
                    if len(rows) > MAX_ROWS:
                        raise ValueError("input exceeds row limit")
        return rows
    with path.open("rb") as f:
        raw = f.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("JSON input exceeds byte limit")
    rows = json.loads(raw, **kwargs)
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("JSON input must be a bounded row array")
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Exploratory hidden-byte manipulation detection only; not malware/backdoor probability. Output must be a new directory under STEGOGATE_DATA_DIR.",
    )
    parser.add_argument("input", type=Path, help="rows .json array or .jsonl (64 MiB maximum)")
    parser.add_argument("output", type=Path, help="new app-owned detector version directory")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=64)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--min-samples-leaf", type=int, default=2)
    parser.add_argument(
        "--threshold-selection",
        choices=("fixed", "validation_f1"),
        default="fixed",
        help="optional validation-only F1 tuning; fixed 0.5 by default",
    )
    parser.add_argument(
        "--source-description",
        default="Caller-supplied controlled-manipulation rows; provenance not independently verified.",
    )
    args = parser.parse_args(argv)
    try:
        result = train_detector(
            load_rows(args.input),
            args.output,
            {
                "threshold_selection": args.threshold_selection,
                "seed": args.seed,
                "n_estimators": args.n_estimators,
                "max_depth": args.max_depth,
                "min_samples_leaf": args.min_samples_leaf,
                "source_description": args.source_description,
            },
        )
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return 0
    except (ValueError, OSError, RuntimeError, TypeError, RecursionError) as e:
        print(
            json.dumps({"status": "failed", "error": f"{type(e).__name__}: {str(e)[:500]}"}), file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
