#!/usr/bin/env python3
"""Explicit CPU/offline known-trigger reproduction; no automatic dataset retrieval."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stegogate.demo import get_demo_catalog, verify_behavior


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--demo-id", choices=[x["demo_id"] for x in get_demo_catalog()], action="append", required=True
    )
    p.add_argument("--root", type=Path, default=Path("data/demo"))
    p.add_argument("--opt-in", action="store_true", required=True)
    p.add_argument("--samples", type=int, default=10000)
    p.add_argument("--timeout", type=float, default=180)
    a = p.parse_args()
    results = [
        verify_behavior(
            d, a.root, {"opt_in": a.opt_in, "sample_count": a.samples, "timeout_seconds": a.timeout}
        )
        for d in a.demo_id
    ]
    print(json.dumps(results, indent=2))
    return int(any(r["status"] not in ("completed", "not_verified") for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
