#!/usr/bin/env python3
"""Explicit retrieval only: python scripts/prepare_demos.py --demo-id ... --opt-in."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stegogate.demo import get_demo_catalog, prepare_demo


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--demo-id", choices=[x["demo_id"] for x in get_demo_catalog()], action="append", required=True
    )
    p.add_argument("--root", type=Path, default=Path("data/demo"))
    p.add_argument("--opt-in", action="store_true", required=True)
    p.add_argument("--download-test-data", action="store_true")
    a = p.parse_args()
    results = [
        prepare_demo(d, a.root, {"opt_in": a.opt_in, "download_test_data": a.download_test_data})
        for d in a.demo_id
    ]
    print(json.dumps(results, indent=2))
    return int(any(r["status"] != "completed" for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
