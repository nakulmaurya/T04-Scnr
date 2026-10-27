"""Explicit CLI separates static artifact scanning from allowlisted demo execution."""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path


def _print(value):
    print(json.dumps(value, indent=2, allow_nan=False))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="T04-Scnr CPU — research artifact forensics")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Static scan; never executes model code")
    scan.add_argument("artifact", type=Path)
    scan.add_argument("--reference", type=Path)
    scan.add_argument("--no-static", action="store_true", help="Explicitly skip ModelAudit and Picklescan")
    scan.add_argument("--max-windows", type=int, default=128)
    scan.add_argument("--window-elements", type=int, default=4096)
    scan.add_argument("--save", action="store_true", help="Persist immutable report in app storage")
    commands.add_parser("doctor", help="Inspect CPU environment and optional tools")
    commands.add_parser("reports", help="List app-owned saved report summaries")
    demo = commands.add_parser("demo", help="Allowlisted research artifact preparation/verification")
    demo.add_argument("action", choices=["catalog", "prepare", "verify"])
    demo.add_argument("demo_id", nargs="?")
    demo.add_argument("--sample-count", type=int, default=100)
    demo.add_argument(
        "--download-test-data",
        action="store_true",
        help="Explicitly fetch pinned MNIST test files during preparation",
    )
    pdf = commands.add_parser("report-pdf", help="Build a detailed local PDF from a saved report")
    pdf.add_argument("scan_id")
    pdf.add_argument("--output", required=True, type=Path)
    pdf.add_argument("--offline-appendix", action="store_true")
    explain = commands.add_parser("explain", help="Interpret a saved report; offline by default")
    explain.add_argument("scan_id")
    explain.add_argument("--groq", action="store_true")
    explain.add_argument("--consent-cloud", action="store_true")
    explain.add_argument(
        "--model", choices=["openai/gpt-oss-20b", "openai/gpt-oss-120b"], default="openai/gpt-oss-20b"
    )
    explain.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            from .pipeline import scan_artifact
            from .storage import save_report

            report = scan_artifact(
                args.artifact,
                reference_path=args.reference,
                config={
                    "run_static": not args.no_static,
                    "max_windows": args.max_windows,
                    "window_elements": args.window_elements,
                },
            )
            if args.save:
                save_report(report)
            _print(report)
            return 2 if report["status"] == "rejected" else 0
        if args.command == "report-pdf":
            from .storage import load_report
            from .pdf_report import build_pdf
            from .explanation import offline_explanation

            report = load_report(args.scan_id)
            appendix = offline_explanation(report) if args.offline_appendix else None
            payload = build_pdf(report, explanation=appendix)
            with args.output.open("xb") as target:
                target.write(payload)
            _print(
                {
                    "status": "completed",
                    "output": str(args.output),
                    "bytes": len(payload),
                    "cloud_request": False,
                }
            )
            return 0
        if args.command == "explain":
            from .storage import load_report
            from .explanation import offline_explanation, explain_with_groq

            report = load_report(args.scan_id)
            result = (
                explain_with_groq(report, consent=args.consent_cloud, model=args.model)
                if args.groq
                else offline_explanation(report)
            )
            if args.output:
                with args.output.open("x") as target:
                    json.dump(result, target, indent=2, allow_nan=False)
                    target.write("\n")
            else:
                _print(result)
            return 0 if result.get("status") == "completed" else 2
        if args.command == "doctor":
            import importlib.metadata
            import platform
            import shutil

            packages = {}
            for name in [
                "t04-scnr",
                "numpy",
                "scipy",
                "scikit-learn",
                "safetensors",
                "streamlit",
                "modelaudit",
                "picklescan",
                "reportlab",
                "torch",
                "torchvision",
                "transformers",
            ]:
                try:
                    packages[name] = importlib.metadata.version(name)
                except importlib.metadata.PackageNotFoundError:
                    packages[name] = None
            from .explanation import get_api_status

            _print(
                {
                    "groq": get_api_status(),
                    "python": platform.python_version(),
                    "device": "cpu",
                    "packages": packages,
                    "modelaudit_executable": shutil.which("modelaudit"),
                    "note": "Default scan does not import torch or execute artifact code. The ModelAudit adapter uses an interpreter module bootstrap; a CLI on PATH is not required.",
                }
            )
            return 0
        if args.command == "reports":
            from .storage import list_reports

            _print(list_reports())
            return 0
        if args.command == "demo":
            from .demo import get_demo_catalog, prepare_demo, verify_behavior
            from .storage import data_root

            if args.action == "catalog":
                _print(get_demo_catalog())
                return 0
            if not args.demo_id:
                parser.error("demo_id is required for prepare/verify")
            root = data_root() / "demo"
            if args.action == "prepare":
                _print(
                    prepare_demo(
                        args.demo_id,
                        root=root,
                        config={"opt_in": True, "download_test_data": args.download_test_data},
                    )
                )
            else:
                _print(
                    verify_behavior(
                        args.demo_id, root=root, config={"opt_in": True, "sample_count": args.sample_count}
                    )
                )
            return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
