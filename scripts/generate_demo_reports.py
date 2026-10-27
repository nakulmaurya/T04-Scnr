"""Generate evidence reports from already prepared fixed local demo artifacts.

No downloads, training, or model execution. Ground-truth names are display-only.
"""

from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stegogate.pipeline import scan_artifact
from stegogate.storage import data_root, save_report


def main():
    root = data_root()
    jobs = []
    for identifier in ("mnist-epoch01", "mnist-epoch02", "cifar10-resnet18"):
        path = root / "demo" / identifier / "model.safetensors"
        if path.is_file():
            ref = (
                root / "demo" / "mnist-epoch01" / "model.safetensors"
                if identifier == "mnist-epoch02"
                else None
            )
            jobs.append((path, identifier + ".safetensors", ref, True))
    for lineage in (
        "authentrics-mnist-ancestry",
        "hugo0076-cifar-resnet-ancestry",
        "google-mobilenet-v2-ancestry",
    ):
        folder = root / "benchmark" / lineage
        for variant in ("no_added_payload", "text", "seeded_random"):
            path = folder / f"{variant}.safetensors"
            if path.is_file():
                ref = folder / "no_added_payload.safetensors" if variant != "no_added_payload" else None
                jobs.append((path, f"{lineage}--{variant}.safetensors", ref, False))
    results = []
    for path, name, ref, run_static in jobs:
        report = scan_artifact(
            path, reference_path=ref, config={"run_static": run_static, "original_name": name}
        )
        save_report(report)
        results.append(
            {
                "name": name,
                "scan_id": report["scan_id"],
                "status": report["status"],
                "verdict": report["verdict"],
                "summary": report["summary"],
                "duration_seconds": report["runtime"]["duration_seconds"],
                "static_status": report["static_analysis"]["status"],
                "ml_status": report["ml_analysis"]["status"],
            }
        )
        print(json.dumps(results[-1]), flush=True)
    (root / "demo_scan_index.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
