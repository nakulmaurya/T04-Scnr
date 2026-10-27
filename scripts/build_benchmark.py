#!/usr/bin/env python3
"""Explicit preparation: real F32 sources + harmless low-mantissa-byte variants.

No model execution, unsafe deserialization, automatic online tuning, or malware.
Three ancestry groups give a mechanics demonstration, not a population estimate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stegogate.intake import inspect_artifact
from stegogate.features import analyze_weights
from stegogate.ml import _metrics, score_windows, train_detector
from stegogate.storage import data_root

MOBILE_REPO = "google/mobilenet_v2_1.0_224"
MOBILE_REV = "75e607b00aeae1297cc89d026a118bce012f5c5a"
MOBILE_SHA = "94f61c6902b411e6b730cfe2443c8b2d983a2d50d289c4bd7083e0583ccdfe76"
MOBILE_SIZE = 14199388
MAX_BYTES = 256 * 1024 * 1024
SEED = 42
TEXT = b"STEGOGATE HARMLESS TEXT DEMONSTRATION. NOT EXECUTABLE. CONTROLLED PAYLOAD. "
SCANNING = {"max_windows": 128, "window_elements": 4096, "min_window_elements": 32}
SCOPE = "Exploratory controlled low-mantissa-byte manipulation of three actual source checkpoints. NOT arbitrary malware/backdoor detection or a safety assessment."
SOURCES = [
    {
        "lineage": "authentrics-mnist-ancestry",
        "repository": "authentrics/mnist-badnets-poisoned",
        "revision": "42b52757ec703365710e27865c8fe57e9db35a4d",
        "relative_path": "mnist-epoch01/model.safetensors",
        "sha256": "88ebce334a81ad59fe59dc809165f25ba2ff3520bfd3701ba644dfe1720a78bf",
        "original_file": "epoch_01.pt",
        "original_sha256": "6c0b5fe0c5f794678020292d2184b84029527e3fff86a62a3571dacb75ae117d",
        "notes": "Preceding epoch checkpoint from a backdoor-training source; converted by separate reviewed preparation. Not a pristine/safe control; no torch loading here.",
    },
    {
        "lineage": "hugo0076-cifar-resnet-ancestry",
        "repository": "hugo0076/cifar10-badnets-backdoor-resnet18",
        "revision": "b68ac7c29824b0eef7d38176eb5e19cfde20c4c6",
        "relative_path": "cifar10-resnet18/model.safetensors",
        "sha256": "f8389e3312359d4db7d6cbd7a999e3bc9213092d7abb2ce002f3ea88fc79e161",
        "notes": "Published backdoored ResNet source; baseline means no added benchmark payload, NEVER backdoor-free.",
    },
    {
        "lineage": "google-mobilenet-v2-ancestry",
        "repository": MOBILE_REPO,
        "revision": MOBILE_REV,
        "sha256": MOBILE_SHA,
        "notes": "Published MobileNet source; no added benchmark payload does not certify safety. Hub card license is 'other'; review upstream license before redistribution.",
    },
]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def fetch_mobile(directory, allow_network):
    path = directory / "mobilenet-v2.safetensors"
    if path.exists():
        if path.stat().st_size != MOBILE_SIZE or digest(path) != MOBILE_SHA:
            raise ValueError("cached pinned MobileNet identity mismatch")
        return path
    if not allow_network:
        raise ValueError(
            "pinned MobileNet missing; explicit --fetch-mobilenet is required for network preparation"
        )
    metadata_url = f"https://huggingface.co/api/models/{MOBILE_REPO}/revision/{MOBILE_REV}?blobs=true"
    with urllib.request.urlopen(metadata_url, timeout=60) as response:
        metadata_raw = response.read(4 * 1024 * 1024 + 1)
    if len(metadata_raw) > 4 * 1024 * 1024:
        raise ValueError("upstream metadata exceeds bound")
    metadata = json.loads(metadata_raw)
    entries = [x for x in metadata.get("siblings", []) if x.get("rfilename") == "model.safetensors"]
    if metadata.get("sha") != MOBILE_REV or len(entries) != 1:
        raise ValueError("upstream source revision mismatch")
    entry = entries[0]
    if entry.get("size") != MOBILE_SIZE or entry.get("lfs", {}).get("sha256") != MOBILE_SHA:
        raise ValueError("upstream LFS metadata identity mismatch")
    write_json(directory / "mobilenet-source-metadata.json", metadata)
    url = f"https://huggingface.co/{MOBILE_REPO}/resolve/{MOBILE_REV}/model.safetensors"
    temporary = path.with_suffix(".part")
    size = 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open("xb") as f:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MOBILE_SIZE:
                    raise ValueError("upstream download exceeds pinned size")
                f.write(chunk)
        if size != MOBILE_SIZE or digest(temporary) != MOBILE_SHA:
            raise ValueError("MobileNet download hash/size mismatch")
        temporary.rename(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def mutate_copy(source, target, kind, seed):
    """Only replace mantissa bits 0..7, preserving header/exponent/sign."""
    import numpy as np

    inventory = inspect_artifact(source)
    if inventory["errors"] or inventory["format"] != "safetensors":
        raise ValueError("source inventory invalid: " + str(inventory["errors"]))
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("source exceeds 256 MiB")
    with source.open("rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    changed = eligible = 0
    rng = np.random.default_rng(seed)
    stream_offset = 0
    with target.open("r+b") as f:
        for tensor in sorted(inventory["tensors"], key=lambda t: t["name"]):
            if tensor["dtype"] != "F32":
                continue
            absolute = inventory["data_start"] + tensor["data_offsets"][0]
            for start in range(0, tensor["numel"], 262144):
                n = min(262144, tensor["numel"] - start)
                f.seek(absolute + 4 * start)
                words = np.frombuffer(f.read(4 * n), dtype="<u4").copy()
                if len(words) != n:
                    raise ValueError("truncated source")
                if kind == "text":
                    pattern = np.frombuffer(TEXT, dtype=np.uint8)
                    payload = pattern[(np.arange(n) + stream_offset) % len(pattern)].astype(np.uint32)
                elif kind == "seeded_random":
                    payload = rng.integers(0, 256, size=n, dtype=np.uint32)
                else:
                    raise ValueError("unknown harmless variant")
                stream_offset += n
                modified = (words & np.uint32(0xFFFFFF00)) | payload
                # Independent bit-level invariant: no exponent/sign/high mantissa changes.
                if np.any(((modified ^ words) & np.uint32(0xFFFFFF00)) != 0):
                    raise AssertionError("mutation exceeded low-byte scope")
                changed += int(np.count_nonzero(modified != words))
                eligible += n
                f.seek(absolute + 4 * start)
                f.write(modified.astype("<u4").tobytes())
    result = inspect_artifact(target)
    if result["errors"]:
        raise ValueError("generated safetensors failed structural validation")
    return {
        "bits": list(range(8)),
        "dtype": "F32",
        "coverage": "all F32 elements, other dtypes/header untouched",
        "kind": kind,
        "seed": seed if kind == "seeded_random" else None,
        "text_ascii": TEXT.decode() if kind == "text" else None,
        "eligible_f32_elements": eligible,
        "actually_changed_elements": changed,
        "exponent_sign_high_mantissa_preserved": True,
        "behavioral_equivalence": "not tested; even low-bit changes can affect behavior",
    }


def run(demo_root, fetch):
    root = data_root().resolve()
    bench = root / "benchmark"
    detector_dir = root / "detector"
    if bench.exists() or detector_dir.exists():
        raise ValueError(
            "benchmark/detector already exists; preserve prior evidence and use a new STEGOGATE_DATA_DIR"
        )
    bench.mkdir(parents=True)
    sources_dir = bench / "sources"
    sources_dir.mkdir()
    manifest = {
        "schema_version": "1.0",
        "status": "preparing",
        "scope": SCOPE,
        "predeclared": {
            "split_seed": SEED,
            "threshold": 0.5,
            "threshold_selection": "fixed",
            "n_estimators": 64,
            "max_depth": 10,
            "min_samples_leaf": 2,
            "feature_sampling": SCANNING,
            "variants_per_source": ["no_added_payload", "text", "seeded_random"],
            "mutation_seed": 20261026,
        },
        "label_definitions": {
            "0": "no added controlled benchmark payload; NOT safe/backdoor-free",
            "1": "added harmless controlled low-byte payload",
        },
        "sources": [],
        "artifacts": [],
        "warnings": [
            "ONLY THREE INDEPENDENT SOURCE CHECKPOINTS. One lineage per train/validation/test partition. No population-generalization inference or meaningful cluster confidence interval is possible.",
            "Ancestry independence is based on distinct published architectures/source repositories; shared remote training-data influences are not ruled out.",
            "Model/window variants are correlated; hundreds of windows do not create hundreds of independent checkpoints.",
            "Seeded-random payload bytes are not encrypted. Near-random natural LSBs may make random payloads indistinguishable.",
            "Known-backdoor source status and added benchmark byte payload are different labels.",
            "Payload changes are non-executable data; no model inference or behavioral-preservation testing performed.",
            "Test evaluated once; no tuning, reseeding, family selection or retries based on performance.",
        ],
    }
    write_json(bench / "benchmark_manifest.json", manifest)
    try:
        mobile = fetch_mobile(sources_dir, fetch)
        rows = []
        provenance = []
        for spec in SOURCES:
            source = mobile if spec["repository"] == MOBILE_REPO else demo_root / spec["relative_path"]
            inv = inspect_artifact(source)
            if inv["errors"] or inv["sha256"] != spec["sha256"] or inv["size_bytes"] > MAX_BYTES:
                raise ValueError("pinned actual source identity/inventory mismatch: " + spec["lineage"])
            source_record = {
                **spec,
                "source_path": str(source),
                "size_bytes": inv["size_bytes"],
                "tensor_count": len(inv["tensors"]),
            }
            manifest["sources"].append(source_record)
            directory = bench / spec["lineage"]
            directory.mkdir()
            for variant in ("no_added_payload", "text", "seeded_random"):
                target = directory / (variant + ".safetensors")
                if variant == "no_added_payload":
                    with source.open("rb") as src, target.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
                    mutation = None
                    if digest(target) != spec["sha256"]:
                        raise ValueError("untouched copy hash mismatch")
                else:
                    mutation = mutate_copy(source, target, variant, 20261026)
                inventory = inspect_artifact(target)
                analysis = analyze_weights(target, inventory, SCANNING)
                if analysis["status"] not in ("completed", "partial") or not analysis["windows"]:
                    raise ValueError("no usable numeric features: " + str(target))
                label = int(variant != "no_added_payload")
                artifact = {
                    "artifact_id": f"{spec['lineage']}/{variant}",
                    "path": str(target),
                    "relative_path": str(target.relative_to(root)),
                    "lineage": spec["lineage"],
                    "variant": variant,
                    "label": label,
                    "sha256": inventory["sha256"],
                    "size_bytes": inventory["size_bytes"],
                    "mutation": mutation,
                    "coverage": analysis["coverage"],
                    "row_count": len(analysis["windows"]),
                }
                manifest["artifacts"].append(artifact)
                for window in analysis["windows"]:
                    row_index = len(rows)
                    rows.append(
                        {
                            "features": window["features"],
                            "label": label,
                            "lineage": spec["lineage"],
                            "variant": variant,
                        }
                    )
                    provenance.append(
                        {
                            "row_index": row_index,
                            "artifact_id": artifact["artifact_id"],
                            "tensor": window["tensor"],
                            "window_index": window["window_index"],
                            "element_start": window["element_start"],
                            "element_count": window["element_count"],
                        }
                    )
        with (bench / "rows.jsonl").open("x") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        with (bench / "row_provenance.jsonl").open("x") as f:
            for row in provenance:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        manifest["rows_sha256"] = digest(bench / "rows.jsonl")
        manifest["row_count"] = len(rows)
        # Data profile is computed before model fit; finite shape checked by trainer.
        manifest["profile"] = {
            "grain": "one deterministic sampled weight window of one artifact variant",
            "distinct_lineages": len({r["lineage"] for r in rows}),
            "distinct_feature_schemas": len({tuple(sorted(r["features"])) for r in rows}),
            "feature_count": len(rows[0]["features"]),
            "duplicate_numeric_rows_including_label": len(rows)
            - len({json.dumps([r["label"], r["features"]], sort_keys=True) for r in rows}),
            "missing_values": sum(v is None for r in rows for v in r["features"].values()),
            "duplicate_policy": "retain correlated/identical windows; all derivatives remain in one ancestry group",
        }
        result = train_detector(
            rows,
            detector_dir,
            {
                "seed": SEED,
                "n_estimators": 64,
                "max_depth": 10,
                "min_samples_leaf": 2,
                "threshold_selection": "fixed",
                "source_description": SCOPE
                + " Source hashes and mutation recipes: benchmark/benchmark_manifest.json; labels describe only added payloads, not source safety.",
            },
        )
        detector_manifest_path = detector_dir / "detector_manifest.json"
        detector_manifest = result["manifest"]
        detector_manifest["label_definitions"] = manifest["label_definitions"]
        detector_manifest["benchmark_manifest_relative_path"] = "benchmark/benchmark_manifest.json"
        write_json(detector_manifest_path, detector_manifest)
        manifest["split"] = detector_manifest["split"]
        manifest["window_evaluation"] = result["metrics"]
        artifact_summaries = []
        # Re-score for audit/aggregation only, never model selection or retraining.
        for artifact in manifest["artifacts"]:
            selected = [
                (r, p) for r, p in zip(rows, provenance) if p["artifact_id"] == artifact["artifact_id"]
            ]
            windows = [
                {"tensor": p["tensor"], "window_index": p["window_index"], "features": r["features"]}
                for r, p in selected
            ]
            scored = score_windows(windows, detector_dir / "detector.json")
            if scored["status"] != "completed":
                raise ValueError("artifact scoring failed: " + str(scored["warnings"]))
            mean_vote = sum(s["score"] for s in scored["scores"]) / len(scored["scores"])
            partition = next(k for k, groups in manifest["split"].items() if artifact["lineage"] in groups)
            artifact_summaries.append(
                {
                    "artifact_id": artifact["artifact_id"],
                    "lineage": artifact["lineage"],
                    "variant": artifact["variant"],
                    "partition": partition,
                    "label": artifact["label"],
                    "mean_window_vote": mean_vote,
                    "predicted_label": int(mean_vote >= 0.5),
                    "window_count": len(selected),
                }
            )
        manifest["artifact_summary"] = artifact_summaries
        manifest["artifact_group_evaluation"] = {
            partition: _metrics(
                [a["label"] for a in artifact_summaries if a["partition"] == partition],
                [a["mean_window_vote"] for a in artifact_summaries if a["partition"] == partition],
                0.5,
            )
            for partition in ("validation", "test")
        }
        manifest["artifact_group_evaluation_note"] = (
            "Mean-window-vote aggregation is predeclared in this script, NOT an independent checkpoint estimate: each partition has three correlated variants from exactly one source. Uncertainty/confidence intervals unavailable at the lineage level. Train scores are resubstitution only."
        )
        # Independent direct count/hash/split checks, not a metric-improvement loop.
        assert len(rows) == sum(a["row_count"] for a in manifest["artifacts"])
        assert len(rows) == sum(result["manifest"]["row_counts"].values())
        groups = [set(v) for v in manifest["split"].values()]
        assert all(not a & b for i, a in enumerate(groups) for b in groups[i + 1 :])
        test_rows = [r for r in rows if r["lineage"] in manifest["split"]["test"]]
        assert result["metrics"]["test"]["class_support"]["1"] == sum(r["label"] == 1 for r in test_rows)
        manifest["independent_checks"] = (
            "row totals, class support, pinned hashes, and lineage disjointness verified"
        )
        manifest["detector_sha256"] = digest(detector_dir / "detector.json")
        manifest["status"] = "completed"
        write_json(bench / "benchmark_manifest.json", manifest)
        return {
            "status": "completed",
            "benchmark_manifest": str(bench / "benchmark_manifest.json"),
            "detector_path": str(detector_dir / "detector.json"),
            "rows": len(rows),
            "sources": len(SOURCES),
            "scope": SCOPE,
            "warnings": manifest["warnings"],
            "test_window_metrics": result["metrics"]["test"],
            "test_artifact_metrics": manifest["artifact_group_evaluation"]["test"],
        }
    except Exception as e:
        manifest.update(status="failed", error=f"{type(e).__name__}: {str(e)[:500]}")
        write_json(bench / "benchmark_manifest.json", manifest)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-root", type=Path, default=Path("data/demo"))
    parser.add_argument(
        "--fetch-mobilenet", action="store_true", help="explicit opt-in pinned HF metadata+weight retrieval"
    )
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.demo_root.resolve(), args.fetch_mobilenet), indent=2, allow_nan=False))
    except Exception as e:
        print(
            json.dumps({"status": "failed", "error": f"{type(e).__name__}: {str(e)[:500]}"}), file=sys.stderr
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
