#!/usr/bin/env python3
"""Two-phase predeclared research benchmark. CPU only, no model execution.

prepare writes immutable rows; fit refuses without a profile file and never
replaces an existing detector. The original benchmark/detector stay untouched.
"""

from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import shutil
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_benchmark import digest, mutate_copy, write_json, SCANNING
from stegogate.intake import inspect_artifact
from stegogate.features import analyze_weights
from stegogate.ml import train_detector, score_windows, _metrics
from stegogate.storage import data_root

POLICY = Path(__file__).resolve().parents[1] / "docs/benchmark_v2_policy.json"
POLICY_SHA = "68451d7f5a75622733d9031771eaccde6f5301157c783be86f706a8b161d825c"


def policy():
    if digest(POLICY) != POLICY_SHA:
        raise ValueError("predeclared policy changed")
    return json.loads(POLICY.read_text())


def fetch(spec, target, allow_network):
    if target.exists():
        if target.stat().st_size != spec["size"] or digest(target) != spec["sha256"]:
            raise ValueError("cache identity mismatch")
        return
    if not allow_network:
        raise ValueError("explicit --allow-network required for missing public source")
    url = f"https://huggingface.co/{spec['repository']}/resolve/{spec['revision']}/model.safetensors"
    part = target.with_suffix(".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as src, part.open("xb") as dst:
            total = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > spec["size"]:
                    raise ValueError("source exceeds pinned size")
                dst.write(chunk)
        if total != spec["size"] or digest(part) != spec["sha256"]:
            raise ValueError("source hash mismatch")
        part.rename(target)
    finally:
        part.unlink(missing_ok=True)


def prepare(allow_network=False):
    p = policy()
    root = data_root()
    out = root / "benchmark-v2"
    out.mkdir(exist_ok=False)
    write_json(out / "predeclared_policy.json", p)
    rawdir = out / "sources"
    rawdir.mkdir()
    rows = []
    provenance = []
    artifacts = []
    # Existing original baseline files are reused read-only, no relabeling as safe.
    old = root / "benchmark"
    for spec in p["sources"]:
        lineage = spec["lineage"]
        if "size" in spec:
            source = rawdir / (lineage + ".safetensors")
            fetch(spec, source, allow_network)
        else:
            source = old / lineage / "no_added_payload.safetensors"
        inv = inspect_artifact(source)
        if inv["errors"] or inv["sha256"] != spec["sha256"]:
            raise ValueError("invalid source " + lineage)
        directory = out / lineage
        directory.mkdir()
        for variant in p["variants"]:
            target = directory / (variant + ".safetensors")
            if variant == "no_added_payload":
                with source.open("rb") as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                mutation = None
            else:
                mutation = mutate_copy(source, target, variant, p["mutation_seed"])
            inv = inspect_artifact(target)
            analysis = analyze_weights(target, inv, SCANNING)
            if inv["errors"] or not analysis["windows"]:
                raise ValueError("no eligible F32 windows " + lineage)
            aid = lineage + "/" + variant
            artifacts.append(
                dict(
                    artifact_id=aid,
                    lineage=lineage,
                    variant=variant,
                    label=int(variant != "no_added_payload"),
                    sha256=inv["sha256"],
                    relative_path=str(target.relative_to(root)),
                    mutation=mutation,
                    coverage=analysis["coverage"],
                )
            )
            for w in analysis["windows"]:
                provenance.append(
                    dict(
                        row_index=len(rows),
                        artifact_id=aid,
                        tensor=w["tensor"],
                        window_index=w["window_index"],
                    )
                )
                rows.append(
                    dict(
                        features=w["features"],
                        label=int(variant != "no_added_payload"),
                        lineage=lineage,
                        variant=variant,
                    )
                )
    for name, records in [("rows.jsonl", rows), ("row_provenance.jsonl", provenance)]:
        with (out / name).open("x") as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True, allow_nan=False) + "\n")
    with (out / "profile_input.csv").open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["lineage", "variant", "label"] + list(rows[0]["features"]))
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in ("lineage", "variant", "label")} | r["features"])
    write_json(
        out / "preparation.json",
        dict(
            status="prepared",
            policy_sha256=POLICY_SHA,
            rows_sha256=digest(out / "rows.jsonl"),
            row_count=len(rows),
            artifacts=artifacts,
            profile=dict(
                missing_values=sum(v is None for r in rows for v in r["features"].values()),
                duplicate_numeric_rows=len(rows)
                - len({json.dumps(r["features"], sort_keys=True) for r in rows}),
                duplicate_policy=p["duplicate_policy"],
            ),
        ),
    )
    print(json.dumps(dict(status="prepared", rows=len(rows), artifacts=len(artifacts))))


def fit():
    p = policy()
    root = data_root()
    out = root / "benchmark-v2"
    detector = root / "detector-v2"
    preparation = json.loads((out / "preparation.json").read_text())
    if digest(out / "rows.jsonl") != preparation["rows_sha256"]:
        raise ValueError("rows changed")
    profile = out / "data_profile.txt"
    if not profile.is_file() or profile.stat().st_size < 100:
        raise ValueError("run and inspect the dataset profile before fitting")
    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    cfg = p["hyperparameters"] | dict(
        seed=p["seed"],
        threshold_selection="fixed",
        lineage_partition=p["lineage_partition"],
        source_description="Predeclared nine published parameter groups. Harmless low-byte mutations, NOT arbitrary backdoor/malware detection. benchmark-v2/predeclared_policy.json",
    )
    result = train_detector(rows, detector, cfg)
    # Record honest label semantics; no repeat fitting or threshold selection.
    manifest = result["manifest"]
    manifest["label_definitions"] = {"0": p["label0"], "1": "added harmless controlled low-byte payload"}
    manifest["benchmark_manifest_relative_path"] = "benchmark-v2/preparation.json"
    write_json(detector / "detector_manifest.json", manifest)
    provenance = [json.loads(line) for line in (out / "row_provenance.jsonl").read_text().splitlines()]
    windows = [dict(tensor=str(i), window_index=0, features=r["features"]) for i, r in enumerate(rows)]
    scores = score_windows(windows, detector / "detector.json")
    if scores["status"] != "completed":
        raise ValueError("JSON inference audit failed")
    groups = {k: set(v) for k, v in p["lineage_partition"].items()}
    matrix = [[0, 0], [0, 0]]
    per_artifact = []
    for r, s in zip(rows, scores["scores"]):
        if r["lineage"] in groups["test"]:
            matrix[r["label"]][s["predicted_label"]] += 1
    assert matrix == result["metrics"]["test"]["confusion_matrix"]
    for a in preparation["artifacts"]:
        values = [
            s["score"]
            for s, prov in zip(scores["scores"], provenance)
            if prov["artifact_id"] == a["artifact_id"]
        ]
        mean = sum(values) / len(values)
        partition = next(k for k, v in groups.items() if a["lineage"] in v)
        per_artifact.append(
            {k: a[k] for k in ("artifact_id", "lineage", "variant", "label")}
            | dict(partition=partition, mean_vote=mean, predicted_label=int(mean >= 0.5))
        )
    group_metrics = {
        k: _metrics(
            [a["label"] for a in per_artifact if a["partition"] == k],
            [a["mean_vote"] for a in per_artifact if a["partition"] == k],
            0.5,
        )
        for k in ("validation", "test")
    }
    per_lineage = {
        lineage: dict(
            artifacts=sum(a["lineage"] == lineage for a in per_artifact),
            errors=sum(a["label"] != a["predicted_label"] for a in per_artifact if a["lineage"] == lineage),
        )
        for lineage in groups["test"]
    }
    evidence = dict(
        status="completed",
        policy_sha256=POLICY_SHA,
        profile_sha256=digest(profile),
        rows_sha256=preparation["rows_sha256"],
        row_count=len(rows),
        metrics=result["metrics"],
        artifact_metrics=group_metrics,
        artifacts=per_artifact,
        heldout_lineage_errors=per_lineage,
        audit=dict(independent_test_confusion_matrix=matrix, whole_lineage_disjoint=True),
        limitations=[
            "Only two new held-out lineages; exploratory, not population generalization.",
            "Distinct published parameter ancestry is caller-asserted, not audited training genealogy.",
            "Correlated windows and variants are not independent model observations.",
            "No source is certified safe, no inference performed, unknown-trigger backdoors not detected.",
            "Original v1 results and default detector preserved; metrics across versions not directly comparable.",
        ],
    )
    write_json(out / "evaluation.json", evidence)
    print(
        json.dumps(
            dict(
                status="completed",
                rows=len(rows),
                test_confusion=matrix,
                artifact_test_confusion=group_metrics["test"]["confusion_matrix"],
            )
        )
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["prepare", "fit"])
    ap.add_argument("--allow-network", action="store_true")
    args = ap.parse_args()
    if args.action == "prepare":
        prepare(args.allow_network)
    else:
        fit()
