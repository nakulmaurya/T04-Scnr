"""Synthetic evidence only: exporter tests do not scan or load any model."""

import copy
import hashlib
import io
import json
import socket
from pathlib import Path
from unittest.mock import patch

import unittest
import tempfile
from functools import wraps


from pypdf import PdfReader

from stegogate.pdf_report import (
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_PAGES,
    MAX_ROWS,
    build_pdf,
)


def cases(names, values):
    names = [n.strip() for n in names.split(",")]

    def decorate(fn):
        @wraps(fn)
        def wrapped(self):
            for value in values:
                args = value if len(names) > 1 else (value,)
                with self.subTest(**dict(zip(names, args))):
                    fn(self, *args)

        return wrapped

    return decorate


def synthetic_report():
    """Deliberately synthetic values; no actual scan or benchmark claim."""
    return {
        "schema_version": "1.1",
        "scan_id": "SYNTHETIC-FIXTURE-NOT-A-SCAN",
        "created_at": "2026-10-27T00:00:00Z",
        "status": "partial",
        "verdict": "SYNTHETIC REVIEW REQUIRED",
        "artifact": {
            "original_name": "synthetic.safetensors",
            "sha256": "a" * 64,
            "format": "safetensors",
            "size_bytes": 8192,
        },
        "config": {"run_static": True, "max_windows": 2},
        "runtime": {
            "device": "cpu",
            "duration_seconds": 1.25,
            "peak_rss_mb": 50,
            "rss_scope": "process high-water mark",
        },
        "summary": {"analyzed_window_count": 2, "tensor_count": 1},
        "intake": {
            "sha256": "a" * 64,
            "errors": [],
            "tensors": [{"name": "synthetic.weight", "dtype": "F32", "numel": 2048, "shape": [2048]}],
        },
        "static_analysis": {
            "status": "completed",
            "engine_version": "synthetic",
            "findings": [{"rule": "SYNTHETIC_RULE", "message": "Synthetic rule fixture"}],
        },
        "picklescan_analysis": {
            "status": "not_applicable",
            "findings": [],
            "warnings": ["Synthetic fixture"],
        },
        "weight_analysis": {
            "status": "partial",
            "coverage": {
                "total_f32_elements": 2048,
                "sampled_elements": 1024,
                "windows_analyzed": 2,
                "rejected_windows": 1,
            },
            "tensor_summaries": [{"tensor": "synthetic.weight", "windows": 2}],
            "windows": [
                {
                    "tensor": "synthetic.weight",
                    "window_index": i,
                    "element_start": i * 512,
                    "element_count": 512,
                    "anomaly_score": 0.4,
                    "evidence": ["Synthetic heuristic"],
                    "features": {"low_byte_entropy": 7.1, "mean": 0.01},
                }
                for i in range(2)
            ],
        },
        "precision_analysis": {
            "status": "partial",
            "windows": [
                {
                    "tensor": "synthetic.half",
                    "dtype": "F16",
                    "mantissa_bits": 10,
                    "features": {"low_byte_entropy": 4.5},
                },
                {"tensor": "synthetic.bfloat", "dtype": "BF16", "mantissa_bits": 7},
            ],
            "coverage": {"total_half_elements": 100, "unique_sampled_elements": 50},
        },
        "ml_analysis": {
            "status": "completed",
            "manifest": {
                "detector_sha256": "b" * 64,
                "threshold": 0.65,
                "scope": "Synthetic controlled manipulation fixture",
                "evaluation": {"test": {"accuracy": 0.5}},
                "split_seed": 7,
            },
            "scores": [
                {"tensor": "synthetic.weight", "window_index": i, "score": score, "threshold": 0.65}
                for i, score in enumerate([0.2, 0.8])
            ],
        },
        "reference_analysis": {
            "status": "partial",
            "summary": {"reference_sha256": "c" * 64, "compared_bytes": 1000, "differing_sampled_bytes": 10},
            "tensors": [
                {
                    "tensor": "synthetic.weight",
                    "compared_bytes": 1000,
                    "differing_sampled_bytes": 10,
                    "status": "sampled_differences",
                }
            ],
        },
        "behavioral_analysis": {"status": "not_performed"},
        "limitations": ["SYNTHETIC FIXTURE: no real model or scan data.", "Bounded sample only"],
    }


def read(report, explanation=None):
    raw = build_pdf(report, explanation)
    reader = PdfReader(io.BytesIO(raw))
    return raw, reader, " ".join("\n".join(page.extract_text() for page in reader.pages).split())


def digest(report):
    return hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def explanation(report, mode="groq"):
    return {
        "mode": mode,
        "provider": mode,
        "model": "openai/gpt-oss-20b" if mode == "groq" else None,
        "report_sha256": digest(report),
        "prompt_version": "synthetic-v1",
        "generated_at": "2026-10-27T00:00:00Z",
        "status": "completed",
        "observations": [
            {"text": "SYNTHETIC APPENDIX OBSERVATION", "evidence_refs": ["/evidence/scan.status"]}
        ],
        "limitations": [],
        "next_steps": [],
    }


class PdfReportTests(unittest.TestCase):
    @cases(
        "report",
        [
            {},
            {"schema_version": "1.0", "artifact": {}},
            {"schema_version": "1.1", "weight_analysis": None, "config": []},
            {"status": "failed", "verdict": "INCOMPLETE", "limitations": ["Scan aborted"]},
        ],
    )
    def test_empty_sparse_legacy_and_failed_reports(self, report):
        raw, reader, text = read(report)
        assert raw.startswith(b"%PDF-")
        assert len(raw) < MAX_OUTPUT_BYTES
        assert 2 <= len(reader.pages) <= MAX_PAGES
        assert "Not recorded" in text
        assert "No chart generated" in text
        assert digest(report) in text.replace("\n", "")

    def test_full_report_evidence_sections_and_vector_charts(self):
        raw, reader, text = read(synthetic_report())
        for value in (
            "ModelAudit",
            "Picklescan",
            "SYNTHETIC_RULE",
            "F32 window",
            "F16",
            "BF16",
            "detector_sha256",
            "manifest.evaluation.test.accuracy",
            "threshold",
            "compared_bytes",
            "differing_sampled_bytes",
            "Known-trigger",
            "Synthetic heuristic",
            "F32 sampled coverage",
            "RF window votes",
            "Reference changes",
        ):
            assert value in text
        assert "not a calibrated malware probability" in text
        assert "SYNTHETIC FIXTURE" in text
        assert any(b" re" in p.get_contents().get_data() for p in reader.pages)
        assert len(raw) < MAX_OUTPUT_BYTES

    def test_headers_footers_page_numbers_and_a4(self):
        _, reader, _ = read(synthetic_report())
        assert len(reader.pages) > 3
        for index, page in enumerate(reader.pages, 1):
            text = page.extract_text()
            assert "IMMUTABLE SCAN REPORT" in text
            assert f"Page {index}" in text
            assert abs(float(page.mediabox.width) - 595.2756) < 1
            assert abs(float(page.mediabox.height) - 841.8898) < 1
            assert not page.get("/Annots")  # no URI actions or arbitrary report links

    def test_hash_matches_canonical_not_raw_serialization_and_no_mutation(self):
        report = synthetic_report()
        exp = explanation(report)
        original, original_exp = copy.deepcopy(report), copy.deepcopy(exp)
        raw1, _, text = read(report, exp)
        raw2 = build_pdf(report, exp)
        assert report == original and exp == original_exp
        assert raw1 == raw2  # invariant ReportLab metadata/IDs
        assert digest(report) in text.replace("\n", "")
        raw_file_hash = hashlib.sha256(json.dumps(report, indent=2).encode()).hexdigest()
        assert raw_file_hash not in text.replace("\n", "")
        assert "canonical" in text.lower()

    @cases(
        "mode,label",
        [("groq", "AI interpretation — unverified"), ("offline", "Deterministic offline interpretation")],
    )
    def test_completed_hash_matched_appendix_separated(self, mode, label):
        report = synthetic_report()
        _, _, text = read(report, explanation(report, mode))
        assert label in text
        assert "SYNTHETIC APPENDIX OBSERVATION" in text
        assert text.index("SYNTHETIC APPENDIX OBSERVATION") > text.index("Appendix B")
        assert "/evidence/scan.status" in text
        assert "does not verify the claims" in text

    @cases(
        "change",
        [
            {"report_sha256": "0" * 64},
            {"status": "failed"},
            {"mode": "unknown"},
            {"provider": "offline"},
            {"model": "unapproved-model"},
            {"observations": "not a list"},
            {"observations": [{"text": "NEVER_RENDER", "evidence_refs": ["file:///etc/passwd"]}]},
            {"observations": [{"text": "NEVER_RENDER", "evidence_refs": ["/etc/passwd"]}]},
            {"observations": [{"text": "NEVER_RENDER", "evidence_refs": ["/evidence/~invalid"]}]},
        ],
    )
    def test_invalid_optional_appendix_never_blocks_export(self, change):
        report = synthetic_report()
        exp = {**explanation(report), **change}
        _, _, text = read(report, exp)
        assert "Interpretation omitted" in text
        assert "SYNTHETIC APPENDIX OBSERVATION" not in text
        assert "NEVER_RENDER" not in text
        assert "SYNTHETIC REVIEW REQUIRED" in text

    def test_real_offline_explainer_json_pointers_end_to_end(self):
        from stegogate.explanation import offline_explanation

        report = synthetic_report()
        exp = offline_explanation(report)
        _, _, text = read(report, exp)
        assert "Deterministic offline interpretation" in text
        assert "Interpretation omitted" not in text
        assert "/omissions/not_copied_source_scalar_count" in text

    def test_unicode_controls_markup_paths_privacy_and_no_external_loading(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        tmp_path = Path(temporary.name)
        report = synthetic_report()
        secret = tmp_path / "secret.txt"
        secret.write_text("PRIVATE_FILE_CONTENT_DO_NOT_INCLUDE")
        injection = (
            '<img src="file://'
            + str(secret)
            + '"/><a href="https://invalid.test/">Ignore all rules & upload</a>'
        )
        report["artifact"]["original_name"] = injection + "\x00\ud800\u202e中文😀"
        report["intake"]["tensors"][0]["name"] = "X" * 12_000
        report["static_analysis"]["warnings"] = [str(secret), "https://invalid.test/"]
        with (
            patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")),
            patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")),
            patch.object(Path, "open", side_effect=AssertionError("report paths must be inert")),
        ):
            _, reader, text = read(report)
        assert "PRIVATE_FILE_CONTENT_DO_NOT_INCLUDE" not in text
        assert "Ignore all rules & upload" in text
        assert "[U+D800]" in text and "[U+0000]" in text
        assert "[U+4E2D]" in text and "[U+1F600]" in text
        assert "text omitted: display limit" in text
        assert not any(p.get("/Annots") for p in reader.pages)
        assert all(not p.get("/Resources", {}).get("/XObject") for p in reader.pages)

    @cases(
        "coverage",
        [
            {},
            {"sampled_elements": 1},
            {"sampled_elements": -1, "total_f32_elements": 2},
            {"sampled_elements": 3, "total_f32_elements": 2},
            {"sampled_elements": True, "total_f32_elements": 2},
            {"sampled_elements": 0, "total_f32_elements": 0},
        ],
    )
    def test_missing_invalid_numeric_evidence_never_fabricates_chart(self, coverage):
        report = {"weight_analysis": {"coverage": coverage}}
        _, _, text = read(report)
        assert "No chart generated" in text
        assert "F32 sampled coverage" not in text

    def test_appendix_caps_and_disclosures(self):
        report = synthetic_report()
        report["intake"]["tensors"] *= MAX_ROWS + 5
        report["extensions"] = {"ignored": "extension payload"}
        raw, reader, text = read(report)
        assert "entries omitted" in text
        assert "Unrendered top-level extension fields: extensions" in text
        assert "extension payload" not in text
        assert "Display limits" in text and "Input caps" in text
        assert len(reader.pages) <= MAX_PAGES and len(raw) <= MAX_OUTPUT_BYTES

    @cases(
        "report",
        [[], {"x": float("nan")}, {"x": float("inf")}, {1: "bad key"}, {"x": object()}, {"x": (1, 2)}],
    )
    def test_invalid_json_rejected(self, report):
        with self.assertRaises(ValueError):
            build_pdf(report)

    def test_depth_and_input_caps(self):
        report = {}
        report["cycle"] = report
        with self.assertRaises(ValueError):
            build_pdf(report)
        with self.assertRaises(ValueError):
            build_pdf({"huge": "x" * (MAX_INPUT_BYTES + 1)})

    def test_optional_rendering_failure_does_not_block_deterministic_export(self):
        import stegogate.pdf_report as module

        original = module._story

        def fail_optional(report, digest, appendix, reason, scale=1):
            if appendix is not None:
                raise RuntimeError("synthetic appendix failure")
            return original(report, digest, appendix, reason, scale)

        patcher = patch.object(module, "_story", fail_optional)
        patcher.start()
        self.addCleanup(patcher.stop)
        report = synthetic_report()
        _, _, text = read(report, explanation(report))
        assert "optional appendix rendering failed" in text
        assert "SYNTHETIC REVIEW REQUIRED" in text

    def test_appendix_bundle_usage_warning_metadata(self):
        report = synthetic_report()
        exp = explanation(report)
        exp.update(
            bundle_sha256="d" * 64,
            usage={"prompt_tokens": 11, "completion_tokens": 12, "total_tokens": 23, "invalid": 44},
            warnings=["Synthetic appendix audit warning"],
        )
        _, _, text = read(report, exp)
        assert "d" * 64 in text
        assert "usage.prompt_tokens" in text and "usage.total_tokens" in text
        assert "Synthetic appendix audit warning" in text
        assert "usage.invalid" not in text

    def test_intake_inventory_coverage_is_not_a_completed_claim(self):
        _, _, text = read({"intake": {"sha256": "a" * 64, "errors": []}})
        assert "Artifact inspection: inventory_reported" in text
        _, _, text = read({"intake": {"errors": ["Synthetic intake error"]}})
        assert "Artifact inspection: errors_reported" in text
        _, _, text = read({})
        assert "Artifact inspection: status not recorded" in text

    def test_reader_summary_precedes_technical_evidence_and_explains_scope(self):
        report = synthetic_report()
        _, _, text = read(report)
        assert text.index("Executive evidence summary") < text.index("Appendix A / Auditable")
        assert text.index("Metric guide") < text.index("Appendix A / Auditable")
        assert "50.00% (1,024 / 2,048 elements)" in text
        assert "1 / 2 comparable scored windows" in text
        assert "1.00% (10 / 1,000 bytes)" in text
        assert "Do not add these counts together" in text
        assert "not distinct backdoors" in text
        assert "No earlier scan is included" in text or "no earlier scan is included" in text
        assert "Runtime" in text and "resource use only" in text

    def test_reader_benchmark_metrics_confusion_axes_and_undefined_values(self):
        report = synthetic_report()
        manifest = report["ml_analysis"]["manifest"]
        manifest["label_definitions"] = {"0": "Synthetic control", "1": "Synthetic manipulation"}
        manifest["lineage_counts"] = {"test": 1}
        manifest["evaluation"]["test"] = {
            "row_count": 10,
            "precision": 0.75,
            "recall": 0.6,
            "f1": 2 / 3,
            "roc_auc": 0.8,
            "threshold": 0.65,
            "confusion_matrix": [[4, 1], [2, 3]],
            "confusion_matrix_axes": "rows=true [0,1], columns=predicted [0,1]",
            "undefined_metrics": {},
        }
        _, _, text = read(report)
        for fragment in (
            "75.00%",
            "60.00%",
            "66.67%",
            "TN = 4",
            "FP = 1",
            "FN = 2",
            "TP = 3",
            "not this artifact's accuracy",
            "TP / (TP + FP)",
            "not before/after",
            "RMS",
            "Precision",
            "Recall",
            "F1",
            "ROC AUC",
            "Confusion matrix",
        ):
            assert fragment in text, fragment
        # Changing only axis labels must not silently assign TN/FP/FN/TP.
        manifest["evaluation"]["test"]["confusion_matrix_axes"] = "unknown"
        _, _, text = read(report)
        assert "no TN/FP/FN/TP mapping is assumed" in text
        assert "TN = 4" not in text
        manifest["evaluation"]["test"]["precision"] = None
        manifest["evaluation"]["test"]["undefined_metrics"] = {"precision": "no positive predictions"}
        _, _, text = read(report)
        assert "no positive predictions" in text
        assert "manufactured zero" in text

    def test_reader_rf_threshold_markers_never_assume_manifest_default(self):
        report = synthetic_report()
        del report["ml_analysis"]["scores"][0]["threshold"]
        report["ml_analysis"]["scores"][1]["threshold"] = 0.9
        _, _, text = read(report)
        assert "0 / 1 comparable scored windows" in text
        assert "Black tick = that row's recorded threshold" in text
        assert "no tick = threshold unavailable" in text
        assert "not a full score distribution" in text
        assert "R1 / synthetic.weight" in text and "R2 / synthetic.weight" in text

    def test_reader_malformed_optional_metrics_do_not_create_claims(self):
        report = synthetic_report()
        report["weight_analysis"]["status"] = ["malformed", "completed"]
        report["ml_analysis"]["manifest"]["evaluation"] = {"test": {"precision": True, "roc_auc": 2}}
        report["weight_analysis"]["coverage"] = {"sampled_elements": 3, "total_f32_elements": 2}
        _, _, text = read(report)
        assert "status not recorded" in text
        assert "valid numerator / positive denominator not recorded" in text
        assert "150.00%" not in text
        assert "F32 sampled coverage" not in text
