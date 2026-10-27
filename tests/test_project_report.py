"""Submission-document checks, separate from artifact evidence-PDF tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from pypdf import PdfReader


def renderer():
    path = Path(__file__).resolve().parents[1] / "scripts" / "build_project_report.py"
    spec = importlib.util.spec_from_file_location("submission_report_renderer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_project_report_has_requested_structure_and_real_figures(tmp_path):
    module = renderer()
    output = tmp_path / "report.pdf"
    module.build(output)
    pdf = PdfReader(output)
    text = "\n".join(page.extract_text() for page in pdf.pages)
    assert len(pdf.pages) == 10
    sections = ["1. Problem Statement", "2. Our Solution", "3. Approach", "4. Conclusion"]
    for page, section in zip([pdf.pages[1], pdf.pages[2], pdf.pages[3], pdf.pages[-1]], sections):
        assert section in page.extract_text()
    assert sum(len(page.images) for page in pdf.pages) == 4
    for figure in range(1, 5):
        assert f"Figure {figure}." in text
    assert "not a calibrated malware" in " ".join(text.split()).lower()


def test_project_report_rejects_images_outside_asset_directory(tmp_path, monkeypatch):
    module = renderer()
    source = tmp_path / "PROJECT_REPORT.md"
    source.write_text("# Report\n\n![Outside](../private.png)\n")
    monkeypatch.setattr(module, "SOURCE", source)
    with pytest.raises(ValueError, match="local docs/assets"):
        module.build(tmp_path / "report.pdf")


def test_project_report_build_needs_no_network(tmp_path, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Documentation export must not connect to a network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    module = renderer()
    output = tmp_path / "offline.pdf"
    module.build(output)
    assert output.read_bytes().startswith(b"%PDF-")
