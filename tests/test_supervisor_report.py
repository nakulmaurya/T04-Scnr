"""Validate the supervisor-facing report without Word, providers, or a network."""
from pathlib import Path
import hashlib
import xml.etree.ElementTree as ET
from zipfile import ZipFile

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def test_supervisor_report_is_six_pages_with_requested_sections():
    pdf = PdfReader(DOCS / "StegoLens_Project_Report.pdf")
    assert len(pdf.pages) == 6
    text = " ".join(" ".join(page.extract_text().split()) for page in pdf.pages)
    for expected in ("StegoLens", "Steganographic Malware Detection", "Problem definition", "our approach", "Architecture", "Working", "Results", "Conclusion"):
        assert expected in text
    for name in ("Pranav Khandelwal", "Jaimil Maniar", "Nakul Maurya", "Rishit Nanavati"):
        assert name in text
    assert "Shreya" not in text and "Sherya" not in text
    assert "61,562 total recorded F32" in text
    assert "not the scanner’s detection accuracy" in text
    assert len({hashlib.sha256(image.data).hexdigest() for page in pdf.pages for image in page.images}) == 3


def test_word_report_has_editable_text_and_explicit_page_breaks():
    with ZipFile(DOCS / "StegoLens_Project_Report.docx") as package:
        root = ET.fromstring(package.read("word/document.xml"))
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        texts = " ".join(element.text or "" for element in root.findall(".//w:t", ns))
        assert "Problem definition" in texts and "The full process" in texts
        assert "Shreya" not in texts and "Sherya" not in texts
        breaks = root.findall(".//w:br", ns)
        assert sum(item.attrib.get("{" + ns["w"] + "}type") == "page" for item in breaks) == 5
        assert len([n for n in package.namelist() if n.startswith("word/media/")]) == 3
