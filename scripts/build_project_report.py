#!/usr/bin/env python3
"""Build the illustrated submission report from its reviewed Markdown source.

This is a documentation renderer, not the scanner's evidence-PDF exporter.
It supports the small Markdown subset used by docs/PROJECT_REPORT.md and
resolves image files only inside docs/assets. No network or artifact reads.
"""

from __future__ import annotations

import argparse
import re
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "PROJECT_REPORT.md"
PAGE = (595.28, 841.89)
WIDTH = PAGE[0] - 100


def inline(text: str) -> str:
    text = escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return re.sub(r"`(.+?)`", r'<font name="Courier">\1</font>', text)


def build(output: Path) -> None:
    base = getSampleStyleSheet()
    styles = {
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=10,
            leading=14.4,
            spaceAfter=9,
            textColor=colors.HexColor("#292929"),
        ),
        "h1": ParagraphStyle(
            "Section",
            parent=base["Heading1"],
            fontSize=23,
            leading=28,
            spaceAfter=18,
            textColor=colors.HexColor("#171717"),
        ),
        "h2": ParagraphStyle(
            "Subsection", parent=base["Heading2"], fontSize=12.5, leading=16, spaceBefore=12, spaceAfter=8
        ),
        "caption": ParagraphStyle(
            "Caption",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            spaceBefore=7,
            spaceAfter=10,
            textColor=colors.HexColor("#555555"),
        ),
        "cell": ParagraphStyle("Cell", parent=base["Normal"], fontSize=8.1, leading=11),
        "title": ParagraphStyle(
            "Title", parent=base["Title"], fontSize=43, leading=49, alignment=TA_CENTER, spaceAfter=18
        ),
    }
    story = []
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    first = True
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        if line == "<!-- pagebreak -->":
            story.append(PageBreak())
        elif line.startswith("# "):
            if first:
                story.extend([Spacer(1, 95), Paragraph(inline(line[2:]), styles["title"])])
                first = False
            else:
                story.append(Paragraph(inline(line[2:]), styles["h1"]))
        elif line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), styles["h2"]))
        elif line.startswith("!["):
            match = re.fullmatch(r"!\[(.+)\]\((.+)\)", line)
            if not match:
                raise ValueError("Invalid figure declaration")
            caption, name = match.groups()
            asset = (SOURCE.parent / name).resolve()
            if not asset.is_relative_to((SOURCE.parent / "assets").resolve()) or not asset.is_file():
                raise ValueError("Figure must be a local docs/assets file")
            w, h = ImageReader(str(asset)).getSize()
            scale = min(WIDTH / w, 535 / h)
            story.append(
                KeepTogether(
                    [
                        Image(str(asset), width=w * scale, height=h * scale),
                        Paragraph(inline(caption), styles["caption"]),
                    ]
                )
            )
        elif line.startswith("| "):
            rows = [line]
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            parsed = []
            for row in rows:
                values = [v.strip() for v in row.strip("|").split("|")]
                if all(re.fullmatch(r"[: -]+", v) for v in values):
                    continue
                parsed.append([Paragraph(inline(v), styles["cell"]) for v in values])
            table = Table(
                parsed, colWidths=[WIDTH * 0.18, WIDTH * 0.37, WIDTH * 0.45], repeatRows=1, hAlign="LEFT"
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9e9e9")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d1d1")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            story.extend([table, Spacer(1, 10)])
        elif line.startswith("- ") or re.match(r"\d+\. ", line):
            story.append(Paragraph(inline(line), styles["body"]))
        else:
            paragraph = [line]
            while (
                i < len(lines)
                and lines[i].strip()
                and not lines[i].lstrip().startswith(("#", "![", "<!--", "|", "- "))
            ):
                paragraph.append(lines[i].strip())
                i += 1
            story.append(Paragraph(inline(" ".join(paragraph)), styles["body"]))

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(50, PAGE[1] - 32, "T04-SCNR  /  PROJECT SUBMISSION REPORT")
        canvas.setStrokeColor(colors.HexColor("#dddddd"))
        canvas.line(50, 43, PAGE[0] - 50, 43)
        canvas.drawString(50, 29, "Research prototype | Release 0.4.2 | Evidence, not safety certification")
        canvas.drawRightString(PAGE[0] - 50, 29, f"{doc.page}")
        canvas.restoreState()

    output.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(
        str(output),
        pagesize=PAGE,
        rightMargin=50,
        leftMargin=50,
        topMargin=57,
        bottomMargin=59,
        title="T04-Scnr - Project Report",
        author="T04-Scnr project / nakulmaurya",
        subject="Problem statement, solution, approach and conclusion",
        pageCompression=1,
    ).build(story, onFirstPage=decorate, onLaterPages=decorate)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "T04-Scnr_Project_Report.pdf")
    build(parser.parse_args().output)
