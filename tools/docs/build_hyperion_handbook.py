#!/usr/bin/env python3
"""Build the Hyperion engineering handbook and its native diagrams."""

from __future__ import annotations

import argparse
import re
import textwrap
from pathlib import Path
from urllib.parse import unquote, urlparse

from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.shared import Inches, Pt, RGBColor


BLUE = "2E74B5"
DARK_BLUE = "1F4D78"
NAVY = "17324D"
PALE_BLUE = "E8EEF5"
PALE_GOLD = "FFF4D6"
PALE_GREEN = "E8F4EC"
PALE_RED = "FBE9E7"
GREY = "66727F"
CONTENT_DXA = 9360


def font(name: str, size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    fonts = Path("C:/Windows/Fonts")
    candidates = {
        "regular": ["segoeui.ttf", "arial.ttf"],
        "bold": ["seguisb.ttf", "segoeuib.ttf", "arialbd.ttf"],
    }
    for candidate in candidates["bold" if bold else "regular"]:
        path = fonts / candidate
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


def wrapped(draw: ImageDraw.ImageDraw, value: str, box: tuple[int, int, int, int],
            value_font: ImageFont.FreeTypeFont, fill: str, spacing: int = 8) -> None:
    x1, y1, x2, y2 = box
    width = max(12, int((x2 - x1) / max(value_font.getlength("M"), 1)))
    lines = textwrap.wrap(value, width=width, break_long_words=False)
    metrics = draw.multiline_textbbox((0, 0), "\n".join(lines), font=value_font, spacing=spacing)
    height = metrics[3] - metrics[1]
    draw.multiline_text(
        ((x1 + x2) / 2, (y1 + y2 - height) / 2),
        "\n".join(lines),
        font=value_font,
        fill=fill,
        anchor="ma",
        align="center",
        spacing=spacing,
    )


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], color: str = BLUE) -> None:
    if not color.startswith("#"):
        color = f"#{color}"
    draw.line([start, end], fill=color, width=6)
    x, y = end
    if abs(end[0] - start[0]) >= abs(end[1] - start[1]):
        direction = 1 if end[0] > start[0] else -1
        points = [(x, y), (x - 20 * direction, y - 13), (x - 20 * direction, y + 13)]
    else:
        direction = 1 if end[1] > start[1] else -1
        points = [(x, y), (x - 13, y - 20 * direction), (x + 13, y - 20 * direction)]
    draw.polygon(points, fill=color)


def layered_diagram(path: Path, title: str, subtitle: str,
                    layers: list[tuple[str, list[str], str]]) -> None:
    image_height = max(1040, 275 + len(layers) * 186)
    image = Image.new("RGB", (1800, image_height), "#F7F9FB")
    draw = ImageDraw.Draw(image)
    title_font = font("regular", 52, True)
    subtitle_font = font("regular", 25)
    label_font = font("regular", 24, True)
    box_font = font("regular", 23, True)
    draw.text((90, 68), title, font=title_font, fill="#17324D")
    draw.text((90, 136), subtitle, font=subtitle_font, fill="#66727F")
    row_top = 225
    row_height = 132
    row_gap = 54
    for index, (label, boxes, fill) in enumerate(layers):
        y1 = row_top + index * (row_height + row_gap)
        y2 = y1 + row_height
        draw.text((90, y1 + 51), label.upper(), font=label_font, fill="#1F4D78", anchor="lm")
        x_start = 385
        available = 1325
        gap = 28
        box_width = int((available - gap * (len(boxes) - 1)) / len(boxes))
        centers: list[tuple[int, int]] = []
        for box_index, box in enumerate(boxes):
            x1 = x_start + box_index * (box_width + gap)
            x2 = x1 + box_width
            draw.rounded_rectangle((x1, y1, x2, y2), radius=20, fill=fill, outline="#2E74B5", width=3)
            wrapped(draw, box, (x1 + 18, y1 + 12, x2 - 18, y2 - 12), box_font, "#17324D")
            centers.append(((x1 + x2) // 2, y2))
        if index < len(layers) - 1:
            next_y = row_top + (index + 1) * (row_height + row_gap)
            arrow(draw, (1048, y2 + 6), (1048, next_y - 8), "#6888A5")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, dpi=(180, 180))


def state_diagram(path: Path) -> None:
    image = Image.new("RGB", (1800, 900), "#F7F9FB")
    draw = ImageDraw.Draw(image)
    draw.text((90, 68), "One run, explicit states", font=font("regular", 52, True), fill="#17324D")
    draw.text((90, 136), "Resumability and human release are part of the protocol, not UI decoration.",
              font=font("regular", 25), fill="#66727F")
    nodes = [
        ("Created", f"#{PALE_BLUE}"), ("Running", f"#{PALE_BLUE}"), ("Awaiting approval", f"#{PALE_GOLD}"),
        ("Released", f"#{PALE_GREEN}"), ("Cancelled", f"#{PALE_RED}"), ("Failed", f"#{PALE_RED}"),
    ]
    positions = [(110, 290), (400, 290), (690, 290), (1050, 290), (690, 610), (400, 610)]
    width, height = 235, 120
    for (label, fill), (x, y) in zip(nodes, positions):
        draw.rounded_rectangle((x, y, x + width, y + height), radius=20, fill=fill, outline="#2E74B5", width=3)
        wrapped(draw, label, (x + 12, y + 10, x + width - 12, y + height - 10), font("regular", 24, True), "#17324D")
    arrow(draw, (345, 350), (392, 350))
    arrow(draw, (635, 350), (682, 350))
    arrow(draw, (925, 350), (1042, 350))
    arrow(draw, (807, 418), (807, 602), "#A66B00")
    arrow(draw, (690, 670), (643, 670), "#A33B30")
    arrow(draw, (517, 602), (517, 418), "#6888A5")
    draw.text((1120, 318), "human release", font=font("regular", 20), fill="#4D6A82")
    draw.text((836, 500), "cancel / policy stop", font=font("regular", 20), fill="#7F5C13")
    draw.text((90, 805), "Every transition is persisted with optimistic concurrency and hash-chained events.",
              font=font("regular", 24, True), fill="#17324D")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, dpi=(180, 180))


def build_diagrams(asset_dir: Path) -> None:
    layered_diagram(
        asset_dir / "hyperion-system-architecture.png",
        "Hyperion system architecture",
        "Authority moves downward through immutable records; evidence moves upward for review.",
        [
            ("Clients", ["Operator CLI", "Hosted API + worker", "Terminal adapter"], "#E8EEF5"),
            ("Coordination", ["Five-role workflow", "Budgets + approvals", "SQLite + artifact store"], "#DDECF7"),
            ("Model evidence", ["Corpus + teacher lineage", "Training + evaluation", "Promotion + readiness"], "#E8F4EC"),
            ("Safety", ["Signed verifier authority", "Container controller", "Narrow .NET worker"], "#FFF4D6"),
        ],
    )
    state_diagram(asset_dir / "hyperion-run-state-machine.png")
    layered_diagram(
        asset_dir / "hyperion-evidence-lifecycle.png",
        "Evidence lifecycle",
        "No gate inherits authority from an earlier gate without a new, bound record.",
        [
            ("Data", ["Rights + provenance", "Independent review", "Signed corpus release"], "#E8EEF5"),
            ("Training", ["Pinned base + runtime", "Adapter checkpoint", "Sealed artifact"], "#DDECF7"),
            ("Evaluation", ["Sealed tasks", "Independent replay", "Promotion decision"], "#FFF4D6"),
            ("Serving", ["Activation envelope", "Runtime attestation", "Readiness proof"], "#E8F4EC"),
        ],
    )
    layered_diagram(
        asset_dir / "hyperion-trust-chain.png",
        "Trust and signing chain",
        "Detached signers approve hashes and claims; they do not rebuild evidence supplied by the caller.",
        [
            ("Producers", ["Corpus author", "Trainer", "Verifier controller"], "#E8EEF5"),
            ("Review", ["Independent reviewer", "Replay auditor", "Promotion authority"], "#FFF4D6"),
            ("Signing", ["KMS/HSM request", "Detached signature", "Canonical envelope"], "#DDECF7"),
            ("Consumers", ["Coordinator", "Hosted platform", "Deployment gate"], "#E8F4EC"),
        ],
    )
    layered_diagram(
        asset_dir / "hyperion-gpu-cluster-topology.png",
        "Small-cluster training topology",
        "Start with adapter training on a right-sized open-weight base; keep control and evidence off GPU workers.",
        [
            ("Control", ["Scheduler + run registry", "Secrets/KMS broker", "Metrics + audit"], "#E8EEF5"),
            ("Storage", ["Versioned corpus", "Immutable artifacts", "Model/cache mirror"], "#DDECF7"),
            ("GPU pool", ["Trainer rank 0", "Trainer ranks 1..N", "Evaluation/serving"], "#E8F4EC"),
            ("Isolation", ["Verifier microVM", "Restricted egress", "Backup + restore"], "#FFF4D6"),
        ],
    )
    layered_diagram(
        asset_dir / "hyperion-frontier-model-factory.png",
        "Hyperion frontier model factory",
        "Models propose; governed evidence, independent verification, and human release grant authority.",
        [
            ("Authority", ["Registry + policy", "Budgets + credits", "Promotion + rollback"], "#E8EEF5"),
            ("Knowledge", ["Reviewed corpus", "Versioned private RAG", "Sealed evaluation"], "#DDECF7"),
            ("Teachers", ["Hosted frontier", "Open large models", "Critics + judges"], "#FFF4D6"),
            ("Student factory", ["Raw-base bake-off", "SFT / DPO / RLVR", "Specialists + router"], "#E8F4EC"),
            ("Runtime", ["Coordinator + tools", "Verifier + replay", "Inference + GPU cluster"], "#E8EEF5"),
        ],
    )


def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def prevent_row_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def set_cell_width(cell, width: int) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_w = tc_pr.find(qn("w:tcW"))
    if tc_w is None:
        tc_w = OxmlElement("w:tcW")
        tc_pr.append(tc_w)
    tc_w.set(qn("w:w"), str(width))
    tc_w.set(qn("w:type"), "dxa")


def set_table_geometry(table, column_count: int) -> None:
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    tbl_pr = table._tbl.tblPr
    tbl_w = tbl_pr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        tbl_pr.append(tbl_w)
    tbl_w.set(qn("w:w"), str(CONTENT_DXA))
    tbl_w.set(qn("w:type"), "dxa")
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tbl_pr.append(layout)
    indent = OxmlElement("w:tblInd")
    indent.set(qn("w:w"), "120")
    indent.set(qn("w:type"), "dxa")
    tbl_pr.append(indent)
    margins = OxmlElement("w:tblCellMar")
    for side, value in (("top", 80), ("bottom", 80), ("start", 120), ("end", 120)):
        element = OxmlElement(f"w:{side}")
        element.set(qn("w:w"), str(value))
        element.set(qn("w:type"), "dxa")
        margins.append(element)
    tbl_pr.append(margins)
    base = CONTENT_DXA // column_count
    widths = [base] * column_count
    widths[-1] += CONTENT_DXA - sum(widths)
    for row in table.rows:
        prevent_row_split(row)
        for index, cell in enumerate(row.cells):
            set_cell_width(cell, widths[index])
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP


def add_page_field(paragraph) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = " PAGE "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instruction, separate, end])


def add_hyperlink(paragraph, text: str, url: str) -> None:
    relationship = paragraph.part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), relationship)
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), BLUE)
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    props.extend([color, underline])
    run.append(props)
    value = OxmlElement("w:t")
    value.text = text
    run.append(value)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|https?://[^\s]+|\*[^*]+\*)")


def soft_wrap(value: str) -> str:
    if len(value) < 28 or " " in value:
        return value
    value = re.sub(r"([/\\._-])", r"\1" + "\u200b", value)
    return re.sub(r"([A-Za-z0-9]{16})(?=[A-Za-z0-9])", r"\1" + "\u200b", value)


def add_inline(paragraph, value: str, *, base_bold: bool = False) -> None:
    position = 0
    for match in INLINE.finditer(value):
        if match.start() > position:
            paragraph.add_run(value[position:match.start()]).bold = base_bold
        token = match.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        elif token.startswith("`"):
            run = paragraph.add_run(soft_wrap(token[1:-1]))
            run.font.name = "Consolas"
            run.font.size = Pt(8.5)
            run.font.color.rgb = RGBColor.from_string(DARK_BLUE)
        elif token.startswith("["):
            link_match = re.match(r"\[([^\]]+)\]\(([^)]+)\)", token)
            assert link_match
            add_hyperlink(paragraph, link_match.group(1), link_match.group(2))
        elif token.startswith("http"):
            url = token.rstrip(".,;")
            parsed = urlparse(url)
            path_parts = [unquote(part) for part in parsed.path.split("/") if part]
            path_label = "/".join(path_parts[-2:]) if path_parts else "source"
            link_label = f"{parsed.netloc.removeprefix('www.')} / {path_label}"
            add_hyperlink(paragraph, link_label, url)
            if len(url) < len(token):
                paragraph.add_run(token[len(url):])
        else:
            run = paragraph.add_run(token[1:-1])
            run.italic = True
        position = match.end()
    if position < len(value):
        paragraph.add_run(value[position:]).bold = base_bold


def configure_styles(document: Document) -> None:
    styles = document.styles
    normal = styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    normal.font.color.rgb = RGBColor.from_string("25313B")
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.25
    normal.paragraph_format.widow_control = True
    for name, size, color, before, after in (
        ("Heading 1", 16, BLUE, 18, 10),
        ("Heading 2", 13, BLUE, 14, 7),
        ("Heading 3", 12, DARK_BLUE, 10, 5),
    ):
        style = styles[name]
        style.font.name = "Calibri"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string(color)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.keep_together = True
        style.paragraph_format.widow_control = True
    for name in ("List Bullet", "List Bullet 2", "List Bullet 3", "List Number", "List Number 2", "List Number 3"):
        style = styles[name]
        style.font.name = "Calibri"
        style.font.size = Pt(11)
        style.paragraph_format.space_after = Pt(4)
        style.paragraph_format.line_spacing = 1.25
        level = 0 if name.endswith(("Bullet", "Number")) else int(name[-1]) - 1
        style.paragraph_format.left_indent = Inches(0.375 + 0.25 * level)
        style.paragraph_format.first_line_indent = Inches(-0.188)
    if "Code Block" not in styles:
        code = styles.add_style("Code Block", WD_STYLE_TYPE.PARAGRAPH)
    else:
        code = styles["Code Block"]
    code.font.name = "Consolas"
    code.font.size = Pt(8.3)
    code.font.color.rgb = RGBColor.from_string("243B53")
    code.paragraph_format.left_indent = Inches(0.18)
    code.paragraph_format.right_indent = Inches(0.18)
    code.paragraph_format.space_before = Pt(4)
    code.paragraph_format.space_after = Pt(7)
    if "Figure Caption" not in styles:
        caption = styles.add_style("Figure Caption", WD_STYLE_TYPE.PARAGRAPH)
    else:
        caption = styles["Figure Caption"]
    caption.font.name = "Calibri"
    caption.font.size = Pt(9)
    caption.font.italic = True
    caption.font.color.rgb = RGBColor.from_string(GREY)
    caption.paragraph_format.space_before = Pt(3)
    caption.paragraph_format.space_after = Pt(8)
    caption.paragraph_format.keep_with_next = False
    caption.paragraph_format.keep_together = True


def configure_document(document: Document) -> None:
    section = document.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)
    section.header_distance = Inches(0.492)
    section.footer_distance = Inches(0.492)
    section.different_first_page_header_footer = True
    header = section.header.paragraphs[0]
    header.text = "HYPERION  /  ENGINEERING HANDBOOK"
    header.style = document.styles["Normal"]
    header.runs[0].font.size = Pt(8.5)
    header.runs[0].font.bold = True
    header.runs[0].font.color.rgb = RGBColor.from_string(DARK_BLUE)
    footer = section.footer.paragraphs[0]
    footer.paragraph_format.tab_stops.add_tab_stop(Inches(6.5), WD_TAB_ALIGNMENT.RIGHT)
    run = footer.add_run("PRIVATE ENGINEERING MATERIAL")
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor.from_string(GREY)
    footer.add_run("\t")
    add_page_field(footer)
    for footer_run in footer.runs:
        footer_run.font.size = Pt(8)
        footer_run.font.color.rgb = RGBColor.from_string(GREY)


def add_cover(document: Document) -> None:
    document.add_paragraph().paragraph_format.space_after = Pt(38)
    kicker = document.add_paragraph()
    kicker.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = kicker.add_run("PRIVATE ENGINEERING HANDBOOK  •  VERSION 1.1")
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = RGBColor.from_string(BLUE)
    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_before = Pt(24)
    title.paragraph_format.space_after = Pt(10)
    run = title.add_run("Hyperion")
    run.bold = True
    run.font.size = Pt(30)
    run.font.color.rgb = RGBColor.from_string(NAVY)
    subtitle = document.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_after = Pt(28)
    run = subtitle.add_run("LLM Coordinator\nEngineering Handbook")
    run.font.size = Pt(16)
    run.font.color.rgb = RGBColor.from_string(DARK_BLUE)
    band = document.add_paragraph()
    band.alignment = WD_ALIGN_PARAGRAPH.CENTER
    band.paragraph_format.left_indent = Inches(0.12)
    band.paragraph_format.right_indent = Inches(0.12)
    band.paragraph_format.space_before = Pt(14)
    band.paragraph_format.space_after = Pt(14)
    band_properties = band._p.get_or_add_pPr()
    band_shading = OxmlElement("w:shd")
    band_shading.set(qn("w:fill"), NAVY)
    band_properties.append(band_shading)
    run = band.add_run(
        "Coordinator • frontier model factory • isolated verifier\n"
        "For ML, platform, safety, and operations teams"
    )
    run.font.size = Pt(12)
    run.font.bold = True
    run.font.color.rgb = RGBColor(255, 255, 255)
    document.add_paragraph().paragraph_format.space_after = Pt(54)
    for label, value in (
        ("DATE", "31 July 2026"),
        ("REPOSITORY", "github.com/dhruuvsharma/Hyperion"),
        ("CLASSIFICATION", "Private engineering material"),
        ("STATUS", "Infrastructure implemented; no trained Hyperion checkpoint or production deployment"),
    ):
        paragraph = document.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        paragraph.paragraph_format.space_after = Pt(8)
        label_run = paragraph.add_run(f"{label}  ")
        label_run.bold = True
        label_run.font.size = Pt(9)
        label_run.font.color.rgb = RGBColor.from_string(BLUE)
        value_run = paragraph.add_run(value)
        value_run.font.size = Pt(10.5)
        value_run.font.color.rgb = RGBColor.from_string("25313B")
    document.add_page_break()


def add_callout(document: Document, value: str, fill: str = PALE_GOLD) -> None:
    paragraph = document.add_paragraph()
    paragraph.paragraph_format.left_indent = Inches(0.18)
    paragraph.paragraph_format.right_indent = Inches(0.12)
    paragraph.paragraph_format.space_before = Pt(5)
    paragraph.paragraph_format.space_after = Pt(9)
    paragraph.paragraph_format.keep_together = True
    p_pr = paragraph._p.get_or_add_pPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    p_pr.append(shading)
    borders = OxmlElement("w:pBdr")
    left = OxmlElement("w:left")
    left.set(qn("w:val"), "single")
    left.set(qn("w:sz"), "18")
    left.set(qn("w:space"), "8")
    left.set(qn("w:color"), BLUE)
    borders.append(left)
    p_pr.append(borders)
    add_inline(paragraph, value)


def markdown_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def add_table(document: Document, rows: list[list[str]]) -> None:
    column_count = max(len(row) for row in rows)
    table = document.add_table(rows=len(rows), cols=column_count)
    table.style = "Table Grid"
    for row_index, values in enumerate(rows):
        for column_index in range(column_count):
            cell = table.cell(row_index, column_index)
            value = values[column_index] if column_index < len(values) else ""
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(2)
            paragraph.paragraph_format.line_spacing = 1.08
            add_inline(paragraph, value, base_bold=row_index == 0)
            for run in paragraph.runs:
                run.font.size = Pt(8.3)
            if row_index == 0:
                set_cell_shading(cell, PALE_BLUE)
                cell._tc.get_or_add_tcPr().append(OxmlElement("w:tcFitText"))
    set_repeat_table_header(table.rows[0])
    set_table_geometry(table, column_count)
    after = document.add_paragraph()
    after.paragraph_format.space_after = Pt(2)


def add_picture(document: Document, source_dir: Path, alt: str, relative_path: str, number: int) -> None:
    image_path = (source_dir / relative_path).resolve()
    if not image_path.exists():
        add_callout(document, f"Diagram unavailable during build: {relative_path}", PALE_RED)
        return
    paragraph = document.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.keep_together = True
    run = paragraph.add_run()
    run.add_picture(str(image_path), width=Inches(6.35))
    drawing = run._r.xpath(".//wp:docPr")
    if drawing:
        drawing[0].set("descr", alt)
        drawing[0].set("title", alt)
    caption = document.add_paragraph(style="Figure Caption")
    caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.add_run(f"Figure {number}. {alt}")


def add_code(document: Document, code: str) -> None:
    paragraph = document.add_paragraph(style="Code Block")
    p_pr = paragraph._p.get_or_add_pPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), "F2F5F7")
    p_pr.append(shading)
    paragraph.paragraph_format.keep_together = len(code.splitlines()) <= 22
    paragraph.add_run(code.rstrip())


def create_numbering_instance(document: Document, start: int = 1) -> int:
    """Create a real, independently restarting decimal list."""
    numbering = document.part.numbering_part.element
    abstract_ids = [
        int(element.get(qn("w:abstractNumId")))
        for element in numbering.findall(qn("w:abstractNum"))
    ]
    number_ids = [
        int(element.get(qn("w:numId")))
        for element in numbering.findall(qn("w:num"))
    ]
    abstract_id = max(abstract_ids, default=0) + 1
    number_id = max(number_ids, default=0) + 1

    abstract = OxmlElement("w:abstractNum")
    abstract.set(qn("w:abstractNumId"), str(abstract_id))
    multi_level = OxmlElement("w:multiLevelType")
    multi_level.set(qn("w:val"), "multilevel")
    abstract.append(multi_level)
    for level in range(3):
        lvl = OxmlElement("w:lvl")
        lvl.set(qn("w:ilvl"), str(level))
        start_element = OxmlElement("w:start")
        start_element.set(qn("w:val"), "1")
        number_format = OxmlElement("w:numFmt")
        number_format.set(qn("w:val"), "decimal")
        level_text = OxmlElement("w:lvlText")
        level_text.set(qn("w:val"), f"%{level + 1}.")
        suffix = OxmlElement("w:suff")
        suffix.set(qn("w:val"), "space")
        justification = OxmlElement("w:lvlJc")
        justification.set(qn("w:val"), "left")
        p_pr = OxmlElement("w:pPr")
        tabs = OxmlElement("w:tabs")
        tab = OxmlElement("w:tab")
        tab.set(qn("w:val"), "num")
        tab.set(qn("w:pos"), str(540 + 360 * level))
        tabs.append(tab)
        indent = OxmlElement("w:ind")
        indent.set(qn("w:left"), str(540 + 360 * level))
        indent.set(qn("w:hanging"), "270")
        p_pr.extend([tabs, indent])
        lvl.extend([start_element, number_format, level_text, suffix, justification, p_pr])
        abstract.append(lvl)
    numbering.append(abstract)

    number = OxmlElement("w:num")
    number.set(qn("w:numId"), str(number_id))
    abstract_reference = OxmlElement("w:abstractNumId")
    abstract_reference.set(qn("w:val"), str(abstract_id))
    number.append(abstract_reference)
    override = OxmlElement("w:lvlOverride")
    override.set(qn("w:ilvl"), "0")
    start_override = OxmlElement("w:startOverride")
    start_override.set(qn("w:val"), str(start))
    override.append(start_override)
    number.append(override)
    numbering.append(number)
    return number_id


def apply_numbering(paragraph, number_id: int, level: int) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    num_pr = OxmlElement("w:numPr")
    ilvl = OxmlElement("w:ilvl")
    ilvl.set(qn("w:val"), str(level))
    num_id = OxmlElement("w:numId")
    num_id.set(qn("w:val"), str(number_id))
    num_pr.extend([ilvl, num_id])
    p_pr.append(num_pr)


def add_contents(document: Document, headings: list[str], architecture_path: Path) -> None:
    heading = document.add_paragraph("Contents", style="Heading 1")
    heading.paragraph_format.space_before = Pt(0)
    for value in headings:
        paragraph = document.add_paragraph(style="List Number")
        # Markdown section headings already carry explicit numbers; avoid a second visible number.
        paragraph.style = document.styles["Normal"]
        paragraph.paragraph_format.left_indent = Inches(0.18)
        paragraph.paragraph_format.first_line_indent = Inches(-0.18)
        paragraph.paragraph_format.space_after = Pt(3)
        add_inline(paragraph, value)
    add_callout(
        document,
        "Evidence boundary: Hyperion has implemented and tested infrastructure, but no rights-approved "
        "production corpus, conforming training run, trained checkpoint, accepted benchmark, or production "
        "deployment. Every quality and readiness claim must remain attached to its evidence.",
    )
    paragraph = document.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    run.add_picture(str(architecture_path), width=Inches(6.15))
    drawing = run._r.xpath(".//wp:docPr")
    if drawing:
        drawing[0].set("descr", "Hyperion system architecture overview")
        drawing[0].set("title", "Hyperion system architecture overview")
    document.add_page_break()


def render_markdown(document: Document, source: Path) -> None:
    lines = source.read_text(encoding="utf-8").splitlines()
    headings = [line[3:].strip() for line in lines if line.startswith("## ") and not line.startswith("## Engineering")]
    asset_dir = source.parent / "assets"
    add_contents(document, headings, asset_dir / "hyperion-system-architecture.png")
    start = next(index for index, line in enumerate(lines) if re.match(r"##\s+1\.", line))
    index = start
    figure_number = 1
    active_number_id: int | None = None
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            active_number_id = None
            index += 1
            continue
        image_match = re.match(r"!\[([^]]+)\]\(([^)]+)\)", stripped)
        heading_match = re.match(r"^(#{2,4})\s+(.+)$", line)
        if heading_match:
            active_number_id = None
            level = len(heading_match.group(1)) - 1
            text = heading_match.group(2).strip()
            document.add_paragraph(text, style=f"Heading {min(level, 3)}")
            index += 1
            continue
        if image_match:
            active_number_id = None
            add_picture(document, source.parent, image_match.group(1), image_match.group(2), figure_number)
            figure_number += 1
            index += 1
            continue
        if stripped.startswith("```"):
            active_number_id = None
            index += 1
            code_lines: list[str] = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            add_code(document, "\n".join(code_lines))
            index += 1
            continue
        if stripped.startswith(">"):
            active_number_id = None
            quote: list[str] = []
            while index < len(lines) and lines[index].strip().startswith(">"):
                quote.append(lines[index].strip()[1:].strip())
                index += 1
            add_callout(document, " ".join(quote))
            continue
        if stripped.startswith("|") and index + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[index + 1]):
            active_number_id = None
            rows = [markdown_cells(line)]
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(markdown_cells(lines[index]))
                index += 1
            add_table(document, rows)
            continue
        list_match = re.match(r"^(\s*)[-*]\s+(.+)$", line)
        number_match = re.match(r"^(\s*)(\d+)\.\s+(.+)$", line)
        if list_match or number_match:
            match = list_match or number_match
            assert match
            level = min(len(match.group(1).replace("\t", "    ")) // 2, 2)
            value = match.group(2) if list_match else match.group(3)
            index += 1
            while index < len(lines) and lines[index].startswith("  ") and not re.match(r"^\s*[-*]\s+", lines[index]):
                value += " " + lines[index].strip()
                index += 1
            if list_match:
                active_number_id = None
                style_root = "List Bullet"
                style = style_root if level == 0 else f"{style_root} {level + 1}"
            else:
                if active_number_id is None:
                    active_number_id = create_numbering_instance(document, int(number_match.group(2)))
                style = "List Number" if level == 0 else f"List Number {level + 1}"
            paragraph = document.add_paragraph(style=style)
            if number_match:
                apply_numbering(paragraph, active_number_id, level)
            add_inline(paragraph, value)
            continue
        if stripped in {"---", "***"}:
            active_number_id = None
            index += 1
            continue
        active_number_id = None
        paragraph_lines = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index]
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                break
            if (
                candidate_stripped.startswith(("#", ">", "```", "![", "|"))
                or re.match(r"^\s*[-*]\s+", candidate)
                or re.match(r"^\s*\d+\.\s+", candidate)
                or candidate_stripped in {"---", "***"}
            ):
                break
            paragraph_lines.append(candidate_stripped)
            index += 1
        paragraph = document.add_paragraph()
        add_inline(paragraph, " ".join(paragraph_lines))


def build(source: Path, output: Path) -> None:
    assets = source.parent / "assets"
    build_diagrams(assets)
    document = Document()
    configure_styles(document)
    configure_document(document)
    document.core_properties.title = "Hyperion LLM Coordinator Engineering Handbook"
    document.core_properties.subject = "Frontier model architecture, model evidence, verifier safety, and ML operations"
    document.core_properties.author = "Hyperion Engineering"
    document.core_properties.keywords = "Hyperion, LLM coordinator, distillation, RLVR, QLoRA, verifier, model governance"
    document.core_properties.comments = "Private engineering material"
    settings = document.settings.element
    language = settings.find(qn("w:themeFontLang"))
    if language is None:
        language = OxmlElement("w:themeFontLang")
        settings.append(language)
    language.set(qn("w:val"), "en-GB")
    add_cover(document)
    render_markdown(document, source)
    output.parent.mkdir(parents=True, exist_ok=True)
    document.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("docs/engineering/hyperion-llm-coordinator-handbook.md"))
    parser.add_argument("--output", type=Path, default=Path("docs/engineering/hyperion-llm-coordinator-handbook.docx"))
    arguments = parser.parse_args()
    build(arguments.source.resolve(), arguments.output.resolve())
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
