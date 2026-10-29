from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = (
    ROOT / "products" / "free-strategy-workflow" / "manifests" / "workflow.v1.json"
)
OUTPUT = ROOT / "output" / "pdf" / "hyperion-free-cli-agentic-workflow.pdf"

PAGE_WIDTH, PAGE_HEIGHT = LETTER
LEFT = 0.72 * inch
RIGHT = 0.72 * inch
TOP = 0.68 * inch
BOTTOM = 0.62 * inch
CONTENT_WIDTH = PAGE_WIDTH - LEFT - RIGHT

NAVY = HexColor("#102A43")
BLUE = HexColor("#1F5E85")
TEAL = HexColor("#177E76")
GREEN = HexColor("#3E7B58")
AMBER = HexColor("#B7791F")
RED = HexColor("#A83E3E")
INK = HexColor("#243B53")
MUTED = HexColor("#627D98")
LINE = HexColor("#BCCCDC")
PALE = HexColor("#F3F7FA")
PALE_BLUE = HexColor("#EAF2F8")
PALE_TEAL = HexColor("#E9F5F3")
PALE_GREEN = HexColor("#EDF7F0")
PALE_AMBER = HexColor("#FFF7E8")
PALE_RED = HexColor("#FCEEEE")
WHITE = colors.white


def register_fonts() -> None:
    try:
        import matplotlib

        font_root = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
        fonts = {
            "HyperionSans": font_root / "DejaVuSans.ttf",
            "HyperionSans-Bold": font_root / "DejaVuSans-Bold.ttf",
            "HyperionSans-Oblique": font_root / "DejaVuSans-Oblique.ttf",
            "HyperionSerif": font_root / "DejaVuSerif.ttf",
            "HyperionSerif-Bold": font_root / "DejaVuSerif-Bold.ttf",
            "HyperionSerif-Italic": font_root / "DejaVuSerif-Italic.ttf",
            "HyperionMono": font_root / "DejaVuSansMono.ttf",
            "HyperionMono-Bold": font_root / "DejaVuSansMono-Bold.ttf",
        }
    except ImportError:
        fonts = {
            "HyperionSans": Path(r"C:\Windows\Fonts\arial.ttf"),
            "HyperionSans-Bold": Path(r"C:\Windows\Fonts\arialbd.ttf"),
            "HyperionSans-Oblique": Path(r"C:\Windows\Fonts\ariali.ttf"),
            "HyperionSerif": Path(r"C:\Windows\Fonts\georgia.ttf"),
            "HyperionSerif-Bold": Path(r"C:\Windows\Fonts\georgiab.ttf"),
            "HyperionSerif-Italic": Path(r"C:\Windows\Fonts\georgiai.ttf"),
            "HyperionMono": Path(r"C:\Windows\Fonts\consola.ttf"),
            "HyperionMono-Bold": Path(r"C:\Windows\Fonts\consolab.ttf"),
        }

    missing = [str(path) for path in fonts.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Required document fonts are missing: " + ", ".join(missing)
        )
    for name, path in fonts.items():
        pdfmetrics.registerFont(TTFont(name, str(path)))
    pdfmetrics.registerFontFamily(
        "HyperionSans",
        normal="HyperionSans",
        bold="HyperionSans-Bold",
        italic="HyperionSans-Oblique",
        boldItalic="HyperionSans-Bold",
    )
    pdfmetrics.registerFontFamily(
        "HyperionSerif",
        normal="HyperionSerif",
        bold="HyperionSerif-Bold",
        italic="HyperionSerif-Italic",
        boldItalic="HyperionSerif-Bold",
    )


register_fonts()

BASE = getSampleStyleSheet()
STYLES = {
    "body": ParagraphStyle(
        "Body",
        parent=BASE["BodyText"],
        fontName="HyperionSerif",
        fontSize=9.1,
        leading=13.0,
        textColor=INK,
        spaceAfter=6,
        alignment=TA_LEFT,
        allowWidows=0,
        allowOrphans=0,
    ),
    "body_tight": ParagraphStyle(
        "BodyTight",
        parent=BASE["BodyText"],
        fontName="HyperionSerif",
        fontSize=8.45,
        leading=11.5,
        textColor=INK,
        spaceAfter=4,
    ),
    "small": ParagraphStyle(
        "Small",
        parent=BASE["BodyText"],
        fontName="HyperionSans",
        fontSize=7.2,
        leading=9.6,
        textColor=INK,
    ),
    "small_muted": ParagraphStyle(
        "SmallMuted",
        parent=BASE["BodyText"],
        fontName="HyperionSans",
        fontSize=7.0,
        leading=9.4,
        textColor=MUTED,
    ),
    "table": ParagraphStyle(
        "TableCell",
        parent=BASE["BodyText"],
        fontName="HyperionSans",
        fontSize=6.8,
        leading=8.8,
        textColor=INK,
    ),
    "table_header": ParagraphStyle(
        "TableHeader",
        parent=BASE["BodyText"],
        fontName="HyperionSans-Bold",
        fontSize=6.8,
        leading=8.5,
        textColor=WHITE,
    ),
    "caption": ParagraphStyle(
        "Caption",
        parent=BASE["BodyText"],
        fontName="HyperionSans",
        fontSize=7.1,
        leading=9.4,
        textColor=MUTED,
        spaceBefore=4,
        spaceAfter=7,
    ),
    "equation": ParagraphStyle(
        "Equation",
        parent=BASE["BodyText"],
        fontName="HyperionSerif-Italic",
        fontSize=11.2,
        leading=15.0,
        textColor=NAVY,
        alignment=TA_CENTER,
    ),
    "code": ParagraphStyle(
        "Code",
        parent=BASE["Code"],
        fontName="HyperionMono",
        fontSize=7.0,
        leading=10.0,
        textColor=INK,
    ),
    "h1": ParagraphStyle(
        "Heading1",
        parent=BASE["Heading1"],
        fontName="HyperionSans-Bold",
        fontSize=17.0,
        leading=20.0,
        textColor=NAVY,
        spaceBefore=0,
        spaceAfter=8,
        keepWithNext=1,
    ),
    "h2": ParagraphStyle(
        "Heading2",
        parent=BASE["Heading2"],
        fontName="HyperionSans-Bold",
        fontSize=11.4,
        leading=14.0,
        textColor=BLUE,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=1,
    ),
    "h3": ParagraphStyle(
        "Heading3",
        parent=BASE["Heading3"],
        fontName="HyperionSans-Bold",
        fontSize=9.2,
        leading=11.5,
        textColor=TEAL,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=1,
    ),
    "cover_title": ParagraphStyle(
        "CoverTitle",
        parent=BASE["Title"],
        fontName="HyperionSans-Bold",
        fontSize=26,
        leading=30,
        textColor=WHITE,
        alignment=TA_LEFT,
        spaceAfter=9,
    ),
    "cover_subtitle": ParagraphStyle(
        "CoverSubtitle",
        parent=BASE["BodyText"],
        fontName="HyperionSerif",
        fontSize=12.5,
        leading=17,
        textColor=HexColor("#DCEAF3"),
    ),
    "cover_meta": ParagraphStyle(
        "CoverMeta",
        parent=BASE["BodyText"],
        fontName="HyperionSans",
        fontSize=8.2,
        leading=11.5,
        textColor=MUTED,
    ),
    "callout_title": ParagraphStyle(
        "CalloutTitle",
        parent=BASE["BodyText"],
        fontName="HyperionSans-Bold",
        fontSize=8.3,
        leading=10,
        textColor=NAVY,
        spaceAfter=2,
    ),
    "callout_body": ParagraphStyle(
        "CalloutBody",
        parent=BASE["BodyText"],
        fontName="HyperionSerif",
        fontSize=7.8,
        leading=10.6,
        textColor=INK,
    ),
    "reference": ParagraphStyle(
        "Reference",
        parent=BASE["BodyText"],
        fontName="HyperionSerif",
        fontSize=7.35,
        leading=10.3,
        textColor=INK,
        leftIndent=13,
        firstLineIndent=-13,
        spaceAfter=4,
    ),
}


def p(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, STYLES[style])


def heading(text: str, level: int = 1) -> Paragraph:
    return p(text, f"h{level}")


def caption(number: int, text: str) -> Paragraph:
    return p(f"<b>Figure {number}.</b> {text}", "caption")


def table_cell(text: str, header: bool = False) -> Paragraph:
    return p(text, "table_header" if header else "table")


def styled_table(
    rows: list[list[object]],
    widths: list[float],
    *,
    header: bool = True,
    font_size: float = 6.8,
    row_backgrounds: bool = True,
) -> Table:
    normalized: list[list[object]] = []
    for row_index, row in enumerate(rows):
        normalized.append(
            [
                value
                if isinstance(value, Flowable)
                else table_cell(str(value), header and row_index == 0)
                for value in row
            ]
        )
    table = Table(
        normalized, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT"
    )
    commands: list[tuple] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if row_backgrounds:
        start = 1 if header else 0
        for row_index in range(start, len(rows)):
            if (row_index - start) % 2 == 1:
                commands.append(("BACKGROUND", (0, row_index), (-1, row_index), PALE))
    table.setStyle(TableStyle(commands))
    return table


def callout(title: str, text: str, background: Color, border: Color) -> Table:
    content = [[p(title, "callout_title")], [p(text, "callout_body")]]
    result = Table(content, colWidths=[CONTENT_WIDTH], hAlign="LEFT")
    result.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.8, border),
                ("LINEBEFORE", (0, 0), (0, -1), 4.0, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
            ]
        )
    )
    return result


def equation(text: str) -> Table:
    result = Table(
        [[p(text, "equation")]], colWidths=[CONTENT_WIDTH - 28], hAlign="CENTER"
    )
    result.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE_BLUE),
                ("BOX", (0, 0), (-1, -1), 0.65, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return result


def bullets(items: Iterable[str], *, compact: bool = False) -> ListFlowable:
    style = STYLES["body_tight" if compact else "body"]
    return ListFlowable(
        [ListItem(Paragraph(item, style), leftIndent=12) for item in items],
        bulletType="bullet",
        start="circle",
        leftIndent=18,
        bulletFontName="HyperionSans",
        bulletFontSize=5.5,
        bulletColor=TEAL,
        spaceAfter=5,
    )


class Diagram(Flowable):
    def __init__(self, height: float):
        super().__init__()
        self.width = CONTENT_WIDTH
        self.height = height

    def box(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        title: str,
        detail: str = "",
        *,
        fill: Color = PALE_BLUE,
        stroke: Color = BLUE,
        title_size: float = 7.5,
        detail_size: float = 6.2,
    ) -> None:
        canvas = self.canv
        canvas.setFillColor(fill)
        canvas.setStrokeColor(stroke)
        canvas.setLineWidth(0.8)
        canvas.roundRect(x, y, width, height, 5, fill=1, stroke=1)
        canvas.setFillColor(stroke)
        canvas.setFont("HyperionSans-Bold", title_size)
        canvas.drawCentredString(x + width / 2, y + height - 13, title)
        if detail:
            paragraph = Paragraph(
                detail,
                ParagraphStyle(
                    "DiagramDetail",
                    fontName="HyperionSans",
                    fontSize=detail_size,
                    leading=detail_size + 1.8,
                    textColor=INK,
                    alignment=TA_CENTER,
                ),
            )
            _, paragraph_height = paragraph.wrap(width - 10, height - 18)
            paragraph.drawOn(
                canvas, x + 5, y + max(5, (height - 18 - paragraph_height) / 2)
            )

    def arrow(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        color: Color = BLUE,
        dashed: bool = False,
        label: str | None = None,
    ) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setStrokeColor(color)
        canvas.setFillColor(color)
        canvas.setLineWidth(1.15)
        if dashed:
            canvas.setDash(4, 3)
        canvas.line(x1, y1, x2, y2)
        if abs(x2 - x1) >= abs(y2 - y1):
            direction = 1 if x2 >= x1 else -1
            points = [x2, y2, x2 - 6 * direction, y2 + 3, x2 - 6 * direction, y2 - 3]
        else:
            direction = 1 if y2 >= y1 else -1
            points = [x2, y2, x2 - 3, y2 - 6 * direction, x2 + 3, y2 - 6 * direction]
        path = canvas.beginPath()
        path.moveTo(points[0], points[1])
        path.lineTo(points[2], points[3])
        path.lineTo(points[4], points[5])
        path.close()
        canvas.drawPath(path, fill=1, stroke=0)
        if label:
            canvas.setFont("HyperionSans", 5.8)
            canvas.setFillColor(color)
            canvas.drawCentredString((x1 + x2) / 2, (y1 + y2) / 2 + 4, label)
        canvas.restoreState()


class ArchitectureDiagram(Diagram):
    def __init__(self):
        super().__init__(250)

    def draw(self) -> None:
        self.box(
            0,
            174,
            104,
            58,
            "Operator + CLI",
            "brief, supplied sources,<br/>approvals, provider choice",
        )
        self.box(
            132,
            174,
            116,
            58,
            "Pinned BYOK profile",
            "fixed protocol + origin;<br/>secret resolved at start",
            fill=PALE_TEAL,
            stroke=TEAL,
        )
        self.box(
            276,
            174,
            112,
            58,
            "Coordinator",
            "serial state machine;<br/>budgets + strict validation",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            416,
            174,
            88,
            58,
            "Provider",
            "one bounded call<br/>per role attempt",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.arrow(104, 203, 132, 203)
        self.arrow(248, 203, 276, 203)
        self.arrow(388, 203, 416, 203)
        self.arrow(416, 187, 388, 187, color=AMBER, label="strict JSON")

        role_width = 88
        gap = 15
        roles = [
            ("Planner", "bounded spec"),
            ("Evidence Analyst", "source constraints"),
            ("Critic", "failure challenge"),
            ("Synthesizer", "inert C# draft"),
            ("Risk Judge", "Approve / Revise / Reject"),
        ]
        for index, (title, detail) in enumerate(roles):
            x = index * (role_width + gap)
            self.box(
                x,
                92,
                role_width,
                49,
                title,
                detail,
                fill=PALE_BLUE,
                stroke=BLUE,
                title_size=6.5,
                detail_size=5.6,
            )
            if index < len(roles) - 1:
                self.arrow(x + role_width, 116, x + role_width + gap, 116)
        self.arrow(332, 174, 332, 143, color=GREEN)

        self.box(
            10,
            10,
            136,
            52,
            "SQLite event chain",
            "versioned run state,<br/>budgets, approvals, hashes",
            fill=PALE,
            stroke=MUTED,
        )
        self.box(
            184,
            10,
            136,
            52,
            "Content-addressed store",
            "role outputs + exact<br/>strategy artifact bytes",
            fill=PALE,
            stroke=MUTED,
        )
        self.box(
            358,
            10,
            136,
            52,
            "Process gauntlet",
            "eight deterministic checks;<br/>no provider request",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.arrow(300, 92, 252, 63, color=MUTED)
        self.arrow(332, 92, 78, 63, color=MUTED)
        self.arrow(320, 36, 358, 36, color=GREEN)


class RolePipelineDiagram(Diagram):
    def __init__(self):
        super().__init__(165)

    def draw(self) -> None:
        role_width = 88
        gap = 15
        data = [
            ("1. Planner", "Request -> bounded<br/>specification"),
            ("2. Evidence Analyst", "Supplied sources -><br/>supported constraints"),
            ("3. Critic", "Prior outputs -><br/>failure hypotheses"),
            ("4. Synthesizer", "All prior outputs -><br/>complete inert draft"),
            ("5. Risk Judge", "Exact draft -><br/>terminal decision"),
        ]
        for index, (title, detail) in enumerate(data):
            x = index * (role_width + gap)
            fill = PALE_AMBER if index == 4 else PALE_BLUE
            stroke = AMBER if index == 4 else BLUE
            self.box(
                x,
                83,
                role_width,
                59,
                title,
                detail,
                fill=fill,
                stroke=stroke,
                title_size=6.3,
                detail_size=5.6,
            )
            if index < len(data) - 1:
                self.arrow(x + role_width, 112, x + role_width + gap, 112)
        self.box(
            22,
            8,
            126,
            42,
            "Immutable inputs",
            "objective + user sources",
            fill=PALE_TEAL,
            stroke=TEAL,
        )
        self.box(
            190,
            8,
            126,
            42,
            "Growing transcript",
            "validated outputs only",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            358,
            8,
            126,
            42,
            "No model tools",
            "no browser, shell, compiler,<br/>broker, or execution",
            fill=PALE_RED,
            stroke=RED,
        )
        self.arrow(85, 50, 44, 82, color=TEAL)
        self.arrow(253, 50, 251, 82, color=GREEN)
        self.arrow(421, 50, 456, 82, color=RED, dashed=True)


class PromptValidationDiagram(Diagram):
    def __init__(self):
        super().__init__(205)

    def draw(self) -> None:
        self.box(
            0,
            139,
            100,
            48,
            "Fixed role policy",
            "no tools; inert text;<br/>strict output schema",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            0,
            75,
            100,
            48,
            "Run inputs",
            "objective + escaped<br/>untrusted sources",
            fill=PALE_TEAL,
            stroke=TEAL,
        )
        self.box(
            0,
            11,
            100,
            48,
            "Prior outputs",
            "only already validated<br/>role artifacts",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            148,
            72,
            112,
            65,
            "Prompt renderer",
            "canonical ordering,<br/>source safety instruction,<br/>hash-bound catalog",
            fill=PALE,
            stroke=MUTED,
        )
        self.box(
            304,
            72,
            90,
            65,
            "Model call",
            "bounded request;<br/>provider selected<br/>by approved profile",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            438,
            72,
            66,
            65,
            "Parser",
            "JSON + role +<br/>citations + limits",
            fill=PALE_RED,
            stroke=RED,
        )
        self.arrow(100, 163, 148, 119)
        self.arrow(100, 99, 148, 104)
        self.arrow(100, 35, 148, 89)
        self.arrow(260, 104, 304, 104)
        self.arrow(394, 104, 438, 104)
        self.box(
            304,
            9,
            90,
            38,
            "Retry",
            "same role; bounded attempts",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            414,
            9,
            90,
            38,
            "Persist",
            "hash + event + CAS",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.arrow(471, 72, 349, 47, color=AMBER, label="invalid")
        self.arrow(471, 72, 459, 47, color=GREEN, label="valid")


class StateMachineDiagram(Diagram):
    def __init__(self):
        super().__init__(225)

    def draw(self) -> None:
        self.box(
            0,
            166,
            92,
            45,
            "Create",
            "specification<br/>stored",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            122,
            166,
            118,
            45,
            "AwaitingStartApproval",
            "exact spec hash",
            fill=PALE_AMBER,
            stroke=AMBER,
            title_size=5.9,
        )
        self.box(270, 166, 96, 45, "Ready", "approved", fill=PALE_GREEN, stroke=GREEN)
        self.box(
            400, 166, 104, 45, "Running", "serial roles", fill=PALE_GREEN, stroke=GREEN
        )
        self.arrow(92, 188, 122, 188)
        self.arrow(240, 188, 270, 188, color=GREEN)
        self.arrow(366, 188, 400, 188, color=GREEN)

        self.box(
            0,
            70,
            112,
            45,
            "Rejected",
            "review may start repair",
            fill=PALE_RED,
            stroke=RED,
        )
        self.box(
            177,
            70,
            130,
            45,
            "NeedsRevision",
            "fresh-run repair permitted",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            356,
            70,
            148,
            45,
            "AwaitingReleaseApproval",
            "Risk Judge approved;<br/>exact artifact hash",
            fill=PALE_AMBER,
            stroke=AMBER,
            title_size=6.0,
        )

        self.arrow(452, 166, 452, 145, color=NAVY)
        self.canv.setStrokeColor(NAVY)
        self.canv.setLineWidth(1.0)
        self.canv.line(56, 145, 452, 145)
        self.arrow(56, 145, 56, 115, color=RED, label="Reject")
        self.arrow(242, 145, 242, 115, color=AMBER, label="Revise")
        self.arrow(430, 145, 430, 115, color=AMBER, label="Approve")

        self.box(
            0,
            0,
            307,
            43,
            "Other terminal stops from Running",
            "Failed | BudgetExhausted | Cancelled",
            fill=PALE_RED,
            stroke=RED,
        )
        self.box(
            356,
            0,
            148,
            43,
            "Completed",
            "human released inert bytes",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.arrow(430, 70, 430, 43, color=GREEN, label="release")


class GauntletDiagram(Diagram):
    def __init__(self):
        super().__init__(264)

    def draw(self) -> None:
        checks = [
            ("1", "Event chain + profile"),
            ("2", "Exact start approval"),
            ("3", "Five role artifacts"),
            ("4", "Risk Judge approval"),
            ("5", "Artifact lineage"),
            ("6", "Inert authority flags"),
            ("7", "Release review state"),
            ("8", "Approval consistency"),
        ]
        box_width = 111
        gap_x = 20
        for index, (number, label) in enumerate(checks):
            row = 1 - index // 4
            column = index % 4
            x = column * (box_width + gap_x)
            y = 113 + row * 75
            self.box(
                x,
                y,
                box_width,
                50,
                f"Check {number}",
                label,
                fill=PALE_GREEN,
                stroke=GREEN,
                title_size=6.6,
            )

        self.box(
            92,
            23,
            138,
            52,
            "ProcessIntegrityPassed",
            "logical AND of all eight<br/>deterministic checks",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            274,
            23,
            138,
            52,
            "ReadyForHumanReview",
            "integrity passed AND status<br/>is AwaitingReleaseApproval",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        for column in range(4):
            center = column * (box_width + gap_x) + box_width / 2
            self.arrow(center, 113, 161, 75, color=GREEN)
        self.arrow(230, 49, 274, 49, color=AMBER)
        self.canv.setFont("HyperionSans-Bold", 6.4)
        self.canv.setFillColor(RED)
        self.canv.drawCentredString(
            self.width / 2,
            5,
            "Compilation, functional tests, and semantic correctness remain explicitly NOT RUN",
        )


class RepairLoopDiagram(Diagram):
    def __init__(self):
        super().__init__(230)

    def draw(self) -> None:
        self.box(
            0,
            142,
            126,
            62,
            "Root run",
            "exact objective + sources;<br/>five roles + decision R0",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            188,
            142,
            126,
            62,
            "Repair run 1",
            "parent artifacts + approved<br/>change request + diagnostics",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            378,
            142,
            126,
            62,
            "Repair run 2",
            "same lineage rules;<br/>final permitted depth",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.arrow(126, 173, 188, 173, color=AMBER, label="fresh run")
        self.arrow(314, 173, 378, 173, color=AMBER, label="fresh run")

        self.box(
            13,
            58,
            100,
            48,
            "Approval set A0",
            "new start + release",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            201,
            58,
            100,
            48,
            "Approval set A1",
            "never inherited",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            391,
            58,
            100,
            48,
            "Approval set A2",
            "never inherited",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.arrow(63, 142, 63, 106, color=GREEN)
        self.arrow(251, 142, 251, 106, color=GREEN)
        self.arrow(441, 142, 441, 106, color=GREEN)

        self.box(
            177,
            1,
            150,
            36,
            "Third-generation repair",
            "rejected before run creation",
            fill=PALE_RED,
            stroke=RED,
        )
        self.arrow(441, 58, 327, 19, color=RED, dashed=True, label="depth > 2")


class ByokDiagram(Diagram):
    def __init__(self):
        super().__init__(248)

    def draw(self) -> None:
        self.box(
            0,
            169,
            112,
            55,
            "Reviewed config",
            "named profile, model,<br/>declared prices, consent",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            144,
            169,
            112,
            55,
            "Profile registry",
            "fixed protocol + origin +<br/>credential slot name",
            fill=PALE_TEAL,
            stroke=TEAL,
        )
        self.box(
            288,
            169,
            96,
            55,
            "Start only",
            "resolve secret from<br/>environment",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            416,
            169,
            88,
            55,
            "HTTP adapter",
            "no redirects, proxy,<br/>cookies, ambient auth",
            fill=PALE_RED,
            stroke=RED,
        )
        self.arrow(112, 196, 144, 196)
        self.arrow(256, 196, 288, 196, color=TEAL)
        self.arrow(384, 196, 416, 196, color=AMBER)

        self.box(
            48,
            91,
            112,
            48,
            "Workspace",
            "config + run + hashes;<br/>no secret value",
            fill=PALE_GREEN,
            stroke=GREEN,
        )
        self.box(
            220,
            91,
            130,
            48,
            "Response guard",
            "bounded strict UTF-8 + stop reason;<br/>reject exact secret echo",
            fill=PALE_RED,
            stroke=RED,
        )
        self.box(
            392,
            91,
            112,
            48,
            "Provider round trip",
            "request includes brief, sources,<br/>and prior validated outputs",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.arrow(460, 169, 448, 139, color=AMBER, label="request")
        self.arrow(392, 115, 350, 115, color=RED, label="response")
        self.arrow(220, 115, 160, 115, color=GREEN, label="safe result")

        self.box(
            62,
            7,
            178,
            44,
            "Pinned remote profiles",
            "OpenAI, OpenRouter, Groq, Mistral,<br/>DeepSeek, Anthropic, Gemini",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.box(
            264,
            7,
            178,
            44,
            "Local / custom profiles",
            "Ollama loopback; explicit custom origin<br/>with origin-derived secret slot",
            fill=PALE_TEAL,
            stroke=TEAL,
        )


class TerminalGauntletDiagram(Diagram):
    def __init__(self):
        super().__init__(218)

    def draw(self) -> None:
        stages = [
            ("Released inert bytes", BLUE, PALE_BLUE),
            ("Exact intake", TEAL, PALE_TEAL),
            ("Restricted compile", GREEN, PALE_GREEN),
            ("Functional tests", GREEN, PALE_GREEN),
            ("Property tests", GREEN, PALE_GREEN),
            ("Sandbox behavior", AMBER, PALE_AMBER),
            ("Human registration", NAVY, PALE_BLUE),
        ]
        width = 66
        gap = 7
        for index, (title, stroke, fill) in enumerate(stages):
            x = index * (width + gap)
            self.box(
                x,
                126,
                width,
                55,
                str(index) if index else "Input",
                title,
                fill=fill,
                stroke=stroke,
                title_size=5.8,
                detail_size=5.2,
            )
            if index < len(stages) - 1:
                self.arrow(x + width, 153, x + width + gap, 153, color=stroke)

        self.box(
            55,
            34,
            174,
            55,
            "Machine-readable diagnostics",
            "parent artifact hash + stable IDs +<br/>profile and fixture hashes + safe messages",
            fill=PALE_AMBER,
            stroke=AMBER,
        )
        self.box(
            276,
            34,
            174,
            55,
            "User-approved repair request",
            "feeds a new workflow run; the model proposes<br/>a complete replacement, never a hidden patch",
            fill=PALE_BLUE,
            stroke=BLUE,
        )
        self.arrow(
            333, 126, 142, 89, color=AMBER, dashed=True, label="hard gate failure"
        )
        self.arrow(229, 61, 276, 61, color=BLUE)
        self.arrow(
            363,
            89,
            99,
            126,
            color=BLUE,
            dashed=True,
            label="fresh run outside Terminal gate",
        )
        self.canv.setFillColor(RED)
        self.canv.setFont("HyperionSans-Bold", 6.2)
        self.canv.drawCentredString(
            self.width / 2,
            10,
            "This downstream compiler/test/property/sandbox gauntlet is PROPOSED and NOT implemented by workflow gauntlet",
        )


def page_decor(canvas, doc) -> None:
    canvas.saveState()
    canvas.setTitle("Hyperion Free CLI Agentic Workflow")
    canvas.setAuthor("Hyperion Research")
    canvas.setSubject(
        "Implemented agentic workflow, process gauntlet, repair lineage, and authority boundary"
    )
    canvas.setKeywords(
        "Hyperion, agentic workflow, BYOK, strategy authoring, process integrity"
    )
    page = canvas.getPageNumber()
    if page > 1:
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(LEFT, PAGE_HEIGHT - 36, PAGE_WIDTH - RIGHT, PAGE_HEIGHT - 36)
        canvas.setFont("HyperionSans-Bold", 6.8)
        canvas.setFillColor(NAVY)
        canvas.drawString(LEFT, PAGE_HEIGHT - 27, "HYPERION RESEARCH")
        canvas.setFont("HyperionSans", 6.8)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(
            PAGE_WIDTH - RIGHT, PAGE_HEIGHT - 27, "FREE CLI AGENTIC WORKFLOW"
        )
    canvas.setStrokeColor(LINE)
    canvas.line(LEFT, 31, PAGE_WIDTH - RIGHT, 31)
    canvas.setFont("HyperionSans", 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(
        LEFT, 20, "Implemented-system paper | Version 1.0 | 8 August 2026"
    )
    canvas.drawRightString(PAGE_WIDTH - RIGHT, 20, f"Page {page}")
    canvas.restoreState()


class HyperionDocument(SimpleDocTemplate):
    def afterFlowable(self, flowable) -> None:
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        if style_name not in {"Heading1", "Heading2"}:
            return
        level = 0 if style_name == "Heading1" else 1
        text = flowable.getPlainText()
        key = f"section-{self.page}-{len(text)}-{abs(hash(text))}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=False)


def add_cover(story: list[Flowable], manifest: dict) -> None:
    banner = Table(
        [
            [p("HYPERION RESEARCH", "table_header")],
            [p("Free CLI Agentic Workflow", "cover_title")],
            [
                p(
                    "A bounded five-role coordination architecture for bring-your-own-key strategy authoring, durable review, and fresh-run repair",
                    "cover_subtitle",
                )
            ],
        ],
        colWidths=[CONTENT_WIDTH],
        rowHeights=[30, 92, 76],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("LEFTPADDING", (0, 0), (-1, -1), 24),
                ("RIGHTPADDING", (0, 0), (-1, -1), 24),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend([Spacer(1, 42), banner, Spacer(1, 25)])
    story.append(
        callout(
            "IMPLEMENTATION STATUS",
            "This paper describes the implemented Hyperion Free Strategy Workflow baseline. The five named agents are fixed serial role invocations inside one coordinator. The current gauntlet verifies process integrity only; it does not compile, execute, backtest, or certify generated strategy code.",
            PALE_GREEN,
            GREEN,
        )
    )
    story.append(Spacer(1, 18))
    meta_rows = [
        ["Document", "System design and operator assurance paper"],
        ["Version", "1.0 - 8 August 2026"],
        ["Workflow schema", manifest["schemaVersion"]],
        ["Policy", manifest["policyVersion"]],
        ["Prompt catalog SHA-256", manifest["promptCatalogSha256"]],
        [
            "Audience",
            "Project review, security review, Terminal integration, and research submission",
        ],
    ]
    meta = styled_table(
        meta_rows, [112, CONTENT_WIDTH - 112], header=False, row_backgrounds=True
    )
    story.append(meta)
    story.append(Spacer(1, 16))
    story.append(
        p(
            "<b>Core claim.</b> Reliability comes from narrow authority, immutable evidence, strict schemas, external deterministic checks, exact-hash approvals, and bounded retry - not from asking a language model to declare its own work correct.",
            "body",
        )
    )
    story.append(PageBreak())


def add_executive_overview(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("Executive overview"),
            p(
                "The Hyperion Free Strategy Workflow lets a user supply a strategy brief, approved reference sources, and a model provider they control. Hyperion then runs five fixed roles in order: Planner, Evidence Analyst, Critic, Synthesizer, and Risk Judge. Each role receives the immutable objective, untrusted supplied sources, and only the earlier outputs that have already passed structural validation. The workflow grants the model no browser, filesystem, shell, compiler, package, broker, order, or execution tool.",
            ),
            p(
                "The result is a hash-bound inert C# strategy artifact for human review. A deterministic eight-check process gauntlet verifies the durable event chain, approvals, role artifacts, decision, artifact lineage, authority flags, and release state. If revision is needed, Hyperion creates a new lineage-bound run. No source bytes or approvals are silently mutated or inherited.",
            ),
            Spacer(1, 4),
            callout(
                "WHAT IS IMPLEMENTED",
                "Serial five-role orchestration; strict JSON and citation validation; durable SQLite event history; content-addressed artifacts; bounded budgets and retries; pinned BYOK provider profiles; eight process-integrity checks; exact-hash start and release approvals; and at most two fresh repair generations.",
                PALE_GREEN,
                GREEN,
            ),
            Spacer(1, 8),
            callout(
                "WHAT IS DEFERRED",
                "Terminal-owned restricted compilation, deterministic functional tests, property and metamorphic tests, sandbox execution, and final registration authority. Diagnostics from those future gates may seed a separately approved repair run.",
                PALE_AMBER,
                AMBER,
            ),
            Spacer(1, 8),
            callout(
                "WHAT IS NOT GUARANTEED",
                "A passing process gauntlet does not prove compilation, correctness, safety, profitability, robustness, regulatory suitability, or live-trading fitness. No probabilistic agent loop can honestly promise 100 percent semantic correctness.",
                PALE_RED,
                RED,
            ),
            heading("How to read the paper", 2),
            styled_table(
                [
                    ["Part", "Question answered"],
                    [
                        "Architecture and roles",
                        "What calls what, what each role sees, and what each role may produce.",
                    ],
                    [
                        "State and gauntlet",
                        "How approvals, hashes, durable artifacts, and deterministic process checks work.",
                    ],
                    [
                        "Repair and budgets",
                        "How feedback creates fresh runs and where every loop stops.",
                    ],
                    [
                        "BYOK and threats",
                        "How provider routing, secrets, network policy, and failure recovery are bounded.",
                    ],
                    [
                        "Terminal boundary",
                        "Which stronger validation gates are deliberately outside this implementation.",
                    ],
                ],
                [128, CONTENT_WIDTH - 128],
            ),
            PageBreak(),
        ]
    )


def add_research_basis(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("1. Research basis and architecture decision"),
            p(
                "The design draws useful mechanisms from established agent and code-generation research while rejecting open-ended loops that weaken cost, authority, or auditability. ReAct interleaves reasoning and actions [1]; Reflexion and Self-Refine use feedback across attempts [2, 3]; language-agent tree search explores branches [4]; debate introduces competing arguments [5]; CRITIC and self-debugging ground revision in external observations [6, 7]; AlphaCodium and CodeT emphasize test-aware generation [8, 9]; and EvalPlus shows that shallow test suites can overstate correctness [10].",
            ),
            p(
                "Hyperion adopts a narrower rule: model critique is advisory, while deterministic external evidence controls acceptance. The current free workflow implements process evidence and a diagnostics bridge. Compilation and behavioral evidence belong to the consuming Terminal, not to the model or the current CLI.",
            ),
            styled_table(
                [
                    ["Research pattern", "Useful idea", "Hyperion decision"],
                    [
                        "ReAct [1]",
                        "Reasoning linked to observations and actions.",
                        "No model tools. Hyperion sequences calls and validations.",
                    ],
                    [
                        "Reflexion [2]",
                        "Feedback can inform a later attempt.",
                        "Exact parent artifacts and approved diagnostics enter a fresh run; no free-form persistent memory.",
                    ],
                    [
                        "Self-Refine [3]",
                        "Generation, critique, and revision.",
                        "Critic and Risk Judge advise review but cannot certify correctness.",
                    ],
                    [
                        "Tree search [4]",
                        "Branch, score, and backtrack.",
                        "Not used: branching cost and model-valued rollouts are incompatible with predictable free workflow bounds.",
                    ],
                    [
                        "Debate [5]",
                        "Disagreement may expose assumptions.",
                        "Not represented as debate: roles are serial, may share one model, and do not vote.",
                    ],
                    [
                        "CRITIC / self-debug [6, 7]",
                        "External diagnostics ground repair.",
                        "Diagnostics bridge implemented; compiler and execution tools deferred to Terminal.",
                    ],
                    [
                        "AlphaCodium / CodeT [8, 9]",
                        "Test-oriented flow improves code selection.",
                        "Future Terminal gates rerun on exact replacement bytes; generated tests never override hard failures.",
                    ],
                    [
                        "EvalPlus [10]",
                        "Expanded tests reveal false passes.",
                        "Use multiple independent gates and retain an explicit non-guarantee boundary.",
                    ],
                    [
                        "Deep research [12, 13]",
                        "Plan, search, pivot, parallelize, and synthesize sources.",
                        "Not used: this workflow has no search or subagents and accepts only user-supplied sources.",
                    ],
                ],
                [88, 145, CONTENT_WIDTH - 233],
                font_size=6.5,
            ),
            Spacer(1, 8),
            callout(
                "DESIGN DECISION",
                "One deterministic coordinator runs five fixed role prompts, validates every output, stores exact artifacts, and stops at explicit terminal states. A new repair generation is allowed only through an approved request and exact lineage. Search, debate, hidden candidates, and autonomous tools are not part of this workflow.",
                PALE_BLUE,
                BLUE,
            ),
            PageBreak(),
        ]
    )


def add_architecture(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("2. End-to-end architecture"),
            p(
                "The CLI is an operator surface around a durable coordinator. Configuration selects a reviewed provider profile. The coordinator constructs canonical role prompts, calls the selected provider serially, validates responses, and appends hash-bound events and artifacts. The gauntlet is a read-only inspection over durable state and makes no provider request.",
            ),
            ArchitectureDiagram(),
            caption(
                1,
                "Implemented end-to-end path. Model calls are serial and tool-free. Durable stores and the process gauntlet remain under Hyperion control.",
            ),
            styled_table(
                [
                    ["Component", "Authority", "Durable output"],
                    [
                        "CLI",
                        "Collect configuration, sources, actor identity, exact hashes, and explicit approvals.",
                        "Reviewed config and command result.",
                    ],
                    [
                        "Coordinator",
                        "Sequence roles, reserve and charge budgets, retry bounded failures, and apply the state machine.",
                        "Hash-chained events and snapshots.",
                    ],
                    [
                        "Provider adapter",
                        "Perform one protocol-specific completion request within fixed origin and response limits.",
                        "Validated provider result only.",
                    ],
                    [
                        "Role validator",
                        "Enforce schema, expected role, known citations, strategy file limits, and terminal decision rules.",
                        "Canonical role artifact.",
                    ],
                    [
                        "Content-addressed store",
                        "Persist exact bytes under their SHA-256 identity.",
                        "Role and strategy artifacts.",
                    ],
                    [
                        "Gauntlet",
                        "Recompute process facts from durable state without model discretion.",
                        "Versioned eight-check report.",
                    ],
                ],
                [94, 220, CONTENT_WIDTH - 314],
            ),
            PageBreak(),
        ]
    )


def add_roles(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("3. How the five agents work"),
            callout(
                "TERMINOLOGY",
                "In the product experience, each named role is called an agent. In the implementation, it is a fixed role invocation inside one serial state machine - not a separately deployed autonomous process, identity, memory, or independently trained model.",
                PALE_AMBER,
                AMBER,
            ),
            Spacer(1, 8),
            RolePipelineDiagram(),
            caption(
                2,
                "Role order and information growth. Every downstream role sees only immutable inputs and earlier validated outputs.",
            ),
            styled_table(
                [
                    [
                        "Order and role",
                        "Primary job",
                        "Permitted special output",
                        "Why it exists",
                    ],
                    [
                        "1. Planner",
                        "Turn the brief into a bounded strategy specification and identify missing requirements.",
                        "No strategy source; decision must remain None.",
                        "Reduces ambiguity before source generation.",
                    ],
                    [
                        "2. Evidence Analyst",
                        "Extract only supplied SDK, architecture, quantitative, and risk constraints.",
                        "Claims cite only known source IDs.",
                        "Separates evidence from model inference.",
                    ],
                    [
                        "3. Critic",
                        "Challenge invented APIs, lookahead, unsafe order behavior, weak controls, and unverifiable assumptions.",
                        "Risks and recommendations; no acceptance authority.",
                        "Surfaces failure hypotheses before drafting.",
                    ],
                    [
                        "4. Synthesizer",
                        "Produce one complete inert C# strategy using safe relative .cs paths.",
                        "The only role allowed to return a strategy draft.",
                        "Converts the validated context into exact reviewable bytes.",
                    ],
                    [
                        "5. Risk Judge",
                        "Review the exact draft as inert text and choose Approve, Revise, or Reject.",
                        "The only role allowed to set a terminal decision.",
                        "Creates an explicit advisory disposition for the state machine.",
                    ],
                ],
                [76, 166, 133, CONTENT_WIDTH - 375],
            ),
            heading("Independence caveat", 2),
            p(
                "All five roles may be served by the same provider and model. Their errors can therefore be correlated. The role split improves task decomposition and review coverage, but it does not create statistical independence, formal verification, or a majority vote. This is why Risk Judge approval alone is never a semantic guarantee.",
            ),
            PageBreak(),
        ]
    )


def add_prompt_mechanics(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("4. Prompt composition, output validation, and artifact identity"),
            p(
                "For role index <i>i</i>, Hyperion composes a role-specific system policy, the immutable objective, escaped source records, and validated outputs from roles 1 through <i>i - 1</i>. Source text is explicitly marked as untrusted data, so instructions embedded inside a source are not part of coordinator policy.",
            ),
            equation(
                "P<sub>i</sub> = Compose(S<sub>i</sub>, Objective, Sources, Y<sub>1:i-1</sub>) &nbsp;&nbsp;&nbsp; and &nbsp;&nbsp;&nbsp; Y<sub>i</sub> = Provider(P<sub>i</sub>)"
            ),
            PromptValidationDiagram(),
            caption(
                3,
                "A role output reaches durable workflow state only after protocol, schema, role, citation, and size checks succeed.",
            ),
            heading("Validation predicate", 2),
            equation(
                "Valid<sub>i</sub> = Schema<sub>i</sub>(Y<sub>i</sub>) AND RoleMatch<sub>i</sub> AND Citations(Y<sub>i</sub>) subset Sources AND Limits<sub>i</sub>"
            ),
            p(
                "The strict role schema rejects unknown fields. Citations must name supplied source IDs. Only the Synthesizer may include a strategy draft; only the Risk Judge may choose a terminal decision. A draft must contain one to sixteen non-empty C# files, safe relative paths, no more than 200,000 characters per file, and no more than 1,000,000 aggregate characters. These are structural controls, not C# parsing or correctness checks.",
            ),
            heading("Content identity", 2),
            equation(
                "h(x) = SHA-256(CanonicalBytes(x)) &nbsp;&nbsp;&nbsp; and &nbsp;&nbsp;&nbsp; ArtifactId = h(exact persisted artifact)"
            ),
            p(
                "The run binds its policy, workflow version, prompt-catalog hash, provider descriptor, budget, specification, approvals, role outputs, and final artifact. The strategy artifact is reproducible from the exact Synthesizer output, Risk Judge output, evidence IDs, and run identity. Hashing does not prove that content is correct; it proves which content was reviewed and whether it changed.",
            ),
            PageBreak(),
        ]
    )


def add_state_machine(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("5. Durable state machine and exact approvals"),
            p(
                "Creation stores a specification without contacting a provider. Starting requires an actor and the exact specification SHA-256. The coordinator records one start approval, runs or resumes serial roles, and transitions according to the Risk Judge decision or a bounded failure. Human release is a separate approval bound to both the specification and the final artifact hash.",
            ),
            StateMachineDiagram(),
            caption(
                4,
                "Principal states and outcomes. Explicit cancellation is terminal. A repair is a separate run and therefore does not appear as an in-place transition.",
            ),
            equation(
                "StartApproval = (RunId, h(Specification), Actor, Time) &nbsp;&nbsp;&nbsp; ReleaseApproval = (RunId, h(Specification), h(Artifact), Actor, Time)"
            ),
            heading("Resume and crash behavior", 2),
            bullets(
                [
                    "Repeating the exact start command resumes an approved Ready or Running run; it does not create another run or approval.",
                    "A still-live invocation is not duplicated. After request timeout plus 30 seconds, stale work is marked interrupted and its reserved budget is conservatively charged before bounded retry.",
                    "If a host dies after the provider accepted a request but before durable completion, external dispatch and billing may remain ambiguous. Hyperion does not claim exactly-once provider execution without a provider-backed idempotency receipt.",
                    "Explicit operator cancellation transitions to Cancelled and does not resume.",
                ],
                compact=True,
            ),
            PageBreak(),
        ]
    )


def add_gauntlet(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("6. The implemented eight-check process gauntlet"),
            p(
                "The gauntlet is a deterministic inspection of durable workflow integrity. It performs no model call and does not compile or execute source. Integrity failures fail closed before a successful report can be returned.",
            ),
            GauntletDiagram(),
            caption(
                5,
                "The report passes only when every process-integrity predicate passes. Human review readiness also requires the exact release-review state.",
            ),
            equation(
                "ProcessIntegrityPassed(run) = C<sub>1</sub> AND C<sub>2</sub> AND ... AND C<sub>8</sub>"
            ),
            styled_table(
                [
                    ["ID", "Implemented assertion"],
                    [
                        "1. verified-event-chain-and-profile",
                        "Durable events load and the run uses the exact free-strategy policy and workflow profile.",
                    ],
                    [
                        "2. exact-start-approval",
                        "Exactly one start approval binds the current specification hash and no artifact.",
                    ],
                    [
                        "3. complete-role-artifacts",
                        "Exactly one validated artifact exists for each of the five roles.",
                    ],
                    [
                        "4. risk-judge-approval",
                        "The exact Risk Judge artifact says Approve.",
                    ],
                    [
                        "5. strategy-artifact-lineage",
                        "The final artifact hash and contents reproduce from the exact run, Synthesizer, Risk Judge, and evidence IDs.",
                    ],
                    [
                        "6. inert-authority-boundary",
                        "Human release and Terminal compile consent are required; installEligible is false; delivery state is inert.",
                    ],
                    [
                        "7. release-review-state",
                        "The run is awaiting exact release review or is already completed.",
                    ],
                    [
                        "8. release-approval-consistency",
                        "Awaiting review has no release approval; Completed has exactly one approval bound to spec and artifact.",
                    ],
                ],
                [155, CONTENT_WIDTH - 155],
                font_size=6.4,
            ),
            p(
                "A malformed event chain, profile, or required artifact may fail closed before a report is returned. The CLI exits 0 for a passing process report and 2 for a returned failing report. A Completed run may still pass process integrity, but ReadyForHumanReleaseReview is true only while a passing run is AwaitingReleaseApproval.",
                "body_tight",
            ),
            PageBreak(),
        ]
    )


def add_repair(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("7. Fresh-run repair: bounded feedback without approval drift"),
            p(
                "Revision is deliberately not an in-place patch. Hyperion verifies the actual parent run and then creates a new specification containing the original sources, root objective, exact parent Synthesizer output, exact parent Risk Judge review, required user-approved change request, and optional diagnostics supplied by the user or Terminal.",
            ),
            p(
                "Diagnostics are accepted as supplied, hash-bound text. The free workflow neither creates nor executes them and does not prove that their claims are true.",
                "body_tight",
            ),
            RepairLoopDiagram(),
            caption(
                6,
                "A lineage permits at most two repair generations. Each generation reruns all five roles and receives new approvals.",
            ),
            equation(
                "Lineage<sub>r</sub> = (r, ParentRunId, h(ParentSpec), h(ParentDraft), h(ParentReview), h(ChangeRequest), h(Diagnostics))"
            ),
            styled_table(
                [
                    ["Invariant", "Enforcement"],
                    [
                        "Verified ancestry",
                        "Every loaded repair recursively checks the actual parent event chain, status, provider, artifacts, decision, root objective, and round depth.",
                    ],
                    [
                        "Provider continuity",
                        "Provider, model, protocol, endpoint, prices, and credential binding must match the parent.",
                    ],
                    [
                        "Replacement, not patch",
                        "The new objective asks for one complete strategy; the previous bytes remain immutable evidence.",
                    ],
                    [
                        "Fresh authority",
                        "No start or release approval is inherited. Every approved replacement binds new exact hashes.",
                    ],
                    [
                        "Bounded depth",
                        "Round 1 and round 2 are permitted; round 3 is rejected before run creation.",
                    ],
                    [
                        "Context headroom",
                        "Initial runs accept at most 58 user sources, reserving six of 64 slots for lineage records.",
                    ],
                    [
                        "Preflight failure",
                        "Oversized inherited evidence or repair input fails before partial lineage is created.",
                    ],
                ],
                [116, CONTENT_WIDTH - 116],
            ),
            callout(
                "CURRENT LIMIT",
                "The store does not enforce one child per parent, so sibling repair runs may be created. The depth cap is per lineage, and each new run has its own configured budget; there is no implemented aggregate root-family cost cap.",
                PALE_AMBER,
                AMBER,
            ),
            PageBreak(),
        ]
    )


def add_budgets(story: list[Flowable], manifest: dict) -> None:
    story.extend(
        [
            heading("8. Budget model, retries, and stop conditions"),
            p(
                "Bounds are part of the security and product contract. Before each provider call, Hyperion reserves capacity against request, token, byte, elapsed-time, and declared-cost ceilings. Invalid role output may consume another attempt, but it cannot create an unbounded self-correction loop.",
            ),
            styled_table(
                [
                    ["Resource", "Default per run", "Validation ceiling"],
                    ["Provider requests", "10", "1,000"],
                    ["Attempts per role", "2", "20"],
                    ["Prompt tokens", "500,000", "10,000,000"],
                    ["Output tokens", "40,000", "10,000,000"],
                    ["Output tokens per request", "8,000", "1,000,000"],
                    ["Declared cost", "USD 5", "USD 1,000,000"],
                    ["Response bytes", "1,000,000", "100,000,000"],
                    ["Artifact bytes", "2,000,000", "100,000,000"],
                    ["Elapsed time", "900 seconds", "86,400 seconds"],
                    ["Request timeout", "120 seconds", "3,600 seconds"],
                    [
                        "Repair generations",
                        str(manifest["repair"]["maximumRounds"]),
                        "2, fixed",
                    ],
                ],
                [190, 142, CONTENT_WIDTH - 332],
            ),
            Spacer(1, 8),
            equation(
                "ChargedPromptTokens = max(ProviderReportedTokens, ConservativeUtf8Estimate)"
            ),
            heading("Terminal outcomes", 2),
            styled_table(
                [
                    ["Condition", "Outcome"],
                    ["Role exhausts its attempt count", "Failed"],
                    [
                        "Non-retryable provider error, truncation, or invalid terminal response",
                        "Failed",
                    ],
                    [
                        "Request, token, byte, artifact, time, or declared-cost limit reached",
                        "BudgetExhausted",
                    ],
                    [
                        "Operator cancellation token interrupts the invocation",
                        "Cancelled",
                    ],
                    ["Risk Judge says Revise", "NeedsRevision"],
                    ["Risk Judge says Reject", "Rejected"],
                    ["Risk Judge says Approve", "AwaitingReleaseApproval"],
                    ["Exact human release approval succeeds", "Completed"],
                ],
                [322, CONTENT_WIDTH - 322],
            ),
            p(
                "There is no current diagnostic-fingerprint or no-improvement detector. Fixed per-role attempts and two repair generations are the implemented outer bounds.",
                "body_tight",
            ),
            PageBreak(),
        ]
    )


def add_byok(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("9. Bring-your-own-key provider routing"),
            p(
                "The CLI chooses a named profile instead of allowing every network field to vary. Each built-in remote profile fixes its origin, protocol, authentication adapter, and environment-variable slot. Secrets are resolved only when a live start needs them and are excluded from config, run specification, workspace, artifacts, and CLI output.",
            ),
            ByokDiagram(),
            caption(
                7,
                "Credential routing and persistence boundary. The nonsecret slot name is hash-bound; the secret value is not stored.",
            ),
            styled_table(
                [
                    ["Profile family", "Protocol and boundary"],
                    ["mock", "Network-free rehearsal with no provider key."],
                    [
                        "ollama",
                        "Loopback OpenAI-compatible HTTP at the pinned local origin; no key by default.",
                    ],
                    [
                        "openai / openrouter / groq / mistral / deepseek",
                        "Pinned HTTPS origin and OpenAI-compatible adapter with a dedicated DAXALGO_LLM_* slot.",
                    ],
                    [
                        "anthropic",
                        "Pinned official HTTPS origin with native Anthropic Messages protocol and authentication.",
                    ],
                    [
                        "gemini",
                        "Pinned official HTTPS origin with native Gemini generateContent protocol and authentication.",
                    ],
                    [
                        "custom-openai-compatible",
                        "Explicit custom-provider consent; canonical origin determines a full SHA-256 credential-slot suffix.",
                    ],
                    [
                        "external-adapter/v1",
                        "Embedding Terminal owns endpoint, authentication, egress consent, credential store, and redaction.",
                    ],
                ],
                [150, CONTENT_WIDTH - 150],
            ),
            callout(
                "OPENAI ROUTE LIMIT",
                "The current OpenAI profile uses a constrained Chat Completions adapter and rejects o-series model IDs because its bounded request shape is incompatible with those models. Native OpenAI Responses support is deferred.",
                PALE_AMBER,
                AMBER,
            ),
            Spacer(1, 6),
            p(
                "The routing controls do not declare a selected provider trustworthy. Hyperion grants the model no tools, but it cannot prove that an independently operated remote service or local daemon performs no activity outside the request.",
                "body_tight",
            ),
            PageBreak(),
        ]
    )


def add_security(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("10. Threat model and failure containment"),
            p(
                "The workflow assumes model output and supplied sources are untrusted. It limits what can leave the process, what can enter durable state, and what authority an accepted artifact receives. The table separates implemented mitigations from residual risk.",
            ),
            styled_table(
                [
                    ["Threat", "Implemented containment", "Residual risk"],
                    [
                        "Prompt injection in a source",
                        "Escape source records; label them untrusted data; fixed system policy; no model tools.",
                        "A model may still follow malicious prose or produce poor advice; downstream validation remains necessary.",
                    ],
                    [
                        "Invented SDK or API",
                        "Evidence Analyst and Critic prompts; known source citations; Risk Judge review.",
                        "No compiler currently runs, so invented symbols may remain in inert source.",
                    ],
                    [
                        "Artifact tampering",
                        "Content-addressed bytes, event-chain validation, exact artifact reconstruction, exact-hash approval.",
                        "Hashes identify changed bytes but cannot establish semantic quality.",
                    ],
                    [
                        "Approval replay or drift",
                        "Exactly one approval at each gate; start binds spec; release binds spec and artifact; repairs inherit no approval.",
                        "Actor identity is local workflow evidence, not a public-key signature claim.",
                    ],
                    [
                        "Credential exfiltration",
                        "Fixed origins and slots, no redirects/proxy/cookies/ambient auth, whitespace/control rejection, exact-secret echo filter.",
                        "A trusted provider receives the key by design; custom/private network and DNS behavior still require production hardening.",
                    ],
                    [
                        "Provider endpoint drift",
                        "Pinned profile descriptor is part of the approved run binding; resume and repair reject mismatch.",
                        "Provider behavior behind the same origin may change without a capability fingerprint.",
                    ],
                    [
                        "Runaway inference cost",
                        "Requests, attempts, tokens, bytes, time, and declared cost are bounded per run.",
                        "No aggregate budget across sibling repairs or an entire root family.",
                    ],
                    [
                        "Crash after dispatch",
                        "Durable state, stale detection, conservative reservation charge, bounded retry.",
                        "External execution or billing may be duplicated without provider idempotency evidence.",
                    ],
                    [
                        "Unsafe generated behavior",
                        "Artifact is inert, human release and Terminal compile consent required, installEligible false.",
                        "Safety, behavior, and profitability remain unverified until separate Terminal gates run.",
                    ],
                ],
                [94, 216, CONTENT_WIDTH - 310],
                font_size=6.2,
            ),
            heading("Plaintext local workspace", 2),
            p(
                "The workspace contains the brief, supplied sources, role outputs, approvals, and generated source in plaintext SQLite and content-addressed files. Review commands may emit specifications or artifacts to standard output. Users must choose a private workspace, protect logs, and apply an appropriate retention policy. A production Terminal integration remains responsible for app-owned storage, operating-system-backed secrets, run-bound egress receipts, and safe deletion.",
            ),
            PageBreak(),
        ]
    )


def add_operator_walkthrough(story: list[Flowable]) -> None:
    command_text = """
<b>1. Configure:</b> hyperion workflow init --config workflow.json --profile anthropic --model MODEL --input-price PRICE --output-price PRICE --allow-provider-egress<br/>
<b>2. Create:</b> hyperion workflow create --config workflow.json --workspace PATH --brief brief.md --source sdk=SDK.md<br/>
<b>3. Approve and run:</b> hyperion workflow start --config workflow.json --workspace PATH --run RUN_ID --spec SHA256 --actor USER<br/>
<b>4. Inspect:</b> hyperion workflow gauntlet --config workflow.json --workspace PATH --run RUN_ID<br/>
<b>5. Review:</b> hyperion workflow show --config workflow.json --workspace PATH --run RUN_ID<br/>
<b>6a. Release inert bytes:</b> hyperion workflow release --config workflow.json --workspace PATH --run RUN_ID --artifact SHA256 --actor USER<br/>
<b>6b. Or repair:</b> hyperion workflow revise --config workflow.json --workspace PATH --run RUN_ID --request change.md --diagnostics diagnostics.json --owner USER
"""
    story.extend(
        [
            heading("11. Operator walkthrough and evidence produced"),
            p(
                "The normal path has two explicit approvals and no hidden deployment step. The operator first approves the exact run specification, then reviews the generated artifact and process report before releasing those exact inert bytes to the next stage.",
            ),
            Table(
                [[p(command_text, "code")]],
                colWidths=[CONTENT_WIDTH],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F5F7FA")),
                        ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                    ]
                ),
            ),
            heading("Evidence ledger", 2),
            styled_table(
                [
                    ["Moment", "Human sees", "Durable evidence"],
                    [
                        "After create",
                        "Objective, sources, provider descriptor, budget, and specification SHA-256.",
                        "AwaitingStartApproval snapshot.",
                    ],
                    [
                        "After start",
                        "Role progress, status, resource usage, and terminal decision.",
                        "Exactly one start approval plus hash-chained role events.",
                    ],
                    [
                        "After gauntlet",
                        "Eight pass/fail checks and explicit not-run semantic fields.",
                        "Versioned gauntlet report derived from durable state.",
                    ],
                    [
                        "Before release",
                        "Exact source files, evidence IDs, role outputs, risk decision, and artifact SHA-256.",
                        "AwaitingReleaseApproval with no release approval yet.",
                    ],
                    [
                        "After release",
                        "Completed state for the same exact artifact.",
                        "Exactly one release approval bound to spec and artifact.",
                    ],
                    [
                        "After revise",
                        "New run ID, new specification hash, explicit parent lineage, and new approval requirement.",
                        "Fresh AwaitingStartApproval run; parent remains immutable.",
                    ],
                ],
                [96, 210, CONTENT_WIDTH - 306],
            ),
            callout(
                "REVIEW QUESTION",
                "The correct release question is: 'May these exact inert bytes proceed to the Terminal verification stage?' It is not: 'Is this strategy safe, profitable, compiled, or ready to trade?'",
                PALE_BLUE,
                BLUE,
            ),
            PageBreak(),
        ]
    )


def add_terminal_boundary(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("12. Proposed Terminal-owned verification gauntlet"),
            p(
                "After human release or import, the consuming Terminal should independently validate the exact artifact in a restricted environment. These gates are a design target, not behavior of the current workflow gauntlet.",
            ),
            TerminalGauntletDiagram(),
            caption(
                8,
                "Proposed downstream verification and diagnostics feedback. Every repair returns to a fresh Hyperion run and then repeats all applicable Terminal gates from clean state.",
            ),
            styled_table(
                [
                    ["Deferred gate", "Required evidence", "Failure disposition"],
                    [
                        "1. Exact intake",
                        "Artifact, file, compiler profile, SDK/context pack, and source-manifest hashes.",
                        "Reject any drift.",
                    ],
                    [
                        "2. Restricted compile",
                        "Pinned compiler/toolchain; no package restore, network, broker, or model authority; normalized diagnostics.",
                        "Hard fail; diagnostics may seed an approved repair.",
                    ],
                    [
                        "3. Functional tests",
                        "Versioned golden and request-derived tests for lifecycle, state, signals, order intent, sizing, exits, and controls.",
                        "Hard fail; a model cannot waive an assertion.",
                    ],
                    [
                        "4. Property tests",
                        "Determinism, bounds, causality, missing/extreme inputs, risk invariants, and declared metamorphic relations.",
                        "Hard fail or explicitly inconclusive; never semantic pass on inconclusive evidence.",
                    ],
                    [
                        "5. Sandbox behavior",
                        "Frozen fixtures, bounded CPU/memory/time, no network or broker, exception and trace records.",
                        "Terminate on authority or resource violation.",
                    ],
                    [
                        "6. Human registration",
                        "Source, diagnostics, tests, properties, residual risks, and exact hashes.",
                        "No registration without separate Terminal authority.",
                    ],
                ],
                [88, 246, CONTENT_WIDTH - 334],
                font_size=6.2,
            ),
            p(
                "Synthetic fixtures produced for these gates would be workflow-verification evidence only. They must not be described as model-training evidence or as proof of trading quality.",
                "body_tight",
            ),
            PageBreak(),
        ]
    )


def add_assurance_boundary(story: list[Flowable]) -> None:
    story.extend(
        [
            heading("13. Assurance boundary and evaluation protocol"),
            p(
                "A reliable review separates process integrity from program behavior. The implemented gauntlet can establish provenance, completeness, structural validity, and approval consistency for exact bytes. It cannot establish claims that require parsing, compilation, execution, market data, or statistical evaluation.",
            ),
            styled_table(
                [
                    ["A passing current gauntlet establishes", "It does not establish"],
                    [
                        "Exact policy, workflow, prompt catalog, provider, budget, specification, and event lineage.",
                        "That the provider is truthful, independent, stable, or high quality.",
                    ],
                    [
                        "Complete structurally valid role artifacts and an approving Risk Judge output.",
                        "That the Risk Judge is a formal verifier or that agent debate occurred.",
                    ],
                    [
                        "Reproduction of the inert strategy artifact from exact approved lineage.",
                        "Parsing, compilation, linking, loading, execution, or behavioral correctness.",
                    ],
                    [
                        "Bounded workflow authority and no install eligibility.",
                        "Absence of unsafe logic, lookahead, leakage, numerical defects, or excessive risk.",
                    ],
                    [
                        "Human approvals bound to exact hashes.",
                        "Profitability, robustness, suitability, compliance, or live-trading safety.",
                    ],
                ],
                [CONTENT_WIDTH / 2, CONTENT_WIDTH / 2],
            ),
            heading("Recommended evaluation layers", 2),
            styled_table(
                [
                    ["Layer", "Metric", "Interpretation"],
                    [
                        "Workflow integrity",
                        "Eight-check pass rate; corrupted-state rejection; approval-binding tests.",
                        "Does the coordinator fail closed and preserve exact lineage?",
                    ],
                    [
                        "Generation utility",
                        "Structural-validity rate, citation validity, provider cost, latency, repair rate.",
                        "Can the selected model satisfy the narrow output contract efficiently?",
                    ],
                    [
                        "Compiler evidence",
                        "Compile-at-one and compile-after-repair under a pinned toolchain.",
                        "Do exact artifacts satisfy syntax, types, and SDK contracts?",
                    ],
                    [
                        "Behavioral evidence",
                        "Functional, property, metamorphic, and sandbox pass rates on sealed fixtures.",
                        "Do tested behaviors match declared requirements and invariants?",
                    ],
                    [
                        "Trading research",
                        "Out-of-sample protocol, leakage controls, robustness, uncertainty, and economic assumptions.",
                        "Separate research evidence; never implied by code-generation success.",
                    ],
                ],
                [94, 205, CONTENT_WIDTH - 299],
            ),
            heading("Acceptance rule", 2),
            equation(
                "Proceed = ProcessIntegrity AND HumanRelease AND TerminalHardGates AND RegistrationConsent"
            ),
            p(
                "Each term is necessary; none may be replaced by model confidence or persuasive prose. Even when all proposed Terminal gates pass, the evidence is scoped to the exact artifact, toolchain, profiles, fixtures, and tests used. It is not a universal proof of profitability or behavior under all market conditions.",
            ),
            PageBreak(),
        ]
    )


def add_implementation_map(story: list[Flowable], manifest: dict) -> None:
    story.extend(
        [
            heading("14. Implementation map and reproducibility"),
            p(
                "The paper is grounded in the repository artifacts below. Normative version strings and limits should be read from code and the manifest if this explanatory paper ever becomes stale.",
            ),
            styled_table(
                [
                    ["Concern", "Repository anchor"],
                    [
                        "Workflow contracts, defaults, gauntlet report, repair lineage",
                        "src/windows/AI/Hyperion.FreeStrategyWorkflow/FreeStrategyWorkflowContracts.cs",
                    ],
                    [
                        "Create, start, gauntlet, release, recursive repair validation",
                        "src/windows/AI/Hyperion.FreeStrategyWorkflow/FreeStrategyWorkflowRunner.cs",
                    ],
                    [
                        "Five role instructions and prompt-catalog hash",
                        "src/windows/AI/TradingTerminal.Ai.Coordinator/Orchestration/CoordinatorPromptCatalog.cs",
                    ],
                    [
                        "Coordinator state machine",
                        "src/windows/AI/TradingTerminal.Ai.Coordinator/Orchestration/ResearchCoordinator.cs",
                    ],
                    [
                        "CLI commands and disclosures",
                        "src/windows/Tools/Hyperion.Cli/FreeStrategyWorkflowCli.cs",
                    ],
                    [
                        "Pinned provider profiles",
                        "src/windows/Tools/Hyperion.Cli/FreeStrategyWorkflowCliConfig.cs",
                    ],
                    [
                        "Provider runtime and secret resolution",
                        "src/windows/Tools/Hyperion.Cli/FreeStrategyWorkflowCliRuntime.cs",
                    ],
                    [
                        "Native Anthropic and Gemini adapters",
                        "src/windows/AI/TradingTerminal.Ai.Coordinator/Providers/",
                    ],
                    [
                        "Distributable contract",
                        "products/free-strategy-workflow/manifests/workflow.v1.json",
                    ],
                    [
                        "Research comparison and future design",
                        "products/free-strategy-workflow/planning/agentic-gauntlet-design.md",
                    ],
                    [
                        "Workflow and provider tests",
                        "tests/TradingTerminal.Tests.Pro.Headless/Coordinator/",
                    ],
                ],
                [176, CONTENT_WIDTH - 176],
            ),
            heading("Version snapshot", 2),
            styled_table(
                [
                    ["Field", "Value"],
                    ["Workflow schema", manifest["schemaVersion"]],
                    ["Gauntlet schema", manifest["gauntlet"]["schemaVersion"]],
                    ["Repair schema", manifest["repair"]["schemaVersion"]],
                    ["Strategy artifact schema", manifest["output"]["schemaVersion"]],
                    ["Maximum repair rounds", str(manifest["repair"]["maximumRounds"])],
                    [
                        "Maximum initial user sources",
                        str(manifest["repair"]["maximumInitialSources"]),
                    ],
                    ["Model tools", "none"],
                    ["SemanticCorrectnessGuaranteed", "false"],
                    ["CompilationVerification", "not-run-by-free-workflow"],
                    ["FunctionalVerification", "not-run-by-free-workflow"],
                ],
                [190, CONTENT_WIDTH - 190],
            ),
            callout(
                "REPRODUCIBILITY NOTE",
                "This PDF is generated from a repository-owned Python builder using ReportLab. It embeds fonts, uses vector diagrams and tables, reads the current workflow manifest, and is visually verified by rendering every page through Poppler.",
                PALE_BLUE,
                BLUE,
            ),
            PageBreak(),
        ]
    )


def add_references(story: list[Flowable]) -> None:
    references = [
        (
            "[1]",
            "Yao et al. ReAct: Synergizing Reasoning and Acting in Language Models.",
            "https://arxiv.org/abs/2210.03629",
        ),
        (
            "[2]",
            "Shinn et al. Reflexion: Language Agents with Verbal Reinforcement Learning.",
            "https://arxiv.org/abs/2303.11366",
        ),
        (
            "[3]",
            "Madaan et al. Self-Refine: Iterative Refinement with Self-Feedback.",
            "https://arxiv.org/abs/2303.17651",
        ),
        (
            "[4]",
            "Zhou et al. Language Agent Tree Search Unifies Reasoning, Acting, and Planning.",
            "https://arxiv.org/abs/2310.04406",
        ),
        (
            "[5]",
            "Du et al. Improving Factuality and Reasoning through Multiagent Debate.",
            "https://arxiv.org/abs/2305.14325",
        ),
        (
            "[6]",
            "Gou et al. CRITIC: Large Language Models Can Self-Correct with Tool-Interactive Critiquing.",
            "https://arxiv.org/abs/2305.11738",
        ),
        (
            "[7]",
            "Chen et al. Teaching Large Language Models to Self-Debug.",
            "https://arxiv.org/abs/2304.05128",
        ),
        (
            "[8]",
            "Ridnik et al. Code Generation with AlphaCodium: From Prompt Engineering to Flow Engineering.",
            "https://arxiv.org/abs/2401.08500",
        ),
        (
            "[9]",
            "Chen et al. CodeT: Code Generation with Generated Tests.",
            "https://arxiv.org/abs/2207.10397",
        ),
        (
            "[10]",
            "Liu et al. Is Your Code Generated by ChatGPT Really Correct? EvalPlus.",
            "https://arxiv.org/abs/2305.01210",
        ),
        (
            "[11]",
            "Huang et al. Large Language Models Cannot Self-Correct Reasoning Yet.",
            "https://arxiv.org/abs/2310.01798",
        ),
        (
            "[12]",
            "OpenAI. Introducing deep research.",
            "https://openai.com/index/introducing-deep-research/",
        ),
        (
            "[13]",
            "Anthropic. How we built our multi-agent research system.",
            "https://www.anthropic.com/engineering/multi-agent-research-system",
        ),
        (
            "[14]",
            "OpenAI API reference. Create chat completion.",
            "https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create",
        ),
    ]
    story.extend(
        [
            heading("References"),
            p(
                "References describe design precedents and limitations. Their reported results are not Hyperion benchmark results, and citation does not imply that Hyperion implements the cited system in full.",
            ),
        ]
    )
    for number, title, url in references:
        story.append(
            p(
                f'{number} {title} <link href="{url}" color="#1F5E85">{url}</link>',
                "reference",
            )
        )
    story.extend(
        [
            Spacer(1, 10),
            HRFlowable(width="100%", thickness=0.6, color=LINE),
            Spacer(1, 8),
            heading("Conclusion", 2),
            p(
                "Hyperion's free CLI workflow is best understood as a bounded, durable authoring protocol around an untrusted model. Five fixed roles improve decomposition and review coverage; exact artifacts, hash-bound approvals, process gates, and fresh-run repair preserve accountability. The model proposes. Hyperion records and constrains. Humans release exact inert bytes. The Terminal must separately compile, test, sandbox, and authorize any later use.",
            ),
            callout(
                "ONE-SENTENCE SYSTEM MODEL",
                "A serial role team produces a reviewable proposal; deterministic infrastructure decides whether the proposal's process evidence is intact; separate Terminal authority decides whether exact bytes may ever become executable.",
                PALE_GREEN,
                GREEN,
            ),
        ]
    )


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected_roles = [
        "Planner",
        "EvidenceAnalyst",
        "Critic",
        "Synthesizer",
        "RiskJudge",
    ]
    if manifest.get("schemaVersion") != "hyperion-free-strategy-workflow/v1":
        raise ValueError("Unexpected workflow manifest schema")
    if manifest.get("roles") != expected_roles:
        raise ValueError(
            "Workflow role order changed; update the paper before rebuilding"
        )
    if manifest.get("gauntlet", {}).get("semanticCorrectnessGuaranteed") is not False:
        raise ValueError("Paper requires the explicit semantic non-guarantee")
    if manifest.get("modelTools") != []:
        raise ValueError("Paper assumes the implemented workflow grants no model tools")
    return manifest


def build() -> Path:
    manifest = load_manifest()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = HyperionDocument(
        str(OUTPUT),
        pagesize=LETTER,
        rightMargin=RIGHT,
        leftMargin=LEFT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="Hyperion Free CLI Agentic Workflow",
        author="Hyperion Research",
        subject="Implemented agentic workflow, gauntlet, repair, and authority boundary",
        pageCompression=1,
    )
    story: list[Flowable] = []
    add_cover(story, manifest)
    add_executive_overview(story)
    add_research_basis(story)
    add_architecture(story)
    add_roles(story)
    add_prompt_mechanics(story)
    add_state_machine(story)
    add_gauntlet(story)
    add_repair(story)
    add_budgets(story, manifest)
    add_byok(story)
    add_security(story)
    add_operator_walkthrough(story)
    add_terminal_boundary(story)
    add_assurance_boundary(story)
    add_implementation_map(story, manifest)
    add_references(story)
    document.build(story, onFirstPage=page_decor, onLaterPages=page_decor)
    return OUTPUT


if __name__ == "__main__":
    print(build())
