"""
scripts/build_proposal_pdf.py

Compiles Technical_Proposal.md into a high-quality PDF report for PUSHPAK 2026 Stage 1 Submission.
Uses ReportLab to generate a clean, court-admissible/academic proposal PDF document.
"""

import os
import re
import html
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
)
from reportlab.pdfgen import canvas

class ProposalCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e293b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "SECURITY OF DRONES (PUSHPAK GC-3) | STAGE 1 PRELIMINARY DESIGN PROPOSAL")
            self.drawRightString(612 - 54, 750, "TEAM CODE: TM-C22002DAA34")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.75)
            self.line(54, 742, 612 - 54, 742)

        # Footer
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.75)
        self.line(54, 50, 612 - 54, 50)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(54, 38, "CONFIDENTIAL — FOR PUSHPAK EVALUATION COMMITTEE ONLY")
        self.drawRightString(612 - 54, 38, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

def clean_format_text(text: str) -> str:
    tokens = []
    
    def repl_code(m):
        code_content = html.escape(m.group(1))
        tokens.append(f'<font face="Courier" size="8" color="#0f172a">{code_content}</font>')
        return f"__CODE_TOKEN_{len(tokens)-1}__"
    
    text = re.sub(r'`([^`]+)`', repl_code, text)
    
    def repl_bold(m):
        bold_content = html.escape(m.group(1))
        tokens.append(f'<b>{bold_content}</b>')
        return f"__BOLD_TOKEN_{len(tokens)-1}__"
    
    text = re.sub(r'\*\*([^*]+)\*\*', repl_bold, text)
    
    text = html.escape(text)
    
    for i, tok in enumerate(tokens):
        text = text.replace(f"__CODE_TOKEN_{i}__", tok)
        text = text.replace(f"__BOLD_TOKEN_{i}__", tok)
        
    return text

def md_to_reportlab(md_path: Path, pdf_path: Path):
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=64,
        bottomMargin=64
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1e40af"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'H3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=7,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f8fafc"),
        spaceBefore=4,
        spaceAfter=6,
        leftIndent=10,
        rightIndent=10
    )

    story = []

    lines = content.split('\n')
    in_code_block = False
    code_lines = []
    in_table = False
    table_lines = []

    def flush_code():
        nonlocal code_lines
        if code_lines:
            code_text = "<br/>".join([html.escape(line).replace(' ', '&nbsp;') for line in code_lines])
            story.append(Paragraph(code_text, code_style))
            code_lines = []

    def flush_table():
        nonlocal table_lines
        if not table_lines:
            return
        
        table_data = []
        for line in table_lines:
            if re.match(r'^\s*\|?\s*:?-+:?\s*\|', line):
                continue
            row_cells = [cell.strip() for cell in line.strip('|').split('|')]
            formatted_row = []
            for cell in row_cells:
                formatted_row.append(Paragraph(clean_format_text(cell), body_style))
            table_data.append(formatted_row)
        
        if table_data:
            col_count = max(len(r) for r in table_data)
            col_width = (612 - 108) / max(col_count, 1)
            t = Table(table_data, colWidths=[col_width]*col_count)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 4),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 8))
        table_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith('```'):
            if in_code_block:
                in_code_block = False
                flush_code()
            else:
                if in_table:
                    in_table = False
                    flush_table()
                in_code_block = True
            continue

        if in_code_block:
            code_lines.append(line)
            continue

        if '|' in stripped and ('---' in stripped or line.startswith('|') or line.strip().endswith('|')):
            if not in_table:
                in_table = True
            table_lines.append(line)
            continue
        elif in_table:
            in_table = False
            flush_table()

        if not stripped:
            continue

        if stripped == '---':
            story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#e2e8f0"), spaceBefore=8, spaceAfter=8))
            continue

        if stripped.startswith('# '):
            story.append(Paragraph(clean_format_text(stripped[2:]), title_style))
            continue
        elif stripped.startswith('## '):
            story.append(Paragraph(clean_format_text(stripped[3:]), h1_style))
            continue
        elif stripped.startswith('### '):
            story.append(Paragraph(clean_format_text(stripped[4:]), h2_style))
            continue
        elif stripped.startswith('#### '):
            story.append(Paragraph(clean_format_text(stripped[5:]), h3_style))
            continue

        if stripped.startswith('- ') or stripped.startswith('* '):
            item_text = clean_format_text(stripped[2:])
            story.append(Paragraph(f"&bull; {item_text}", bullet_style))
            continue

        num_match = re.match(r'^(\d+)\.\s+(.*)$', stripped)
        if num_match:
            num, item_text = num_match.groups()
            formatted_item = clean_format_text(item_text)
            story.append(Paragraph(f"<b>{num}.</b> {formatted_item}", bullet_style))
            continue

        story.append(Paragraph(clean_format_text(stripped), body_style))

    if in_code_block:
        flush_code()
    if in_table:
        flush_table()

    doc.build(story, canvasmaker=ProposalCanvas)
    print(f"Proposal PDF generated successfully: {pdf_path}")

if __name__ == '__main__':
    root_dir = Path(__file__).resolve().parent.parent
    md_file = root_dir / "Technical_Proposal.md"
    pdf_file = root_dir / "Security_of_Drones_TM-C22002DAA34_Report.pdf"
    md_to_reportlab(md_file, pdf_file)
