"""
reports package

Forensic report generation engine for courtroom-admissible PDF documentation.
"""

from reports.generator import (
    ForensicCaseMetadata,
    ForensicReportGenerator,
    generate_pdf_report,
)

__all__ = [
    "ForensicCaseMetadata",
    "ForensicReportGenerator",
    "generate_pdf_report",
]
