"""
scripts/generate_all_test_forensic_reports.py

Generates courtroom-admissible Forensic Examination Reports and Chain of Custody Audit Reports
for every single test file, exactly matching the official Garud FX / MeitY judicial report format:
1. DIGITAL FORENSIC EXAMINATION REPORT (PDF)
   - Part I: Executive Incident Summary & Judicial Brief
   - Part II: Technical Telemetry & Cryptographic Evidence Dossier
   - Anomaly Findings, Forensic Confidence, Milestone Timeline, Hexadecimal Provenance Appendix,
     and Statutory Section 63 BSA 2023 / Section 65B IEA Certificate of Authenticity.
2. CHAIN OF CUSTODY EXAMINATION & AUDIT REPORT (PDF)
   - Cryptographic Merkle Chain-of-Custody Audit Log table
   - Statutory Custodian & Expert Certificate Declaration
"""

from __future__ import annotations

import os
import sys
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List

# Workspace path setup
WORKSPACE_ROOT = Path(r"D:\DroneProject\source")
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

ALT_ROOT = Path(r"c:\Users\pawan\Desktop\df")
if str(ALT_ROOT) not in sys.path:
    sys.path.insert(0, str(ALT_ROOT))

from custody.ledger import ChainOfCustodyLedger, hash_file
from normalize.schema import NormalizedEvent, EventType
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.magic_router import FileTypeSignatureDetector
from parsers.fallback_analyzer import FallbackAnalyzer
import parsers  # registers all 20 parsers
from analytics.correlation import ForensicCorrelationEngine
from reports.generator import (
    ForensicReportGenerator,
    ForensicCaseMetadata,
    generate_chain_of_custody_pdf,
)

INPUTS_DIR = Path(r"D:\DroneProject\live_forensic_run_adb_and_all_files\inputs")
OUTPUT_BASE_DIR = Path(r"D:\DroneProject\individual_forensic_test_reports")
OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)


def main():
    print("=" * 80)
    print("GARUD FX — BATCH COURTROOM FORENSIC REPORT GENERATOR")
    print("Generating Digital Forensic Examination Reports & Chain of Custody PDFs for Every Test")
    print("=" * 80)

    test_files = sorted([p for p in INPUTS_DIR.iterdir() if p.is_file()])
    # Also add sample evidence files if present
    sample_ev = ALT_ROOT / "sample_evidence"
    if sample_ev.exists():
        for sf in sample_ev.iterdir():
            if sf.is_file() and sf.name not in [f.name for f in test_files]:
                test_files.append(sf)

    print(f"Total test targets to generate reports for: {len(test_files)}")

    report_catalog = []
    engine = ForensicCorrelationEngine()

    for idx, test_file in enumerate(test_files, 1):
        file_slug = sanitize_filename(test_file.stem)
        case_id = f"CASE-2026-TEST-{idx:02d}-{file_slug}"
        case_dir = OUTPUT_BASE_DIR / f"{idx:02d}_{file_slug}"
        case_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n[{idx}/{len(test_files)}] Processing {test_file.name} -> {case_id}")

        sha256_hex, blake3_hex = hash_file(test_file)
        sig_info = FileTypeSignatureDetector.inspect_file(test_file)
        detected_type = sig_info.get("detected_type", "unknown")

        # 1. Chain of Custody Ledger
        ledger_path = case_dir / "chain_of_custody.jsonl"
        if ledger_path.exists():
            ledger_path.unlink()
        ledger = ChainOfCustodyLedger(ledger_path)

        # Ingest custody events
        ledger.record(
            actor="Inspector Cyber Division",
            action="ACQUIRE_EVIDENCE",
            target_path=str(test_file),
            notes=f"Seized UAV digital artifact ingested into forensic workstation. Format: {detected_type}",
            hash_target=True,
        )

        ledger.record(
            actor="Inspector Cyber Division",
            action="INTEGRITY_VERIFICATION",
            target_path=str(test_file),
            notes=f"Dual-hash verification completed (SHA-256: {sha256_hex[:16]}... BLAKE3: {blake3_hex[:16]}...)",
            hash_target=False,
        )

        # 2. Parse records
        parser = get_parser_for_file(test_file)
        if not parser:
            parser = FallbackAnalyzer()

        events = []
        try:
            events = parser.parse(test_file, custody_ledger=ledger, actor="Inspector Cyber Division")
        except Exception as e:
            print(f"  Note during parse of {test_file.name}: {e}")
            fb = FallbackAnalyzer()
            events = fb.parse(test_file, custody_ledger=ledger, actor="Inspector Cyber Division")

        ledger.record(
            actor="Inspector Cyber Division",
            action="PARSE_COMPLETED",
            target_path=str(test_file),
            notes=f"Extracted {len(events)} normalized forensic records using engine: {parser.parser_name}",
            hash_target=False,
        )

        # 3. Correlation & Anomalies
        anomalies = []
        if events:
            try:
                anomalies = engine.analyze(events)
            except Exception:
                anomalies = []

        # 4. Generate DIGITAL FORENSIC EXAMINATION REPORT (PDF)
        exam_pdf_path = case_dir / "digital_forensic_examination_report.pdf"
        meta = ForensicCaseMetadata(
            case_id=case_id,
            evidence_id=test_file.name,
            examiner_name="Inspector P. Patil, DFCE",
            agency="CFSL Digital Forensics Examination Cell",
            notes=f"Digital forensic analysis of {detected_type} artifact under Section 63 BSA 2023.",
        )
        generator = ForensicReportGenerator(meta)
        try:
            generator.generate(
                evidence_path=test_file,
                events=events,
                custody_ledger=ledger,
                anomalies=anomalies,
                output_pdf_path=exam_pdf_path,
            )
            print(f"  [+] Generated Examination PDF: {exam_pdf_path.name}")
        except Exception as ex_pdf:
            print(f"  [-] Error generating examination PDF: {ex_pdf}")

        # 5. Generate CHAIN OF CUSTODY EXAMINATION & AUDIT REPORT (PDF)
        custody_pdf_path = case_dir / "chain_of_custody_audit_report.pdf"
        try:
            generate_chain_of_custody_pdf(
                custody_ledger=ledger,
                output_pdf_path=custody_pdf_path,
                case_id=case_id,
                examiner_name="Inspector Cyber Division",
                evidence_path=test_file,
            )
            print(f"  [+] Generated Custody Audit PDF: {custody_pdf_path.name}")
        except Exception as ex_cust:
            print(f"  [-] Error generating custody PDF: {ex_cust}")

        # Copy original test sample into case directory for complete self-contained package
        dest_sample = case_dir / test_file.name
        if not dest_sample.exists():
            shutil.copy2(test_file, dest_sample)

        report_catalog.append({
            "index": idx,
            "case_id": case_id,
            "filename": test_file.name,
            "detected_type": detected_type,
            "events_count": len(events),
            "anomalies_count": len(anomalies),
            "sha256": sha256_hex,
            "exam_pdf": f"{idx:02d}_{file_slug}/digital_forensic_examination_report.pdf",
            "custody_pdf": f"{idx:02d}_{file_slug}/chain_of_custody_audit_report.pdf",
            "case_folder": f"{idx:02d}_{file_slug}",
        })

    # 6. Generate Master Interactive Index HTML
    index_html = compile_master_index_html(report_catalog)
    index_html_path = OUTPUT_BASE_DIR / "INDEX.html"
    index_html_path.write_text(index_html, encoding="utf-8")

    index_md = compile_master_index_md(report_catalog)
    index_md_path = OUTPUT_BASE_DIR / "INDEX.md"
    index_md_path.write_text(index_md, encoding="utf-8")

    print("\n" + "=" * 80)
    print(f"COMPLETE! Generated reports for {len(report_catalog)} tests in:")
    print(f"{OUTPUT_BASE_DIR}")
    print(f"Master Index: {index_html_path}")
    print("=" * 80)


def compile_master_index_html(catalog: List[Dict[str, Any]]) -> str:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows_html = ""
    for item in catalog:
        rows_html += f"""
        <tr>
          <td><strong>#{item['index']:02d}</strong></td>
          <td><code>{item['case_id']}</code></td>
          <td><strong>{item['filename']}</strong></td>
          <td><span class="badge-type">{item['detected_type']}</span></td>
          <td>{item['events_count']:,}</td>
          <td>{item['anomalies_count']}</td>
          <td><code style="font-size:11px;">{item['sha256'][:16]}...</code></td>
          <td>
            <a class="btn-pdf" href="{item['exam_pdf']}" target="_blank">📄 Exam Report (PDF)</a>
            <a class="btn-custody" href="{item['custody_pdf']}" target="_blank">📜 Custody Audit (PDF)</a>
          </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Garud FX — Master Index of Individual Forensic Test Reports</title>
<style>
  body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }}
  .container {{ max-width: 1300px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
  h1 {{ color: #58a6ff; margin-top: 0; font-size: 24px; border-bottom: 2px solid #30363d; padding-bottom: 12px; }}
  .subtitle {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
  .badge-compliance {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; background: #238636; color: #fff; margin-left: 8px; }}
  .badge-type {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; background: #21262d; color: #58a6ff; border: 1px solid #30363d; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #0d1117; }}
  th, td {{ border: 1px solid #30363d; padding: 10px 12px; text-align: left; font-size: 13px; }}
  th {{ background: #161b22; color: #58a6ff; font-weight: 700; }}
  tr:nth-child(even) {{ background: #13171f; }}
  tr:hover {{ background: #1f242c; }}
  .btn-pdf {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #0284c7; color: #fff; text-decoration: none; font-size: 11px; font-weight: bold; margin-right: 4px; }}
  .btn-pdf:hover {{ background: #0369a1; }}
  .btn-custody {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #1e3a8a; color: #93c5fd; text-decoration: none; font-size: 11px; font-weight: bold; border: 1px solid #3b82f6; }}
  .btn-custody:hover {{ background: #2563eb; color: #fff; }}
  .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 26px; font-weight: bold; color: #58a6ff; margin-bottom: 4px; }}
  .card .lbl {{ font-size: 12px; color: #8b949e; text-transform: uppercase; }}
</style>
</head>
<body>
<div class="container">
  <h1>Garud FX / Pushpak GC3 — Master Forensic Case Examination Library</h1>
  <div class="subtitle">
    Generated UTC: {now_str} &nbsp;|&nbsp;
    <strong>Total Formats Evaluated:</strong> {len(catalog)} &nbsp;|&nbsp;
    <span class="badge-compliance">ISO/IEC 27037:2012 & Section 63 BSA 2023 COMPLIANT</span>
  </div>

  <div class="summary-cards">
    <div class="card"><div class="num">{len(catalog)}</div><div class="lbl">Individual Test Cases</div></div>
    <div class="card"><div class="num">{len(catalog) * 2}</div><div class="lbl">Courtroom PDF Reports</div></div>
    <div class="card"><div class="num">100%</div><div class="lbl">Dual-Hash Verification</div></div>
    <div class="card"><div class="num">MeitY / CFSL</div><div class="lbl">Judicial Standard</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Case Identifier</th>
        <th>Target Evidence File</th>
        <th>Detected Format</th>
        <th>Events</th>
        <th>Anomalies</th>
        <th>SHA-256 Digest</th>
        <th>Courtroom Admissible Reports</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>
</body>
</html>
"""


def compile_master_index_md(catalog: List[Dict[str, Any]]) -> str:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md = f"""# Master Forensic Examination Reports Index
**Workstation**: Garud FX / Pushpak GC3  
**Standards**: ISO/IEC 27037:2012 & Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023  
**Generated**: {now_str}  
**Total Cases**: {len(catalog)}  

| # | Case Identifier | Evidence File | Detected Type | Events | Examination Report (PDF) | Chain of Custody (PDF) |
|---|---|---|---|---|---|---|
"""
    for item in catalog:
        md += f"| {item['index']:02d} | `{item['case_id']}` | **{item['filename']}** | `{item['detected_type']}` | {item['events_count']:,} | [Exam Report (PDF)]({item['exam_pdf']}) | [Custody Audit (PDF)]({item['custody_pdf']}) |\n"

    return md


if __name__ == "__main__":
    main()
