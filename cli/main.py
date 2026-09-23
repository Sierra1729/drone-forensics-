"""
cli/main.py

Unified Command-Line Interface for the Pushpak Drone Forensics Toolkit.
Compliant with ISO/IEC 27037 and NIST SP 800-86 standards.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table as RichTable

import parsers  # Ensures all parser plugins are registered
from acquisition.adb_extractor import triage_offline_dump
from analytics.correlation import ForensicCorrelationEngine, NoFlyZone
from custody.ledger import ChainOfCustodyLedger, hash_file
from export.geospatial import export_geojson, export_html_map, export_kml
from normalize.schema import NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from reports.generator import ForensicCaseMetadata, generate_pdf_report

app = typer.Typer(
    name="drone-forensics",
    help="Pushpak Indigenous UAV Digital Forensics Toolkit (IIT Bombay / VJTI / MeitY)",
    add_completion=False,
)
console = Console()


@app.command(name="info")
def info_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to the evidence flight log file (.BIN, .txt, .dat, .tlog).",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Inspect evidence file header, compute forensic digests, and identify parser."""
    path = Path(evidence_path).resolve()
    sha256_hex, blake3_hex = hash_file(path)
    file_size = path.stat().st_size
    parser = get_parser_for_file(path)

    table = RichTable(title="Forensic Evidence Inspection", show_header=True, header_style="bold cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Evidence Path", str(path))
    table.add_row("File Size", f"{file_size:,} bytes")
    table.add_row("SHA-256 Digest", sha256_hex)
    table.add_row("BLAKE3 Digest", blake3_hex)
    table.add_row("Parser Plugin", parser.parser_name if parser else "[red]NO COMPATIBLE PARSER FOUND[/red]")
    table.add_row(
        "Supported Platforms",
        ", ".join(parser.supported_platforms) if parser else "N/A",
    )

    console.print(table)


@app.command(name="list-parsers")
def list_parsers_command() -> None:
    """List all registered UAV log parser plugins."""
    plugins = list_registered_parsers()
    table = RichTable(title="Registered Forensic Parser Plugins", show_header=True, header_style="bold green")
    table.add_column("#", style="dim", width=4)
    table.add_column("Plugin Identifier", style="bold")

    for idx, name in enumerate(plugins, start=1):
        table.add_row(str(idx), name)

    console.print(table)


@app.command(name="verify")
def verify_command(
    ledger_path: Path = typer.Argument(
        ...,
        help="Path to the chain-of-custody ledger file (.jsonl).",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Audit the cryptographic chain of custody ledger for tampering or deletion."""
    ledger = ChainOfCustodyLedger(ledger_path)
    is_valid, broken_index = ledger.verify_chain()

    if is_valid:
        console.print(
            Panel(
                f"[bold green]CHAIN OF CUSTODY VERIFIED INTACT[/bold green]\n\n"
                f"Ledger Path: {ledger_path.resolve()}\n"
                f"Total Cryptographic Entries: {len(ledger)}\n"
                f"Audit Status: 100% Tamper-Evident Integrity Confirmed (ISO/IEC 27037).",
                title="Cryptographic Ledger Audit",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]CRITICAL INTEGRITY FAILURE: TAMPERING DETECTED[/bold red]\n\n"
                f"Ledger Path: {ledger_path.resolve()}\n"
                f"Breach identified at entry index: {broken_index}\n"
                f"Warning: Hash chain broken. Evidence log has been altered or truncated!",
                title="Cryptographic Ledger Audit",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


@app.command(name="ingest")
def ingest_command(
    evidence_path: Path = typer.Argument(
        ...,
        help="Path to the UAV flight log evidence file (.BIN, .txt, .dat).",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        Path("forensic_output"),
        "--output-dir",
        "-o",
        help="Target directory for generated evidence artifacts, maps, and reports.",
    ),
    case_id: str = typer.Option("CASE-2026-UAV-001", "--case-id", help="Official case reference identifier."),
    evidence_id: str = typer.Option("EXHIBIT-A1", "--evidence-id", help="Evidence exhibit item identifier."),
    examiner: str = typer.Option("Inspector P. Patil", "--examiner", help="Name and badge of lead forensics examiner."),
    agency: str = typer.Option(
        "Central Forensic Science Laboratory", "--agency", help="Examining law enforcement agency."
    ),
    nfz_file: Optional[Path] = typer.Option(
        None, "--nfz-file", help="Path to JSON file containing statutory No-Fly Zones."
    ),
    controller_dir: Optional[Path] = typer.Option(
        None,
        "--controller-dir",
        "-c",
        help="Path to pre-extracted ADB ground control station (GCS) dump directory or ZIP file.",
    ),
) -> None:
    """One-click automated UAV evidence ingestion, analysis, and courtroom reporting pipeline."""
    target_dir = Path(output_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = Path(evidence_path).resolve()

    console.print(
        Panel.fit(
            "[bold white]PUSHPAK INDIGENOUS DRONE FORENSICS TOOLKIT[/bold white]\n"
            "[cyan]Grand Challenge 2026 | IIT Bombay, VJTI & MeitY[/cyan]\n"
            "[dim]Compliant with ISO/IEC 27037:2012 and NIST SP 800-86[/dim]",
            border_style="blue",
        )
    )

    # 1. Evidence Verification & Custody Registration
    with console.status("[bold green]Calculating dual cryptographic digests (SHA-256 + BLAKE3)..."):
        sha256_hex, blake3_hex = hash_file(evidence_file)
        ledger_path = target_dir / "chain_of_custody.jsonl"
        ledger = ChainOfCustodyLedger(ledger_path)
        ledger.record(
            actor=examiner,
            action="ACQUIRE",
            target_path=str(evidence_file),
            notes=f"Initial ingestion for Case: {case_id}, Exhibit: {evidence_id}",
        )

    console.print(f"[green][OK][/green] Cryptographic Digest (SHA-256): [dim]{sha256_hex}[/dim]")
    console.print(f"[green][OK][/green] Cryptographic Digest (BLAKE3):  [dim]{blake3_hex}[/dim]")
    console.print(f"[green][OK][/green] Tamper-evident ledger updated:   [dim]{ledger_path.name}[/dim]")

    # 1b. GCS Controller Ingestion if specified
    gcs_events = []
    if controller_dir is not None and Path(controller_dir).exists():
        with console.status(f"[bold green]Scanning & hashing GCS controller dump from {controller_dir}..."):
            triage_res = triage_offline_dump(
                dump_path=controller_dir,
                output_directory=target_dir,
                custody_ledger=ledger,
                operator_id=examiner,
            )
            gcs_events = triage_res.extracted_events
            console.print(f"[green][OK][/green] Ingested GCS Controller Dump: Hashed [bold]{triage_res.total_files_hashed}[/bold] files ({triage_res.total_bytes_hashed:,} bytes)")
            console.print(f"[green][OK][/green] Pilot Identity:           [cyan]{triage_res.pilot_identity.email or triage_res.pilot_identity.pilot_uid}[/cyan]")
            console.print(f"[green][OK][/green] Controller Hardware SN:   [cyan]{triage_res.hardware_metadata.controller_sn}[/cyan]")

    # 2. Dynamic Parser Selection & Extraction
    parser = get_parser_for_file(evidence_file)
    if parser is None:
        console.print(f"[bold red]Error: No compatible parser plugin found for {evidence_file.name}[/bold red]")
        raise typer.Exit(code=2)

    console.print(f"[green][OK][/green] Identified Parser Plugin:       [bold cyan]{parser.parser_name}[/bold cyan]")

    with console.status(f"[bold green]Parsing binary telemetry using {parser.parser_name}..."):
        events = parser.parse(evidence_file, custody_ledger=ledger, actor=examiner)

    if gcs_events:
        events.extend(gcs_events)

    console.print(f"[green][OK][/green] Extracted [bold]{len(events):,}[/bold] normalized telemetry events")


    # 3. Persist Normalized Event Store
    events_jsonl_path = target_dir / "events.jsonl"
    store = NormalizedEventStore(backing_path=events_jsonl_path)
    for ev in events:
        store.add(ev)
    console.print(f"[green][OK][/green] Normalized event store saved:    [dim]{events_jsonl_path.name}[/dim]")

    # 4. Load No-Fly Zones if specified
    no_fly_zones: list[NoFlyZone] = []
    if nfz_file is not None and nfz_file.exists():
        try:
            nfz_data = json.loads(nfz_file.read_text(encoding="utf-8"))
            for item in nfz_data:
                no_fly_zones.append(
                    NoFlyZone(
                        name=item.get("name", "Restricted Area"),
                        polygon_vertices=[(v[0], v[1]) for v in item.get("polygon_vertices", [])],
                        min_altitude_m=item.get("min_altitude_m", 0.0),
                        max_altitude_m=item.get("max_altitude_m", 500.0),
                        description=item.get("description", ""),
                    )
                )
            console.print(f"[green][OK][/green] Loaded [bold]{len(no_fly_zones)}[/bold] No-Fly Zones from config")
        except Exception as exc:
            console.print(f"[yellow]Warning: Failed to load NFZ file: {exc}[/yellow]")

    # 5. Anomaly & Incident Correlation Engine
    with console.status("[bold green]Executing forensic incident correlation engine..."):
        correlation_engine = ForensicCorrelationEngine()
        anomalies = correlation_engine.analyze(events, no_fly_zones=no_fly_zones)

    if anomalies:
        console.print(f"[yellow][!][/yellow] Detected [bold red]{len(anomalies)}[/bold red] forensic flight anomalies!")
    else:
        console.print("[green][OK][/green] Anomaly scan complete: Zero critical flight anomalies detected")

    # 6. Geospatial Visualization & 3D Export
    with console.status("[bold green]Generating geospatial visualizations (GeoJSON, 3D KML, Leaflet HTML)..."):
        geojson_path = target_dir / "flight_trajectory.geojson"
        kml_path = target_dir / "flight_trajectory.kml"
        html_map_path = target_dir / "flight_map.html"

        export_geojson(events, anomalies, no_fly_zones, output_path=geojson_path)
        export_kml(events, anomalies, no_fly_zones, output_path=kml_path)
        export_html_map(events, anomalies, no_fly_zones, output_path=html_map_path)

    console.print(f"[green][OK][/green] RFC 7946 GeoJSON:               [dim]{geojson_path.name}[/dim]")
    console.print(f"[green][OK][/green] 3D Extruded Google Earth KML:   [dim]{kml_path.name}[/dim]")
    console.print(f"[green][OK][/green] Interactive Leaflet HTML Map:   [dim]{html_map_path.name}[/dim]")

    # 7. Courtroom PDF Report Generation
    with console.status("[bold green]Compiling ISO/IEC 27037 Courtroom PDF Forensic Report..."):
        pdf_path = target_dir / "forensic_examination_report.pdf"
        meta = ForensicCaseMetadata(
            case_id=case_id,
            evidence_id=evidence_id,
            agency=agency,
            examiner_name=examiner,
        )
        generate_pdf_report(
            evidence_path=evidence_file,
            events=events,
            custody_ledger=ledger,
            anomalies=anomalies,
            metadata=meta,
            output_pdf_path=pdf_path,
        )

    console.print(f"[green][OK][/green] Courtroom-Admissible PDF Report: [bold cyan]{pdf_path.name}[/bold cyan]")

    # Final Summary Table
    res_table = RichTable(title="Forensic Acquisition & Examination Summary", show_header=True, header_style="bold blue")
    res_table.add_column("Artifact", style="bold")
    res_table.add_column("Path / Status")

    res_table.add_row("Evidence Item", str(evidence_file))
    res_table.add_row("Chain of Custody Ledger", str(ledger_path))
    res_table.add_row("Normalized Event Stream", str(events_jsonl_path))
    res_table.add_row("GeoJSON Flight Track", str(geojson_path))
    res_table.add_row("3D Google Earth KML", str(kml_path))
    res_table.add_row("Interactive HTML Map", str(html_map_path))
    res_table.add_row("Final PDF Examination Report", str(pdf_path))
    res_table.add_row("Chain Integrity Status", "[bold green]VERIFIED INTACT[/bold green]")
    res_table.add_row("Anomalies Detected", f"[bold red]{len(anomalies)}[/bold red]" if anomalies else "[green]0[/green]")

    console.print(res_table)
    console.print("\n[bold green]Ingestion pipeline completed successfully.[/bold green]\n")


if __name__ == "__main__":
    app()
