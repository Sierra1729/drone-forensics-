"""
tests/test_cli.py

Integration test suite for the Drone Forensics Typer CLI interface.
Validates:
1. `drone-forensics list-parsers` command.
2. `drone-forensics info` command.
3. `drone-forensics verify` command on valid and tampered ledgers.
4. `drone-forensics ingest` command executing the full end-to-end pipeline.
"""

import json
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app
from custody.ledger import ChainOfCustodyLedger
from tests.synthetic_ardupilot import generate_synthetic_ardupilot_bin
from tests.synthetic_dji import generate_synthetic_dji_log

runner = CliRunner()


def test_cli_list_parsers():
    result = runner.invoke(app, ["list-parsers"])
    assert result.exit_code == 0
    assert "ardupilot_dataflash_bin" in result.stdout
    assert "dji_flight_log" in result.stdout


def test_cli_info(tmp_path):
    bin_file = tmp_path / "test_flight.bin"
    generate_synthetic_ardupilot_bin(bin_file)

    result = runner.invoke(app, ["info", str(bin_file)])
    assert result.exit_code == 0
    assert "ardupilot_dataflash_bin" in result.stdout
    assert "SHA-256 Digest" in result.stdout
    assert "BLAKE3 Digest" in result.stdout


def test_cli_verify_chain(tmp_path):
    bin_file = tmp_path / "test_flight.bin"
    bin_file.write_bytes(b"dummy flight evidence")

    ledger_path = tmp_path / "audit_ledger.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)
    ledger.record(actor="examiner_1", action="ACQUIRE", target_path=bin_file)
    ledger.record(actor="examiner_1", action="ANALYZE", target_path=bin_file)

    # Clean verification
    res_clean = runner.invoke(app, ["verify", str(ledger_path)])
    assert res_clean.exit_code == 0
    assert "CHAIN OF CUSTODY VERIFIED INTACT" in res_clean.stdout

    # Tamper with ledger
    lines = ledger_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["actor"] = "malicious_actor"
    lines[1] = json.dumps(entry)
    ledger_path.write_text("\n".join(lines) + "\n")

    res_tampered = runner.invoke(app, ["verify", str(ledger_path)])
    assert res_tampered.exit_code == 1
    assert "CRITICAL INTEGRITY FAILURE" in res_tampered.stdout


def test_cli_ingest_ardupilot(tmp_path):
    bin_file = tmp_path / "test_flight.bin"
    generate_synthetic_ardupilot_bin(bin_file)

    out_dir = tmp_path / "ardupilot_out"

    result = runner.invoke(
        app,
        [
            "ingest",
            str(bin_file),
            "--output-dir",
            str(out_dir),
            "--case-id",
            "CASE-MUM-2026-999",
            "--evidence-id",
            "ITEM-01",
            "--examiner",
            "Inspector Sharma",
        ],
    )
    assert result.exit_code == 0
    assert "Ingestion pipeline completed successfully" in result.stdout

    # Verify all generated artifacts exist
    assert (out_dir / "chain_of_custody.jsonl").exists()
    assert (out_dir / "events.jsonl").exists()
    assert (out_dir / "flight_trajectory.geojson").exists()
    assert (out_dir / "flight_trajectory.kml").exists()
    assert (out_dir / "flight_map.html").exists()
    assert (out_dir / "forensic_examination_report.pdf").exists()


def test_cli_ingest_dji(tmp_path):
    dji_file = tmp_path / "test_dji.txt"
    generate_synthetic_dji_log(dji_file)

    out_dir = tmp_path / "dji_out"

    result = runner.invoke(
        app,
        [
            "ingest",
            str(dji_file),
            "--output-dir",
            str(out_dir),
            "--case-id",
            "CASE-DJI-2026-444",
        ],
    )
    assert result.exit_code == 0
    assert "Ingestion pipeline completed successfully" in result.stdout

    assert (out_dir / "chain_of_custody.jsonl").exists()
    assert (out_dir / "events.jsonl").exists()
    assert (out_dir / "flight_trajectory.geojson").exists()
    assert (out_dir / "flight_trajectory.kml").exists()
    assert (out_dir / "flight_map.html").exists()
    assert (out_dir / "forensic_examination_report.pdf").exists()
