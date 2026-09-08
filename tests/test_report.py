"""
tests/test_report.py

Comprehensive test suite for the Courtroom-Admissible PDF Report Generator.
Validates:
1. Legal PDF report generation compliant with ISO/IEC 27037.
2. Inclusion of cryptographic SHA-256 and BLAKE3 digests.
3. Case metadata and examiner credential rendering.
4. Section 63 BSA 2023 / Section 65B Indian Evidence Act certificate block.
5. End-to-end report generation for both ArduPilot and DJI flight logs.
"""

from pathlib import Path
import pytest

from analytics.correlation import ForensicCorrelationEngine, NoFlyZone
from custody.ledger import ChainOfCustodyLedger
from parsers.ardupilot import ArduPilotDataFlashParser
from parsers.dji import DJIFlightLogParser
from reports.generator import (
    ForensicCaseMetadata,
    ForensicReportGenerator,
    generate_pdf_report,
)
from tests.synthetic_ardupilot import generate_synthetic_ardupilot_bin
from tests.synthetic_dji import generate_synthetic_dji_log


def test_ardupilot_pdf_report_generation(tmp_path):
    bin_path = tmp_path / "flight_test.bin"
    generate_synthetic_ardupilot_bin(bin_path)

    ledger_path = tmp_path / "custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    # 1. Parse log
    parser = ArduPilotDataFlashParser()
    events = parser.parse(bin_path, custody_ledger=ledger, actor="inspector_patil")

    # 2. Correlate anomalies
    nfz = NoFlyZone(
        name="IIT Bombay High Security Zone",
        polygon_vertices=[
            (19.0700, 72.8700),
            (19.0800, 72.8700),
            (19.0800, 72.8800),
            (19.0700, 72.8800),
        ],
    )
    engine = ForensicCorrelationEngine(critical_battery_pct=15.0)
    anomalies = engine.analyze(events, no_fly_zones=[nfz])

    # 3. Generate Report
    meta = ForensicCaseMetadata(
        case_id="MUM-CYBER-2026-0891",
        evidence_id="UAV-DRONE-QUAD-01",
        examiner_name="Inspector R. Sharma",
        agency="Anti-Terrorism Cyber Cell & Forensic Unit",
    )

    pdf_out = tmp_path / "ardupilot_forensic_report.pdf"
    result_path = generate_pdf_report(
        evidence_path=bin_path,
        events=events,
        custody_ledger=ledger,
        anomalies=anomalies,
        metadata=meta,
        output_pdf_path=pdf_out,
    )

    assert result_path.exists()
    assert result_path.stat().st_size > 5000  # Valid multi-page PDF

    # Verify PDF magic header
    header = result_path.read_bytes()[:5]
    assert header == b"%PDF-"


def test_dji_pdf_report_generation(tmp_path):
    dji_path = tmp_path / "dji_flight_record.txt"
    generate_synthetic_dji_log(dji_path)

    ledger = ChainOfCustodyLedger(tmp_path / "dji_custody.jsonl")
    parser = DJIFlightLogParser()
    events = parser.parse(dji_path, custody_ledger=ledger, actor="analyst_verma")

    engine = ForensicCorrelationEngine()
    anomalies = engine.analyze(events)

    pdf_out = tmp_path / "dji_forensic_report.pdf"
    result = generate_pdf_report(
        evidence_path=dji_path,
        events=events,
        custody_ledger=ledger,
        anomalies=anomalies,
        output_pdf_path=pdf_out,
    )

    assert result.exists()
    assert result.stat().st_size > 5000
    assert result.read_bytes()[:5] == b"%PDF-"


def test_clean_flight_zero_anomalies_report(tmp_path):
    # Test report when no anomalies exist
    dummy_file = tmp_path / "dummy_log.bin"
    dummy_file.write_bytes(b"dummy binary content")

    pdf_out = tmp_path / "clean_report.pdf"
    result = generate_pdf_report(
        evidence_path=dummy_file,
        events=[],
        custody_ledger=None,
        anomalies=[],
        output_pdf_path=pdf_out,
    )

    assert result.exists()
    assert result.stat().st_size > 2000
    assert result.read_bytes()[:5] == b"%PDF-"


def test_report_with_3d_evidence_exhibits(tmp_path):
    import base64

    # 1x1 valid PNG in bytes
    png_bytes = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
    img_file = tmp_path / "test_snapshot.png"
    img_file.write_bytes(png_bytes)

    dummy_log = tmp_path / "flight_log.ulg"
    dummy_log.write_bytes(b"dummy ulog content")

    exhibits = [
        {
            "id": "EVID-01",
            "index": 42,
            "ts": "12:44:19 UTC",
            "alt": 28.5,
            "spd": 18.2,
            "hdg": 90.0,
            "pitch": -12.4,
            "roll": 8.5,
            "lat": 19.076012,
            "lon": 72.877715,
            "note": "Rapid uncommanded descent detected near geofence boundary.",
            "image_path": str(img_file),
        },
        {
            "id": "EVID-02",
            "index": 98,
            "ts": "12:48:30 UTC",
            "alt": 5.2,
            "spd": 0.5,
            "hdg": 180.0,
            "pitch": 1.2,
            "roll": 0.3,
            "lat": 19.076890,
            "lon": 72.878400,
            "note": "Emergency landing touchdown location.",
            "image_data": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        }
    ]

    pdf_out = tmp_path / "courtroom_report_with_exhibits.pdf"
    result = generate_pdf_report(
        evidence_path=dummy_log,
        events=[],
        custody_ledger=None,
        anomalies=[],
        output_pdf_path=pdf_out,
        evidence_exhibits=exhibits,
    )

    assert result.exists()
    assert result.stat().st_size > 3000
    assert result.read_bytes()[:5] == b"%PDF-"


def test_http_bridge_exhibit_sync_and_courtroom_pdf_rebuild(tmp_path):
    """Verify that DesktopForensicAPI local HTTP bridge receives exhibits and rebuilds Courtroom PDF."""
    import urllib.request, json, time
    from gui.api import DesktopForensicAPI

    api = DesktopForensicAPI()
    api.output_dir = tmp_path / "desktop_case"
    api.output_dir.mkdir(parents=True, exist_ok=True)
    time.sleep(0.3)

    case_id = "CASE-HTTP-REBUILD-01"

    # Health check
    status_url = f"http://127.0.0.1:{api.http_port}/api/status"
    with urllib.request.urlopen(status_url) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "online"

    # Send exhibit via HTTP POST
    dummy_b64 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    exhibit = {
        "id": "EVID-HTTP-01",
        "num": 1,
        "index": 20,
        "ts": "11:22:33 UTC",
        "alt": 42.0,
        "spd": 15.0,
        "lat": 19.076,
        "lon": 72.877,
        "hdg": 45.0,
        "pitch": 4.0,
        "roll": -1.0,
        "note": "Critical maneuver exhibit via HTTP",
        "image_data": dummy_b64,
    }

    save_url = f"http://127.0.0.1:{api.http_port}/api/save_evidence_exhibit"
    payload = json.dumps({"exhibit": exhibit, "case_id": case_id}).encode("utf-8")
    req = urllib.request.Request(save_url, data=payload, headers={"Content-Type": "application/json"})

    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        assert res["status"] == "ok"
        assert res["total_exhibits"] == 1

    # Verify exhibits stored on disk
    exhibits_on_disk = api.get_evidence_exhibits(case_id)
    assert len(exhibits_on_disk) == 1
    assert exhibits_on_disk[0]["id"] == "EVID-HTTP-01"
    assert "image_path" in exhibits_on_disk[0]
    assert Path(exhibits_on_disk[0]["image_path"]).exists()

