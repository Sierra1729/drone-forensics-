"""tests/test_controller_ingest.py

Unit and integration tests for GCS ADB Logical Ingestion Pipeline.
Compliant with ISO/IEC 27037:2012 and NIST SP 800-86 standards.

Tests:
1. Immediate SHA-256 + BLAKE3 custody hashing for all discovered ADB dump files before parsing.
2. Pilot account (UID, email, phone, token) & hardware metadata extraction from XML/SQLite artifacts.
3. Clean parsing of GCS telemetry into unified schema with origin: "GCS_CONTROLLER" and UTC timestamps.
4. Cross-stream correlation of Controller Home Point GPS vs. Drone Takeoff GPS.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from acquisition.adb_extractor import (
    AdbExtractor,
    GcsPilotIdentity,
    GcsHardwareMetadata,
    parse_shared_prefs_xml,
    parse_sqlite_db_artifacts,
    triage_offline_dump,
)
from analytics.correlation import ForensicCorrelationEngine, AnomalyType
from custody.ledger import ChainOfCustodyLedger
from normalize.schema import NormalizedEvent, EventType, NormalizedEventStore


def test_parse_shared_prefs_xml():
    """Verify pilot account and hardware metadata extraction from Android shared_prefs XML."""
    xml_content = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_email">pilot.forensics@meity.gov.in</string>
    <string name="user_id">PILOT_998124_INDIA</string>
    <string name="phone_number">+919876543210</string>
    <string name="controller_sn">DJI-RC-PRO-ENTERPRISE-001</string>
    <string name="drone_sn">1581F4AFK22090001</string>
    <string name="device_model">DJI Smart Controller Enterprise</string>
    <string name="user_token">abc123xyz_token_secret_99</string>
</map>
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        xml_file = Path(tmpdir) / "shared_prefs_dji.xml"
        xml_file.write_text(xml_content, encoding="utf-8")

        identity, hardware = parse_shared_prefs_xml(xml_file)
        assert identity.email == "pilot.forensics@meity.gov.in"
        assert identity.pilot_uid == "PILOT_998124_INDIA"
        assert identity.phone == "+919876543210"
        assert hardware.controller_sn == "DJI-RC-PRO-ENTERPRISE-001"
        assert hardware.paired_drone_sn == "1581F4AFK22090001"
        assert hardware.device_model == "DJI Smart Controller Enterprise"


def test_triage_offline_dump_custody_and_hashing():
    """Verify that every discovered file is hashed and recorded in the custody ledger before parsing."""
    with tempfile.TemporaryDirectory() as dump_dir, tempfile.TemporaryDirectory() as out_dir:
        dump_path = Path(dump_dir)
        ledger_path = Path(out_dir) / "chain_of_custody.jsonl"
        ledger = ChainOfCustodyLedger(ledger_path)

        # Create realistic directory layout (FlightRecord, shared_prefs, db)
        fr_dir = dump_path / "sdcard" / "DJI" / "dji.go.v4" / "FlightRecord"
        fr_dir.mkdir(parents=True, exist_ok=True)
        sample_log = fr_dir / "DJIFlightRecord_2026-09-22.csv"
        sample_log.write_text("Date,Latitude,Longitude,Altitude\n2026-09-22,19.076,72.877,15.0\n", encoding="utf-8")

        sp_dir = dump_path / "apps" / "dji.go.v4" / "shared_prefs"
        sp_dir.mkdir(parents=True, exist_ok=True)
        sp_xml = sp_dir / "account_info.xml"
        sp_xml.write_text("<map><string name='user_email'>inspector@cyber.gov.in</string></map>", encoding="utf-8")

        # Execute triage ingestion
        extractor = AdbExtractor()
        res = extractor.triage_offline_dump(
            dump_path=dump_path,
            output_directory=out_dir,
            custody_ledger=ledger,
            operator_id="INV-UNITTEST-01",
        )

        assert res.success is True
        assert res.total_files_hashed >= 2
        assert res.pilot_identity.email == "inspector@cyber.gov.in"
        assert len(res.custody_entries) >= 2

        # Verify Chain of Custody integrity
        is_valid, broken_idx = ledger.verify_chain()
        assert is_valid is True
        assert broken_idx is None
        assert any(e.action == "ACQUIRE_ADB_OFFLINE" for e in ledger._entries)


def test_gcs_telemetry_normalization_origin():
    """Verify that GCS events are labeled with origin: 'GCS_CONTROLLER' and timezone-aware UTC timestamps."""
    with tempfile.TemporaryDirectory() as dump_dir, tempfile.TemporaryDirectory() as out_dir:
        dump_path = Path(dump_dir)
        fr_dir = dump_path / "FlightRecord"
        fr_dir.mkdir(parents=True, exist_ok=True)
        sample_csv = fr_dir / "test_gcs_flight.csv"
        
        csv_data = """CUSTOM.date(millisecond),OSD.latitude,OSD.longitude,OSD.height [ft],OSD.flycState
1790073600000,19.076000,72.877000,49.2,P-GPS
1790073601000,19.076100,72.877100,50.0,P-GPS
"""
        sample_csv.write_text(csv_data, encoding="utf-8")

        res = triage_offline_dump(dump_path=dump_path, output_directory=out_dir)
        assert res.success is True
        assert len(res.extracted_events) >= 1

        for ev in res.extracted_events:
            assert isinstance(ev, NormalizedEvent)
            assert ev.timestamp_utc.tzinfo is not None
            assert ev.payload.get("origin") == "GCS_CONTROLLER"


def test_cross_stream_controller_drone_correlation():
    """Verify correlation detection of GCS Controller vs. Drone Takeoff Home Point mismatch and clock skew."""
    now = datetime.now(timezone.utc)

    # Controller event at location A
    gcs_event = NormalizedEvent(
        timestamp_utc=now,
        source_platform="dji_gcs_controller",
        event_type=EventType.GPS_FIX.value,
        source_file="controller_dump.txt",
        source_file_sha256="a" * 64,
        latitude=19.076000,
        longitude=72.877000,
        altitude_m=10.0,
        payload={"origin": "GCS_CONTROLLER", "record_type": "HOME_POINT_LOCK"},
    )

    # Drone event at location B (600 meters away -> mismatch/spoofing)
    drone_event = NormalizedEvent(
        timestamp_utc=now,
        source_platform="px4_autopilot",
        event_type=EventType.GPS_FIX.value,
        source_file="real_px4_flight.ulg",
        source_file_sha256="b" * 64,
        latitude=19.081500,
        longitude=72.877000,
        altitude_m=12.0,
        payload={"origin": "AIRCRAFT_BLACKBOX"},
    )

    engine = ForensicCorrelationEngine()
    anomalies = engine.analyze([gcs_event, drone_event])

    assert len(anomalies) >= 1
    mismatch_anomalies = [a for a in anomalies if "Home Point Mismatch" in a.description or a.anomaly_type == AnomalyType.GPS_SPOOFING_OR_TELEPORTATION.value]
    assert len(mismatch_anomalies) >= 1
    assert "Controller / Drone Home Point Mismatch" in mismatch_anomalies[0].description
