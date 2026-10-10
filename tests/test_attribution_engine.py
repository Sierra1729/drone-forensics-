"""
tests/test_attribution_engine.py

Comprehensive unit test suite for analytics/attribution_engine.py.
Verifies the Universal Polymorphic Correlation Framework & Telemetry Continuity Engine
across arbitrary N evidence artifacts (PX4, ArduPilot, DJI, Parrot, Betaflight, Params, Media).
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analytics.attribution_engine import (
    UniversalAttributionEngine,
    ForensicArtifact,
    IdentityAttributionReport,
    TelemetryContinuityReport,
    ComprehensiveAttributionResult,
    ArtifactCategory,
    haversine_distance,
)


@pytest.fixture
def sample_evidence_dir():
    root = Path(__file__).resolve().parent.parent
    return root / "sample_evidence"


def test_haversine_distance():
    """Verify geodetic distance calculation accuracy."""
    # Distance between New Delhi (28.6139, 77.2090) and Mumbai (19.0760, 72.8777) ~ 1150 km
    dist_m = haversine_distance(28.6139, 77.2090, 19.0760, 72.8777)
    assert 1100000 < dist_m < 1200000


def test_extract_artifact_px4(sample_evidence_dir):
    """Verify artifact extraction from a real PX4 .ulg blackbox file."""
    px4_file = sample_evidence_dir / "px4_mission_sample.ulg"
    if not px4_file.exists():
        pytest.skip("px4_mission_sample.ulg not found in sample_evidence")

    engine = UniversalAttributionEngine()
    artifact = engine.extract_artifact(px4_file)

    assert isinstance(artifact, ForensicArtifact)
    assert artifact.file_type == ArtifactCategory.ONBOARD_BLACKBOX.value
    assert artifact.platform in ("px4", "generic")
    assert artifact.raw_event_count > 0
    assert artifact.file_sha256 != ""
    assert artifact.session_start_utc is not None
    assert artifact.session_end_utc is not None


def test_extract_artifact_ardupilot(sample_evidence_dir):
    """Verify artifact extraction from an ArduPilot DataFlash .bin file."""
    bin_file = sample_evidence_dir / "ardupilot_sample.bin"
    if not bin_file.exists():
        pytest.skip("ardupilot_sample.bin not found in sample_evidence")

    engine = UniversalAttributionEngine()
    artifact = engine.extract_artifact(bin_file)

    assert isinstance(artifact, ForensicArtifact)
    assert artifact.file_type == ArtifactCategory.ONBOARD_BLACKBOX.value
    assert artifact.platform in ("ardupilot", "generic")
    assert artifact.raw_event_count > 0


def test_extract_artifact_param(sample_evidence_dir):
    """Verify artifact extraction from a standalone .params file."""
    param_file = sample_evidence_dir / "vehicle.params"
    if not param_file.exists():
        pytest.skip("vehicle.params not found in sample_evidence")

    engine = UniversalAttributionEngine()
    artifact = engine.extract_artifact(param_file)

    assert isinstance(artifact, ForensicArtifact)
    assert artifact.file_type == ArtifactCategory.CONFIG.value
    assert len(artifact.parameter_map) > 0


def test_identity_attribution_match():
    """Verify identity attribution returns MATCH when artifacts share matching hardware UID & trajectory."""
    now = datetime.now(timezone.utc)
    a1 = ForensicArtifact(
        file_path=Path("onboard_px4.ulg"),
        file_type="onboard_blackbox",
        platform="px4",
        hardware_uid="PX4-CUBE-9901A",
        session_start_utc=now,
        session_end_utc=now + timedelta(minutes=15),
        home_coordinates=(28.6139, 77.2090, 100.0),
        trajectory_points=[{"timestamp_utc": now, "latitude": 28.6139, "longitude": 77.2090, "altitude_m": 100.0}],
        parameter_map={"FS_BATT_VOLT": 10.5, "RTL_ALT": 50.0},
        raw_event_count=500,
    )
    a2 = ForensicArtifact(
        file_path=Path("gcs_telemetry.csv"),
        file_type="gcs_telemetry",
        platform="dji",
        hardware_uid="px4-cube-9901a",  # case insensitive match
        session_start_utc=now + timedelta(seconds=10),
        session_end_utc=now + timedelta(minutes=15, seconds=5),
        home_coordinates=(28.6140, 77.2091, 100.0),  # ~14m away
        trajectory_points=[{"timestamp_utc": now + timedelta(seconds=10), "latitude": 28.6140, "longitude": 77.2091, "altitude_m": 100.0}],
        parameter_map={"FS_BATT_VOLT": 10.5, "RTL_ALT": 50.0},
        raw_event_count=450,
    )

    engine = UniversalAttributionEngine()
    report = engine.analyze_identity_attribution([a1, a2])

    assert isinstance(report, IdentityAttributionReport)
    assert report.match_verdict == "MATCH"
    assert report.overall_confidence_score >= 80.0
    assert report.hardware_uid_match["status"] == "MATCH"
    assert report.spatio_temporal_match["status"] == "MATCH"


def test_identity_attribution_mismatch():
    """Verify identity attribution returns MISMATCH when hardware UIDs conflict."""
    now = datetime.now(timezone.utc)
    a1 = ForensicArtifact(
        file_path=Path("drone_alpha.ulg"),
        file_type="onboard_blackbox",
        platform="px4",
        hardware_uid="ALPHA-111",
        session_start_utc=now,
        session_end_utc=now + timedelta(minutes=10),
        home_coordinates=(28.6139, 77.2090, 100.0),
        raw_event_count=200,
    )
    a2 = ForensicArtifact(
        file_path=Path("drone_bravo.bin"),
        file_type="onboard_blackbox",
        platform="ardupilot",
        hardware_uid="BRAVO-999",  # Conflict!
        session_start_utc=now + timedelta(hours=5),  # Time conflict!
        session_end_utc=now + timedelta(hours=5, minutes=10),
        home_coordinates=(19.0760, 72.8777, 50.0),  # Mumbai vs Delhi conflict!
        raw_event_count=200,
    )

    engine = UniversalAttributionEngine()
    report = engine.analyze_identity_attribution([a1, a2])

    assert isinstance(report, IdentityAttributionReport)
    assert report.match_verdict == "MISMATCH"
    assert len(report.conflicting_artifacts) >= 2


def test_telemetry_continuity_analysis():
    """Verify telemetry continuity analysis detects packet dropouts and early terminations."""
    now = datetime.now(timezone.utc)
    points = [
        {"timestamp_utc": now, "latitude": 28.6139, "longitude": 77.2090, "altitude_m": 10.0, "ground_speed_mps": 5.0},
        {"timestamp_utc": now + timedelta(seconds=1), "latitude": 28.6140, "longitude": 77.2091, "altitude_m": 12.0, "ground_speed_mps": 6.0},
        # Packet dropout: 10s gap
        {"timestamp_utc": now + timedelta(seconds=11), "latitude": 28.6145, "longitude": 77.2095, "altitude_m": 15.0, "ground_speed_mps": 8.0},
        # Early termination while airborne & fast
        {"timestamp_utc": now + timedelta(seconds=12), "latitude": 28.6146, "longitude": 77.2096, "altitude_m": 20.0, "ground_speed_mps": 12.0},
    ]

    a1 = ForensicArtifact(
        file_path=Path("flight_crash.ulg"),
        file_type="onboard_blackbox",
        platform="px4",
        session_start_utc=now,
        session_end_utc=now + timedelta(seconds=12),
        trajectory_points=points,
        raw_event_count=4,
        is_corrupted=True,
        corruption_offset=0x0001F800,
    )

    engine = UniversalAttributionEngine()
    report = engine.analyze_telemetry_continuity([a1], dropout_threshold_s=3.0)

    assert isinstance(report, TelemetryContinuityReport)
    assert report.is_uninterrupted is False
    assert len(report.detected_gaps) >= 2
    assert report.early_termination_detected is True
    assert report.wiped_sectors_detected is True


def test_correlate_evidence_master(sample_evidence_dir):
    """Verify master correlate_evidence method across multiple real evidence files."""
    f1 = sample_evidence_dir / "px4_mission_sample.ulg"
    f2 = sample_evidence_dir / "vehicle.params"

    paths = [f for f in (f1, f2) if f.exists()]
    if not paths:
        pytest.skip("Sample files not found")

    engine = UniversalAttributionEngine()
    result = engine.correlate_evidence(paths)

    assert isinstance(result, ComprehensiveAttributionResult)
    assert len(result.artifacts) == len(paths)
    assert result.identity_attribution is not None
    assert result.telemetry_continuity is not None
    assert "UNIVERSAL FORENSIC ATTRIBUTION SUMMARY" in result.executive_summary
