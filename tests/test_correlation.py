"""
tests/test_correlation.py

Comprehensive test suite for the Forensic Anomaly & Correlation Engine.
Validates:
1. Haversine distance accuracy against known geographic coordinates.
2. Ray-casting point-in-polygon algorithm for Geofence / No-Fly Zone (NFZ) breaches.
3. GPS teleportation / spoofing detection based on kinematic velocity thresholds.
4. GPS HDOP and satellite constellation degradation alerts.
5. Critical battery decay alerts.
6. Catastrophic attitude deviation / crash shock detection.
"""

from datetime import datetime, timezone, timedelta
import pytest

from analytics.correlation import (
    AnomalyType,
    ForensicCorrelationEngine,
    NoFlyZone,
    haversine_distance_m,
    point_in_polygon,
)
from normalize.schema import NormalizedEvent, EventType


def make_event(dt_offset_s: float, **kwargs) -> NormalizedEvent:
    base_ts = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    ts = base_ts + timedelta(seconds=dt_offset_s)
    defaults = {
        "timestamp_utc": ts,
        "source_platform": "ardupilot",
        "event_type": EventType.GPS_FIX.value,
        "source_file": "flight.bin",
        "source_file_sha256": "f" * 64,
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


def test_haversine_distance_calculation():
    # Distance between Gateway of India (18.9220, 72.8347) and Marine Drive (18.9432, 72.8231)
    # is approximately 2.64 km (~2640 meters)
    dist = haversine_distance_m(18.9220, 72.8347, 18.9432, 72.8231)
    assert 2500 < dist < 2800


def test_point_in_polygon_ray_casting():
    # Square polygon around IIT Bombay Powai Lake area: Lat [19.12, 19.14], Lon [72.90, 72.92]
    square_nfz = [
        (19.1200, 72.9000),
        (19.1400, 72.9000),
        (19.1400, 72.9200),
        (19.1200, 72.9200),
    ]

    # Inside point
    assert point_in_polygon(19.1300, 72.9100, square_nfz) is True

    # Outside point
    assert point_in_polygon(19.1000, 72.8800, square_nfz) is False

    # Triangle polygon
    triangle = [(0.0, 0.0), (10.0, 0.0), (5.0, 10.0)]
    assert point_in_polygon(5.0, 2.0, triangle) is True
    assert point_in_polygon(15.0, 15.0, triangle) is False


def test_geofence_breach_detection():
    # Define restricted airport zone
    nfz = NoFlyZone(
        name="Mumbai Airport NFZ",
        polygon_vertices=[
            (19.0850, 72.8650),
            (19.0950, 72.8650),
            (19.0950, 72.8850),
            (19.0850, 72.8850),
        ],
        description="Statutory Red Zone - CSIA Mumbai",
    )

    # Flight path: Starts outside -> Enters NFZ -> Leaves NFZ
    events = [
        make_event(0, latitude=19.0700, longitude=72.8500, altitude_m=50.0),  # Outside
        make_event(10, latitude=19.0900, longitude=72.8750, altitude_m=50.0),  # INSIDE BREACH
        make_event(20, latitude=19.0910, longitude=72.8760, altitude_m=50.0),  # Still inside
        make_event(30, latitude=19.1100, longitude=72.8900, altitude_m=50.0),  # Outside
    ]

    engine = ForensicCorrelationEngine()
    anomalies = engine.analyze(events, no_fly_zones=[nfz])

    breaches = [a for a in anomalies if a.anomaly_type == AnomalyType.GEOFENCE_BREACH.value]
    assert len(breaches) == 1
    assert breaches[0].severity == "CRITICAL"
    assert "Mumbai Airport NFZ" in breaches[0].description
    assert breaches[0].latitude == 19.0900


def test_gps_spoofing_teleportation_detection():
    # Consecutive GPS fixes with unrealistic jump:
    # 10 km jump in 1 second = 10,000 m/s >> 45 m/s limit
    events = [
        make_event(0, latitude=19.0760, longitude=72.8777, altitude_m=20.0),
        make_event(1, latitude=19.1760, longitude=72.9777, altitude_m=20.0),  # Huge jump
    ]

    engine = ForensicCorrelationEngine(max_kinematic_speed_mps=45.0)
    anomalies = engine.analyze(events)

    spoofs = [a for a in anomalies if a.anomaly_type == AnomalyType.GPS_SPOOFING_OR_TELEPORTATION.value]
    assert len(spoofs) == 1
    assert spoofs[0].severity == "HIGH"
    assert "exceeds airframe limit" in spoofs[0].description
    assert spoofs[0].evidence_context.get("computed_velocity_mps", 0) > 1000.0


def test_gps_signal_degradation_detection():
    events = [
        make_event(0, latitude=19.0760, longitude=72.8777, hdop=6.5, satellites_visible=12),
        make_event(1, latitude=19.0761, longitude=72.8778, hdop=1.0, satellites_visible=4),
    ]

    engine = ForensicCorrelationEngine(max_hdop_threshold=4.0, min_satellites_threshold=6)
    anomalies = engine.analyze(events)

    degradations = [a for a in anomalies if a.anomaly_type == AnomalyType.GPS_SIGNAL_DEGRADATION.value]
    assert len(degradations) == 2


def test_critical_battery_and_crash_detection():
    events = [
        # Normal cruise
        make_event(0, latitude=19.0760, longitude=72.8777, pitch_deg=2.0, roll_deg=-1.5, battery_remaining_pct=50.0),
        # Low battery
        make_event(10, latitude=19.0761, longitude=72.8778, pitch_deg=2.0, roll_deg=-1.5, battery_remaining_pct=12.0),
        # Crash attitude shock
        make_event(15, latitude=19.0762, longitude=72.8779, pitch_deg=-82.0, roll_deg=45.0, battery_remaining_pct=10.0),
    ]

    engine = ForensicCorrelationEngine(critical_battery_pct=15.0, impact_pitch_roll_deg=70.0)
    anomalies = engine.analyze(events)

    batt_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.CRITICAL_BATTERY_FAILSAFE.value]
    assert len(batt_anomalies) >= 1
    assert batt_anomalies[0].evidence_context.get("battery_remaining_pct") == 12.0

    crash_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.IMPACT_OR_CRASH.value]
    assert len(crash_anomalies) == 1
    assert crash_anomalies[0].severity == "CRITICAL"
    assert "impact shock" in crash_anomalies[0].description
