"""
tests/test_geospatial.py

Test suite for the Geospatial Exporter (GeoJSON, 3D KML, and Folium HTML maps).
Validates:
1. RFC 7946 GeoJSON schema and coordinate integrity.
2. OGC KML 3D trajectory extrusion and Placemark styling.
3. Interactive Folium Leaflet HTML map generation.
4. Edge cases (empty events, missing coordinates).
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from analytics.correlation import ForensicAnomaly, NoFlyZone
from export.geospatial import (
    GeospatialExporter,
    export_geojson,
    export_kml,
    export_html_map,
    export_3d_html_map,
)
from normalize.schema import NormalizedEvent, EventType


@pytest.fixture
def sample_trajectory():
    base_ts = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    events: list[NormalizedEvent] = []
    base_lat = 19.0760
    base_lon = 72.8777

    for i in range(5):
        events.append(
            NormalizedEvent(
                timestamp_utc=base_ts + timedelta(seconds=i * 5),
                source_platform="ardupilot",
                event_type=EventType.GPS_FIX.value,
                source_file="flight.bin",
                source_file_sha256="0" * 64,
                latitude=base_lat + (i * 0.001),
                longitude=base_lon + (i * 0.001),
                altitude_m=20.0 + (i * 10.0),
                ground_speed_mps=12.0,
            )
        )

    anomalies = [
        ForensicAnomaly(
            anomaly_type="geofence_breach",
            severity="CRITICAL",
            timestamp_utc=base_ts + timedelta(seconds=10),
            latitude=base_lat + 0.002,
            longitude=base_lon + 0.002,
            altitude_m=40.0,
            description="Entered restricted airport boundary",
        )
    ]

    nfz = [
        NoFlyZone(
            name="Security Zone Alpha",
            polygon_vertices=[
                (19.0750, 72.8750),
                (19.0850, 72.8750),
                (19.0850, 72.8850),
                (19.0750, 72.8850),
            ],
            description="High-security restricted airspace",
        )
    ]

    return events, anomalies, nfz


def test_geojson_export(tmp_path, sample_trajectory):
    events, anomalies, nfz = sample_trajectory
    geojson_path = tmp_path / "flight.geojson"

    data = export_geojson(events, anomalies, nfz, output_path=geojson_path)
    assert geojson_path.exists()
    assert data["type"] == "FeatureCollection"
    assert len(data["features"]) >= 4

    feature_types = [f["properties"].get("feature_type") for f in data["features"]]
    assert "flight_path" in feature_types
    assert "takeoff_point" in feature_types
    assert "landing_or_termination_point" in feature_types
    assert "forensic_anomaly" in feature_types
    assert "no_fly_zone" in feature_types

    # Validate LineString coordinates
    path_feat = [f for f in data["features"] if f["properties"].get("feature_type") == "flight_path"][0]
    coords = path_feat["geometry"]["coordinates"]
    assert len(coords) == 5
    assert coords[0][1] == pytest.approx(19.0760, 0.0001)
    assert coords[0][0] == pytest.approx(72.8777, 0.0001)
    assert coords[0][2] == 20.0


def test_kml_3d_export(tmp_path, sample_trajectory):
    events, anomalies, nfz = sample_trajectory
    kml_path = tmp_path / "flight_3d.kml"

    result_path = export_kml(events, anomalies, nfz, output_path=kml_path)
    assert result_path.exists()

    content = kml_path.read_text(encoding="utf-8")
    assert "<kml" in content
    assert "<LineString" in content
    assert "<extrude>1</extrude>" in content
    assert "Takeoff Point" in content
    assert "ANOMALY: GEOFENCE_BREACH" in content
    assert "Security Zone Alpha" in content


def test_html_map_export(tmp_path, sample_trajectory):
    events, anomalies, nfz = sample_trajectory
    html_path = tmp_path / "flight_map.html"

    result_path = export_html_map(events, anomalies, nfz, output_path=html_path)
    assert result_path.exists()
    assert result_path.stat().st_size > 1000

    content = html_path.read_text(encoding="utf-8")
    assert "leaflet" in content.lower()
    assert "Takeoff" in content
    assert "Landing" in content
    assert "Security Zone Alpha" in content


def test_empty_events_handling(tmp_path):
    empty_geojson = tmp_path / "empty.geojson"
    data = export_geojson([], [], [], output_path=empty_geojson)
    assert data["type"] == "FeatureCollection"
    assert len(data["features"]) == 0

    empty_kml = tmp_path / "empty.kml"
    export_kml([], [], [], output_path=empty_kml)
    assert empty_kml.exists()

    empty_html = tmp_path / "empty.html"
    export_html_map([], [], [], output_path=empty_html)
    assert empty_html.exists()

    empty_3d_html = tmp_path / "empty_3d.html"
    export_3d_html_map([], [], [], output_path=empty_3d_html)
    assert empty_3d_html.exists()


def test_3d_html_map_export(tmp_path, sample_trajectory):
    events, anomalies, nfz = sample_trajectory
    html_3d_path = tmp_path / "flight_3d_map.html"

    result_path = export_3d_html_map(events, anomalies, nfz, output_path=html_3d_path)
    assert result_path.exists()
    assert result_path.stat().st_size > 2000

    content = html_3d_path.read_text(encoding="utf-8")
    assert "THREE.WebGLRenderer" in content
    assert "curtainMesh" in content
    assert "flightData" in content
    assert "TAKEOFF POINT" in content
    assert "geofence_breach" in content.lower()
    # Verify Artificial Horizon Indicator
    assert "hudHorizonSphere" in content
    assert "horizon-dial-3d" in content
    # Verify Compass with East
    assert "hudCompassNeedle" in content
    assert "EAST (E - 90°)" in content
    # Verify Telemetry Coordinates & Speed
    assert "hudLat" in content
    assert "hudLon" in content
    assert "hudAlt" in content
    assert "hudSpd" in content
    # Verify Live Telemetry Log Feed
    assert "telemetryLogPanel" in content
    assert "populateTelemetryLog" in content
    # Verify Evidence Action Suite
    assert "markEvidenceBtn" in content
    assert "addToEvidenceBtn" in content
    assert "topEvidenceBtn" in content
    assert "evidenceDrawer" in content
    assert "evidenceModalBackdrop" in content
    assert "dossierModalBackdrop" in content
    assert "evidenceToast" in content
    assert "confirmMarkEvidence" in content
    assert "addCurrentToEvidence" in content
    assert "create3DEvidenceMarker" in content
    assert "exportForensicExhibitReport" in content
    assert "addToCourtroomPdf" in content
    assert "captureViewportSnapshot" in content


def test_desktop_api_evidence_exhibits(tmp_path):
    from gui.api import DesktopForensicAPI
    api = DesktopForensicAPI()
    api.output_dir = tmp_path

    exhibit = {
        "id": "EVID-01",
        "index": 42,
        "ts": "12:00:00 UTC",
        "alt": 25.5,
        "spd": 15.2,
        "lat": 19.076,
        "lon": 72.877,
        "note": "Rapid descent detected",
        "image_data": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    }

    res = api.save_evidence_exhibit(exhibit, case_id="CASE-TEST-API")
    assert res["status"] == "ok"
    assert res["total_exhibits"] == 1

    # Verify that image was extracted and saved as a PNG file
    saved_img = tmp_path / "CASE-TEST-API" / "exhibits" / "EVID-01.png"
    assert saved_img.exists()
    assert saved_img.stat().st_size > 50

    exhibits = api.get_evidence_exhibits(case_id="CASE-TEST-API")
    assert len(exhibits) == 1
    assert exhibits[0]["id"] == "EVID-01"
    assert exhibits[0]["note"] == "Rapid descent detected"
    assert "image_path" in exhibits[0]

