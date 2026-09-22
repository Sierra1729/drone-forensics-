"""
tests/test_gui_api.py

Unit tests for the Desktop Forensic GUI API backend.
Validates:
1. Instantiation and parser registration listing (9 plugins).
2. End-to-end evidence ingestion and visualization payload generation via DesktopForensicAPI.
3. Hash computation and Merkle custody verification.
"""

from pathlib import Path
import pytest

from gui.api import DesktopForensicAPI
from tests.synthetic_ardupilot import generate_synthetic_ardupilot_bin


@pytest.fixture
def sample_bin(tmp_path) -> Path:
    bin_path = tmp_path / "gui_test_flight.BIN"
    return generate_synthetic_ardupilot_bin(bin_path)


def test_gui_api_list_parsers():
    api = DesktopForensicAPI()
    parsers = api.list_parsers()
    assert len(parsers) >= 9
    assert "px4_ulog" in parsers
    assert "ardupilot_dataflash_bin" in parsers
    assert "drone_media_carver" in parsers


def test_gui_api_analyze_evidence(sample_bin):
    api = DesktopForensicAPI()
    res = api.analyze_evidence(str(sample_bin), case_id="CASE-GUI-TEST-001", examiner="Test Examiner")

    assert res["status"] == "success"
    assert res["sha256"] is not None
    assert res["blake3"] is not None
    assert res["chain_intact"] is True
    assert res["parser_name"] == "ardupilot_dataflash_bin"
    assert res["total_events"] > 0
    assert len(res["coords"]) > 0

    first_coord = res["coords"][0]
    assert "lat" in first_coord
    assert "lon" in first_coord
    assert "alt" in first_coord
    assert "spd" in first_coord
    assert "pitch" in first_coord
    assert "roll" in first_coord

    # Verify output artifact paths
    assert Path(res["pdf_path"]).exists()
    assert Path(res["kml_path"]).exists()
    assert Path(res["geojson_path"]).exists()
    assert "html_3d_map_path" in res
    assert Path(res["html_3d_map_path"]).exists()
    assert "extended_telemetry" in res


def test_gui_api_analyze_px4_extended_telemetry():
    api = DesktopForensicAPI()
    px4_file = Path("sample_evidence/real_px4_flight.ulg")
    if px4_file.exists():
        res = api.analyze_evidence(str(px4_file), case_id="CASE-PX4-EXT-001", examiner="Inspector Cyber")
        assert res["status"] == "success"
        assert res["parser_name"] == "px4_ulog"
        assert "extended_telemetry" in res
        ext = res["extended_telemetry"]
        assert "summary" in ext
        assert "altitude_chart" in ext
        assert "attitude_chart" in ext
        assert "velocity_chart" in ext
        assert "power_chart" in ext
        assert "actuator_chart" in ext
        assert "sensor_health_chart" in ext
        assert "logged_messages" in ext
        assert "parameters_table" in ext


def test_gui_api_analyze_multi_evidence():
    api = DesktopForensicAPI()
    px4_file = Path("sample_evidence/real_px4_flight.ulg")
    dji_csv_file = Path("sample_evidence/secondary_dji_swarm.csv")
    if px4_file.exists() and dji_csv_file.exists():
        drones_payload = [
            {"file_path": str(px4_file), "label": "Primary Target (PX4)", "drone_id": "DRONE-01"},
            {"file_path": str(dji_csv_file), "label": "Escort UAV (DJI)", "drone_id": "DRONE-02"}
        ]
        res = api.analyze_multi_evidence(drones_payload, case_id="CASE-MULTI-TEST-001", examiner="Test Examiner")
        assert res["status"] == "success"
        assert res["is_multi_drone"] is True
        assert res["drones_count"] == 2
        assert len(res["drones"]) == 2

        d1 = res["drones"][0]
        d2 = res["drones"][1]
        assert d1["drone_id"] == "DRONE-01"
        assert d2["drone_id"] == "DRONE-02"
        assert len(d1["coords"]) > 0
        assert len(d2["coords"]) > 0
        assert d1["sha256"] is not None
        assert d2["sha256"] is not None

        # Verify multi-drone spatial correlation & closest approach calculation
        assert "min_separation_m" in res
        assert res["min_separation_m"] is not None
        assert res["min_separation_m"] > 0
        assert "proximity_events" in res
        assert Path(res["pdf_path"]).exists()


