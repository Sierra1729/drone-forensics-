"""
tests/test_param_parser.py

Unit tests for ParamParser and ParamDiffEngine.
"""

from pathlib import Path
from datetime import datetime, timezone
import pytest

from parsers.param_parser import ParamParser
from analytics.param_diff import ParamDiffEngine


@pytest.fixture
def temp_param_files(tmp_path: Path):
    # 1. Tab delimited parameter file
    tab_file = tmp_path / "vehicle_tab.param"
    tab_file.write_text(
        "# ArduPilot Parameter Export\n"
        "FENCE_ENABLE\t1\n"
        "FENCE_ACTION\t1\n"
        "PILOT_ALT_MAX\t120.5\n",
        encoding="utf-8"
    )

    # 2. Comma delimited parameter file
    comma_file = tmp_path / "vehicle_comma.params"
    comma_file.write_text(
        "# QGroundControl Params\n"
        "FENCE_ENABLE,0 # Disabled for test flight\n"
        "FS_THR_ENABLE,1\n"
        "ARMING_CHECK,0\n",
        encoding="utf-8"
    )

    # 3. Space delimited parameter file
    space_file = tmp_path / "vehicle_space.param"
    space_file.write_text(
        "FENCE_ENABLE 1\n"
        "PILOT_ALT_MAX 250\n",
        encoding="utf-8"
    )

    return {
        "tab": tab_file,
        "comma": comma_file,
        "space": space_file,
    }


def test_param_parser_can_parse(temp_param_files):
    parser = ParamParser()
    assert parser.can_parse(temp_param_files["tab"]) is True
    assert parser.can_parse(temp_param_files["comma"]) is True
    assert parser.can_parse(temp_param_files["space"]) is True


def test_param_parser_tab_delimited(temp_param_files):
    parser = ParamParser()
    events = parser.parse(temp_param_files["tab"])
    assert len(events) == 3

    params = {e.payload["parameter"]: e.payload["value"] for e in events}
    assert params["FENCE_ENABLE"] == 1
    assert params["FENCE_ACTION"] == 1
    assert params["PILOT_ALT_MAX"] == 120.5

    for e in events:
        assert e.event_type == "config_param"
        assert e.source_platform == "ardupilot"
        assert e.raw_hex_offset.startswith("0x")


def test_param_parser_comma_delimited(temp_param_files):
    parser = ParamParser()
    events = parser.parse(temp_param_files["comma"])
    assert len(events) == 3

    params = {e.payload["parameter"]: e.payload["value"] for e in events}
    assert params["FENCE_ENABLE"] == 0
    assert params["FS_THR_ENABLE"] == 1
    assert params["ARMING_CHECK"] == 0


def test_param_parser_space_delimited(temp_param_files):
    parser = ParamParser()
    events = parser.parse(temp_param_files["space"])
    assert len(events) == 2

    params = {e.payload["parameter"]: e.payload["value"] for e in events}
    assert params["FENCE_ENABLE"] == 1
    assert params["PILOT_ALT_MAX"] == 250


def test_param_parser_byte_offsets(temp_param_files):
    parser = ParamParser()
    events = parser.parse(temp_param_files["tab"])
    # First record byte offset should be > 0 (since line 1 is a comment)
    assert events[0].byte_offset != "0x00000000"
    assert int(events[0].byte_offset, 16) > 0


def test_param_diff_engine():
    engine = ParamDiffEngine()

    onboard = {
        "FENCE_ENABLE": 1,
        "FS_THR_ENABLE": 1,
        "PILOT_ALT_MAX": 120.0,
        "BATT_MONITOR": 4,
    }

    gcs = {
        "FENCE_ENABLE": 0,  # Critical diff!
        "FS_THR_ENABLE": 1, # Same
        "PILOT_ALT_MAX": 400.0, # Critical diff!
        "GCS_PARAM": 99,
    }

    res = engine.compare(onboard, gcs)
    assert res["summary"]["modified_count"] == 2
    assert res["summary"]["critical_diff_count"] == 2

    critical_param_names = [d["parameter"] for d in res["critical_diffs"]]
    assert "FENCE_ENABLE" in critical_param_names
    assert "PILOT_ALT_MAX" in critical_param_names
