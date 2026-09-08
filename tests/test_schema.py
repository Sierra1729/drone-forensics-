from datetime import datetime, timezone

import pytest

from normalize.schema import NormalizedEvent, NormalizedEventStore, EventType


def make_event(**overrides):
    defaults = dict(
        timestamp_utc=datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc),
        source_platform="ardupilot",
        event_type=EventType.GPS_FIX.value,
        source_file="samples/flight1.bin",
        source_file_sha256="a" * 64,
        latitude=19.0760,
        longitude=72.8777,
        altitude_m=120.5,
        payload={"num_satellites": 11},
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        NormalizedEvent(
            timestamp_utc=datetime(2026, 8, 30, 12, 0, 0),  # no tzinfo
            source_platform="ardupilot",
            event_type=EventType.GPS_FIX.value,
            source_file="x.bin",
            source_file_sha256="a" * 64,
        )


def test_round_trip_serialization():
    event = make_event()
    restored = NormalizedEvent.from_dict(event.to_dict())
    assert restored.record_id == event.record_id
    assert restored.timestamp_utc == event.timestamp_utc
    assert restored.payload == event.payload


def test_store_sorts_chronologically(tmp_path):
    store = NormalizedEventStore(backing_path=tmp_path / "events.jsonl")
    later = make_event(timestamp_utc=datetime(2026, 8, 30, 12, 5, tzinfo=timezone.utc))
    earlier = make_event(timestamp_utc=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc))
    store.add(later)
    store.add(earlier)
    ordered = store.all_sorted()
    assert ordered[0].record_id == earlier.record_id
    assert ordered[1].record_id == later.record_id


def test_store_persists_and_reloads(tmp_path):
    path = tmp_path / "events.jsonl"
    store = NormalizedEventStore(backing_path=path)
    store.add(make_event())
    store.add(
        make_event(
            event_type=EventType.RTH_TRIGGER.value,
            payload={"reason": "low_battery"},
        )
    )

    reloaded = NormalizedEventStore.load(path)
    assert len(reloaded) == 2
    assert len(reloaded.by_type(EventType.RTH_TRIGGER.value)) == 1


def test_flight_dynamics_fields_serialization():
    event = make_event(
        ground_speed_mps=15.2,
        heading_deg=180.5,
        pitch_deg=-2.5,
        roll_deg=1.1,
        yaw_deg=179.9,
        satellites_visible=16,
        hdop=0.7,
        battery_voltage_v=11.8,
        battery_current_a=22.4,
        battery_remaining_pct=65.0,
        flight_mode="POSHOLD",
        session_id="flight-session-001",
    )
    d = event.to_dict()
    restored = NormalizedEvent.from_dict(d)
    assert restored.ground_speed_mps == 15.2
    assert restored.heading_deg == 180.5
    assert restored.pitch_deg == -2.5
    assert restored.roll_deg == 1.1
    assert restored.yaw_deg == 179.9
    assert restored.satellites_visible == 16
    assert restored.hdop == 0.7
    assert restored.battery_voltage_v == 11.8
    assert restored.battery_current_a == 22.4
    assert restored.battery_remaining_pct == 65.0
    assert restored.flight_mode == "POSHOLD"
    assert restored.session_id == "flight-session-001"

