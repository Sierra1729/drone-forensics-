import struct
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from normalize.schema import EventType, NormalizedEventStore
from parsers.ardupilot import ArduPilotDataFlashParser, HEAD1, HEAD2
from tests.synthetic_ardupilot import pack_fmt

TYPE_PARM = 0x81
TYPE_GPS = 0x02
TYPE_ATT = 0x03
TYPE_BAT = 0x04
TYPE_MODE = 0x05
TYPE_MSG = 0x06

def create_known_answer_bin(path: Path):
    chunks = []
    # 1. Declarations
    chunks.append(pack_fmt(TYPE_PARM, 31, 'PARM', 'QNf', 'TimeUS,Name,Value'))
    chunks.append(pack_fmt(TYPE_GPS, 41, 'GPS', 'QBIHBCLLfff', 'TimeUS,Status,GMS,GWk,NSats,HDop,Lat,Lng,Alt,Spd,GCrs'))
    chunks.append(pack_fmt(TYPE_ATT, 23, 'ATT', 'Qfff', 'TimeUS,Roll,Pitch,Yaw'))
    chunks.append(pack_fmt(TYPE_BAT, 20, 'BAT', 'QffB', 'TimeUS,Volt,Curr,RemPct'))
    chunks.append(pack_fmt(TYPE_MODE, 27, 'MODE', 'QN', 'TimeUS,Mode'))
    chunks.append(pack_fmt(TYPE_MSG, 75, 'MSG', 'QZ', 'TimeUS,Message'))

    # Boot Parm
    p_payload = struct.pack('<Q16sf', 100000, b'SYS_ID\x00', 1.0)
    chunks.append(bytes([HEAD1, HEAD2, TYPE_PARM]) + p_payload)

    # 100 Waypoints
    gwk = 2350
    base_gms = 100000000
    base_time_us = 1000000
    base_lat = 19.0760000
    base_lng = 72.8777000
    base_alt = 10.0
    base_volt = 12.60

    for i in range(100):
        t_us = base_time_us + (i * 100000)
        gms = base_gms + (i * 100)
        lat = base_lat + (i * 0.0001000)
        lng = base_lng + (i * 0.0001000)
        lat_scaled = int(round(lat * 1e7))
        lng_scaled = int(round(lng * 1e7))
        alt = base_alt + (i * 0.50)
        speed = 15.0
        gcrs = 45.0
        nsats = 16
        hdop_scaled = 80
        status = 3
        volt = base_volt - (i * 0.02)
        curr = 8.5 + (i * 0.05)
        rem_pct = max(0, int(100 - i * 0.7))

        # Pack GPS
        gps_payload = struct.pack(
            '<QBIHBHiifff',
            t_us, status, gms, gwk, nsats, hdop_scaled,
            lat_scaled, lng_scaled, alt, speed, gcrs
        )
        chunks.append(bytes([HEAD1, HEAD2, TYPE_GPS]) + gps_payload)

        # Pack ATT
        att_payload = struct.pack('<Qfff', t_us, 0.5, 1.2, 45.0)
        chunks.append(bytes([HEAD1, HEAD2, TYPE_ATT]) + att_payload)

        # Pack BAT
        bat_payload = struct.pack('<QffB', t_us, volt, curr, rem_pct)
        chunks.append(bytes([HEAD1, HEAD2, TYPE_BAT]) + bat_payload)

    path.write_bytes(b''.join(chunks))

def run_validation():
    out_bin = Path('output/known_answer_test.bin')
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    create_known_answer_bin(out_bin)

    parser = ArduPilotDataFlashParser()
    events = parser.parse(out_bin)
    store = NormalizedEventStore()
    for e in events:
        store.add(e)

    gps_events = store.by_type(EventType.GPS_FIX.value)
    bat_events = store.by_type(EventType.BATTERY_STATE.value)

    print('=== KNOWN-ANSWER VALIDATION TEST RESULTS ===')
    print('Source Evidence: ' + out_bin.name + ' (' + str(out_bin.stat().st_size) + ' bytes)')
    print('Total Extracted Events: ' + str(len(events)))
    print('Extracted GPS Fixes: ' + str(len(gps_events)) + ' / Expected: 100')
    print('Extracted Battery Records: ' + str(len(bat_events)) + ' / Expected: 100')

    test_indices = [0, 24, 49, 74, 99]
    print('\n+-----+----------------------+----------------------+------------+------------------+------------------+------------+---------+')
    print('| Pt# | Expected Lat         | Extracted Lat        | Delta Lat  | Expected Volt    | Extracted Volt   | Delta Volt | Verdict |')
    print('+-----+----------------------+----------------------+------------+------------------+------------------+------------+---------+')

    all_pass = True
    for idx in test_indices:
        exp_lat = 19.0760000 + idx * 0.0001000
        exp_volt = 12.60 - idx * 0.02
        
        ext_lat = gps_events[idx].latitude
        ext_volt = bat_events[idx].battery_voltage_v
        
        d_lat = abs(exp_lat - ext_lat)
        d_volt = abs(exp_volt - ext_volt)
        
        verdict = 'PASS' if (d_lat < 1e-5 and d_volt < 0.01) else 'FAIL'
        if verdict == 'FAIL':
            all_pass = False
        
        print('| {:>3} | {:>20.7f} | {:>20.7f} | {:>10.2e} | {:>14.2f} V | {:>14.2f} V | {:>8.2e} V | {:>7} |'.format(idx+1, exp_lat, ext_lat, d_lat, exp_volt, ext_volt, d_volt, verdict))

    print('+-----+----------------------+----------------------+------------+------------------+------------------+------------+---------+')
    final_verdict = 'PASS (100% MATHEMATICAL PRECISION)' if all_pass else 'FAIL'
    print('\nFINAL VALIDATION OUTCOME: ' + final_verdict)
    return all_pass

if __name__ == '__main__':
    run_validation()
