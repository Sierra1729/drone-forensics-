"""
Test parsing the newly acquired DJI DAT ADS-B log from VTO Labs
"""
import sys
from pathlib import Path
sys.path.insert(0, ".")
from parsers.dji import DJIFlightLogParser

dat_path = Path("sample_evidence/vto_labs_drone_forensics/DJI_Assistant_export_ADB/DJI_Assistant_Export_ADBS/adsb_log_type0_20180913112320.dat")

if dat_path.exists():
    print(f"[*] Found authentic DJI DAT file: {dat_path} ({dat_path.stat().st_size} bytes)")
    parser = DJIFlightLogParser()
    events = list(parser.parse(str(dat_path)))
    print(f"[+] Total parsed events: {len(events)}")
    gps_events = [e for e in events if getattr(e, "latitude", None) is not None]
    print(f"[+] GPS telemetry events: {len(gps_events)}")
    if gps_events:
        print(f"[+] First GPS: lat={gps_events[0].latitude}, lon={gps_events[0].longitude}")
else:
    print(f"[!] File not found: {dat_path}")
