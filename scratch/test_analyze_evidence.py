"""
Test analyze_evidence on betaflight_multi.bbl and other files
"""
import sys
import json
from pathlib import Path
sys.path.insert(0, ".")

from gui.api import DesktopForensicAPI

api = DesktopForensicAPI()

files_to_test = [
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\03_Betaflight_FPV_Logs\betaflight_multi.bbl",
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\03_Betaflight_FPV_Logs\betaflight_sample.bfl",
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\01_DJI_Flight_Logs\dji_flight_record.csv",
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\01_DJI_Flight_Logs\adsb_log_type0_20180913112320.dat",
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\02_ArduPilot_and_PX4_Logs\2018-06-04 15-29-57.bin",
    r"C:\Users\pawan\Desktop\Drone_Test_Evidence\02_ArduPilot_and_PX4_Logs\real_px4_flight.ulg",
]

for fpath in files_to_test:
    p = Path(fpath)
    if not p.exists():
        print(f"[!] File not found: {fpath}")
        continue
    print(f"\n=======================================================")
    print(f"Testing analyze_evidence on: {p.name}")
    try:
        res = api.analyze_evidence(str(p), case_id="TEST-CASE-001", examiner="Auditor")
        status = res.get("status")
        msg = res.get("message", "")
        summary = res.get("summary", {})
        print(f"Result Status: {status}")
        if status == "error":
            print(f"Error Message: {msg}")
        else:
            print(f"Success! Total Events: {summary.get('total_events')}, Drone: {summary.get('drone_model')}, Flight Duration: {summary.get('duration_sec')}s")
    except Exception as e:
        print(f"Exception during analyze_evidence: {e}")
        import traceback
        traceback.print_exc()
