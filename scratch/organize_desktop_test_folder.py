"""
scratch/organize_desktop_test_folder.py

Creates a categorized, easy-to-use testing folder on the User's Desktop
with authentic and synthetic flight logs ready for GUI drag-and-drop / upload testing.
"""
import shutil
import os
from pathlib import Path

DESKTOP_DIR = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence")
PROJECT_DIR = Path(r"c:\Users\pawan\Desktop\df")
SAMPLE_EVIDENCE = PROJECT_DIR / "sample_evidence"

CATEGORIES = {
    "01_DJI_Flight_Logs": [
        SAMPLE_EVIDENCE / "dji_flight_record.csv",
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "DJI_Assistant_export_ADB" / "DJI_Assistant_Export_ADBS" / "adsb_log_type0_20180913112320.dat",
    ],
    "02_ArduPilot_and_PX4_Logs": [
        SAMPLE_EVIDENCE / "ardupilot_sample.bin",
        SAMPLE_EVIDENCE / "real_px4_flight.ulg",
        SAMPLE_EVIDENCE / "mission_planner_logs" / "2018-06-04 15-29-57.bin",
        SAMPLE_EVIDENCE / "mission_planner_logs" / "2018-06-04 15-40-17.bin",
        SAMPLE_EVIDENCE / "mission_planner_logs" / "2018-06-04 15-29-57.log",
        SAMPLE_EVIDENCE / "mission_planner_logs" / "2018-06-04 15-29-57.log.param",
        SAMPLE_EVIDENCE / "mission_planner_logs" / "2018-06-04 15-29-57.kmz",
    ],
    "03_Betaflight_FPV_Logs": [
        SAMPLE_EVIDENCE / "betaflight_sample.bfl",
        SAMPLE_EVIDENCE / "betaflight_multi.bbl",
    ],
    "04_Yuneec_and_Companion_Logs": [
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "df033_Yuneec_H520" / "Controller_Logical",
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "df046_Ryze_Tello" / "Android_Logical",
    ],
    "05_Corrupted_and_Carving_Samples": [
        SAMPLE_EVIDENCE / "betaflight_corrupt.bfl",
    ],
    "06_Chain_of_Custody_Manifests": [
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "df057_ArduPilot_Drone" / "README_DF057_Drone_Forensics_Program.txt",
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "df057_ArduPilot_Drone" / "README_DF057_Drone_Forensics_Program.txt.MD5",
        SAMPLE_EVIDENCE / "vto_labs_drone_forensics" / "df057_ArduPilot_Drone" / "README_DF057_Drone_Forensics_Program.txt.SHA1",
    ]
}

README_CONTENT = """===============================================================================
               DRONE FORENSICS SUITE - TEST EVIDENCE FOLDER
===============================================================================

Use the files in these folders to test the Forensic Suite GUI and CLI:

-------------------------------------------------------------------------------
FOLDER / EVIDENCE TYPE                RECOMMENDED TESTING WORKFLOW
-------------------------------------------------------------------------------
01_DJI_Flight_Logs                    • Upload CSV to Tab 1 (Flight Analysis)
  - dji_flight_record.csv             • Upload DAT to Tab 6 (Hex & Carving Inspector)
  - adsb_log_type0_*.dat

02_ArduPilot_and_PX4_Logs             • Upload .bin or .ulg to Tab 1 (Flight Analysis)
  - 2018-06-04 15-29-57.bin           • Check 2D Leaflet map, 3D trajectory plot,
  - real_px4_flight.ulg                 altitude charts, and EKF attitude gauges.

03_Betaflight_FPV_Logs                • Upload .bfl / .bbl to Tab 1
  - betaflight_sample.bfl             • Test multi-session FPV racing analysis.

04_Yuneec_and_Companion_Logs          • Contains ground station ST16 logs and
  - Yuneec H520 controller logs         mobile app databases for pilot tracking.
  - Ryze Tello Android logs

05_Corrupted_and_Carving_Samples      • Upload to Tab 6 (Hex & Carving Inspector)
  - betaflight_corrupt.bfl            • Test resilient carving & damaged frame repair.

06_Chain_of_Custody_Manifests         • Upload to Tab 5 (Chain of Custody & Audit)
  - NIST / VTO README & MD5/SHA1      • Validate court-admissible hash verification.
===============================================================================
"""

def main():
    if DESKTOP_DIR.exists():
        shutil.rmtree(DESKTOP_DIR, ignore_errors=True)
    DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
    
    # Write Readme
    with open(DESKTOP_DIR / "00_HOW_TO_TEST_READ_ME.txt", "w", encoding="utf-8") as f:
        f.write(README_CONTENT)
        
    copied_count = 0
    for cat_name, file_list in CATEGORIES.items():
        cat_dir = DESKTOP_DIR / cat_name
        cat_dir.mkdir(parents=True, exist_ok=True)
        
        for item in file_list:
            if not item.exists():
                print(f"[!] Warning: missing item {item}")
                continue
            if item.is_dir():
                # Copy a curated subset (e.g. top 5 files) if directory
                for subfile in list(item.glob("*"))[:8]:
                    if subfile.is_file():
                        shutil.copy2(subfile, cat_dir / subfile.name)
                        copied_count += 1
            else:
                shutil.copy2(item, cat_dir / item.name)
                copied_count += 1
                
    print(f"[+] Successfully organized {copied_count} test evidence files into:\n    {DESKTOP_DIR}")

if __name__ == "__main__":
    main()
