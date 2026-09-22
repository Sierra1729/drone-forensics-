r"""
scratch/verify_all_desktop_files.py

Automatically audits and runs the full forensic pipeline (analyze_evidence)
on every single file inside C:\Users\pawan\Desktop\Drone_Test_Evidence.
"""
import sys
from pathlib import Path
sys.path.insert(0, ".")

from gui.api import DesktopForensicAPI

api = DesktopForensicAPI()
desktop_dir = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence")

print(f"===============================================================================")
print(f"       COMPREHENSIVE SELF-TEST: AUDITING ALL DESKTOP EVIDENCE FILES")
print(f"===============================================================================")

total_tested = 0
passed_count = 0
failed_count = 0

for cat_dir in sorted(desktop_dir.iterdir()):
    if not cat_dir.is_dir():
        continue
        
    print(f"\n[*] Category: {cat_dir.name}")
    for file_path in sorted(cat_dir.iterdir()):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() in [".md5", ".sha1", ".param"]:
            continue
            
        total_tested += 1
        print(f"  - Testing: {file_path.name} ({file_path.stat().st_size} bytes)...", end=" ")
        try:
            res = api.analyze_evidence(str(file_path), case_id=f"AUDIT-{total_tested:03d}", examiner="System Auditor")
            status = res.get("status")
            if status == "success":
                passed_count += 1
                coords = res.get("coords", [])
                threats = res.get("threats", [])
                print(f"[OK] SUCCESS! ({len(coords)} GPS coords, {len(threats)} anomalies)")
            else:
                failed_count += 1
                print(f"[FAIL] Error: {res.get('message')}")
        except Exception as e:
            failed_count += 1
            print(f"[EXCEPTION] {e}")

print(f"\n===============================================================================")
print(f"Self-Test Summary: {passed_count}/{total_tested} Passed ({failed_count} Failed)")
print(f"===============================================================================")
