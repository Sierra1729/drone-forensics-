"""
Test script to inspect the Google Drive catalog and download targeted drone logs.
"""
import sys
from pathlib import Path
import gdown

DRIVE_FOLDER_URL = "https://drive.google.com/drive/folders/1-UrxFGpCo54bVujwFmmqNbsZEV28dSNz?usp=sharing"

def inspect_and_download():
    print("[*] Retrieving file list from Google Drive folder...")
    files = gdown.download_folder(DRIVE_FOLDER_URL, skip_download=True, quiet=True)
    print(f"[+] Found {len(files)} total files.")
    
    # Print sample file paths
    drone_categories = set()
    flight_log_files = []
    
    for f in files:
        p = Path(f.path)
        parts = p.parts
        if len(parts) > 1:
            drone_categories.add(parts[1])
        
        ext = p.suffix.lower()
        if ext in {'.dat', '.ulg', '.bin', '.tlog', '.txt', '.csv', '.json', '.bbl', '.log', '.param', '.zip'}:
            flight_log_files.append(f)
            
    print("\n--- Available Drone Models in Dataset ---")
    for d in sorted(drone_categories):
        print(f"  • {d}")
        
    print(f"\n[+] Total candidate flight log files: {len(flight_log_files)}")
    print("\n--- Sample Flight Log Files ---")
    for f in flight_log_files[:15]:
        print(f"  {f.path} (ID: {f.id})")

if __name__ == "__main__":
    inspect_and_download()
