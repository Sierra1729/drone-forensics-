"""
scratch/download_lightweight_evidence.py

Downloads specific lightweight flight logs, mobile companion app records,
and parameters for various drones in the VTO dataset.
"""
import os
import sys
import zipfile
import requests
from pathlib import Path

# Known target files from task-1474.log
TARGETS = [
    # DJI Inspire 1
    {"name": "DF010_flight_ios.zip", "id": "0B1aBvVt_vSSeb05sR2NYRWU4a1E", "folder": "df010_DJI_Inspire_1"},
    {"name": "DF011_flight_ios.zip", "id": "0B1aBvVt_vSSeYk1TLXowRXpjeW8", "folder": "df011_DJI_Inspire_1"},
    {"name": "DF025_flight_ios.zip", "id": "0B1aBvVt_vSSeTVh0cThnYmpnSnM", "folder": "df025_DJI_Inspire_2"},
    {"name": "DF026_flight_ios.zip", "id": "0B1aBvVt_vSSeV1lhalBRempqT0k", "folder": "df026_DJI_Inspire_2"},
    {"name": "DF027_flight_ios.zip", "id": "0B1aBvVt_vSSeR0FrR1o5S3pCNFU", "folder": "df027_DJI_Inspire_2"},
    {"name": "DF034_internal_logical.zip", "id": "0B1aBvVt_vSSeWlQxWURBUDd4TXM", "folder": "df034_DJI_Matrice_600"},
    {"name": "DF035_internal_logical.zip", "id": "0B1aBvVt_vSSeTkF4QmkteWpFNk0", "folder": "df035_DJI_Matrice_600"},
]

OUTPUT_BASE = Path("sample_evidence/vto_labs_drone_forensics")

def download_file_from_google_drive(file_id, destination):
    session = requests.Session()
    url = "https://docs.google.com/uc?export=download"
    response = session.get(url, params={'id': file_id, 'confirm': 't'}, stream=True)
    
    # Check if download warning exists
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            response = session.get(url, params={'id': file_id, 'confirm': value}, stream=True)
            break
            
    content_type = response.headers.get('content-type', '')
    if 'text/html' in content_type and 'google.com' in response.text:
        # Might be a permission / sign-in screen
        return False, "Google Drive restricted permission / HTML response"
        
    with open(destination, "wb") as f:
        for chunk in response.iter_content(32768):
            if chunk:
                f.write(chunk)
                
    return True, f"{destination.stat().st_size} bytes"

def main():
    print("[*] Starting targeted forensic log download...")
    for t in TARGETS:
        dest_dir = OUTPUT_BASE / t["folder"]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / t["name"]
        
        print(f"\n[*] Processing {t['folder']} -> {t['name']}...")
        success, msg = download_file_from_google_drive(t["id"], dest_path)
        print(f"    Status: {msg}")
        
        if success and dest_path.exists() and dest_path.stat().st_size > 1000:
            if t["name"].endswith(".zip"):
                extract_dir = dest_dir / Path(t["name"]).stem
                try:
                    with zipfile.ZipFile(dest_path, 'r') as z:
                        z.extractall(extract_dir)
                        print(f"    [+] Extracted {len(z.namelist())} files into {extract_dir}")
                except Exception as e:
                    print(f"    [!] Extract error: {e}")

if __name__ == "__main__":
    main()
