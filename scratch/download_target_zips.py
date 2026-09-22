"""
scratch/download_target_zips.py

Downloads and extracts lightweight (<50MB) flight logs, telemetry archives,
and mobile extractions from the VTO Labs dataset.
"""
import os
import re
import sys
import zipfile
from pathlib import Path
import gdown

LOG_PATH = Path(r"C:\Users\pawan\.gemini\antigravity\brain\bb3ef03a-d696-48f6-8331-721c2751b59d\.system_generated\tasks\task-1474.log")
OUTPUT_DIR = Path("sample_evidence/vto_labs_drone_forensics")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def parse_log_targets():
    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    current_drone = "unknown_drone"
    targets = []
    
    for line in lines:
        line = line.strip()
        m_folder = re.search(r"Retrieving folder\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
        if m_folder:
            f_id, f_name = m_folder.groups()
            if "df0" in f_name.lower() or "dji" in f_name.lower() or "parrot" in f_name.lower() or "yuneec" in f_name.lower() or "solo" in f_name.lower() or "ardupilot" in f_name.lower():
                current_drone = f_name
            continue
        
        m_file = re.search(r"Processing file\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
        if m_file:
            file_id, file_name = m_file.groups()
            ext = Path(file_name).suffix.lower()
            if ext in {'.zip', '.bin', '.dat', '.txt', '.csv', '.json', '.ulg', '.log', '.param', '.md5', '.sha1'}:
                targets.append({
                    "drone": current_drone,
                    "id": file_id,
                    "name": file_name,
                    "ext": ext
                })
    return targets

def main():
    targets = parse_log_targets()
    print(f"[*] Found {len(targets)} candidate forensic log files in VTO Labs dataset.")
    
    # Priority targets: flight_logs.zip, android, ios, dat, bin
    priority_keywords = ["flight", "log", "mission", "telemetry", "record", "android", "ios", "readme"]
    
    prioritized = []
    for t in targets:
        name_lower = t["name"].lower()
        if any(k in name_lower for k in priority_keywords):
            prioritized.append(t)
            
    print(f"[*] Prioritized flight logs & extractions: {len(prioritized)}")
    
    downloaded_count = 0
    extracted_count = 0
    
    for idx, item in enumerate(prioritized, 1):
        drone_dir = OUTPUT_DIR / item["drone"]
        drone_dir.mkdir(parents=True, exist_ok=True)
        dest_file = drone_dir / item["name"]
        
        if dest_file.exists() and dest_file.stat().st_size > 0:
            print(f"[{idx}/{len(prioritized)}] Already exists: {dest_file.name}")
            downloaded_count += 1
            continue
            
        print(f"[{idx}/{len(prioritized)}] Downloading {item['drone']} -> {item['name']} (ID: {item['id']})...")
        try:
            res = gdown.download(id=item["id"], output=str(dest_file), quiet=True)
            if res and dest_file.exists():
                file_size_mb = dest_file.stat().st_size / (1024 * 1024)
                print(f"    -> Downloaded {file_size_mb:.2f} MB")
                
                # If oversized (>60MB), remove to keep repo clean
                if file_size_mb > 60:
                    print(f"    -> Removing oversized file ({file_size_mb:.2f} MB > 60 MB limit)")
                    dest_file.unlink()
                    continue
                    
                downloaded_count += 1
                
                # If it is a zip file, extract it
                if item["ext"] == ".zip":
                    try:
                        extract_dir = drone_dir / Path(item["name"]).stem
                        with zipfile.ZipFile(dest_file, "r") as z:
                            z.extractall(extract_dir)
                            print(f"    -> Extracted {len(z.namelist())} files into {extract_dir.name}/")
                            extracted_count += 1
                    except Exception as ze:
                        print(f"    -> Zip extraction warning: {ze}")
                        
        except Exception as e:
            print(f"    -> Download error: {e}")
            
    print(f"\n[+] Completed! Downloaded {downloaded_count} evidence files, extracted {extracted_count} archives into {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
