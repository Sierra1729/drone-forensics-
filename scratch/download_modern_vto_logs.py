"""
scratch/download_modern_vto_logs.py

Downloads flight logs, mobile companion archives, and parameters
from the VTO dataset using modern accessible Google Drive IDs.
"""
import os
import re
import sys
import zipfile
import requests
from pathlib import Path

LOG_PATH = Path(r"C:\Users\pawan\.gemini\antigravity\brain\bb3ef03a-d696-48f6-8331-721c2751b59d\.system_generated\tasks\task-1474.log")
OUTPUT_BASE = Path("sample_evidence/vto_labs_drone_forensics")

def get_modern_targets():
    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    current_drone = "VTO_Drone"
    targets = []
    
    for line in lines:
        line = line.strip()
        m_folder = re.search(r"Retrieving folder\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
        if m_folder:
            f_id, f_name = m_folder.groups()
            if any(k in f_name.lower() for k in ["df0", "dji", "parrot", "yuneec", "solo", "ardupilot", "rover"]):
                current_drone = f_name
            continue
            
        m_file = re.search(r"Processing file\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
        if m_file:
            file_id, file_name = m_file.groups()
            ext = Path(file_name).suffix.lower()
            
            # Filter: only IDs starting with '1' (public modern Drive IDs) and flight/telemetry/zip/txt
            if file_id.startswith("1") and ext in {'.zip', '.bin', '.dat', '.ulg', '.txt', '.param', '.log', '.csv'}:
                name_lower = file_name.lower()
                if any(kw in name_lower for kw in ['flight', 'log', 'mission', 'media', 'ios', 'android', 'readme', 'assistant']):
                    targets.append({
                        "drone": current_drone,
                        "id": file_id,
                        "name": file_name,
                        "ext": ext
                    })
    return targets

def download_file(file_id, dest_path):
    session = requests.Session()
    url = "https://docs.google.com/uc?export=download"
    response = session.get(url, params={'id': file_id, 'confirm': 't'}, stream=True)
    
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            response = session.get(url, params={'id': file_id, 'confirm': value}, stream=True)
            break
            
    content_type = response.headers.get('content-type', '')
    if 'text/html' in content_type and 'google.com' in response.text:
        return False, "Google Drive restricted"
        
    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(65536):
            if chunk:
                f.write(chunk)
                
    size = dest_path.stat().st_size
    return True, f"{size} bytes ({size / (1024*1024):.2f} MB)"

def main():
    targets = get_modern_targets()
    print(f"[*] Found {len(targets)} accessible flight log candidates.", flush=True)
    
    successful = 0
    for idx, t in enumerate(targets, 1):
        drone_dir = OUTPUT_BASE / t["drone"]
        drone_dir.mkdir(parents=True, exist_ok=True)
        dest_path = drone_dir / t["name"]
        
        if dest_path.exists() and dest_path.stat().st_size > 0:
            print(f"[{idx}/{len(targets)}] Already exists: {t['drone']} / {t['name']}", flush=True)
            successful += 1
            continue
            
        print(f"[{idx}/{len(targets)}] Downloading {t['drone']} -> {t['name']}...", end=" ", flush=True)
        ok, msg = download_file(t["id"], dest_path)
        print(f"[{msg}]", flush=True)
        
        if ok and dest_path.exists():
            size_mb = dest_path.stat().st_size / (1024 * 1024)
            # If oversized > 50MB, skip or extract and delete zip
            if size_mb > 50:
                print(f"    -> File > 50MB ({size_mb:.2f} MB). Skipping zip to preserve git repo limits.", flush=True)
                dest_path.unlink()
                continue
                
            successful += 1
            if t["ext"] == ".zip":
                try:
                    extract_dir = drone_dir / Path(t["name"]).stem
                    with zipfile.ZipFile(dest_path, 'r') as z:
                        z.extractall(extract_dir)
                        print(f"    [+] Extracted {len(z.namelist())} files into {extract_dir.name}/", flush=True)
                except Exception as ze:
                    print(f"    [!] Extraction error: {ze}", flush=True)
                    
    print(f"\n[+] Finished downloading & extracting {successful} evidence files!", flush=True)

if __name__ == "__main__":
    main()
