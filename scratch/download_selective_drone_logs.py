"""
scratch/download_selective_drone_logs.py

Selectively downloads drone flight records, telemetry logs, and manifests
from the VTO Labs / NIST Drone Forensics Google Drive repository, skipping
multi-gigabyte raw physical SD card disk image dumps (.001 / raw image chunks).
"""
import os
import sys
from pathlib import Path
import gdown

DRIVE_FOLDER_URL = "https://drive.google.com/drive/folders/1-UrxFGpCo54bVujwFmmqNbsZEV28dSNz?usp=sharing"
OUTPUT_DIR = Path("sample_evidence/vto_labs_drone_forensics")

# Allowed forensic log and metadata extensions
ALLOWED_EXTENSIONS = {
    ".dat", ".ulg", ".bin", ".tlog", ".txt", ".csv", ".json",
    ".bbl", ".bfl", ".aem", ".log", ".params", ".srt", ".jpg",
    ".jpeg", ".png", ".md5", ".sha1", ".zip"
}


# Explicitly skip raw physical disk images (.001, .raw, .dd, .img)
SKIP_EXTENSIONS = {".001", ".002", ".003", ".raw", ".dd", ".img", ".iso", ".vmdk", ".vdi"}


def main():
    print(f"[*] Querying Google Drive folder: {DRIVE_FOLDER_URL}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Retrieve file list without downloading
    print("[*] Retrieving file metadata catalog...")
    all_files = gdown.download_folder(DRIVE_FOLDER_URL, skip_download=True, quiet=False)
    print(f"[+] Total files in Drive folder: {len(all_files)}")

    # 2. Filter for flight logs and telemetry
    target_files = []
    skipped_large_images = 0

    for f in all_files:
        p = Path(f.path)
        ext = p.suffix.lower()
        if ext in SKIP_EXTENSIONS or ".00" in ext:
            skipped_large_images += 1
            continue
        if ext in ALLOWED_EXTENSIONS or "flight_logs" in f.path.lower() or "mobile" in f.path.lower():
            target_files.append(f)

    print(f"[+] Target flight logs & metadata files: {len(target_files)}")
    print(f"[+] Skipped raw physical disk images (.001): {skipped_large_images}")

    # 3. Download each target file into categorized folder structure
    success_count = 0
    for idx, f in enumerate(target_files, 1):
        rel_path = Path(f.path)
        # Strip top-level root folder name if present
        parts = rel_path.parts
        if len(parts) > 1:
            dest_rel = Path(*parts[1:])
        else:
            dest_rel = rel_path

        dest_file = OUTPUT_DIR / dest_rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        if dest_file.exists() and dest_file.stat().st_size > 0:
            print(f"[{idx}/{len(target_files)}] Already exists: {dest_rel}")
            success_count += 1
            continue

        print(f"[{idx}/{len(target_files)}] Downloading: {dest_rel} (ID: {f.id})")
        try:
            downloaded = gdown.download(id=f.id, output=str(dest_file), quiet=True)
            if downloaded and dest_file.exists():
                success_count += 1
                print(f"    -> Successfully downloaded: {dest_file.stat().st_size} bytes")
        except Exception as e:
            print(f"    -> Download error: {e}")

    print(f"\n[+] Selective download finished: {success_count}/{len(target_files)} files downloaded to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
