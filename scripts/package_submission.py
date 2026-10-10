"""
scripts/package_submission.py

Packages the complete PUSHPAK Stage 1 Submission into a clean ZIP archive named:
Security_of_Drones_TM-C22002DAA34.zip

Strictly excludes large physical disk images (.dd files) to ensure total size < 1 GB.
Computes SHA-256 and BLAKE3 digests of the final package.
"""

import os
import zipfile
import hashlib
from pathlib import Path

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

ROOT_DIR = Path(__file__).resolve().parent.parent
ZIP_NAME = "Security_of_Drones_TM-C22002DAA34.zip"
OUTPUT_ZIP_PATH = ROOT_DIR / ZIP_NAME

# File extensions to strictly exclude
EXCLUDED_EXTENSIONS = {'.dd', '.pyc', '.git', '.pytest_cache'}
EXCLUDED_DIRS = {'.git', '__pycache__', '.pytest_cache', 'temp_test_dir', '.idea', '.vscode'}

def build_submission_zip():
    print(f"Building submission archive: {ZIP_NAME}")
    
    files_added = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(OUTPUT_ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

            rel_root = Path(root).relative_to(ROOT_DIR)
            
            # Don't re-include zip packages themselves
            for file in files:
                file_path = Path(root) / file
                rel_path = rel_root / file

                # Skip self zip, previous submission zips, or .dd files
                if file_path.suffix.lower() in EXCLUDED_EXTENSIONS:
                    print(f"  [EXCLUDING] {rel_path} (Excluded extension)")
                    continue
                if file in {ZIP_NAME, "Pushpak_GC3_Drone_Forensics_Toolkit_Submission.zip", "Pushpak_Core_For_Review.zip"}:
                    continue
                
                # Add file to zip
                zipf.write(file_path, arcname=str(rel_path))
                files_added += 1
                total_uncompressed_bytes += file_path.stat().st_size

    zip_size = OUTPUT_ZIP_PATH.stat().st_size
    print(f"\nSuccessfully created {ZIP_NAME}")
    print(f"  -> Total Files Included: {files_added}")
    print(f"  -> Uncompressed Size:    {total_uncompressed_bytes / (1024*1024):.2f} MB")
    print(f"  -> Compressed ZIP Size:   {zip_size / (1024*1024):.2f} MB")
    
    # Check 1 GB limit
    if zip_size < 1024 * 1024 * 1024:
        print("  -> Size Limit Audit:     PASS (< 1 GB limit)")
    else:
        print("  -> Size Limit Audit:     FAIL (Exceeds 1 GB!)")

    # Hashes
    sha256_hash = hashlib.sha256()
    blake3_hash = blake3.blake3() if HAS_BLAKE3 else None

    with open(OUTPUT_ZIP_PATH, 'rb') as f:
        while chunk := f.read(65536):
            sha256_hash.update(chunk)
            if blake3_hash:
                blake3_hash.update(chunk)

    print(f"  -> SHA-256 Digest: {sha256_hash.hexdigest()}")
    if blake3_hash:
        print(f"  -> BLAKE3 Digest:  {blake3_hash.hexdigest()}")

    # Update SUBMISSION_MANIFEST.txt
    manifest_path = ROOT_DIR / "SUBMISSION_MANIFEST.txt"
    manifest_content = (
        f"PUSHPAK GRAND CHALLENGE 2026-27 | STAGE 1 SUBMISSION MANIFEST\n"
        f"Team ID: TM-C22002DAA34\n"
        f"Archive File: {ZIP_NAME}\n"
        f"Archive Size: {zip_size:,} bytes ({zip_size / (1024*1024):.2f} MB)\n"
        f"SHA-256 Digest: {sha256_hash.hexdigest()}\n"
    )
    if blake3_hash:
        manifest_content += f"BLAKE3 Digest:  {blake3_hash.hexdigest()}\n"
    manifest_content += f"Total Included Files: {files_added}\n"

    with open(manifest_path, 'w', encoding='utf-8') as f:
        f.write(manifest_content)
    print("  -> SUBMISSION_MANIFEST.txt updated.")

if __name__ == '__main__':
    build_submission_zip()
