"""
scripts/package_submission.py

Packages the entire clean codebase, documentation, verification artifacts,
and sample evidence into a submission-ready ZIP file for Grand Challenge 3.
Excludes git histories, cache directories, temporary test files, and logs.
Computes and prints the SHA-256 and BLAKE3 digests of the final package.
"""

import hashlib
import zipfile
from pathlib import Path
from typing import Set

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "temp_test_dir",
}

EXCLUDE_EXTENSIONS: Set[str] = {
    ".pyc",
    ".pyo",
    ".log",
}

EXCLUDE_FILES: Set[str] = {
    "tmp_test.bin",
}


def should_include(rel_path: Path) -> bool:
    for part in rel_path.parts:
        if part in EXCLUDE_DIRS:
            return False
    if rel_path.suffix.lower() in EXCLUDE_EXTENSIONS:
        return False
    if rel_path.name in EXCLUDE_FILES:
        return False
    return True


def package_repository(root_dir: Path, output_zip: Path) -> None:
    print(f"[*] Packaging repository: {root_dir}")
    print(f"[*] Output target: {output_zip}")

    included_count = 0
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(root_dir.rglob("*")):
            if file_path.is_file() and file_path != output_zip:
                rel_path = file_path.relative_to(root_dir)
                if should_include(rel_path):
                    zf.write(file_path, arcname=str(rel_path))
                    included_count += 1

    print(f"[+] Archived {included_count} files into {output_zip.name} ({output_zip.stat().st_size:,} bytes)")

    # Compute digests
    sha256 = hashlib.sha256()
    blake3_hasher = blake3.blake3() if HAS_BLAKE3 else None

    with open(output_zip, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            if blake3_hasher:
                blake3_hasher.update(chunk)

    sha256_hex = sha256.hexdigest()
    blake3_hex = blake3_hasher.hexdigest() if blake3_hasher else "N/A"

    manifest_path = root_dir / "SUBMISSION_MANIFEST.txt"
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write("PUSHPAK GRAND CHALLENGE 2026-27 | SUBMISSION ARCHIVE MANIFEST\n")
        mf.write(f"Archive File: {output_zip.name}\n")
        mf.write(f"Archive Size: {output_zip.stat().st_size:,} bytes\n")
        mf.write(f"SHA-256 Digest: {sha256_hex}\n")
        mf.write(f"BLAKE3 Digest:  {blake3_hex}\n")
        mf.write(f"Total Included Files: {included_count}\n")

    print(f"[+] Generated manifest at: {manifest_path}")
    print(f"    SHA-256: {sha256_hex}")
    print(f"    BLAKE3:  {blake3_hex}")


if __name__ == "__main__":
    workspace_root = Path(__file__).resolve().parent.parent
    zip_target = workspace_root / "Pushpak_GC3_Drone_Forensics_Toolkit_Submission.zip"
    package_repository(workspace_root, zip_target)
