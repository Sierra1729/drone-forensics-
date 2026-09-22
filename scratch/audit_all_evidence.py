"""
Check crypto / parser analysis for all files in Drone_Test_Evidence
"""
import sys
from pathlib import Path
sys.path.insert(0, ".")

import parsers
from parsers.base import get_parser_for_file
from crypto.protected_data import identify_encryption, decrypt_artifact

evidence_dir = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence")

for f in sorted(evidence_dir.rglob("*")):
    if f.is_file() and not f.name.endswith(".txt") and not f.name.endswith(".MD5") and not f.name.endswith(".SHA1"):
        rel = str(f.relative_to(evidence_dir))
        enc_type, entropy, meta = identify_encryption(f)
        parser = get_parser_for_file(f)
        p_name = parser.parser_name if parser else "None"
        print(f"{rel:50} | Size: {f.stat().st_size:8d} | Enc: {enc_type.value:18} | Parser: {p_name}")
