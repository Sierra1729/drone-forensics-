"""
crypto/__init__.py

Forensic Protected-Data Analysis and Decryption Package.
Compliant with ISO/IEC 27037:2012 (Digital Evidence Preservation).
"""

from crypto.protected_data import (
    EncryptionType,
    ProtectedDataReport,
    identify_encryption,
    find_keys,
    decrypt_artifact,
)

__all__ = [
    "EncryptionType",
    "ProtectedDataReport",
    "identify_encryption",
    "find_keys",
    "decrypt_artifact",
]
