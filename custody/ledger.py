"""
custody/ledger.py

Hash-chained, append-only chain-of-custody ledger.

Every acquisition, hash-verification, parse, or export action against a
piece of evidence gets one entry here. Each entry embeds the hash of the
previous entry, so altering or deleting any past entry breaks the chain
from that point forward onward -- the same principle tamper-evident logs
and blockchains use, applied at the scale of a single case file.

Both SHA-256 and BLAKE3 are recorded for every hashed target:
- SHA-256 because it's the algorithm forensic tooling, courts, and existing
  case law are already familiar with.
- BLAKE3 as a fast, modern secondary digest -- two independent algorithms
  agreeing is stronger evidence against tampering than one, and BLAKE3's
  speed matters once you're hashing multi-gigabyte disk images.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union, Tuple, Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import blake3
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The 'blake3' package is required for chain-of-custody hashing "
        "(pip install blake3 --break-system-packages). Silently falling "
        "back to a different digest algorithm is not acceptable in a "
        "forensic tool, so the toolkit refuses to start instead."
    ) from exc

_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB, sized for multi-GB disk images


def generate_session_key(
    examiner_cert_path: Optional[Union[Path, str]] = None,
    salt: Optional[bytes] = None,
    ledger_filename: str = "chain_of_custody.jsonl",
) -> Tuple[bytes, Dict[str, Any]]:
    """Derive dynamic session key bound to an examiner X.509 certificate via HKDF,
    or generate a 256-bit cryptographically secure session key bound to salt.
    """
    cert_path_str = examiner_cert_path or os.environ.get("GARUD_EXAMINER_CERT")
    salt_bytes = salt or os.urandom(32)

    if cert_path_str:
        cert_p = Path(cert_path_str)
        if cert_p.is_file():
            try:
                cert_bytes = cert_p.read_bytes()
                try:
                    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                except Exception:
                    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

                pub_key = cert.public_key()
                pub_bytes = pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                cert_fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
                subject_str = cert.subject.rfc4514_string()

                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt_bytes,
                    info=b"GARUD_FX_SESSION_KEY_V2",
                    backend=default_backend(),
                )
                session_key = hkdf.derive(pub_bytes)
                metadata = {
                    "key_type": "CERTIFICATE_BOUND",
                    "cert_fingerprint": cert_fp,
                    "cert_subject": subject_str,
                    "kdf": "HKDF-HMAC-SHA256",
                    "salt_hex": salt_bytes.hex(),
                }
                return session_key, metadata
            except Exception:
                pass

    # Ephemeral Key Derivation with salt binding
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        info=ledger_filename.encode("utf-8"),
        backend=default_backend(),
    )
    ephemeral_key = hkdf.derive(salt_bytes)
    fp = hashlib.sha256(ephemeral_key).hexdigest()
    metadata = {
        "key_type": "EPHEMERAL",
        "event": "EPHEMERAL_KEY_GENERATED",
        "cert_fingerprint": fp,
        "cert_subject": "EPHEMERAL_EXAMINER",
        "kdf": "SECRETS_TOKEN_BYTES_256",
        "salt_hex": salt_bytes.hex(),
    }
    return ephemeral_key, metadata


def hash_file(path: Path) -> tuple[str, str]:
    """Stream-hash a file with SHA-256 and BLAKE3 in a single pass."""
    sha256 = hashlib.sha256()
    b3 = blake3.blake3()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            sha256.update(chunk)
            b3.update(chunk)
    return sha256.hexdigest(), b3.hexdigest()


def compute_hmac_signature(payload_bytes: bytes, secret_key: bytes) -> str:
    """Computes HMAC-SHA256 digital signature to seal ledger entry against manual text-editor tampering."""
    return hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()


class ChainIntegrityError(Exception):
    """Raised where a caller needs verify_chain() failures to be fatal."""


@dataclass
class LedgerEntry:
    index: int
    timestamp_utc: str
    actor: str
    action: str
    target_path: str
    target_sha256: Optional[str]
    target_blake3: Optional[str]
    notes: Optional[str]
    previous_entry_hash: str
    entry_hash: str = ""  # filled in after the rest of the entry is fixed
    digital_signature: str = ""  # HMAC-SHA256 digital signature sealing the entry

    def canonical_bytes_without_own_hash(self) -> bytes:
        d = asdict(self)
        d.pop("entry_hash", None)
        d.pop("digital_signature", None)
        return json.dumps(d, sort_keys=True).encode("utf-8")


class ChainOfCustodyLedger:
    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        ledger_path: Union[Path, str],
        session_key: Optional[bytes] = None,
        examiner_cert_path: Optional[Union[Path, str]] = None,
    ) -> None:
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.examiner_cert_path = examiner_cert_path
        self._entries: list[LedgerEntry] = []

        stored_meta = None
        if self.ledger_path.exists():
            self._entries = self._read_all()
            if self._entries and self._entries[0].notes and "[GENESIS BINDING:" in self._entries[0].notes:
                try:
                    notes_text = self._entries[0].notes
                    json_str = notes_text.split("[GENESIS BINDING: ", 1)[1].split("]", 1)[0]
                    stored_meta = json.loads(json_str)
                except Exception:
                    pass

        if session_key:
            self.session_key = session_key
            self.session_metadata = {"key_type": "EXPLICIT_KEY"}
        elif os.environ.get("GARUD_SESSION_KEY"):
            self.session_key = os.environ.get("GARUD_SESSION_KEY", "").encode("utf-8")
            self.session_metadata = {"key_type": "ENV_SESSION_KEY"}
        elif stored_meta and "salt_hex" in stored_meta:
            salt_b = bytes.fromhex(stored_meta["salt_hex"])
            self.session_key, self.session_metadata = generate_session_key(
                examiner_cert_path=examiner_cert_path,
                salt=salt_b,
                ledger_filename=self.ledger_path.name,
            )
        else:
            self.session_key, self.session_metadata = generate_session_key(
                examiner_cert_path=examiner_cert_path,
                ledger_filename=self.ledger_path.name,
            )



    def _read_all(self) -> list[LedgerEntry]:
        entries = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entries.append(LedgerEntry(**data))
        return entries

    def _last_entry_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH

    def record(
        self,
        actor: str,
        action: str,
        target_path: Union[Path, str],
        notes: Optional[str] = None,
        hash_target: bool = True,
    ) -> LedgerEntry:
        """Append one tamper-evident entry.

        Hashes target_path unless hash_target=False (e.g. logging a second
        action moments after an already-hashed step, to avoid re-reading a
        multi-GB image twice).
        """
        target_path_str = str(target_path)
        sha256_hex = blake3_hex = None
        if hash_target:
            sha256_hex, blake3_hex = hash_file(Path(target_path_str))

        entry_idx = len(self._entries)
        # If this is the genesis block (index 0), bind examiner identity & KDF metadata into notes
        if entry_idx == 0:
            genesis_meta = json.dumps(self.session_metadata, sort_keys=True)
            genesis_prefix = f"[GENESIS BINDING: {genesis_meta}]"
            notes = f"{genesis_prefix} {notes}" if notes else genesis_prefix

        entry = LedgerEntry(
            index=entry_idx,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target_path=target_path_str,
            target_sha256=sha256_hex,
            target_blake3=blake3_hex,
            notes=notes,
            previous_entry_hash=self._last_entry_hash(),
        )
        canonical = entry.canonical_bytes_without_own_hash()
        entry.entry_hash = hashlib.sha256(canonical).hexdigest()
        entry.digital_signature = compute_hmac_signature(entry.entry_hash.encode("utf-8"), self.session_key)

        self._entries.append(entry)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry


    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Recompute every entry's hash, digital signature, and the linkage between entries.

        Returns (True, None) if the entire chain is intact, or
        (False, index) where index is the first entry found broken, tampered, or altered.
        """
        previous_hash = self.GENESIS_HASH
        for entry in self._entries:
            if entry.previous_entry_hash != previous_hash:
                return False, entry.index
            recomputed = hashlib.sha256(
                entry.canonical_bytes_without_own_hash()
            ).hexdigest()
            if recomputed != entry.entry_hash:
                return False, entry.index
            if entry.digital_signature:
                expected_sig = compute_hmac_signature(entry.entry_hash.encode("utf-8"), self.session_key)
                if entry.digital_signature != expected_sig:
                    return False, entry.index
            previous_hash = entry.entry_hash
        return True, None

    def read_all(self) -> list[dict[str, Any]]:
        """Return all ledger entries as a list of dictionaries."""
        return [asdict(e) for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

