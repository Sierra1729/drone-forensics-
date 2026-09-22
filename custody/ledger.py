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
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

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


def hash_file(path: Path) -> tuple[str, str]:
    """Stream-hash a file with SHA-256 and BLAKE3 in a single pass."""
    sha256 = hashlib.sha256()
    b3 = blake3.blake3()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            sha256.update(chunk)
            b3.update(chunk)
    return sha256.hexdigest(), b3.hexdigest()


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

    def canonical_bytes_without_own_hash(self) -> bytes:
        d = asdict(self)
        d.pop("entry_hash")
        return json.dumps(d, sort_keys=True).encode("utf-8")


class ChainOfCustodyLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, ledger_path: Union[Path, str]) -> None:
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[LedgerEntry] = []
        if self.ledger_path.exists():
            self._entries = self._read_all()


    def _read_all(self) -> list[LedgerEntry]:
        entries = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(LedgerEntry(**json.loads(line)))
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
        target_path = str(target_path)
        sha256_hex = blake3_hex = None
        if hash_target:
            sha256_hex, blake3_hex = hash_file(Path(target_path))

        entry = LedgerEntry(
            index=len(self._entries),
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target_path=target_path,
            target_sha256=sha256_hex,
            target_blake3=blake3_hex,
            notes=notes,
            previous_entry_hash=self._last_entry_hash(),
        )
        entry.entry_hash = hashlib.sha256(
            entry.canonical_bytes_without_own_hash()
        ).hexdigest()

        self._entries.append(entry)
        # Append-and-fsync immediately: a crash mid-investigation must not
        # cost custody entries that were already recorded.
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Recompute every entry's hash and the linkage between entries.

        Returns (True, None) if the entire chain is intact, or
        (False, index) where index is the first entry found broken or
        altered.
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
            previous_hash = entry.entry_hash
        return True, None

    def __len__(self) -> int:
        return len(self._entries)
