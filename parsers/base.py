"""
parsers/base.py

Abstract base class and registry for UAV flight log parsers.

Forensic Soundness Guarantee:
Every parser subclass conforms to this interface. When parsing evidence,
the base framework calculates the dual cryptographic hashes (SHA-256 + BLAKE3)
and optionally registers a 'PARSE' action into the ChainOfCustodyLedger before
yielding normalized events.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Optional, Type

from custody.ledger import ChainOfCustodyLedger, hash_file
from normalize.schema import NormalizedEvent


class BaseParser(abc.ABC):
    """Abstract plugin interface for all vendor/platform log parsers."""

    @property
    @abc.abstractmethod
    def parser_name(self) -> str:
        """Human-readable identifier for this parser (e.g. 'ardupilot_dataflash')."""
        pass

    @property
    @abc.abstractmethod
    def supported_platforms(self) -> list[str]:
        """List of platform identifiers this parser handles (e.g. ['ardupilot', 'px4'])."""
        pass

    @property
    def parser_version(self) -> str:
        """Semantic version of the parser plugin for strict forensic reproducibility."""
        return "1.0.0"

    def __init__(self) -> None:
        self.is_corrupted: bool = False
        self.corruption_offset: Optional[int] = None
        self.salvaged_records_count: int = 0

    @abc.abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Inspect file header/magic bytes to determine if this parser can handle it.

        Must be fast, read minimal bytes, and handle corrupt or zero-byte files
        safely without raising unhandled exceptions.
        """
        pass

    @abc.abstractmethod
    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Core parsing logic implemented by subclasses.

        Args:
            file_path: Validated path to evidence file.
            file_sha256: Verified SHA-256 digest of the source file.

        Returns:
            List of NormalizedEvent instances.
        """
        pass

    def parse(
        self,
        file_path: Path,
        custody_ledger: Optional[ChainOfCustodyLedger] = None,
        actor: str = "forensic_analyst",
    ) -> list[NormalizedEvent]:
        """Public entrypoint for parsing evidence.

        1. Validates file existence.
        2. Computes dual cryptographic digests (SHA-256 and BLAKE3).
        3. Appends an immutable 'PARSE' entry to the custody ledger (if provided).
        4. Invokes subclass parse_records with the verified source hash.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        sha256_hex, blake3_hex = hash_file(path)

        if custody_ledger is not None:
            custody_ledger.record(
                actor=actor,
                action="PARSE",
                target_path=str(path),
                notes=f"Parsed via {self.parser_name}",
                hash_target=True,
            )

        return self.parse_records(file_path=path, file_sha256=sha256_hex)


# ============================================================================
# Plugin Registry
# ============================================================================

_PARSER_REGISTRY: list[Type[BaseParser]] = []


def register_parser(parser_cls: Type[BaseParser]) -> Type[BaseParser]:
    """Decorator or function to register a parser plugin."""
    if parser_cls not in _PARSER_REGISTRY:
        _PARSER_REGISTRY.append(parser_cls)
    return parser_cls


def get_parser_for_file(file_path: Path) -> Optional[BaseParser]:
    """Find the first registered parser capable of parsing the given file."""
    for parser_cls in _PARSER_REGISTRY:
        parser = parser_cls()
        try:
            if parser.can_parse(file_path):
                return parser
        except Exception:
            continue
    return None


def list_registered_parsers() -> list[str]:
    """List names of all registered parser plugins."""
    return [cls().parser_name for cls in _PARSER_REGISTRY]
