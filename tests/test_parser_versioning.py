"""
tests/test_parser_versioning.py

Tests that all registered forensic parser plugins declare explicit semantic versioning
attributes (parser_version) for forensic reproducibility and ISO/IEC 27037 auditability.
"""

from parsers.base import _PARSER_REGISTRY, BaseParser
import parsers  # Ensures all 10 parsers are imported and registered


def test_all_parsers_have_semantic_version():
    assert len(_PARSER_REGISTRY) >= 10, f"Expected at least 10 registered parsers, found {len(_PARSER_REGISTRY)}"

    for parser_cls in _PARSER_REGISTRY:
        parser = parser_cls()
        assert isinstance(parser, BaseParser)
        assert hasattr(parser, "parser_version"), f"{parser_cls.__name__} missing parser_version"
        assert isinstance(parser.parser_version, str)
        assert len(parser.parser_version.split(".")) >= 3, f"{parser_cls.__name__} parser_version '{parser.parser_version}' is not valid SemVer"
        assert parser.parser_version == "1.0.0"
