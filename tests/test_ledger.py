import json

from custody.ledger import ChainOfCustodyLedger, hash_file


def test_record_and_verify_clean_chain(tmp_path):
    evidence = tmp_path / "flight1.bin"
    evidence.write_bytes(b"fake flight controller dump")
    ledger = ChainOfCustodyLedger(tmp_path / "custody.jsonl")

    ledger.record(actor="investigator_1", action="ACQUIRE", target_path=evidence)
    ledger.record(
        actor="investigator_1",
        action="HASH_VERIFY",
        target_path=evidence,
        notes="pre-analysis re-hash",
    )

    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None
    assert len(ledger) == 2


def test_recorded_hash_matches_independent_hash(tmp_path):
    evidence = tmp_path / "flight1.bin"
    evidence.write_bytes(b"fake flight controller dump")
    ledger = ChainOfCustodyLedger(tmp_path / "custody.jsonl")
    entry = ledger.record(actor="investigator_1", action="ACQUIRE", target_path=evidence)

    expected_sha256, expected_blake3 = hash_file(evidence)
    assert entry.target_sha256 == expected_sha256
    assert entry.target_blake3 == expected_blake3


def test_tampering_with_ledger_is_detected(tmp_path):
    evidence = tmp_path / "flight1.bin"
    evidence.write_bytes(b"fake flight controller dump")
    ledger_path = tmp_path / "custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    ledger.record(actor="investigator_1", action="ACQUIRE", target_path=evidence)
    ledger.record(actor="investigator_1", action="PARSE", target_path=evidence)
    ledger.record(actor="investigator_1", action="EXPORT", target_path=evidence)

    # Simulate an insider quietly editing the middle entry's actor field.
    lines = ledger_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["actor"] = "someone_else"
    lines[1] = json.dumps(tampered, sort_keys=True)
    ledger_path.write_text("\n".join(lines) + "\n")

    reloaded = ChainOfCustodyLedger(ledger_path)
    ok, broken_at = reloaded.verify_chain()
    assert ok is False
    assert broken_at == 1


def test_missing_ledger_starts_clean(tmp_path):
    ledger = ChainOfCustodyLedger(tmp_path / "does_not_exist_yet.jsonl")
    assert len(ledger) == 0
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None
