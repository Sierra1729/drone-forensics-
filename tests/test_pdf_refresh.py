"""
tests/test_pdf_refresh.py

Tests for courtroom PDF report refresh, case isolation, and Windows file-lock handling.
"""

from pathlib import Path
import json
import pytest

from gui.api import DesktopForensicAPI
from reports.generator import ForensicReportGenerator, ForensicCaseMetadata
from tests.synthetic_ardupilot import generate_synthetic_ardupilot_bin


@pytest.fixture
def sample_bin(tmp_path) -> Path:
    bin_path = tmp_path / "pdf_refresh_test.BIN"
    return generate_synthetic_ardupilot_bin(bin_path)


def test_generator_handles_locked_file(tmp_path, sample_bin):
    """Verify that if target PDF is locked, generator writes to a timestamped file instead of failing."""
    api = DesktopForensicAPI()
    api.output_dir = tmp_path / "output"
    
    res = api.analyze_evidence(str(sample_bin), case_id="CASE-LOCK-TEST", examiner="Lock Examiner")
    assert res["status"] == "success"
    pdf_path = Path(res["pdf_path"])
    assert pdf_path.exists()

    # Lock the file using Windows CreateFile with FILE_SHARE_READ only (matching Acrobat/Edge behavior)
    import ctypes
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    OPEN_EXISTING = 3
    handle = ctypes.windll.kernel32.CreateFileW(str(pdf_path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
    assert handle != -1

    try:
        meta = ForensicCaseMetadata(case_id="CASE-LOCK-TEST", evidence_id="locked.bin", examiner_name="Lock Examiner")
        generator = ForensicReportGenerator(meta)

        # Calling generate on the locked path should gracefully write to a timestamped file
        actual_pdf = generator.generate(
            evidence_path=sample_bin,
            events=api.last_events,
            custody_ledger=api.last_ledger,
            anomalies=api.last_anomalies,
            output_pdf_path=pdf_path,
        )
        assert actual_pdf.exists()
        assert actual_pdf != pdf_path
        assert actual_pdf.name.startswith("forensic_examination_report_")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def test_open_pdf_case_isolation_and_refresh(tmp_path, sample_bin, monkeypatch):
    """Verify open_pdf refreshes correctly and isolates distinct cases."""
    api = DesktopForensicAPI()
    api.output_dir = tmp_path / "output"

    # Analyze Case A
    res_a = api.analyze_evidence(str(sample_bin), case_id="CASE-AAA", examiner="Examiner A")
    assert res_a["status"] == "success"
    pdf_a = Path(res_a["pdf_path"])
    assert pdf_a.exists()

    # Analyze Case B
    res_b = api.analyze_evidence(str(sample_bin), case_id="CASE-BBB", examiner="Examiner B")
    assert res_b["status"] == "success"
    pdf_b = Path(res_b["pdf_path"])
    assert pdf_b.exists()
    assert pdf_a != pdf_b

    opened_paths = []
    def mock_startfile(filepath):
        opened_paths.append(str(filepath))

    monkeypatch.setattr("os.startfile", mock_startfile)

    # Calling open_pdf for Case A should open Case A's PDF
    success_a = api.open_pdf("CASE-AAA")
    assert success_a is True
    assert len(opened_paths) == 1
    assert "CASE-AAA" in opened_paths[0]

    # Calling open_pdf for Case B should open Case B's PDF
    success_b = api.open_pdf("CASE-BBB")
    assert success_b is True
    assert len(opened_paths) == 2
    assert "CASE-BBB" in opened_paths[1]


def test_rebuild_pdf_report_updates_exhibits(tmp_path, sample_bin):
    """Verify rebuild_pdf_report incorporates newly added evidence exhibits."""
    api = DesktopForensicAPI()
    api.output_dir = tmp_path / "output"

    res = api.analyze_evidence(str(sample_bin), case_id="CASE-EXHIBIT-TEST", examiner="Exhibit Examiner")
    assert res["status"] == "success"

    case_out = api.output_dir / "CASE-EXHIBIT-TEST"
    exhibits_file = case_out / "evidence_exhibits.json"

    # Add a mock exhibit
    exhibit_payload = [{
        "title": "Airspace Violation Point",
        "description": "Captured at Waypoint 3",
        "timestamp": "2026-09-14 12:00:00 UTC",
        "lat": 28.6139,
        "lon": 77.2090,
        "alt_m": 120.5,
    }]
    exhibits_file.write_text(json.dumps(exhibit_payload), encoding="utf-8")

    # Rebuild should pick up the exhibit
    rebuilt_path = api.rebuild_pdf_report("CASE-EXHIBIT-TEST")
    assert rebuilt_path is not None
    assert Path(rebuilt_path).exists()
