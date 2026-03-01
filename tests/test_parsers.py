"""Parser tests: SARIF and Snyk -> UnifiedFinding."""

from pathlib import Path

import pytest

from vulnsift.models import UnifiedFinding
from vulnsift.parsers import parse_sarif, parse_scan_file, parse_snyk


def test_parse_sarif(sample_sarif_path: Path) -> None:
    findings = parse_sarif(sample_sarif_path)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, UnifiedFinding)
    assert f.rule_id == "SQLi"
    assert "SQL" in f.title or "injection" in f.title.lower()
    assert f.source_format == "sarif"
    assert f.location.file_path == "src/app.py"
    assert f.location.start_line == 42
    assert "execute" in (f.location.snippet or "")


def test_parse_snyk(sample_snyk_path: Path) -> None:
    findings = parse_snyk(sample_snyk_path)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, UnifiedFinding)
    assert "lodash" in f.title.lower() or "lodash" in f.message.lower()
    assert f.severity == "high"
    assert f.cve == "CVE-2020-8203"
    assert f.source_format == "snyk"


def test_parse_scan_file_sarif(sample_sarif_path: Path) -> None:
    findings = parse_scan_file(sample_sarif_path, "sarif")
    assert len(findings) >= 1
    assert all(isinstance(x, UnifiedFinding) for x in findings)


def test_parse_scan_file_snyk(sample_snyk_path: Path) -> None:
    findings = parse_scan_file(sample_snyk_path, "snyk")
    assert len(findings) >= 1
    assert all(isinstance(x, UnifiedFinding) for x in findings)


def test_parse_scan_file_unsupported_format(sample_sarif_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported format"):
        parse_scan_file(sample_sarif_path, "unknown")


def test_parse_sarif_missing_file() -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        parse_sarif("/nonexistent/file.sarif")


def test_parse_sarif_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json")
    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_sarif(bad)


def test_parse_sarif_empty_runs(tmp_path: Path) -> None:
    import json

    from vulnsift.parsers.sarif import parse_sarif
    path = tmp_path / "empty.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    findings = parse_sarif(path)
    assert findings == []
