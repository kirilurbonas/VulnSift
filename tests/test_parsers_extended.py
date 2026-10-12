"""Extended parser tests: real-world SARIF (Semgrep/CodeQL), Snyk multi-project, Trivy full, Semgrep, detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vulnsift.parsers import (
    SUPPORTED_FORMATS,
    detect_format,
    parse_sarif,
    parse_scan_file,
    parse_semgrep,
    parse_snyk,
    parse_trivy,
)
from vulnsift.parsers._common import extract_cves, extract_cwes, normalize_cwe, severity_from_cvss

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _write(tmp_path: Path, name: str, data: Any) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return p


def _sarif(results: list, rules: list | None = None, **run_extra: Any) -> dict:
    run = {"tool": {"driver": {"name": "T", "rules": rules or []}}, "results": results, **run_extra}
    return {"version": "2.1.0", "runs": [run]}


def _ploc(uri: str | None = None, line: int | None = 1, **art: Any) -> dict:
    artifact = dict(art)
    if uri is not None:
        artifact["uri"] = uri
    region = {"startLine": line} if line is not None else {}
    return {"physicalLocation": {"artifactLocation": artifact, "region": region}}


# --------------------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("external/cwe/cwe-079", "CWE-79"),
        ("CWE-89: Improper Neutralization of Special Elements", "CWE-89"),
        ("cwe-022", "CWE-22"),
        (502, "CWE-502"),
        ("security", None),
        (None, None),
    ],
)
def test_normalize_cwe(value: Any, expected: str | None) -> None:
    assert normalize_cwe(value) == expected


def test_extract_cwes_and_cves_dedupe() -> None:
    assert extract_cwes(["external/cwe/cwe-079", ["CWE-79", "CWE-116"], None]) == ["CWE-79", "CWE-116"]
    assert extract_cves(["see cve-2021-44228 and CVE-2021-44228", "CVE-2022-0001", None]) == [
        "CVE-2021-44228",
        "CVE-2022-0001",
    ]


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("9.8", "critical"),
        (9.0, "critical"),
        ("7.5", "high"),
        (7, "high"),
        ("4.0", "medium"),
        ("3.9", "low"),
        ("0", "low"),
        ("n/a", None),
        (None, None),
    ],
)
def test_severity_from_cvss(score: Any, expected: str | None) -> None:
    assert severity_from_cvss(score) == expected


# --------------------------------------------------------------------------- SARIF: Semgrep fixture


@pytest.fixture
def semgrep_sarif() -> list:
    return parse_sarif(FIXTURES / "semgrep.sarif.json")


def test_semgrep_sarif_file_paths_from_artifact_uri(semgrep_sarif: list) -> None:
    paths = [f.location.file_path for f in semgrep_sarif]
    # Absolute %SRCROOT% base is not prepended: repo-relative paths stay relative; %20 is decoded.
    assert paths == ["app/views.py", "app/db/reports.py", "web/src/sandbox utils.js"]


def test_semgrep_sarif_security_severity_precedence(semgrep_sarif: list) -> None:
    sqli, formatted, vm = semgrep_sarif
    assert sqli.severity == "critical"  # 9.8 wins over defaultConfiguration error
    assert formatted.severity == "warning"  # no security-severity, no level -> rule defaultConfiguration
    assert vm.severity == "medium"  # 5.3


def test_semgrep_sarif_cwe_cve_and_text(semgrep_sarif: list) -> None:
    sqli, formatted, vm = semgrep_sarif
    assert sqli.cwe == "CWE-89"
    assert formatted.cwe == "CWE-89"
    assert vm.cwe == "CWE-94"
    assert vm.cve == "CVE-2023-37466"
    assert sqli.cve is None
    # Placeholder "Semgrep Finding: ..." shortDescription replaced by the message
    assert not sqli.title.startswith("Semgrep Finding")
    assert "SQL injection" in sqli.title
    assert "parameterized" in sqli.description  # rule.help appended
    assert sqli.raw["references"] == [
        "https://semgrep.dev/r/python.django.security.injection.sql.sql-injection-using-raw"
    ]
    assert sqli.raw["tool_name"] == "Semgrep OSS"


def test_semgrep_sarif_snippets_and_lines(semgrep_sarif: list) -> None:
    sqli, formatted, vm = semgrep_sarif
    assert sqli.location.start_line == 27 and sqli.location.end_line == 28
    assert "objects.raw" in sqli.location.snippet
    assert "cur.execute" in formatted.location.snippet  # from contextRegion
    assert formatted.location.start_line == 112
    assert vm.location.snippet is None
    assert vm.location.end_line == 14  # endLine defaults to startLine


def test_semgrep_sarif_ids_stable_and_unique(semgrep_sarif: list) -> None:
    again = parse_sarif(FIXTURES / "semgrep.sarif.json")
    assert [f.id for f in semgrep_sarif] == [f.id for f in again]
    assert len({f.id for f in semgrep_sarif}) == len(semgrep_sarif)


# --------------------------------------------------------------------------- SARIF: CodeQL fixture


@pytest.fixture
def codeql_sarif() -> list:
    return parse_sarif(FIXTURES / "codeql.sarif.json")


def test_codeql_rules_from_extensions(codeql_sarif: list) -> None:
    assert len(codeql_sarif) == 3  # second run is empty
    xss, path_inj, unused = codeql_sarif
    assert xss.rule_id == "js/xss"
    assert xss.title == "Client-side cross-site scripting"
    assert xss.cwe == "CWE-79"
    assert xss.raw["cwes"] == ["CWE-79", "CWE-116"]
    assert xss.severity == "high"
    assert "Directly writing user input" in xss.description
    # result had no ruleId: resolved via rule.id / rule.index + toolComponent
    assert path_inj.rule_id == "js/path-injection"
    assert path_inj.cwe == "CWE-22"
    assert unused.severity == "note"  # rule defaultConfiguration.level
    assert unused.cwe is None


def test_codeql_artifact_index_and_context_snippet(codeql_sarif: list) -> None:
    xss, path_inj, unused = codeql_sarif
    assert xss.location.file_path == "src/client/render.js"
    assert path_inj.location.file_path == "src/server/files.js"  # only artifactLocation.index given
    assert "sendFile" in path_inj.location.snippet
    assert unused.location.file_path == "src/server/util.js"


def test_codeql_same_line_hash_different_files_get_distinct_ids(codeql_sarif: list) -> None:
    _, path_inj, unused = codeql_sarif
    assert path_inj.raw["partialFingerprints"] == unused.raw["partialFingerprints"]
    assert path_inj.id != unused.id
    assert path_inj.id.startswith("sarif_js_path-injection_")


# --------------------------------------------------------------------------- SARIF: edge cases


def test_sarif_file_uri_and_relative_base(tmp_path: Path) -> None:
    data = _sarif(
        [
            {"ruleId": "r", "message": {"text": "a"}, "locations": [_ploc("file:///home/ci/repo/src/a.py")]},
            {"ruleId": "r", "message": {"text": "b"}, "locations": [_ploc("b.py", uriBaseId="SRC")]},
            {"ruleId": "r", "message": {"text": "c"}, "locations": [_ploc("./c.py")]},
            {"ruleId": "r", "message": {"text": "d"}, "locations": [_ploc("file:///C:/work/d.py")]},
            {"ruleId": "r", "message": {"text": "e"}, "locations": [_ploc("e.py", uriBaseId="UNKNOWN")]},
        ],
        originalUriBaseIds={"SRC": {"uri": "src/", "uriBaseId": "ROOT"}, "ROOT": {"uri": "file:///repo/"}},
    )
    findings = parse_sarif(_write(tmp_path, "x.sarif", data))
    assert [f.location.file_path for f in findings] == [
        "/home/ci/repo/src/a.py",
        "src/b.py",
        "c.py",
        "C:/work/d.py",
        "e.py",
    ]


def test_sarif_rule_index_without_rule_id(tmp_path: Path) -> None:
    rules = [
        {"id": "R0"},
        {"id": "R1", "shortDescription": {"text": "Second rule"}, "properties": {"tags": ["CWE-352"]}},
    ]
    data = _sarif([{"ruleIndex": 1, "message": {"text": "m"}, "locations": [_ploc("x.py")]}], rules)
    (f,) = parse_sarif(_write(tmp_path, "x.sarif", data))
    assert f.rule_id == "R1"
    assert f.title == "Second rule"
    assert f.cwe == "CWE-352"


def test_sarif_level_overrides_default_and_result_security_severity(tmp_path: Path) -> None:
    rules = [{"id": "R", "defaultConfiguration": {"level": "error"}}]
    data = _sarif(
        [
            {"ruleId": "R", "level": "note", "message": {"text": "a"}},
            {"ruleId": "R", "message": {"text": "b"}, "properties": {"security-severity": "8.1"}},
            {"ruleId": "R", "message": {"text": "c"}, "properties": {"security-severity": "garbage"}},
            {"ruleId": "UNKNOWN", "message": {"text": "d"}},
        ],
        rules,
    )
    assert [f.severity for f in parse_sarif(_write(tmp_path, "x.sarif", data))] == ["note", "high", "error", "warning"]


def test_sarif_missing_locations_and_null_fields(tmp_path: Path) -> None:
    data = _sarif(
        [
            {"ruleId": "R", "message": {"text": "no location"}},
            {"ruleId": "R", "message": {"text": "empty"}, "locations": []},
            {"ruleId": "R", "message": {"text": "nulls"}, "locations": [{"physicalLocation": None}]},
            {"ruleId": "R", "message": {"text": "noregion"}, "locations": [_ploc("a.py", line=None)]},
        ]
    )
    findings = parse_sarif(_write(tmp_path, "x.sarif", data))
    assert len(findings) == 4
    assert findings[0].location.file_path == "" and findings[0].location.start_line is None
    assert findings[3].location.file_path == "a.py" and findings[3].location.start_line is None
    assert len({f.id for f in findings}) == 4


@pytest.mark.parametrize("runs", [[], None, [{"results": None}], [{"tool": None, "results": []}], ["junk"]])
def test_sarif_empty_or_null_runs(tmp_path: Path, runs: Any) -> None:
    assert parse_sarif(_write(tmp_path, "x.sarif", {"version": "2.1.0", "runs": runs})) == []


def test_sarif_skips_pass_results_and_handles_multiple_runs(tmp_path: Path) -> None:
    run1 = {
        "tool": {"driver": {"name": "A"}},
        "results": [
            {"ruleId": "a", "kind": "pass", "message": {"text": "x"}},
            {"ruleId": "a", "message": {"text": "y"}},
        ],
    }
    run2 = {"tool": {"driver": {"name": "B"}}, "results": [{"ruleId": "b", "message": {"text": "z"}}]}
    findings = parse_sarif(_write(tmp_path, "x.sarif", {"version": "2.1.0", "runs": [run1, run2]}))
    assert [(f.rule_id, f.raw["tool_name"]) for f in findings] == [("a", "A"), ("b", "B")]


def test_sarif_cve_from_message_and_rule_id(tmp_path: Path) -> None:
    data = _sarif(
        [
            {"ruleId": "R", "message": {"text": "log4j CVE-2021-44228 reachable"}},
            {"ruleId": "CVE-2022-22965", "message": {"text": "spring4shell"}},
        ]
    )
    a, b = parse_sarif(_write(tmp_path, "x.sarif", data))
    assert a.cve == "CVE-2021-44228"
    assert b.cve == "CVE-2022-22965"


def test_sarif_message_strings_and_hierarchical_rule_id(tmp_path: Path) -> None:
    rules = [
        {
            "id": "CA2101",
            "shortDescription": {"text": "Marshal strings"},
            "messageStrings": {"default": {"text": "Call {0} with {1}"}},
        }
    ]
    data = _sarif([{"ruleId": "CA2101/1", "message": {"id": "default", "arguments": ["Foo", "Bar"]}}], rules)
    (f,) = parse_sarif(_write(tmp_path, "x.sarif", data))
    assert f.message == "Call Foo with Bar"
    assert f.title == "Marshal strings"
    assert f.rule_id == "CA2101/1"


def test_sarif_fingerprint_id_survives_line_shift(tmp_path: Path) -> None:
    def make(line: int) -> list:
        res = {
            "ruleId": "R",
            "message": {"text": "m"},
            "locations": [_ploc("a.py", line=line)],
            "fingerprints": {"matchBasedId/v1": "abc"},
        }
        return parse_sarif(_write(tmp_path, f"x{line}.sarif", _sarif([res])))

    assert make(10)[0].id == make(25)[0].id


def test_sarif_composite_id_deterministic_and_duplicates_unique(tmp_path: Path) -> None:
    res = {"ruleId": "R", "message": {"text": "m"}, "locations": [_ploc("a.py", line=3)]}
    p = _write(tmp_path, "x.sarif", _sarif([res, res]))
    first = [f.id for f in parse_sarif(p)]
    assert first == [f.id for f in parse_sarif(p)]
    assert first[1] == first[0] + "_2"


def test_sarif_legacy_artifact_index_on_physical_location(sample_sarif_path: Path) -> None:
    (f,) = parse_sarif(sample_sarif_path)
    assert f.location.file_path == "src/app.py"
    assert f.severity == "error"


def test_sarif_unsupported_version(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported SARIF version"):
        parse_sarif(_write(tmp_path, "x.sarif", {"version": "1.0.0", "runs": []}))


# --------------------------------------------------------------------------- Snyk


@pytest.fixture
def snyk_multi() -> list:
    return parse_snyk(FIXTURES / "snyk-multi.json")


def test_snyk_multi_project_list(snyk_multi: list) -> None:
    assert [f.rule_id for f in snyk_multi] == [
        "SNYK-JS-LODASH-567746",
        "SNYK-JS-MINIMIST-2429795",
        "SNYK-PYTHON-JINJA2-6150717",
    ]
    assert [f.location.file_path for f in snyk_multi] == [
        "web/package-lock.json",
        "web/package-lock.json",
        "api/requirements.txt",  # targetFile fallback
    ]
    assert len({f.id for f in snyk_multi}) == 3


def test_snyk_dedupes_dependency_paths(snyk_multi: list) -> None:
    lodash = snyk_multi[0]
    assert lodash.raw["occurrences"] == 2
    assert len(lodash.raw["paths"]) == 2
    assert "web-app@1.0.0 > lodash@4.17.15" in lodash.message
    assert "webpack-dev-server@3.11.0 > http-proxy-middleware@0.19.1 > lodash@4.17.15" in lodash.message
    assert "lodash@4.17.15" in lodash.message
    assert lodash.location.region == "web-app@1.0.0 > lodash@4.17.15"


def test_snyk_identifiers_fix_and_references(snyk_multi: list) -> None:
    lodash, minimist, jinja = snyk_multi
    assert (lodash.cve, lodash.cwe) == ("CVE-2020-8203", "CWE-1321")
    assert (jinja.cve, jinja.cwe) == ("CVE-2024-22195", "CWE-79")
    assert "Fixed in: 4.17.16" in lodash.description
    assert "Upgrade path: lodash@4.17.16" in lodash.description
    assert lodash.raw["upgrade_paths"][1] == "webpack-dev-server@4.0.0 > http-proxy-middleware@1.0.0 > lodash@4.17.16"
    assert lodash.raw["references"] == [
        "https://github.com/lodash/lodash/pull/4759",
        "https://hackerone.com/reports/712065",
    ]
    assert "Fixed in: 1.2.6" in minimist.description
    assert lodash.raw["project_name"] == "web-app"


def test_snyk_target_file_precedence(tmp_path: Path) -> None:
    vuln = {"id": "SNYK-1", "title": "T", "severity": "low", "packageName": "p", "version": "1", "package": "bogus"}
    cases = [
        ({"displayTargetFile": "a/package.json", "targetFile": "b", "path": "/c"}, "a/package.json"),
        ({"targetFile": "b/pom.xml", "path": "/c"}, "b/pom.xml"),
        ({"path": "/repo"}, "/repo"),
        ({}, ""),
    ]
    for i, (extra, expected) in enumerate(cases):
        (f,) = parse_snyk(_write(tmp_path, f"s{i}.json", {"vulnerabilities": [vuln], **extra}))
        assert f.location.file_path == expected


def test_snyk_same_vuln_different_versions_not_merged(tmp_path: Path) -> None:
    base = {"id": "SNYK-1", "title": "T", "severity": "high", "packageName": "p"}
    data = {"vulnerabilities": [{**base, "version": "1.0"}, {**base, "version": "2.0"}, {**base, "version": "1.0"}]}
    findings = parse_snyk(_write(tmp_path, "s.json", data))
    assert [f.raw["occurrences"] for f in findings] == [2, 1]


def test_snyk_same_vuln_in_two_projects_kept_separately(tmp_path: Path) -> None:
    vuln = {"id": "SNYK-1", "title": "T", "severity": "high", "packageName": "p", "version": "1"}
    data = [
        {"vulnerabilities": [vuln], "displayTargetFile": "a/package.json"},
        {"vulnerabilities": [vuln], "displayTargetFile": "b/package.json"},
    ]
    findings = parse_snyk(_write(tmp_path, "s.json", data))
    assert len(findings) == 2 and findings[0].id != findings[1].id


def test_snyk_error_and_empty(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Authentication failed"):
        parse_snyk(_write(tmp_path, "err.json", {"ok": False, "error": "Authentication failed"}))
    assert parse_snyk(_write(tmp_path, "empty.json", [])) == []
    assert parse_snyk(_write(tmp_path, "ok.json", {"ok": True, "vulnerabilities": []})) == []
    with pytest.raises(ValueError, match="Snyk root"):
        parse_snyk(_write(tmp_path, "num.json", "42"))


# --------------------------------------------------------------------------- Trivy


@pytest.fixture
def trivy_full() -> list:
    return parse_trivy(FIXTURES / "trivy-full.json")


def test_trivy_full_counts_and_targets(trivy_full: list) -> None:
    kinds = [f.raw["finding_type"] for f in trivy_full]
    assert kinds == [
        "vulnerability",
        "vulnerability",
        "misconfiguration",
        "misconfiguration",
        "misconfiguration",
        "secret",
    ]  # PASS misconfig skipped, null Vulnerabilities tolerated
    assert [f.location.file_path for f in trivy_full] == [
        "package-lock.json",
        "package-lock.json",
        "Dockerfile",
        "Dockerfile",
        "deploy/terraform/main.tf",
        "config/settings.py",
    ]
    assert len({f.id for f in trivy_full}) == len(trivy_full)


def test_trivy_vulnerability_details(trivy_full: list) -> None:
    lodash, semver = trivy_full[:2]
    assert lodash.cve == "CVE-2021-23337"
    assert lodash.cwe == "CWE-94"
    assert "lodash" in lodash.message and "4.17.15" in lodash.message and "Fixed in 4.17.21" in lodash.message
    assert lodash.raw["references"][0] == "https://avd.aquasec.com/nvd/cve-2021-23337"  # PrimaryURL first
    assert len(lodash.raw["references"]) == 3  # deduped
    assert "References:" in lodash.description
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" in lodash.raw["references"]
    assert lodash.raw["result"] == {"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm"}
    assert semver.rule_id == "GHSA-35jh-r3h4-6jhm"
    assert semver.cve == "CVE-2022-25883"  # from VendorIDs
    assert "semver@5.7.1" in semver.title
    assert "No fixed version" in semver.message


def test_trivy_misconfigurations(trivy_full: list) -> None:
    root_user, run_cd, s3 = trivy_full[2:5]
    assert root_user.rule_id == "AVD-DS-0002"
    assert root_user.location.start_line is None and root_user.location.snippet is None
    assert "Resolution: Add 'USER" in root_user.description
    assert run_cd.location.start_line == 9 and run_cd.location.snippet == "RUN cd /app && npm ci"
    assert run_cd.severity == "medium"
    assert (s3.location.start_line, s3.location.end_line) == (12, 15)
    assert 'acl    = "public-read"' in s3.location.snippet
    assert s3.location.region == "aws_s3_bucket.uploads"
    assert s3.severity == "high"


def test_trivy_secret(trivy_full: list) -> None:
    secret = trivy_full[5]
    assert secret.rule_id == "aws-access-key-id"
    assert secret.severity == "critical"
    assert secret.cwe == "CWE-798"
    assert secret.location.start_line == 22
    assert secret.location.snippet == 'AWS_ACCESS_KEY_ID = "********************"'  # only cause line, masked


@pytest.mark.parametrize(
    "data",
    [
        {"SchemaVersion": 2, "ArtifactName": "x", "Results": None},
        {"SchemaVersion": 2, "ArtifactName": "x"},
        {"Results": [{"Target": "a", "Vulnerabilities": None, "Misconfigurations": None, "Secrets": None}]},
    ],
)
def test_trivy_null_results(tmp_path: Path, data: dict) -> None:
    assert parse_trivy(_write(tmp_path, "t.json", data)) == []


def test_trivy_legacy_list_root(tmp_path: Path) -> None:
    data = [
        {
            "Target": "img (alpine 3.12)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1j",
                    "Severity": "CRITICAL",
                }
            ],
        }
    ]
    (f,) = parse_trivy(_write(tmp_path, "t.json", data))
    assert f.location.file_path == "img (alpine 3.12)"
    assert f.severity == "critical"
    assert f.title.startswith("CVE-2021-3711")


# --------------------------------------------------------------------------- Semgrep


@pytest.fixture
def semgrep_full() -> list:
    return parse_semgrep(FIXTURES / "semgrep-full.json")


def test_semgrep_severity_mapping(semgrep_full: list) -> None:
    assert [f.severity for f in semgrep_full] == ["high", "low", "medium"]
    assert [f.raw["scanner_severity"] for f in semgrep_full] == ["ERROR", "INFO", "WARNING"]


def test_semgrep_cwe_owasp_and_snippet(semgrep_full: list) -> None:
    sqli, secret, redirect = semgrep_full
    assert sqli.cwe == "CWE-89"
    assert secret.cwe == "CWE-798"  # plain string metadata.cwe
    assert redirect.cwe == "CWE-601"
    assert sqli.raw["owasp"] == ["A01:2017 - Injection", "A03:2021 - Injection"]
    assert redirect.raw["owasp"] == ["A01:2021 - Broken Access Control"]
    assert "OWASP: A01:2017" in sqli.description
    assert "Likelihood: HIGH" in sqli.description
    assert "djangoproject" in sqli.description
    assert "cursor.execute(query)" in sqli.location.snippet
    assert (sqli.location.start_line, sqli.location.end_line) == (40, 41)
    assert secret.location.snippet is None  # "requires login" placeholder dropped
    assert sqli.title == "Detected user input used to manually construct a SQL string."


def test_semgrep_fingerprint_ids(semgrep_full: list, tmp_path: Path) -> None:
    assert len({f.id for f in semgrep_full}) == 3
    data = json.loads((FIXTURES / "semgrep-full.json").read_text())
    data["results"][0]["start"]["line"] = 99  # code moved; fingerprint unchanged
    moved = parse_semgrep(_write(tmp_path, "s.json", data))
    assert moved[0].id == semgrep_full[0].id
    assert moved[0].id.startswith("semgrep_tainted-sql-string_")


def test_semgrep_new_style_severities_and_cve(tmp_path: Path) -> None:
    data = {
        "results": [
            {
                "check_id": "r",
                "path": "a",
                "extra": {"severity": "CRITICAL", "message": "m", "metadata": {"cve": ["CVE-2024-1234"]}},
            },
            {"check_id": "r2", "path": "b", "extra": None},
        ]
    }
    a, b = parse_semgrep(_write(tmp_path, "s.json", data))
    assert a.severity == "critical" and a.cve == "CVE-2024-1234"
    assert b.severity == "medium" and b.message == "r2"


# --------------------------------------------------------------------------- detection


@pytest.mark.parametrize(
    ("name", "fmt", "count"),
    [
        ("semgrep.sarif.json", "sarif", 3),
        ("codeql.sarif.json", "sarif", 3),
        ("snyk-multi.json", "snyk", 3),
        ("trivy-full.json", "trivy", 6),
        ("semgrep-full.json", "semgrep", 3),
    ],
)
def test_detect_and_parse_new_fixtures(name: str, fmt: str, count: int) -> None:
    assert detect_format(FIXTURES / name) == fmt
    findings = parse_scan_file(FIXTURES / name, "auto")
    assert len(findings) == count
    assert all(f.source_format == fmt for f in findings)


@pytest.mark.parametrize(
    ("data", "fmt"),
    [
        ({"version": "2.1.0", "runs": []}, "sarif"),
        ({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []}, "sarif"),
        ({"SchemaVersion": 2, "ArtifactName": ".", "Results": None}, "trivy"),
        ({"Results": [{"Target": "x", "Vulnerabilities": []}]}, "trivy"),
        ([{"Target": "x", "Vulnerabilities": []}], "trivy"),
        ({"results": [{"check_id": "x"}], "errors": []}, "semgrep"),
        ({"results": [], "errors": [], "paths": {"scanned": []}}, "semgrep"),
        ({"vulnerabilities": []}, "snyk"),
        ([{"vulnerabilities": []}, {"vulnerabilities": [{"id": "x"}]}], "snyk"),
        ([{"ok": True, "packageManager": "npm", "dependencyCount": 1}], "snyk"),
    ],
)
def test_detect_format_variants(tmp_path: Path, data: Any, fmt: str) -> None:
    assert detect_format(_write(tmp_path, "scan.json", data)) == fmt


@pytest.mark.parametrize("data", [{"foo": 1}, [], [1, 2], "42", {"results": [{"no": "check_id"}]}])
def test_detect_format_unknown_lists_supported(tmp_path: Path, data: Any) -> None:
    p = _write(tmp_path, "mystery.json", data)
    with pytest.raises(ValueError) as exc:
        detect_format(p)
    msg = str(exc.value)
    assert "mystery.json" in msg
    assert all(fmt in msg for fmt in SUPPORTED_FORMATS)


@pytest.mark.parametrize("content", ["not json {", ""])
def test_detect_format_invalid_json_names_file(tmp_path: Path, content: str) -> None:
    p = tmp_path / "broken.json"
    p.write_text(content)
    with pytest.raises(ValueError, match=r"Invalid JSON.*broken\.json"):
        detect_format(p)


def test_detect_format_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        detect_format(tmp_path / "nope.json")


@pytest.mark.parametrize("parser", [parse_sarif, parse_snyk, parse_semgrep, parse_trivy])
def test_parsers_invalid_json_names_file(tmp_path: Path, parser: Any) -> None:
    p = tmp_path / "garbage.json"
    p.write_text("{oops")
    with pytest.raises(ValueError, match=r"Invalid JSON.*garbage\.json"):
        parser(p)


def test_parse_scan_file_accepts_bom(tmp_path: Path) -> None:
    p = tmp_path / "bom.json"
    p.write_text("\ufeff" + json.dumps({"vulnerabilities": []}), encoding="utf-8")
    assert parse_scan_file(p, "auto") == []
