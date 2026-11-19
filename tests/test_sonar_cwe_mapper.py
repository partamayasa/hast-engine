# tests/test_sonar_cwe_mapper.py
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from backend.services.parsers.sonar_cwe_mapper import (
    extract_metadata_from_rule_payload,
    fetch_sonar_rule_metadata,
    load_sonar_cwe_mappings,
    save_sonar_rule_to_cache,
    convert_sonar_report,
    resolve_sonar_cwe,
    pick_primary_cwe,
)


def test_extract_metadata_from_rule_payload():
    """Menguji ekstraksi CWE dan OWASP dari payload resmi API SonarQube."""
    mock_rule = {
        "name": "SQL Injection in Query",
        "type": "VULNERABILITY",
        "severity": "CRITICAL",
        "descriptionSections": [
            {
                "key": "resources",
                "content": "<p>See <a href='https://cwe.mitre.org/data/definitions/89.html'>CWE-89</a></p><p>OWASP Top 10 2021 Category A03</p>"
            }
        ],
        "sysTags": ["cwe-89", "sql"],
        "tags": ["owasp-a3"]
    }

    meta = extract_metadata_from_rule_payload(mock_rule, rule_key="php:S3649")
    assert meta["rule_key"] == "php:S3649"
    assert meta["name"] == "SQL Injection in Query"
    assert "CWE-89" in meta["cwe"]
    assert any("A03" in o for o in meta["owasp"])


def test_resolve_sonar_cwe_priorities():
    """Menguji hierarki prioritas pemetaan CWE ID pada objek issue."""
    # Prioritas 0: issue sudah diperkaya dengan properti 'cwe' hasil konversi
    issue_with_cwe = {
        "rule": "php:S1234",
        "cwe": ["CWE-1004", "CWE-614"],
        "tags": ["cookie"]
    }
    cwe_val, has_tag = resolve_sonar_cwe(issue_with_cwe)
    assert cwe_val == "CWE-1004"
    assert has_tag is True

    # Prioritas 1: tag cwe-\d+ pada issue
    issue_with_tag = {
        "rule": "php:S9999",
        "tags": ["cwe-79", "security"]
    }
    cwe_val, has_tag = resolve_sonar_cwe(issue_with_tag)
    assert cwe_val == "CWE-79"
    assert has_tag is True

    # Prioritas 2: nama rule langsung memuat cwe-\d+
    issue_with_rule_cwe = {
        "rule": "php:CWE-352",
        "tags": ["web"]
    }
    cwe_val, has_tag = resolve_sonar_cwe(issue_with_rule_cwe)
    assert cwe_val == "CWE-352"
    assert has_tag is True

    # Prioritas 3: rule cocok dengan cache / pemetaan (mis. S3649 -> CWE-89)
    save_sonar_rule_to_cache("php:S3649", {"cwe": ["CWE-89"], "owasp": ["Top 10 2021 Category A3"]})
    issue_with_known_rule = {
        "rule": "php:S3649",
        "tags": []
    }
    cwe_val, has_tag = resolve_sonar_cwe(issue_with_known_rule)
    assert cwe_val == "CWE-89"
    assert has_tag is True


def test_convert_sonar_report_enrichment():
    """Menguji pengayaan berkas laporan SonarQube dengan CWE-ID dan OWASP."""
    sample_report = {
        "issues": [
            {
                "key": "issue-1",
                "rule": "php:CWE-89",
                "type": "VULNERABILITY",
                "message": "SQL Injection found",
                "tags": ["cwe-89"]
            },
            {
                "key": "issue-2",
                "rule": "php:S3649",
                "type": "VULNERABILITY",
                "message": "Raw SQL concatenation",
                "tags": []
            },
            {
                "key": "issue-3",
                "rule": "php:S1135",
                "type": "CODE_SMELL",
                "message": "TODO comment found",
                "tags": []
            }
        ]
    }

    enriched, stats = convert_sonar_report(sample_report)
    assert stats["total_issues"] == 3
    assert stats["cwe_mapped_count"] >= 2
    assert "CWE-89" in stats["cwe_distribution"]

    # Pastikan properti cwe dan owasp ditambahkan ke setiap issue
    for issue in enriched["issues"]:
        assert "cwe" in issue
        assert "owasp" in issue
        assert isinstance(issue["cwe"], list)


@patch("requests.get")
def test_fetch_sonar_rule_metadata_mocked(mock_get):
    """Menguji pemanggilan API SonarQube dengan respons tiruan (mock)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "rule": {
            "name": "Hardcoded credentials",
            "type": "VULNERABILITY",
            "severity": "CRITICAL",
            "descriptionSections": [
                {
                    "key": "resources",
                    "content": "<p>CWE-798: Use of Hard-coded Credentials</p>"
                }
            ],
            "sysTags": ["cwe-798"],
            "tags": []
        }
    }
    mock_get.return_value = mock_resp

    meta = fetch_sonar_rule_metadata("php:S7980", sonar_host="https://mock-sonar.test", token="dummy-token")
    assert meta["name"] == "Hardcoded credentials"
    assert "CWE-798" in meta["cwe"]


def test_pick_primary_cwe_priorities():
    """Menguji pemilihan CWE spesifik dibanding CWE payung / generik."""
    # php:S2092 memiliki CWE-311, CWE-315, CWE-614. CWE-614 harus dipilih
    assert pick_primary_cwe(["CWE-311", "CWE-315", "CWE-614"]) == "CWE-614"
    # php:S2612 memiliki CWE-266, CWE-732. CWE-732 harus dipilih
    assert pick_primary_cwe(["CWE-266", "CWE-732"]) == "CWE-732"
    # CWE tunggal
    assert pick_primary_cwe(["CWE-1004"]) == "CWE-1004"
    # Masukan berupa string
    assert pick_primary_cwe("CWE-89") == "CWE-89"
    # Kosong
    assert pick_primary_cwe([]) == "N/A"


def test_rule_s2092_resolves_to_cwe_614():
    """Memastikan aturan cookie S2092 terpetakan ke CWE-614 agar beririsan dengan DAST ZAP."""
    mappings = load_sonar_cwe_mappings(force_reload=True)
    assert mappings.get("php:S2092") == "CWE-614"
    assert mappings.get("S2092") == "CWE-614"

