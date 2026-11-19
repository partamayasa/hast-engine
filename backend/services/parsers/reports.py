# backend/services/parsers/reports.py
"""
Parser laporan pemindai (dipindah dari frontend/components/tab_sast.py dan tab_dast.py).

Aturan penyaringan tidak berubah dari v1.0.0-tesis dan dikunci oleh
tests/test_regression_golden.py.
"""
import json
import re

from backend.services.parsers.sonar_cwe_mapper import load_sonar_cwe_mappings, resolve_sonar_cwe


class ReportParseError(ValueError):
    pass


def decode_report(raw_bytes: bytes) -> dict | list:
    try:
        content = raw_bytes.decode("utf-8-sig")
    except Exception:
        content = raw_bytes.decode("utf-8", errors="replace")
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReportParseError(f"File bukan JSON yang valid: {exc}") from exc


def parse_sonarqube(raw_json, sonar_host: str = "", token: str = "", auto_fetch: bool = False) -> list[dict]:
    if not isinstance(raw_json, (dict, list)):
        raise ReportParseError("Struktur laporan SonarQube tidak dikenali.")
    issues_list = raw_json.get("issues", []) if isinstance(raw_json, dict) else raw_json
    known_mappings = load_sonar_cwe_mappings()
    records = []
    for i in issues_list:
        issue_type = i.get("type", "").upper()
        tags = [str(t) for t in i.get("tags", [])]
        rule = str(i.get("rule", ""))
        rule_m = re.search(r"S\d+", rule)
        rule_short = rule_m.group(0) if rule_m else ""

        # Lewati code smell non-keamanan, tetapi pertahankan kelemahan yang terkait CWE (mis. Web:S6819 -> CWE-693)
        has_cwe_indication = (
            bool(i.get("cwe"))
            or issue_type == "VULNERABILITY"
            or any("cwe" in t.lower() for t in tags)
            or "cwe" in rule.lower()
            or rule in known_mappings
            or (rule_short and rule_short in known_mappings)
        )
        if not has_cwe_indication:
            continue

        cwe_value, has_cwe = resolve_sonar_cwe(i, sonar_host=sonar_host, token=token, auto_fetch=auto_fetch)
        # Hanya temuan VULNERABILITY atau item yang terpetakan ke CWE valid yang merupakan insiden keamanan
        if issue_type != "VULNERABILITY" and (not has_cwe or cwe_value == "N/A"):
            continue

        records.append({
            "key_id": i.get("key", "N/A"),
            "cwe_id": cwe_value,
            "component": i.get("component", "N/A"),
            "issue_description": i.get("message", ""),
            "issue_type": issue_type,
            "has_cwe_tag": has_cwe,
            "comment_solution": "",
        })
    return records


def _clean_html(value) -> str:
    text = re.sub(r"<[^>]*>", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()


def parse_zap(raw_json, unprocessing_domains: list[str] | None = None) -> list[dict]:
    if not isinstance(raw_json, dict):
        raise ReportParseError("Struktur laporan OWASP ZAP tidak dikenali.")
    unprocessing_domains = unprocessing_domains or []
    site_data = raw_json.get("site", [])
    sites = site_data if isinstance(site_data, list) else [site_data]
    records = []
    for site in sites:
        for alert in site.get("alerts", []):
            cwe_id_raw = str(alert.get("cweid", "")).strip()
            cwe_value = f"CWE-{cwe_id_raw}" if cwe_id_raw and cwe_id_raw not in ["-1", "0"] else "N/A"
            instances = alert.get("instances", [])
            if instances and isinstance(instances, list):
                first = instances[0]
                uri_target = first.get("uri", first.get("url", "N/A"))
                method_target = first.get("method", "").strip()
                url_component = f"{method_target} {uri_target}".strip() if method_target else uri_target
            else:
                url_component = alert.get("url", "N/A")

            if unprocessing_domains and any(
                d.strip().lower() in str(url_component).lower() for d in unprocessing_domains
            ):
                continue

            records.append({
                "key_id": alert.get("alert", "N/A"),
                "cwe_id": cwe_value,
                "component": url_component,
                "issue_description": _clean_html(alert.get("desc", "")),
                "comment_solution": _clean_html(alert.get("solution", "")),
            })
    return records
