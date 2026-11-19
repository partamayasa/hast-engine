"""
Membangkitkan baseline regresi emas untuk pipeline skoring HAST.

Skrip ini adalah salinan BEKU dari perilaku sebelum refaktor (v1.0.0-tesis):
- parsing SonarQube dari frontend/components/tab_sast.py
- parsing OWASP ZAP dari frontend/components/tab_dast.py
- pra-penyaringan fast-path dari frontend/components/analysis_flow.py
- pemasangan hybrid dari frontend/components/tab_hybrid.py
- skoring melalui backend.engine (run_single_prediction / run_hybrid_prediction)

Jangan "memodernkan" berkas ini. Tujuannya mencatat bagaimana angka baseline tesis dihasilkan
agar pipeline hasil refaktor dapat dibandingkan dengannya (tests/test_regression_golden.py).

Pemakaian:
    uv run python tools/regression/generate_baseline.py
"""
import json
import os
import re
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd  # noqa: E402

OUTPUT_PATH = os.path.join(ROOT_DIR, "tests", "golden", "baseline_predictions.json")
SAMPLE_SQ = os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json")
SAMPLE_ZAP = os.path.join(ROOT_DIR, "sample-reports", "OWASP_ZAP_Report.json")
EXCLUDED_JSON_PATH = os.path.join(ROOT_DIR, "backend", "config", "excluded_domains.json")


def _read_json(path):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except Exception:
        return json.loads(raw.decode("utf-8", errors="replace"))


def parse_sonar_v1(raw_json):
    """Logika apa adanya dari tab_sast.py (v1.0.0-tesis), dengan auto_fetch=False."""
    # Modul pemeta dipindah apa adanya ke backend pada v2 (git mv); logikanya tidak berubah.
    from backend.services.parsers.sonar_cwe_mapper import resolve_sonar_cwe, load_sonar_cwe_mappings

    issues_list = raw_json.get("issues", raw_json if isinstance(raw_json, list) else [])
    known_mappings = load_sonar_cwe_mappings()
    records = []
    for i in issues_list:
        issue_type = i.get("type", "").upper()
        tags = [str(t) for t in i.get("tags", [])]
        rule = str(i.get("rule", ""))
        rule_short = ""
        rule_m = re.search(r"S\d+", rule)
        if rule_m:
            rule_short = rule_m.group(0)
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
        cwe_value, has_cwe = resolve_sonar_cwe(i, sonar_host="", token="", auto_fetch=False)
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


def parse_zap_v1(raw_json, unprocessing_domains):
    """Logika apa adanya dari tab_dast.py (v1.0.0-tesis)."""
    records = []
    site_data = raw_json.get("site", [])
    sites = site_data if isinstance(site_data, list) else [site_data]
    for site in sites:
        for alert in site.get("alerts", []):
            cwe_id_raw = str(alert.get("cweid", "")).strip()
            cwe_value = f"CWE-{cwe_id_raw}" if cwe_id_raw and cwe_id_raw not in ["-1", "0"] else "N/A"
            instances = alert.get("instances", [])
            if instances and isinstance(instances, list):
                first_instance = instances[0]
                uri_target = first_instance.get("uri", first_instance.get("url", "N/A"))
                method_target = first_instance.get("method", "").strip()
                url_component = f"{method_target} {uri_target}".strip() if method_target else uri_target
            else:
                url_component = alert.get("url", "N/A")
            if unprocessing_domains:
                if any(domain.strip().lower() in str(url_component).lower() for domain in unprocessing_domains):
                    continue
            sol_text = alert.get("solution", "")
            clean_sol_text = re.sub(r"<[^>]*>", " ", str(sol_text))
            clean_sol_text = re.sub(r"\s+", " ", clean_sol_text).strip()
            raw_desc = alert.get("desc", "")
            clean_desc_text = re.sub(r"<[^>]*>", " ", str(raw_desc))
            clean_desc_text = re.sub(r"\s+", " ", clean_desc_text).strip()
            records.append({
                "key_id": alert.get("alert", "N/A"),
                "cwe_id": cwe_value,
                "component": url_component,
                "issue_description": clean_desc_text,
                "comment_solution": clean_sol_text,
            })
    return records


def score_records_v1(prefix_batch, records):
    """Fast-path apa adanya dari analysis_flow.py, dilanjutkan skoring backend."""
    from backend import engine

    out = []
    for row in records:
        issue_type = str(row.get("issue_type", "")).upper()
        has_cwe = bool(row.get("has_cwe_tag", True))
        desc = str(row.get("issue_description") or "")
        comp = str(row.get("component") or "N/A")
        if prefix_batch == "SAST" and issue_type != "VULNERABILITY" and not has_cwe:
            score, sev = 0.0, "NONE"
        elif not desc.strip():
            score, sev = 0.0, "NONE"
        else:
            res = engine.run_single_prediction(prefix_batch, desc, comp, issue_type, has_cwe)
            score, sev = res["predicted_cvss4_score"], res["predicted_severity"]
        out.append({**row, "predicted_cvss4_score": score, "predicted_severity": sev})
    return out


def hybrid_pairs_v1(sast_rows, dast_rows):
    """Aturan pemasangan tab_hybrid.py: irisan CWE pada temuan yang sudah diberi skor dan bertag CWE."""
    from backend import engine

    df_s = pd.DataFrame(sast_rows)
    df_d = pd.DataFrame(dast_rows)
    df_s = df_s[(df_s["cwe_id"] != "N/A") & (df_s["cwe_id"] != "") & (df_s["predicted_cvss4_score"] > 0.0)].copy()
    df_d = df_d[(df_d["cwe_id"] != "N/A") & (df_d["cwe_id"] != "") & (df_d["predicted_cvss4_score"] > 0.0)].copy()
    df_s["cwe_id"] = df_s["cwe_id"].astype(str).str.strip().str.upper()
    df_d["cwe_id"] = df_d["cwe_id"].astype(str).str.strip().str.upper()
    joined = pd.merge(df_s, df_d, on="cwe_id", suffixes=("_sast", "_dast"))
    joined = joined.drop_duplicates(subset=["cwe_id", "component_sast", "component_dast"]).reset_index(drop=True)

    pairs = []
    for _, r in joined.iterrows():
        res = engine.run_hybrid_prediction(
            sast_desc=str(r["issue_description_sast"]).strip(),
            dast_desc=str(r["issue_description_dast"]).strip(),
            cwe_id=r["cwe_id"],
        )
        pairs.append({
            "cwe_id": r["cwe_id"],
            "key_id_sast": r["key_id_sast"],
            "key_id_dast": r["key_id_dast"],
            "component_sast": r["component_sast"],
            "component_dast": r["component_dast"],
            "sast_score": res["individual_scores"]["sast_score"],
            "dast_score": res["individual_scores"]["dast_score"],
            "base_score": res["base_score"],
            "hybrid_score": res["predicted_cvss4_score"],
            "severity": res["predicted_severity"],
            "is_verified_true_positive": res["is_verified_true_positive"],
            "shap_base_value": res["shap_base_value"],
            "shap_total_pos": res["shap_total_pos"],
            "shap_total_neg": res["shap_total_neg"],
            "shap_predicted_score": res["shap_predicted_score"],
        })
    return pairs


def main():
    from backend import model_loader
    from backend.config import load_hybrid_escalation_rate

    model_loader.init_models()
    excluded = []
    if os.path.exists(EXCLUDED_JSON_PATH):
        excluded = _read_json(EXCLUDED_JSON_PATH).get("unprocessing_domains", [])

    sast = score_records_v1("SAST", parse_sonar_v1(_read_json(SAMPLE_SQ)))
    dast = score_records_v1("DAST", parse_zap_v1(_read_json(SAMPLE_ZAP), excluded))
    pairs = hybrid_pairs_v1(sast, dast)

    slim = lambda rows: [  # noqa: E731
        {k: r[k] for k in ("key_id", "cwe_id", "component", "predicted_cvss4_score", "predicted_severity")}
        for r in rows
    ]
    payload = {
        "_description": "Golden baseline v1.0.0-tesis. Generated by tools/regression/generate_baseline.py.",
        "escalation_rate": load_hybrid_escalation_rate(),
        "excluded_domains": excluded,
        "sast": slim(sast),
        "dast": slim(dast),
        "hybrid_pairs": pairs,
    }
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"SAST={len(sast)} DAST={len(dast)} pairs={len(pairs)} -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
