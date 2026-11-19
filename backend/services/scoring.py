# backend/services/scoring.py
"""
Skoring batch dan korelasi hybrid (dipindah dari analysis_flow.py / tab_hybrid.py frontend).

Skor dihasilkan oleh backend.engine persis seperti pada v1.0.0-tesis; modul ini hanya
menghilangkan permintaan HTTP per temuan yang dulu dilakukan UI.
"""
import hashlib
import time
import uuid
from functools import lru_cache

import pandas as pd

from backend import engine
from backend.core.settings import get_settings
from backend.services.identity import decision_key_for, normalise_cwe

SCANNER_LABELS = {"SAST": "SonarQube (SAST)", "DAST": "OWASP ZAP (DAST)"}


@lru_cache
def model_version() -> str:
    """SHA-256 pendek dari artefak model + vectorizer, dicatat pada setiap run skoring."""
    s = get_settings()
    h = hashlib.sha256()
    for p in (s.rf_model_path, s.tfidf_path):
        try:
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        except FileNotFoundError:
            h.update(b"missing:" + str(p).encode())
    return f"rf-{h.hexdigest()[:12]}"


def score_records(prefix: str, records: list[dict]) -> list[dict]:
    """Menerapkan pra-penyaringan fast-path v1, lalu memberi skor pada temuan yang tersisa."""
    prefix = prefix.upper()
    out = []
    for row in records:
        issue_type = str(row.get("issue_type", "")).upper()
        has_cwe = bool(row.get("has_cwe_tag", True))
        desc = str(row.get("issue_description") or "")
        comp = str(row.get("component") or "N/A")
        if prefix == "SAST" and issue_type != "VULNERABILITY" and not has_cwe:
            score, sev = 0.0, "NONE"
        elif not desc.strip():
            score, sev = 0.0, "NONE"
        else:
            res = engine.run_single_prediction(prefix, desc, comp, issue_type, has_cwe)
            score, sev = res["predicted_cvss4_score"], res["predicted_severity"]
        out.append({**row, "predicted_cvss4_score": score, "predicted_severity": sev})
    return out


def new_batch_id(prefix: str) -> str:
    return f"{prefix}-{int(time.time())}"


# ---------------------------------------------------------------------------
# Korelasi hybrid
# ---------------------------------------------------------------------------
def _eligible(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df[(df["cwe_id"] != "N/A") & (df["cwe_id"] != "") & (df["predicted_score"] > 0.0)].copy()
    df["cwe_id"] = df["cwe_id"].astype(str).str.strip().str.upper()
    return df


def _sast_text(row) -> str:
    v = row.get("sast_description_sast")
    if v is None or (isinstance(v, float) and pd.isna(v)) or str(v).strip() in ("", "None", "nan"):
        v = row.get("description_sast", "")
    return str(v or "").strip()


def _dast_text(row) -> str:
    """Deskripsi DAST tanpa blok [MITIGATION] yang ditambahkan (hasilnya sama dengan regex v1)."""
    v = row.get("dast_description_dast")
    if v is None or (isinstance(v, float) and pd.isna(v)) or str(v).strip() in ("", "None", "nan"):
        v = row.get("description_dast", "")
    text = str(v or "")
    idx = text.find("[MITIGATION]")
    if idx >= 0:
        text = text[:idx]
    return text.strip()


def preview_pairs(sast_rows: list[dict], dast_rows: list[dict], excluded_domains: list[str] | None = None) -> list[dict]:
    """Irisan CWE Left-Base dari dua batch yang sudah diberi skor (belum diberi skor hybrid)."""
    df_s = _eligible(pd.DataFrame(sast_rows))
    df_d = _eligible(pd.DataFrame(dast_rows))
    if df_s.empty or df_d.empty:
        return []
    if excluded_domains:
        mask = df_d["component"].str.lower().apply(
            lambda url: any(d.strip().lower() in str(url) for d in excluded_domains))
        df_d = df_d[~mask].reset_index(drop=True)
    joined = pd.merge(df_s, df_d, on="cwe_id", suffixes=("_sast", "_dast"))
    joined = joined.drop_duplicates(subset=["cwe_id", "component_sast", "component_dast"]).reset_index(drop=True)

    pairs = []
    for _, r in joined.iterrows():
        mitigation = r.get("mitigation_text_dast")
        if mitigation is None or (isinstance(mitigation, float) and pd.isna(mitigation)):
            raw = str(r.get("description_dast") or "")
            mitigation = raw.split("[MITIGATION]:", 1)[1].strip() if "[MITIGATION]:" in raw else None
        pairs.append({
            "pair_id": f"PAIR-{str(uuid.uuid4())[:8].upper()}",
            "cwe_id": r["cwe_id"],
            "sast_key_id": r["key_id_sast"],
            "dast_key_id": r["key_id_dast"],
            "sast_component": r["component_sast"],
            "dast_component": r["component_dast"],
            "initial_sast_score": float(r["predicted_score_sast"]),
            "initial_dast_score": float(r["predicted_score_dast"]),
            "sast_description": _sast_text(r),
            "dast_description": _dast_text(r),
            "mitigation_text": mitigation,
            "decision_key": decision_key_for(r["cwe_id"], r["component_sast"], r["component_dast"]),
        })
    return pairs


def score_pairs(pairs: list[dict]) -> list[dict]:
    """Menjalankan logika /predict/hybrid untuk setiap pasangan dan mengembalikan record yang siap disimpan."""
    out = []
    for p in pairs:
        res = engine.run_hybrid_prediction(sast_desc=p["sast_description"], dast_desc=p["dast_description"],
                                           cwe_id=p["cwe_id"])
        mitigation_block = f"\n[MITIGATION]: {p['mitigation_text']}" if p.get("mitigation_text") else ""
        out.append({
            "key_id": p["pair_id"],
            "cwe_id": normalise_cwe(p["cwe_id"]),
            "component": f"{p['sast_component']} | {p['dast_component']}".strip(),
            # Tata letak sama dengan v1 agar tampilan riwayat tetap dapat mengekstrak teks mitigasi.
            "issue_description": f"[SAST]: {p['sast_description']}\n[DAST]: {p['dast_description']}{mitigation_block}".strip(),
            "predicted_cvss4_score": res["predicted_cvss4_score"],
            "predicted_severity": res["predicted_severity"],
            "base_score": res["base_score"],
            "shap_base_value": res["shap_base_value"],
            "shap_total_pos": res["shap_total_pos"],
            "shap_total_neg": res["shap_total_neg"],
            "absent_vocab_bias": res["absent_vocab_bias"],
            "shap_predicted_score": res["shap_predicted_score"],
            "shap_positive": res["shap_positive"],
            "shap_negative": res["shap_negative"],
            "sast_description": p["sast_description"],
            "dast_description": p["dast_description"] + mitigation_block,
            "mitigation_text": p.get("mitigation_text"),
            "sast_score": res["individual_scores"]["sast_score"],
            "dast_score": res["individual_scores"]["dast_score"],
            "is_true_positive": res["is_verified_true_positive"],
            "sast_key_id": p["sast_key_id"],
            "dast_key_id": p["dast_key_id"],
            "sast_component": p["sast_component"],
            "dast_component": p["dast_component"],
        })
    return out
