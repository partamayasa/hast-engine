# backend/dss/issues.py
"""
Mengelompokkan pasangan SAST-DAST menjadi ISU — satuan yang benar-benar diputuskan tim keamanan.

Tampilan per pasangan mengulang masalah yang sama berkali-kali (misalnya satu header CSP yang hilang
dikorelasikan dengan 20 berkas kode menghasilkan 20 baris identik). Satu isu adalah satu jenis alert
OWASP ZAP untuk satu CWE, dengan seluruh endpoint (DAST) dan berkas kode (SAST) terdampak sebagai bukti.

Fungsi murni: tanpa I/O, tanpa model ML.
"""
import hashlib
import math

from backend.dss.escalation import escalate
from backend.services.identity import normalise_cwe

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
# Kolom pasangan representatif (pasangan yang menentukan skor isu) yang disimpan untuk penjelasan.
REP_FIELDS = ("key_id", "sast_score", "dast_score", "base_score", "predicted_score", "is_true_positive",
              "shap_base_value", "shap_total_pos", "shap_total_neg", "shap_predicted_score",
              "absent_vocab_bias", "shap_positive", "shap_negative")


def issue_key_for(cwe_id, dast_alert) -> str:
    raw = f"{normalise_cwe(cwe_id)}|{str(dast_alert or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_code(issue_key: str) -> str:
    """Kode pendek, stabil, dan mudah dibaca (isu yang sama mempertahankan kode yang sama lintas sesi pemindaian)."""
    return f"ISU-{issue_key[:6].upper()}"


def _num(v):
    try:
        return None if v is None or (isinstance(v, float) and math.isnan(v)) else float(v)
    except (TypeError, ValueError):
        return None


def _split_component(row: dict) -> tuple[str, str]:
    s, d = row.get("sast_component"), row.get("dast_component")
    if s is None or d is None:
        sp, _, dp = str(row.get("component") or "").partition(" | ")
        s, d = s or sp.strip(), d or dp.strip()
    return s or "", d or ""


def _severity_of(score: float) -> str:
    # Ambang sama dengan backend.config.calculate_severity (diimpor saat dipakai agar modul ini tetap murni).
    from backend.config import calculate_severity
    return calculate_severity(score)


def aggregate_issues(rows: list[dict], escalation_rate: float | None = None) -> list[dict]:
    """
    rows: pasangan hybrid tersimpan (scan_history). Mengembalikan satu dict per isu yang berbentuk seperti baris
    pemindaian agar dapat dipakai pembangun kriteria, ditambah kolom bukti (title, endpoints, files, pairs).
    Bila escalation_rate diberikan, skor hybrid tiap pasangan dihitung ulang dari base score (what-if).
    """
    groups: dict[str, dict] = {}
    for r in rows:
        sast_comp, dast_comp = _split_component(r)
        alert = r.get("dast_key_id") or dast_comp or "Tanpa nama alert"
        key = issue_key_for(r.get("cwe_id"), alert)
        tp = r.get("is_true_positive")
        tp = None if tp is None else bool(tp)
        score = _num(r.get("predicted_score")) or 0.0
        base = _num(r.get("base_score"))
        if escalation_rate is not None and base is not None and tp is not None:
            score = escalate(base, tp, escalation_rate)

        g = groups.setdefault(key, {
            "issue_key": key, "title": str(alert), "cwe_id": normalise_cwe(r.get("cwe_id")) or "N/A",
            "endpoints": [], "files": [], "pairs": [], "mitigation_text": None,
            "score": -1.0, "base_score": None, "tp_values": [], "sast_messages": [], "rep": {},
        })
        if dast_comp and dast_comp not in g["endpoints"]:
            g["endpoints"].append(dast_comp)
        if sast_comp and sast_comp not in g["files"]:
            g["files"].append(sast_comp)
        g["pairs"].append(r.get("key_id"))
        g["tp_values"].append(tp)
        if not g["mitigation_text"] and r.get("mitigation_text"):
            g["mitigation_text"] = r["mitigation_text"]
        msg = str(r.get("sast_description") or "").strip()
        if msg and msg not in g["sast_messages"] and len(g["sast_messages"]) < 3:
            g["sast_messages"].append(msg)
        if score > g["score"]:
            g["score"], g["base_score"] = score, base
            g["rep"] = {f: r.get(f) for f in REP_FIELDS}

    issues = []
    for g in groups.values():
        known = [v for v in g["tp_values"] if v is not None]
        verified = any(known) if known else None
        issues.append({
            # kolom yang kompatibel dengan baris pemindaian (dipakai criteria.build_matrix)
            "id": None,
            "key_id": issue_code(g["issue_key"]),
            "decision_key": g["issue_key"],
            "cwe_id": g["cwe_id"],
            "component": f"{', '.join(g['files'][:3])} | {', '.join(g['endpoints'][:3])}",
            "sast_component": g["files"][0] if g["files"] else "",
            "dast_component": g["endpoints"][0] if g["endpoints"] else "",
            "predicted_score": round(g["score"], 2),
            "predicted_severity": _severity_of(g["score"]),
            "base_score": g["base_score"],
            "is_true_positive": verified,
            "mitigation_text": g["mitigation_text"],
            "locations": len(g["files"]) + len(g["endpoints"]),
            # bukti
            "title": g["title"],
            "endpoints": g["endpoints"],
            "files": g["files"],
            "pair_ids": g["pairs"],
            "sast_messages": g["sast_messages"],
            "rep": g["rep"],
        })
    # Urutan stabil (berdasarkan kode isu) agar varian what-if tetap sejajar; service mengurutkan menurut prioritas.
    issues.sort(key=lambda i: i["key_id"])
    return issues
