# backend/dss/explain.py
"""
Penjelasan skor untuk DSS (fungsi murni, tanpa I/O, tanpa model ML).

Dua hal berbeda dijelaskan dan tidak boleh tercampur:
1. RANTAI SKOR yang menghasilkan skor hybrid yang dipakai DSS:
       skor SAST, skor DAST -> base (rata-rata) -> + eskalasi (terdeteksi di kedua pemindai) -> skor hybrid.
       Temuan pemindai tunggal: skor dasar = skor temuan, tanpa eskalasi.
2. Dekomposisi SHAP, yang menjelaskan prediksi model atas teks GABUNGAN SAST+DAST
   (shap_predicted_score = E[f] + positif + negatif + sisa kosakata absen). Bagian ini ditampilkan sebagai
   "faktor teks yang memengaruhi model", bukan sebagai dekomposisi eksak skor hybrid.

Penanda tinjauan ("Perlu diperiksa") adalah HEURISTIK yang mengarahkan analis ke skor yang paling layak diperiksa
manual sebelum ditindaklanjuti; penanda ini bukan ukuran keyakinan statistik. Ambangnya berasal dari
dss_config["review"].
"""
import re

# Batas bawah LOW, MEDIUM, HIGH, CRITICAL (ambang sama dengan backend.config.calculate_severity).
CLASS_BOUNDARIES = {0.1: "LOW", 4.0: "MEDIUM", 7.0: "HIGH", 9.0: "CRITICAL"}
DEFAULT_REVIEW = {"threshold_margin": 0.3, "min_text_evidence": 0.5}
_TOKEN_RE = re.compile(r"([^|()]+?)\s*\(([+\-]?\d+(?:\.\d+)?)\)")


def parse_tokens(raw) -> list[dict]:
    """'code (+0.36) | access (+0.01)' -> [{'token': 'code', 'value': 0.36}, ...]."""
    if not raw or str(raw).strip().upper() == "N/A":
        return []
    out = []
    for tok, val in _TOKEN_RE.findall(str(raw)):
        tok = tok.strip(" |,")
        if tok:
            out.append({"token": tok, "value": round(float(val), 2)})
    return out


def _f(v):
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def score_chain(rep: dict, hybrid_score: float, verified) -> dict:
    sast, dast, base = _f(rep.get("sast_score")), _f(rep.get("dast_score")), _f(rep.get("base_score"))
    escalation = round(hybrid_score - base, 2) if base is not None else None
    return {"sast_score": sast, "dast_score": dast, "base_score": base,
            "escalation": escalation, "hybrid_score": round(float(hybrid_score), 2),
            "verified": verified}


def shap_summary(rep: dict) -> dict | None:
    pos, neg = parse_tokens(rep.get("shap_positive")), parse_tokens(rep.get("shap_negative"))
    base_value = _f(rep.get("shap_base_value"))
    # Nilai dasar 0 berarti SHAP belum dihitung (save_findings mengisi 0), bukan penjelasan bernilai nol.
    if not base_value or (not pos and not neg and not _f(rep.get("shap_predicted_score"))):
        return None
    total_pos, total_neg = _f(rep.get("shap_total_pos")) or 0.0, _f(rep.get("shap_total_neg")) or 0.0
    return {
        "base_value": round(base_value, 2),
        "predicted": _f(rep.get("shap_predicted_score")),
        "total_positive": round(total_pos, 2),
        "total_negative": round(total_neg, 2),
        "text_evidence": round(abs(total_pos) + abs(total_neg), 2),
        "unexplained": _f(rep.get("absent_vocab_bias")),
        "raising": pos,
        "lowering": neg,
    }


def nearest_boundary(score: float) -> tuple[float, str, float]:
    b = min(CLASS_BOUNDARIES, key=lambda x: abs(score - x))
    return b, CLASS_BOUNDARIES[b], round(abs(score - b), 2)


def review_flags(hybrid_score: float, shap: dict | None, review_cfg: dict | None = None) -> list[dict]:
    cfg = {**DEFAULT_REVIEW, **(review_cfg or {})}
    flags = []
    b, cls, dist = nearest_boundary(hybrid_score)
    if dist <= float(cfg["threshold_margin"]):
        side = "di bawah" if hybrid_score < b else "di atas"
        flags.append({"code": "NEAR_THRESHOLD",
                      "text": f"Skor {hybrid_score:.2f} hanya {dist:.2f} {side} batas kelas {cls} ({b:.1f}); "
                              "severity class dan prioritasnya bisa berubah oleh selisih kecil."})
    if shap is None:
        flags.append({"code": "NO_EXPLANATION",
                      "text": "Penjelasan model (SHAP) tidak tersedia untuk issue ini."})
    elif shap["text_evidence"] < float(cfg["min_text_evidence"]):
        flags.append({"code": "WEAK_TEXT_EVIDENCE",
                      "text": f"Kata-kata dalam laporan hanya menggeser penilaian model sebesar "
                              f"{shap['text_evidence']:.2f}; skor sebagian besar berasal dari nilai rata-rata "
                              f"model ({shap['base_value']:.2f}), bukan dari bukti spesifik."})
    return flags


def _tokens_text(tokens: list[dict], limit: int = 3) -> str:
    return ", ".join(f"{t['token']} ({t['value']:+.2f})" for t in tokens[:limit])


def plain_reason(shap: dict | None) -> str:
    """Alasan model dalam satu baris untuk ekspor dan jejak audit."""
    if shap is None:
        return "Penjelasan model tidak tersedia."
    parts = []
    if shap["raising"]:
        parts.append(f"menaikkan: {_tokens_text(shap['raising'])}")
    if shap["lowering"]:
        parts.append(f"menurunkan: {_tokens_text(shap['lowering'])}")
    return ("Kata yang " + "; kata yang ".join(parts) + ".") if parts else "Tidak ada kata yang berpengaruh berarti."


def chain_text(chain: dict) -> str:
    if chain["base_score"] is None:
        return f"Skor hybrid {chain['hybrid_score']:.2f}."
    sast, dast = chain["sast_score"], chain["dast_score"]
    if sast and dast:
        head = f"SAST {sast:.2f} dan DAST {dast:.2f} → rata-rata {chain['base_score']:.2f}"
    elif sast or dast:
        head = f"Hanya terdeteksi {'SAST' if sast else 'DAST'}: skor {chain['base_score']:.2f}"
    else:
        head = f"Skor dasar {chain['base_score']:.2f}"
    if chain["escalation"]:
        return f"{head} → +{chain['escalation']:.2f} karena terdeteksi di kedua scanner = {chain['hybrid_score']:.2f}."
    return f"{head} = {chain['hybrid_score']:.2f} (tanpa eskalasi)."


def build(issue: dict, review_cfg: dict | None = None) -> dict:
    """Penjelasan lengkap untuk satu isu (dict isu dari issues.aggregate_issues)."""
    rep = issue.get("rep") or {}
    chain = score_chain(rep, issue["predicted_score"], issue.get("is_true_positive"))
    shap = shap_summary(rep)
    flags = review_flags(issue["predicted_score"], shap, review_cfg)
    return {
        "representative_pair": rep.get("key_id"),
        "chain": chain, "chain_text": chain_text(chain),
        "shap": shap, "model_reason": plain_reason(shap),
        "review_flags": flags, "needs_review": bool(flags),
    }
