# backend/dss/service.py
"""
Orkestrasi DSS pada tingkat ISU:
    pasangan hybrid tersimpan -> isu -> matriks kriteria -> urgensi MCDM -> aturan P1-P4 -> penjelasan
    bahasa biasa -> persistensi (dss_runs, dss_decisions, dss_decision_events).

Urutan yang dilihat pengguna: tingkat prioritas (P1 lebih dulu; prioritas yang ditetapkan analis
diutamakan) -> skor urgensi di dalam tingkat (MCDM) -> skor keparahan. Dengan demikian MCDM hanya
mengurutkan pekerjaan DI DALAM satu tingkat dan tidak pernah menaikkan isu P3 di atas isu P1, sehingga
daftar dan tindakan yang direkomendasikan tidak pernah bertentangan.
"""
import datetime
import uuid

import numpy as np
from sqlalchemy.orm import Session

from backend.config import load_hybrid_escalation_rate
from backend.core.settings import get_settings
from backend.dss import criteria as crit
from backend.dss.config import config_hash, load_dss_config
from backend.dss.explain import build as build_explanation
from backend.dss.issues import aggregate_issues
from backend.dss.mcdm import normalize_weights, rank_order, run_method
from backend.dss.recommender import (
    BUSINESS_IMPACT, EFFORT, PRIORITY_LABELS, PRIORITY_OF_ACTION, recommend,
)
from backend.dss.sensitivity import escalation_rate_sensitivity, weight_sensitivity
from backend.repositories import dss as dss_repo
from backend.repositories import history as history_repo
from backend.services.scoring import model_version

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

# Frasa bahasa biasa untuk faktor yang menaikkan urutan isu di dalam tingkat prioritasnya.
FACTOR_PHRASES = {
    "hybrid_score": "skor keparahannya lebih tinggi",
    "true_positive": "terbukti di kode dan aplikasi berjalan",
    "exploitability": "jenis kelemahannya lebih mudah dieksploitasi",
    "impact": "dampak teknisnya lebih besar",
    "prevalence": "tersebar di lebih banyak lokasi",
    "asset_criticality": "dampak bisnisnya lebih tinggi",
}


class DssError(ValueError):
    pass


def _load_batch(session: Session, batch_id: str) -> list[dict]:
    rows = history_repo.list_batch(session, batch_id)
    if not rows:
        raise LookupError(f"Session {batch_id} tidak ditemukan.")
    if rows[0].get("scanner_type") != history_repo.HYBRID_SCANNER:
        raise DssError("Prioritas hanya dapat disusun dari session Korelasi Hybrid (HAST-*).")
    return rows


def _apply_overrides(cfg: dict, method: str | None, weights: dict | None) -> tuple[dict, str]:
    cfg = {**cfg, "criteria": [dict(c) for c in cfg["criteria"]]}
    source = cfg.get("weighting_source", "config")
    if method:
        cfg["method"] = method.upper()
    if weights:
        unknown = set(weights) - {c["key"] for c in cfg["criteria"]}
        if unknown:
            raise DssError(f"Bobot untuk kriteria tidak dikenal: {', '.join(sorted(unknown))}")
        for c in cfg["criteria"]:
            if c["key"] in weights:
                c["weight"] = float(weights[c["key"]])
                c["enabled"] = float(weights[c["key"]]) > 0  # bobot nol menghapus kriteria tersebut
        source = "manual"
    return cfg, source


def _technical_notes(matrix: crit.DecisionMatrix, lookup_available: bool) -> list[str]:
    """Catatan metodologis. Ditampilkan kepada peneliti (mode dev), bukan pada daftar kerja analis."""
    keys = set(matrix.keys)
    out = []
    if "hybrid_score" in keys and keys & {"exploitability", "impact"}:
        out.append("C1 (skor model) dilatih dari skor CVSS, sedangkan C3/C4 berasal dari metrik CVSS yang sama: "
                   "ada tumpang tindih informasi (double counting).")
    if not lookup_available and keys & {"exploitability", "impact"}:
        out.append("Tabel lookup CWE tidak tersedia; C3/C4 diisi nilai netral 0.5.")
    n_imp = sum(1 for f in matrix.imputed if f)
    if n_imp:
        out.append(f"{n_imp} issue memakai nilai default (mis. dampak bisnis/upaya belum diisi analis).")
    if "true_positive" in keys and all(a.is_true_positive is None for a in matrix.alternatives):
        out.append("Status True Positive tidak tersimpan pada session ini (dibuat sebelum v2); jalankan ulang korelasi.")
    return out


def _tie_breakers(matrix: crit.DecisionMatrix) -> list[tuple]:
    return [(-a.predicted_score, -(1 if a.is_true_positive else 0), a.key_id) for a in matrix.alternatives]


def _build(session: Session, batch_id: str, method: str | None, weights: dict | None,
           escalation_rate: float | None):
    rows = _load_batch(session, batch_id)
    issues = aggregate_issues(rows, escalation_rate)
    cfg, source = _apply_overrides(load_dss_config(), method, weights)
    lookup = crit.load_cwe_lookup(get_settings().cwe_lookup_path)
    decisions = dss_repo.decisions_by_keys(session, [i["decision_key"] for i in issues])
    overrides = {k: {"asset_criticality": d.asset_criticality, "remediation_effort": d.remediation_effort}
                 for k, d in decisions.items()}
    matrix = crit.build_matrix(issues, cfg, lookup, overrides)
    return cfg, source, lookup, matrix, decisions, issues, rows


def _urgency(method: str, scores: np.ndarray) -> np.ndarray:
    """Urgensi 0-100: preferensi TOPSIS/SAW sudah berskala 0-1; WP dibuat relatif terhadap isu teratas."""
    if method == "WP":
        mx = float(scores.max()) or 1.0
        return np.round(scores / mx * 100)
    return np.round(scores * 100)


def _why(issue: dict, rec: dict, business_impact: float, impact_is_default: bool, top_keys: list[str]) -> str:
    n_files, n_ep = len(issue["files"]), len(issue["endpoints"])
    if issue["is_true_positive"]:
        proof = f"terbukti di kode ({n_files} file) dan di aplikasi berjalan ({n_ep} endpoint)"
    elif issue["is_true_positive"] is False:
        proof = "belum terbukti di kedua scanner"
    else:
        proof = "status pembuktian tidak tersimpan (session lama)"
    bi = BUSINESS_IMPACT.get(int(business_impact), str(business_impact))
    bi_txt = "dampak bisnis belum dinilai (dianggap Sedang)" if impact_is_default else f"dampak bisnis {bi}"
    head = (f"{rec['priority_label']}: severity {issue['predicted_severity']} ({issue['predicted_score']:.2f}), "
            f"{proof}, {bi_txt}.")
    factors = [FACTOR_PHRASES[k] for k in top_keys if k in FACTOR_PHRASES][:2]
    tail = (f" Di antara issue lain, issue ini diurutkan lebih atas karena {' dan '.join(factors)}."
            if factors else "")
    return head + tail


def _distinguishing_factors(matrix: crit.DecisionMatrix, i: int, weights: np.ndarray) -> list[str]:
    """
    Kriteria benefit tempat isu i jelas BERADA DI ATAS median seluruh isu dalam sesi, diurutkan menurut
    bobot x jarak relatif. Kolom yang konstan (misalnya semua isu terverifikasi, dampak belum dinilai) tidak
    pernah dijadikan alasan, sehingga penjelasan hanya menyebut hal yang benar-benar membedakan isu ini.
    """
    found = []
    for j, c in enumerate(matrix.criteria):
        if c["direction"] != "benefit":
            continue
        col = matrix.values[:, j]
        spread = float(col.max() - col.min())
        if spread <= 1e-9:
            continue
        gap = (float(col[i]) - float(np.median(col))) / spread
        if gap > 0.05:
            found.append((weights[j] * gap, c["key"]))
    return [k for _, k in sorted(found, reverse=True)]


def rank_batch(session: Session, batch_id: str, method: str | None = None, weights: dict | None = None,
               escalation_rate: float | None = None, persist: bool = True, actor: str | None = None,
               today: datetime.date | None = None) -> dict:
    cfg, source, lookup, matrix, decisions, issues, rows = _build(session, batch_id, method, weights, escalation_rate)
    if not matrix.alternatives:
        raise DssError("Session tidak memiliki issue untuk diprioritaskan.")
    w = normalize_weights(matrix.weights)
    res = run_method(cfg["method"], matrix.values, w, matrix.directions)
    urgency = _urgency(cfg["method"], res.scores)
    mcdm_order = rank_order(res.scores, _tie_breakers(matrix))
    mcdm_rank = {i: r for r, i in enumerate(mcdm_order, start=1)}
    keys = matrix.keys

    items = []
    for i, a in enumerate(matrix.alternatives):
        issue = issues[i]
        contrib = res.weighted[i] if cfg["method"] in ("SAW", "TOPSIS") else w * res.normalized[i]
        total = float(np.sum(contrib)) or 1.0
        contributions = [
            {"key": c["key"], "code": c.get("code"), "label": c["label"], "direction": c["direction"],
             "value": float(matrix.values[i, j]), "normalized": round(float(res.normalized[i, j]), 6),
             "weight": round(float(w[j]), 6), "weighted": round(float(contrib[j]), 6),
             "share": round(float(contrib[j]) / total, 4) if c["direction"] == "benefit" else None}
            for j, c in enumerate(matrix.criteria)
        ]
        top = sorted([c for c in contributions if c["share"] is not None], key=lambda c: -c["share"])[:3]
        d = decisions.get(a.decision_key)
        if "asset_criticality" in keys:
            business_impact = float(matrix.values[i, keys.index("asset_criticality")])
            # Nilai dari aturan pola komponen di konfigurasi bukan default; hanya imputasi 'config_default'.
            impact_is_default = matrix.imputed[i].get("asset_criticality") == "config_default"
        else:
            impact_is_default = not (d and d.asset_criticality)
            business_impact = float((d.asset_criticality if not impact_is_default else None)
                                    or cfg.get("asset_criticality", {}).get("default", 3))
        ctx = {"severity": a.predicted_severity, "true_positive": bool(a.is_true_positive),
               "hybrid_score": a.predicted_score, "rank": mcdm_rank[i], "preference": float(res.scores[i]),
               "business_impact": business_impact}
        rec = recommend(ctx, cfg["recommendation_rules"], cfg.get("sla_days"), today)
        override = PRIORITY_OF_ACTION.get(d.chosen_action) if d and d.chosen_action else None
        effective_priority = override or rec["priority"]
        effort = None
        if d and d.remediation_effort:
            effort = d.remediation_effort
        explanation = build_explanation(issue, cfg.get("review"))
        items.append({
            "issue_code": a.key_id, "key_id": a.key_id, "decision_key": a.decision_key,
            "title": issue["title"], "cwe_id": a.cwe_id,
            "endpoints": issue["endpoints"], "files": issue["files"], "pair_count": len(issue["pair_ids"]),
            "sast_messages": issue["sast_messages"],
            "sast_component": a.sast_component, "dast_component": a.dast_component,
            "hybrid_score": a.predicted_score, "severity": a.predicted_severity,
            "is_true_positive": a.is_true_positive, "mitigation_text": a.mitigation_text,
            "urgency": int(urgency[i]), "preference": round(float(res.scores[i]), 4), "mcdm_rank": mcdm_rank[i],
            "business_impact": int(business_impact), "business_impact_label": BUSINESS_IMPACT.get(int(business_impact)),
            "business_impact_is_default": impact_is_default,
            "effort_label": EFFORT.get(effort) if effort else None,
            "recommendation": rec,
            "priority": effective_priority, "priority_label": PRIORITY_LABELS[effective_priority],
            "priority_overridden": override is not None and override != rec["priority"],
            "why": _why(issue, rec, business_impact, impact_is_default, _distinguishing_factors(matrix, i, w)),
            "score_explanation": explanation, "needs_review": explanation["needs_review"],
            "criteria": contributions, "top_contributors": [c["key"] for c in top],
            "imputed": matrix.imputed[i],
            "decision": dss_repo.decision_to_dict(d) if d else None,
        })

    items.sort(key=lambda it: (PRIORITY_RANK[it["priority"]], -it["preference"], -it["hybrid_score"], it["issue_code"]))
    for rank, it in enumerate(items, start=1):
        it["rank"] = rank

    er = escalation_rate if escalation_rate is not None else load_hybrid_escalation_rate()
    run = {
        "run_id": str(uuid.uuid4()), "batch_id": batch_id, "unit": "issue", "method": cfg["method"],
        "weights": {c["key"]: round(float(w[j]), 6) for j, c in enumerate(matrix.criteria)},
        "criteria": [{k: c.get(k) for k in ("code", "key", "label", "direction")} for c in matrix.criteria],
        "weighting_source": source, "config_hash": config_hash(cfg), "escalation_rate": er,
        "escalation_rate_overridden": escalation_rate is not None, "model_version": model_version(),
        "lookup_available": bool(lookup), "warnings": _technical_notes(matrix, bool(lookup)),
        "pairs_count": len(rows), "issues_count": len(items),
        "created_by": actor, "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "persisted": False, "items": items,
    }
    if persist:
        dss_repo.save_run(session, run)
        for it in items:
            dec = dss_repo.upsert_recommendation(session, it, batch_id, run["run_id"], actor)
            it["decision"] = dss_repo.decision_to_dict(dec)
        run["persisted"] = True
    return run


def summary(run: dict) -> dict:
    """Hitungan untuk header daftar kerja."""
    open_items = [it for it in run["items"] if not (it.get("decision") or {}).get("is_closed")]
    return {
        "issues": len(run["items"]),
        "open": len(open_items),
        "by_priority": {p: sum(1 for it in open_items if it["priority"] == p) for p in ("P1", "P2", "P3", "P4")},
        "overdue": sum(1 for it in open_items if (it.get("decision") or {}).get("is_overdue")),
        "needs_review": sum(1 for it in open_items if it.get("needs_review")),
        "closed": len(run["items"]) - len(open_items),
    }


def sensitivity(session: Session, batch_id: str, method: str | None = None, steps=None, k: int = 10) -> dict:
    cfg, _source, _lookup, matrix, *_ = _build(session, batch_id, method, None, None)
    if not matrix.alternatives:
        raise DssError("Session tidak memiliki issue untuk dianalisis.")
    ids = [a.key_id for a in matrix.alternatives]
    kwargs = {"steps": tuple(steps)} if steps else {}
    out = weight_sensitivity(cfg["method"], matrix.values, matrix.weights, matrix.directions, ids,
                             matrix.keys, k=k, tie_breakers=_tie_breakers(matrix), **kwargs)
    out.update({"method": cfg["method"], "batch_id": batch_id, "n_alternatives": len(ids), "unit": "issue"})
    return out


def er_sensitivity(session: Session, batch_id: str, rates: list[float], method: str | None = None,
                   k: int = 10) -> dict:
    cfg, _source, lookup, matrix, decisions, _issues, rows = _build(session, batch_id, method, None, None)
    if "hybrid_score" not in matrix.keys:
        raise DssError("Kriteria severity tidak aktif; sensitivitas ER tidak relevan.")
    if any(r.get("base_score") is None or r.get("is_true_positive") is None for r in rows):
        raise DssError("Session ini tidak menyimpan base_score/status TP (dibuat sebelum v2); jalankan ulang korelasi.")
    overrides = {k_: {"asset_criticality": d.asset_criticality, "remediation_effort": d.remediation_effort}
                 for k_, d in decisions.items()}
    ids = [a.key_id for a in matrix.alternatives]

    def build_values(rate):
        return crit.build_matrix(aggregate_issues(rows, rate), cfg, lookup, overrides).values

    out = escalation_rate_sensitivity(build_values, cfg["method"], matrix.weights, matrix.directions, ids,
                                      rates, load_hybrid_escalation_rate(), k, _tie_breakers(matrix))
    out.update({"method": cfg["method"], "batch_id": batch_id, "n_alternatives": len(ids), "unit": "issue"})
    return out
