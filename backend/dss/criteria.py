# backend/dss/criteria.py
"""
Membangun matriks keputusan (alternatif x kriteria) dari pasangan hybrid yang tersimpan.

Hanya data yang ada di sistem (atau yang diisi secara eksplisit oleh analis) yang dipakai:
- C1 hybrid_score       : scan_history.predicted_score (skor hybrid setelah eskalasi)
- C2 true_positive      : scan_history.is_true_positive
- C3 exploitability     : metrik dasar CVSS 4.0 dari profil CWE (tabel lookup)
- C4 impact             : metrik dampak sistem rentan CVSS 4.0 dari profil CWE
- C5 prevalence         : ln(1 + n), n = jumlah lokasi terdampak suatu isu (berkas kode + endpoint); untuk
                          baris tingkat pasangan (tanpa kolom 'locations') n = jumlah pasangan ber-CWE sama dalam sesi.
                          Transformasi log meredam isu dengan lokasi sangat banyak agar C5 tidak mendominasi
                          normalisasi vektor TOPSIS (efek cakupan dianggap makin kecil untuk setiap lokasi tambahan).
- C6 asset_criticality  : masukan analis (1-5) atau aturan pola komponen di dss_config
- C7 remediation_effort : masukan analis (1-5) atau nilai bawaan di dss_config (berkode C8 sebelum 26 November 2026;
                          kriteria paparan yang dulu berkode C7 tidak dipakai)

Encoding ordinal nilai metrik CVSS 4.0 di bawah adalah ASUMSI PERANCANGAN DSS ini:
CVSS 4.0 sendiri menghitung skor melalui lookup macrovector, bukan bobot numerik per metrik.
"""
import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

from backend.dss.escalation import escalate

EXPLOITABILITY_ENCODING = {
    "attack_vector": {"NETWORK": 1.0, "ADJACENT": 0.67, "LOCAL": 0.33, "PHYSICAL": 0.0},
    "attack_complexity": {"LOW": 1.0, "HIGH": 0.0},
    "attack_requirements": {"NONE": 1.0, "PRESENT": 0.0},
    "privileges_required": {"NONE": 1.0, "LOW": 0.5, "HIGH": 0.0},
    "user_interaction": {"NONE": 1.0, "PASSIVE": 0.5, "ACTIVE": 0.0},
}
# Kolom sub_* (sistem berikutnya) selalu bernilai NONE pada tabel lookup saat ini, sehingga hanya
# dampak pada sistem rentan yang membawa informasi.
IMPACT_ENCODING = {
    col: {"HIGH": 1.0, "LOW": 0.5, "NONE": 0.0}
    for col in ("vuln_confidentiality", "vuln_integrity", "vuln_availability")
}

SUPPORTED_CRITERIA = ("hybrid_score", "true_positive", "exploitability", "impact", "prevalence",
                      "asset_criticality", "remediation_effort")


@dataclass
class Alternative:
    decision_key: str
    key_id: str
    cwe_id: str
    sast_component: str
    dast_component: str
    predicted_score: float
    predicted_severity: str
    base_score: float | None
    is_true_positive: bool | None
    mitigation_text: str | None
    row_id: int | None = None


@dataclass
class DecisionMatrix:
    alternatives: list[Alternative]
    criteria: list[dict]                      # entri konfigurasi kriteria yang aktif, sesuai urutan kolom
    values: np.ndarray                        # m x n
    imputed: list[dict] = field(default_factory=list)  # per alternatif: {kunci_kriteria: alasan}

    @property
    def keys(self) -> list[str]:
        return [c["key"] for c in self.criteria]

    @property
    def directions(self) -> list[str]:
        return [c["direction"] for c in self.criteria]

    @property
    def weights(self) -> np.ndarray:
        return np.array([float(c["weight"]) for c in self.criteria])


# ---------------------------------------------------------------------------
# Tabel lookup CWE
# ---------------------------------------------------------------------------
@lru_cache(maxsize=4)
def _load_lookup_cached(path: str, mtime: float) -> dict[str, dict]:
    df = pd.read_csv(path)
    return {str(r["cwe_code"]).strip().upper(): r.to_dict() for _, r in df.iterrows()}


def load_cwe_lookup(path: Path) -> dict[str, dict]:
    """Mengembalikan {} bila tabel lookup (di-ignore git, dihasilkan pipeline) tidak tersedia."""
    try:
        return _load_lookup_cached(str(path), path.stat().st_mtime)
    except (FileNotFoundError, OSError):
        return {}


def _encode(profile: dict | None, encoding: dict) -> float | None:
    if not profile:
        return None
    vals = []
    for col, mapping in encoding.items():
        v = mapping.get(str(profile.get(col, "")).strip().upper())
        if v is not None:
            vals.append(v)
    return float(np.mean(vals)) if vals else None


def exploitability_of(profile: dict | None) -> float | None:
    return _encode(profile, EXPLOITABILITY_ENCODING)


def impact_of(profile: dict | None) -> float | None:
    return _encode(profile, IMPACT_ENCODING)


# ---------------------------------------------------------------------------
# Alternatif
# ---------------------------------------------------------------------------
def _f(v):
    try:
        return None if v is None or (isinstance(v, float) and math.isnan(v)) else float(v)
    except (TypeError, ValueError):
        return None


def alternatives_from_rows(rows: list[dict]) -> list[Alternative]:
    alts = []
    for r in rows:
        comp = str(r.get("component") or "")
        s_comp = r.get("sast_component")
        d_comp = r.get("dast_component")
        if s_comp is None or d_comp is None:
            s_part, _, d_part = comp.partition(" | ")
            s_comp, d_comp = s_comp or s_part.strip(), d_comp or d_part.strip()
        tp = r.get("is_true_positive")
        if tp is not None and not isinstance(tp, bool):
            tp = bool(tp)
        alts.append(Alternative(
            decision_key=r.get("decision_key") or "",
            key_id=str(r.get("key_id") or ""),
            cwe_id=str(r.get("cwe_id") or "N/A").upper(),
            sast_component=s_comp, dast_component=d_comp,
            predicted_score=_f(r.get("predicted_score")) or 0.0,
            predicted_severity=str(r.get("predicted_severity") or "NONE").upper(),
            base_score=_f(r.get("base_score")),
            is_true_positive=tp,
            mitigation_text=r.get("mitigation_text"),
            row_id=r.get("id"),
        ))
    return alts


def asset_criticality_for(alt: Alternative, cfg: dict, override: int | None) -> tuple[float, str | None]:
    if override is not None:
        return float(override), None
    section = cfg.get("asset_criticality", {})
    target = f"{alt.sast_component} | {alt.dast_component}"
    for rule in section.get("rules", []):
        try:
            if re.search(rule["pattern"], target):
                return float(rule["value"]), None
        except re.error:
            continue
    return float(section.get("default", 3)), "config_default"


def build_matrix(rows: list[dict], cfg: dict, lookup: dict[str, dict],
                 overrides: dict[str, dict] | None = None,
                 escalation_rate: float | None = None) -> DecisionMatrix:
    """
    rows: baris scan_history dari SATU sesi hybrid. overrides: {decision_key: {asset_criticality,
    remediation_effort}} yang diisi analis. escalation_rate: bila diberikan, C1 dihitung ulang dari
    base_score untuk analisis what-if (selain itu memakai skor tersimpan).
    """
    overrides = overrides or {}
    alts = alternatives_from_rows(rows)
    criteria = [c for c in cfg["criteria"] if c.get("enabled", True)]
    unknown = [c["key"] for c in criteria if c["key"] not in SUPPORTED_CRITERIA]
    if unknown:
        raise ValueError(f"Kriteria tidak dikenal pada konfigurasi DSS: {', '.join(unknown)}")
    if not alts:
        return DecisionMatrix([], criteria, np.zeros((0, len(criteria))), [])

    cwe_counts = pd.Series([a.cwe_id for a in alts]).value_counts().to_dict()
    expl = [exploitability_of(lookup.get(a.cwe_id)) for a in alts]
    imp = [impact_of(lookup.get(a.cwe_id)) for a in alts]
    expl_fill = float(np.median([v for v in expl if v is not None])) if any(v is not None for v in expl) else 0.5
    imp_fill = float(np.median([v for v in imp if v is not None])) if any(v is not None for v in imp) else 0.5

    values = np.zeros((len(alts), len(criteria)))
    imputed: list[dict] = []
    for i, a in enumerate(alts):
        flags = {}
        ov = overrides.get(a.decision_key, {})
        for j, c in enumerate(criteria):
            key = c["key"]
            if key == "hybrid_score":
                if escalation_rate is not None and a.base_score is not None and a.is_true_positive is not None:
                    v = escalate(a.base_score, a.is_true_positive, escalation_rate)
                else:
                    v = a.predicted_score
            elif key == "true_positive":
                if a.is_true_positive is None:
                    v, flags[key] = 0.0, "not_stored_v1"
                else:
                    v = 1.0 if a.is_true_positive else 0.0
            elif key == "exploitability":
                v = expl[i]
                if v is None:
                    v, flags[key] = expl_fill, "cwe_not_in_lookup"
            elif key == "impact":
                v = imp[i]
                if v is None:
                    v, flags[key] = imp_fill, "cwe_not_in_lookup"
            elif key == "prevalence":
                loc = rows[i].get("locations")
                n = float(loc) if loc is not None else float(cwe_counts.get(a.cwe_id, 1))
                v = math.log1p(n)
            elif key == "asset_criticality":
                v, reason = asset_criticality_for(a, cfg, ov.get("asset_criticality"))
                if reason:
                    flags[key] = reason
            elif key == "remediation_effort":
                o = ov.get("remediation_effort")
                if o is None:
                    v, flags[key] = float(cfg.get("remediation_effort", {}).get("default", 3)), "config_default"
                else:
                    v = float(o)
            values[i, j] = v
        imputed.append(flags)
    return DecisionMatrix(alts, criteria, values, imputed)
