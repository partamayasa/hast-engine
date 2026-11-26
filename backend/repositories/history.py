# backend/repositories/history.py
"""
Persistensi temuan yang sudah diberi skor (tabel scan_history).

save_findings() adalah port dari save_to_history() frontend v1: aturan pembersihan
deskripsi tidak berubah, dan kolom terstruktur baru juga diisi.
"""
import datetime
import math
import re
from typing import Any, Iterable

from sqlalchemy import case, delete, distinct, func, select
from sqlalchemy.orm import Session

from backend.db.bootstrap import HTML_TAG_RE, PAIR_PREFIX_RE, TAG_STRIP_RE
from backend.db.models import ScanHistory
from backend.services.identity import decision_key_for

HYBRID_SCANNER = "Pengujian Korelasi Hybrid"
# Temuan SAST atau DAST yang tidak memiliki pasangan CWE pada korelasi hybrid. Disimpan pada batch HAST-* yang
# sama agar DSS memprioritaskan seluruh temuan, tetapi dengan tipe tersendiri agar statistik hybrid tidak tercampur.
SINGLE_SCANNER = "Temuan Pemindai Tunggal"
DSS_SCANNERS = (HYBRID_SCANNER, SINGLE_SCANNER)
SAST_SCANNER = "SonarQube (SAST)"
DAST_SCANNER = "OWASP ZAP (DAST)"


def _missing(v: Any) -> bool:
    if v is None:
        return True
    try:
        return isinstance(v, float) and math.isnan(v)
    except Exception:
        return False


def _first(row: dict, *keys, default=None):
    for k in keys:
        if k in row and not _missing(row[k]):
            return row[k]
    return default


def _num_from_tag(raw_text: str, pattern: str, default):
    m = re.search(pattern, raw_text)
    return float(m.group(1)) if m else default


def _strip_html_lines(value: str) -> str:
    c = re.sub(r'<[^>]*>', ' ', value)
    lines = [re.sub(r'[ \t]+', ' ', l).strip() for l in c.splitlines()]
    return "\n".join([l for l in lines if l]).strip()


def build_row(batch_id: str, scanner_type: str, row: dict, now: str,
              execution_duration: float | None = None, model_version: str | None = None) -> ScanHistory:
    k_id = _first(row, 'key_id', 'Key ID', default='N/A')
    c_id = _first(row, 'cwe_id', 'CWE ID', default='N/A')
    comp = _first(row, 'component', 'Component', default='N/A')

    desc = _first(row, 'issue_description', 'Description', default='')
    if not desc and 'description' in row:
        desc = row['description']

    comment_sol = _first(row, 'comment_solution', 'mitigation_text', default='')
    if comment_sol:
        desc = f"{desc}\n[MITIGATION]: {comment_sol}"

    p_score = _first(row, 'predicted_cvss4_score', 'Predicted Score', 'predicted_score', default=0.0)
    p_sev = _first(row, 'predicted_severity', 'Predicted Severity', default='NONE')
    raw_text = str(desc or '')

    b_score = _first(row, 'base_score', 'Base Score')
    b_score = float(b_score) if b_score is not None else _num_from_tag(
        raw_text, r'\[BASE_SCORE\]:\s*([\d\.]+)', float(p_score) if not _missing(p_score) else 0.0)
    sb_val = _first(row, 'shap_base_value', 'SHAP Base Value')
    sb_val = float(sb_val) if sb_val is not None else _num_from_tag(raw_text, r'\[SHAP_BASE\]:\s*([\-\d\.]+)', 0.0)
    stp_val = _first(row, 'shap_total_pos', 'Total SHAP Positive')
    stp_val = float(stp_val) if stp_val is not None else _num_from_tag(raw_text, r'\[SHAP_TOT_POS\]:\s*([\-\d\.]+)', 0.0)
    stn_val = _first(row, 'shap_total_neg', 'Total SHAP Negative')
    stn_val = float(stn_val) if stn_val is not None else _num_from_tag(raw_text, r'\[SHAP_TOT_NEG\]:\s*([\-\d\.]+)', 0.0)
    av_val = _first(row, 'absent_vocab_bias', 'Absent Vocabulary Bias')
    av_val = float(av_val) if av_val is not None else _num_from_tag(raw_text, r'\[ABSENT_VOCAB\]:\s*([\-\d\.]+)', 0.0)
    sp_val = _first(row, 'shap_predicted_score', 'SHAP Predicted Score')
    sp_val = float(sp_val) if sp_val is not None else _num_from_tag(raw_text, r'\[SHAP_PRED\]:\s*([\-\d\.]+)', b_score)

    pos_str = _first(row, 'shap_positive', 'Dominant Vulnerability Aggravating Factors (SHAP Positive)')
    if pos_str is None:
        m = re.search(r'\[SHAP_POS\]:\s*(.*?)(?=(?:\r?\n|\s*)\[SHAP_NEG\]:|$)', raw_text, re.DOTALL)
        pos_str = m.group(1).strip() if m else "N/A"
    else:
        pos_str = str(pos_str).strip()
    neg_str = _first(row, 'shap_negative', 'Dominant Vulnerability Reducing Factors (SHAP Negative)')
    if neg_str is None:
        m = re.search(r'\[SHAP_NEG\]:\s*(.*?)(?=$)', raw_text, re.DOTALL)
        neg_str = m.group(1).strip() if m else "N/A"
    else:
        neg_str = str(neg_str).strip()

    sast_desc = _first(row, 'sast_description', 'Description (SAST)')
    dast_desc = _first(row, 'dast_description', 'Description (DAST)')

    clean_desc = re.sub(TAG_STRIP_RE, '', raw_text, flags=re.DOTALL).strip()
    clean_desc = re.sub(PAIR_PREFIX_RE, '', clean_desc).strip()

    if sast_desc is not None:
        sast_desc = re.sub(TAG_STRIP_RE, '', str(sast_desc), flags=re.DOTALL).strip()
        sast_desc = re.sub(PAIR_PREFIX_RE, '', sast_desc).strip()
    elif "Hybrid" in str(scanner_type) or "[SAST]:" in clean_desc:
        m = re.search(r'\[SAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[DAST\]:|$)', clean_desc, re.DOTALL)
        sast_desc = m.group(1).strip() if m else None
    elif "SAST" in str(scanner_type) or "SonarQube" in str(scanner_type):
        sast_desc = clean_desc

    if dast_desc is not None:
        dast_desc = re.sub(TAG_STRIP_RE, '', str(dast_desc), flags=re.DOTALL).strip()
    elif "Hybrid" in str(scanner_type) or "[DAST]:" in clean_desc:
        m = re.search(r'\[DAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[MITIGATION\]:|$)', clean_desc, re.DOTALL)
        dast_desc = m.group(1).strip() if m else None
    elif "DAST" in str(scanner_type) or "OWASP ZAP" in str(scanner_type):
        dast_desc = clean_desc

    if re.search(HTML_TAG_RE, clean_desc, re.IGNORECASE):
        clean_desc = _strip_html_lines(clean_desc)
    if dast_desc and re.search(HTML_TAG_RE, str(dast_desc), re.IGNORECASE):
        dast_desc = _strip_html_lines(str(dast_desc))

    # --- kolom terstruktur v2 ------------------------------------------------
    mitigation = _first(row, 'mitigation_text', 'comment_solution')
    if mitigation is None and "[MITIGATION]:" in str(dast_desc or ""):
        m = re.search(r'\[MITIGATION\]:\s*(.*)', str(dast_desc), re.DOTALL)
        mitigation = m.group(1).strip() if m else None
    sast_comp = _first(row, 'sast_component')
    dast_comp = _first(row, 'dast_component')
    is_hybrid = scanner_type in DSS_SCANNERS
    if is_hybrid and (sast_comp is None or dast_comp is None):
        s_part, _, d_part = str(comp).partition(" | ")
        sast_comp = sast_comp if sast_comp is not None else s_part.strip()
        dast_comp = dast_comp if dast_comp is not None else d_part.strip()
    is_tp = _first(row, 'is_true_positive', 'is_verified_true_positive')
    if isinstance(is_tp, str):
        is_tp = is_tp.strip().upper() in ("YES", "TRUE", "1")
    has_cwe = _first(row, 'has_cwe_tag')

    return ScanHistory(
        batch_id=str(batch_id), timestamp=now, scanner_type=str(scanner_type), key_id=str(k_id),
        cwe_id=str(c_id), component=str(comp), description=str(clean_desc), predicted_score=float(p_score),
        predicted_severity=str(p_sev), execution_duration=execution_duration, base_score=b_score,
        shap_base_value=sb_val, shap_total_pos=stp_val, shap_total_neg=stn_val, absent_vocab_bias=av_val,
        shap_predicted_score=sp_val, shap_positive=str(pos_str), shap_negative=str(neg_str),
        sast_description=str(sast_desc) if sast_desc is not None else None,
        dast_description=str(dast_desc) if dast_desc is not None else None,
        issue_type=_first(row, 'issue_type'),
        has_cwe_tag=bool(has_cwe) if has_cwe is not None else None,
        mitigation_text=str(mitigation).strip() if mitigation else None,
        sast_score=_first(row, 'sast_score'), dast_score=_first(row, 'dast_score'),
        is_true_positive=bool(is_tp) if is_tp is not None else None,
        sast_key_id=_first(row, 'sast_key_id', 'key_id_sast'), dast_key_id=_first(row, 'dast_key_id', 'key_id_dast'),
        sast_component=sast_comp, dast_component=dast_comp,
        decision_key=decision_key_for(c_id, sast_comp, dast_comp) if is_hybrid else None,
        model_version=model_version,
    )


def save_findings(session: Session, batch_id: str, scanner_type: str, records: Iterable[dict],
                  execution_duration: float | None = None, model_version: str | None = None) -> int:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = [build_row(batch_id, scanner_type, r, now, execution_duration, model_version) for r in records]
    session.add_all(rows)
    session.flush()
    return len(rows)


def row_to_dict(r: ScanHistory) -> dict:
    return {c.name: getattr(r, c.name) for c in ScanHistory.__table__.columns}


def list_by_scanner(session: Session, scanner_type: str) -> list[dict]:
    rows = session.scalars(select(ScanHistory).where(ScanHistory.scanner_type == scanner_type)
                           .order_by(ScanHistory.id.desc()))
    return [row_to_dict(r) for r in rows]


def list_batch(session: Session, batch_id: str) -> list[dict]:
    rows = session.scalars(select(ScanHistory).where(ScanHistory.batch_id == batch_id).order_by(ScanHistory.id))
    return [row_to_dict(r) for r in rows]


def list_batches(session: Session, scanner_type: str | None = None) -> list[dict]:
    stmt = select(ScanHistory.batch_id, ScanHistory.scanner_type, func.min(ScanHistory.timestamp),
                  func.count(), func.max(ScanHistory.id))
    if scanner_type:
        stmt = stmt.where(ScanHistory.scanner_type == scanner_type)
    stmt = stmt.group_by(ScanHistory.batch_id, ScanHistory.scanner_type).order_by(func.max(ScanHistory.id).desc())
    return [
        {"batch_id": b, "scanner_type": s, "timestamp": t, "count": c}
        for b, s, t, c, _ in session.execute(stmt).all()
    ]


def list_dss_batches(session: Session) -> list[dict]:
    """
    Mengembalikan sesi hasil korelasi yang dapat diprioritaskan DSS, terurut dari yang terbaru.

    Satu baris untuk setiap sesi HAST-*, baik yang memuat pasangan hybrid maupun yang seluruhnya berisi temuan
    pemindai tunggal (tidak ada CWE yang beririsan). `count` mencakup kedua jenis baris.
    """
    stmt = (select(ScanHistory.batch_id, func.min(ScanHistory.timestamp), func.count())
            .where(ScanHistory.scanner_type.in_(DSS_SCANNERS))
            .group_by(ScanHistory.batch_id).order_by(func.max(ScanHistory.id).desc()))
    return [{"batch_id": b, "timestamp": t, "count": c} for b, t, c in session.execute(stmt).all()]


def batch_stats(session: Session, limit: int = 30) -> list[dict]:
    """
    Mengembalikan statistik per batch untuk dasbor, terurut dari batch terbaru.

    Parameter:
        session: sesi basis data.
        limit: jumlah batch terbaru yang diambil.

    Mengembalikan:
        list dict berisi `batch_id`, `scanner_type`, `timestamp`, `count`, `avg_score`, `max_score`,
        `true_positive` (hanya bermakna untuk korelasi hybrid), dan `severity` (jumlah per kelas keparahan).
    """
    latest = select(ScanHistory.batch_id, ScanHistory.scanner_type, func.min(ScanHistory.timestamp),
                    func.count(), func.avg(ScanHistory.predicted_score), func.max(ScanHistory.predicted_score),
                    func.sum(case((ScanHistory.is_true_positive.is_(True), 1), else_=0)), func.max(ScanHistory.id))         .group_by(ScanHistory.batch_id, ScanHistory.scanner_type).order_by(func.max(ScanHistory.id).desc()).limit(limit)
    rows = session.execute(latest).all()
    if not rows:
        return []
    ids = [r[0] for r in rows]
    sev_stmt = select(ScanHistory.batch_id, ScanHistory.scanner_type, ScanHistory.predicted_severity, func.count())         .where(ScanHistory.batch_id.in_(ids))         .group_by(ScanHistory.batch_id, ScanHistory.scanner_type, ScanHistory.predicted_severity)
    severity: dict[tuple, dict] = {}
    for b, s, sev, n in session.execute(sev_stmt).all():
        severity.setdefault((b, s), {})[str(sev or "NONE").upper()] = n
    return [{
        "batch_id": b, "scanner_type": s, "timestamp": t, "count": c,
        "avg_score": round(avg, 2) if avg is not None else None,
        "max_score": round(mx, 2) if mx is not None else None,
        "true_positive": int(tp or 0), "severity": severity.get((b, s), {}),
    } for b, s, t, c, avg, mx, tp, _ in rows]


def scanner_types(session: Session) -> list[str]:
    return [s for (s,) in session.execute(select(distinct(ScanHistory.scanner_type)))]


def delete_batch(session: Session, batch_id: str) -> int:
    return session.execute(delete(ScanHistory).where(ScanHistory.batch_id == batch_id)).rowcount or 0


def clear_scanner(session: Session, scanner_type: str) -> int:
    # Temuan pemindai tunggal adalah bagian sesi hybrid; tanpa ikut dihapus, sesi parsial akan tersisa di DSS.
    types = DSS_SCANNERS if scanner_type == HYBRID_SCANNER else (scanner_type,)
    return session.execute(delete(ScanHistory).where(ScanHistory.scanner_type.in_(types))).rowcount or 0


SHAP_UPDATABLE = ("description", "base_score", "shap_base_value", "shap_total_pos", "shap_total_neg",
                  "absent_vocab_bias", "shap_predicted_score", "shap_positive", "shap_negative",
                  "sast_description", "dast_description")


def update_shap_fields(session: Session, updates: list[dict]) -> int:
    """Menyimpan nilai SHAP yang dihitung belakangan (sebelumnya ditulis oleh thread pekerja frontend)."""
    n = 0
    for u in updates:
        row = session.get(ScanHistory, int(u["id"]))
        if row is None:
            continue
        for f in SHAP_UPDATABLE:
            if f in u:
                setattr(row, f, u[f])
        n += 1
    session.flush()
    return n
