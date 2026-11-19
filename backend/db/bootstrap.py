# backend/db/bootstrap.py
"""
Inisialisasi basis data: migrasi Alembic + langkah data yang sebelumnya berada di init_db() frontend.

Langkah data lama (pemindahan tag ke kolom, pembersihan HTML, pengisian nilai bawaan) di-port apa adanya
dari v1.0.0-tesis sehingga basis data yang sudah ada berperilaku sama. Lihat
docs/CATATAN_PERUBAHAN_DSS.md untuk keputusan terbuka mengenai metrik bawaan yang diisikan.
"""
import json
import re
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from backend.core.settings import ROOT_DIR, get_settings
from backend.db.session import get_engine

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_INITIALISED: set[str] = set()

TAG_STRIP_RE = (
    r'(?:\r?\n|\s+)\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|ABSENT_VOCAB|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$'
)
PAIR_PREFIX_RE = r'^(?:PAIR-)?[A-Fa-f0-9]{8}\s*-\s*'
HTML_TAG_RE = r'</?(?:p|b|i|u|br|ul|ol|li|div|span|a|em|strong)[^>]*>'


def run_migrations(database_url: str) -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["database_url"] = database_url
    engine = get_engine(database_url)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")


def _backfill_tagged_descriptions(conn) -> None:
    """Lama: memindahkan tag [BASE_SCORE]/[SHAP_*] dari deskripsi ke kolom khusus."""
    rows = conn.execute(text(
        "SELECT id, scanner_type, description, predicted_score FROM scan_history "
        "WHERE description LIKE '%[BASE_SCORE]%' OR description LIKE '%[SHAP_%'"
    )).fetchall()
    for r_id, s_type, raw_desc, pred_score in rows:
        raw_text = str(raw_desc or "")

        def num(pattern, default):
            m = re.search(pattern, raw_text)
            return float(m.group(1)) if m else default

        b_score = num(r'\[BASE_SCORE\]:\s*([\d\.]+)', float(pred_score) if pred_score is not None else 0.0)
        sb_val = num(r'\[SHAP_BASE\]:\s*([\-\d\.]+)', 0.0)
        stp_val = num(r'\[SHAP_TOT_POS\]:\s*([\-\d\.]+)', 0.0)
        stn_val = num(r'\[SHAP_TOT_NEG\]:\s*([\-\d\.]+)', 0.0)
        sp_val = num(r'\[SHAP_PRED\]:\s*([\-\d\.]+)', b_score)
        av_val = num(r'\[ABSENT_VOCAB\]:\s*([\-\d\.]+)', 0.0)
        pos_m = re.search(r'\[SHAP_POS\]:\s*(.*?)(?=(?:\r?\n|\s*)\[SHAP_NEG\]:|$)', raw_text, re.DOTALL)
        pos_str = pos_m.group(1).strip() if pos_m else "N/A"
        neg_m = re.search(r'\[SHAP_NEG\]:\s*(.*?)(?=$)', raw_text, re.DOTALL)
        neg_str = neg_m.group(1).strip() if neg_m else "N/A"

        clean_d = re.sub(TAG_STRIP_RE, '', raw_text, flags=re.DOTALL).strip()
        clean_d = re.sub(PAIR_PREFIX_RE, '', clean_d).strip()

        sast_c = dast_c = None
        if "Hybrid" in str(s_type) or "[SAST]:" in clean_d:
            sm = re.search(r'\[SAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[DAST\]:|$)', clean_d, re.DOTALL)
            dm = re.search(r'\[DAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[MITIGATION\]:|$)', clean_d, re.DOTALL)
            sast_c = sm.group(1).strip() if sm else None
            dast_c = dm.group(1).strip() if dm else None
        elif "SAST" in str(s_type) or "SonarQube" in str(s_type):
            sast_c = clean_d
        elif "DAST" in str(s_type) or "OWASP ZAP" in str(s_type):
            dast_c = clean_d

        conn.execute(text(
            "UPDATE scan_history SET description=:d, base_score=:b, shap_base_value=:sb, shap_total_pos=:tp, "
            "shap_total_neg=:tn, absent_vocab_bias=:av, shap_predicted_score=:sp, shap_positive=:pos, "
            "shap_negative=:neg, sast_description=:sd, dast_description=:dd WHERE id=:id"
        ), dict(d=clean_d, b=b_score, sb=sb_val, tp=stp_val, tn=stn_val, av=av_val, sp=sp_val,
                pos=pos_str, neg=neg_str, sd=sast_c, dd=dast_c, id=r_id))


def _strip_html(value: str) -> str:
    c = re.sub(r'<[^>]*>', ' ', value)
    lines = [re.sub(r'[ \t]+', ' ', line).strip() for line in c.splitlines()]
    return "\n".join([l for l in lines if l]).strip()


def _backfill_html(conn) -> None:
    """Lama: membersihkan tag HTML yang tertinggal di deskripsi dari impor ZAP versi awal."""
    rows = conn.execute(text(
        "SELECT id, description, dast_description FROM scan_history "
        "WHERE description LIKE '%<%' OR dast_description LIKE '%<%'"
    )).fetchall()
    for h_id, h_desc, h_dast in rows:
        new_desc, new_dast = h_desc, h_dast
        if re.search(HTML_TAG_RE, str(h_desc or ''), re.IGNORECASE):
            new_desc = _strip_html(str(h_desc or ''))
        if re.search(HTML_TAG_RE, str(h_dast or ''), re.IGNORECASE):
            new_dast = _strip_html(str(h_dast or ''))
        if new_desc != h_desc or new_dast != h_dast:
            conn.execute(text("UPDATE scan_history SET description=:d, dast_description=:dd WHERE id=:id"),
                         dict(d=new_desc, dd=new_dast, id=h_id))


def _backfill_structured_columns(conn) -> None:
    """v2: menurunkan kolom terstruktur untuk baris yang disimpan sebelum revisi 0002 (tanpa menghitung ulang skor)."""
    from backend.services.identity import decision_key_for

    rows = conn.execute(text(
        "SELECT id, scanner_type, description, dast_description, component, cwe_id FROM scan_history "
        "WHERE mitigation_text IS NULL AND description LIKE '%[MITIGATION]:%'"
    )).fetchall()
    for r_id, _s_type, desc, _dast, _comp, _cwe in rows:
        m = re.search(r'\[MITIGATION\]:\s*(.*)', str(desc or ''), re.DOTALL)
        if m:
            conn.execute(text("UPDATE scan_history SET mitigation_text=:m WHERE id=:id"),
                         dict(m=re.sub(r'<[^>]*>', '', m.group(1)).strip(), id=r_id))

    rows = conn.execute(text(
        "SELECT id, component, cwe_id FROM scan_history "
        "WHERE scanner_type = 'Pengujian Korelasi Hybrid' AND decision_key IS NULL"
    )).fetchall()
    for r_id, comp, cwe in rows:
        sast_comp, _, dast_comp = str(comp or "").partition(" | ")
        conn.execute(text(
            "UPDATE scan_history SET sast_component=:s, dast_component=:d, decision_key=:k WHERE id=:id"
        ), dict(s=sast_comp.strip(), d=dast_comp.strip(),
                k=decision_key_for(cwe, sast_comp.strip(), dast_comp.strip()), id=r_id))


def _seed_research_defaults(conn) -> None:
    """
    Lama (apa adanya dari init_db v1): mengisi tabel riset bila masih kosong.

    CATATAN: nilai tertanam ini tidak sama dengan ai-model/data/model_training_result.json.
    Nilai dipertahankan agar perilaku v1 tidak berubah; lihat keputusan terbuka di catatan perubahan.
    """
    if conn.execute(text("SELECT COUNT(*) FROM dataset_metadata")).scalar() == 0:
        conn.execute(text(
            "INSERT OR REPLACE INTO dataset_metadata (id, total_samples, train_samples, test_samples, train_ratio, "
            "test_ratio, mean_score, std_score, min_score, max_score, validation_scheme, updated_at) VALUES "
            "(1, 34194, 27355, 6839, 0.8, 0.2, 6.185, 2.340, 0.0, 10.0, 'Train-Test Split (80:20)', datetime('now'))"
        ))
        for s_name, c_cnt, c_prop, s_rng in [
            ("MEDIUM", 14563, 42.59, "4.0 - 6.9"), ("HIGH", 10830, 31.67, "7.0 - 8.9"),
            ("LOW", 5721, 16.73, "0.1 - 3.9"), ("CRITICAL", 3020, 8.83, "9.0 - 10.0"), ("NONE", 60, 0.18, "0.0"),
        ]:
            conn.execute(text(
                "INSERT OR REPLACE INTO dataset_class_distribution (severity, count, proportion, score_range) "
                "VALUES (:s, :c, :p, :r)"), dict(s=s_name, c=c_cnt, p=c_prop, r=s_rng))

    if conn.execute(text("SELECT COUNT(*) FROM model_evaluation_metrics")).scalar() == 0:
        cm_default = [[3015, 1634, 154, 91], [726, 9814, 1524, 312], [63, 2442, 5311, 394], [1, 409, 1334, 479]]
        shap_default = {
            "site": 0.3521, "unauthenticated": 0.2345, "code": 0.1791, "scripting": 0.1305, "execute": 0.1197,
            "privileges": 0.1030, "arbitrary": 0.0764, "authentication": 0.0739, "cross": 0.0575,
            "manipulation": 0.0549,
        }
        conn.execute(text(
            "INSERT OR REPLACE INTO model_evaluation_metrics (algorithm, accuracy, precision, recall, f1_score, mae, "
            "rmse, r2_score, training_time_seconds, confusion_matrix_json, shap_features_json, updated_at) VALUES "
            "(:a, :acc, :p, :r, :f1, :mae, :rmse, :r2, :t, :cm, :sh, datetime('now'))"
        ), dict(a="Random Forest Regressor", acc=0.6707, p=0.4966, r=0.4543, f1=0.4683, mae=1.0678, rmse=1.5076,
                r2=0.5848, t=40.84, cm=json.dumps(cm_default), sh=json.dumps(shap_default)))


def _bootstrap_admin(database_url: str) -> None:
    settings = get_settings()
    if not (settings.admin_username and settings.admin_password):
        return
    from backend.db.session import session_scope
    from backend.repositories import users as users_repo

    with session_scope(database_url) as s:
        if users_repo.count_users(s) == 0:
            users_repo.create_user(s, settings.admin_username, settings.admin_password, role="admin",
                                   full_name="Administrator")


def init_database(database_url: str | None = None, force: bool = False) -> str:
    """Migrasi + backfill + seed. Aman dipanggil berulang; hasilnya di-cache per URL dalam satu proses."""
    url = database_url or get_settings().database_url
    if url in _INITIALISED and not force:
        return url
    run_migrations(url)
    engine = get_engine(url)
    with engine.begin() as conn:
        for step in (_backfill_tagged_descriptions, _backfill_html, _backfill_structured_columns,
                     _seed_research_defaults):
            try:
                step(conn)
            except Exception as exc:  # mempertahankan semantik v1: langkah data tidak pernah menghentikan startup
                print(f"-> [DB bootstrap warning] {step.__name__}: {exc}")
    _bootstrap_admin(url)
    _INITIALISED.add(url)
    return url


__all__ = ["init_database", "run_migrations", "ROOT_DIR"]
