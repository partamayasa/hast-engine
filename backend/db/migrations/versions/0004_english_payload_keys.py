"""Penyeragaman kunci data JSON tersimpan ke bahasa Inggris (lanjutan Fase 11).

Jejak audit dan run DSS yang tercatat sebelum penyeragaman nama masih memakai kunci berbahasa Indonesia.
Revisi ini menulis ulang kunci tersebut sehingga kode tidak lagi memerlukan penerjemah kunci lama:
- dss_decision_events.payload_json: konteks_model -> model_context (beserta kunci di dalamnya) dan
  diff {dari, menjadi} -> {from, to};
- dss_runs.result_json: kode imputasi per isu (items[].imputed).

Idempoten: baris yang sudah berkunci bahasa Inggris tidak berubah.

Revision ID: 0004_english_payload_keys
Revises: 0003_issue_decisions
Create Date: 2026-11-19
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0004_english_payload_keys"
down_revision = "0003_issue_decisions"
branch_labels = None
depends_on = None

CONTEXT_KEYS = {"asal_skor": "score_origin", "alasan_model": "model_reason",
                "perlu_dicek": "review_notes", "prioritas_rekomendasi": "recommended_priority"}
IMPUTATION_CODES = {"cwe_tidak_ada_di_lookup": "cwe_not_in_lookup", "tidak_tersimpan_v1": "not_stored_v1",
                    "default_konfigurasi": "config_default"}


def normalise_event_payload(payload: dict) -> dict:
    """Mengembalikan salinan payload jejak audit dengan seluruh kunci lama diganti kunci bahasa Inggris."""
    out = {}
    for key, value in payload.items():
        if key == "konteks_model":
            key = "model_context"
        if key == "model_context" and isinstance(value, dict):
            value = {CONTEXT_KEYS.get(k, k): v for k, v in value.items()}
        elif isinstance(value, dict) and ("dari" in value or "menjadi" in value):
            value = {"from": value.get("dari"), "to": value.get("menjadi")}
        if key == "model_context" and "model_context" in out:
            continue  # kunci baru sudah ada; pertahankan yang baru
        out[key] = value
    return out


def normalise_run_result(result: dict) -> dict:
    """Mengembalikan salinan hasil run DSS dengan kode imputasi lama diganti kode bahasa Inggris."""
    items = []
    for item in result.get("items", []):
        imputed = item.get("imputed")
        if isinstance(imputed, dict):
            item = {**item, "imputed": {k: IMPUTATION_CODES.get(v, v) for k, v in imputed.items()}}
        items.append(item)
    return {**result, "items": items} if "items" in result else result


def _rewrite(conn, table: str, key_col: str, json_col: str, transform) -> None:
    rows = conn.execute(sa.text(f"SELECT {key_col}, {json_col} FROM {table} WHERE {json_col} IS NOT NULL")).fetchall()
    for row_key, raw in rows:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        new = transform(data)
        if new != data:
            conn.execute(sa.text(f"UPDATE {table} SET {json_col} = :v WHERE {key_col} = :k"),
                         {"v": json.dumps(new, ensure_ascii=False, default=str), "k": row_key})


def upgrade() -> None:
    conn = op.get_bind()
    tables = set(sa.inspect(conn).get_table_names())
    if "dss_decision_events" in tables:
        _rewrite(conn, "dss_decision_events", "id", "payload_json", normalise_event_payload)
    if "dss_runs" in tables:
        _rewrite(conn, "dss_runs", "run_id", "result_json", normalise_run_result)


def downgrade() -> None:
    pass
