"""Pengisian ulang konteks model pada peristiwa RECOMMENDED yang sudah tersimpan.

Sejak revisi ini, setiap peristiwa "Rekomendasi sistem" menyimpan snapshot penjelasan model (`model_context`).
Peristiwa lama diisi dari run DSS yang menghasilkannya (`dss_decision_events.run_id` → `dss_runs.result_json`,
item dengan `decision_key` yang sama), sehingga isinya sama dengan yang dihitung saat rekomendasi diberikan.
Peristiwa yang run-nya tidak ditemukan atau tidak memuat penjelasan dibiarkan apa adanya.

Idempoten: peristiwa yang sudah memiliki `model_context` tidak diubah.

Revision ID: 0005_recommendation_model_context
Revises: 0004_english_payload_keys
Create Date: 2026-11-19
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0005_recommendation_model_context"
down_revision = "0004_english_payload_keys"
branch_labels = None
depends_on = None


def context_from_item(item: dict, run_id: str) -> dict | None:
    """Menyusun snapshot konteks model dari item run (format sama dengan `repositories.dss.model_context`)."""
    exp = item.get("score_explanation")
    if not exp:
        return None
    return {
        "score_origin": exp.get("chain_text"),
        "model_reason": exp.get("model_reason"),
        "review_notes": [f["text"] for f in exp.get("review_flags", [])],
        "recommended_priority": (item.get("recommendation") or {}).get("priority"),
        "run_id": run_id,
    }


def upgrade() -> None:
    conn = op.get_bind()
    tables = set(sa.inspect(conn).get_table_names())
    if not {"dss_decision_events", "dss_decisions", "dss_runs"} <= tables:
        return
    rows = conn.execute(sa.text(
        "SELECT e.id, e.payload_json, e.run_id, d.decision_key FROM dss_decision_events e "
        "JOIN dss_decisions d ON d.id = e.decision_id "
        "WHERE e.event_type = 'RECOMMENDED' AND e.run_id IS NOT NULL")).fetchall()
    runs: dict[str, dict] = {}
    for event_id, payload_json, run_id, decision_key in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except ValueError:
            continue
        if not isinstance(payload, dict) or payload.get("model_context"):
            continue
        if run_id not in runs:
            raw = conn.execute(sa.text("SELECT result_json FROM dss_runs WHERE run_id = :r"), {"r": run_id}).scalar()
            try:
                result = json.loads(raw) if raw else {}
            except ValueError:
                result = {}
            runs[run_id] = {it.get("decision_key"): it for it in result.get("items", []) if isinstance(it, dict)}
        item = runs[run_id].get(decision_key)
        ctx = context_from_item(item, run_id) if item else None
        if not ctx:
            continue
        payload["model_context"] = ctx
        conn.execute(sa.text("UPDATE dss_decision_events SET payload_json = :p WHERE id = :i"),
                     {"p": json.dumps(payload, ensure_ascii=False, default=str), "i": event_id})


def downgrade() -> None:
    pass
