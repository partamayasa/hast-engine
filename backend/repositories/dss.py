# backend/repositories/dss.py
"""Persistensi run DSS, keputusan analis, dan jejak auditnya."""
import datetime
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import DssDecision, DssDecisionEvent, DssRun
from backend.dss.recommender import (
    ACTIONS, BUSINESS_IMPACT, CLOSED_STATUSES, EFFORT, LEVEL_MAX, LEVEL_MIN, PRIORITY_LABELS, PRIORITY_OF_ACTION, STATUSES,
)

DECIDABLE_FIELDS = ("chosen_action", "status", "reason", "asset_criticality", "remediation_effort", "sla_due_date",
                    "owner")


# --- Run ---------------------------------------------------------------------
def save_run(session: Session, run: dict) -> DssRun:
    row = DssRun(
        run_id=run["run_id"], batch_id=run["batch_id"], method=run["method"],
        weights_json=json.dumps(run["weights"]), criteria_json=json.dumps(run["criteria"], ensure_ascii=False),
        weighting_source=run.get("weighting_source"), config_hash=run.get("config_hash"),
        escalation_rate=run.get("escalation_rate"), model_version=run.get("model_version"),
        alternatives_count=len(run["items"]), result_json=json.dumps(run, ensure_ascii=False, default=str),
        created_by=run.get("created_by"),
    )
    session.add(row)
    session.flush()
    return row


def list_runs(session: Session, batch_id: str | None = None, limit: int = 50) -> list[dict]:
    stmt = select(DssRun).order_by(DssRun.created_at.desc()).limit(limit)
    if batch_id:
        stmt = stmt.where(DssRun.batch_id == batch_id)
    return [{
        "run_id": r.run_id, "batch_id": r.batch_id, "method": r.method,
        "weights": json.loads(r.weights_json), "weighting_source": r.weighting_source,
        "escalation_rate": r.escalation_rate, "alternatives_count": r.alternatives_count,
        "config_hash": r.config_hash, "created_by": r.created_by, "created_at": str(r.created_at),
    } for r in session.scalars(stmt)]


def get_run(session: Session, run_id: str) -> dict | None:
    r = session.get(DssRun, run_id)
    return json.loads(r.result_json) if r else None


def run_item(session: Session, run_id: str | None, decision_key: str, _cache: dict | None = None) -> dict | None:
    """Isu sebagaimana tercatat pada run yang disimpan (snapshot penjelasan skor), atau None."""
    if not run_id:
        return None
    cache = _cache if _cache is not None else {}
    if run_id not in cache:
        cache[run_id] = get_run(session, run_id)
    run = cache[run_id]
    if not run:
        return None
    return next((it for it in run.get("items", []) if it.get("decision_key") == decision_key), None)


def model_context(item: dict | None) -> dict | None:
    """Snapshot ringkas dan ramah audit atas penjelasan model mengenai isu (saat rekomendasi atau keputusan)."""
    exp = (item or {}).get("score_explanation")
    if not exp:
        return None
    return {
        "score_origin": exp.get("chain_text"),
        "model_reason": exp.get("model_reason"),
        "review_notes": [f["text"] for f in exp.get("review_flags", [])],
        "recommended_priority": (item.get("recommendation") or {}).get("priority"),
        "run_id": item.get("_run_id"),
    }


# --- Keputusan --------------------------------------------------------------
def get_decision(session: Session, decision_key: str) -> DssDecision | None:
    return session.scalar(select(DssDecision).where(DssDecision.decision_key == decision_key))


def decisions_by_keys(session: Session, keys: list[str]) -> dict[str, DssDecision]:
    if not keys:
        return {}
    rows = session.scalars(select(DssDecision).where(DssDecision.decision_key.in_(keys)))
    return {d.decision_key: d for d in rows}


def _event(session: Session, decision: DssDecision, event_type: str, actor: str | None, run_id: str | None = None,
           from_status=None, to_status=None, reason=None, payload=None) -> None:
    session.add(DssDecisionEvent(
        decision_id=decision.id, event_type=event_type, from_status=from_status, to_status=to_status,
        chosen_action=decision.chosen_action, recommended_action=decision.recommended_action,
        reason=reason, payload_json=json.dumps(payload, ensure_ascii=False, default=str) if payload else None,
        actor=actor, run_id=run_id,
    ))


def upsert_recommendation(session: Session, item: dict, batch_id: str, run_id: str, actor: str | None) -> DssDecision:
    """
    Mencatat rekomendasi sistem terbaru untuk satu identitas temuan.
    Kolom milik analis (chosen_action, status, reason, masukan kekritisan/upaya) TIDAK PERNAH diubah.
    """
    d = get_decision(session, item["decision_key"])
    rec = item["recommendation"]
    if d is None:
        d = DssDecision(
            decision_key=item["decision_key"], title=item.get("title"), cwe_id=item["cwe_id"],
            sast_component=item["sast_component"],
            dast_component=item["dast_component"], last_batch_id=batch_id, last_run_id=run_id,
            recommended_action=rec["action"], recommended_rule_id=rec["rule_id"], status="OPEN",
            sla_due_date=rec.get("sla_due_date"),
        )
        session.add(d)
        session.flush()
        _event(session, d, "RECOMMENDED", actor, run_id, to_status="OPEN",
               payload=_recommendation_payload(item, run_id))
        return d

    if item.get("title") and not d.title:
        d.title = item["title"]
    changed = d.recommended_action != rec["action"] or d.recommended_rule_id != rec["rule_id"]
    d.recommended_action, d.recommended_rule_id = rec["action"], rec["rule_id"]
    d.last_batch_id, d.last_run_id = batch_id, run_id
    payload = _recommendation_payload(item, run_id)
    new_due = rec.get("sla_due_date")
    if new_due and d.chosen_action is None and d.status not in CLOSED_STATUSES and not _sla_set_by_human(d):
        # Tenggat otomatis hanya boleh MENGETAT (rekomendasi naik prioritas), tidak pernah melonggar,
        # dan tidak pernah menimpa tenggat yang ditetapkan analis.
        if d.sla_due_date is None or (changed and new_due < d.sla_due_date):
            payload["sla_due_date"] = {"from": d.sla_due_date, "to": new_due}
            d.sla_due_date = new_due
    if changed or "sla_due_date" in payload:
        _event(session, d, "RECOMMENDED", actor, run_id, payload=payload)
    return d


def _recommendation_payload(item: dict, run_id: str) -> dict:
    """
    Menyusun payload peristiwa RECOMMENDED beserta snapshot penjelasan model saat rekomendasi diberikan.

    Parameter:
        item: issue hasil `dss.service.rank_batch` (memuat `recommendation` dan `score_explanation`).
        run_id: run DSS yang menghasilkan rekomendasi ini.

    Mengembalikan:
        dict berisi peringkat, nilai preferensi, ID aturan, dan `model_context` bila penjelasan tersedia.
    """
    payload = {"rank": item["rank"], "preference": item["preference"], "rule_id": item["recommendation"]["rule_id"]}
    ctx = model_context(item)
    if ctx:
        payload["model_context"] = {**ctx, "run_id": run_id}
    return payload


def _sla_set_by_human(d: DssDecision) -> bool:
    """Memeriksa jejak audit: apakah tenggat isu ini pernah diubah langsung oleh pengguna."""
    for e in d.events:
        if e.event_type in ("UPDATED", "DECIDED") and e.payload_json and "sla_due_date" in json.loads(e.payload_json):
            return True
    return False


def update_decision(session: Session, decision_key: str, changes: dict, actor: str) -> DssDecision:
    d = get_decision(session, decision_key)
    if d is None:
        raise LookupError("Keputusan untuk temuan ini belum ada. Jalankan ranking DSS terlebih dahulu.")
    if "chosen_action" in changes and changes["chosen_action"] not in (None, *ACTIONS):
        raise ValueError(f"Aksi tidak dikenal: {changes['chosen_action']}")
    if "status" in changes and changes["status"] not in STATUSES:
        raise ValueError(f"Status tidak dikenal: {changes['status']}")
    for f, lo, hi in (("asset_criticality", LEVEL_MIN, LEVEL_MAX), ("remediation_effort", LEVEL_MIN, LEVEL_MAX)):
        v = changes.get(f)
        if v is not None and not (lo <= int(v) <= hi):
            raise ValueError(f"Nilai {f} harus di antara {lo} dan {hi}.")
    if changes.get("sla_due_date"):
        datetime.date.fromisoformat(changes["sla_due_date"])

    before = {f: getattr(d, f) for f in DECIDABLE_FIELDS}
    for f in DECIDABLE_FIELDS:
        if f in changes:
            setattr(d, f, changes[f])
    after = {f: getattr(d, f) for f in DECIDABLE_FIELDS}
    diff = {f: {"from": before[f], "to": after[f]} for f in DECIDABLE_FIELDS if before[f] != after[f]}
    if not diff:
        return d
    if "chosen_action" in diff or "status" in diff:
        d.decided_by = actor
        d.decided_at = datetime.datetime.now()
    decided = "chosen_action" in diff or "status" in diff
    payload = dict(diff)
    if decided:
        # Snapshot sisi server atas penjelasan model yang dilihat analis (dari run terakhir yang disimpan).
        ctx = model_context(run_item(session, d.last_run_id, d.decision_key))
        if ctx:
            ctx["run_id"] = d.last_run_id
            payload["model_context"] = ctx
    _event(session, d, "DECIDED" if decided else "UPDATED", actor,
           d.last_run_id, from_status=before["status"], to_status=after["status"], reason=changes.get("reason"),
           payload=payload)
    session.flush()
    return d


def decision_to_dict(d: DssDecision) -> dict:
    effective = d.chosen_action or d.recommended_action or ""
    priority = PRIORITY_OF_ACTION.get(effective)
    overdue = bool(d.sla_due_date and d.status not in CLOSED_STATUSES
                   and d.sla_due_date < datetime.date.today().isoformat())
    return {
        "decision_key": d.decision_key, "title": d.title, "owner": d.owner,
        "priority": priority, "priority_label": PRIORITY_LABELS.get(priority) if priority else None,
        "recommended_priority": PRIORITY_OF_ACTION.get(d.recommended_action or ""),
        "is_closed": d.status in CLOSED_STATUSES, "is_overdue": overdue,
        "business_impact_label": BUSINESS_IMPACT.get(d.asset_criticality) if d.asset_criticality else None,
        "effort_label": EFFORT.get(d.remediation_effort) if d.remediation_effort else None,
        "cwe_id": d.cwe_id, "sast_component": d.sast_component,
        "dast_component": d.dast_component, "last_batch_id": d.last_batch_id, "last_run_id": d.last_run_id,
        "recommended_action": d.recommended_action,
        "recommended_action_label": ACTIONS.get(d.recommended_action or "", None),
        "recommended_rule_id": d.recommended_rule_id, "chosen_action": d.chosen_action,
        "chosen_action_label": ACTIONS.get(d.chosen_action or "", None), "status": d.status,
        "status_label": STATUSES.get(d.status, d.status), "reason": d.reason,
        "asset_criticality": d.asset_criticality, "remediation_effort": d.remediation_effort,
        "sla_due_date": d.sla_due_date, "decided_by": d.decided_by,
        "decided_at": str(d.decided_at) if d.decided_at else None,
        "updated_at": str(d.updated_at) if d.updated_at else None,
    }


def list_decisions(session: Session, batch_id: str | None = None, status: str | None = None) -> list[dict]:
    stmt = select(DssDecision).order_by(DssDecision.id)
    if batch_id:
        stmt = stmt.where(DssDecision.last_batch_id == batch_id)
    if status:
        stmt = stmt.where(DssDecision.status == status)
    return [decision_to_dict(d) for d in session.scalars(stmt)]


# Kunci payload jejak audit seluruhnya berbahasa Inggris; data lama dinormalkan oleh migrasi 0004.
def _event_changes(payload_json: str | None) -> dict | None:
    """Mengembalikan perubahan kolom pada suatu peristiwa audit (tanpa konteks model)."""
    if not payload_json:
        return None
    return {k: v for k, v in json.loads(payload_json).items() if k != "model_context"}


def _event_model_context(payload_json: str | None) -> dict | None:
    """Mengembalikan konteks model yang tercatat pada suatu peristiwa audit, atau None."""
    if not payload_json:
        return None
    return json.loads(payload_json).get("model_context") or None


def list_events(session: Session, decision_key: str) -> list[dict]:
    d = get_decision(session, decision_key)
    if d is None:
        return []
    return [{
        "event_type": e.event_type, "from_status": e.from_status, "to_status": e.to_status,
        "chosen_action": e.chosen_action, "recommended_action": e.recommended_action, "reason": e.reason,
        "changes": _event_changes(e.payload_json),
        "model_context": _event_model_context(e.payload_json),
        "actor": e.actor, "run_id": e.run_id,
        "created_at": str(e.created_at),
    } for e in d.events]
