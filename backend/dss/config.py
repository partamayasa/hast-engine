# backend/dss/config.py
"""Memuat, memvalidasi, dan menyimpan konfigurasi DSS (backend/config/dss_config.json, dengan sampel sebagai cadangan)."""
import copy
import hashlib
import json
from pathlib import Path

from backend.core.settings import get_settings
from backend.dss.criteria import SUPPORTED_CRITERIA
from backend.dss.mcdm import METHODS, normalize_weights
from backend.dss.recommender import ACTIONS

WEIGHTING_SOURCES = ("config", "ahp", "manual", "entropy")


def _paths() -> tuple[Path, Path]:
    s = get_settings()
    return s.dss_config_path, s.dss_config_sample_path


def load_dss_config() -> dict:
    runtime, sample = _paths()
    path = runtime if runtime.exists() else sample
    if not path.exists():
        raise FileNotFoundError(f"Konfigurasi DSS tidak ditemukan ({runtime} / {sample}).")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    validate_dss_config(cfg)
    cfg["_source_file"] = path.name
    return cfg


def validate_dss_config(cfg: dict) -> None:
    if cfg.get("method", "").upper() not in METHODS:
        raise ValueError(f"Metode DSS harus salah satu dari: {', '.join(METHODS)}")
    crit = cfg.get("criteria") or []
    if not crit:
        raise ValueError("Konfigurasi DSS harus memiliki minimal satu kriteria.")
    seen = set()
    for c in crit:
        for f in ("key", "label", "direction", "weight"):
            if f not in c:
                raise ValueError(f"Kriteria DSS tidak lengkap (kolom '{f}' hilang): {c}")
        if c["key"] not in SUPPORTED_CRITERIA:
            raise ValueError(f"Kriteria tidak didukung: {c['key']}")
        if c["key"] in seen:
            raise ValueError(f"Kriteria ganda: {c['key']}")
        seen.add(c["key"])
        if c["direction"] not in ("benefit", "cost"):
            raise ValueError(f"Arah kriteria {c['key']} harus 'benefit' atau 'cost'.")
    enabled = [c for c in crit if c.get("enabled", True)]
    if not enabled:
        raise ValueError("Minimal satu kriteria harus aktif.")
    normalize_weights([float(c["weight"]) for c in enabled])
    rules = cfg.get("recommendation_rules") or []
    if not rules or rules[-1].get("when") not in ({}, None):
        raise ValueError("Aturan rekomendasi terakhir harus berupa aturan penampung (when: {}).")
    for r in rules:
        if r.get("action") not in ACTIONS:
            raise ValueError(f"Aksi tidak dikenal pada aturan {r.get('id')}: {r.get('action')}")
        if r.get("priority") is not None and r["priority"] not in ("P1", "P2", "P3", "P4"):
            raise ValueError(f"Prioritas pada aturan {r.get('id')} harus P1, P2, P3, atau P4.")
    if cfg.get("weighting_source", "config") not in WEIGHTING_SOURCES:
        raise ValueError(f"Sumber bobot harus salah satu dari: {', '.join(WEIGHTING_SOURCES)}")
    review = cfg.get("review") or {}
    for k in ("threshold_margin", "min_text_evidence"):
        if k in review and (not isinstance(review[k], (int, float)) or review[k] < 0):
            raise ValueError(f"Nilai review.{k} harus angka >= 0.")
    for k, v in (cfg.get("sla_days") or {}).items():
        if v is not None and (not isinstance(v, int) or v < 0):
            raise ValueError(f"Nilai SLA untuk {k} harus bilangan bulat >= 0 atau null.")


def save_dss_config(cfg: dict) -> dict:
    cfg = copy.deepcopy(cfg)
    cfg.pop("_source_file", None)
    validate_dss_config(cfg)
    runtime, _ = _paths()
    runtime.parent.mkdir(parents=True, exist_ok=True)
    tmp = runtime.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    tmp.replace(runtime)
    return load_dss_config()


def config_hash(cfg: dict) -> str:
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return hashlib.sha256(json.dumps(clean, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
