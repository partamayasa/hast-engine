# backend/services/identity.py
"""Identitas stabil untuk temuan, tidak bergantung pada Pair ID acak per run."""
import hashlib


def normalise_cwe(cwe_id) -> str:
    return str(cwe_id or "").strip().upper()


def decision_key_for(cwe_id, sast_component, dast_component) -> str:
    """
    SHA-256 dari 'CWE|sast_component|dast_component' (dinormalisasi).

    Pair ID (PAIR-XXXXXXXX) dibuat ulang setiap kali korelasi dijalankan, sehingga keputusan
    analis dikaitkan dengan identitas alami ini.
    """
    raw = "|".join([
        normalise_cwe(cwe_id),
        str(sast_component or "").strip(),
        str(dast_component or "").strip(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
