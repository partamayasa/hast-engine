# backend/services/parsers/sonar_cwe_mapper.py
# Dipindah dari frontend/utils/sonar_cwe_mapper.py (v2): resolusi CWE adalah urusan backend.
import os
import json
import re
import requests
from backend.core.settings import get_settings

_SETTINGS = get_settings()
SONAR_RULES_CACHE_PATH = str(_SETTINGS.sonar_rules_cache_path)
SONAR_RULES_CWE_PATH = str(_SETTINGS.sonar_rules_cache_path.with_name("sonar_rules_cwe.json"))
DEFAULT_SONAR_HOST = "http://localhost:9000"
SONAR_HOST_URL = _SETTINGS.sonar_host_url.rstrip("/")
SONAR_TOKEN = _SETTINGS.sonar_token

_MAPPINGS_CACHE = None
_FULL_METADATA_CACHE = None

SPECIFIC_CWE_PRIORITY = {
    "CWE-614": 100,
    "CWE-1004": 100,
    "CWE-1275": 100,
    "CWE-89": 100,
    "CWE-78": 100,
    "CWE-79": 100,
    "CWE-352": 100,
    "CWE-497": 100,
    "CWE-798": 100,
    "CWE-601": 100,
    "CWE-1021": 100,
    "CWE-732": 95,
    "CWE-400": 90,
    "CWE-770": 90,
    "CWE-327": 90,
    "CWE-1240": 85,
    "CWE-200": 30,
    "CWE-693": 30,
    "CWE-315": 20,
    "CWE-311": 10,
    "CWE-266": 10,
}


def pick_primary_cwe(cwes) -> str:
    """
    Memilih CWE-ID utama yang paling spesifik dari daftar CWE.
    Menghindari CWE payung yang umum (seperti CWE-311) bila CWE spesifik (seperti CWE-614) tersedia.
    """
    if not cwes:
        return "N/A"
    if isinstance(cwes, str):
        clean = cwes.strip().upper()
        return clean if clean else "N/A"
    if isinstance(cwes, (list, tuple)):
        valid_cwes = [str(c).strip().upper() for c in cwes if str(c).strip() and str(c).strip().upper() != "N/A"]
        if not valid_cwes:
            return "N/A"
        # Utamakan bobot tertinggi; bila bobot sama, pertahankan urutan awal
        return max(valid_cwes, key=lambda c: SPECIFIC_CWE_PRIORITY.get(c, 50))
    return str(cwes).strip().upper() or "N/A"


def get_sonar_config(sonar_host: str = None, token: str = None) -> tuple[str, str]:
    """Mengambil Host URL dan Token SonarQube dengan urutan prioritas: argumen, .env, nilai bawaan."""
    env_host = os.getenv("SONAR_HOST_URL", SONAR_HOST_URL)
    env_token = os.getenv("SONAR_TOKEN", SONAR_TOKEN)
    host = (sonar_host or env_host or DEFAULT_SONAR_HOST).strip().rstrip("/")
    auth_token = (token or env_token or "").strip()
    return host, auth_token


def load_sonar_cwe_mappings(force_reload: bool = False) -> dict:
    """
    Membaca pemetaan Rule SonarQube ke CWE ID dari berkas cache dinamis (sonar_rules_cache.json)
    atau, sebagai cadangan, dari berkas aturan bawaan (sonar_rules_cwe.json / sampel).
    """
    global _MAPPINGS_CACHE, _FULL_METADATA_CACHE
    if _MAPPINGS_CACHE is not None and not force_reload:
        return _MAPPINGS_CACHE

    _MAPPINGS_CACHE = {}
    _FULL_METADATA_CACHE = {}

    # 1. Coba baca dari berkas cache dinamis lebih dulu
    target_cache = SONAR_RULES_CACHE_PATH
    if not os.path.exists(target_cache):
        sample_cache = SONAR_RULES_CACHE_PATH.replace(".json", ".sample.json")
        if os.path.exists(sample_cache):
            target_cache = sample_cache

    if os.path.exists(target_cache):
        try:
            with open(target_cache, "r", encoding="utf-8") as f:
                data = json.load(f)
                mappings = data.get("mappings", data)
                if isinstance(mappings, dict):
                    for k, v in mappings.items():
                        if isinstance(v, dict):
                            # Format metadata lengkap
                            _FULL_METADATA_CACHE[k] = v
                            cwes = v.get("cwe") or v.get("CWE") or []
                            if cwes:
                                _MAPPINGS_CACHE[k] = pick_primary_cwe(cwes)
                        elif isinstance(v, (str, list)):
                            _MAPPINGS_CACHE[k] = pick_primary_cwe(v)

                # Muat bagian metadata lengkap bila tersedia di JSON cache
                metadata = data.get("metadata", {})
                if isinstance(metadata, dict):
                    _FULL_METADATA_CACHE.update(metadata)

            if _MAPPINGS_CACHE:
                return _MAPPINGS_CACHE
        except Exception as e:
            print(f"-> [Peringatan]: Gagal membaca cache {target_cache}: {e}")

    # 2. Cadangan ke sonar_rules_cwe.json bila cache belum tersedia
    target_path = SONAR_RULES_CWE_PATH
    if not os.path.exists(target_path):
        sample_path = SONAR_RULES_CWE_PATH.replace(".json", ".sample.json")
        if os.path.exists(sample_path):
            target_path = sample_path

    if os.path.exists(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                mappings = data.get("mappings", data)
                if isinstance(mappings, dict):
                    for k, v in mappings.items():
                        if isinstance(v, dict):
                            _FULL_METADATA_CACHE[k] = v
                            cwes = v.get("cwe") or v.get("CWE") or []
                            if cwes:
                                _MAPPINGS_CACHE[k] = pick_primary_cwe(cwes)
                        elif isinstance(v, (str, list)):
                            _MAPPINGS_CACHE[k] = pick_primary_cwe(v)
        except Exception as e:
            print(f"-> [Peringatan]: Gagal membaca {target_path}: {e}")

    # Kamus cadangan bawaan untuk aturan standar SonarSource
    builtin_fallbacks = {
        "php:S3330": "CWE-1004",
        "S3330": "CWE-1004",
        "php:S2092": "CWE-614",
        "S2092": "CWE-614",
        "php:S4502": "CWE-352",
        "S4502": "CWE-352",
        "php:S4507": "CWE-497",
        "S4507": "CWE-497",
        "Web:S6819": "CWE-693",
        "S6819": "CWE-693",
        "php:S6341": "CWE-79",
        "S6341": "CWE-79",
        "php:S6348": "CWE-79",
        "S6348": "CWE-79",
        "php:S2068": "CWE-798",
        "S2068": "CWE-798",
        "php:S4790": "CWE-327",
        "S4790": "CWE-327",
        "php:S2612": "CWE-732",
        "S2612": "CWE-732",
        "javascript:S2245": "CWE-338",
        "S2245": "CWE-338",
    }
    for k, v in builtin_fallbacks.items():
        if k not in _MAPPINGS_CACHE:
            _MAPPINGS_CACHE[k] = v

    return _MAPPINGS_CACHE


def save_sonar_rule_to_cache(rule_key: str, metadata: dict) -> None:
    """Menyimpan metadata aturan yang baru diambil dari API SonarQube ke cache lokal."""
    global _MAPPINGS_CACHE, _FULL_METADATA_CACHE
    if _MAPPINGS_CACHE is None:
        load_sonar_cwe_mappings()

    if _FULL_METADATA_CACHE is None:
        _FULL_METADATA_CACHE = {}

    _FULL_METADATA_CACHE[rule_key] = metadata
    cwes = metadata.get("cwe") or []
    cwe_val = pick_primary_cwe(cwes) if cwes else "N/A"
    _MAPPINGS_CACHE[rule_key] = cwe_val
    # Simpan juga format kunci pendek, mis. 'S3330' dari 'php:S3330'
    rule_m = re.search(r"S\d+", rule_key)
    if rule_m:
        _MAPPINGS_CACHE[rule_m.group(0)] = cwe_val

    # Simpan secara permanen ke berkas cache
    try:
        os.makedirs(os.path.dirname(SONAR_RULES_CACHE_PATH), exist_ok=True)
        cache_data = {
            "_description": "Cache otomatis metadata dan pemetaan SonarQube Rule ke MITRE CWE ID via SonarQube API",
            "mappings": _MAPPINGS_CACHE,
            "metadata": _FULL_METADATA_CACHE
        }
        with open(SONAR_RULES_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"-> [Peringatan]: Gagal menyimpan cache ke {SONAR_RULES_CACHE_PATH}: {e}")


def extract_metadata_from_rule_payload(rule_obj: dict, rule_key: str = "") -> dict:
    """Mengekstrak CWE ID dan kategori OWASP dari objek respons JSON aturan SonarQube."""
    cwes = []
    owasps = []

    rule_name = rule_obj.get("name", "")
    rule_type = rule_obj.get("type", "")
    rule_severity = rule_obj.get("severity", "")

    # a. Ekstrak dari descriptionSections (resources)
    sections = rule_obj.get("descriptionSections", [])
    if isinstance(sections, list):
        for sec in sections:
            if isinstance(sec, dict) and sec.get("key") == "resources":
                content = sec.get("content", "")
                if content:
                    # Regex untuk CWE-ID: CWE-(\d+)
                    for m in re.finditer(r"CWE-(\d+)", content, re.IGNORECASE):
                        cwe_item = f"CWE-{m.group(1)}"
                        if cwe_item not in cwes:
                            cwes.append(cwe_item)

                    # Regex untuk OWASP Top 10
                    for m in re.finditer(r"(Top 10 \d{4} Category A\d+|Category A\d+[^<]*)", content, re.IGNORECASE):
                        clean_owasp = m.group(1).strip()
                        if clean_owasp and clean_owasp not in owasps:
                            owasps.append(clean_owasp)

    # b. Ekstrak dari sysTags dan tags bila berformat cwe-xxx
    all_tags = []
    sys_tags = rule_obj.get("sysTags")
    tags = rule_obj.get("tags")
    if isinstance(sys_tags, list):
        all_tags.extend(sys_tags)
    if isinstance(tags, list):
        all_tags.extend(tags)

    for t in all_tags:
        m = re.match(r"^cwe-(\d+)$", str(t), re.IGNORECASE)
        if m:
            cwe_tag = f"CWE-{m.group(1)}"
            if cwe_tag not in cwes:
                cwes.append(cwe_tag)

    # c. Cadangan ke kunci aturan bila langsung memuat pola CWE (mis. php:CWE-89)
    if not cwes and rule_key:
        m = re.search(r"cwe-(\d+)", rule_key, re.IGNORECASE)
        if m:
            cwes.append(f"CWE-{m.group(1)}")

    return {
        "rule_key": rule_key,
        "name": rule_name,
        "type": rule_type,
        "severity": rule_severity,
        "cwe": cwes,
        "owasp": owasps,
    }


def fetch_sonar_rule_metadata(
    rule_key: str,
    sonar_host: str = None,
    token: str = None,
    timeout: int = 10
) -> dict:
    """
    Memanggil SonarQube Web API /api/rules/show?key=<rule_key>
    untuk memperoleh nama aturan, tipe, tingkat keparahan, CWE-ID, dan metadata standar OWASP.
    """
    host, auth_token = get_sonar_config(sonar_host, token)
    rule_url = f"{host}/api/rules/show?key={rule_key}"

    # Gunakan HTTP Basic Auth dengan Token SonarQube (token sebagai username, kata sandi kosong)
    auth = (auth_token, "") if auth_token else None

    try:
        res = requests.get(rule_url, auth=auth, timeout=timeout)
        if res.status_code == 200:
            payload = res.json()
            rule_obj = payload.get("rule", {})
            metadata = extract_metadata_from_rule_payload(rule_obj, rule_key=rule_key)
            save_sonar_rule_to_cache(rule_key, metadata)
            return metadata
        else:
            print(f"-> [Info]: SonarQube API {rule_url} mengembalikan status {res.status_code}")
    except Exception as e:
        print(f"-> [Peringatan]: Gagal menghubungi SonarQube API untuk aturan {rule_key}: {e}")

    # Ekstraksi mandiri cadangan tanpa API
    fallback_meta = extract_metadata_from_rule_payload({}, rule_key=rule_key)
    # Periksa apakah sudah pernah di-cache secara lokal
    cached_mappings = load_sonar_cwe_mappings()
    rule_m = re.search(r"S\d+", rule_key)
    cwe_match = cached_mappings.get(rule_key) or (cached_mappings.get(rule_m.group(0)) if rule_m else None)
    if cwe_match:
        fallback_meta["cwe"] = [cwe_match] if isinstance(cwe_match, str) else list(cwe_match)

    return fallback_meta


def convert_sonar_report(
    report_data: dict,
    sonar_host: str = None,
    token: str = None,
    progress_callback=None
) -> tuple[dict, dict]:
    """
    Mengonversi dan memperkaya seluruh issue JSON SonarQube dengan CWE-ID resmi & kategori OWASP,
    setara dengan fungsi convert-sonar-to-cwe.ps1.

    Parameter:
        report_data (dict): Data laporan SonarQube yang sudah di-parse.
        sonar_host (str): URL host SonarQube.
        token (str): Token autentikasi SonarQube.
        progress_callback (callable): Fungsi callback progres (current, total, rule_key).

    Mengembalikan:
        tuple[dict, dict]: (enriched_report_data, summary_statistics)
    """
    issues = report_data.get("issues", [])
    if not isinstance(issues, list):
        return report_data, {
            "total_issues": 0,
            "cwe_mapped_count": 0,
            "unique_cwe_count": 0,
            "cwe_distribution": {},
            "rule_metadata_map": {}
        }

    # Kumpulkan aturan unik
    unique_rules = []
    for issue in issues:
        r = issue.get("rule")
        if r and r not in unique_rules:
            unique_rules.append(r)

    rule_metadata_map = {}
    cached_mappings = load_sonar_cwe_mappings()
    host, auth_token = get_sonar_config(sonar_host, token)

    total_rules = len(unique_rules)
    for idx, r in enumerate(unique_rules, start=1):
        if progress_callback:
            progress_callback(idx, total_rules, r)

        # Periksa apakah metadata aturan sudah ada di memori / cache lengkap
        if _FULL_METADATA_CACHE and r in _FULL_METADATA_CACHE:
            meta = _FULL_METADATA_CACHE[r]
            rule_metadata_map[r] = meta
            continue

        # Periksa apakah aturan ada di pemetaan cache lokal (mis. php:S3330 atau S3330)
        rule_m = re.search(r"S\d+", r)
        cwe_cached = cached_mappings.get(r) or (cached_mappings.get(rule_m.group(0)) if rule_m else None)
        if cwe_cached:
            meta = {
                "rule_key": r,
                "name": r,
                "type": "VULNERABILITY",
                "severity": "MAJOR",
                "cwe": [cwe_cached] if isinstance(cwe_cached, str) else list(cwe_cached),
                "owasp": []
            }
            rule_metadata_map[r] = meta
            continue

        # Periksa apakah aturan dapat diselesaikan lewat API SonarQube bila belum ada di cache
        meta = fetch_sonar_rule_metadata(r, sonar_host=host, token=auth_token)
        rule_metadata_map[r] = meta

    # Perkaya setiap issue dengan properti 'cwe' dan 'owasp'
    cwe_mapped_count = 0
    cwe_distribution = {}

    for issue in issues:
        r = issue.get("rule", "")
        meta = rule_metadata_map.get(r, {})

        issue_cwes = list(meta.get("cwe", []))
        issue_owasps = list(meta.get("owasp", []))

        # Periksa juga tags pada tingkat issue
        tags = issue.get("tags", [])
        if isinstance(tags, list):
            for t in tags:
                m = re.match(r"^cwe-(\d+)$", str(t), re.IGNORECASE)
                if m:
                    c_tag = f"CWE-{m.group(1)}"
                    if c_tag not in issue_cwes:
                        issue_cwes.append(c_tag)

        # Periksa properti 'cwe' yang mungkin sudah ada pada issue
        existing_cwe = issue.get("cwe")
        if existing_cwe:
            if isinstance(existing_cwe, list):
                for c in existing_cwe:
                    if c not in issue_cwes and c != "N/A":
                        issue_cwes.append(str(c))
            elif isinstance(existing_cwe, str) and existing_cwe != "N/A":
                if existing_cwe not in issue_cwes:
                    issue_cwes.append(existing_cwe)

        # Urutkan issue_cwes sehingga CWE spesifik berprioritas tertinggi berada di indeks 0
        if issue_cwes:
            issue_cwes = sorted(issue_cwes, key=lambda c: SPECIFIC_CWE_PRIORITY.get(c, 50), reverse=True)

        # Lekatkan kembali ke objek issue
        issue["cwe"] = issue_cwes
        issue["owasp"] = issue_owasps

        if issue_cwes:
            cwe_mapped_count += 1
            for c in issue_cwes:
                cwe_distribution[c] = cwe_distribution.get(c, 0) + 1

    # Urutkan distribusi CWE yang paling sering muncul
    sorted_distribution = dict(sorted(cwe_distribution.items(), key=lambda item: item[1], reverse=True))

    summary_stats = {
        "total_issues": len(issues),
        "cwe_mapped_count": cwe_mapped_count,
        "unique_cwe_count": len(sorted_distribution),
        "cwe_distribution": sorted_distribution,
        "rule_metadata_map": rule_metadata_map,
    }

    return report_data, summary_stats


def resolve_sonar_cwe(
    issue: dict,
    sonar_host: str = None,
    token: str = None,
    auto_fetch: bool = False
) -> tuple[str, bool]:
    r"""
    Mengekstrak dan menentukan CWE ID dari temuan SonarQube dengan hierarki prioritas:
    0. Properti 'cwe' eksplisit bila laporan sudah dikonversi/diperkaya.
    1. Pencarian regex 'cwe-\d+' pada larik tags (mis. 'cwe-89', 'cwe-525')
    2. Pencarian regex 'cwe-\d+' pada string rule (mis. 'php:CWE-89')
    3. Pemetaan kunci aturan SonarSource dari berkas cache / API SonarQube
       (mis. 'php:S4790' -> 'CWE-327')
    4. Evaluasi tag 'cwe' generik sebagai penanda has_cwe_tag

    Mengembalikan:
        tuple[str, bool]: (cwe_id, has_cwe_tag)
    """
    # 0. Periksa apakah issue sudah memiliki properti 'cwe' hasil konversi
    existing_cwe = issue.get("cwe")
    if existing_cwe:
        if isinstance(existing_cwe, list) and len(existing_cwe) > 0:
            first_val = pick_primary_cwe(existing_cwe)
            if first_val and first_val != "N/A":
                return first_val, True
        elif isinstance(existing_cwe, str) and existing_cwe.strip() and existing_cwe != "N/A":
            return existing_cwe.strip(), True

    tags = [str(t) for t in issue.get("tags", [])]
    rule = str(issue.get("rule", ""))
    issue_type = str(issue.get("type", "")).upper()

    # 1. Periksa apakah larik tags memuat spesifikasi CWE numerik eksplisit
    for t in tags:
        m = re.search(r"cwe-(\d+)", t, re.IGNORECASE)
        if m:
            return f"CWE-{m.group(1)}", True

    # 2. Periksa apakah nama rule langsung memuat CWE numerik (mis. php:CWE-89)
    m = re.search(r"cwe-(\d+)", rule, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}", True

    # 3. Periksa kecocokan ID aturan SonarSource dari konfigurasi / cache dinamis
    mappings = load_sonar_cwe_mappings()
    if rule in mappings:
        return mappings[rule], True

    rule_id_m = re.search(r"S\d+", rule)
    if rule_id_m:
        rule_key = rule_id_m.group(0)
        if rule_key in mappings:
            return mappings[rule_key], True

    has_generic_cwe_tag = any("cwe" in t.lower() for t in tags)

    # Bila auto_fetch aktif dan aturan belum ada di cache, kueri API SonarQube
    # Hanya untuk issue VULNERABILITY atau bertag keamanan agar tidak terjadi ratusan panggilan jaringan untuk code smell
    if auto_fetch and rule and (issue_type == "VULNERABILITY" or has_generic_cwe_tag):
        meta = fetch_sonar_rule_metadata(rule, sonar_host=sonar_host, token=token)
        if meta and meta.get("cwe"):
            return pick_primary_cwe(meta["cwe"]), True
        else:
            save_sonar_rule_to_cache(rule, {"cwe": [], "owasp": []})

    # 4. Cadangan bila tag 'cwe' generik atau tipe VULNERABILITY ada
    if has_generic_cwe_tag or issue_type == "VULNERABILITY":
        return "N/A", True

    return "N/A", False
