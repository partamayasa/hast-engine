# tests/test_dss_core.py
"""Logika DSS murni: metode MCDM, AHP, aturan rekomendasi, eskalasi, kriteria, sensitivitas, dan evaluasi."""
import datetime
import json
import os
import random

import numpy as np
import pytest

from backend.core.settings import ROOT_DIR
from backend.dss import ahp, criteria, evaluation, mcdm, recommender, sensitivity
from backend.dss.config import load_dss_config, validate_dss_config
from backend.dss.escalation import escalate

# Contoh hitung tangan: 3 alternatif x (benefit, benefit, cost). Nilai rujukan dihitung dengan
# implementasi Python polos yang terpisah dari rumus buku teks (lihat docs/CATATAN_PERUBAHAN_DSS.md).
X = [[8, 1, 2], [6, 0, 1], [9, 1, 3]]
W = [0.5, 0.3, 0.2]
D = ["benefit", "benefit", "cost"]


# --- MCDM -------------------------------------------------------------------
def test_saw_matches_hand_computation():
    """SAW: r = x/max (benefit), min/x (cost); V = jumlah w r."""
    res = mcdm.saw(X, W, D)
    assert res.scores == pytest.approx([0.844444, 0.533333, 0.866667], abs=1e-6)
    assert mcdm.rank_order(res.scores) == [2, 0, 1]


def test_topsis_matches_hand_computation():
    """Kedekatan TOPSIS C = D- / (D+ + D-) dengan normalisasi vektor."""
    res = mcdm.topsis(X, W, D)
    assert res.scores == pytest.approx([0.780169, 0.30848, 0.69152], abs=1e-6)
    # SAW dan TOPSIS memang berbeda dalam menentukan alternatif teratas untuk matriks ini.
    assert mcdm.rank_order(res.scores) == [0, 2, 1]


def test_wp_scores_sum_to_one_and_shift_zero_columns():
    """WP menggeser kolom yang memuat nol dan mengembalikan preferensi ternormalisasi."""
    res = mcdm.wp(X, W, D)
    assert res.scores.sum() == pytest.approx(1.0)
    assert res.extras["shifted_columns"] == [1]


@pytest.mark.parametrize("weights", [[-0.1, 0.6, 0.5], [0, 0, 0], [0.5, 0.5]])
def test_invalid_weights_rejected(weights):
    """Vektor bobot negatif, seluruhnya nol, atau berukuran salah ditolak."""
    with pytest.raises(ValueError):
        mcdm.saw(X, weights, D)


def test_weights_are_normalised():
    """Bobot yang jumlahnya bukan 1 dinormalisasi (hasilnya sama dengan masukan ternormalisasi)."""
    a = mcdm.topsis(X, [5, 3, 2], D).scores
    b = mcdm.topsis(X, W, D).scores
    assert a == pytest.approx(b)


@pytest.mark.parametrize("method", mcdm.METHODS)
def test_monotonicity_benefit_increase_never_lowers_rank(method):
    """Menaikkan nilai benefit satu alternatif tidak dapat memperburuk peringkatnya."""
    base = mcdm.run_method(method, X, W, D).scores
    X2 = [row[:] for row in X]
    X2[1][0] += 5
    new = mcdm.run_method(method, X2, W, D).scores
    assert mcdm.rank_order(new).index(1) <= mcdm.rank_order(base).index(1)


@pytest.mark.parametrize("method", mcdm.METHODS)
def test_identical_alternatives_and_single_alternative(method):
    """Kasus tepi tidak membagi dengan nol: baris identik bernilai seri, satu baris menempati peringkat pertama."""
    same = mcdm.run_method(method, [[5, 1, 2]] * 3, W, D).scores
    assert np.allclose(same, same[0])
    assert mcdm.rank_order(mcdm.run_method(method, [[5, 1, 2]], W, D).scores) == [0]


def test_nan_in_matrix_rejected():
    with pytest.raises(ValueError):
        mcdm.topsis([[1, float("nan"), 2]], W, D)


def test_rank_order_deterministic_under_shuffle():
    """Mengacak urutan masukan menghasilkan ranking identitas yang sama (tie-break eksplisit)."""
    rng = random.Random(7)
    rows = [([7, 1, 2], "PAIR-B"), ([7, 1, 2], "PAIR-A"), ([9, 0, 1], "PAIR-C"), ([4, 1, 3], "PAIR-D")]
    expected = None
    for _ in range(5):
        rng.shuffle(rows)
        res = mcdm.topsis([r[0] for r in rows], W, D)
        order = [rows[i][1] for i in mcdm.rank_order(res.scores, [(r[1],) for r in rows])]
        expected = expected or order
        assert order == expected
    assert expected.index("PAIR-A") < expected.index("PAIR-B")


# --- AHP ----------------------------------------------------------------------
def test_ahp_perfectly_consistent_matrix_recovers_weights():
    """Matriks yang dibangun dari w = [0.5, 0.3, 0.2] mengembalikan bobot tersebut dengan CR ~ 0."""
    w = np.array([0.5, 0.3, 0.2])
    A = w[:, None] / w[None, :]
    res = ahp.ahp_weights(A)
    assert res.weights == pytest.approx(w, abs=1e-9)
    assert res.cr == pytest.approx(0.0, abs=1e-9)
    assert res.is_consistent


def test_ahp_inconsistent_matrix_flagged():
    """Preferensi melingkar (A>B, B>C, C>A secara kuat) menghasilkan CR > 0,10."""
    A = ahp.reciprocal_from_upper({(0, 1): 9, (1, 2): 9, (0, 2): 1 / 9}, 3)
    res = ahp.ahp_weights(A)
    assert res.cr > ahp.CR_THRESHOLD
    assert not res.is_consistent


def test_ahp_rejects_non_reciprocal_matrix():
    with pytest.raises(ValueError):
        ahp.ahp_weights([[1, 3], [3, 1]])


def test_ahp_group_aggregation_geometric_mean():
    """Rata-rata geometrik [[1,2],[1/2,1]] dan [[1,8],[1/8,1]] adalah [[1,4],[1/4,1]]."""
    agg = ahp.aggregate_judgements([[[1, 2], [0.5, 1]], [[1, 8], [0.125, 1]]])
    assert agg[0, 1] == pytest.approx(4.0) and agg[1, 0] == pytest.approx(0.25)


# --- Aturan rekomendasi -------------------------------------------------------
RULES = [
    {"id": "R1", "when": {"severity_in": ["CRITICAL"], "true_positive": True}, "action": "REMEDIATE_NOW"},
    {"id": "R1b", "when": {"severity_in": ["HIGH"], "true_positive": True, "min_business_impact": 4},
     "action": "REMEDIATE_NOW"},
    {"id": "R2", "when": {"severity_in": ["CRITICAL", "HIGH"]}, "action": "REMEDIATE_SCHEDULED"},
    {"id": "R3", "when": {"severity_in": ["MEDIUM"], "true_positive": True}, "action": "PLAN"},
    {"id": "R9", "when": {}, "action": "REVIEW_OR_ACCEPT"},
]


@pytest.mark.parametrize("ctx,rule", [
    ({"severity": "CRITICAL", "true_positive": True}, "R1"),
    ({"severity": "HIGH", "true_positive": True, "business_impact": 5}, "R1b"),
    ({"severity": "CRITICAL", "true_positive": False}, "R2"),
    ({"severity": "HIGH", "true_positive": True}, "R2"),
    ({"severity": "MEDIUM", "true_positive": True}, "R3"),
    ({"severity": "MEDIUM", "true_positive": False}, "R9"),
    ({"severity": "LOW", "true_positive": True}, "R9"),
])
def test_every_rule_reachable_and_first_match_wins(ctx, rule):
    full = {"hybrid_score": 5.0, "rank": 1, "preference": 0.5, **ctx}
    assert recommender.recommend(full, RULES)["rule_id"] == rule


def test_sla_due_date_only_when_policy_given():
    ctx = {"severity": "CRITICAL", "true_positive": True, "hybrid_score": 9.5, "rank": 1, "preference": 0.9}
    today = datetime.date(2026, 11, 17)
    assert recommender.recommend(ctx, RULES, {"REMEDIATE_NOW": None}, today)["sla_due_date"] is None
    assert recommender.recommend(ctx, RULES, {"REMEDIATE_NOW": 7}, today)["sla_due_date"] == "2026-11-24"


def test_rules_without_catch_all_fail_loudly():
    with pytest.raises(ValueError):
        recommender.recommend({"severity": "LOW", "true_positive": False, "hybrid_score": 1, "rank": 1,
                               "preference": 0.1}, RULES[:3])


# --- Eskalasi (harus sama dengan backend.engine) ------------------------------
def test_escalation_matches_engine_on_golden_pairs():
    """escalate() mereproduksi setiap skor hybrid baseline emas v1 (rumus engine)."""
    path = os.path.join(ROOT_DIR, "tests", "golden", "baseline_predictions.json")
    if not os.path.exists(path):
        pytest.skip("Baseline emas tidak tersedia.")
    with open(path, encoding="utf-8") as f:
        g = json.load(f)
    for p in g["hybrid_pairs"]:
        assert escalate(p["base_score"], p["is_verified_true_positive"], g["escalation_rate"]) == p["hybrid_score"]


def test_escalation_not_applied_to_non_true_positive():
    assert escalate(6.2, False, 0.10) == 6.2
    assert escalate(6.2, True, 0.10) == 6.58
    assert escalate(9.99, True, 1.0) == 10.0


# --- Kriteria -----------------------------------------------------------------
def _row(key, cwe, score, tp=True, comp="src/a.php | GET https://x/y", base=None):
    s, _, d = comp.partition(" | ")
    return {"id": hash(key) % 1000, "key_id": key, "cwe_id": cwe, "component": comp, "predicted_score": score,
            "predicted_severity": "HIGH" if score >= 7 else "MEDIUM", "base_score": base if base is not None else score,
            "is_true_positive": tp, "sast_component": s, "dast_component": d, "decision_key": f"k-{key}",
            "mitigation_text": None}


def test_build_matrix_encodes_lookup_and_flags_imputation():
    cfg = load_dss_config()
    lookup = {"CWE-79": {"attack_vector": "NETWORK", "attack_complexity": "LOW", "attack_requirements": "NONE",
                         "privileges_required": "NONE", "user_interaction": "PASSIVE",
                         "vuln_confidentiality": "LOW", "vuln_integrity": "LOW", "vuln_availability": "NONE"}}
    m = criteria.build_matrix([_row("P1", "CWE-79", 7.1), _row("P2", "CWE-9999", 6.0, tp=False)], cfg, lookup,
                              overrides={"k-P2": {"asset_criticality": 1, "remediation_effort": 3}})
    k = m.keys
    assert m.values[0, k.index("exploitability")] == pytest.approx((1 + 1 + 1 + 1 + 0.5) / 5)
    assert m.values[0, k.index("impact")] == pytest.approx((0.5 + 0.5 + 0) / 3)
    assert m.imputed[1]["exploitability"] == "cwe_not_in_lookup"
    assert m.values[1, k.index("true_positive")] == 0.0
    assert m.values[1, k.index("asset_criticality")] == 1.0
    assert m.values[1, k.index("remediation_effort")] == 3.0
    assert "asset_criticality" not in m.imputed[1]


def test_build_matrix_prevalence_is_log_of_locations():
    cfg = load_dss_config()
    rows = [{**_row("P1", "CWE-79", 7.1), "locations": 21}, {**_row("P2", "CWE-89", 7.2), "locations": 2}]
    m = criteria.build_matrix(rows, cfg, {})
    col = m.keys.index("prevalence")
    assert m.values[0, col] == pytest.approx(np.log(22))
    assert m.values[1, col] == pytest.approx(np.log(3))
    # tanpa kolom 'locations', n = jumlah pasangan ber-CWE sama dalam sesi
    m = criteria.build_matrix([_row("P1", "CWE-79", 7.1), _row("P2", "CWE-79", 6.0)], cfg, {})
    assert m.values[0, m.keys.index("prevalence")] == pytest.approx(np.log(3))


def test_build_matrix_escalation_override_recomputes_c1():
    cfg = load_dss_config()
    m = criteria.build_matrix([_row("P1", "CWE-79", 6.58, base=6.2)], cfg, {}, escalation_rate=0.20)
    assert m.values[0, m.keys.index("hybrid_score")] == escalate(6.2, True, 0.20)


def test_sample_config_is_valid_and_marks_weights_as_examples():
    cfg = load_dss_config()
    validate_dss_config(cfg)
    assert "BUKAN hasil penelitian" in cfg["_note"] and "bukan standar industri" in cfg["_note"]
    assert all(v is None or (isinstance(v, int) and v >= 0) for v in cfg["sla_days"].values())
    # Tanpa aturan aset berbasis pola path secara bawaan: dampak bisnis netral sampai dinilai analis.
    assert cfg["asset_criticality"]["rules"] == []


# --- Sensitivitas & evaluasi --------------------------------------------------
def test_perturb_weights_keeps_sum_one():
    w = sensitivity.perturb_weights(W, 0, 0.2)
    assert w.sum() == pytest.approx(1.0)
    assert w[0] == pytest.approx(0.6)
    assert w[1] / w[2] == pytest.approx(0.3 / 0.2)


def test_weight_sensitivity_reports_every_criterion_and_step():
    out = sensitivity.weight_sensitivity("TOPSIS", X, W, D, ["A", "B", "C"], ["c1", "c2", "c3"])
    assert len(out["variants"]) == 3 * len(sensitivity.DEFAULT_STEPS)
    assert out["baseline_order"] == ["A", "C", "B"]


def test_rank_correlation_and_top_k():
    assert evaluation.rank_correlation(["a", "b", "c"], ["a", "b", "c"])["spearman_rho"] == pytest.approx(1.0)
    assert evaluation.rank_correlation(["a", "b", "c"], ["c", "b", "a"])["kendall_tau"] == pytest.approx(-1.0)
    top = evaluation.top_k_overlap(["a", "b", "c", "d"], ["b", "a", "d", "c"], 2)
    assert top == {"k": 2, "overlap": 2, "precision_at_k": 1.0}


def test_agreement_rate_ignores_undecided():
    r = evaluation.agreement_rate([("PLAN", "PLAN"), ("PLAN", None), ("REMEDIATE_NOW", "DEFER")])
    assert r == {"decided": 2, "agreed": 1, "rate": 0.5}


def test_kendall_w_perfect_and_opposite_agreement():
    """W = 1 untuk ranking identik; W = 0 untuk dua ranking yang terbalik sempurna."""
    assert evaluation.kendall_w([["a", "b", "c"], ["a", "b", "c"], ["a", "b", "c"]])["W"] == pytest.approx(1.0)
    assert evaluation.kendall_w([["a", "b", "c", "d"], ["d", "c", "b", "a"]])["W"] == pytest.approx(0.0)
    with pytest.raises(ValueError):
        evaluation.kendall_w([["a", "b"], ["a", "c"]])


def test_aggregate_issues_groups_by_cwe_and_alert():
    from backend.dss.issues import aggregate_issues
    rows = [
        {"key_id": "P1", "cwe_id": "cwe-693", "dast_key_id": "CSP Header Not Set", "sast_component": "a.php",
         "dast_component": "GET https://x/", "predicted_score": 6.6, "base_score": 6.0, "is_true_positive": True},
        {"key_id": "P2", "cwe_id": "CWE-693", "dast_key_id": "CSP Header Not Set", "sast_component": "b.php",
         "dast_component": "GET https://x/", "predicted_score": 6.7, "base_score": 6.1, "is_true_positive": True},
        {"key_id": "P3", "cwe_id": "CWE-693", "dast_key_id": "Other Alert", "sast_component": "a.php",
         "dast_component": "GET https://x/y", "predicted_score": 5.0, "base_score": 5.0, "is_true_positive": False},
    ]
    issues = aggregate_issues(rows)
    assert len(issues) == 2
    csp = next(i for i in issues if i["title"] == "CSP Header Not Set")
    assert csp["files"] == ["a.php", "b.php"] and csp["endpoints"] == ["GET https://x/"]
    assert csp["predicted_score"] == 6.7 and csp["locations"] == 3 and csp["is_true_positive"] is True
    # eskalasi what-if diterapkan per pasangan sebelum nilai maksimum diambil
    esc = next(i for i in aggregate_issues(rows, escalation_rate=0.5) if i["title"] == "CSP Header Not Set")
    assert esc["predicted_score"] == escalate(6.1, True, 0.5)


def test_unpaired_findings_keeps_single_scanner_findings_without_escalation():
    from backend.services.scoring import unpaired_findings
    sast = [{"key_id": "s1", "cwe_id": "CWE-79", "component": "a.php", "description": "xss", "predicted_score": 7.0},
            {"key_id": "s2", "cwe_id": "cwe-798", "component": "b.php", "description": "hardcoded password",
             "predicted_score": 6.8, "predicted_severity": "MEDIUM", "shap_positive": "password (+0.40)"}]
    dast = [{"key_id": "XSS", "cwe_id": "CWE-79", "component": "GET https://x/", "description": "xss",
             "predicted_score": 7.5},
            {"key_id": "SQL Injection", "cwe_id": "CWE-89", "component": "GET https://x/?q=1",
             "description": "SQL injection may be possible.\n[MITIGATION]: Pakai prepared statement.",
             "mitigation_text": "Pakai prepared statement.", "predicted_score": 8.21, "predicted_severity": "HIGH"},
            {"key_id": "Info", "cwe_id": "N/A", "component": "GET https://x/info", "description": "info",
             "predicted_score": 2.0, "predicted_severity": "LOW"}]
    out = {r["cwe_id"]: r for r in unpaired_findings(sast, dast)}
    # CWE-79 ada di kedua pemindai sehingga menjadi pasangan, bukan temuan tunggal
    assert set(out) == {"CWE-798", "CWE-89", "N/A"}
    s, d = out["CWE-798"], out["CWE-89"]
    assert s["is_true_positive"] is False and d["is_true_positive"] is False
    assert (s["sast_score"], s["dast_score"], s["base_score"], s["predicted_cvss4_score"]) == (6.8, 0.0, 6.8, 6.8)
    assert (d["sast_score"], d["dast_score"], d["predicted_cvss4_score"]) == (0.0, 8.21, 8.21)
    assert s["sast_component"] == "b.php" and s["dast_component"] == "" and s["shap_positive"] == "password (+0.40)"
    assert d["dast_key_id"] == "SQL Injection" and d["sast_key_id"] is None
    assert d["dast_description"] == "SQL injection may be possible." and d["mitigation_text"]


def test_aggregate_issues_separates_sources_and_never_escalates_single_findings():
    from backend.dss.issues import aggregate_issues, issue_key_for
    rows = [
        {"key_id": "P1", "cwe_id": "CWE-79", "dast_key_id": "XSS", "sast_component": "a.php",
         "dast_component": "GET https://x/", "predicted_score": 7.6, "base_score": 7.33, "is_true_positive": True},
        {"key_id": "S1", "cwe_id": "CWE-798", "sast_key_id": "u1", "sast_component": "a.php", "dast_component": "",
         "sast_description": "Hardcoded password", "predicted_score": 6.8, "base_score": 6.8,
         "is_true_positive": False},
        {"key_id": "S2", "cwe_id": "CWE-798", "sast_key_id": "u2", "sast_component": "b.php", "dast_component": "",
         "sast_description": "Hardcoded secret", "predicted_score": 6.5, "base_score": 6.5,
         "is_true_positive": False},
        {"key_id": "D1", "cwe_id": "CWE-89", "dast_key_id": "SQL Injection", "sast_component": "",
         "dast_component": "GET https://x/?q=1", "predicted_score": 8.21, "base_score": 8.21,
         "is_true_positive": False},
    ]
    by_src = {i["source"]: i for i in aggregate_issues(rows, escalation_rate=0.5)}
    assert set(by_src) == {"hybrid", "sast", "dast"}
    sast, dast = by_src["sast"], by_src["dast"]
    assert sast["files"] == ["a.php", "b.php"] and sast["endpoints"] == [] and sast["locations"] == 2
    assert sast["title"] == "Hardcoded password" and sast["is_true_positive"] is False
    assert sast["decision_key"] == issue_key_for("CWE-798", "__sast_only__")
    # kunci isu DAST saja sama dengan rumus isu hybrid, sehingga keputusan tetap tersambung lintas sesi
    assert dast["decision_key"] == issue_key_for("CWE-89", "SQL Injection")
    assert dast["predicted_score"] == 8.21 and dast["predicted_severity"] == "HIGH"
    assert by_src["hybrid"]["predicted_score"] == escalate(7.33, True, 0.5)


def test_sensitivity_compares_final_order_with_priority_classes():
    X = np.array([[9.0, 1.0], [5.0, 9.0], [4.0, 8.0]])
    W, D = np.array([0.5, 0.5]), ["benefit", "benefit"]
    # alternatif A sendirian di kelas P1, sehingga selalu teratas pada urutan akhir walaupun MCDM berubah
    out = sensitivity.weight_sensitivity("SAW", X, W, D, ["A", "B", "C"], ["c1", "c2"],
                                         classify=lambda scores: [1, 2, 2])
    assert out["order_basis"] == "final" and out["baseline_order"][0] == "A"
    assert all(not v["top1_changed"] for v in out["variants"])
    assert all(v["spearman_rho"] >= v["mcdm_spearman_rho"] for v in out["variants"])


def test_er_sensitivity_detects_class_change_invisible_to_mcdm():
    X = np.array([[7.0], [6.0]])

    def build(rate):
        # ER 0 menurunkan A dari kelas P2 ke P3, sedangkan matriks MCDM tidak berubah
        return X, (lambda scores: [2, 3]) if rate > 0 else (lambda scores: [3, 2])

    out = sensitivity.escalation_rate_sensitivity(build, "SAW", np.array([1.0]), ["benefit"], ["A", "B"],
                                                  [0.0, 0.1], baseline_rate=0.1)
    by_rate = {v["escalation_rate"]: v for v in out["variants"]}
    assert by_rate[0.0]["top1_changed"] is True and by_rate[0.0]["mcdm_top1_changed"] is False
    assert by_rate[0.1]["spearman_rho"] == pytest.approx(1.0)


def test_topsis_minmax_matches_hand_computation():
    """TOPSIS min-max: r = (x - min) / (max - min); arah cost ditangani oleh solusi ideal."""
    res = mcdm.topsis(X, W, D, normalization="minmax")
    assert res.scores == pytest.approx([0.702730, 0.255397, 0.744603], abs=1e-6)
    assert mcdm.rank_order(res.scores) == [2, 0, 1]
    assert res.extras["normalization"] == "minmax"


def test_topsis_minmax_effective_weight_equals_nominal_weight():
    """Dengan min-max, rentang v_ij setiap kriteria yang bervariasi sama dengan bobotnya; vektor tidak."""
    Xc = np.array([[6.35, 1, 3.0], [7.24, 0, 1.1], [8.21, 1, 2.0], [6.90, 0, 3.1]])
    w = np.array([0.6, 0.3, 0.1])
    spread = lambda r: r.weighted.max(axis=0) - r.weighted.min(axis=0)  # noqa: E731
    assert spread(mcdm.topsis(Xc, w, ["benefit"] * 3, normalization="minmax")) == pytest.approx(w)
    # Skor yang berkumpul jauh dari nol (kolom pertama) kehilangan hampir seluruh pengaruhnya pada normalisasi vektor.
    assert spread(mcdm.topsis(Xc, w, ["benefit"] * 3, normalization="vector"))[0] < 0.1


def test_topsis_minmax_constant_column_and_invalid_normalization():
    res = mcdm.topsis([[5, 1], [5, 2]], [0.5, 0.5], ["benefit", "benefit"], normalization="minmax")
    assert res.normalized[:, 0] == pytest.approx([0.0, 0.0])
    with pytest.raises(ValueError):
        mcdm.topsis(X, W, D, normalization="zscore")


def test_config_normalization_default_and_validation():
    cfg = load_dss_config()
    assert cfg["normalization"] == "minmax"
    bad = json.loads(json.dumps({k: v for k, v in cfg.items() if not k.startswith("_")}))
    bad["normalization"] = "zscore"
    with pytest.raises(ValueError):
        validate_dss_config(bad)


def test_coverage_pairs_include_findings_dropped_by_v1_dedup():
    from backend.services.scoring import coverage_pairs, preview_pairs, unpaired_findings
    sast = [{"key_id": "s1", "cwe_id": "CWE-352", "component": "Csrf.php", "description": "csrf off", "predicted_score": 6.8},
            {"key_id": "s2", "cwe_id": "CWE-352", "component": "Csrf.php", "description": "csrf lain", "predicted_score": 6.5}]
    dast = [{"key_id": "Absence of Anti-CSRF Tokens", "cwe_id": "CWE-352", "component": "GET https://x/",
             "description": "a", "predicted_score": 6.6},
            {"key_id": "Sec-Fetch-Dest Header is Missing", "cwe_id": "CWE-352", "component": "GET https://x/",
             "description": "b", "predicted_score": 6.7}]
    pairs = preview_pairs(sast, dast)
    assert len(pairs) == 1  # v1: satu pasangan per (CWE, berkas, endpoint)
    extra = coverage_pairs(sast, dast, pairs)
    all_pairs = pairs + extra
    assert {p["sast_key_id"] for p in all_pairs} == {"s1", "s2"}
    assert {p["dast_key_id"] for p in all_pairs} == {"Absence of Anti-CSRF Tokens", "Sec-Fetch-Dest Header is Missing"}
    assert len(extra) == 2 and unpaired_findings(sast, dast) == []
    assert coverage_pairs(sast, dast, all_pairs) == []
