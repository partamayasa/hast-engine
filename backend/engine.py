# backend/engine.py
import numpy as np
import pandas as pd
from backend import model_loader
from backend.config import (
    calculate_severity,
    load_hybrid_escalation_rate,
    load_unprocessing_domains
)


def run_single_prediction(scanner_type: str, description: str, component: str, issue_type: str = "", has_cwe_tag: bool = True) -> dict:
    component_lower = component.lower()

    # Deteksi domain DAST yang dikecualikan secara operasional (tepat 0.0)
    if scanner_type.upper() == "DAST":
        unprocessing_list = load_unprocessing_domains()
        for domain in unprocessing_list:
            if domain in component_lower:
                return {"predicted_cvss4_score": 0.0, "predicted_severity": "NONE"}

    # Saring kelayakan insiden SAST (tepat 0.0)
    if scanner_type.upper() == "SAST":
        if issue_type.upper() != "VULNERABILITY" and not has_cwe_tag:
            return {"predicted_cvss4_score": 0.0, "predicted_severity": "NONE"}

    text_vector = model_loader.tfidf.transform([description])

    if model_loader.rf_model is None:
        raise RuntimeError("Engine Random Forest dipilih aktif tetapi file model biner absen.")
    raw_score = model_loader.rf_model.predict(text_vector)[0]

    predicted_score = max(0.0, min(float(np.round(raw_score, 2)), 10.0))
    return {
        "predicted_cvss4_score": predicted_score,
        "predicted_severity": calculate_severity(predicted_score)
    }


def run_hybrid_prediction(sast_desc: str, dast_desc: str, cwe_id: str) -> dict:
    sast_score = 0.0
    if sast_desc.strip():
        sast_vector = model_loader.tfidf.transform([sast_desc])
        if model_loader.rf_model is None:
            raise RuntimeError("Engine Random Forest dipilih aktif tetapi file model biner absen.")
        raw_sast = model_loader.rf_model.predict(sast_vector)[0]
        sast_score = float(np.round(raw_sast, 2))
        sast_score = max(0.0, min(sast_score, 10.0))

    dast_score = 0.0
    if dast_desc.strip():
        dast_vector = model_loader.tfidf.transform([dast_desc])
        if model_loader.rf_model is None:
            raise RuntimeError("Engine Random Forest dipilih aktif tetapi file model biner absen.")
        raw_dast = model_loader.rf_model.predict(dast_vector)[0]
        dast_score = float(np.round(raw_dast, 2))
        dast_score = max(0.0, min(dast_score, 10.0))

    is_verified_true_positive = False
    if sast_score > 0 and dast_score > 0:
        base_score = (sast_score + dast_score) / 2
    else:
        base_score = max(sast_score, dast_score)
    base_score = float(np.round(base_score, 2))

    final_score = base_score
    if cwe_id and cwe_id.upper() != "N/A" and cwe_id.strip() != "":
        if sast_score > 0 and dast_score > 0:
            is_verified_true_positive = True
            escalation_rate = load_hybrid_escalation_rate()
            final_score = final_score + ((10.0 - final_score) * escalation_rate)
            final_score = min(float(np.round(final_score, 2)), 10.0)

    shap_positive = "N/A"
    shap_negative = "N/A"
    shap_base_value = 0.0
    shap_total_pos = 0.0
    shap_total_neg = 0.0
    shap_predicted_score = 0.0
    try:
        shap_res = calculate_dynamic_shap(sast_desc, dast_desc)
        shap_positive = shap_res.get("shap_positive", "N/A")
        shap_negative = shap_res.get("shap_negative", "N/A")
        shap_base_value = shap_res.get("shap_base_value", 0.0)
        shap_total_pos = shap_res.get("shap_total_pos", 0.0)
        shap_total_neg = shap_res.get("shap_total_neg", 0.0)
        shap_predicted_score = shap_res.get("shap_predicted_score", float(
            np.round(shap_base_value + shap_total_pos + shap_total_neg, 2)))
        absent_vocab_bias = shap_res.get("absent_vocab_bias", float(
            np.round(shap_predicted_score - (shap_base_value + shap_total_pos + shap_total_neg), 2)))
    except Exception:
        absent_vocab_bias = 0.0

    return {
        "cwe_id": cwe_id,
        "is_verified_true_positive": is_verified_true_positive,
        "individual_scores": {"sast_score": sast_score, "dast_score": dast_score},
        "base_score": base_score,
        "shap_base_value": shap_base_value,
        "shap_total_pos": shap_total_pos,
        "shap_total_neg": shap_total_neg,
        "absent_vocab_bias": absent_vocab_bias,
        "shap_predicted_score": shap_predicted_score,
        "predicted_cvss4_score": final_score,
        "predicted_severity": calculate_severity(final_score),
        "shap_positive": shap_positive,
        "shap_negative": shap_negative
    }


_SHAP_MEMO_CACHE = {}


def calculate_dynamic_shap_batch(pairs: list[tuple[str, str]]) -> list[dict]:
    """
    Menghitung kontribusi fitur lokal secara dinamis (tingkat instans)
    memakai SHAP Explainer dalam mode BATCH dengan memoisasi teks unik.
    Eksekusi cepat: teks yang berulang diambil langsung dari RAM (0 ms),
    sedangkan teks baru dievaluasi dalam satu panggilan batch ke TF-IDF & TreeExplainer.
    """
    if not pairs:
        return []

    if model_loader.shap_explainer is None:
        try:
            model_loader.init_models()
        except Exception:
            pass

    fallback_item = {
        "shap_base_value": 0.0,
        "shap_total_pos": 0.0,
        "shap_total_neg": 0.0,
        "absent_vocab_bias": 0.0,
        "shap_predicted_score": 0.0,
        "shap_positive": "N/A",
        "shap_negative": "N/A"
    }

    if model_loader.shap_explainer is None:
        return [fallback_item.copy() for _ in pairs]

    combined_texts = [f"{str(s or '').strip()} {str(d or '').strip()}".strip() for s, d in pairs]
    results = [None] * len(pairs)

    missing_texts = []
    text_to_indices = {}

    for idx, text in enumerate(combined_texts):
        if not text:
            results[idx] = fallback_item.copy()
            continue
        if text in _SHAP_MEMO_CACHE:
            results[idx] = _SHAP_MEMO_CACHE[text]
        else:
            if text not in text_to_indices:
                text_to_indices[text] = []
                missing_texts.append(text)
            text_to_indices[text].append(idx)

    if missing_texts:
        try:
            vectorized_batch = model_loader.tfidf.transform(missing_texts).toarray()
            feature_names = model_loader.tfidf.get_feature_names_out()
            shap_values = model_loader.shap_explainer.shap_values(vectorized_batch)

            if isinstance(shap_values, list):
                shap_matrix = shap_values[0]
            elif hasattr(shap_values, "values"):
                shap_matrix = shap_values.values
            else:
                shap_matrix = shap_values

            shap_matrix = np.asarray(shap_matrix)
            if shap_matrix.ndim == 3:
                shap_matrix = shap_matrix[:, :, 0]
            elif shap_matrix.ndim == 1:
                shap_matrix = shap_matrix.reshape(1, -1)

            base_val = 0.0
            if hasattr(model_loader.shap_explainer, "expected_value"):
                ev = model_loader.shap_explainer.expected_value
                if isinstance(ev, (list, np.ndarray)):
                    base_val = float(ev[0])
                else:
                    base_val = float(ev)
            base_val = float(np.round(base_val, 2))

            for row_idx, text in enumerate(missing_texts):
                current_shap_array = shap_matrix[row_idx]
                current_vec = vectorized_batch[row_idx]
                present_indices = np.where(current_vec > 0.0)[0]

                pos_list = []
                neg_list = []
                total_pos = 0.0
                total_neg = 0.0

                for idx in present_indices:
                    if idx >= len(feature_names):
                        break
                    val = float(current_shap_array[idx])
                    token_word = feature_names[idx]
                    if val > 0.0:
                        pos_list.append((token_word, val))
                        total_pos += val
                    elif val < 0.0:
                        neg_list.append((token_word, val))
                        total_neg += val

                pos_list.sort(key=lambda x: x[1], reverse=True)
                neg_list.sort(key=lambda x: x[1])

                top_pos = pos_list[:3]
                top_neg = neg_list[:3]

                pos_str = " | ".join([f"{word} (+{v:.2f})" for word, v in top_pos]) if top_pos else "N/A"
                neg_str = " | ".join([f"{word} ({v:.2f})" for word, v in top_neg]) if top_neg else "N/A"

                tot_pos_rnd = float(np.round(total_pos, 2))
                tot_neg_rnd = float(np.round(total_neg, 2))

                # Prediksi model keseluruhan f(x) yang diperoleh dari model Random Forest
                curr_model = model_loader.rf_model
                if curr_model is not None:
                    try:
                        pred_raw = float(curr_model.predict(current_vec.reshape(1, -1))[0])
                    except Exception:
                        pred_raw = base_val + float(np.sum(current_shap_array))
                else:
                    pred_raw = base_val + float(np.sum(current_shap_array))

                shap_pred_score = max(0.0, min(float(np.round(pred_raw, 2)), 10.0))
                absent_bias = float(np.round(shap_pred_score - (base_val + tot_pos_rnd + tot_neg_rnd), 2))

                item_res = {
                    "shap_base_value": base_val,
                    "shap_total_pos": tot_pos_rnd,
                    "shap_total_neg": tot_neg_rnd,
                    "absent_vocab_bias": absent_bias,
                    "shap_predicted_score": shap_pred_score,
                    "shap_positive": pos_str,
                    "shap_negative": neg_str
                }

                _SHAP_MEMO_CACHE[text] = item_res
                for target_idx in text_to_indices[text]:
                    results[target_idx] = item_res
        except Exception:
            for text in missing_texts:
                _SHAP_MEMO_CACHE[text] = fallback_item.copy()
                for target_idx in text_to_indices[text]:
                    results[target_idx] = fallback_item.copy()

    for i in range(len(results)):
        if results[i] is None:
            results[i] = fallback_item.copy()

    return results


def calculate_dynamic_shap(sast_desc: str, dast_desc: str) -> dict:
    """
    Menghitung kontribusi fitur lokal secara dinamis (tingkat instans)
    memakai objek SHAP Explainer di memori dengan cache teks.
    """
    res_list = calculate_dynamic_shap_batch([(sast_desc, dast_desc)])
    return res_list[0] if res_list else {
        "shap_base_value": 0.0, "shap_total_pos": 0.0, "shap_total_neg": 0.0,
        "absent_vocab_bias": 0.0, "shap_predicted_score": 0.0, "shap_positive": "N/A", "shap_negative": "N/A"
    }


def correlate_hybrid_vulnerabilities(df_sast, df_dast):
    """
    Melakukan korelasi hybrid berdasarkan kecocokan CWE ID tanpa batasan penyaringan berkas atau parameter.
    """
    final_correlations = pd.merge(df_sast, df_dast, on='cwe_id', suffixes=('_sast', '_dast'))
    return final_correlations
