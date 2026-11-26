# tests/test_tab_shap_visual.py
import pandas as pd
import pytest
from frontend.components.tab_shap_visual import build_shap_figures_from_records


def test_build_shap_figures_from_records():
    records = [
        {
            "Key ID": "KEY-1",
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "manipulation (+0.45) | exploit (+0.30)",
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": "site (-0.57) | xss (-0.27)"
        },
        {
            "Key ID": "KEY-2",
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "injection (+0.75) | manipulation (+0.20)",
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": "unauthenticated (-0.15)"
        }
    ]

    fig_shap, fig_beeswarm, has_features = build_shap_figures_from_records(records, id_col_name="Key ID")

    assert has_features is True
    assert fig_shap is not None
    assert fig_beeswarm is not None
    assert "manipulation" in fig_shap.data[0].y
