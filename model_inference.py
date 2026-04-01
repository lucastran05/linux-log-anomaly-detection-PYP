
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, Optional

import joblib
import numpy as np
import pandas as pd

from preprocessing import enrich_columns_from_message, load_scaling_stats, preprocess_csv, preprocess_dataframe


def load_model_bundle(model_path: str | Path) -> Dict[str, Any]:
    try:
        bundle = joblib.load(model_path)
    except ModuleNotFoundError as exc:
        if "numpy._core" in str(exc):
            raise RuntimeError(
                "Model compatibility error: cannot import numpy._core while loading model. "
                "This usually means environment mismatch (often Python 3.8 + older NumPy). "
                f"Current Python: {sys.version.split()[0]}. "
                "Use Python 3.10+ and reinstall dependencies from requirements.txt, "
                "or retrain/re-export model in the current environment."
            ) from exc
        raise

    if isinstance(bundle, dict) and "model" in bundle:
        model = bundle["model"]
        feature_names = bundle.get("feature_names")
        return {
            "model": model,
            "feature_names": feature_names,
            "bundle": bundle,
        }

    return {
        "model": bundle,
        "feature_names": None,
        "bundle": {"model": bundle},
    }


def _predict_scores(model: Any, X: pd.DataFrame) -> Dict[str, np.ndarray]:
    result: Dict[str, np.ndarray] = {}

    raw_pred = model.predict(X)
    result["raw_prediction"] = raw_pred

    if hasattr(model, "decision_function"):
        result["decision_score"] = model.decision_function(X)

    if hasattr(model, "score_samples"):
        result["score_samples"] = model.score_samples(X)

    return result


def predict_from_dataframe(
    input_df: pd.DataFrame,
    model_path: str | Path,
    scaling_stats: Optional[Dict[str, Dict[str, float]]] = None,
) -> Dict[str, Any]:
    loaded = load_model_bundle(model_path)
    model = loaded["model"]
    feature_names = loaded["feature_names"]

    feature_df, preprocess_meta = preprocess_dataframe(
        input_df,
        expected_feature_names=feature_names,
        scaling_stats=scaling_stats,
    )

    score_dict = _predict_scores(model, feature_df)
    raw_pred = score_dict["raw_prediction"]

    result_df = enrich_columns_from_message(input_df.copy())
    result_df["prediction"] = np.where(raw_pred == -1, "anomaly", "normal")
    result_df["is_anomaly"] = np.where(raw_pred == -1, 1, 0)

    if "decision_score" in score_dict:
        result_df["decision_score"] = score_dict["decision_score"]
        # Với IsolationForest: decision_score càng nhỏ càng bất thường
        result_df["anomaly_score"] = -result_df["decision_score"]

    if "score_samples" in score_dict:
        result_df["score_samples"] = score_dict["score_samples"]

    return {
        "dataframe": result_df,
        "records": result_df.to_dict(orient="records"),
        "feature_dataframe": feature_df,
        "preprocess_meta": preprocess_meta,
    }


def predict_from_csv(
    csv_path: str | Path,
    model_path: str | Path,
    scaling_stats_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    scaling_stats = None
    if scaling_stats_path:
        scaling_stats = load_scaling_stats(scaling_stats_path)

    raw_df, feature_df, preprocess_meta = preprocess_csv(
        csv_path=csv_path,
        expected_feature_names=load_model_bundle(model_path)["feature_names"],
        scaling_stats=scaling_stats,
    )

    loaded = load_model_bundle(model_path)
    model = loaded["model"]

    score_dict = _predict_scores(model, feature_df)
    raw_pred = score_dict["raw_prediction"]

    result_df = raw_df.copy()
    result_df["prediction"] = np.where(raw_pred == -1, "anomaly", "normal")
    result_df["is_anomaly"] = np.where(raw_pred == -1, 1, 0)

    if "decision_score" in score_dict:
        result_df["decision_score"] = score_dict["decision_score"]
        result_df["anomaly_score"] = -result_df["decision_score"]

    if "score_samples" in score_dict:
        result_df["score_samples"] = score_dict["score_samples"]

    return {
        "dataframe": result_df,
        "records": result_df.to_dict(orient="records"),
        "feature_dataframe": feature_df,
        "preprocess_meta": preprocess_meta,
    }
