from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import numpy as np
import pandas as pd

CATEGORICAL_TO_ENCODE = ["component", "status"]
BINARY_TO_KEEP = [
    "is_invalid_user",
    "is_night",
    "is_weekend",
]
NUMERIC_TO_NORMALIZE = [
    "fail_count_1m",
    "fail_count_5m",
    "success_count_5m",
    "unique_ip_count",
    "unique_user_count",
    "time_since_last_attempt",
    "event_frequency",
]
OPTIONAL_BINARY = [
    "is_root_attempt",
]

OPTIONAL_NUMERIC = []

COMPONENT_PATTERNS = [
    "sshd",
    "sudo",
    "cron",
    "pkexec",
    "vsftpd",
    "gdm-password",
    "gdm-launch-environment",
]

FAILED_PATTERNS = [
    "failed password",
    "authentication failure",
    "failed",
    "failure",
    "invalid user",
]

SUCCESS_PATTERNS = [
    "accepted password",
    "accepted publickey",
    "session opened",
    "opened for user",
    "successful",
    "success",
]

IP_REGEX = re.compile(r"\b(?:from|src=|rhost=)?\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)
USER_REGEXES = [
    re.compile(r"invalid user\s+([^\s]+)", re.IGNORECASE),
    re.compile(r"for\s+(?:invalid user\s+)?([^\s]+)", re.IGNORECASE),
    re.compile(r"user(?:name)?[=:]\s*([^\s]+)", re.IGNORECASE),
]


def sanitize_token(value: Any) -> str:
    text = "unknown" if pd.isna(value) else str(value)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown"


def load_scaling_stats(json_path: str | Path) -> Dict[str, Dict[str, float]]:
    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, dict) and "scaling_stats" in payload:
        return payload["scaling_stats"]
    return payload


def normalize_with_stats(series: pd.Series, stats: Optional[Dict[str, float]] = None) -> Tuple[pd.Series, Dict[str, float]]:
    s = pd.to_numeric(series, errors="coerce")
    if stats is None:
        min_val = float(s.min()) if s.notna().any() else 0.0
        max_val = float(s.max()) if s.notna().any() else 0.0
    else:
        min_val = float(stats.get("min", 0.0))
        max_val = float(stats.get("max", 0.0))

    if max_val == min_val:
        scaled = pd.Series(0.0, index=s.index)
    else:
        scaled = (s - min_val) / (max_val - min_val)

    scaled = scaled.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(float)
    return scaled, {"min": min_val, "max": max_val}


def infer_component_from_message(message: str) -> str:
    text = str(message).lower()
    for item in COMPONENT_PATTERNS:
        if item in text:
            return item
    return "unknown"


def infer_status_from_message(message: str) -> str:
    text = str(message).lower()
    if any(p in text for p in FAILED_PATTERNS):
        return "failed"
    if any(p in text for p in SUCCESS_PATTERNS):
        return "success"
    return "connection_event"


def extract_ip_from_message(message: str) -> str:
    text = str(message)
    match = IP_REGEX.search(text)
    if not match:
        return "unknown"
    return match.group(1)


def extract_username_from_message(message: str) -> str:
    text = str(message)
    for pattern in USER_REGEXES:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return "unknown"


def enrich_columns_from_message(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if "message" not in df.columns:
        if "source_ip" not in df.columns:
            for candidate in ["ip", "src_ip", "remote_ip", "client_ip", "rhost"]:
                if candidate in df.columns:
                    df["source_ip"] = df[candidate].fillna("unknown").astype(str)
                    break

        if "username" not in df.columns:
            for candidate in ["user", "user_name", "account", "account_name"]:
                if candidate in df.columns:
                    df["username"] = df[candidate].fillna("unknown").astype(str)
                    break
        return df

    msg = df["message"].fillna("").astype(str)

    if "component" not in df.columns:
        df["component"] = msg.map(infer_component_from_message)

    if "status" not in df.columns:
        df["status"] = msg.map(infer_status_from_message)

    if "is_invalid_user" not in df.columns:
        df["is_invalid_user"] = msg.str.contains(r"\binvalid user\b", case=False, regex=True).astype(int)

    if "is_root_attempt" not in df.columns:
        df["is_root_attempt"] = msg.str.contains(r"\broot\b", case=False, regex=True).astype(int)

    if "source_ip" not in df.columns:
        copied = False
        for candidate in ["ip", "src_ip", "remote_ip", "client_ip", "rhost"]:
            if candidate in df.columns:
                df["source_ip"] = df[candidate].fillna("unknown").astype(str)
                copied = True
                break
        if not copied:
            df["source_ip"] = msg.map(extract_ip_from_message)

    if "username" not in df.columns:
        copied = False
        for candidate in ["user", "user_name", "account", "account_name"]:
            if candidate in df.columns:
                df["username"] = df[candidate].fillna("unknown").astype(str)
                copied = True
                break
        if not copied:
            df["username"] = msg.map(extract_username_from_message)

    return df

def build_time_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        hour = ts.dt.hour.fillna(0).astype(int)
        day_of_week = ts.dt.dayofweek.fillna(0).astype(int)

        # Nếu chưa có thì suy ra
        if "is_night" not in df.columns:
            df["is_night"] = ((hour >= 0) & (hour < 6)).astype(int)

        df["is_weekend"] = day_of_week.isin([5, 6]).astype(int)
        df["hour_sin"] = np.sin(2 * np.pi * hour / 24.0)
        df["hour_cos"] = np.cos(2 * np.pi * hour / 24.0)
        df["dow_sin"] = np.sin(2 * np.pi * day_of_week / 7.0)
        df["dow_cos"] = np.cos(2 * np.pi * day_of_week / 7.0)
    else:
        if "is_night" not in df.columns:
            df["is_night"] = 0
        df["is_weekend"] = 0
        df["hour_sin"] = 0.0
        df["hour_cos"] = 1.0
        df["dow_sin"] = 0.0
        df["dow_cos"] = 1.0

    return df


def preprocess_dataframe(
    df: pd.DataFrame,
    expected_feature_names: Optional[list[str]] = None,
    scaling_stats: Optional[Dict[str, Dict[str, float]]] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]

    object_cols = df.select_dtypes(include=["object"]).columns.tolist()
    for col in object_cols:
        df[col] = df[col].fillna("unknown")
        
    bool_cols = df.select_dtypes(include=["bool"]).columns.tolist()
    for col in bool_cols:
        df[col] = df[col].astype(int)

    df = enrich_columns_from_message(df)

    df = build_time_features(df)

    categorical_cols = [c for c in CATEGORICAL_TO_ENCODE if c in df.columns]

    binary_keep_cols = [c for c in BINARY_TO_KEEP if c in df.columns]
    binary_keep_cols += [
        c for c in OPTIONAL_BINARY
        if c in df.columns and df[c].nunique(dropna=False) > 1
    ]

    numeric_cols = [c for c in NUMERIC_TO_NORMALIZE if c in df.columns]
    numeric_cols += [
        c for c in OPTIONAL_NUMERIC
        if c in df.columns and df[c].nunique(dropna=False) > 1
    ]

    # One-hot encoding
    encoded_parts = []
    category_maps: Dict[str, list[str]] = {}
    for col in categorical_cols:
        safe_series = df[col].astype(str).map(sanitize_token)
        dummies = pd.get_dummies(safe_series, prefix=col, dtype=int)
        if expected_feature_names is None:
            dummies = dummies.loc[:, dummies.nunique(dropna=False) > 1]
        encoded_parts.append(dummies)
        category_maps[col] = sorted(safe_series.unique().tolist())

    encoded_df = pd.concat(encoded_parts, axis=1) if encoded_parts else pd.DataFrame(index=df.index)

    normalized_df = pd.DataFrame(index=df.index)
    used_scaling_stats: Dict[str, Dict[str, float]] = {}
    for col in numeric_cols:
        col_stats = scaling_stats.get(col) if scaling_stats else None
        normalized_df[f"{col}_norm"], used_scaling_stats[col] = normalize_with_stats(df[col], col_stats)

    final_df = pd.DataFrame(index=df.index)

    for col in binary_keep_cols:
        final_df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    for cyc_col in ["hour_sin", "hour_cos", "dow_sin", "dow_cos"]:
        final_df[cyc_col] = pd.to_numeric(df[cyc_col], errors="coerce").fillna(0.0).astype(float)

    final_df = pd.concat([final_df, encoded_df, normalized_df], axis=1)
    final_df = final_df.replace([np.inf, -np.inf], np.nan).fillna(0)

    added_missing_features = []
    dropped_extra_features = []

    if expected_feature_names is not None:
        # Thêm các cột mà model cần nhưng input hiện chưa sinh ra
        for col in expected_feature_names:
            if col not in final_df.columns:
                final_df[col] = 0
                added_missing_features.append(col)

        dropped_extra_features = [c for c in final_df.columns if c not in expected_feature_names]
        final_df = final_df[[c for c in final_df.columns if c in expected_feature_names]]

        final_df = final_df[expected_feature_names]

    meta = {
        "input_columns": df.columns.tolist(),
        "categorical_encoded": categorical_cols,
        "binary_kept": binary_keep_cols,
        "numeric_normalized": numeric_cols,
        "category_maps": category_maps,
        "scaling_stats_used": used_scaling_stats,
        "added_missing_features": added_missing_features,
        "dropped_extra_features": dropped_extra_features,
        "output_columns": final_df.columns.tolist(),
        "output_shape": list(final_df.shape),
    }

    return final_df.astype(float), meta


def preprocess_csv(
    csv_path: str | Path,
    expected_feature_names: Optional[list[str]] = None,
    scaling_stats: Optional[Dict[str, Dict[str, float]]] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    raw_df = pd.read_csv(csv_path)
    enriched_raw_df = enrich_columns_from_message(raw_df)
    feature_df, meta = preprocess_dataframe(
        enriched_raw_df,
        expected_feature_names=expected_feature_names,
        scaling_stats=scaling_stats,
    )
    return enriched_raw_df, feature_df, meta
