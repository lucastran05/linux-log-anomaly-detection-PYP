"""
Main pipeline:
auth.log -> parse -> feature -> ML -> alert
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from alert import AlertManager
from model_inference import predict_from_dataframe
from readlog_final import calculate_features, parse_line

class LogPipeline:
    def __init__(
        self,
        log_path: str | Path = "auth.log",
        model_path: str | Path = "isolation_forest_model.joblib",
        max_lines: int = 500,
    ):
        self.alert = AlertManager()
        self.log_path = Path(log_path)
        self.model_path = Path(model_path)
        self.max_lines = max_lines

    def _build_feature_dataframe(self) -> pd.DataFrame:
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        with self.log_path.open("r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()

        selected_lines = all_lines[-self.max_lines :] if self.max_lines > 0 else all_lines

        features: list[dict[str, Any]] = []
        for line in selected_lines:
            parsed = parse_line(line)
            if not parsed:
                continue
            features.append(calculate_features(parsed))

        return pd.DataFrame(features)

    def run(self):
        print("[*] Starting detection ...")

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        feature_df = self._build_feature_dataframe()
        if feature_df.empty:
            print("[i] No valid auth events found to analyze.")
            return

        prediction_output = predict_from_dataframe(
            input_df=feature_df,
            model_path=self.model_path,
        )

        result_df = prediction_output["dataframe"]
        anomalies = result_df[result_df["is_anomaly"] == 1]

        print(f"[*] Total analyzed events: {len(result_df)}")
        print(f"[*] Detected anomalies: {len(anomalies)}")

        for _, row in anomalies.iterrows():
            self.alert.send_alert(row.to_dict())


if __name__ == "__main__":
    pipeline = LogPipeline()
    pipeline.run()

