"""
Main pipeline:
auth.log -> parse -> feature -> ML -> alert
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Optional, Union

import pandas as pd

from alert import AlertManager
from model_inference import predict_from_dataframe
from readlog_final import calculate_features, parse_line

class LogPipeline:
    def __init__(
        self,
        log_path: Union[str, Path] = "auth.log",
        model_path: Union[str, Path] = "isolation_forest_model.joblib",
        max_lines: int = 500,
    ):
        self.alert = AlertManager()
        self.log_path = Path(log_path)
        self.model_path = Path(model_path)
        self.max_lines = max_lines

    def _build_feature_dataframe(self) -> pd.DataFrame:
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        try:
            with self.log_path.open("r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
        except PermissionError as exc:
            raise PermissionError(
                f"Permission denied when reading log file: {self.log_path}. "
                "Try running with a readable file or use sudo."
            ) from exc

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


def resolve_log_path(cli_log_path: Optional[str]) -> Path:
    if cli_log_path:
        return Path(cli_log_path)

    default_candidates = [Path("auth.log"), Path("/var/log/auth.log")]
    for candidate in default_candidates:
        if candidate.exists():
            return candidate

    return Path("auth.log")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Linux auth.log anomaly detection")
    parser.add_argument(
        "--log-path",
        type=str,
        default=None,
        help="Path to auth log file. Example: /var/log/auth.log",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="isolation_forest_model.joblib",
        help="Path to trained model file",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=500,
        help="How many latest lines to analyze (0 = all)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    pipeline = LogPipeline(
        log_path=resolve_log_path(args.log_path),
        model_path=args.model_path,
        max_lines=args.max_lines,
    )
    pipeline.run()

