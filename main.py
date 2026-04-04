from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Optional, Union

import pandas as pd

from alert import AlertManager
from model_inference import load_model_bundle, predict_from_dataframe
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

    def run_realtime(self, poll_interval: float = 0.2, start_at_end: bool = True):
        print("[*] Starting detection (realtime mode) ...")

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        loaded_bundle = load_model_bundle(self.model_path)

        try:
            with self.log_path.open("r", encoding="utf-8", errors="ignore") as f:
                if start_at_end:
                    f.seek(0, 2)
                    print("[*] Realtime tail from now (ignoring old lines).")
                else:
                    print("[*] Realtime tail from beginning of file.")

                analyzed = 0
                anomalies = 0
                show_stats = getattr(self, "show_realtime_stats", False)

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(poll_interval)
                        continue

                    parsed = parse_line(line)
                    if not parsed:
                        continue

                    feature_row = calculate_features(parsed)
                    prediction_output = predict_from_dataframe(
                        input_df=pd.DataFrame([feature_row]),
                        model_path=self.model_path,
                        loaded_bundle=loaded_bundle,
                    )

                    result_row = prediction_output["dataframe"].iloc[0]
                    analyzed += 1

                    if int(result_row.get("is_anomaly", 0)) == 1:
                        anomalies += 1
                        self.alert.send_alert(result_row.to_dict())

                    if show_stats and analyzed % 20 == 0:
                        print(f"[*] Realtime analyzed: {analyzed} | anomalies: {anomalies}")

        except PermissionError as exc:
            raise PermissionError(
                f"Permission denied when reading log file: {self.log_path}. "
                "Try running with a readable file or use sudo."
            ) from exc

    def run_minute_batch(
        self,
        poll_interval: float = 0.2,
        cut_seconds: int = 60,
        start_at_end: bool = True,
    ):
        print("[*] Starting detection (minute-cut mode) ...")

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        loaded_bundle = load_model_bundle(self.model_path)
        buffer_logs = []

        try:
            with self.log_path.open("r", encoding="utf-8", errors="ignore") as f:
                if start_at_end:
                    f.seek(0, 2)
                    print("[*] Minute-cut tail from now (ignoring old lines).")
                else:
                    print("[*] Minute-cut tail from beginning of file.")

                last_cut_time = time.time()

                while True:
                    line = f.readline()
                    if line:
                        parsed = parse_line(line)
                        if parsed:
                            buffer_logs.append(parsed)
                    else:
                        time.sleep(poll_interval)

                    now = time.time()
                    if now - last_cut_time < cut_seconds:
                        continue

                    if not buffer_logs:
                        last_cut_time = now
                        continue

                    raw_batch = []
                    feature_batch = []
                    for item in buffer_logs:
                        raw_item = {k: v for k, v in item.items() if k != "ts_obj"}
                        raw_batch.append(raw_item)
                        feature_batch.append(calculate_features(item))

                    raw_df = pd.DataFrame(raw_batch)
                    feature_df = pd.DataFrame(feature_batch)

                    prediction_output = predict_from_dataframe(
                        input_df=feature_df,
                        model_path=self.model_path,
                        loaded_bundle=loaded_bundle,
                    )

                    result_df = prediction_output["dataframe"]
                    anomalies = result_df[result_df["is_anomaly"] == 1]

                    if not anomalies.empty:
                        for _, row in anomalies.iterrows():
                            self.alert.send_alert(row.to_dict())

                    buffer_logs.clear()
                    last_cut_time = now

        except PermissionError as exc:
            raise PermissionError(
                f"Permission denied when reading log file: {self.log_path}. "
                "Try running with a readable file or use sudo."
            ) from exc


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
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Tail log file in realtime from the moment the app starts",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.2,
        help="Polling interval in seconds for realtime mode",
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="In realtime mode, start reading from beginning instead of current EOF",
    )
    parser.add_argument(
        "--show-realtime-stats",
        action="store_true",
        help="Show periodic counters in realtime mode (for debugging)",
    )
    parser.add_argument(
        "--minute-batch",
        action="store_true",
        help="Cut log every interval: write raw/features CSV then run ML on each batch",
    )
    parser.add_argument(
        "--cut-seconds",
        type=int,
        default=60,
        help="Batch cut interval in seconds for --minute-batch mode",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    pipeline = LogPipeline(
        log_path=resolve_log_path(args.log_path),
        model_path=args.model_path,
        max_lines=args.max_lines,
    )
    pipeline.show_realtime_stats = args.show_realtime_stats
    if args.minute_batch:
        try:
            pipeline.run_minute_batch(
                poll_interval=max(args.poll_interval, 0.05),
                cut_seconds=max(args.cut_seconds, 5),
                start_at_end=not args.from_beginning,
            )
        except KeyboardInterrupt:
            print("\n[!] Minute-cut detection stopped.")
    elif args.realtime:
        try:
            pipeline.run_realtime(
                poll_interval=max(args.poll_interval, 0.05),
                start_at_end=not args.from_beginning,
            )
        except KeyboardInterrupt:
            print("\n[!] Realtime detection stopped.")
    else:
        pipeline.run()

