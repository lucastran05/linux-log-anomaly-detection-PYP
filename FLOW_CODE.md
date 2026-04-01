# Flow code - Linux Log Anomaly Detection

## 1) Tong quan pipeline

Input log -> Parse -> Feature Engineering -> Preprocess theo schema model -> Predict -> Alert

Co 2 che do chay:
- Batch mode: doc N dong gan nhat, predict 1 lan.
- Realtime mode: tail log tu luc start, co dong moi la predict ngay.

## 2) Diem vao chuong trinh

`main.py` la entrypoint.

Ham chinh:
- `parse_args()`
  - Doc tham so CLI:
    - `--log-path`
    - `--model-path`
    - `--max-lines`
    - `--realtime`
    - `--poll-interval`
    - `--from-beginning`
    - `--show-realtime-stats`
- `resolve_log_path()`
  - Neu user truyen `--log-path` thi dung path do.
  - Neu khong, thu lan luot:
    - `auth.log` trong project
    - `/var/log/auth.log` tren Linux

Sau do tao `LogPipeline(...)` va:
- Neu `--realtime`: goi `run_realtime(...)`
- Neu khong: goi `run()`

## 3) Luong batch (`LogPipeline.run`)

Buoc 1: Validate file model ton tai.

Buoc 2: Build feature DataFrame qua `_build_feature_dataframe()`:
- Mo file log
- Lay `max_lines` dong cuoi (hoac all neu = 0)
- Moi dong:
  - `parse_line()` trong `readlog_final.py`
  - Neu parse hop le -> `calculate_features()`
- Tra ve `pd.DataFrame(features)`

Buoc 3: Inference:
- Goi `predict_from_dataframe(input_df, model_path)` trong `model_inference.py`

Buoc 4: Loc anomaly:
- `is_anomaly == 1`
- In tong so event va so anomaly
- Voi moi anomaly: `AlertManager.send_alert(...)`

## 4) Luong realtime (`LogPipeline.run_realtime`)

Buoc 1: Validate model/log path.

Buoc 2: Load model 1 lan:
- `loaded_bundle = load_model_bundle(model_path)`
- Muc tieu: tranh load lai model moi dong log.

Buoc 3: Tail file:
- Mo log file
- Neu `start_at_end=True` (mac dinh): `seek(EOF)` de bo qua log cu, chi doc event moi.
- Vong lap vo han:
  - `readline()`
  - Neu chua co dong moi -> sleep theo `poll_interval`
  - Co dong moi:
    - `parse_line()`
    - `calculate_features()`
    - Tao DataFrame 1 dong
    - `predict_from_dataframe(..., loaded_bundle=loaded_bundle)`
    - Neu `is_anomaly == 1` -> alert ngay

Buoc 4: Logging stats (optional):
- Chi in dong `Realtime analyzed ...` khi bat `--show-realtime-stats`

## 5) Luong model va preprocess (`model_inference.py` + `preprocessing.py`)

### 5.1 Load model bundle

Ham `load_model_bundle()`:
- Co shim tuong thich `numpy._core` -> `numpy.core` de giam loi khi artifact cu/moi lech nhau.
- `joblib.load(model_path)`
- Neu bundle la dict co key `model`:
  - lay model + `feature_names` (neu co)
- Neu khong:
  - coi object load duoc la model

Neu gap loi `numpy._core` thi raise RuntimeError mo ta ro nguyen nhan mismatch moi truong.

### 5.2 Score va gan nhan

Ham `_predict_scores()`:
- `model.predict(X)` -> raw prediction
- Neu co `decision_function` / `score_samples` thi lay them score

Ham `predict_from_dataframe()`:
- Lay `feature_names` tu bundle.
- Neu bundle khong co, fallback tu `model.feature_names_in_`.
- Goi `preprocess_dataframe(..., expected_feature_names=feature_names)`
- Predict
- Gan:
  - `prediction` = anomaly/normal
  - `is_anomaly` = 1/0
  - `anomaly_score` = `-decision_score` (voi IsolationForest)

### 5.3 Dung schema feature khop luc train

Trong `preprocess_dataframe()`:
- Lam sach cot, fillna
- Build cac feature (categorical one-hot, binary, numeric norm, time cyc)
- Neu co `expected_feature_names`:
  - Them cot thieu = 0
  - Bo cot du
  - Sap xep dung thu tu feature luc train

Day la diem then chot giup tranh loi:
- Feature names unseen at fit time
- Feature names seen at fit time, yet now missing

## 6) Parse log va tao feature (`readlog_final.py`)

`parse_line()`:
- Nhan dien event auth (failed/success) theo keyword
- Trich xuat timestamp, component, pid, ip, username, ...

`calculate_features()`:
- Dung cua so thoi gian 1m/5m theo IP/global
- Tinh cac chi so:
  - fail_count_1m, fail_count_5m
  - success_count_5m
  - unique_ip_count, unique_user_count
  - time_since_last_attempt
  - is_night

## 7) Alert (`alert.py`)

Khi event bi danh dau anomaly:
- `AlertManager.send_alert(row_dict)`
- In thong tin canh bao ra man hinh (User, IP, score)

## 8) Ghi chu van hanh tren Linux

- Neu warning `InconsistentVersionWarning` (sklearn) xuat hien:
  - Chuong trinh van co the chay, nhung canh bao rang model train khac version.
- Neu ket qua anomaly qua nhieu:
  - Nen retrain model bang dung data/feature tren Linux
  - Hoac them threshold cho `anomaly_score` de giam false positive.
