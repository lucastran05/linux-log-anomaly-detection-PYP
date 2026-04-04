# Linux Log Anomaly Detection (Python)

Dự án phát hiện bất thường trên log xác thực Linux (`auth.log`) bằng mô hình Isolation Forest.

Pipeline:

`auth.log -> parse -> feature engineering -> preprocess theo schema model -> predict -> alert`

## 1. Yêu cầu hệ thống

- OS: Linux
- Python: 3.10+
- File model đã được huấn luyện: `isolation_forest_model.joblib`

Kiểm tra Python:

```bash
python3 --version
```

## 2. Cài đặt nhanh

Chạy tại thư mục project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Cấu hình đầu vào

Chương trình sẽ tìm log theo thứ tự:

1. Giá trị từ `--log-path` (nếu bạn truyền vào).
2. File `auth.log` trong thư mục project.
3. `/var/log/auth.log` tren Linux.

Model mặc định:

- `--model-path isolation_forest_model.joblib`

Nếu đọc `/var/log/auth.log` bị lỗi quyền, dùng `sudo` hoặc copy log sang file bạn có quyền đọc.

## 4. Các chế độ chạy

### 4.1 Batch mode (mặc định)

Đọc `N` dòng cuối, phân tích 1 lần rồi kết thúc.

```bash
python main.py --log-path /var/log/auth.log --max-lines 500
```

Ghi chú:

- `--max-lines 0`: đọc toàn bộ file.

### 4.2 Realtime mode

Tail log liên tục, có dòng mới là dự đoán ngay.

```bash
python main.py --log-path /var/log/auth.log --realtime
```

Tùy chọn hay dùng:

- Đọc từ đầu file thay vì bỏ qua log cũ:

```bash
python main.py --log-path /var/log/auth.log --realtime --from-beginning
```

- In thống kê định kỳ:

```bash
python main.py --log-path /var/log/auth.log --realtime --show-realtime-stats
```

- Điều chỉnh tần suất poll:

```bash
python main.py --log-path /var/log/auth.log --realtime --poll-interval 0.2
```

### 4.3 Chế độ từng phút

Gom log theo từng cửa sổ thời gian (`cut-seconds`) rồi dự đoán theo thời gian config.

```bash
python main.py --log-path /var/log/auth.log --minute-batch --cut-seconds 60
```

Tùy chọn bổ sung:

```bash
python main.py --log-path /var/log/auth.log --minute-batch --cut-seconds 30 --from-beginning
```

## 5. Kết quả đầu ra

- Batch mode: in tổng số event đã phân tích và số anomaly.
- Realtime/Minute-batch: in cảnh báo ngay khi gặp anomaly.
- Nội dung alert gồm thông tin chính như user, IP, anomaly score.

## 6. Tắt chương trình

- Realtime/Minute-batch: nhấn `Ctrl + C`.
- Thoát virtual environment:

```bash
deactivate
```
