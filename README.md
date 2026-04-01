# Linux Log Anomaly Detection (Python)

Pipeline:

`auth.log -> parse -> feature engineering -> ML inference -> alert`

## 1. Yeu cau

- Python 3.10+
- Ho tro:
	- Windows (PowerShell)
	- Linux (bash)

Kiem tra Python:

Windows:

```powershell
python --version
```

Linux:

```bash
python3 --version
```

## 2. Tao virtual environment (venv)

Chay trong thu muc project.

Windows:

```powershell
python -m venv .venv
```

Linux:

```bash
python3 -m venv .venv
```

## 3. Kich hoat venv

Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

Neu gap loi execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Linux (bash):

```bash
source .venv/bin/activate
```

Sau khi active, ban se thay `(.venv)` o dau dong lenh.

## 4. Cai dependencies

Windows:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Linux:

```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Chuan bi du lieu

Dat file log dau vao trong project voi ten `auth.log` (mac dinh duoc doc boi `main.py`).

Bat buoc co san model:

- `isolation_forest_model.joblib`

## 6. Chay chuong trinh

Windows:

```powershell
python main.py
```

Linux:

```bash
python3 main.py --log-path /var/log/auth.log
```

Neu file log nam trong project (ten `auth.log`), ban co the chay:

```bash
python3 main.py
```

Ket qua:

- In tong so event duoc phan tich
- In so anomaly tim thay
- In alert chi tiet (User, IP, anomaly score) cho tung event bat thuong

## 7. Tat venv

```powershell
deactivate
```

## Ghi chu

- File `main.py` hien doc batch cac dong gan nhat trong `auth.log` (khong phai realtime tail).
- So dong phan tich mac dinh la 500 dong cuoi.
- Tren Linux, neu bi loi quyen doc `/var/log/auth.log`, hay chay voi `sudo` hoac copy log ra file ban co quyen doc.
