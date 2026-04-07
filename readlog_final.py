import re
import time
import csv
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dateutil import parser  # Cần cài: pip install python-dateutil

# --- CẤU HÌNH ---
LOG_FILE = "/var/log/auth.log"
OUTPUT_FILE = "realtime_output.csv"
IP_PATTERN = r'(?:from\s+|rhost=|rhost\s+|host\s+)(?P<ip>\d+\.\d+\.\d+\.\d+)'
USER_PATTERN = r'(?:for |user |user=)(?P<user>[a-zA-Z0-9_\-\.]+)'

# Các pattern fallback để giảm hụt trường username
USER_FALLBACK_PATTERNS = [
    re.compile(r"invalid user\s+(?P<user>[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    re.compile(r"for\s+(?:invalid user\s+)?(?P<user>[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    re.compile(r"user(?:name)?[=:]\s*(?P<user>[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    re.compile(r"session opened for user\s+(?P<user>[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
]

# Bộ nhớ đệm
buffer_logs = [] 
history = defaultdict(deque)
global_window = deque()


def extract_username(line):
    user_match = re.search(USER_PATTERN, line, re.IGNORECASE)
    if user_match:
        return user_match.group('user')

    for pattern in USER_FALLBACK_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group('user')

    return "unknown"

def parse_date_from_log(line):
    """
    Tự động bóc tách và định dạng ngày tháng từ dòng log.
    Xử lý cả dạng 'Oct 10 10:00:01' và '2024-10-10T10:00:01+07:00'
    """
    try:
        # Lấy 15-30 ký tự đầu tiên thường chứa timestamp
        date_str = " ".join(line.split()[:3]) # Dạng truyền thống
        if "T" in line.split()[0]: # Dạng ISO8601
            date_str = line.split()[0]
        
        dt = parser.parse(date_str, fuzzy=True)
        # Nếu log thiếu năm (như định dạng cũ), tự gán năm hiện tại
        if dt.year == 1900:
            dt = dt.replace(year=datetime.now().year)
        return dt
    except:
        return datetime.now()

def parse_line(line):
    line = line.strip()
    if not line: return None

    # Phân loại trạng thái
    status = "other"
    if any(kw in line for kw in ["Failed password", "authentication failure", "invalid user"]):
        status = "failed"
    elif any(kw in line for kw in ["Accepted password", "session opened"]):
        status = "success"
    else:
        return None

    # Trích xuất thông tin
    ip_match = re.search(IP_PATTERN, line)
    username = extract_username(line)
    pid_match = re.search(r"\[(?P<pid>\d+)\]", line)
    comp_match = re.search(r"\s(?P<comp>[\w\-\[\]]+):", line)

    log_time = parse_date_from_log(line)
    
    return {
        "ts_obj": log_time,
        "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
        "component": comp_match.group('comp').split('[')[0] if comp_match else "sshd",
        "pid": pid_match.group('pid') if pid_match else "0",
        "ip": ip_match.group('ip') if ip_match else "unknown",
        "username": username,
        "port": "22",
        "action": "login_attempt",
        "status": status,
        "raw": line[:150],
        "is_invalid_user": "1" if "invalid user" in line.lower() else "0",
        "is_root_attempt": "1" if "user root" in line or "for root" in line else "0"
    }

def calculate_features(row):
    now = row["ts_obj"]
    ip = row["ip"]
    history[ip].append(row)
    global_window.append(row)
    
    # Cleanup dữ liệu cũ hơn 5 phút để nhẹ máy
    while history[ip] and (now - history[ip][0]["ts_obj"]).total_seconds() > 300:
        history[ip].popleft()
    while global_window and (now - global_window[0]["ts_obj"]).total_seconds() > 300:
        global_window.popleft()

    last_5m_ip = list(history[ip])
    last_1m_ip = [r for r in last_5m_ip if (now - r["ts_obj"]).total_seconds() <= 60]
    last_1m_global = [r for r in global_window if (now - r["ts_obj"]).total_seconds() <= 60]
    
    time_diff = (now - last_5m_ip[-2]["ts_obj"]).total_seconds() if len(last_5m_ip) > 1 else 0

    return {
        "timestamp": row["timestamp"], "component": row["component"], "pid": row["pid"],
        "ip": row["ip"], "username": row["username"], "port": row["port"],
        "action": row["action"], "status": row["status"], "raw": row["raw"],
        "is_invalid_user": row["is_invalid_user"], "is_root_attempt": row["is_root_attempt"],
        "fail_count_1m": sum(1 for r in last_1m_ip if r["status"] == "failed"),
        "fail_count_5m": sum(1 for r in last_5m_ip if r["status"] == "failed"),
        "success_count_5m": sum(1 for r in last_5m_ip if r["status"] == "success"),
        "unique_ip_count": len(set(r["ip"] for r in last_1m_global)),
        "unique_user_count": len(set(r["username"] for r in last_1m_global)),
        "time_since_last_attempt": round(time_diff, 2),
        "is_night": "1" if now.hour < 6 or now.hour > 22 else "0"
    }

def main():
    fieldnames = ["timestamp", "component", "pid", "ip", "username", "port", "action", "status", "raw", "is_invalid_user", "is_root_attempt", "fail_count_1m", "fail_count_5m", "success_count_5m", "unique_ip_count", "unique_user_count", "time_since_last_attempt", "is_night"]

    print(f"[*] Đang theo dõi log: {LOG_FILE}")
    print("[*] Chế độ: Đóng gói dữ liệu mỗi 60 giây...")

    with open(LOG_FILE, "r") as f, open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        if out.tell() == 0: writer.writeheader()
        
        f.seek(0, 2) # Nhảy đến cuối file
        last_flush_time = time.time()

        total_processed = 0
        total_missing_user = 0

        while True:
            line = f.readline()
            if line:
                parsed = parse_line(line)
                if parsed:
                    buffer_logs.append(parsed)
            
            # Kiểm tra nếu đã đủ 60 giây thì "cắt" và xử lý
            current_time = time.time()
            if current_time - last_flush_time >= 60:
                if buffer_logs:
                    print(f"--- Đang xử lý {len(buffer_logs)} bản tin của 1 phút vừa qua ---")
                    minute_missing_user = 0
                    for item in buffer_logs:
                        if item["username"] == "unknown":
                            minute_missing_user += 1
                        feat = calculate_features(item)
                        writer.writerow(feat)

                    total_processed += len(buffer_logs)
                    total_missing_user += minute_missing_user

                    minute_ratio = (minute_missing_user / len(buffer_logs)) * 100
                    total_ratio = (total_missing_user / total_processed) * 100 if total_processed else 0.0

                    print(
                        f"[*] Username unknown (1 phút): {minute_missing_user}/{len(buffer_logs)} ({minute_ratio:.1f}%)"
                    )
                    if minute_ratio >= 30.0:
                        print("[!] Cảnh báo: trường username đang bị hụt nhiều trong phút vừa qua.")
                    print(
                        f"[*] Username unknown (tổng): {total_missing_user}/{total_processed} ({total_ratio:.1f}%)"
                    )

                    out.flush()
                    buffer_logs.clear() # Xóa đệm để chờ phút tiếp theo
                
                last_flush_time = current_time
            
            if not line:
                time.sleep(0.1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Đã dừng chương trình.")
