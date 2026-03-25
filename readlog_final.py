import re
import time
import csv
from datetime import datetime
from collections import defaultdict, deque

# --- CẤU HÌNH REGEX (Giữ nguyên để bắt E1 - E20) ---
IP_PATTERN = r'(?:from|rhost=| rhost\s+|host\s+)(?P<ip>[\d\.]+)'
USER_PATTERN = r'(?:for |user |user=)(?P<user>[a-zA-Z0-9_\-\.]+)'

# Bộ nhớ đệm tính toán
history = defaultdict(deque)
global_window = deque()

def parse_line(line):
    line = line.strip()
    if not line: return None

    # Phân loại sự kiện
    status = "other"
    is_fail = any(kw in line for kw in ["Failed password", "authentication failure", "invalid user", "user unknown", "password check failed", "maximum authentication attempts exceeded"])
    is_success = any(kw in line for kw in ["Accepted password", "session opened"])
    is_conn = any(kw in line for kw in ["Connection closed", "Received disconnect", "Did not receive identification string"])

    if is_fail: status = "failed"
    elif is_success: status = "success"
    elif is_conn: status = "connection_event"
    else: return None

    # Trích xuất Field
    ip_match = re.search(IP_PATTERN, line)
    user_match = re.search(USER_PATTERN, line)
    pid_match = re.search(r"\[(?P<pid>\d+)\]", line)
    port_match = re.search(r"port\s+(?P<port>\d+)", line)
    comp_match = re.search(r"\s(?P<comp>[\w\-\[\]]+):", line)

    ip = ip_match.group('ip') if ip_match else "unknown"
    user = user_match.group('user') if user_match else "unknown"
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ts_obj": datetime.now(),
        "component": comp_match.group('comp').split('[')[0] if comp_match else "sshd",
        "pid": pid_match.group('pid') if pid_match else "0",
        "ip": ip,
        "username": user,
        "port": port_match.group('port') if port_match else "22",
        "action": "login_attempt",
        "status": status,
        "raw": line[:150],
        "is_invalid_user": "TRUE" if "invalid user" in line.lower() or "user unknown" in line.lower() else "FALSE",
        "is_root_attempt": "TRUE" if user == "root" else "FALSE"
    }

def calculate_features(row):
    now = row["ts_obj"]
    ip = row["ip"]
    history[ip].append(row)
    global_window.append(row)
    
    # Cleanup > 5 phút
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
        "is_night": "TRUE" if now.hour < 6 or now.hour > 22 else "FALSE",
        "event_frequency": round(len(last_1m_ip) / 1.0, 2)
    }

def main():
    log_file = "/var/log/auth.log"
    output_file = "realtime_output.csv"
    fieldnames = ["timestamp", "component", "pid", "ip", "username", "port", "action", "status", "raw", "is_invalid_user", "is_root_attempt", "fail_count_1m", "fail_count_5m", "success_count_5m", "unique_ip_count", "unique_user_count", "time_since_last_attempt", "is_night", "event_frequency"]

    print("[*] CHẾ ĐỘ: THỜI GIAN THỰC (Skip log cũ)")
    print("[*] Đang đợi dữ liệu mới... (Nhấn Ctrl+C để dừng)")

    with open(log_file, "r") as f, open(output_file, "a", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        # Nếu file trống thì mới viết Header
        if out.tell() == 0:
            writer.writeheader()
        
        # Nhảy đến cuối file ngay lập tức
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            parsed = parse_line(line)
            if parsed:
                feat = calculate_features(parsed)
                writer.writerow(feat)
                out.flush()
                print(f"[{feat['timestamp']}] Detect {feat['status']} from {feat['ip']} (User: {feat['username']})")

if __name__ == "__main__":
    main()
