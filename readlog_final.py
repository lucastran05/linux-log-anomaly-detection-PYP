import re
import time
import csv
from datetime import datetime
from collections import defaultdict, deque

history = defaultdict(deque)
all_events = deque()

def parse_line(line):
    line = line.strip()
    if not line: return None
    
    # 1. Nhận diện sự kiện
    is_fail = any(kw in line for kw in ["Failed password", "authentication failure", "Invalid user"])
    is_success = "Accepted password" in line
    if not (is_fail or is_success): return None

    # 2. Bóc tách dữ liệu bằng Regex nhỏ (Chính xác cao)
    ip_match = re.search(r"(?:from|rhost=)(?P<ip>[\d\.]+)", line)
    user_match = re.search(r"(?:for (?:invalid user )?|user=)(?P<user>\S+)", line)
    pid_match = re.search(r"sshd\[(?P<pid>\d+)\]", line)
    port_match = re.search(r"port\s+(?P<port>\d+)", line)

    ip = ip_match.group('ip') if ip_match else "unknown"
    user = user_match.group('user') if user_match else "unknown"
    pid = pid_match.group('pid') if pid_match else "0"
    port = port_match.group('port') if port_match else "22"

    # 3. Xử lý thời gian (Hỗ trợ định dạng 2026-03-25T...)
    try:
        ts_str = line.split(' ')[0].split('.')[0].replace('T', ' ')
        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except:
        ts = datetime.now()

    return {
        "timestamp": ts,
        "component": "sshd",
        "pid": pid,
        "ip": ip,
        "username": user,
        "port": port,
        "action": "login", # Thêm trường action như Code 0
        "status": "failure" if is_fail else "success",
        "raw": line[-60:],
        "is_invalid_user": 1 if ("invalid user" in line.lower() or "user unknown" in line.lower()) else 0,
        "is_root_attempt": 1 if user == "root" else 0
    }

def calculate_features(row):
    now = row["timestamp"]
    ip = row["ip"]
    history[ip].append(row)
    all_events.append(row)
    while history[ip] and (now - history[ip][0]["timestamp"]).total_seconds() > 300:
        history[ip].popleft()
    while all_events and (now - all_events[0]["timestamp"]).total_seconds() > 300:
        all_events.popleft()

    last_5m_ip = list(history[ip])
    last_1m_ip = [r for r in last_5m_ip if (now - r["timestamp"]).total_seconds() <= 60]

    return {
        **row,
        "fail_count_1m": sum(1 for r in last_1m_ip if r["status"] == "failure"),
        "fail_count_5m": sum(1 for r in last_5m_ip if r["status"] == "failure"),
        "success_count_5m": sum(1 for r in last_5m_ip if r["status"] == "success"),
        "unique_ip_count": len(set(r["ip"] for r in all_events)),
        "unique_user_count": len(set(r["username"] for r in all_events)),
        "time_since_last_attempt": round((now - last_5m_ip[-2]["timestamp"]).total_seconds(), 2) if len(last_5m_ip) > 1 else 0,
        "is_night": 1 if now.hour < 6 or now.hour > 22 else 0,
        "event_frequency": round(len(last_5m_ip) / 5, 2)
    }

def main():
    log_file = "/var/log/auth.log"
    output_file = "realtime_output.csv"
    
    # 18 trường đầy đủ theo đúng yêu cầu của bạn
    fieldnames = [
        "timestamp", "component", "pid", "ip", "username", "port", "action", "status", 
        "raw", "is_invalid_user", "is_root_attempt", "fail_count_1m", "fail_count_5m", 
        "success_count_5m", "unique_ip_count", "unique_user_count", 
        "time_since_last_attempt", "is_night", "event_frequency"
    ]

    print(f"[!] Bắt đầu trích xuất dữ liệu sang: {output_file}")

    with open(log_file, "r") as f, open(output_file, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        out.flush()

        # Đọc dữ liệu cũ
        lines = f.readlines()
        for line in lines:
            parsed = parse_line(line)
            if parsed:
                feat = calculate_features(parsed)
                writer.writerow(feat)
        
        out.flush()
        print("[+] Đã xử lý xong log cũ. Đang đợi log mới...")

        # Chế độ thời gian thực
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
                print(f"[*] New Attack detected from: {feat['ip']}")

if __name__ == "__main__":
    main()
