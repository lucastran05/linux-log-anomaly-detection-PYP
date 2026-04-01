"""
Alert module:
- Hiển thị cảnh báo ra CLI
- Có thể mở rộng: gửi email, webhook, log file
"""

class AlertManager:
    def __init__(self):
        pass

    def send_alert(self, data):
        ip = data.get("ip") or data.get("source_ip") or "unknown"
        user = data.get("user") or data.get("username") or "unknown"
        score = data.get("anomaly_score")

        print("\n[!] ALERT: Suspicious activity detected!")
        print(f"User: {user}")
        print(f"IP: {ip}")
        if score is not None:
            print(f"Anomaly score: {score:.6f}" if isinstance(score, (int, float)) else f"Anomaly score: {score}")
