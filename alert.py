"""
Alert module:
- Hiển thị cảnh báo ra CLI
- Có thể mở rộng: gửi email, webhook, log file
"""

class AlertManager:
    def __init__(self):
        pass

    def send_alert(self, data):

        ip = data.get("ip")
        user = data.get("user")

        print("\n[!] ALERT: Suspicious activity detected!")
        print(f"User: {user}")
        print(f"IP: {ip}")
