class AlertManager:
    def __init__(self):
        pass

    def send_alert(self, data):
        ip = data.get("ip") or data.get("source_ip") or "unknown"
        user = data.get("user") or data.get("username") or "unknown"

        print("\n[!] ALERT: Suspicious activity detected!")
        print(f"User: {user}")
        print(f"IP: {ip}")