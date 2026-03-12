import os
import requests
import json
from datetime import datetime

# Load config
def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
    with open(config_path, "r") as f:
        return json.load(f)
config = load_config()
TELEGRAM_BOT_TOKEN = config["telegram_bot_token"]
TELEGRAM_CHAT_ID = config["telegram_chat_id"]
# Hàm gửi cảnh báo phishing lên Telegram
def send_phishing_alert(email: str, url: str, malicious_count: int, suspicious_count: int, sender_ip: str = "N/A"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if malicious_count >= 10:
        severity = "HIGH"
    elif malicious_count >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    message = (
        f"*PHISHING ALERT*\n\n"
        f"*Email:* `{email}`\n"
        f"*URL:* `{url}`\n"
        f"*Sender IP:* `{sender_ip}`\n\n"
        f"*VirusTotal Results:*\n"
        f"  Malicious: `{malicious_count}` engines\n"
        f"  Suspicious: `{suspicious_count}` engines\n"
        f"*Severity:* `{severity}`\n\n"
        f"*Time:* `{timestamp}`"
    )
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(api_url, data=payload, timeout=10)
        response.raise_for_status()
        print(f"Telegram alert sent for URL: {url}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Telegram alert: {e}")
        return False

'''
def send_summary_alert(total_scanned: int, total_malicious: int, top_threats: list):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threat_lines = ""
    for i, (url, count) in enumerate(top_threats[:5], 1):
        threat_lines += f"   {i}. `{url}` — {count} detections\n"
    message = (
        f"*PHISHING SUMMARY REPORT*\n\n"
        f"Total Scanned: `{total_scanned}`\n"
        f"Total Malicious: `{total_malicious}`\n"
        f"Detection Rate: `{(total_malicious/total_scanned*100):.1f}%`\n\n"
        f"*Top Threats:*\n"
        f"{threat_lines}"
        f"*Generated:* `{timestamp}`"
    )
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(api_url, data=payload, timeout=10)
        response.raise_for_status()
        print(f"Summary report sent to Telegram.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send summary: {e}")
        return False
'''
# Test
if __name__ == "__main__":
    send_phishing_alert(
        email="attacker@example.com",
        url="http://malicious-site.com",
        malicious_count=15,
        suspicious_count=3,
        sender_ip="192.168.1.100"
    )