import os
import requests
import json
from datetime import datetime

# Load config
def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
TELEGRAM_BOT_TOKEN = config["telegram_bot_token"]
TELEGRAM_CHAT_ID = config["telegram_chat_id"]

# Hàm đa năng gửi cảnh báo phishing lên Telegram
def send_phishing_alert(email: str, ioc_type: str, ioc_value: str, malicious_count: int):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if malicious_count >= 10:
        severity = "HIGH"
    elif malicious_count >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    message = (
        f" *PHISHING ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*Threat Type:* `{ioc_type.upper()}`\n"
        f"*Value:* `{ioc_value}`\n\n"
        f"*VirusTotal Results:*\n"
        f"  Malicious: `{malicious_count}` engines\n"
        f"*Severity:* {severity}\n\n"
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
        print(f"Đã gửi cảnh báo Telegram cho {ioc_type.upper()}: {ioc_value}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Không thể gửi cảnh báo Telegram: {e}")
        return False

# Test độc lập
if __name__ == "__main__":
    send_phishing_alert(
        email="attacker@example.com",
        ioc_type="url",
        ioc_value="http://malicious-site.com",
        malicious_count=15
    )