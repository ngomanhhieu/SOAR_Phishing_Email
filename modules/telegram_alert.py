import os
import requests
import json
from datetime import datetime

def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
TELEGRAM_BOT_TOKEN = config["telegram_bot_token"]
TELEGRAM_CHAT_ID = config["telegram_chat_id"]

def send_phishing_alert(email: str, ioc_type: str, ioc_value: str, malicious_count: int):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if malicious_count >= 10:
        severity = "HIGH"
    elif malicious_count >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    message = (
        f"*PHISHING ALERT*\n\n"          # ← Bug 3: thêm emoji
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
        print(f"   Đã gửi cảnh báo Telegram cho {ioc_type.upper()}: {ioc_value}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"   Không thể gửi cảnh báo Telegram: {e}")
        return False

def send_typosquatting_alert(email: str, original_domain: str, active_count: int, 
                              risk_level: str, top_variants: list):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    variant_lines = ""
    for v in top_variants[:5]:
        mx_tag = " HAS MX" if v.get("dns_mx") else ""   # ← Bug 2: thêm dấu cách
        variant_lines += f"  • `{v['domain']}` ({v['fuzzer']}){mx_tag}\n"

    if not variant_lines:
        variant_lines = "  _Không có_"

    # ← Bug 1: emoji bị mất, thêm lại
    severity_emoji = {"HIGH": "", "MEDIUM": "", "LOW": ""}.get(risk_level, "")

    message = (
        f"*TYPOSQUATTING ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*Original Domain:* `{original_domain}`\n\n"
        f"*Active Variants Found:* `{active_count}` domains\n"
        f"*Risk Level:* {severity_emoji} `{risk_level}`\n\n"
        f"*Top Suspicious Domains:*\n{variant_lines}\n"
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
        print(f"   Đã gửi cảnh báo typosquatting cho domain: {original_domain}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"   Không thể gửi cảnh báo Telegram: {e}")
        return False

def send_auth_alert(email: str, auth_result: dict):
    """Gửi cảnh báo SPF/DKIM/DMARC (cả 2 tầng) lên Telegram"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk      = auth_result.get("combined_risk", "UNKNOWN")
    risk_emoji = {"HIGH": "", "MEDIUM": "", "LOW": "", "SAFE": ""}.get(risk, "")
    s_icon     = {"PASS": "", "WARN": "", "FAIL": "",
                  "NOT_FOUND": "", "UNKNOWN": ""}

    # Tầng 2 — Header
    h = auth_result.get("header_check")
    if h:
        header_section = (
            f"*Tầng 2 — Email Header (Thực tế):*\n"
            f"  {s_icon.get(h['spf'],  '')} SPF:   `{h['spf']}`\n"
            f"  {s_icon.get(h['dkim'], '')} DKIM:  `{h['dkim']}`\n"
            f"  {s_icon.get(h['dmarc'],'')} DMARC: `{h['dmarc']}`\n\n"
        )
    else:
        header_section = "*Tầng 2 — Email Header:* `Không có dữ liệu`\n\n"

    # Tầng 1 — DNS
    d     = auth_result.get("dns_check", {})
    spf   = d.get("spf",   {})
    dmarc = d.get("dmarc", {})
    dkim  = d.get("dkim",  {})
    dns_section = (
        f"*Tầng 1 — DNS Lookup (Cấu hình domain):*\n"
        f"  {s_icon.get(spf.get('status'),  '')} SPF:   `{spf.get('status','?')}` "
        f"{spf.get('policy', spf.get('reason', ''))}\n"
        f"  {s_icon.get(dmarc.get('status'),'')} DMARC: `{dmarc.get('status','?')}` "
        f"{dmarc.get('policy','') + ' ' + dmarc.get('note','')}\n"
        f"  {s_icon.get(dkim.get('status'), '')} DKIM:  `{dkim.get('status','?')}` "
        f"{('selector: ' + dkim['selector']) if dkim.get('selector') else dkim.get('reason','')}\n"
    )

    message = (
        f"*EMAIL AUTH ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*Domain:* `{d.get('domain', 'N/A')}`\n\n"
        f"{header_section}"
        f"{dns_section}\n"
        f"*Overall Risk:* {risk_emoji} `{risk}`\n"
        f"*Time:* `{timestamp}`"
    )

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        response = requests.post(api_url, data=payload, timeout=10)
        response.raise_for_status()
        print(f"   Đã gửi auth alert cho: {email}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"   Không thể gửi Telegram: {e}")
        return False

if __name__ == "__main__":
    send_phishing_alert(
        email="attacker@example.com",
        ioc_type="url",
        ioc_value="http://malicious-site.com",
        malicious_count=15
    )