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

config             = load_config()
TELEGRAM_BOT_TOKEN = config["telegram_bot_token"]
TELEGRAM_CHAT_ID   = config["telegram_chat_id"]

def _send(message: str) -> bool:
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        response = requests.post(api_url, data=payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"   Không thể gửi Telegram: {e}")
        return False


#1. Phishing Alert (VirusTotal) 
def send_phishing_alert(email: str, ioc_type: str, ioc_value: str, malicious_count: int):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if malicious_count >= 10:
        severity = "HIGH"
    elif malicious_count >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    message = (
        f"*PHISHING ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*Threat Type:* `{ioc_type.upper()}`\n"
        f"*Value:* `{ioc_value}`\n\n"
        f"*VirusTotal Results:*\n"
        f"  Malicious: `{malicious_count}` engines\n"
        f"*Severity:* {severity}\n\n"
        f"*Time:* `{timestamp}`"
    )

    ok = _send(message)
    if ok:
        print(f"   Đã gửi phishing alert: {ioc_type.upper()} {ioc_value}")
    return ok

#2. Typosquatting Alert
def send_typosquatting_alert(email: str, typo_result: dict):
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_level = typo_result.get("risk_level", "UNKNOWN")
    risk_emoji = {"HIGH": "", "MEDIUM": "", "LOW": ""}.get(risk_level, "")

    domain      = typo_result.get("domain", "N/A")
    similar_to  = typo_result.get("similar_to", "N/A")
    score       = typo_result.get("similarity_score", 0)

    message = (
        f"*TYPOSQUATTING ALERT*\n\n"
        f"*Sender:* `{email}`\n\n"
        f"*Suspicious Domain:* `{domain}`\n"
        f"*Giống với:* `{similar_to}`\n"
        f"*Độ tương đồng:* `{score}%`\n\n"
        f"*Severity:* {risk_emoji} `{risk_level}`\n"
        f"*Time:* `{timestamp}`"
    )

    ok = _send(message)
    if ok:
        print(f"   Đã gửi typosquatting alert: {domain} → {similar_to} ({score}%)")
    return ok


#3. Combined Alert (Typo + VT cùng 1 URL)
def send_combined_alert(email: str, url: str, vt_score: int, typo_result: dict = None):
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    has_typo   = typo_result and typo_result.get("risk_level") in ("LOW", "MEDIUM", "HIGH")

    # Tính severity tổng hợp
    typo_risk  = typo_result.get("risk_level", "SAFE") if typo_result else "SAFE"
    risk_rank  = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    combined   = max(
        risk_rank.get(typo_risk, 0),
        3 if vt_score >= 10 else 2 if vt_score >= 5 else 1 if vt_score > 0 else 0
    )
    risk_str   = {0: "SAFE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[combined]
    risk_emoji = {"HIGH": "", "MEDIUM": "", "LOW": "", "SAFE": ""}[risk_str]

    # Phần VirusTotal
    vt_section = (
        f"*VirusTotal:* `{vt_score}` engines báo độc hại\n"
        if vt_score > 0
        else "*VirusTotal:*Sạch\n"
    )

    # Phần Typosquatting
    typo_section = ""
    if has_typo:
        typo_section = (
            f"\n*Typosquatting:*\n"
            f"  Domain: `{typo_result['domain']}`\n"
            f"  Giống: `{typo_result.get('similar_to', 'N/A')}` "
            f"(`{typo_result.get('similarity_score', 0)}%`)\n"
        )

    message = (
        f"*THREAT ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*URL:* `{url}`\n\n"
        f"{vt_section}"
        f"{typo_section}\n"
        f"*Severity:* {risk_emoji} `{risk_str}`\n"
        f"*Time:* `{timestamp}`"
    )

    ok = _send(message)
    if ok:
        print(f"   Đã gửi combined alert: {url}")
    return ok


#4. Email Auth Alert (SPF/DKIM/DMARC) 
def send_auth_alert(email: str, auth_result: dict):
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk       = auth_result.get("combined_risk", "UNKNOWN")
    risk_emoji = {"HIGH": "", "MEDIUM": "", "LOW": "", "SAFE": ""}.get(risk, "")
    s_icon     = {"PASS": "", "WARN": "", "FAIL": "", "NOT_FOUND": "?", "UNKNOWN": "?"}

    # Tầng 2 — Header
    h = auth_result.get("header_check")
    if h:
        header_section = (
            f"*Header (Thực tế):*\n"
            f"  {s_icon.get(h['spf'],   '?')} SPF:   `{h['spf']}`\n"
            f"  {s_icon.get(h['dkim'],  '?')} DKIM:  `{h['dkim']}`\n"
            f"  {s_icon.get(h['dmarc'], '?')} DMARC: `{h['dmarc']}`\n\n"
        )
    else:
        header_section = "*Header:* `Không có dữ liệu`\n\n"

    # Tầng 1 — DNS
    d     = auth_result.get("dns_check", {})
    spf   = d.get("spf",   {})
    dmarc = d.get("dmarc", {})
    dkim  = d.get("dkim",  {})

    dns_section = (
        f"*DNS Lookup (Cấu hình):*\n"
        f"  {s_icon.get(spf.get('status'),   '?')} SPF:   `{spf.get('status','?')}`"
        f" {spf.get('policy', spf.get('reason', ''))}\n"
        f"  {s_icon.get(dmarc.get('status'), '?')} DMARC: `{dmarc.get('status','?')}`"
        f" {dmarc.get('policy','') + ' ' + dmarc.get('note','')}\n"
        f"  {s_icon.get(dkim.get('status'),  '?')} DKIM:  `{dkim.get('status','?')}`"
        f" {('selector: ' + dkim['selector']) if dkim.get('selector') else dkim.get('reason','')}\n"
    )

    message = (
        f"🛡️ *EMAIL AUTH ALERT*\n\n"
        f"*Sender:* `{email}`\n"
        f"*Domain:* `{d.get('domain', 'N/A')}`\n\n"
        f"{header_section}"
        f"{dns_section}\n"
        f"*Overall Risk:* {risk_emoji} `{risk}`\n"
        f"*Time:* `{timestamp}`"
    )

    ok = _send(message)
    if ok:
        print(f"   Đã gửi auth alert: {email}")
    return ok


if __name__ == "__main__":
    send_phishing_alert("attacker@example.com", "url", "http://malicious.com", 15)