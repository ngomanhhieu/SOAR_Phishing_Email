import dns.resolver
import re
from email.utils import parseaddr

def extract_domain(sender: str) -> str:
    _, addr = parseaddr(sender)
    if not addr:
        addr = sender
    if "@" in addr:
        return addr.split("@")[1].strip().lower().rstrip(">")
    return ""

def _query_txt(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []

def extract_auth_from_header(msg) -> dict:
    auth_header = (
        msg.get("Authentication-Results", "") or
        msg.get("ARC-Authentication-Results", "") or
        msg.get("X-Google-DKIM-Signature", "")
    )

    def find_status(header, keyword):
        match = re.search(rf'\b{keyword}=(\w+)', header, re.IGNORECASE)
        return match.group(1).upper() if match else "NOT_FOUND"

    spf   = find_status(auth_header, "spf")
    dkim  = find_status(auth_header, "dkim")
    dmarc = find_status(auth_header, "dmarc")

    # Tính risk từ header
    statuses = [spf, dkim, dmarc]
    fail_count = sum(1 for s in statuses if s == "FAIL")
    not_found  = sum(1 for s in statuses if s == "NOT_FOUND")

    if fail_count >= 2:
        risk = "HIGH"
    elif fail_count == 1:
        risk = "MEDIUM"
    elif not_found >= 2:
        risk = "LOW"    
    else:
        risk = "SAFE"

    print(f"   [Tầng 2 - Header] SPF={spf} | DKIM={dkim} | DMARC={dmarc} → {risk}")

    return {
        "source": "email_header",
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "overall_risk": risk,
        "raw_header": auth_header[:300] if auth_header else "Không có header"
    }

def check_spf(domain: str) -> dict:
    records = _query_txt(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {"status": "FAIL", "reason": "Không có SPF record — dễ bị giả mạo", "record": None}

    record = spf_records[0]

    if "+all" in record:
        return {"status": "FAIL",   "policy": "+all (OPEN — Nguy hiểm!)", "record": record}
    elif "-all" in record:
        return {"status": "PASS",   "policy": "-all (Strict)",             "record": record}
    elif "~all" in record:
        return {"status": "WARN",   "policy": "~all (SoftFail)",           "record": record}
    elif "?all" in record:
        return {"status": "WARN",   "policy": "?all (Neutral)",            "record": record}
    else:
        return {"status": "WARN",   "policy": "Không rõ policy",           "record": record}

def check_dmarc(domain: str) -> dict:
    records = _query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.upper().startswith("V=DMARC1")]

    if not dmarc_records:
        return {"status": "FAIL", "reason": "Không có DMARC record", "record": None}

    record = dmarc_records[0]
    match  = re.search(r'\bp=(\w+)', record, re.IGNORECASE)
    policy = match.group(1).lower() if match else "none"

    status_map = {
        "reject":     ("PASS", "Reject — Email giả bị từ chối"),
        "quarantine": ("WARN", "Quarantine — Email giả vào spam"),
        "none":       ("WARN", "None — Chỉ monitor, không chặn"),
    }
    status, note = status_map.get(policy, ("WARN", "Không rõ"))
    return {"status": status, "policy": f"p={policy}", "note": note, "record": record}

def check_dkim(domain: str) -> dict:
    SELECTORS = ["default", "google", "mail", "k1",
                 "selector1", "selector2", "dkim", "s1", "s2"]

    for sel in SELECTORS:
        records = _query_txt(f"{sel}._domainkey.{domain}")
        dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
        if dkim_records:
            record = dkim_records[0]
            return {
                "status":   "PASS",
                "selector": sel,
                "record":   record[:80] + "..." if len(record) > 80 else record
            }

    return {
        "status": "UNKNOWN",
        "reason": "Không tìm thấy DKIM với các selector phổ biến",
        "tried":  SELECTORS
    }

def check_dns_auth(sender: str) -> dict:
    """Tầng 1: Query DNS trực tiếp để kiểm tra cấu hình domain"""
    domain = extract_domain(sender)
    if not domain:
        return {"error": "Không trích xuất được domain", "domain": None}

    print(f"   [Tầng 1 - DNS]    Kiểm tra SPF/DKIM/DMARC cho: {domain}")

    spf   = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim  = check_dkim(domain)

    statuses = [spf["status"], dmarc["status"], dkim["status"]]
    if "FAIL" in statuses:
        risk = "HIGH"
    elif statuses.count("WARN") >= 2:
        risk = "MEDIUM"
    elif "WARN" in statuses or "UNKNOWN" in statuses:
        risk = "LOW"
    else:
        risk = "SAFE"

    print(f"   [Tầng 1 - DNS]    SPF={spf['status']} | DMARC={dmarc['status']} | DKIM={dkim['status']} → {risk}")

    return {
        "source":       "dns_lookup",
        "domain":       domain,
        "overall_risk": risk,
        "spf":          spf,
        "dmarc":        dmarc,
        "dkim":         dkim
    }

def check_email_authentication(sender: str, msg=None) -> dict:
    print(f"\n [*] Bắt đầu kiểm tra Email Authentication cho: {sender}")
    header_result = None
    if msg is not None:
        header_result = extract_auth_from_header(msg)
    dns_result = check_dns_auth(sender)
    risk_level = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    r1 = risk_level.get(header_result["overall_risk"], 0) if header_result else 0
    r2 = risk_level.get(dns_result.get("overall_risk", "SAFE"), 0)
    combined_risk = max(r1, r2)
    combined_risk_str = {0: "SAFE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[combined_risk]

    return {
        "sender":        sender,
        "combined_risk": combined_risk_str,
        "header_check":  header_result,   
        "dns_check":     dns_result
    }

if __name__ == "__main__":
    import json
    result = check_email_authentication("test@gmail.com")
    print(json.dumps(result, indent=4, ensure_ascii=False))