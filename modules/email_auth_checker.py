import dns.resolver
import re
import ipaddress
from email.utils import parseaddr

# ─────────────────────────────────────────
# TIỆN ÍCH
# ─────────────────────────────────────────
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

# ─────────────────────────────────────────
# THÊM MỚI: Lấy IP thực tế từ header
# ─────────────────────────────────────────
def extract_sender_ip(msg) -> str:
    """
    Lấy IP thực sự của server đã gửi email từ Received headers.
    
    Header Received có dạng:
    Received: from mail.evil.com (mail.evil.com [1.2.3.4])
                                                 ^^^^^^^^ lấy cái này
    Có nhiều Received header (mỗi hop thêm 1 cái),
    lấy cái CUỐI CÙNG = server gốc gửi email.
    """
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return ""

    # Lấy header cuối cùng = server gốc (các header được thêm từ dưới lên)
    last_received = received_headers[-1]

    # Tìm IP trong dấu ngoặc vuông: [1.2.3.4]
    match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', last_received)
    if match:
        return match.group(1)
    return ""

# ─────────────────────────────────────────
# THÊM MỚI: Parse và kiểm tra IP trong SPF
# ─────────────────────────────────────────
def _resolve_spf_ips(spf_record: str, domain: str, depth: int = 0) -> list:
    """
    Bóc tách TẤT CẢ IP được phép từ SPF record, bao gồm:
      - ip4:x.x.x.x          → IP đơn
      - ip4:x.x.x.x/24       → Dải IP (CIDR)
      - include:domain.com    → Đệ quy SPF của domain khác
      - a:domain.com          → A record của domain
      - mx:domain.com         → IP của MX record
    
    depth: giới hạn đệ quy (SPF cho phép tối đa 10 lần lookup)
    """
    if depth > 5:  # Tránh đệ quy vô tận
        return []

    allowed_networks = []

    # 1. ip4:x.x.x.x hoặc ip4:x.x.x.x/24
    for match in re.finditer(r'ip4:([\d./]+)', spf_record):
        try:
            net = ipaddress.ip_network(match.group(1), strict=False)
            allowed_networks.append(net)
        except ValueError:
            pass

    # 2. ip6 (bỏ qua trong hầu hết trường hợp phishing thực tế,
    #    nhưng vẫn parse để đầy đủ)
    for match in re.finditer(r'ip6:([a-fA-F0-9:/]+)', spf_record):
        try:
            net = ipaddress.ip_network(match.group(1), strict=False)
            allowed_networks.append(net)
        except ValueError:
            pass

    # 3. include:domain → Đệ quy lấy SPF của domain đó
    for match in re.finditer(r'include:(\S+)', spf_record):
        included_domain = match.group(1)
        records = _query_txt(included_domain)
        for r in records:
            if r.lower().startswith("v=spf1"):
                sub_nets = _resolve_spf_ips(r, included_domain, depth + 1)
                allowed_networks.extend(sub_nets)

    # 4. a:domain hoặc chỉ "a" → lấy A record của domain hiện tại
    a_match = re.findall(r'\ba(?::(\S+))?\b', spf_record)
    for a_domain in a_match:
        target = a_domain if a_domain else domain
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=5)
            for rdata in answers:
                net = ipaddress.ip_network(str(rdata), strict=False)
                allowed_networks.append(net)
        except Exception:
            pass

    # 5. mx:domain hoặc chỉ "mx" → lấy IP của MX record
    mx_match = re.findall(r'\bmx(?::(\S+))?\b', spf_record)
    for mx_domain in mx_match:
        target = mx_domain if mx_domain else domain
        try:
            mx_answers = dns.resolver.resolve(target, "MX", lifetime=5)
            for mx in mx_answers:
                a_answers = dns.resolver.resolve(str(mx.exchange), "A", lifetime=5)
                for rdata in a_answers:
                    net = ipaddress.ip_network(str(rdata), strict=False)
                    allowed_networks.append(net)
        except Exception:
            pass

    return allowed_networks


def _check_ip_in_spf(sender_ip: str, spf_record: str, domain: str) -> dict:
    """
    Kiểm tra sender_ip có nằm trong danh sách IP được phép của SPF không.
    """
    try:
        ip_obj = ipaddress.ip_address(sender_ip)
    except ValueError:
        return {"result": "ERROR", "reason": f"IP không hợp lệ: {sender_ip}"}

    allowed_networks = _resolve_spf_ips(spf_record, domain)

    # Kiểm tra IP có nằm trong bất kỳ network nào không
    for net in allowed_networks:
        if ip_obj in net:
            return {
                "result":  "PASS",
                "reason":  f"IP {sender_ip} nằm trong {net}",
                "matched": str(net)
            }

    # Không khớp → kiểm tra policy cuối record
    if "-all" in spf_record:
        verdict = "FAIL"
        reason  = f"IP {sender_ip} không được authorize, policy: -all (reject)"
    elif "~all" in spf_record:
        verdict = "SOFTFAIL"
        reason  = f"IP {sender_ip} không được authorize, policy: ~all (softfail)"
    elif "?all" in spf_record:
        verdict = "NEUTRAL"
        reason  = f"IP {sender_ip} không được authorize, policy: ?all (neutral)"
    elif "+all" in spf_record:
        verdict = "PASS"   # +all cho phép mọi IP
        reason  = "policy: +all (nguy hiểm — cho phép mọi server)"
    else:
        verdict = "FAIL"
        reason  = f"IP {sender_ip} không khớp, không có all policy rõ ràng"

    return {"result": verdict, "reason": reason, "matched": None}


# ─────────────────────────────────────────
# VIẾT LẠI: check_spf() có kiểm tra IP
# ─────────────────────────────────────────
def check_spf(domain: str, sender_ip: str = "") -> dict:
    """
    Kiểm tra SPF đầy đủ:
    1. Tìm SPF record trong DNS
    2. Nếu có sender_ip → kiểm tra IP có được authorize không
    3. Nếu không có sender_ip → chỉ đánh giá policy (như cũ)
    """
    records = _query_txt(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "status": "FAIL",
            "reason": "Không có SPF record — domain dễ bị giả mạo",
            "record": None,
            "ip_check": None
        }

    record = spf_records[0]

    # Có IP thực tế → kiểm tra IP đầy đủ
    if sender_ip:
        ip_result = _check_ip_in_spf(sender_ip, record, domain)
        verdict   = ip_result["result"]

        # Map verdict → status
        status_map = {
            "PASS":     "PASS",
            "FAIL":     "FAIL",
            "SOFTFAIL": "WARN",
            "NEUTRAL":  "WARN",
            "ERROR":    "WARN"
        }
        status = status_map.get(verdict, "WARN")

        print(f"      SPF IP check: {ip_result['reason']}")
        return {
            "status":   status,
            "verdict":  verdict,
            "reason":   ip_result["reason"],
            "matched":  ip_result.get("matched"),
            "record":   record,
            "ip_check": sender_ip
        }

    # Không có IP → fallback đánh giá policy như cũ
    if "+all" in record:
        status, policy = "FAIL", "+all (cho phép mọi IP — nguy hiểm)"
    elif "-all" in record:
        status, policy = "WARN", "-all (strict) nhưng không có IP để verify"
    elif "~all" in record:
        status, policy = "WARN", "~all (softfail)"
    elif "?all" in record:
        status, policy = "WARN", "?all (neutral)"
    else:
        status, policy = "WARN", "Không rõ policy"

    return {
        "status":   status,
        "policy":   policy,
        "record":   record,
        "ip_check": None,
        "reason":   "Không có IP sender để verify đầy đủ"
    }


# ─────────────────────────────────────────
# TẦNG 2: Đọc header (giữ nguyên)
# ─────────────────────────────────────────
def extract_auth_from_header(msg) -> dict:
    auth_header = (
        msg.get("Authentication-Results", "") or
        msg.get("ARC-Authentication-Results", "")
    )

    def find_status(header, keyword):
        match = re.search(rf'\b{keyword}=(\w+)', header, re.IGNORECASE)
        return match.group(1).upper() if match else "NOT_FOUND"

    spf   = find_status(auth_header, "spf")
    dkim  = find_status(auth_header, "dkim")
    dmarc = find_status(auth_header, "dmarc")

    statuses   = [spf, dkim, dmarc]
    fail_count = sum(1 for s in statuses if s == "FAIL")
    not_found  = sum(1 for s in statuses if s == "NOT_FOUND")

    if fail_count >= 2:   risk = "HIGH"
    elif fail_count == 1: risk = "MEDIUM"
    elif not_found >= 2:  risk = "LOW"
    else:                 risk = "SAFE"

    print(f"   [Tầng 2 - Header] SPF={spf} | DKIM={dkim} | DMARC={dmarc} → {risk}")
    return {
        "source": "email_header",
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "overall_risk": risk,
        "raw_header": auth_header[:300] if auth_header else "Không có header"
    }


# ─────────────────────────────────────────
# TẦNG 1: DNS Lookup (cập nhật check_spf)
# ─────────────────────────────────────────
def check_dmarc(domain: str) -> dict:
    records      = _query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.upper().startswith("V=DMARC1")]

    if not dmarc_records:
        return {"status": "FAIL", "reason": "Không có DMARC record", "record": None}

    record = dmarc_records[0]
    match  = re.search(r'\bp=(\w+)', record, re.IGNORECASE)
    policy = match.group(1).lower() if match else "none"

    status_map = {
        "reject":     ("PASS", "Reject — email giả bị từ chối"),
        "quarantine": ("WARN", "Quarantine — email giả vào spam"),
        "none":       ("WARN", "None — chỉ monitor, không chặn"),
    }
    status, note = status_map.get(policy, ("WARN", "Không rõ"))
    return {"status": status, "policy": f"p={policy}", "note": note, "record": record}


def check_dkim(domain: str) -> dict:
    SELECTORS = ["default", "google", "mail", "k1",
                 "selector1", "selector2", "dkim", "s1", "s2"]
    for sel in SELECTORS:
        records      = _query_txt(f"{sel}._domainkey.{domain}")
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


def check_dns_auth(sender: str, sender_ip: str = "") -> dict:
    domain = extract_domain(sender)
    if not domain:
        return {"error": "Không trích xuất được domain", "domain": None}

    print(f"   [Tầng 1 - DNS] Kiểm tra domain: {domain}"
          + (f" | sender IP: {sender_ip}" if sender_ip else " | (không có IP)"))

    spf   = check_spf(domain, sender_ip)   # ← truyền IP vào
    dmarc = check_dmarc(domain)
    dkim  = check_dkim(domain)

    statuses = [spf["status"], dmarc["status"], dkim["status"]]
    if "FAIL" in statuses:              risk = "HIGH"
    elif statuses.count("WARN") >= 2:  risk = "MEDIUM"
    elif "WARN" in statuses or "UNKNOWN" in statuses: risk = "LOW"
    else:                              risk = "SAFE"

    print(f"   [Tầng 1 - DNS] SPF={spf['status']} | DMARC={dmarc['status']} "
          f"| DKIM={dkim['status']} → {risk}")

    return {
        "source": "dns_lookup", "domain": domain,
        "overall_risk": risk,
        "spf": spf, "dmarc": dmarc, "dkim": dkim
    }


# ─────────────────────────────────────────
# HÀM TỔNG HỢP
# ─────────────────────────────────────────
def check_email_authentication(sender: str, msg=None) -> dict:
    print(f"\n   [*] Kiểm tra Email Authentication: {sender}")

    sender_ip     = extract_sender_ip(msg) if msg else ""
    if sender_ip:
        print(f"   [*] Sender IP (từ Received header): {sender_ip}")

    header_result = extract_auth_from_header(msg) if msg else None
    dns_result    = check_dns_auth(sender, sender_ip)

    risk_level    = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    r1 = risk_level.get(header_result["overall_risk"], 0) if header_result else 0
    r2 = risk_level.get(dns_result.get("overall_risk", "SAFE"), 0)
    combined      = {0: "SAFE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[max(r1, r2)]

    return {
        "sender":        sender,
        "sender_ip":     sender_ip,
        "combined_risk": combined,
        "header_check":  header_result,
        "dns_check":     dns_result
    }


# ─────────────────────────────────────────
# TEST
# ─────────────────────────────────────────
if __name__ == "__main__":
    import json

    domain = "gmail.com"
    print("=== Test SPF với IP cụ thể ===")

    # Test IP hợp lệ (IP thật của Google)
    r1 = check_spf(domain, sender_ip="209.85.220.41")
    print(json.dumps(r1, indent=4, ensure_ascii=False))

    # Test IP không hợp lệ
    r2 = check_spf(domain, sender_ip="1.2.3.4")
    print(json.dumps(r2, indent=4, ensure_ascii=False))

    # Test không có IP
    r3 = check_spf(domain)
    print(json.dumps(r3, indent=4, ensure_ascii=False))