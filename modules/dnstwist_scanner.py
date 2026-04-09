import dnstwist
import re
from urllib.parse import urlparse

# Trích xuất domain thuần từ URL
def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Bỏ port nếu có (vd: example.com:8080)
        domain = domain.split(":")[0]
        return domain
    except Exception:
        return ""

def scan_typosquatting(url: str, threshold: int = 5) -> dict:
    """
    Quét typosquatting cho một URL.
    
    Args:
        url: URL cần kiểm tra (vd: http://paypa1.com/login)
        threshold: Ngưỡng cảnh báo - số domain giả mạo đang ACTIVE tối thiểu
    
    Returns:
        dict chứa kết quả phân tích
    """
    domain = extract_domain(url)
    if not domain:
        return {"domain": url, "error": "Không thể trích xuất domain", "active_variants": []}

    print(f"   [*] dnstwist đang quét typosquatting cho domain: {domain}")

    try:
        # Khởi chạy dnstwist
        scanner = dnstwist.run(
            domain=domain,
            registered=True,   # Chỉ lấy domain đã đăng ký
            format="list",
            threads=10
        )

        active_variants = []

        for entry in scanner:
            fuzzer = entry.get("fuzzer", "")
            variant_domain = entry.get("domain", "")
            dns_a = entry.get("dns_a", [])
            dns_mx = entry.get("dns_mx", [])

            # Bỏ qua domain gốc
            if variant_domain == domain:
                continue

            # Chỉ quan tâm domain có DNS A record (đang hoạt động)
            if dns_a:
                active_variants.append({
                    "fuzzer": fuzzer,          # Kiểu biến thể: homoglyph, typo, ...
                    "domain": variant_domain,
                    "dns_a": dns_a,            # IP đang trỏ tới
                    "dns_mx": dns_mx           # Mail server (nguy hiểm hơn nếu có)
                })

        # Đánh giá mức độ nguy hiểm
        count = len(active_variants)
        if count >= 10:
            risk_level = "HIGH"
        elif count >= threshold:
            risk_level = "MEDIUM"
        elif count > 0:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        print(f"   Kết quả: Tìm thấy {count} domain typosquatting đang ACTIVE → {risk_level}")

        return {
            "domain": domain,
            "active_count": count,
            "risk_level": risk_level,
            "active_variants": active_variants
        }

    except Exception as e:
        print(f"   [ERROR] dnstwist lỗi với {domain}: {e}")
        return {"domain": domain, "error": str(e), "active_variants": []}


# Test độc lập
if __name__ == "__main__":
    test_url = "http://paypal.com/login"
    result = scan_typosquatting(test_url)

    import json
    print(json.dumps(result, indent=4, ensure_ascii=False))