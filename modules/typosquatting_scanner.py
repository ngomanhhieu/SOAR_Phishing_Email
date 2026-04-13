import tldextract
import zipfile
import io
import os
import pickle
import requests
from thefuzz import fuzz
from urllib.parse import urlparse
from collections import defaultdict

CACHE_FILE = "top_domains_cache.pkl"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TOP_N      = 100_000

def load_tranco_list(top_n: int = TOP_N) -> list:
    if os.path.exists(CACHE_FILE):
        print("[*] Load danh sách domain từ cache...")
        with open(CACHE_FILE, "rb") as f:
            return pickle.load(f)

    print(f"[*] Đang tải Tranco top {top_n} domains (lần đầu ~30s)...")
    response = requests.get(TRANCO_URL, timeout=60)
    zf = zipfile.ZipFile(io.BytesIO(response.content))

    domains = []
    with zf.open("top-1m.csv") as f:
        for i, line in enumerate(f):
            if i >= top_n:
                break
            parts = line.decode().strip().split(",")
            if len(parts) == 2:
                domain = parts[1].strip().lower()
                ext    = tldextract.extract(domain)
                clean  = f"{ext.domain}.{ext.suffix}".strip(".")
                if clean and "." in clean:
                    domains.append(clean)

    with open(CACHE_FILE, "wb") as f:
        pickle.dump(domains, f)
    print(f"[✓] Đã tải và cache {len(domains)} domains")
    return domains

def build_index(domains: list) -> dict:
    index = defaultdict(list)
    for domain in domains:
        name = domain.split(".")[0]
        if name:
            key = (name[0], len(name))
            index[key].append(domain)
    return index

print("[*] Khởi tạo Typosquatting Scanner...")
TOP_DOMAINS  = load_tranco_list(TOP_N)
DOMAIN_INDEX = build_index(TOP_DOMAINS)
TOP_SET      = set(TOP_DOMAINS[:10_000]) 
print(f"[✓] Scanner sẵn sàng")

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        ext    = tldextract.extract(netloc)
        return f"{ext.domain}.{ext.suffix}".lower().strip(".")
    except Exception:
        return ""

def get_candidates(domain: str) -> list:
    name = domain.split(".")[0]
    if not name:
        return []
    candidates = []
    for delta in range(-2, 3):
        key = (name[0], len(name) + delta)
        candidates.extend(DOMAIN_INDEX.get(key, []))
    return candidates

def scan_typosquatting(url: str, similarity_threshold: int = 85) -> dict:
    domain = extract_domain(url)
    if not domain:
        return {
            "domain":           url,
            "risk_level":       "UNKNOWN",
            "similar_to":       None,
            "similarity_score": 0,
            "error":            "Không trích xuất được domain"
        }

    print(f"   [*] Kiểm tra typosquatting: {domain}")

    if domain in TOP_SET:
        print(f"   → Domain hợp lệ (Tranco top 10k): SAFE")
        return {
            "domain":           domain,
            "risk_level":       "SAFE",
            "similar_to":       None,
            "similarity_score": 100
        }

    candidates = get_candidates(domain)
    if not candidates:
        return {
            "domain":           domain,
            "risk_level":       "SAFE",
            "similar_to":       None,
            "similarity_score": 0
        }

    best_match = None
    best_score = 0
    for legit in candidates:
        score = max(fuzz.ratio(domain, legit), fuzz.partial_ratio(domain, legit))
        if score > best_score:
            best_score = score
            best_match = legit

    if best_score >= similarity_threshold:
        if best_score >= 95:
            risk_level = "HIGH"
        elif best_score >= 88:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        print(f"   → NGHI NGỜ: giống '{best_match}' {best_score}% → {risk_level}")
    else:
        risk_level = "SAFE"
        best_match = None
        print(f"   → Không giống domain hợp lệ nào ({best_score}%) → SAFE")

    return {
        "domain":           domain,
        "risk_level":       risk_level,
        "similar_to":       best_match,
        "similarity_score": best_score
    }

if __name__ == "__main__":
    import json, time
    tests = [
        "http://goog1e.com/login",
        "http://paypa1.com/secure",
        "http://google.com/search",
        "http://vietc0mbank.com",
        "http://arnazon.com",
        "http://xyz-random.com",
    ]
    for url in tests:
        print(f"\n{'='*45}")
        t0      = time.time()
        result  = scan_typosquatting(url)
        elapsed = time.time() - t0
        print(f"   Thời gian: {elapsed:.3f}s")
        print(json.dumps(result, indent=4, ensure_ascii=False))