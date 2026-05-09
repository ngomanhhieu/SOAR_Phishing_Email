import tldextract
import zipfile
import io
import os
import pickle
import requests
import unicodedata
import jellyfish          # pip install jellyfish  (Soundex, Metaphone, Levenshtein)
from thefuzz import fuzz
from urllib.parse import urlparse
from collections import defaultdict

CACHE_FILE = "top_domains_cache.pkl"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TOP_N      = 100_000

# ═══════════════════════════════════════════════════════════════
# PHẦN 1: DỮ LIỆU THAM CHIẾU
# ═══════════════════════════════════════════════════════════════

# 1A. Bảng Homoglyph — ký tự trông giống nhau về mặt thị giác
# Key: ký tự thay thế, Value: ký tự gốc mà nó đang giả
HOMOGLYPH_MAP = {
    # Số → chữ
    '0': 'o',  '1': 'l',  '3': 'e',  '4': 'a',
    '5': 's',  '6': 'g',  '7': 't',  '8': 'b',
    # Chữ hoa → chữ thường (trông giống trong một số font)
    'I': 'l',  'O': '0',
    # Ký tự đặc biệt Unicode trông giống Latin
    'а': 'a',  'е': 'e',  'о': 'o',  'р': 'p',
    'с': 'c',  'х': 'x',  'ν': 'v',  'ι': 'i',
    # Tổ hợp nhiều ký tự → 1 ký tự
    'rn': 'm',  'vv': 'w',  'cl': 'd',  'li': 'h',
    'ri': 'n',  'nn': 'm',  'll': 'u',
}

# 1B. Bàn phím QWERTY — mỗi phím và các phím kề
KEYBOARD_ADJACENCY = {
    'q': ['w', 'a', 's'],
    'w': ['q', 'e', 'a', 's', 'd'],
    'e': ['w', 'r', 's', 'd', 'f'],
    'r': ['e', 't', 'd', 'f', 'g'],
    't': ['r', 'y', 'f', 'g', 'h'],
    'y': ['t', 'u', 'g', 'h', 'j'],
    'u': ['y', 'i', 'h', 'j', 'k'],
    'i': ['u', 'o', 'j', 'k', 'l'],
    'o': ['i', 'p', 'k', 'l'],
    'p': ['o', 'l'],
    'a': ['q', 'w', 's', 'z'],
    's': ['a', 'w', 'e', 'd', 'z', 'x'],
    'd': ['s', 'e', 'r', 'f', 'x', 'c'],
    'f': ['d', 'r', 't', 'g', 'c', 'v'],
    'g': ['f', 't', 'y', 'h', 'v', 'b'],
    'h': ['g', 'y', 'u', 'j', 'b', 'n'],
    'j': ['h', 'u', 'i', 'k', 'n', 'm'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'z': ['a', 's', 'x'],
    'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'],
    'v': ['c', 'f', 'g', 'b'],
    'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'],
    'm': ['n', 'j', 'k'],
    # Số hàng trên
    '1': ['2', 'q', 'w'],
    '2': ['1', '3', 'q', 'w', 'e'],
    '3': ['2', '4', 'w', 'e', 'r'],
    '4': ['3', '5', 'e', 'r', 't'],
    '5': ['4', '6', 'r', 't', 'y'],
    '6': ['5', '7', 't', 'y', 'u'],
    '7': ['6', '8', 'y', 'u', 'i'],
    '8': ['7', '9', 'u', 'i', 'o'],
    '9': ['8', '0', 'i', 'o', 'p'],
    '0': ['9', 'o', 'p'],
}

# ═══════════════════════════════════════════════════════════════
# PHẦN 2: KHỞI TẠO TRANCO LIST
# ═══════════════════════════════════════════════════════════════

def load_tranco_list(top_n: int = TOP_N) -> list:
    if os.path.exists(CACHE_FILE):
        print("[*] Load danh sách domain từ cache...")
        with open(CACHE_FILE, "rb") as f:
            return pickle.load(f)

    print(f"[*] Đang tải Tranco top {top_n} domains (lần đầu ~30s)...")
    response = requests.get(TRANCO_URL, timeout=60)
    zf       = zipfile.ZipFile(io.BytesIO(response.content))

    domains = []
    with zf.open("top-1m.csv") as f:
        for i, line in enumerate(f):
            if i >= top_n:
                break
            parts  = line.decode().strip().split(",")
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
    """Index theo (ký tự đầu, độ dài) để lọc nhanh candidates"""
    index = defaultdict(list)
    for domain in domains:
        name = domain.split(".")[0]
        if name:
            index[(name[0], len(name))].append(domain)
    return index


print("[*] Khởi tạo Typosquatting Scanner (Ensemble Model)...")
TOP_DOMAINS  = load_tranco_list(TOP_N)
DOMAIN_INDEX = build_index(TOP_DOMAINS)
TOP_SET      = set(TOP_DOMAINS[:10_000])
print("[✓] Scanner sẵn sàng")


# ═══════════════════════════════════════════════════════════════
# PHẦN 3: EXTRACT DOMAIN
# ═══════════════════════════════════════════════════════════════

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        ext    = tldextract.extract(netloc)
        return f"{ext.domain}.{ext.suffix}".lower().strip(".")
    except Exception:
        return ""


def get_candidates(domain: str) -> list:
    """Lấy domain ứng viên có cùng ký tự đầu và độ dài ±2"""
    name = domain.split(".")[0]
    if not name:
        return []
    candidates = []
    for delta in range(-2, 3):
        key = (name[0], len(name) + delta)
        candidates.extend(DOMAIN_INDEX.get(key, []))
    return candidates


# ═══════════════════════════════════════════════════════════════
# PHẦN 4: 4 THÀNH PHẦN SCORING
# ═══════════════════════════════════════════════════════════════

# ── 4A. Weighted Edit Distance ──────────────────────────────────
def weighted_edit_distance(s1: str, s2: str) -> float:
    """
    Levenshtein Distance có trọng số:
    - Thay thế homoglyph (l→1, o→0): cost thấp = nguy hiểm hơn
      vì intentional, cố ý lừa mắt người dùng
    - Thay thế bàn phím kề nhau: cost trung bình = typo tự nhiên
    - Thay thế thông thường: cost cao = ít liên quan hơn
    - Thêm/xóa ký tự: cost trung bình

    Score cuối: 0.0 (giống hệt) → 1.0+ (rất khác nhau)
    """
    COST_HOMOGLYPH = 0.1   # Cố ý lừa mắt → nguy hiểm nhất → cost thấp nhất
    COST_KEYBOARD  = 0.5   # Typo tự nhiên → ít nguy hiểm hơn
    COST_NORMAL    = 1.0   # Thay thế thông thường
    COST_INDEL     = 0.8   # Thêm/xóa ký tự

    m, n   = len(s1), len(s2)
    # dp[i][j] = weighted edit distance giữa s1[:i] và s2[:j]
    dp     = [[0.0] * (n + 1) for _ in range(m + 1)]

    # Khởi tạo: biến s1[:i] thành chuỗi rỗng = xóa i ký tự
    for i in range(m + 1):
        dp[i][0] = i * COST_INDEL
    for j in range(n + 1):
        dp[0][j] = j * COST_INDEL

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            c1, c2 = s1[i-1], s2[j-1]

            if c1 == c2:
                cost = 0.0  # Giống nhau → không tốn cost
            elif (HOMOGLYPH_MAP.get(c1) == c2 or
                  HOMOGLYPH_MAP.get(c2) == c1):
                cost = COST_HOMOGLYPH   # Homoglyph → cost rất thấp
            elif c2 in KEYBOARD_ADJACENCY.get(c1, []):
                cost = COST_KEYBOARD    # Phím kề → cost trung bình
            else:
                cost = COST_NORMAL      # Thông thường

            dp[i][j] = min(
                dp[i-1][j]   + COST_INDEL,  # Xóa từ s1
                dp[i][j-1]   + COST_INDEL,  # Thêm vào s1
                dp[i-1][j-1] + cost         # Thay thế
            )

    raw_distance = dp[m][n]
    # Normalize về 0~1: chia cho độ dài chuỗi dài hơn
    normalized   = raw_distance / max(m, n, 1)
    # Convert sang similarity: 1.0 = giống hệt, 0.0 = khác hoàn toàn
    similarity   = max(0.0, 1.0 - normalized)
    return round(similarity, 4)


# ── 4B. Homoglyph Score ─────────────────────────────────────────
def homoglyph_score(domain: str, reference: str) -> float:
    """
    Kiểm tra domain có chứa ký tự homoglyph không.
    Cách làm: chuẩn hóa domain bằng cách thay thế homoglyph → ký tự gốc
    rồi so sánh với reference.

    Ví dụ:
      goog1e.com → normalize → google.com
      google.com == google.com → score = 1.0 (homoglyph hoàn hảo)

      googce.com → normalize → googce.com (không có homoglyph)
      googce.com != google.com → score = 0.0
    """
    def normalize(s: str) -> str:
        """Thay tất cả homoglyph về ký tự gốc"""
        # Xử lý tổ hợp nhiều ký tự trước (rn→m, vv→w)
        result = s
        for combo, replacement in HOMOGLYPH_MAP.items():
            if len(combo) > 1:
                result = result.replace(combo, replacement)
        # Sau đó xử lý ký tự đơn
        result = ''.join(HOMOGLYPH_MAP.get(c, c) for c in result)
        # Chuẩn hóa Unicode (Cyrillic 'а' → Latin 'a')
        result = unicodedata.normalize('NFKD', result)
        result = result.encode('ascii', 'ignore').decode('ascii')
        return result

    domain_name    = domain.split(".")[0]
    reference_name = reference.split(".")[0]

    normalized_domain = normalize(domain_name)

    # Nếu sau khi normalize giống hệt reference → homoglyph hoàn hảo
    if normalized_domain == reference_name:
        return 1.0

    # Tính mức độ tương đồng sau normalize
    similarity = fuzz.ratio(normalized_domain, reference_name) / 100.0

    # Chỉ tính score nếu domain gốc KHÁC reference
    # (tức là có sự biến đổi ký tự xảy ra)
    if domain_name == reference_name:
        return 0.0  # Giống hệt → không phải homoglyph attack

    return round(similarity, 4)


# ── 4C. Keyboard Proximity Score ────────────────────────────────
def keyboard_proximity_score(domain: str, reference: str) -> float:
    """
    Đánh giá khả năng domain là kết quả typo tự nhiên từ bàn phím.

    Với mỗi cặp ký tự khác nhau giữa domain và reference:
    - Nếu 2 phím kề nhau trên bàn phím → typo tự nhiên → score cao
    - Nếu không kề → không phải typo bàn phím → score thấp

    Khác với homoglyph (cố ý lừa), keyboard proximity là nhầm lẫn
    vô tình → ít nguy hiểm hơn về mặt tấn công, nhưng vẫn cần phát hiện.
    """
    d_name = domain.split(".")[0]
    r_name = reference.split(".")[0]

    if d_name == r_name:
        return 0.0  # Giống hệt → không phải keyboard typo

    # Align 2 chuỗi theo độ dài ngắn hơn
    min_len = min(len(d_name), len(r_name))
    if min_len == 0:
        return 0.0

    proximity_scores = []
    for i in range(min_len):
        c1, c2 = d_name[i], r_name[i]
        if c1 == c2:
            proximity_scores.append(1.0)   # Giống nhau hoàn toàn
        elif c2 in KEYBOARD_ADJACENCY.get(c1, []):
            proximity_scores.append(0.7)   # Phím kề nhau → typo tự nhiên
        else:
            proximity_scores.append(0.0)   # Không liên quan

    # Penalize độ dài khác nhau
    length_penalty = min_len / max(len(d_name), len(r_name))

    score = (sum(proximity_scores) / len(proximity_scores)) * length_penalty
    return round(score, 4)


# ── 4D. Phonetic Similarity Score ───────────────────────────────
def phonetic_score(domain: str, reference: str) -> float:
    """
    So sánh âm thanh phát âm giữa 2 domain bằng Soundex và Metaphone.

    Mục đích: Bắt các trường hợp tấn công dựa trên phát âm giống nhau:
      - micosoft.com  vs microsoft.com  (âm gần giống)
      - amazzon.com   vs amazon.com     (âm giống)
      - googel.com    vs google.com     (đảo vị trí)

    Soundex:  mã hóa theo phụ âm (M-000 cho "microsoft")
    Metaphone: chi tiết hơn Soundex, xử lý tốt tiếng Anh

    Score: 1.0 = âm giống hệt, 0.0 = âm khác hoàn toàn
    """
    d_name = domain.split(".")[0]
    r_name = reference.split(".")[0]

    # Bỏ ký tự số trước khi so sánh âm
    d_alpha = ''.join(c for c in d_name if c.isalpha())
    r_alpha = ''.join(c for c in r_name if c.isalpha())

    if not d_alpha or not r_alpha:
        return 0.0

    try:
        # Soundex: mã 4 ký tự (M000, G200...)
        sdx_d = jellyfish.soundex(d_alpha)
        sdx_r = jellyfish.soundex(r_alpha)
        soundex_match = 1.0 if sdx_d == sdx_r else (
            0.5 if sdx_d[0] == sdx_r[0] else 0.0
        )

        # Metaphone: chi tiết hơn soundex
        mph_d = jellyfish.metaphone(d_alpha)
        mph_r = jellyfish.metaphone(r_alpha)
        metaphone_sim = fuzz.ratio(mph_d, mph_r) / 100.0

        # Kết hợp 2 phương pháp
        score = (soundex_match * 0.4 + metaphone_sim * 0.6)
        return round(score, 4)

    except Exception:
        return 0.0


# ═══════════════════════════════════════════════════════════════
# PHẦN 5: ENSEMBLE MODEL
# ═══════════════════════════════════════════════════════════════

# Trọng số cho từng thành phần
WEIGHTS = {
    "edit_distance":  0.30,  # Levenshtein tổng quan
    "homoglyph":      0.35,  # Quan trọng nhất — cố ý lừa mắt
    "keyboard":       0.15,  # Typo tự nhiên — ít nguy hiểm hơn
    "phonetic":       0.20,  # Âm thanh tương tự
}

def ensemble_score(domain: str, reference: str) -> dict:
    """
    Tính điểm tổng hợp từ 4 thành phần.
    Trả về dict chứa điểm từng thành phần và điểm tổng.
    """
    scores = {
        "edit_distance": weighted_edit_distance(domain, reference),
        "homoglyph":     homoglyph_score(domain, reference),
        "keyboard":      keyboard_proximity_score(domain, reference),
        "phonetic":      phonetic_score(domain, reference),
    }

    # Tính điểm tổng có trọng số
    total = sum(scores[k] * WEIGHTS[k] for k in scores)

    return {
        "scores":      scores,
        "total_score": round(total, 4),
        "weights":     WEIGHTS
    }


def classify_risk(total_score: float, has_homoglyph: bool) -> str:
    """
    Phân loại risk dựa trên điểm ensemble.

    Nếu homoglyph score cao → tự động nâng risk vì đây là
    dấu hiệu TẤN CÔNG CỐ Ý, không phải typo tự nhiên.
    """
    if has_homoglyph or total_score >= 0.80:
        return "HIGH"
    elif total_score >= 0.65:
        return "MEDIUM"
    elif total_score >= 0.50:
        return "LOW"
    else:
        return "SAFE"


# ═══════════════════════════════════════════════════════════════
# PHẦN 6: HÀM CHÍNH
# ═══════════════════════════════════════════════════════════════

def scan_typosquatting(url: str) -> dict:
    """
    Hàm chính: kiểm tra URL có phải typosquatting không.

    Quy trình:
    1. Extract domain từ URL
    2. Kiểm tra trong top 10k (nếu có → SAFE)
    3. Lấy candidates từ index (~500 domain)
    4. Với mỗi candidate: tính ensemble score (4 thành phần)
    5. Lấy candidate có điểm cao nhất
    6. Phân loại risk và trả kết quả
    """
    domain = extract_domain(url)
    if not domain:
        return {
            "domain":       url,
            "risk_level":   "UNKNOWN",
            "error":        "Không trích xuất được domain"
        }

    print(f"   [*] Ensemble scan: {domain}")

    # Bước 1: Domain hợp lệ trong top 10k → SAFE ngay
    if domain in TOP_SET:
        print(f"   → Trong Tranco top 10k: SAFE")
        return {
            "domain":       domain,
            "risk_level":   "SAFE",
            "similar_to":   None,
            "total_score":  1.0,
            "detail_scores": {}
        }

    # Bước 2: Lấy candidates từ index
    candidates = get_candidates(domain)
    if not candidates:
        return {
            "domain":       domain,
            "risk_level":   "SAFE",
            "similar_to":   None,
            "total_score":  0.0,
            "detail_scores": {}
        }

    # Bước 3: Tính ensemble score với từng candidate
    best_match       = None
    best_total       = 0.0
    best_detail      = {}
    best_homoglyph   = False

    for legit in candidates:
        result      = ensemble_score(domain, legit)
        total       = result["total_score"]
        has_homoglyph = result["scores"]["homoglyph"] >= 0.85

        if total > best_total:
            best_total     = total
            best_match     = legit
            best_detail    = result["scores"]
            best_homoglyph = has_homoglyph

    # Bước 4: Phân loại risk
    risk_level = classify_risk(best_total, best_homoglyph)

    # In kết quả từng thành phần
    if best_match and risk_level != "SAFE":
        print(f"   → NGHI NGỜ: giống '{best_match}'")
        print(f"      Edit Distance : {best_detail.get('edit_distance', 0):.2f} (×{WEIGHTS['edit_distance']})")
        print(f"      Homoglyph     : {best_detail.get('homoglyph', 0):.2f} (×{WEIGHTS['homoglyph']})")
        print(f"      Keyboard      : {best_detail.get('keyboard', 0):.2f} (×{WEIGHTS['keyboard']})")
        print(f"      Phonetic      : {best_detail.get('phonetic', 0):.2f} (×{WEIGHTS['phonetic']})")
        print(f"      TOTAL SCORE   : {best_total:.2f} → {risk_level}")
    else:
        print(f"   → Score cao nhất: {best_total:.2f} với '{best_match}' → SAFE")

    return {
        "domain":        domain,
        "risk_level":    risk_level,
        "similar_to":    best_match if risk_level != "SAFE" else None,
        "total_score":   best_total,
        "detail_scores": best_detail,
        "has_homoglyph": best_homoglyph
    }


# ═══════════════════════════════════════════════════════════════
# TEST ĐỘC LẬP
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import json, time

    tests = [
        ("http://goog1e.com",       "Homoglyph: 1→l"),
        ("http://paypa1.com",       "Homoglyph: 1→l"),
        ("http://googlе.com",       "Homoglyph: Cyrillic е"),
        ("http://googke.com",       "Keyboard: l→k (phím kề)"),
        ("http://googel.com",       "Transposition: le→el"),
        ("http://micosoft.com",     "Phonetic: giống microsoft"),
        ("http://amazzon.com",      "Double letter: amazon"),
        ("http://googce.com",       "Không có visual match"),
        ("http://google.com",       "Domain hợp lệ"),
        ("http://xyz-random123.com","Domain không liên quan"),
    ]

    print("\n" + "="*60)
    print("ENSEMBLE TYPOSQUATTING SCANNER — TEST RESULTS")
    print("="*60)

    for url, description in tests:
        print(f"\n[TEST] {description}")
        print(f"       URL: {url}")
        t0     = time.time()
        result = scan_typosquatting(url)
        elapsed = time.time() - t0

        risk   = result["risk_level"]
        icon   = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢","SAFE":"✅","UNKNOWN":"⚪"}[risk]
        print(f"       {icon} {risk} | similar_to: {result.get('similar_to')} "
              f"| score: {result.get('total_score'):.2f} | {elapsed:.3f}s")