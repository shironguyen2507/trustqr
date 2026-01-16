import json
import os
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data", "processed")

BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklist_domains.json")
KEYWORDS_FILE = os.path.join(DATA_DIR, "suspicious_keywords.json")
PHISHING_FILE = os.path.join(DATA_DIR, "phishing_samples.json")

# ================== INIT DATA SAFE ==================

def ensure_data():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Tạo dữ liệu mẫu nếu thiếu (để app không crash khi deploy)
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(
                ["fake-login.site", "scam-voucher.xyz", "secure-update.top"],
                f, indent=2, ensure_ascii=False
            )

    if not os.path.exists(KEYWORDS_FILE):
        with open(KEYWORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(
                ["dangnhap", "xacminh", "baomat", "capnhat", "trungthuong"],
                f, indent=2, ensure_ascii=False
            )

    if not os.path.exists(PHISHING_FILE):
        with open(PHISHING_FILE, "w", encoding="utf-8") as f:
            json.dump(
                ["http://fake-login.site/verify?id=123"],
                f, indent=2, ensure_ascii=False
            )

ensure_data()

# ================== LOAD DATA ==================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

BLACKLIST = set(load_json(BLACKLIST_FILE))
KEYWORDS = set(load_json(KEYWORDS_FILE))
PHISHING_DATA = set(load_json(PHISHING_FILE))

# ================== CONFIG ==================

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "cutt.ly"
}

# ================== CORE ==================

def normalize_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""

def analyze_url(url: str):
    score = 0
    warnings = []

    if not url.startswith("http"):
        url = "http://" + url

    domain = normalize_domain(url)

    # 1. Blacklist domain
    if domain in BLACKLIST:
        score += 50
        warnings.append("Domain nằm trong blacklist")

    # 2. Short link
    if domain in SHORTENER_DOMAINS:
        score += 30
        warnings.append("Link rút gọn – dễ che giấu đích đến")

    # 3. HTTPS check
    if not url.startswith("https://"):
        score += 20
        warnings.append("Không sử dụng HTTPS")

    # 4. Keyword scan
    found_keywords = []
    for kw in KEYWORDS:
        if kw.lower() in url.lower():
            found_keywords.append(kw)
            score += 10

    if found_keywords:
        warnings.append("Chứa từ khóa đáng ngờ: " + ", ".join(found_keywords[:5]))

    # 5. Known phishing samples
    if url in PHISHING_DATA:
        score += 40
        warnings.append("URL trùng mẫu phishing đã ghi nhận")

    # Level
    if score > 60:
        level = "HIGH"
        rec = "❌ Không nên truy cập liên kết này."
    elif score > 30:
        level = "MEDIUM"
        rec = "⚠️ Cần thận trọng trước khi truy cập."
    else:
        level = "LOW"
        rec = "✅ Liên kết có vẻ an toàn."

    return {
        "url": url,
        "risk_level": level,
        "score": score,
        "warnings": warnings,
        "recommendation": rec
    }
