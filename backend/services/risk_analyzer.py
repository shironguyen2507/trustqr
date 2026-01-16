import json
import os
import re
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data", "processed")

def load_json(name):
    with open(os.path.join(DATA_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)

BLACKLIST = set(load_json("blacklist_domains.json"))
KEYWORDS = set(load_json("suspicious_keywords.json"))
PHISHING_DATA = set(load_json("phishing_samples.json"))

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "cutt.ly"
}

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
