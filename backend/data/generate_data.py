import json
import random
import string
import os
import csv
from urllib.parse import urlparse

# ================== CẤU HÌNH ==================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")

RAW_CSV_FILE = os.path.join(RAW_DIR, "malicious_phish.csv")

NUM_FAKE_DOMAINS = 10000
NUM_FAKE_URLS = 10000

# ================== THƯ VIỆN MẪU ==================

RISKY_TLDS = [
    ".xyz", ".top", ".vip", ".club", ".online", ".site", ".cc",
    ".info", ".pw", ".icu", ".rest", ".live", ".pro", ".click"
]

PHISHING_KEYWORDS = [
    "dangnhap", "baomat", "xacminh", "capnhat",
    "taikhoan", "xacnhan", "datlai",
    "xacthuc", "uyquyen",
    "kiemtra", "mokhoa", "truycap",
    "phanthuong", "thuong", "uudai", "mienphi",
    "voucher", "khuyenmai", "giamgia",
    "giaohang", "hoadon", "thanhtoan",
    "hotro", "trogiup", "dichvu",
    "nganhang", "vidientu", "tienao", "san",
    "nhanthuong", "giaithuong", "trungthuong",
    "gap", "canhbao", "baomat",
    "login", "secure", "verify", "update",
    "account", "confirm", "reset",
    "authenticate", "signin", "auth",
    "validate", "unlock", "access",
    "reward", "bonus", "offer", "free",
    "voucher", "promo", "discount",
    "shipping", "invoice", "payment",
    "support", "helpdesk", "service",
    "bank", "wallet", "crypto", "exchange",
    "claim", "prize", "winner",
    "verification", "urgent", "alert", "security"
]

BRANDS = [
    "facebook", "google", "zalo", "telegram", "tiktok",
    "shopee", "lazada", "tiki", "amazon", "netflix",
    "paypal", "visa", "mastercard",
    "vietcombank", "techcombank", "bidv", "acb", "mbbank",
    "vnpay", "momo", "zalopay"
]

PATH_PATTERNS = [
    "/login", "/verify", "/secure", "/update",
    "/account", "/confirm", "/reward", "/bonus",
    "/gift", "/payment", "/support", "/secure-login",
    "/update-profile", "/verify-account", "/signin-now",
    "/confirm-payment", "/support-help", "/account-reset",
    "/auth-user", "/verify-identity", "/validate-access"
]

# ================== HÀM TIỆN ÍCH ==================

def rand_str(n=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def random_domain():
    brand = random.choice(BRANDS)
    keyword = random.choice(PHISHING_KEYWORDS)
    noise = rand_str(3)
    tld = random.choice(RISKY_TLDS)
    return f"{brand}-{keyword}{noise}{tld}"

def random_phishing_url(domain):
    path = random.choice(PATH_PATTERNS)
    param = rand_str(12)
    return f"http://{domain}{path}?id={param}"

def extract_domain(url):
    try:
        p = urlparse(url)
        return p.netloc.lower()
    except:
        return ""

# ================== ĐỌC FILE CSV THẬT ==================

def load_real_phishing_urls(csv_file):
    urls = set()
    if not os.path.exists(csv_file):
        print("⚠️ Không tìm thấy malicious_phish.csv – bỏ qua dữ liệu thật.")
        return urls

    print("📥 Đang đọc dữ liệu thật từ malicious_phish.csv ...")
    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            url = row[0].strip()
            if url.startswith("http"):
                urls.add(url)
    print(f"✅ Đã nạp {len(urls)} URL độc hại thật.")
    return urls

# ================== MAIN ==================

def main():
    print("🚀 TRUSTQR – BUILD DATASET")

    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # 1. Load URL thật
    real_urls = load_real_phishing_urls(RAW_CSV_FILE)

    # 2. Sinh domain giả lập
    fake_domains = set()
    while len(fake_domains) < NUM_FAKE_DOMAINS:
        fake_domains.add(random_domain())

    # 3. Sinh URL giả lập
    fake_urls = set()
    while len(fake_urls) < NUM_FAKE_URLS:
        d = random.choice(list(fake_domains))
        fake_urls.add(random_phishing_url(d))

    # 4. Gộp dữ liệu
    all_urls = set(real_urls) | set(fake_urls)

    # 5. Trích domain blacklist
    blacklist_domains = set()
    for u in all_urls:
        d = extract_domain(u)
        if d:
            blacklist_domains.add(d)

    # ================== GHI FILE ==================

    with open(os.path.join(PROCESSED_DIR, "phishing_samples.json"), "w", encoding="utf-8") as f:
        json.dump(sorted(list(all_urls)), f, ensure_ascii=False, indent=2)

    with open(os.path.join(PROCESSED_DIR, "blacklist_domains.json"), "w", encoding="utf-8") as f:
        json.dump(sorted(list(blacklist_domains)), f, ensure_ascii=False, indent=2)

    with open(os.path.join(PROCESSED_DIR, "suspicious_keywords.json"), "w", encoding="utf-8") as f:
        json.dump(sorted(list(set(PHISHING_KEYWORDS))), f, ensure_ascii=False, indent=2)

    # ================== THỐNG KÊ ==================
    print("\n🎉 HOÀN TẤT!")
    print(f"• URL thật          : {len(real_urls)}")
    print(f"• URL giả lập       : {len(fake_urls)}")
    print(f"• Tổng URL          : {len(all_urls)}")
    print(f"• Domain blacklist  : {len(blacklist_domains)}")
    print("\n📁 File đã xuất tại:")
    print(f"  {PROCESSED_DIR}")

if __name__ == "__main__":
    main()
