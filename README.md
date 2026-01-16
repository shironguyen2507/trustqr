# TrustQR 🔐

TrustQR là hệ thống web giúp kiểm tra độ an toàn của liên kết từ QR Code nhằm phòng tránh phishing và lừa đảo.

## Tính năng

- Quét QR Code
- Phân tích rủi ro URL
- Cảnh báo domain giả mạo
- Dataset mô phỏng > 20.000 URL

## Công nghệ

- Backend: FastAPI
- Frontend: HTML + Tailwind
- Engine: Rule-based phishing detection

## Chạy local

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```
