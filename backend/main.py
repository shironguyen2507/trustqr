from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from services.risk_analyzer import analyze_url
from services.qr_decoder import decode_qr_from_image
import uvicorn

app = FastAPI(title="TrustQR API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/check")
async def check_url(payload: dict):
    url = payload.get("url", "")
    result = analyze_url(url)
    return result

@app.post("/api/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    content = await file.read()
    url = decode_qr_from_image(content)
    if not url:
        return {"error": "Không đọc được QR Code"}
    result = analyze_url(url)
    result["decoded_url"] = url
    return result

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
