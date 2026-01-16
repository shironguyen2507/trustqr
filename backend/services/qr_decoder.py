from PIL import Image
import io
import cv2
import numpy as np

def decode_qr_from_image(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        open_cv_image = np.array(img)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(open_cv_image)
        return data if data else None
    except:
        return None
