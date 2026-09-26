import os
import secrets as secrets_mod

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import pypdfium2 as pdfium
import base64
import io

# ── Auth ──────────────────────────────────────────────────────────
# 2026-09-27 資安修補（M-5）：原本 /decrypt、/render 完全未認證，任何人皆可用本服務
# 的算力（尤其 /render 的 scale 參數可放大渲染成本）並直接打漏洞面。
# 改為 HTTP Basic Auth，帳密由環境變數注入，不寫死在程式碼裡。
security = HTTPBasic()
AUTH_USERNAME = os.environ.get("PDF_DECRYPT_BASIC_AUTH_USERNAME", "")
AUTH_PASSWORD = os.environ.get("PDF_DECRYPT_BASIC_AUTH_PASSWORD", "")


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if not AUTH_USERNAME or not AUTH_PASSWORD:
        # 環境變數沒設就直接拒絕，避免「忘了設環境變數 = 等於沒認證」的情況。
        raise HTTPException(500, "Server auth not configured")
    user_ok = secrets_mod.compare_digest(credentials.username, AUTH_USERNAME)
    pass_ok = secrets_mod.compare_digest(credentials.password, AUTH_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(
            401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


# 2026-09-27：關閉 /docs、/redoc、/openapi.json，避免公開洩漏 API schema。
app = FastAPI(title="PDF Decrypt Service", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health():
    # 健康檢查維持公開、不需認證，供 Zeabur/watchdog 探活。
    return {"status": "ok"}


@app.post("/decrypt")
async def decrypt_pdf(
    file: UploadFile = File(...),
    password: str = Form(""),
    _auth: bool = Depends(require_auth),
):
    """Decrypt a password-protected PDF and extract text."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    try:
        pdf = pdfium.PdfDocument(io.BytesIO(content), password=password or None)
    except Exception as e:
        raise HTTPException(422, f"Cannot open PDF: {e}")

    pages_text = []
    for i in range(len(pdf)):
        page = pdf[i]
        textpage = page.get_textpage()
        pages_text.append(textpage.get_text_range())
        textpage.close()
        page.close()
    pdf.close()

    full_text = "\n\n".join(pages_text)
    return JSONResponse({"text": full_text, "pages": len(pages_text)})


@app.post("/render")
async def render_pdf(
    file: UploadFile = File(...),
    password: str = Form(""),
    scale: float = Form(2.0),
    _auth: bool = Depends(require_auth),
):
    """Decrypt PDF and render each page as a base64 PNG image."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # 2026-09-27：夾住 scale 上限，避免即使有認證的呼叫端誤用也能把渲染成本放到很大（DoS 防呆）。
    if scale <= 0 or scale > 4:
        raise HTTPException(400, "scale must be between 0 and 4")

    try:
        pdf = pdfium.PdfDocument(io.BytesIO(content), password=password or None)
    except Exception as e:
        raise HTTPException(422, f"Cannot open PDF: {e}")

    images = []
    for i in range(len(pdf)):
        page = pdf[i]
        bitmap = page.render(scale=scale)
        pil_image = bitmap.to_pil()
        buf = io.BytesIO()
        pil_image.save(buf, format="PNG", optimize=True)
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        images.append(b64)
        page.close()
    pdf.close()

    return JSONResponse({"images": images, "pages": len(images)})
