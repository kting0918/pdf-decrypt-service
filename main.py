import os
import logging
import math
import secrets as secrets_mod
import threading
import time
from collections import deque
from contextlib import contextmanager

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import pypdfium2 as pdfium
import base64
import io

logger = logging.getLogger("pdf-decrypt")

# ── 資源上限 ──────────────────────────────────────────────────────
# 2026-10-21 資安修補：容器 mem_limit 只有 256MB，以下上限避免單一請求把記憶體／CPU 吃光。
# 預設值依實際用量（信用卡帳單、永豐對帳單，數頁、scale=3）留足餘裕，可用環境變數調整。
MAX_UPLOAD_BYTES = int(os.environ.get("PDF_MAX_UPLOAD_BYTES", 20 * 1024 * 1024))
MAX_PAGES = int(os.environ.get("PDF_MAX_PAGES", 40))
# 單頁渲染像素上限：A4 在 scale=3 約 450 萬像素；防止超大頁面尺寸放大渲染成本。
MAX_PIXELS_PER_PAGE = int(os.environ.get("PDF_MAX_PIXELS_PER_PAGE", 20_000_000))
# 同時處理的 PDF 數量；排隊超過逾時就回 503，不讓請求無限堆積。
MAX_CONCURRENT_JOBS = int(os.environ.get("PDF_MAX_CONCURRENT_JOBS", 2))
JOB_QUEUE_TIMEOUT = float(os.environ.get("PDF_JOB_QUEUE_TIMEOUT", 20))
MIN_SCALE = 0.1
MAX_SCALE = 4.0

_job_slots = threading.BoundedSemaphore(MAX_CONCURRENT_JOBS)


@contextmanager
def job_slot():
    if not _job_slots.acquire(timeout=JOB_QUEUE_TIMEOUT):
        raise HTTPException(503, "Server busy, retry later")
    try:
        yield
    finally:
        _job_slots.release()


# ── Auth ──────────────────────────────────────────────────────────
# 2026-09-27 資安修補（M-5）：原本 /decrypt、/render 完全未認證，任何人皆可用本服務
# 的算力（尤其 /render 的 scale 參數可放大渲染成本）並直接打漏洞面。
# 改為 HTTP Basic Auth，帳密由環境變數注入，不寫死在程式碼裡。
security = HTTPBasic()
AUTH_USERNAME = os.environ.get("PDF_DECRYPT_BASIC_AUTH_USERNAME", "")
AUTH_PASSWORD = os.environ.get("PDF_DECRYPT_BASIC_AUTH_PASSWORD", "")

# 2026-10-21：同一來源 10 分鐘內認證失敗 10 次就暫時鎖住，擋暴力猜帳密。
# 服務經 Cloudflare Tunnel 對外，真實來源 IP 在 CF-Connecting-IP；
# 容器只綁 127.0.0.1，外部無法繞過 Cloudflare 偽造這個標頭。
AUTH_FAIL_LIMIT = int(os.environ.get("PDF_AUTH_FAIL_LIMIT", 10))
AUTH_FAIL_WINDOW = float(os.environ.get("PDF_AUTH_FAIL_WINDOW", 600))
_auth_failures: dict[str, deque] = {}
_auth_lock = threading.Lock()


def _client_key(request: Request) -> str:
    return request.headers.get("cf-connecting-ip") or (
        request.client.host if request.client else "unknown"
    )


def _recent_failures(key: str, now: float) -> deque:
    q = _auth_failures.setdefault(key, deque())
    while q and now - q[0] > AUTH_FAIL_WINDOW:
        q.popleft()
    return q


def _prune_auth_failures(now: float):
    # 防止大量不同來源把字典撐大
    if len(_auth_failures) > 10_000:
        for k in [k for k, q in _auth_failures.items() if not q or now - q[-1] > AUTH_FAIL_WINDOW]:
            del _auth_failures[k]


def require_auth(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    if not AUTH_USERNAME or not AUTH_PASSWORD:
        # 環境變數沒設就直接拒絕，避免「忘了設環境變數 = 等於沒認證」的情況。
        raise HTTPException(500, "Server auth not configured")
    key = _client_key(request)
    now = time.monotonic()
    with _auth_lock:
        if len(_recent_failures(key, now)) >= AUTH_FAIL_LIMIT:
            raise HTTPException(429, "Too many failed attempts, retry later")
    user_ok = secrets_mod.compare_digest(credentials.username, AUTH_USERNAME)
    pass_ok = secrets_mod.compare_digest(credentials.password, AUTH_PASSWORD)
    if not (user_ok and pass_ok):
        with _auth_lock:
            _recent_failures(key, now).append(now)
            _prune_auth_failures(now)
        logger.warning("auth failed from %s", key)
        raise HTTPException(
            401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


# 2026-09-27：關閉 /docs、/redoc、/openapi.json，避免公開洩漏 API schema。
app = FastAPI(title="PDF Decrypt Service", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def reject_oversized_body(request: Request, call_next):
    # 依 Content-Length 提早拒絕過大上傳，不必等整個 multipart 收完；
    # 沒帶 Content-Length 的情況由 read_upload() 再把關一次。
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_UPLOAD_BYTES + 64 * 1024:
        return JSONResponse({"detail": "File too large"}, status_code=413)
    return await call_next(request)


@app.get("/health")
def health():
    # 健康檢查維持公開、不需認證，供 Zeabur/watchdog 探活。
    return {"status": "ok"}


def read_upload(file: UploadFile) -> bytes:
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) == 0:
        raise HTTPException(400, "Empty file")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large")
    return content


def open_pdf(content: bytes, password: str):
    try:
        pdf = pdfium.PdfDocument(io.BytesIO(content), password=password or None)
    except Exception as e:
        # 底層錯誤只記 log，不回傳給呼叫端，避免洩漏內部細節。
        logger.info("cannot open PDF: %s", e)
        raise HTTPException(422, "Cannot open PDF (wrong password or invalid file)")
    if len(pdf) > MAX_PAGES:
        pdf.close()
        raise HTTPException(413, f"Too many pages (max {MAX_PAGES})")
    return pdf


# 2026-10-21：端點改為同步 def，FastAPI 會丟到 threadpool 執行，
# PDF 解析與渲染不再卡住 event loop（之前處理大檔時連 /health 都會沒回應）。
@app.post("/decrypt")
def decrypt_pdf(
    file: UploadFile = File(...),
    password: str = Form(""),
    _auth: bool = Depends(require_auth),
):
    """Decrypt a password-protected PDF and extract text."""
    content = read_upload(file)

    with job_slot():
        pdf = open_pdf(content, password)
        pages_text = []
        try:
            for i in range(len(pdf)):
                page = pdf[i]
                try:
                    textpage = page.get_textpage()
                    try:
                        pages_text.append(textpage.get_text_bounded())
                    finally:
                        textpage.close()
                finally:
                    page.close()
        finally:
            pdf.close()

    full_text = "\n\n".join(pages_text)
    return JSONResponse({"text": full_text, "pages": len(pages_text)})


@app.post("/render")
def render_pdf(
    file: UploadFile = File(...),
    password: str = Form(""),
    scale: float = Form(2.0),
    _auth: bool = Depends(require_auth),
):
    """Decrypt PDF and render each page as a base64 PNG image."""
    content = read_upload(file)

    # 2026-09-27：夾住 scale 上限，避免即使有認證的呼叫端誤用也能把渲染成本放到很大（DoS 防呆）。
    # 2026-10-21：補擋 nan／inf（nan 與任何數比較都是 False，原本會繞過檢查），並設下限。
    if not math.isfinite(scale) or not MIN_SCALE <= scale <= MAX_SCALE:
        raise HTTPException(400, f"scale must be between {MIN_SCALE} and {MAX_SCALE:g}")

    with job_slot():
        pdf = open_pdf(content, password)
        images = []
        try:
            for i in range(len(pdf)):
                page = pdf[i]
                try:
                    width, height = page.get_size()
                    if width * height * scale * scale > MAX_PIXELS_PER_PAGE:
                        raise HTTPException(413, f"Page {i + 1} too large to render at this scale")
                    bitmap = page.render(scale=scale)
                    try:
                        pil_image = bitmap.to_pil()
                        buf = io.BytesIO()
                        pil_image.save(buf, format="PNG", optimize=True)
                    finally:
                        bitmap.close()
                    images.append(base64.b64encode(buf.getvalue()).decode("ascii"))
                finally:
                    page.close()
        finally:
            pdf.close()

    return JSONResponse({"images": images, "pages": len(images)})
