from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import pypdfium2 as pdfium
import base64
import io

app = FastAPI(title="PDF Decrypt Service")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/decrypt")
async def decrypt_pdf(
    file: UploadFile = File(...),
    password: str = Form(""),
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
):
    """Decrypt PDF and render each page as a base64 PNG image."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

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
