from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import pypdfium2 as pdfium
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
