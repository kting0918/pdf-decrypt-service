"""pdf-decrypt-service 的 API 測試。

測試用 PDF 全部在測試內以 pypdf 動態產生，不提交任何二進位檔。
認證帳密以 monkeypatch 設定 main.AUTH_USERNAME / main.AUTH_PASSWORD
（兩者為模組層級變數，import 時即讀環境變數，故不能只改 env）。
"""

import base64
import io

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
)

import main

TEST_USER = "test-user"
TEST_PASS = "test-pass"
PDF_PASSWORD = "s3cret-pdf"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def make_pdf(texts, password=None):
    """產生每頁含一行文字的 PDF；給 password 則加密（RC4-128，不需額外套件）。"""
    writer = PdfWriter()
    for text in texts:
        page = writer.add_blank_page(width=200, height=200)
        font = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }
        )
        page[NameObject("/Resources")] = DictionaryObject(
            {
                NameObject("/Font"): DictionaryObject(
                    {NameObject("/F1"): writer._add_object(font)}
                )
            }
        )
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode("latin-1"))
        page[NameObject("/Contents")] = writer._add_object(stream)
    if password is not None:
        writer.encrypt(user_password=password, owner_password=password + "-owner")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def auth_configured(monkeypatch):
    monkeypatch.setattr(main, "AUTH_USERNAME", TEST_USER)
    monkeypatch.setattr(main, "AUTH_PASSWORD", TEST_PASS)


AUTH = (TEST_USER, TEST_PASS)


def pdf_file(content, name="test.pdf"):
    return {"file": (name, content, "application/pdf")}


# ── /health ──────────────────────────────────────────────────────


def test_health_no_auth_required(client, monkeypatch):
    # 即使帳密未設定，/health 也應免認證回 200
    monkeypatch.setattr(main, "AUTH_USERNAME", "")
    monkeypatch.setattr(main, "AUTH_PASSWORD", "")
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ── 認證 ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("endpoint", ["/decrypt", "/render"])
@pytest.mark.parametrize(
    "user,pw",
    [("", ""), (TEST_USER, ""), ("", TEST_PASS)],
    ids=["both-empty", "password-empty", "username-empty"],
)
def test_auth_not_configured_returns_500(client, monkeypatch, endpoint, user, pw):
    monkeypatch.setattr(main, "AUTH_USERNAME", user)
    monkeypatch.setattr(main, "AUTH_PASSWORD", pw)
    r = client.post(endpoint, auth=AUTH, files=pdf_file(make_pdf(["hi"])))
    assert r.status_code == 500
    assert r.json()["detail"] == "Server auth not configured"


@pytest.mark.parametrize("endpoint", ["/decrypt", "/render"])
@pytest.mark.parametrize(
    "creds",
    [(TEST_USER, "wrong"), ("wrong", TEST_PASS), ("wrong", "wrong")],
    ids=["wrong-password", "wrong-username", "both-wrong"],
)
def test_wrong_credentials_returns_401(client, auth_configured, endpoint, creds):
    r = client.post(endpoint, auth=creds, files=pdf_file(make_pdf(["hi"])))
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Basic"


@pytest.mark.parametrize("endpoint", ["/decrypt", "/render"])
def test_missing_credentials_returns_401(client, auth_configured, endpoint):
    r = client.post(endpoint, files=pdf_file(make_pdf(["hi"])))
    assert r.status_code == 401


# ── /decrypt ─────────────────────────────────────────────────────


@pytest.mark.parametrize("endpoint", ["/decrypt", "/render"])
def test_empty_file_returns_400(client, auth_configured, endpoint):
    r = client.post(endpoint, auth=AUTH, files=pdf_file(b""))
    assert r.status_code == 400
    assert r.json()["detail"] == "Empty file"


@pytest.mark.parametrize("password", ["wrong-password", ""], ids=["wrong", "missing"])
def test_decrypt_wrong_password_returns_422(client, auth_configured, password):
    pdf = make_pdf(["Secret"], password=PDF_PASSWORD)
    r = client.post(
        "/decrypt", auth=AUTH, files=pdf_file(pdf), data={"password": password}
    )
    assert r.status_code == 422
    assert r.json()["detail"].startswith("Cannot open PDF")


def test_decrypt_correct_password_returns_text_and_pages(client, auth_configured):
    pdf = make_pdf(["HelloPage1", "HelloPage2"], password=PDF_PASSWORD)
    r = client.post(
        "/decrypt", auth=AUTH, files=pdf_file(pdf), data={"password": PDF_PASSWORD}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pages"] == 2
    assert "HelloPage1" in body["text"]
    assert "HelloPage2" in body["text"]
    assert body["text"].index("HelloPage1") < body["text"].index("HelloPage2")


def test_decrypt_unencrypted_pdf_without_password(client, auth_configured):
    r = client.post("/decrypt", auth=AUTH, files=pdf_file(make_pdf(["Plain"])))
    assert r.status_code == 200
    assert r.json()["pages"] == 1
    assert "Plain" in r.json()["text"]


def test_decrypt_not_a_pdf_returns_422(client, auth_configured):
    r = client.post("/decrypt", auth=AUTH, files=pdf_file(b"this is not a pdf"))
    assert r.status_code == 422


# ── /render ──────────────────────────────────────────────────────


@pytest.mark.parametrize("scale", ["0", "-1", "4.01"])
def test_render_scale_out_of_range_returns_400(client, auth_configured, scale):
    pdf = make_pdf(["x"], password=PDF_PASSWORD)
    r = client.post(
        "/render",
        auth=AUTH,
        files=pdf_file(pdf),
        data={"password": PDF_PASSWORD, "scale": scale},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "scale must be between 0 and 4"


def test_render_scale_4_returns_base64_png(client, auth_configured):
    pdf = make_pdf(["p1", "p2"], password=PDF_PASSWORD)
    r = client.post(
        "/render",
        auth=AUTH,
        files=pdf_file(pdf),
        data={"password": PDF_PASSWORD, "scale": "4"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pages"] == 2
    assert len(body["images"]) == 2
    for b64 in body["images"]:
        png = base64.b64decode(b64, validate=True)
        assert png.startswith(PNG_SIGNATURE)
        # 200pt × scale 4 → 800px 寬（PNG IHDR 寬度位於 byte 16..20）
        assert int.from_bytes(png[16:20], "big") == 800


def test_render_default_scale(client, auth_configured):
    pdf = make_pdf(["p1"])
    r = client.post("/render", auth=AUTH, files=pdf_file(pdf))
    assert r.status_code == 200
    png = base64.b64decode(r.json()["images"][0])
    assert png.startswith(PNG_SIGNATURE)
    assert int.from_bytes(png[16:20], "big") == 400  # 預設 scale 2.0


def test_render_wrong_password_returns_422(client, auth_configured):
    pdf = make_pdf(["x"], password=PDF_PASSWORD)
    r = client.post(
        "/render", auth=AUTH, files=pdf_file(pdf), data={"password": "nope"}
    )
    assert r.status_code == 422


# ── docs 關閉 ────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_disabled(client, path):
    assert client.get(path).status_code == 404
