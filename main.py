# -*- coding: utf-8 -*-
"""
Lead Finder - أداة توليد العملاء
FastAPI + PostgreSQL + Google Places API (New)
المرحلة 1: بحث + حفظ النتائج + واتساب مباشر
"""
import os
import re
import hashlib
import secrets
import datetime
from contextlib import contextmanager

import jwt
import httpx
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------- الإعدادات ----------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-railway")
GOOGLE_PLACES_API_KEY = os.environ.get("GOOGLE_PLACES_API_KEY", "")
JWT_ALGO = "HS256"
TOKEN_DAYS = 30

app = FastAPI(title="Lead Finder API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- قاعدة البيانات ----------------
@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company_name TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS searches (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            query TEXT NOT NULL,
            results_count INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS leads (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            search_id INTEGER REFERENCES searches(id) ON DELETE SET NULL,
            place_id TEXT NOT NULL,
            name TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            whatsapp TEXT DEFAULT '',
            address TEXT DEFAULT '',
            rating REAL,
            reviews_count INTEGER,
            website TEXT DEFAULT '',
            maps_url TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (user_id, place_id)
        );
        ALTER TABLE users ADD COLUMN IF NOT EXISTS logo_base64 TEXT DEFAULT '';
        """)


@app.on_event("startup")
def startup():
    if DATABASE_URL:
        init_db()

# ---------------- كلمات المرور والتوكن ----------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex() == h
    except Exception:
        return False


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def get_current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "غير مصرح / Unauthorized")
    token = authorization[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(401, "جلسة منتهية / Session expired")

# ---------------- النماذج ----------------
class RegisterIn(BaseModel):
    email: str
    password: str
    company_name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


class SearchIn(BaseModel):
    query: str
    language: str = "ar"  # لغة نتائج Google

# ---------------- المصادقة ----------------
@app.post("/api/register")
def register(data: RegisterIn):
    email = data.email.strip().lower()
    if not email or len(data.password) < 6:
        raise HTTPException(400, "بيانات غير صالحة (كلمة المرور 6 أحرف على الأقل)")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            raise HTTPException(400, "البريد مسجل مسبقاً / Email already registered")
        cur.execute(
            "INSERT INTO users (email, password_hash, company_name) VALUES (%s,%s,%s) RETURNING id",
            (email, hash_password(data.password), data.company_name.strip()),
        )
        user_id = cur.fetchone()["id"]
    return {"token": create_token(user_id), "company_name": data.company_name.strip()}


@app.post("/api/login")
def login(data: LoginIn):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (data.email.strip().lower(),))
        user = cur.fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "بيانات الدخول غير صحيحة / Invalid credentials")
    return {"token": create_token(user["id"]), "company_name": user["company_name"]}


@app.get("/api/me")
def me(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, company_name, created_at FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
    if not user:
        raise HTTPException(404, "المستخدم غير موجود")
    return user

# ---------------- البحث عبر Google Places ----------------
def phone_to_whatsapp(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    return f"https://wa.me/{digits}" if len(digits) >= 8 else ""


@app.post("/api/search")
def search(data: SearchIn, user_id: int = Depends(get_current_user)):
    query = data.query.strip()
    if not query:
        raise HTTPException(400, "اكتب القطاع والمدينة أولاً")
    if not GOOGLE_PLACES_API_KEY:
        raise HTTPException(500, "GOOGLE_PLACES_API_KEY غير مضبوط في Railway")

    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY,
        "X-Goog-FieldMask": (
            "places.id,places.displayName,places.formattedAddress,"
            "places.internationalPhoneNumber,places.nationalPhoneNumber,"
            "places.rating,places.userRatingCount,places.websiteUri,places.googleMapsUri"
        ),
    }
    body = {"textQuery": query, "languageCode": data.language, "maxResultCount": 20}

    try:
        resp = httpx.post(
            "https://places.googleapis.com/v1/places:searchText",
            headers=headers, json=body, timeout=30,
        )
    except Exception:
        raise HTTPException(502, "تعذر الاتصال بخدمة Google")

    if resp.status_code != 200:
        raise HTTPException(502, f"خطأ من Google Places: {resp.text[:300]}")

    places = resp.json().get("places", [])

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO searches (user_id, query) VALUES (%s,%s) RETURNING id",
            (user_id, query),
        )
        search_id = cur.fetchone()["id"]

        results = []
        for p in places:
            phone = p.get("internationalPhoneNumber") or p.get("nationalPhoneNumber") or ""
            lead = {
                "place_id": p.get("id", ""),
                "name": (p.get("displayName") or {}).get("text", ""),
                "phone": phone,
                "whatsapp": phone_to_whatsapp(phone),
                "address": p.get("formattedAddress", ""),
                "rating": p.get("rating"),
                "reviews_count": p.get("userRatingCount"),
                "website": p.get("websiteUri", ""),
                "maps_url": p.get("googleMapsUri", ""),
            }
            cur.execute("""
                INSERT INTO leads (user_id, search_id, place_id, name, phone, whatsapp,
                                   address, rating, reviews_count, website, maps_url)
                VALUES (%(user_id)s, %(search_id)s, %(place_id)s, %(name)s, %(phone)s,
                        %(whatsapp)s, %(address)s, %(rating)s, %(reviews_count)s,
                        %(website)s, %(maps_url)s)
                ON CONFLICT (user_id, place_id) DO UPDATE SET
                    phone = EXCLUDED.phone,
                    whatsapp = EXCLUDED.whatsapp,
                    rating = EXCLUDED.rating,
                    reviews_count = EXCLUDED.reviews_count
            """, {**lead, "user_id": user_id, "search_id": search_id})
            results.append(lead)

        cur.execute("UPDATE searches SET results_count=%s WHERE id=%s", (len(results), search_id))

    return {"search_id": search_id, "count": len(results), "leads": results}

# ---------------- السجل ----------------
@app.get("/api/searches")
def list_searches(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, query, results_count, created_at FROM searches "
            "WHERE user_id=%s ORDER BY id DESC LIMIT 50",
            (user_id,),
        )
        return cur.fetchall()


@app.get("/api/searches/{search_id}/leads")
def search_leads(search_id: int, user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM leads WHERE user_id=%s AND search_id=%s ORDER BY rating DESC NULLS LAST",
            (user_id, search_id),
        )
        return cur.fetchall()


@app.get("/api/leads")
def all_leads(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM leads WHERE user_id=%s ORDER BY id DESC LIMIT 500",
            (user_id,),
        )
        return cur.fetchall()

# ---------------- الواجهة ----------------
@app.get("/")
def index():
    return FileResponse("static/index.html")

# ================== المرحلة 2: الشركة + PDF ==================
import html as html_lib
from fastapi.responses import Response

FONT_DIR = "/tmp/fonts"
FONT_URLS = {
    "Tajawal-Regular.ttf": "https://raw.githubusercontent.com/google/fonts/main/ofl/tajawal/Tajawal-Regular.ttf",
    "Tajawal-Bold.ttf": "https://raw.githubusercontent.com/google/fonts/main/ofl/tajawal/Tajawal-Bold.ttf",
}


def ensure_fonts():
    os.makedirs(FONT_DIR, exist_ok=True)
    for name, url in FONT_URLS.items():
        path = os.path.join(FONT_DIR, name)
        if not os.path.exists(path):
            r = httpx.get(url, timeout=30, follow_redirects=True)
            r.raise_for_status()
            with open(path, "wb") as f:
                f.write(r.content)


class CompanyIn(BaseModel):
    company_name: str = ""
    logo_base64: str = ""  # data:image/...;base64,xxxx


@app.get("/api/company")
def get_company(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT company_name, logo_base64 FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    return {"company_name": row["company_name"] or "", "logo_base64": row["logo_base64"] or ""}


@app.post("/api/company")
def save_company(data: CompanyIn, user_id: int = Depends(get_current_user)):
    if len(data.logo_base64) > 2_000_000:
        raise HTTPException(400, "حجم الشعار كبير — اختر صورة أقل من 1.5MB")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET company_name=%s, logo_base64=%s WHERE id=%s",
            (data.company_name.strip(), data.logo_base64, user_id),
        )
    return {"ok": True}


PDF_TEXTS = {
    "ar": {
        "title": "قائمة العملاء المحتملين",
        "search": "البحث", "date": "التاريخ", "count": "عدد النتائج",
        "name": "اسم الشركة", "phone": "الهاتف", "address": "العنوان",
        "rating": "التقييم", "footer": "تم إنشاء هذه القائمة بواسطة",
        "dir": "rtl", "align": "right",
    },
    "en": {
        "title": "Prospective Leads List",
        "search": "Search", "date": "Date", "count": "Results",
        "name": "Business", "phone": "Phone", "address": "Address",
        "rating": "Rating", "footer": "Generated by",
        "dir": "ltr", "align": "left",
    },
}


@app.get("/api/searches/{search_id}/pdf")
def search_pdf(search_id: int, lang: str = "ar", user_id: int = Depends(get_current_user)):
    try:
        from weasyprint import HTML
    except Exception:
        raise HTTPException(500, "مولد PDF غير جاهز — تأكد من وجود ملف nixpacks.toml في المستودع")

    tx = PDF_TEXTS.get(lang, PDF_TEXTS["ar"])

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT company_name, logo_base64 FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        cur.execute("SELECT query, created_at FROM searches WHERE id=%s AND user_id=%s", (search_id, user_id))
        s = cur.fetchone()
        if not s:
            raise HTTPException(404, "البحث غير موجود")
        cur.execute(
            "SELECT * FROM leads WHERE user_id=%s AND search_id=%s ORDER BY rating DESC NULLS LAST",
            (user_id, search_id),
        )
        leads = cur.fetchall()

    ensure_fonts()
    e = html_lib.escape
    company = e(user["company_name"] or "")
    logo_html = f'<img class="logo" src="{user["logo_base64"]}">' if (user["logo_base64"] or "").startswith("data:image") else ""

    rows = "".join(f"""
        <tr>
            <td class="num">{i}</td>
            <td class="name">{e(l['name'] or '')}</td>
            <td class="phone">{e(l['phone'] or '—')}</td>
            <td>{e(l['address'] or '')}</td>
            <td class="rate">{('★ ' + str(l['rating'])) if l['rating'] else '—'}</td>
        </tr>""" for i, l in enumerate(leads, 1))

    doc = f"""<!DOCTYPE html>
<html dir="{tx['dir']}">
<head><meta charset="utf-8">
<style>
@font-face {{ font-family:'Tajawal'; src:url('file://{FONT_DIR}/Tajawal-Regular.ttf'); font-weight:400; }}
@font-face {{ font-family:'Tajawal'; src:url('file://{FONT_DIR}/Tajawal-Bold.ttf'); font-weight:700; }}
@page {{ size:A4; margin:14mm 12mm; }}
body {{ font-family:'Tajawal'; color:#14231E; font-size:11px; }}
.head {{ display:flex; justify-content:space-between; align-items:center;
        border-bottom:3px solid #0E5A4E; padding-bottom:10px; margin-bottom:14px; }}
.brand {{ display:flex; align-items:center; gap:10px; }}
.logo {{ max-height:52px; max-width:120px; }}
.cname {{ font-size:17px; font-weight:700; color:#0E5A4E; }}
h1 {{ font-size:16px; margin:0; color:#0E5A4E; }}
.meta {{ color:#5E7069; font-size:10.5px; margin-bottom:12px; }}
.meta span {{ margin-inline-end:16px; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ background:#0E5A4E; color:#fff; padding:7px 6px; font-size:10.5px; text-align:{tx['align']}; }}
td {{ border-bottom:1px solid #DDE5E1; padding:6px; vertical-align:top; text-align:{tx['align']}; }}
tr:nth-child(even) td {{ background:#F3F7F5; }}
.num {{ color:#5E7069; width:22px; }}
.name {{ font-weight:700; }}
.phone {{ direction:ltr; white-space:nowrap; }}
.rate {{ color:#B8860B; white-space:nowrap; }}
.footer {{ margin-top:14px; text-align:center; color:#8CA29A; font-size:9.5px; }}
</style></head>
<body>
<div class="head">
  <div class="brand">{logo_html}<div class="cname">{company}</div></div>
  <h1>{tx['title']}</h1>
</div>
<div class="meta">
  <span><b>{tx['search']}:</b> {e(s['query'])}</span>
  <span><b>{tx['date']}:</b> {s['created_at'].strftime('%Y-%m-%d')}</span>
  <span><b>{tx['count']}:</b> {len(leads)}</span>
</div>
<table>
<thead><tr><th></th><th>{tx['name']}</th><th>{tx['phone']}</th><th>{tx['address']}</th><th>{tx['rating']}</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<div class="footer">{tx['footer']} {company or 'LeadFinder'} — LeadFinder</div>
</body></html>"""

    pdf_bytes = HTML(string=doc).write_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="leads-{search_id}.pdf"'},
    )
