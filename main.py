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
