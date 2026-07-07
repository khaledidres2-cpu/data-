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
        ALTER TABLE users ADD COLUMN IF NOT EXISTS business_description TEXT DEFAULT '';
        ALTER TABLE leads ADD COLUMN IF NOT EXISTS ai_score REAL;
        ALTER TABLE leads ADD COLUMN IF NOT EXISTS ai_reason TEXT DEFAULT '';
        ALTER TABLE leads ADD COLUMN IF NOT EXISTS ai_message TEXT DEFAULT '';
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
    strict_city: bool = True  # استبعاد النتائج خارج المدينة المكتوبة

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
            "nextPageToken,places.id,places.displayName,places.formattedAddress,"
            "places.internationalPhoneNumber,places.nationalPhoneNumber,"
            "places.rating,places.userRatingCount,places.websiteUri,places.googleMapsUri"
        ),
    }

    # نجلب حتى 3 صفحات (60 نتيجة كحد أقصى)
    places, page_token = [], None
    for _ in range(3):
        body = {"textQuery": query, "languageCode": data.language, "maxResultCount": 20}
        if page_token:
            body["pageToken"] = page_token
        try:
            resp = httpx.post(
                "https://places.googleapis.com/v1/places:searchText",
                headers=headers, json=body, timeout=30,
            )
        except Exception:
            if places:
                break
            raise HTTPException(502, "تعذر الاتصال بخدمة Google")
        if resp.status_code != 200:
            if places:
                break
            raise HTTPException(502, f"خطأ من Google Places: {resp.text[:300]}")
        j = resp.json()
        places.extend(j.get("places", []))
        page_token = j.get("nextPageToken")
        if not page_token:
            break

    # فلتر المدينة: نستبعد النتائج التي لا يظهر في عنوانها آخر كلمة من البحث (اسم المدينة عادةً)
    if data.strict_city:
        tokens = [w for w in re.split(r"\s+", query) if len(w) >= 3]
        if len(tokens) >= 2:  # لا نفلتر إذا كان البحث كلمة واحدة
            city = tokens[-1].lower()
            filtered = [p for p in places if city in (p.get("formattedAddress", "") or "").lower()]
            if filtered:  # إذا الفلتر صفّر النتائج نبقي الأصل بدل صفحة فارغة
                places = filtered

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
            "SELECT * FROM leads WHERE user_id=%s AND search_id=%s "
            "ORDER BY ai_score DESC NULLS LAST, rating DESC NULLS LAST",
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
    business_description: str = ""  # وصف نشاط المستخدم — يستخدمه التحليل الذكي


@app.get("/api/company")
def get_company(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT company_name, logo_base64, business_description FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    return {
        "company_name": row["company_name"] or "",
        "logo_base64": row["logo_base64"] or "",
        "business_description": row.get("business_description") or "",
    }


@app.post("/api/company")
def save_company(data: CompanyIn, user_id: int = Depends(get_current_user)):
    if len(data.logo_base64) > 2_000_000:
        raise HTTPException(400, "حجم الشعار كبير — اختر صورة أقل من 1.5MB")
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET company_name=%s, logo_base64=%s, business_description=%s WHERE id=%s",
            (data.company_name.strip(), data.logo_base64, data.business_description.strip(), user_id),
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
            "SELECT * FROM leads WHERE user_id=%s AND search_id=%s "
            "ORDER BY ai_score DESC NULLS LAST, rating DESC NULLS LAST",
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
table.head {{ width:100%; border-collapse:collapse; margin-bottom:14px;
        border-bottom:3px solid #0E5A4E; }}
table.head td {{ border:none; background:none; padding:0 0 10px 0; vertical-align:middle; }}
.brand-cell {{ text-align:{tx['align']}; }}
.title-cell {{ text-align:{'left' if tx['align'] == 'right' else 'right'}; }}
.logo {{ max-height:48px; max-width:110px; vertical-align:middle; }}
.cname {{ font-size:17px; font-weight:700; color:#0E5A4E; display:inline-block;
        vertical-align:middle; margin:0 8px; }}
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
<table class="head"><tr>
  <td class="brand-cell">{logo_html}<span class="cname">{company}</span></td>
  <td class="title-cell"><h1>{tx['title']}</h1></td>
</tr></table>
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

# ================== المرحلة 3: التحليل الذكي (Claude Haiku) ==================
import json

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


class AnalyzeIn(BaseModel):
    language: str = "ar"


@app.post("/api/searches/{search_id}/analyze")
def analyze_search(search_id: int, data: AnalyzeIn, user_id: int = Depends(get_current_user)):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(500, "ANTHROPIC_API_KEY غير مضبوط في Railway — أضفه من تبويب Variables")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT company_name, business_description FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        cur.execute("SELECT query FROM searches WHERE id=%s AND user_id=%s", (search_id, user_id))
        s = cur.fetchone()
        if not s:
            raise HTTPException(404, "البحث غير موجود")
        cur.execute(
            "SELECT id, place_id, name, address, rating, reviews_count, website, ai_score "
            "FROM leads WHERE user_id=%s AND search_id=%s ORDER BY id",
            (user_id, search_id),
        )
        leads = cur.fetchall()

    desc = (user.get("business_description") or "").strip()
    if not desc:
        raise HTTPException(400, "أضف وصف نشاطك التجاري في «إعدادات الشركة» أولاً حتى يعرف التحليل ماذا تبيع ولمن")
    if not leads:
        raise HTTPException(400, "لا توجد نتائج لتحليلها")

    total = len(leads)
    # نحلل فقط غير المحلل — طلب واحد = 10 شركات (سريع وآمن من انقطاع الاتصال)
    pending = [l for l in leads if l.get("ai_score") is None][:10]
    if not pending:
        return {"remaining": 0, "total": total}

    lang_name = "العربية" if data.language == "ar" else "English"

    leads_json = json.dumps([{
        "place_id": l["place_id"],
        "name": l["name"],
        "address": l["address"],
        "rating": l["rating"],
        "reviews": l["reviews_count"],
        "has_website": bool(l["website"]),
    } for l in pending], ensure_ascii=False)

    prompt = f"""أنت محلل مبيعات خبير. مستخدم اسمه/شركته: «{user['company_name'] or 'غير محدد'}».
وصف نشاطه وما يبيعه: «{desc}»
بحث عن عملاء محتملين بكلمات: «{s['query']}» وحصل على قائمة الشركات أدناه.

لكل شركة قيّم مدى ملاءمتها كعميل محتمل لهذا النشاط تحديداً، واكتب:
- score: رقم من 1 إلى 10 (10 = عميل مثالي جداً)
- reason: سبب التقييم في جملة واحدة بلغة {lang_name}
- message: رسالة واتساب افتتاحية موجهة لهذه الشركة بالاسم، بلغة {lang_name}، ودية ومهنية بلا مبالغة تسويقية، 2-3 جمل قصيرة، تنتهي بسؤال بسيط يفتح الحوار. لا تذكر أنك وجدتهم عبر بحث.

الشركات:
{leads_json}

أعد فقط JSON بهذا الشكل بدون أي نص قبله أو بعده وبدون علامات تنسيق:
[{{"place_id": "...", "score": 8, "reason": "...", "message": "..."}}]"""

    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5",
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=90,
        )
    except Exception as exc:
        raise HTTPException(502, f"تعذر الاتصال بخدمة التحليل ({repr(exc)[:150]}) — أعد الضغط للاستئناف")

    if resp.status_code != 200:
        raise HTTPException(502, f"خطأ من خدمة التحليل: {resp.text[:300]}")

    text = "".join(b.get("text", "") for b in resp.json().get("content", []) if b.get("type") == "text")
    m = re.search(r"\[[\s\S]*\]", re.sub(r"```json|```", "", text))
    try:
        items = json.loads(m.group(0)) if m else []
    except Exception:
        items = []
    if not items:
        raise HTTPException(502, "تعذر قراءة نتيجة التحليل — أعد الضغط على الزر للاستئناف")

    with get_db() as conn:
        cur = conn.cursor()
        for it in items:
            cur.execute(
                "UPDATE leads SET ai_score=%s, ai_reason=%s, ai_message=%s "
                "WHERE user_id=%s AND search_id=%s AND place_id=%s",
                (it.get("score"), it.get("reason", ""), it.get("message", ""),
                 user_id, search_id, it.get("place_id", "")),
            )
        cur.execute(
            "SELECT COUNT(*) AS c FROM leads WHERE user_id=%s AND search_id=%s AND ai_score IS NULL",
            (user_id, search_id),
        )
        remaining = cur.fetchone()["c"]

    return {"remaining": remaining, "total": total}


# ================== تشخيص مؤقت (يُحذف لاحقاً) ==================
@app.get("/api/diag")
def diag():
    out = {
        "anthropic_key_set": bool(ANTHROPIC_API_KEY),
        "key_prefix": (ANTHROPIC_API_KEY[:14] + "...") if ANTHROPIC_API_KEY else "",
        "google_key_set": bool(GOOGLE_PLACES_API_KEY),
    }
    if not ANTHROPIC_API_KEY:
        out["verdict"] = "المفتاح غير موجود — أضف ANTHROPIC_API_KEY في متغيرات خدمة data- في Railway"
        return out
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "قل: تم"}],
            },
            timeout=30,
        )
        out["status_code"] = r.status_code
        out["response"] = r.text[:400]
        out["verdict"] = "الاتصال يعمل ✅" if r.status_code == 200 else "الاتصال يصل لكن الخدمة ترفض — اقرأ response"
    except Exception as exc:
        out["error"] = repr(exc)[:400]
        out["verdict"] = "فشل الاتصال الشبكي من الخادم إلى Anthropic — اقرأ error"
    return out
