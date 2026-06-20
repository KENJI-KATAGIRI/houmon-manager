from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, hashlib, secrets, json, os, csv, io, smtplib, calendar
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import jwt
try:
    from openai import OpenAI as OpenAIClient
except ImportError:
    OpenAIClient = None

from database import get_db, init_db

SECRET_KEY = os.environ.get("SECRET_KEY") or (_ for _ in ()).throw(ValueError("SECRET_KEY env var not set"))
ALGORITHM = "HS256"

# ── ブルートフォース対策 ──────────────────────────────────────────
import time as _time
from collections import defaultdict as _defaultdict
_login_attempts: dict = _defaultdict(list)
_LIMIT_COUNT = 10
_LIMIT_WINDOW = 600

def _get_real_ip(request) -> str:
    return (request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or getattr(request.client, "host", "unknown"))

def _check_rate_limit(ip: str):
    now = _time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _LIMIT_WINDOW]
    if len(_login_attempts[ip]) >= _LIMIT_COUNT:
        raise HTTPException(429, "Too many login attempts. Try again in 10 minutes.")
    _login_attempts[ip].append(now)

BASE_PATH = "/houmon"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, root_path=BASE_PATH)

# ── nginx経由以外の直接ポートアクセス遮断 ─────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as _StarResponse

class _LocalhostOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_host = getattr(request.client, "host", "")
        # nginx経由（X-Real-IP設定あり）またはlocalhost直接アクセスを許可
        if client_host in ("127.0.0.1", "::1", "localhost"):
            return await call_next(request)
        if request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For"):
            return await call_next(request)
        return _StarResponse("Forbidden", status_code=403)

app.add_middleware(_LocalhostOnlyMiddleware)

# ── セキュリティレスポンスヘッダー ────────────────────────────────
class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Server"] = ""
        return response

app.add_middleware(_SecurityHeadersMiddleware)


app.add_middleware(CORSMiddleware,
    allow_origins=[
        "https://gaiaarts.org", "https://www.gaiaarts.org",
        "https://meet.gaiaarts.org", "https://life-energy-coaching.net",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"])
init_db()
# ── stripe_customer_id カラム追加 ──
try:
    _db = get_db()
    _db.execute("ALTER TABLE offices ADD COLUMN stripe_customer_id TEXT")
    _db.commit()
except Exception:
    pass

app.mount("/static", StaticFiles(directory="static"), name="static")

# ── auth helpers ──────────────────────────────────────────────

# ── パスワードハッシュ (bcrypt + SHA256後方互換) ──────────────────
import hashlib as _hashlib
try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

def hash_pw(pw: str, salt: str = "") -> str:
    if _BCRYPT_AVAILABLE:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(rounds=12)).decode()
    return _hashlib.sha256((pw + salt).encode()).hexdigest()

def verify_pw(pw: str, stored_hash: str, salt: str = "") -> bool:
    if _BCRYPT_AVAILABLE and (stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$")):
        try:
            return _bcrypt.checkpw(pw.encode(), stored_hash.encode())
        except Exception:
            return False
    return _hashlib.sha256((pw + salt).encode()).hexdigest() == stored_hash

def make_token(oid, username):
    exp = datetime.utcnow() + timedelta(days=30)
    return jwt.encode({"sub": str(oid), "username": username, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)
def current_office(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    try:
        p = jwt.decode(auth[7:], SECRET_KEY, algorithms=[ALGORITHM])
        return int(p["sub"])
    except: raise HTTPException(401)
def check_active(oid, db):
    row = db.execute("SELECT subscription_status, trial_end FROM offices WHERE id=?", (oid,)).fetchone()
    if not row: raise HTTPException(403)
    if row["subscription_status"] == "active": return
    if row["subscription_status"] == "trial":
        if row["trial_end"] and datetime.now() > datetime.fromisoformat(row["trial_end"]): raise HTTPException(403, "trial_expired")
        return
    raise HTTPException(403)

# ── models ────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str; password: str
class RegisterReq(BaseModel):
    username: str; office_name: str; email: str; password: str
class ClientReq(BaseModel):
    name: str; kana: Optional[str]=""; gender: Optional[str]=""
    birthdate: Optional[str]=""; care_level: Optional[int]=1
    address: Optional[str]=""; phone: Optional[str]=""
    family_name: Optional[str]=""; family_phone: Optional[str]=""; family_relation: Optional[str]=""
    care_manager: Optional[str]=""; care_manager_phone: Optional[str]=""
    allergies: Optional[str]=""; notes: Optional[str]=""
class HelperReq(BaseModel):
    name: str; kana: Optional[str]=""; phone: Optional[str]=""
    employment_type: Optional[str]="part"; qualification: Optional[str]="helper2"
    area: Optional[str]=""; notes: Optional[str]=""
class VisitPlanReq(BaseModel):
    client_id: int; helper_id: Optional[int]=None
    plan_date: str; start_time: str; end_time: str
    service_type: Optional[str]="body"; notes: Optional[str]=""
class VisitRecordReq(BaseModel):
    visit_plan_id: Optional[int]=None; client_id: int; helper_id: Optional[int]=None
    visit_date: str; checkin_time: Optional[str]=""; checkout_time: Optional[str]=""
    services: Optional[str]=""; body_care: Optional[str]=""; life_support: Optional[str]=""
    client_condition: Optional[str]="normal"; notes: Optional[str]=""; helper_notes: Optional[str]=""
class CheckinReq(BaseModel):
    visit_plan_id: Optional[int]=None; client_id: int; helper_id: Optional[int]=None
    visit_date: str; checkin_time: str
class CheckoutReq(BaseModel):
    checkout_time: str; body_care: Optional[str]=""; life_support: Optional[str]=""
    client_condition: Optional[str]="normal"; notes: Optional[str]=""; helper_notes: Optional[str]=""
class MessageReq(BaseModel):
    sender_type: str; sender_name: str; recipient_name: Optional[str]=""
    client_id: Optional[int]=None; content: str; priority: Optional[str]="normal"
class IncidentReq(BaseModel):
    client_id: Optional[int]=None; incident_date: str; incident_time: str
    helper_name: Optional[str]=""; location: Optional[str]=""; category: str
    level: Optional[str]="hiyari"; description: str
    action_taken: Optional[str]=""; followup: Optional[str]=""
class HandoverReq(BaseModel):
    sender_name: str; content: str; category: Optional[str]="general"
class CarePlanReq(BaseModel):
    client_id: int; plan_created: Optional[str]=""; careplan_updated: Optional[str]=""
    next_review: Optional[str]=""; service_content: Optional[str]=""
    goals: Optional[str]=""; notes: Optional[str]=""
class TrainingReq(BaseModel):
    helper_id: Optional[int]=None; helper_name: str; training_type: str
    plan_date: Optional[str]=""; done_date: Optional[str]=""
    content: Optional[str]=""; trainer: Optional[str]=""; notes: Optional[str]=""
class MeetingReq(BaseModel):
    meeting_date: str; attendees: Optional[str]=""; agenda: Optional[str]=""; minutes: Optional[str]=""

# ── pages ─────────────────────────────────────────────────────
GMAIL_USER = os.environ.get("GMAIL_USER", "")
GMAIL_PASS = os.environ.get("GMAIL_PASS", "")
BUG_REPORT_TO = os.environ.get("BUG_REPORT_TO", "kenji.kys@gmail.com")

try:
    import requests as _requests
except ImportError:
    _requests = None

import threading as _threading
import copy as _copy

def _gas_send_bg(webhook_url: str, payload: dict):
    if not _requests or not webhook_url:
        return
    data = _copy.deepcopy(payload)
    def _send():
        try:
            _requests.post(webhook_url, json=data, timeout=5)
        except Exception:
            pass
    _threading.Thread(target=_send, daemon=True).start()

def send_gmail(to: str, subject: str, body: str):
    if not GMAIL_USER or not GMAIL_PASS:
        return
    import ssl
    from email.mime.text import MIMEText
    from email.header import Header
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = f"OWL Manager <{GMAIL_USER}>"
    msg["To"] = to
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context()) as s:
        s.login(GMAIL_USER, GMAIL_PASS)
        s.send_message(msg)

@app.get("/", response_class=HTMLResponse)
@app.get("", response_class=HTMLResponse)
async def index():
    with open("static/index.html", encoding="utf-8") as f: return f.read()

# ── auth ──────────────────────────────────────────────────────
@app.post("/api/register")
async def register(req: RegisterReq, request: Request):
    if len(req.password) < 8 or len(req.password) > 128:
        raise HTTPException(400, "パスワードは8〜128文字で設定してください")
    if len(req.username) < 1 or len(req.username) > 100:
        raise HTTPException(400, "ユーザー名は1〜100文字で設定してください")
    _check_rate_limit(_get_real_ip(request))
    db = get_db()
    if db.execute("SELECT id FROM offices WHERE username=?", (req.username,)).fetchone():
        db.close(); raise HTTPException(400, "already_exists")
    salt = secrets.token_hex(16)
    trial_end = (datetime.now()+timedelta(days=30)).isoformat()
    db.execute("INSERT INTO offices (username,office_name,email,pw_hash,pw_salt,plan,subscription_status,trial_end) VALUES (?,?,?,?,?,?,?,?)",
        (req.username, req.office_name, req.email, hash_pw(req.password,salt), salt, "trial","trial", trial_end))
    db.commit()
    row = db.execute("SELECT id FROM offices WHERE username=?", (req.username,)).fetchone()
    db.close()
    return {"token": make_token(row["id"], req.username), "office_name": req.office_name}

@app.post("/api/login")
async def login(req: LoginReq, request: Request):

    _check_rate_limit(_get_real_ip(request))
    db = get_db()
    row = db.execute("SELECT * FROM offices WHERE username=?", (req.username,)).fetchone()
    db.close()
    if not row or not verify_pw(req.password, row["pw_hash"], row["pw_salt"]): raise HTTPException(401, "invalid")
    return {"token": make_token(row["id"], req.username), "office_name": row["office_name"],
            "plan": row["plan"], "subscription_status": row["subscription_status"]}

@app.get("/api/me")
async def me(oid: int = Depends(current_office)):
    db = get_db()
    row = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end,new_mode,jigyosho_no FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    return dict(row)

# ── dashboard ─────────────────────────────────────────────────
@app.get("/api/dashboard")
async def dashboard(oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    now_time = datetime.now().strftime("%H:%M")
    clients = db.execute("SELECT COUNT(*) as c FROM clients WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
    helpers = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
    today_plans = db.execute("SELECT COUNT(*) as c FROM visit_plans WHERE office_id=? AND plan_date=?", (oid, today)).fetchone()["c"]
    checked_in = db.execute("""SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date=? AND checkin_time!='' AND checkout_time=''""", (oid, today)).fetchone()["c"]
    completed = db.execute("""SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date=? AND checkout_time!=''""", (oid, today)).fetchone()["c"]
    unread_msg = db.execute("SELECT COUNT(*) as c FROM messages WHERE office_id=? AND is_read=0", (oid,)).fetchone()["c"]
    unread_handovers = db.execute("SELECT COUNT(*) as c FROM handovers WHERE office_id=? AND is_read=0", (oid,)).fetchone()["c"]
    incidents_month = db.execute("SELECT COUNT(*) as c FROM incidents WHERE office_id=? AND incident_date LIKE ?", (oid, today[:7]+"%")).fetchone()["c"]
    in30 = (datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d")
    cp_overdue = db.execute("SELECT COUNT(*) as c FROM care_plans WHERE office_id=? AND next_review<? AND next_review!=''", (oid, today)).fetchone()["c"]
    cp_soon = db.execute("SELECT COUNT(*) as c FROM care_plans WHERE office_id=? AND next_review BETWEEN ? AND ? AND next_review!=''", (oid, today, in30)).fetchone()["c"]
    total_h = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
    kaigo_h = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1 AND qualification='care3'", (oid,)).fetchone()["c"]
    three_ago = (datetime.now() - timedelta(days=35)).strftime("%Y-%m-%d")
    mtg_ok = db.execute("SELECT COUNT(*) as c FROM monthly_meetings WHERE office_id=? AND meeting_date>=?", (oid, three_ago)).fetchone()["c"]
    tokutei_gap = not (kaigo_h / total_h >= 0.1 if total_h > 0 else False) or not mtg_ok
    today_visits = db.execute("""
        SELECT vp.*, c.name as client_name, c.address, h.name as helper_name,
               vr.id as record_id, vr.checkin_time, vr.checkout_time, vr.client_condition
        FROM visit_plans vp
        JOIN clients c ON c.id=vp.client_id
        LEFT JOIN helpers h ON h.id=vp.helper_id
        LEFT JOIN visit_records vr ON vr.visit_plan_id=vp.id AND vr.visit_date=?
        WHERE vp.office_id=? AND vp.plan_date=?
        ORDER BY vp.start_time""", (today, oid, today)).fetchall()
    recent_msg = db.execute("SELECT * FROM messages WHERE office_id=? ORDER BY created_at DESC LIMIT 5", (oid,)).fetchall()
    db.close()
    return {
        "clients": clients, "helpers": helpers, "today_plans": today_plans,
        "checked_in": checked_in, "completed": completed,
        "unread_msg": unread_msg, "unread_handovers": unread_handovers,
        "incidents_month": incidents_month,
        "cp_overdue": cp_overdue, "cp_soon": cp_soon, "tokutei_gap": tokutei_gap,
        "today_visits": [dict(r) for r in today_visits],
        "recent_msg": [dict(r) for r in recent_msg],
        "today": today, "now_time": now_time
    }

# ── clients ───────────────────────────────────────────────────
@app.get("/api/clients")
async def get_clients(oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    rows = db.execute("SELECT * FROM clients WHERE office_id=? AND is_active=1 ORDER BY kana", (oid,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/clients")
async def create_client(req: ClientReq, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    db.execute("""INSERT INTO clients (office_id,name,kana,gender,birthdate,care_level,address,phone,
        family_name,family_phone,family_relation,care_manager,care_manager_phone,allergies,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (oid,req.name,req.kana,req.gender,req.birthdate,req.care_level,req.address,req.phone,
         req.family_name,req.family_phone,req.family_relation,req.care_manager,req.care_manager_phone,req.allergies,req.notes))
    db.commit()
    cid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    db.close()
    return dict(row)

@app.get("/api/clients/{cid}")
async def get_client(cid: int, oid: int = Depends(current_office)):
    db = get_db()
    row = db.execute("SELECT * FROM clients WHERE id=? AND office_id=?", (cid, oid)).fetchone()
    db.close()
    if not row: raise HTTPException(404)
    return dict(row)

@app.put("/api/clients/{cid}")
async def update_client(cid: int, req: ClientReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("""UPDATE clients SET name=?,kana=?,gender=?,birthdate=?,care_level=?,address=?,phone=?,
        family_name=?,family_phone=?,family_relation=?,care_manager=?,care_manager_phone=?,allergies=?,notes=?
        WHERE id=? AND office_id=?""",
        (req.name,req.kana,req.gender,req.birthdate,req.care_level,req.address,req.phone,
         req.family_name,req.family_phone,req.family_relation,req.care_manager,req.care_manager_phone,
         req.allergies,req.notes,cid,oid))
    db.commit()
    row = db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    db.close()
    return dict(row)

@app.delete("/api/clients/{cid}")
async def delete_client(cid: int, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("UPDATE clients SET is_active=0 WHERE id=? AND office_id=?", (cid, oid))
    db.commit(); db.close()
    return {"ok": True}

# ── helpers ───────────────────────────────────────────────────
@app.get("/api/helpers")
async def get_helpers(oid: int = Depends(current_office)):
    db = get_db()
    rows = db.execute("SELECT * FROM helpers WHERE office_id=? AND is_active=1 ORDER BY kana", (oid,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/helpers")
async def create_helper(req: HelperReq, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("INSERT INTO helpers (office_id,name,kana,phone,employment_type,qualification,area,notes) VALUES (?,?,?,?,?,?,?,?)",
        (oid,req.name,req.kana,req.phone,req.employment_type,req.qualification,req.area,req.notes))
    db.commit()
    hid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("SELECT * FROM helpers WHERE id=?", (hid,)).fetchone()
    db.close()
    return dict(row)

@app.put("/api/helpers/{hid}")
async def update_helper(hid: int, req: HelperReq, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("UPDATE helpers SET name=?,kana=?,phone=?,employment_type=?,qualification=?,area=?,notes=? WHERE id=? AND office_id=?",
        (req.name,req.kana,req.phone,req.employment_type,req.qualification,req.area,req.notes,hid,oid))
    db.commit()
    row = db.execute("SELECT * FROM helpers WHERE id=?", (hid,)).fetchone()
    db.close()
    return dict(row)

@app.delete("/api/helpers/{hid}")
async def delete_helper(hid: int, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("UPDATE helpers SET is_active=0 WHERE id=? AND office_id=?", (hid, oid))
    db.commit(); db.close()
    return {"ok": True}

# ── visit plans ───────────────────────────────────────────────
@app.get("/api/visit-plans")
async def get_visit_plans(date: Optional[str]=None, week: Optional[str]=None, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    if date:
        rows = db.execute("""SELECT vp.*, c.name as client_name, c.address, h.name as helper_name,
            vr.id as record_id, vr.checkin_time, vr.checkout_time, vr.client_condition
            FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
            LEFT JOIN helpers h ON h.id=vp.helper_id
            LEFT JOIN visit_records vr ON vr.visit_plan_id=vp.id AND vr.visit_date=?
            WHERE vp.office_id=? AND vp.plan_date=? ORDER BY vp.start_time""", (date, oid, date)).fetchall()
    elif week:
        rows = db.execute("""SELECT vp.*, c.name as client_name, c.address, h.name as helper_name
            FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
            LEFT JOIN helpers h ON h.id=vp.helper_id
            WHERE vp.office_id=? AND vp.plan_date BETWEEN ? AND date(?, '+6 days')
            ORDER BY vp.plan_date, vp.start_time""", (oid, week, week)).fetchall()
    else:
        today = datetime.now().strftime("%Y-%m-%d")
        rows = db.execute("""SELECT vp.*, c.name as client_name, c.address, h.name as helper_name,
            vr.id as record_id, vr.checkin_time, vr.checkout_time, vr.client_condition
            FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
            LEFT JOIN helpers h ON h.id=vp.helper_id
            LEFT JOIN visit_records vr ON vr.visit_plan_id=vp.id AND vr.visit_date=?
            WHERE vp.office_id=? AND vp.plan_date=? ORDER BY vp.start_time""", (today, oid, today)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/visit-plans")
async def create_visit_plan(req: VisitPlanReq, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    db.execute("INSERT INTO visit_plans (office_id,client_id,helper_id,plan_date,start_time,end_time,service_type,notes) VALUES (?,?,?,?,?,?,?,?)",
        (oid,req.client_id,req.helper_id,req.plan_date,req.start_time,req.end_time,req.service_type,req.notes))
    db.commit()
    vid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("""SELECT vp.*, c.name as client_name, h.name as helper_name
        FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
        LEFT JOIN helpers h ON h.id=vp.helper_id WHERE vp.id=?""", (vid,)).fetchone()
    db.close()
    return dict(row)

@app.delete("/api/visit-plans/{vid}")
async def delete_visit_plan(vid: int, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("DELETE FROM visit_plans WHERE id=? AND office_id=?", (vid, oid))
    db.commit(); db.close()
    return {"ok": True}

# ── visit records (check-in/out) ──────────────────────────────
@app.post("/api/checkin")
async def checkin(req: CheckinReq, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    existing = db.execute("SELECT id FROM visit_records WHERE office_id=? AND client_id=? AND visit_date=? AND checkout_time=''",
        (oid, req.client_id, req.visit_date)).fetchone()
    if existing:
        db.close(); raise HTTPException(400, "already_checked_in")
    db.execute("INSERT INTO visit_records (office_id,visit_plan_id,client_id,helper_id,visit_date,checkin_time,checkout_time) VALUES (?,?,?,?,?,?,'')",
        (oid,req.visit_plan_id,req.client_id,req.helper_id,req.visit_date,req.checkin_time))
    db.commit()
    rid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("SELECT * FROM visit_records WHERE id=?", (rid,)).fetchone()
    db.close()
    return dict(row)

@app.put("/api/checkout/{rid}")
async def checkout(rid: int, req: CheckoutReq, oid: int = Depends(current_office)):
    db = get_db()
    db.execute("""UPDATE visit_records SET checkout_time=?,body_care=?,life_support=?,
        client_condition=?,notes=?,helper_notes=? WHERE id=? AND office_id=?""",
        (req.checkout_time,req.body_care,req.life_support,req.client_condition,req.notes,req.helper_notes,rid,oid))
    db.commit()
    row = db.execute("""SELECT vr.*, c.name as client_name, h.name as helper_name
        FROM visit_records vr JOIN clients c ON c.id=vr.client_id
        LEFT JOIN helpers h ON h.id=vr.helper_id
        WHERE vr.id=?""", (rid,)).fetchone()
    off = db.execute("SELECT office_name, gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    if off and off["gas_webhook_url"] and row:
        _gas_send_bg(off["gas_webhook_url"], {
            "type": "visit_record", "date": row["visit_date"],
            "office_name": off["office_name"],
            "client_name": row["client_name"] or "",
            "helper_name": row["helper_name"] or "",
            "checkin_time": row["checkin_time"] or "",
            "checkout_time": req.checkout_time or "",
            "condition": req.client_condition or "",
            "body_care": bool(req.body_care),
            "life_support": bool(req.life_support),
            "notes": req.helper_notes or ""
        })
    return dict(row) if row else {"ok": True}

@app.get("/api/visit-records")
async def get_visit_records(client_id: Optional[int]=None, date: Optional[str]=None, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    if client_id and date:
        rows = db.execute("""SELECT vr.*, c.name as client_name, h.name as helper_name
            FROM visit_records vr JOIN clients c ON c.id=vr.client_id
            LEFT JOIN helpers h ON h.id=vr.helper_id
            WHERE vr.office_id=? AND vr.client_id=? AND vr.visit_date=?""", (oid,client_id,date)).fetchall()
    elif client_id:
        rows = db.execute("""SELECT vr.*, c.name as client_name, h.name as helper_name
            FROM visit_records vr JOIN clients c ON c.id=vr.client_id
            LEFT JOIN helpers h ON h.id=vr.helper_id
            WHERE vr.office_id=? AND vr.client_id=? ORDER BY vr.visit_date DESC LIMIT 20""", (oid,client_id)).fetchall()
    else:
        today = datetime.now().strftime("%Y-%m-%d")
        rows = db.execute("""SELECT vr.*, c.name as client_name, h.name as helper_name
            FROM visit_records vr JOIN clients c ON c.id=vr.client_id
            LEFT JOIN helpers h ON h.id=vr.helper_id
            WHERE vr.office_id=? AND vr.visit_date=? ORDER BY vr.checkin_time""", (oid, today)).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── messages ──────────────────────────────────────────────────
@app.get("/api/messages")
async def get_messages(oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    rows = db.execute("""SELECT m.*, c.name as client_name FROM messages m
        LEFT JOIN clients c ON c.id=m.client_id
        WHERE m.office_id=? ORDER BY m.created_at DESC LIMIT 50""", (oid,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/messages")
async def create_message(req: MessageReq, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    db.execute("INSERT INTO messages (office_id,sender_type,sender_name,recipient_name,client_id,content,priority) VALUES (?,?,?,?,?,?,?)",
        (oid,req.sender_type,req.sender_name,req.recipient_name,req.client_id,req.content,req.priority))
    db.commit()
    mid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    db.close()
    return dict(row)

@app.put("/api/messages/read-all")
async def read_all_messages(oid: int = Depends(current_office)):
    db = get_db()
    db.execute("UPDATE messages SET is_read=1 WHERE office_id=?", (oid,))
    db.commit(); db.close()
    return {"ok": True}

# ── incidents ─────────────────────────────────────────────────
@app.get("/api/incidents")
async def get_incidents(oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    rows = db.execute("""SELECT i.*, c.name as client_name FROM incidents i
        LEFT JOIN clients c ON c.id=i.client_id
        WHERE i.office_id=? ORDER BY i.incident_date DESC, i.incident_time DESC""", (oid,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/incidents")
async def create_incident(req: IncidentReq, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    db.execute("""INSERT INTO incidents (office_id,client_id,incident_date,incident_time,helper_name,
        location,category,level,description,action_taken,followup) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (oid,req.client_id,req.incident_date,req.incident_time,req.helper_name,
         req.location,req.category,req.level,req.description,req.action_taken,req.followup))
    db.commit()
    iid = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    row = db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    cl = db.execute("SELECT name FROM clients WHERE id=?", (req.client_id,)).fetchone() if req.client_id else None
    off = db.execute("SELECT office_name, gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    if off and off["gas_webhook_url"]:
        _gas_send_bg(off["gas_webhook_url"], {
            "type": "incident", "date": req.incident_date,
            "time": req.incident_time or "",
            "office_name": off["office_name"],
            "member_name": cl["name"] if cl else "",
            "staff_name": req.helper_name or "",
            "level": req.level or "",
            "category": req.category or "",
            "description": req.description or "",
            "action_taken": req.action_taken or "",
            "followup": req.followup or ""
        })
    return dict(row)

# ── handovers ─────────────────────────────────────────────────
@app.get("/api/handovers")
async def get_handovers(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT * FROM handovers WHERE office_id=? ORDER BY created_at DESC LIMIT 100", (oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/handovers")
async def create_handover(req: HandoverReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("INSERT INTO handovers (office_id,sender_name,content,category) VALUES (?,?,?,?)",
               (oid, req.sender_name, req.content, req.category))
    db.commit()
    row = db.execute("SELECT * FROM handovers WHERE rowid=last_insert_rowid()").fetchone()
    db.close(); return dict(row)

@app.post("/api/handovers/read-all")
async def read_all_handovers(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("UPDATE handovers SET is_read=1 WHERE office_id=?", (oid,))
    db.commit(); db.close(); return {"ok": True}

# ── care plans ─────────────────────────────────────────────────
@app.get("/api/care-plans")
async def get_care_plans(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("""SELECT cp.*, c.name as client_name FROM care_plans cp
        JOIN clients c ON c.id=cp.client_id WHERE cp.office_id=?
        ORDER BY cp.next_review ASC""", (oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/care-plans")
async def upsert_care_plan(req: CarePlanReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing = db.execute("SELECT id FROM care_plans WHERE office_id=? AND client_id=?", (oid, req.client_id)).fetchone()
    if existing:
        db.execute("""UPDATE care_plans SET plan_created=?,careplan_updated=?,next_review=?,
            service_content=?,goals=?,notes=?,updated_at=? WHERE id=?""",
            (req.plan_created,req.careplan_updated,req.next_review,
             req.service_content,req.goals,req.notes,now,existing["id"]))
    else:
        db.execute("""INSERT INTO care_plans (office_id,client_id,plan_created,careplan_updated,
            next_review,service_content,goals,notes,updated_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (oid,req.client_id,req.plan_created,req.careplan_updated,
             req.next_review,req.service_content,req.goals,req.notes,now))
    db.commit()
    row = db.execute("SELECT cp.*,c.name as client_name FROM care_plans cp JOIN clients c ON c.id=cp.client_id WHERE cp.office_id=? AND cp.client_id=?", (oid, req.client_id)).fetchone()
    db.close(); return dict(row)

@app.get("/api/care-plans/alerts")
async def care_plan_alerts(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    in30 = (datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d")
    overdue = db.execute("""SELECT cp.*,c.name as client_name FROM care_plans cp
        JOIN clients c ON c.id=cp.client_id WHERE cp.office_id=? AND cp.next_review < ? AND cp.next_review!=''
        ORDER BY cp.next_review""", (oid, today)).fetchall()
    soon = db.execute("""SELECT cp.*,c.name as client_name FROM care_plans cp
        JOIN clients c ON c.id=cp.client_id WHERE cp.office_id=? AND cp.next_review BETWEEN ? AND ? AND cp.next_review!=''
        ORDER BY cp.next_review""", (oid, today, in30)).fetchall()
    no_plan = db.execute("""SELECT c.id,c.name FROM clients c
        WHERE c.office_id=? AND c.is_active=1
        AND NOT EXISTS (SELECT 1 FROM care_plans cp WHERE cp.client_id=c.id)""", (oid,)).fetchall()
    db.close()
    return {"overdue": [dict(r) for r in overdue], "soon": [dict(r) for r in soon], "no_plan": [dict(r) for r in no_plan]}

# ── helper trainings ───────────────────────────────────────────
@app.get("/api/trainings")
async def get_trainings(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT * FROM helper_trainings WHERE office_id=? ORDER BY plan_date DESC, created_at DESC", (oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/trainings")
async def create_training(req: TrainingReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("""INSERT INTO helper_trainings (office_id,helper_id,helper_name,training_type,
        plan_date,done_date,content,trainer,notes) VALUES (?,?,?,?,?,?,?,?,?)""",
        (oid,req.helper_id,req.helper_name,req.training_type,
         req.plan_date,req.done_date,req.content,req.trainer,req.notes))
    db.commit()
    row = db.execute("SELECT * FROM helper_trainings WHERE rowid=last_insert_rowid()").fetchone()
    db.close(); return dict(row)

@app.put("/api/trainings/{tid}/complete")
async def complete_training(tid: int, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    db.execute("UPDATE helper_trainings SET done_date=? WHERE id=? AND office_id=?", (today, tid, oid))
    db.commit(); db.close(); return {"ok": True}

@app.delete("/api/trainings/{tid}")
async def delete_training(tid: int, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("DELETE FROM helper_trainings WHERE id=? AND office_id=?", (tid, oid))
    db.commit(); db.close(); return {"ok": True}

# ── monthly meetings ───────────────────────────────────────────
@app.get("/api/meetings")
async def get_meetings(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT * FROM monthly_meetings WHERE office_id=? ORDER BY meeting_date DESC LIMIT 24", (oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/meetings")
async def create_meeting(req: MeetingReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    db.execute("INSERT INTO monthly_meetings (office_id,meeting_date,attendees,agenda,minutes) VALUES (?,?,?,?,?)",
               (oid, req.meeting_date, req.attendees, req.agenda, req.minutes))
    db.commit()
    row = db.execute("SELECT * FROM monthly_meetings WHERE rowid=last_insert_rowid()").fetchone()
    db.close(); return dict(row)

# ── AI summary ────────────────────────────────────────────────
@app.post("/api/ai/daily-summary")
async def ai_daily_summary(oid: int = Depends(current_office)):
    if not OpenAIClient: raise HTTPException(503, "AI未設定")
    api_key = os.environ.get("OPENAI_API_KEY","")
    if not api_key: raise HTTPException(503, "APIキー未設定")
    db = get_db()
    check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    records = db.execute("""SELECT vr.*, c.name as client_name, h.name as helper_name
        FROM visit_records vr JOIN clients c ON c.id=vr.client_id
        LEFT JOIN helpers h ON h.id=vr.helper_id
        WHERE vr.office_id=? AND vr.visit_date=? AND vr.checkout_time!=''
        ORDER BY vr.checkin_time""", (oid, today)).fetchall()
    not_checked = db.execute("""SELECT vp.*, c.name as client_name, h.name as helper_name
        FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
        LEFT JOIN helpers h ON h.id=vp.helper_id
        WHERE vp.office_id=? AND vp.plan_date=?
        AND NOT EXISTS (SELECT 1 FROM visit_records vr WHERE vr.visit_plan_id=vp.id)
        ORDER BY vp.start_time""", (oid, today)).fetchall()
    db.close()
    if not records and not not_checked: raise HTTPException(404, "本日のデータがありません")
    cond_label = {"good":"良好","normal":"普通","poor":"不調","bad":"要注意","":"普通"}
    lines = [f"【訪問完了 {len(records)}件】"]
    for r in records:
        alert = "⚠️ " if r["client_condition"] in ("poor","bad") else ""
        notes = f"（{r['helper_notes'][:30]}）" if r["helper_notes"] else ""
        lines.append(f"{alert}{r['client_name']}様 {r['checkin_time']}〜{r['checkout_time']} 担当:{r['helper_name'] or '未設定'} 体調:{cond_label.get(r['client_condition'],'')} {notes}")
    if not_checked:
        lines.append(f"\n【訪問未完了 {len(not_checked)}件】")
        for v in not_checked:
            lines.append(f"{v['client_name']}様 {v['start_time']} 担当:{v['helper_name'] or '未割当'}")
    text = "\n".join(lines)
    try:
        client = OpenAIClient(api_key=api_key, timeout=30.0)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=400,
            messages=[
                {"role": "system", "content": "訪問介護事業所の管理者です。本日の訪問記録から、事業所全体の日報サマリーを150字程度で作成してください。体調不良者・未訪問者・特記事項を優先して記載。自然な文体で。"},
                {"role": "user", "content": f"本日（{today}）の訪問記録：\n{text}\n\n日報サマリーを作成してください。"}
            ]
        )
        summary_text = resp.choices[0].message.content
        # オフィス情報取得
        db2 = get_db()
        off = db2.execute("SELECT office_name, gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
        db2.close()
        office_name = off["office_name"] if off else ""
        webhook_url = off["gas_webhook_url"] if off else ""
        # メール送信
        try:
            cond_map = {"good":"良好","normal":"普通","poor":"不調","bad":"要注意","":"普通"}
            detail_lines = "\n".join([
                f"・{r['client_name']}（担当:{r['helper_name'] or '-'}）　体調:{cond_map.get(r['client_condition'],r['client_condition'])}　{r['helper_notes'] or ''}"
                for r in records
            ])
            mail_body = f"【AI日報】{office_name} {today}\n\n■ 訪問記録\n{detail_lines}\n\n■ 総評・申し送り\n{summary_text}"
            send_gmail(BUG_REPORT_TO, f"【AI日報】{office_name} {today}", mail_body)
        except Exception:
            pass
        # スプレッドシート送信
        try:
            if webhook_url and _requests:
                gas_records = [{"member_name": r["client_name"], "staff_name": r["helper_name"] or "", "condition": r["client_condition"], "content": f"{r['checkin_time']}〜{r['checkout_time']} {r['helper_notes'] or ''}", "staff_notes": ""} for r in records]
                _requests.post(webhook_url, json={"date": today, "office_name": office_name, "records": gas_records, "summary": summary_text}, timeout=15)
        except Exception:
            pass
        return {"summary": summary_text, "records_count": len(records)}
    except Exception as e:
        raise HTTPException(500, str(e)[:80])

# ── export ────────────────────────────────────────────────────
@app.get("/api/export/visit-records")
async def export_records(year: int, month: int, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    prefix = f"{year:04d}-{month:02d}"
    rows = db.execute("""SELECT vr.visit_date, c.name as client_name, h.name as helper_name,
        vr.checkin_time, vr.checkout_time, vr.body_care, vr.life_support, vr.client_condition, vr.helper_notes
        FROM visit_records vr JOIN clients c ON c.id=vr.client_id
        LEFT JOIN helpers h ON h.id=vr.helper_id
        WHERE vr.office_id=? AND vr.visit_date LIKE ? ORDER BY vr.visit_date, vr.checkin_time""",
        (oid, prefix+"%")).fetchall()
    db.close()
    cond = {"good":"良好","normal":"普通","poor":"不調","bad":"要注意","":""}
    buf = io.StringIO(); buf.write("﻿")
    w = csv.writer(buf)
    w.writerow(["訪問日","利用者名","担当ヘルパー","開始時刻","終了時刻","身体介護","生活援助","体調","特記事項"])
    for r in rows:
        w.writerow([r["visit_date"],r["client_name"],r["helper_name"] or "",
                    r["checkin_time"],r["checkout_time"],r["body_care"] or "",r["life_support"] or "",
                    cond.get(r["client_condition"],""),r["helper_notes"] or ""])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''houmon_{year}{month:02d}.csv"})

@app.get("/api/export/billing")
async def export_billing(year: int, month: int, oid: int = Depends(current_office)):
    """請求連携用CSV：既存の介護請求ソフトへの転記に使えるフォーマット"""
    db = get_db()
    check_active(oid, db)
    prefix = f"{year:04d}-{month:02d}"
    rows = db.execute("""
        SELECT vr.visit_date, c.name as client_name, c.care_level, c.birthdate,
               h.name as helper_name, h.qualification,
               vr.checkin_time, vr.checkout_time,
               vr.body_care, vr.life_support, vr.client_condition
        FROM visit_records vr
        JOIN clients c ON c.id=vr.client_id
        LEFT JOIN helpers h ON h.id=vr.helper_id
        WHERE vr.office_id=? AND vr.visit_date LIKE ? AND vr.checkout_time!=''
        ORDER BY c.name, vr.visit_date, vr.checkin_time""",
        (oid, prefix+"%")).fetchall()
    db.close()

    def calc_minutes(start, end):
        try:
            sh, sm = map(int, start.split(":"))
            eh, em = map(int, end.split(":"))
            return max(0, (eh*60+em) - (sh*60+sm))
        except: return 0

    def service_code(body, life, minutes):
        """訪問介護のサービス種別コード（簡易）"""
        has_body = bool(body and body.strip())
        has_life = bool(life and life.strip())
        if has_body and has_life:
            if minutes < 20: return "身体1生活"
            if minutes < 45: return "身体1.5生活"
            return "身体2生活"
        elif has_body:
            if minutes < 20: return "身体介護1"
            if minutes < 30: return "身体介護1.5"
            if minutes < 60: return "身体介護2"
            return "身体介護3"
        else:
            if minutes < 20: return "生活援助1"
            if minutes < 45: return "生活援助2"
            return "生活援助3"

    qual_label = {"care3":"介護福祉士","care2":"実務者研修","helper2":"初任者研修","none":"無資格","":""}

    buf = io.StringIO(); buf.write("﻿")
    w = csv.writer(buf)
    w.writerow(["サービス提供日","利用者名","要介護度","担当者名","資格",
                "開始時刻","終了時刻","提供時間(分)","サービス種別コード",
                "身体介護内容","生活援助内容","利用者の状態"])
    cond = {"good":"良好","normal":"普通","poor":"不調","bad":"要注意","":""}
    for r in rows:
        mins = calc_minutes(r["checkin_time"] or "", r["checkout_time"] or "")
        code = service_code(r["body_care"], r["life_support"], mins)
        w.writerow([
            r["visit_date"], r["client_name"], f"要介護{r['care_level']}",
            r["helper_name"] or "", qual_label.get(r["qualification"],""),
            r["checkin_time"], r["checkout_time"], mins, code,
            r["body_care"] or "", r["life_support"] or "",
            cond.get(r["client_condition"],"")
        ])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''seikyu_{year}{month:02d}.csv"})

# ── HQ pages ─────────────────────────────────────────────────
@app.get("/lp/", response_class=HTMLResponse)
@app.get("/api/office-settings")
async def get_office_settings(oid: int = Depends(current_office)):
    db = get_db()
    row = db.execute("SELECT gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    return {"gas_webhook_url": row["gas_webhook_url"] if row else ""}

@app.put("/api/office-settings")
async def update_office_settings(request: Request, oid: int = Depends(current_office)):
    body = await request.json()
    url = body.get("gas_webhook_url", "").strip()
    db = get_db()
    db.execute("UPDATE offices SET gas_webhook_url=? WHERE id=?", (url, oid))
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/lp", response_class=HTMLResponse)
async def lp_page():
    with open("static/lp.html", encoding="utf-8") as f: content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control":"no-store"})

@app.get("/hq/demo/", response_class=HTMLResponse)
@app.get("/hq/demo", response_class=HTMLResponse)
async def hq_demo_page():
    with open("static/hq_demo.html", encoding="utf-8") as f: content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control":"no-store"})

@app.get("/hq/auto-login/", response_class=HTMLResponse)
@app.get("/hq/auto-login", response_class=HTMLResponse)
async def hq_auto_login(request: Request):
    """本部ポータル用自動ログイン"""
    db = get_db()
    row = db.execute("SELECT * FROM hq_accounts WHERE username='honbu'").fetchone()
    db.close()
    if not row:
        return HTMLResponse("<p>本部デモアカウントが見つかりません</p>", status_code=404)
    token = make_hq_token(row["id"], row["username"])
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>本部ポータルにアクセス中...</title>
<style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#eff6ff;margin:0}}
.box{{text-align:center;color:#2563eb}}.spin{{border:4px solid #dbeafe;border-top:4px solid #2563eb;border-radius:50%;width:40px;height:40px;animation:s .8s linear infinite;margin:0 auto 16px}}
@keyframes s{{to{{transform:rotate(360deg)}}}}</style></head>
<body><div class="box"><div class="spin"></div><div style="font-weight:700">本部ポータルに移動中...</div></div>
<script>localStorage.setItem('houmon_hq_token',token);location.href='/houmon/hq/';</script></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/demo/", response_class=HTMLResponse)
@app.get("/demo", response_class=HTMLResponse)
async def app_demo_page():
    with open("static/demo.html", encoding="utf-8") as f: content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control":"no-store"})

@app.get("/auto-login/", response_class=HTMLResponse)
@app.get("/auto-login", response_class=HTMLResponse)
async def auto_login(request: Request):
    db = get_db()
    row = db.execute("SELECT * FROM offices WHERE username='admin'").fetchone()
    db.close()
    if not row:
        return HTMLResponse("<p>デモアカウントが見つかりません</p>", status_code=404)
    token = make_token(row["id"], row["username"])
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>デモにアクセス中...</title>
<style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#eff6ff;margin:0}}
.box{{text-align:center;color:#2563eb}}.spin{{border:4px solid #dbeafe;border-top:4px solid #2563eb;border-radius:50%;width:40px;height:40px;animation:s .8s linear infinite;margin:0 auto 16px}}
@keyframes s{{to{{transform:rotate(360deg)}}}}</style></head>
<body><div class="box"><div class="spin"></div><div style="font-weight:700">デモ画面に移動中...</div></div>
<script>
localStorage.setItem('houmon_token','{token}');
localStorage.setItem('houmon_office','{row["office_name"]}');
setTimeout(()=>location.href='/houmon/',300);
</script></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/hq/", response_class=HTMLResponse)
@app.get("/hq", response_class=HTMLResponse)
async def hq_page():
    with open("static/hq.html", encoding="utf-8") as f: content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control":"no-store"})

# ── HQ auth ───────────────────────────────────────────────────
HQ_SECRET = os.environ.get("HQ_SECRET") or (_ for _ in ()).throw(ValueError("HQ_SECRET env var not set"))

class HqLoginReq(BaseModel):
    username: str; password: str
class HqRegisterReq(BaseModel):
    username: str; org_name: str; email: str; password: str; office_ids: Optional[List[int]]=[]
class HqSmtpReq(BaseModel):
    smtp_host: str; smtp_port: int; smtp_user: str; smtp_pass: str
class HqChangePasswordReq(BaseModel):
    current_password: str; new_password: str

def make_hq_token(hq_id, username):
    exp = datetime.utcnow() + timedelta(days=30)
    return jwt.encode({"sub": str(hq_id), "username": username, "role": "hq", "exp": exp}, HQ_SECRET, algorithm=ALGORITHM)

def current_hq(request: Request):
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    try:
        p = jwt.decode(auth[7:], HQ_SECRET, algorithms=[ALGORITHM])
        if p.get("role")!="hq": raise HTTPException(401)
        return int(p["sub"])
    except: raise HTTPException(401)

def get_hq_office_ids(hq_id, db):
    return [r["office_id"] for r in db.execute("SELECT office_id FROM hq_office_access WHERE hq_id=?", (hq_id,)).fetchall()]

@app.post("/api/hq/register")
async def hq_register(req: HqRegisterReq, key: str=""):
    if not __import__("hmac").compare_digest(key or "", ADMIN_KEY): raise HTTPException(403)
    db = get_db()
    if db.execute("SELECT id FROM hq_accounts WHERE username=?", (req.username,)).fetchone():
        db.close(); raise HTTPException(400, "already_exists")
    salt = secrets.token_hex(16)
    db.execute("INSERT INTO hq_accounts (username,org_name,email,pw_hash,pw_salt) VALUES (?,?,?,?,?)",
               (req.username, req.org_name, req.email, hash_pw(req.password, salt), salt))
    db.commit()
    hq_id = db.execute("SELECT id FROM hq_accounts WHERE username=?", (req.username,)).fetchone()["id"]
    if req.office_ids:
        for oid in req.office_ids:
            try: db.execute("INSERT OR IGNORE INTO hq_office_access (hq_id,office_id) VALUES (?,?)", (hq_id, oid))
            except: pass
    else:
        for r in db.execute("SELECT id FROM offices").fetchall():
            db.execute("INSERT OR IGNORE INTO hq_office_access (hq_id,office_id) VALUES (?,?)", (hq_id, r["id"]))
    db.commit(); db.close()
    return {"ok": True, "hq_id": hq_id}

@app.post("/api/hq/login")
async def hq_login(req: HqLoginReq, request: Request):

    _check_rate_limit(_get_real_ip(request))
    db = get_db()
    row = db.execute("SELECT * FROM hq_accounts WHERE username=?", (req.username,)).fetchone()
    db.close()
    if not row or not verify_pw(req.password, row["pw_hash"], row["pw_salt"]): raise HTTPException(401)
    return {"token": make_hq_token(row["id"], req.username), "org_name": row["org_name"]}

@app.get("/api/hq/me")
async def hq_me(hq_id: int = Depends(current_hq)):
    db = get_db()
    row = db.execute("SELECT id,username,org_name,email,smtp_host,smtp_user FROM hq_accounts WHERE id=?", (hq_id,)).fetchone()
    db.close(); return dict(row)

# ── HQ dashboard ──────────────────────────────────────────────
@app.get("/api/hq/dashboard")
async def hq_dashboard(hq_id: int = Depends(current_hq)):
    db = get_db()
    oids = get_hq_office_ids(hq_id, db)
    if not oids: db.close(); return {"offices": []}
    ph = ",".join("?"*len(oids))
    today = datetime.now().strftime("%Y-%m-%d")
    offices = db.execute(f"SELECT id,office_name FROM offices WHERE id IN ({ph})", oids).fetchall()
    result = []
    for o in offices:
        oid = o["id"]
        clients  = db.execute("SELECT COUNT(*) as c FROM clients WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
        helpers  = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
        planned  = db.execute("SELECT COUNT(*) as c FROM visit_plans WHERE office_id=? AND plan_date=?", (oid,today)).fetchone()["c"]
        in_visit = db.execute("SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date=? AND checkin_time!='' AND checkout_time=''", (oid,today)).fetchone()["c"]
        done     = db.execute("SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date=? AND checkout_time!=''", (oid,today)).fetchone()["c"]
        urgent   = db.execute("SELECT COUNT(*) as c FROM messages WHERE office_id=? AND priority='urgent' AND is_read=0", (oid,)).fetchone()["c"]
        incidents_m = db.execute("SELECT COUNT(*) as c FROM incidents WHERE office_id=? AND incident_date LIKE ?", (oid,today[:7]+"%")).fetchone()["c"]
        result.append({"office_id":oid,"office_name":o["office_name"],"clients":clients,"helpers":helpers,
                        "planned":planned,"in_visit":in_visit,"done":done,"urgent_msg":urgent,"incidents_month":incidents_m})
    db.close()
    return {"offices": result, "today": today}

@app.get("/api/hq/today-visits")
async def hq_today_visits(office_id: Optional[int]=None, hq_id: int = Depends(current_hq)):
    db = get_db()
    oids = get_hq_office_ids(hq_id, db)
    target = [office_id] if office_id and office_id in oids else oids
    if not target: db.close(); return []
    ph = ",".join("?"*len(target))
    today = datetime.now().strftime("%Y-%m-%d")
    rows = db.execute(f"""SELECT vp.*, c.name as client_name, c.address, h.name as helper_name,
        o.office_name, vr.id as record_id, vr.checkin_time, vr.checkout_time, vr.client_condition
        FROM visit_plans vp JOIN clients c ON c.id=vp.client_id
        JOIN offices o ON o.id=vp.office_id
        LEFT JOIN helpers h ON h.id=vp.helper_id
        LEFT JOIN visit_records vr ON vr.visit_plan_id=vp.id AND vr.visit_date=?
        WHERE vp.office_id IN ({ph}) AND vp.plan_date=?
        ORDER BY vp.start_time""", [today]+target+[today]).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.get("/api/hq/incidents")
async def hq_incidents(office_id: Optional[int]=None, year: Optional[int]=None, month: Optional[int]=None, hq_id: int = Depends(current_hq)):
    db = get_db()
    oids = get_hq_office_ids(hq_id, db)
    target = [office_id] if office_id and office_id in oids else oids
    if not target: db.close(); return []
    ph = ",".join("?"*len(target))
    now = datetime.now()
    prefix = f"{(year or now.year):04d}-{(month or now.month):02d}"
    rows = db.execute(f"""SELECT i.*, c.name as client_name, o.office_name FROM incidents i
        LEFT JOIN clients c ON c.id=i.client_id JOIN offices o ON o.id=i.office_id
        WHERE i.office_id IN ({ph}) AND i.incident_date LIKE ?
        ORDER BY i.incident_date DESC, i.incident_time DESC""", target+[prefix+"%"]).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/hq/smtp")
async def hq_smtp(req: HqSmtpReq, hq_id: int = Depends(current_hq)):
    db = get_db()
    db.execute("UPDATE hq_accounts SET smtp_host=?,smtp_port=?,smtp_user=?,smtp_pass=? WHERE id=?",
               (req.smtp_host, req.smtp_port, req.smtp_user, req.smtp_pass, hq_id))
    db.commit(); db.close(); return {"ok": True}

@app.post("/api/hq/send-report")
async def hq_send_report(hq_id: int = Depends(current_hq)):
    db = get_db()
    hq = db.execute("SELECT * FROM hq_accounts WHERE id=?", (hq_id,)).fetchone()
    if not hq or not hq["smtp_host"]: db.close(); raise HTTPException(400, "SMTP未設定")
    oids = get_hq_office_ids(hq_id, db)
    today = datetime.now()
    prefix = today.strftime("%Y-%m")
    lines = [f"【訪問介護マネージャー 月次報告】{today.year}年{today.month}月", "="*48, ""]
    for oid in oids:
        o = db.execute("SELECT office_name FROM offices WHERE id=?", (oid,)).fetchone()
        if not o: continue
        clients = db.execute("SELECT COUNT(*) as c FROM clients WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
        total_v = db.execute("SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date LIKE ? AND checkout_time!=''", (oid,prefix+"%")).fetchone()["c"]
        incs = db.execute("SELECT COUNT(*) as c FROM incidents WHERE office_id=? AND incident_date LIKE ?", (oid,prefix+"%")).fetchone()["c"]
        lines += [f"■ {o['office_name']}", f"  利用者数: {clients}名 ｜ 訪問完了: {total_v}件 ｜ ヒヤリハット: {incs}件", ""]
    lines += ["詳細: https://life-energy-coaching.net/houmon/hq/"]
    body = "\n".join(lines)
    db.close()
    try:
        msg = MIMEMultipart(); msg["From"]=hq["smtp_user"]; msg["To"]=hq["email"]
        msg["Subject"]=f"【訪問介護月次報告】{today.year}年{today.month}月"
        msg.attach(MIMEText(body,"plain","utf-8"))
        with smtplib.SMTP(hq["smtp_host"], hq["smtp_port"]) as s:
            s.starttls(); s.login(hq["smtp_user"],hq["smtp_pass"]); s.send_message(msg)
        return {"ok":True,"message":f"{hq['email']}に送信しました"}
    except Exception as e: raise HTTPException(500, str(e)[:80])

@app.post("/api/hq/change-password")
async def hq_change_password(req: HqChangePasswordReq, hq_id: int = Depends(current_hq)):
    db = get_db()
    row = db.execute("SELECT * FROM hq_accounts WHERE id=?", (hq_id,)).fetchone()
    if not row or not verify_pw(req.current_password, row["pw_hash"], row["pw_salt"]):
        db.close(); raise HTTPException(400, "現在のパスワードが正しくありません")
    new_salt = secrets.token_hex(16)
    db.execute("UPDATE hq_accounts SET pw_hash=?,pw_salt=? WHERE id=?",
               (hash_pw(req.new_password, new_salt), new_salt, hq_id))
    db.commit(); db.close(); return {"ok": True}

# ── admin ─────────────────────────────────────────────────────
ADMIN_KEY = os.environ.get("ADMIN_KEY") or (_ for _ in ()).throw(ValueError("ADMIN_KEY env var not set"))
class ActivateReq(BaseModel):
    username: str; plan: str
# 居宅介護 基本報酬 単位数テーブル（R6年度 障害福祉サービス 種別11）
# 身体介護（mins上限, サービスコード, 単位数）
_BODY_TABLE = [
    (30,  "111101", 256),
    (60,  "111201", 409),
    (90,  "111301", 564),
    (120, "111401", 660),
    (150, "111501", 756),
    (180, "111601", 852),
]
# 家事援助
_LIFE_TABLE = [
    (30,  "112101", 106),
    (60,  "112201", 190),
    (90,  "112301", 244),
]

def _visit_mins(ci, co):
    """訪問時間（分）を計算。失敗時は30分を返す。"""
    try:
        sh, sm = map(int, (ci or "").split(":")[:2])
        eh, em = map(int, (co or "").split(":")[:2])
        return max(0, (eh * 60 + em) - (sh * 60 + sm)) or 30
    except Exception:
        return 30

def _visit_info(is_body, mins):
    """(サービスコード, 単位数) を返す。延長加算も計算。"""
    if is_body:
        for mx, code, upv in _BODY_TABLE:
            if mins <= mx:
                return code, upv
        # 180分超: 延長 83単位/30分
        extra = max(0, (mins - 180) // 30)
        return "111701", 921 + 83 * extra
    else:
        for mx, code, upv in _LIFE_TABLE:
            if mins <= mx:
                return code, upv
        # 90分超: 延長 35単位/30分
        extra = max(0, (mins - 90) // 30)
        return "112401", 311 + 35 * extra

class BillingSettingsReq(BaseModel):
    jigyosho_no: Optional[str]=""; pref_no: Optional[str]=""
    service_code: Optional[str]="111101"; service_code_life: Optional[str]="112101"
    tanka_unit: Optional[int]=1140; new_mode: Optional[int]=0
class JukyushaReq(BaseModel):
    jukyusha_no: Optional[str]=""; jukyusha_valid_from: Optional[str]=""; jukyusha_valid_to: Optional[str]=""
    shikyu_visits: Optional[int]=26; futan_jogen: Optional[int]=0
class KasanReq(BaseModel):
    kasan_code: str; kasan_name: str; kasan_rate: Optional[float]=0
    is_active: Optional[int]=1; notes: Optional[str]=""

@app.get("/api/admin/offices")
async def admin_offices(key: str):
    if not __import__("hmac").compare_digest(key or "", ADMIN_KEY): raise HTTPException(403)
    db = get_db()
    rows = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end,created_at FROM offices ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/admin/activate")
async def admin_activate(req: ActivateReq, key: str):
    if not __import__("hmac").compare_digest(key or "", ADMIN_KEY): raise HTTPException(403)
    db = get_db()
    db.execute("UPDATE offices SET plan=?,subscription_status='active' WHERE username=?", (req.plan, req.username))
    db.commit(); db.close()
    return {"ok": True}

# ── billing settings ──────────────────────────────────────────
@app.get("/api/billing/settings")
async def get_billing_settings(oid: int = Depends(current_office)):
    db=get_db()
    row=db.execute("SELECT jigyosho_no,pref_no,service_code,service_code_life,tanka_unit,new_mode FROM offices WHERE id=?",(oid,)).fetchone()
    db.close(); return dict(row) if row else {}

@app.put("/api/billing/settings")
async def update_billing_settings(req: BillingSettingsReq, oid: int = Depends(current_office)):
    db=get_db()
    db.execute("UPDATE offices SET jigyosho_no=?,pref_no=?,service_code=?,service_code_life=?,tanka_unit=?,new_mode=? WHERE id=?",
        (req.jigyosho_no,req.pref_no,req.service_code,req.service_code_life,req.tanka_unit,req.new_mode,oid))
    db.commit(); db.close(); return {"ok":True}

@app.get("/api/billing/jukyusha")
async def get_jukyusha(oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    rows=db.execute("SELECT id,name,kana,jukyusha_no,jukyusha_valid_from,jukyusha_valid_to,shikyu_visits,futan_jogen FROM clients WHERE office_id=? AND is_active=1 ORDER BY kana",(oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.put("/api/billing/jukyusha/{cid}")
async def update_jukyusha(cid: int, req: JukyushaReq, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    db.execute("UPDATE clients SET jukyusha_no=?,jukyusha_valid_from=?,jukyusha_valid_to=?,shikyu_visits=?,futan_jogen=? WHERE id=? AND office_id=?",
        (req.jukyusha_no,req.jukyusha_valid_from,req.jukyusha_valid_to,req.shikyu_visits,req.futan_jogen,cid,oid))
    db.commit(); db.close(); return {"ok":True}

@app.get("/api/kasan")
async def get_kasan(oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    rows=db.execute("SELECT * FROM kasan_settings WHERE office_id=? ORDER BY kasan_code",(oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/kasan")
async def create_kasan(req: KasanReq, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    db.execute("INSERT INTO kasan_settings (office_id,kasan_code,kasan_name,kasan_rate,is_active,notes) VALUES (?,?,?,?,?,?)",
        (oid,req.kasan_code,req.kasan_name,req.kasan_rate,req.is_active,req.notes))
    db.commit(); db.close(); return {"ok":True}

@app.put("/api/kasan/{kid}")
async def update_kasan(kid: int, req: KasanReq, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    db.execute("UPDATE kasan_settings SET kasan_code=?,kasan_name=?,kasan_rate=?,is_active=?,notes=? WHERE id=? AND office_id=?",
        (req.kasan_code,req.kasan_name,req.kasan_rate,req.is_active,req.notes,kid,oid))
    db.commit(); db.close(); return {"ok":True}

@app.delete("/api/kasan/{kid}")
async def delete_kasan(kid: int, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    db.execute("DELETE FROM kasan_settings WHERE id=? AND office_id=?",(kid,oid))
    db.commit(); db.close(); return {"ok":True}

@app.get("/api/billing/preview/{year}/{month}")
async def billing_preview(year: int, month: int, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    office=db.execute("SELECT * FROM offices WHERE id=?",(oid,)).fetchone()
    prefix=f"{year:04d}-{month:02d}"
    clients=db.execute(
        "SELECT id,name,kana,jukyusha_no,shikyu_visits,futan_jogen,jukyusha_valid_to FROM clients WHERE office_id=? AND is_active=1 ORDER BY kana",
        (oid,)).fetchall()
    visits=db.execute(
        "SELECT client_id,checkin_time,checkout_time,body_care,life_support FROM visit_records WHERE office_id=? AND visit_date LIKE ? AND checkout_time!=''",
        (oid,prefix+"%")).fetchall()
    kasans=db.execute("SELECT * FROM kasan_settings WHERE office_id=? AND is_active=1",(oid,)).fetchall()
    tanka=office["tanka_unit"] or 1140
    db.close()
    # 訪問ごとに身体/家事 × 時間から単位数を計算しクライアント別に集計
    from collections import defaultdict
    agg=defaultdict(lambda:{"body_v":0,"life_v":0,"body_u":0,"life_u":0})
    for v in visits:
        cid=v["client_id"]
        is_body=bool((v["body_care"] or "").strip())
        mins=_visit_mins(v["checkin_time"],v["checkout_time"])
        _,upv=_visit_info(is_body,mins)
        if is_body: agg[cid]["body_v"]+=1; agg[cid]["body_u"]+=upv
        else:       agg[cid]["life_v"]+=1; agg[cid]["life_u"]+=upv
    last_day=f"{year:04d}-{month:02d}-{calendar.monthrange(year,month)[1]:02d}"
    total_units=0; total_amount=0; result=[]
    for c in clients:
        a=agg.get(c["id"]); total_v=(a["body_v"]+a["life_v"]) if a else 0
        if total_v==0: continue
        shikyu=c["shikyu_visits"] or 26
        actual_v=min(total_v,shikyu)
        scale=actual_v/total_v
        body_u=round((a["body_u"] or 0)*scale); life_u=round((a["life_u"] or 0)*scale)
        base_units=body_u+life_u
        kasan_units=sum(round(base_units*k["kasan_rate"]/100) for k in kasans)
        svc_units=base_units+kasan_units
        amount=svc_units*tanka//100
        futan=min(c["futan_jogen"] or 0,amount)
        total_units+=svc_units; total_amount+=amount
        alerts=[]
        if not c["jukyusha_no"]: alerts.append("受給者番号未登録")
        if total_v>shikyu: alerts.append(f"支給量超過（{total_v}回/{shikyu}回）")
        if c["jukyusha_valid_to"] and c["jukyusha_valid_to"]<last_day: alerts.append("受給者証期限切れ")
        result.append({"client_id":c["id"],"name":c["name"],
            "jukyusha_no":c["jukyusha_no"] or "","total_visits":total_v,"actual_visits":actual_v,
            "shikyu_visits":shikyu,
            "body_visits":a["body_v"] if a else 0,"body_units":body_u,
            "life_visits":a["life_v"] if a else 0,"life_units":life_u,
            "base_units":base_units,"kasan_units":kasan_units,
            "total_units":svc_units,"amount":amount,"futan":futan,"alerts":alerts})
    return {"items":result,"total_units":total_units,"total_amount":total_amount,"tanka":tanka,
            "jigyosho_no":office["jigyosho_no"] or "","warning_count":sum(len(i["alerts"]) for i in result)}

@app.get("/api/billing/csv/{year}/{month}")
async def billing_csv(year: int, month: int, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    office=db.execute("SELECT * FROM offices WHERE id=?",(oid,)).fetchone()
    if not office["jigyosho_no"]: db.close(); raise HTTPException(400,"事業所番号が未設定です。請求設定から登録してください。")
    prefix=f"{year:04d}-{month:02d}"; billing_ym=f"{year:04d}{month:02d}"
    tanka=office["tanka_unit"] or 1140
    pref_no=(office["pref_no"] or "00").zfill(2)
    jigyosho_no=office["jigyosho_no"].zfill(10)
    clients=db.execute(
        "SELECT id,name,jukyusha_no,shikyu_visits,futan_jogen FROM clients WHERE office_id=? AND is_active=1 AND jukyusha_no!='' AND jukyusha_no IS NOT NULL ORDER BY kana",
        (oid,)).fetchall()
    visits=db.execute(
        "SELECT client_id,checkin_time,checkout_time,body_care,life_support FROM visit_records WHERE office_id=? AND visit_date LIKE ? AND checkout_time!=''",
        (oid,prefix+"%")).fetchall()
    kasans=db.execute("SELECT * FROM kasan_settings WHERE office_id=? AND is_active=1",(oid,)).fetchall()
    db.close()
    # (client_id → [(code, upv), ...]) 各訪問のサービスコード+単位数
    from collections import defaultdict
    client_visits=defaultdict(list)
    client_meta={c["id"]:c for c in clients}
    for v in visits:
        cid=v["client_id"]
        if cid not in client_meta: continue
        is_body=bool((v["body_care"] or "").strip())
        mins=_visit_mins(v["checkin_time"],v["checkout_time"])
        code,upv=_visit_info(is_body,mins)
        client_visits[cid].append((code,upv))
    hb_lines=[]; hb_count=0; total_units=0; total_amount=0
    for c in clients:
        cid=c["id"]; v_list=client_visits.get(cid,[])
        if not v_list: continue
        shikyu=c["shikyu_visits"] or 26
        actual_list=v_list[:min(len(v_list),shikyu)]
        # (code,upv) 別にグループ化
        code_groups=defaultdict(int)
        for code,upv in actual_list: code_groups[(code,upv)]+=1
        jno=str(c["jukyusha_no"]).zfill(10)
        c_base=0; c_amount=0
        for (code,upv),cnt in sorted(code_groups.items()):
            lu=upv*cnt; la=lu*tanka//100
            hb_lines.append(f"HB,{billing_ym}01,02,{pref_no},{jigyosho_no},{jno},{c['name']},{billing_ym},11,{code},{upv},{cnt},1,{lu},{la},0,0,0")
            hb_count+=1; c_base+=lu; c_amount+=la
        for k in kasans:
            if k["kasan_rate"]>0 and k["kasan_code"]:
                ku=round(c_base*k["kasan_rate"]/100); ka=ku*tanka//100
                hb_lines.append(f"HB,{billing_ym}01,02,{pref_no},{jigyosho_no},{jno},{c['name']},{billing_ym},11,{k['kasan_code']},{ku},1,1,{ku},{ka},0,0,0")
                hb_count+=1; c_base+=ku; c_amount+=ka
        futan=min(c["futan_jogen"] or 0,c_amount)
        # 最後のHBラインに利用者負担額を追記する代わり、FTで合算
        total_units+=c_base; total_amount+=c_amount
    ha=f"HA,{billing_ym}01,02,{pref_no},{jigyosho_no},{office['office_name']},{billing_ym},{hb_count:06d}"
    ft=f"FT,{hb_count:06d},{total_units:07d},{total_amount:09d}"
    content="\r\n".join([ha]+hb_lines+[ft])+"\r\n"
    try: encoded=content.encode("cp932")
    except UnicodeEncodeError: encoded=content.encode("cp932",errors="replace")
    fname=f"kokuho_{jigyosho_no}_{billing_ym}.csv"
    return StreamingResponse(io.BytesIO(encoded),media_type="application/octet-stream",
        headers={"Content-Disposition":f"attachment; filename={fname}"})

@app.get("/api/billing/invoice/{year}/{month}", response_class=HTMLResponse)
async def billing_invoice(year: int, month: int, oid: int = Depends(current_office)):
    db=get_db(); check_active(oid,db)
    office=db.execute("SELECT * FROM offices WHERE id=?",(oid,)).fetchone()
    prefix=f"{year:04d}-{month:02d}"; tanka=office["tanka_unit"] or 1140
    clients=db.execute(
        "SELECT id,name,jukyusha_no,shikyu_visits,futan_jogen FROM clients WHERE office_id=? AND is_active=1 ORDER BY kana",
        (oid,)).fetchall()
    visits=db.execute(
        "SELECT client_id,checkin_time,checkout_time,body_care,life_support FROM visit_records WHERE office_id=? AND visit_date LIKE ? AND checkout_time!=''",
        (oid,prefix+"%")).fetchall()
    kasans=db.execute("SELECT * FROM kasan_settings WHERE office_id=? AND is_active=1",(oid,)).fetchall()
    db.close()
    from collections import defaultdict
    agg=defaultdict(lambda:{"body_v":0,"life_v":0,"body_u":0,"life_u":0})
    for v in visits:
        cid=v["client_id"]; is_body=bool((v["body_care"] or "").strip())
        mins=_visit_mins(v["checkin_time"],v["checkout_time"]); _,upv=_visit_info(is_body,mins)
        if is_body: agg[cid]["body_v"]+=1; agg[cid]["body_u"]+=upv
        else:       agg[cid]["life_v"]+=1; agg[cid]["life_u"]+=upv
    next_month=month+1 if month<12 else 1; next_year=year if month<12 else year+1
    today=datetime.now().strftime("%Y年%m月%d日")
    pages=""
    for c in clients:
        a=agg.get(c["id"]); total_v=(a["body_v"]+a["life_v"]) if a else 0
        if total_v==0: continue
        shikyu=c["shikyu_visits"] or 26; actual_v=min(total_v,shikyu)
        scale=actual_v/total_v
        body_u=round((a["body_u"] or 0)*scale); life_u=round((a["life_u"] or 0)*scale)
        base_units=body_u+life_u; base_amount=base_units*tanka//100
        body_detail=(f"<tr><td style='padding:6px;border:1px solid #000'>身体介護（{a['body_v']}回 / {body_u}単位）</td><td style='padding:6px;border:1px solid #000;text-align:right'>{body_u*tanka//100:,}円</td></tr>" if a and a["body_v"] else "")
        life_detail=(f"<tr><td style='padding:6px;border:1px solid #000'>家事援助（{a['life_v']}回 / {life_u}単位）</td><td style='padding:6px;border:1px solid #000;text-align:right'>{life_u*tanka//100:,}円</td></tr>" if a and a["life_v"] else "")
        k_rows=""; k_total=0
        for k in kasans:
            if k["kasan_rate"]>0:
                ku=round(base_units*k["kasan_rate"]/100); ka=ku*tanka//100
                k_rows+=f"<tr><td style='padding:6px;border:1px solid #000'>{k['kasan_name']}</td><td style='padding:6px;border:1px solid #000;text-align:right'>{ka:,}円</td></tr>"
                k_total+=ka
        total_amount=base_amount+k_total; futan=min(c["futan_jogen"] or 0,total_amount)
        pages+=f"""<div style="page-break-after:always;padding:20px;font-family:'MS Mincho','游明朝',serif;font-size:11pt">
<h2 style="text-align:center;font-size:16pt;margin-bottom:20px">{year}年{month}月分　利用者負担金請求書</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
  <tr><td style="width:30%;font-weight:bold;padding:6px;border:1px solid #000">宛先</td><td style="padding:6px;border:1px solid #000"><strong>{c['name']}</strong>　様</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">請求事業所</td><td style="padding:6px;border:1px solid #000">{office['office_name']}</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">サービス種別</td><td style="padding:6px;border:1px solid #000">居宅介護（障害福祉）</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">対象期間</td><td style="padding:6px;border:1px solid #000">{year}年{month}月1日〜{year}年{month}月末日</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">サービス提供回数</td><td style="padding:6px;border:1px solid #000">{actual_v}回</td></tr>
</table>
<h3 style="font-size:13pt;margin-bottom:8px">請求明細</h3>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
  <thead><tr style="background:#f0f0f0"><th style="padding:6px;border:1px solid #000;text-align:left">項目</th><th style="padding:6px;border:1px solid #000;text-align:right">金額</th></tr></thead>
  <tbody>
    {body_detail}{life_detail}
    {k_rows}
    <tr style="font-weight:bold;background:#f9f9f9"><td style="padding:6px;border:1px solid #000">給付費合計</td><td style="padding:6px;border:1px solid #000;text-align:right">{total_amount:,}円</td></tr>
    <tr style="font-weight:bold;background:#e8f4ff"><td style="padding:8px;border:2px solid #000;font-size:14pt">ご請求金額（利用者負担額）</td><td style="padding:8px;border:2px solid #000;text-align:right;font-size:14pt">{futan:,}円</td></tr>
  </tbody>
</table>
<div style="margin-top:12px;font-size:10pt">お支払い期限：{next_year}年{next_month}月25日　／　作成日：{today}</div>
<div style="margin-top:16px;text-align:right;font-size:10pt">以上よろしくお願いいたします。<br>{office['office_name']}</div>
</div>"""
    html=f"""<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
<title>利用者負担金請求書 {year}年{month}月</title>
<style>body{{font-family:'MS Mincho','游明朝',serif;font-size:11pt}}@media print{{@page{{margin:15mm}}.no-print{{display:none}}}}</style>
</head><body>
<div class="no-print" style="padding:12px">
  <button onclick="window.print()" style="padding:8px 20px;background:#0891b2;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px">🖨️ 全員分を印刷</button>
</div>
{pages or '<p style="padding:20px;color:#666">対象データがありません</p>'}
</body></html>"""
    return HTMLResponse(html)

# ── 特定事業所加算 要件チェック ────────────────────────────────
@app.get("/api/tokutei-check")
async def tokutei_check(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    # ① 介護福祉士比率（常勤・非常勤問わず在籍ヘルパー全体で計算）
    total_helpers = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1", (oid,)).fetchone()["c"]
    kaigo_helpers = db.execute("SELECT COUNT(*) as c FROM helpers WHERE office_id=? AND is_active=1 AND qualification='care3'", (oid,)).fetchone()["c"]
    kaigo_ratio = round(kaigo_helpers / total_helpers * 100, 1) if total_helpers > 0 else 0
    # ② 定期会議（直近3ヶ月に開催されているか）
    three_months_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
    meetings_3m = db.execute("SELECT COUNT(*) as c FROM monthly_meetings WHERE office_id=? AND meeting_date>=?", (oid, three_months_ago)).fetchone()["c"]
    last_meeting = db.execute("SELECT meeting_date FROM monthly_meetings WHERE office_id=? ORDER BY meeting_date DESC LIMIT 1", (oid,)).fetchone()
    days_since_meeting = (datetime.now() - datetime.strptime(last_meeting["meeting_date"], "%Y-%m-%d")).days if last_meeting else 999
    # ③ 個別研修計画（全ヘルパーに今年度の研修計画があるか）
    year_prefix = datetime.now().strftime("%Y")
    helpers_with_training = db.execute("""
        SELECT COUNT(DISTINCT helper_id) as c FROM helper_trainings
        WHERE office_id=? AND plan_date LIKE ? AND helper_id IS NOT NULL
    """, (oid, year_prefix + "%")).fetchone()["c"]
    training_coverage = round(helpers_with_training / total_helpers * 100, 1) if total_helpers > 0 else 0
    # ④ 実施済み研修（done_dateがある）
    helpers_done_training = db.execute("""
        SELECT COUNT(DISTINCT helper_id) as c FROM helper_trainings
        WHERE office_id=? AND plan_date LIKE ? AND done_date!='' AND done_date IS NOT NULL AND helper_id IS NOT NULL
    """, (oid, year_prefix + "%")).fetchone()["c"]
    training_done_rate = round(helpers_done_training / total_helpers * 100, 1) if total_helpers > 0 else 0
    # 加算判定
    req_kaigo30 = kaigo_ratio >= 30  # 加算I・II要件
    req_kaigo10 = kaigo_ratio >= 10  # 加算III要件
    req_meeting = days_since_meeting <= 35  # 月1回以上（少し余裕を持たせる）
    req_training_plan = training_coverage >= 100  # 全員に研修計画
    req_training_done = training_done_rate >= 80   # 実施率80%以上
    can_tokutei1 = req_kaigo30 and req_meeting and req_training_plan and req_training_done
    can_tokutei2 = req_kaigo30 and req_meeting
    can_tokutei3 = req_kaigo10 and req_meeting
    db.close()
    return {
        "total_helpers": total_helpers, "kaigo_helpers": kaigo_helpers, "kaigo_ratio": kaigo_ratio,
        "meetings_3m": meetings_3m, "days_since_meeting": days_since_meeting,
        "helpers_with_training": helpers_with_training, "helpers_done_training": helpers_done_training,
        "training_coverage": training_coverage, "training_done_rate": training_done_rate,
        "req_kaigo30": req_kaigo30, "req_kaigo10": req_kaigo10,
        "req_meeting": req_meeting, "req_training_plan": req_training_plan, "req_training_done": req_training_done,
        "can_tokutei1": can_tokutei1, "can_tokutei2": can_tokutei2, "can_tokutei3": can_tokutei3,
        "today": today
    }

# ── 運営指導対策チェックリスト ─────────────────────────────────
INSPECTION_ITEMS_HOUMON = [
  {"key":"doc_enrollment","cat":"書類・記録","label":"利用者ファイル（契約書・重説・アセスメント・個別計画）の整備","required":True},
  {"key":"doc_careplan","cat":"書類・記録","label":"訪問介護計画書の作成・交付・保護者署名","required":True},
  {"key":"doc_visit_record","cat":"書類・記録","label":"サービス実施記録（毎回）の整備と利用者確認","required":True},
  {"key":"doc_incident","cat":"書類・記録","label":"ヒヤリハット・事故報告書の整備","required":True},
  {"key":"staff_license","cat":"人員・資格","label":"サービス提供責任者の資格要件（介護福祉士等）確認","required":True},
  {"key":"staff_ratio","cat":"人員・資格","label":"ヘルパー人員基準の充足","required":True},
  {"key":"staff_health","cat":"人員・資格","label":"健康診断の実施（年1回以上）","required":True},
  {"key":"staff_training","cat":"人員・資格","label":"採用時研修・年2回以上の定期研修の実施","required":True},
  {"key":"meeting_monthly","cat":"会議・研修","label":"サービス提供責任者との定期会議（月1回以上）記録","required":True},
  {"key":"meeting_individual","cat":"会議・研修","label":"個別研修計画の作成と実施","required":False},
  {"key":"privacy","cat":"権利擁護","label":"個人情報取扱同意書の取得","required":True},
  {"key":"complaint","cat":"権利擁護","label":"苦情対応手順の整備・掲示","required":True},
  {"key":"kinkyu","cat":"緊急対応","label":"緊急時対応マニュアルの整備・周知","required":True},
  {"key":"bcp","cat":"BCP","label":"業務継続計画（BCP）の策定・訓練","required":True},
  {"key":"signage","cat":"設備・環境","label":"運営規程・重説・管理者氏名等の掲示","required":True},
  {"key":"billing_check","cat":"請求","label":"国保連請求内容と実績記録の突合確認","required":True},
]

class InspectionReq(BaseModel):
    item_key: str
    status: str  # ok / ng / na / unchecked
    note: str = ''

@app.get("/api/inspection-checklist")
async def get_inspection(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT item_key, status, note, checked_at FROM inspection_checks WHERE office_id=?", (oid,)).fetchall()
    db.close()
    saved = {r["item_key"]: dict(r) for r in rows}
    items = []
    for item in INSPECTION_ITEMS_HOUMON:
        s = saved.get(item["key"], {})
        items.append({**item, "status": s.get("status","unchecked"), "note": s.get("note",""), "checked_at": s.get("checked_at","")})
    total = len(items); ok_count = sum(1 for i in items if i["status"]=="ok")
    return {"items": items, "total": total, "ok_count": ok_count, "score": round(ok_count/total*100) if total else 0}

@app.patch("/api/inspection-checklist")
async def update_inspection(req: InspectionReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    db.execute("""INSERT INTO inspection_checks(office_id,item_key,status,note,checked_at) VALUES(?,?,?,?,?)
        ON CONFLICT(office_id,item_key) DO UPDATE SET status=excluded.status,note=excluded.note,checked_at=excluded.checked_at""",
        (oid, req.item_key, req.status, req.note, now)); db.commit(); db.close()
    return {"ok": True}

# ── 行政手続きカレンダー ─────────────────────────────────────────
ADMIN_SCHEDULE_HOUMON = [
  {"month":4,"day":None,"title":"介護報酬改定 対応確認","cat":"請求・報酬","note":"算定単位数・加算要件の変更確認"},
  {"month":5,"day":10,"title":"前月（4月）分 国保連請求締切","cat":"請求・報酬","note":"請求誤りがないか確認"},
  {"month":5,"day":None,"title":"前年度 実績報告（自治体）","cat":"報告・届出","note":"自治体により期限が異なる"},
  {"month":6,"day":10,"title":"前月（5月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":7,"day":10,"title":"前月（6月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":8,"day":10,"title":"前月（7月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":9,"day":10,"title":"前月（8月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":10,"day":10,"title":"前月（9月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":10,"day":None,"title":"処遇改善加算 計画届（翌年度分）","cat":"加算・届出","note":"自治体により10〜12月締切"},
  {"month":11,"day":10,"title":"前月（10月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":11,"day":None,"title":"介護保険事業計画 ヒアリング対応","cat":"計画・調査","note":"3年に1度・自治体による"},
  {"month":12,"day":10,"title":"前月（11月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":1,"day":10,"title":"前月（12月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":2,"day":10,"title":"前月（1月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":2,"day":None,"title":"処遇改善加算 実績報告（前年度分）","cat":"加算・届出","note":"自治体により1〜3月締切"},
  {"month":3,"day":10,"title":"前月（2月）分 国保連請求締切","cat":"請求・報酬","note":""},
  {"month":3,"day":None,"title":"次年度 加算算定届・変更届","cat":"加算・届出","note":"人員・体制変更がある場合"},
  {"month":3,"day":31,"title":"個人情報・プライバシーポリシー年次確認","cat":"コンプライアンス","note":""},
  {"month":4,"day":1,"title":"新年度 運営規程・重要事項説明書 改訂確認","cat":"書類更新","note":"報酬改定に合わせて料金表等を更新"},
]

@app.get("/api/admin-schedule")
async def admin_schedule(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db); db.close()
    today = datetime.now()
    cur_month = today.month
    items = []
    for item in ADMIN_SCHEDULE_HOUMON:
        m = item["month"]
        diff = (m - cur_month) % 12
        items.append({**item, "months_until": diff, "is_this_month": diff == 0, "is_next_month": diff == 1})
    items.sort(key=lambda x: x["months_until"])
    return {"items": items, "current_month": cur_month}

# ── 処遇改善加算シミュレーター ──────────────────────────────────
# R6 介護職員等処遇改善加算（訪問介護）
SHOGU_RATES_HOUMON = {
    "I": 24.5, "II": 22.4, "III": 18.0, "IV": 14.5
}
# 要件: I=全要件, II=月給・就業規則, III=賃金体系・研修, IV=キャリアパスのみ

class ShoguSimReq(BaseModel):
    monthly_sales: float = 0           # 月間売上（円）
    career_path: bool = False           # キャリアパス要件
    salary_rules: bool = False          # 就業規則・賃金規程
    monthly_salary: bool = False        # 月給制
    training_plan: bool = False         # 研修計画・実施
    improvement_plan: bool = False      # 職場環境等要件（賃金改善計画）
    all_staff_raise: bool = False       # 全職員への配分

@app.post("/api/shogu-sim")
async def shogu_sim(req: ShoguSimReq, oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    # 月間売上が未指定の場合は実績から推定
    if req.monthly_sales <= 0:
        today = datetime.now()
        last_month = (today.replace(day=1) - timedelta(days=1))
        ym = last_month.strftime("%Y-%m")
        records = db.execute("SELECT COUNT(*) as c FROM visit_records WHERE office_id=? AND visit_date LIKE ?", (oid, ym+"%")).fetchone()["c"]
        office = db.execute("SELECT units_per_visit, tanka_unit FROM offices WHERE id=?", (oid,)).fetchone()
        est_visits = records if records > 0 else 80
        units = office["units_per_visit"] or 254; tanka = office["tanka_unit"] or 1140
        monthly_sales = est_visits * units * tanka / 100
    else:
        monthly_sales = req.monthly_sales
    db.close()
    # 加算判定
    can_4 = req.career_path
    can_3 = can_4 and req.salary_rules and req.training_plan
    can_2 = can_3 and req.monthly_salary
    can_1 = can_2 and req.improvement_plan and req.all_staff_raise
    achievable = "I" if can_1 else "II" if can_2 else "III" if can_3 else "IV" if can_4 else None
    results = {}
    for rank, rate in SHOGU_RATES_HOUMON.items():
        amount = monthly_sales * rate / 100
        results[rank] = {"rate": rate, "monthly_amount": round(amount), "annual_amount": round(amount * 12)}
    missing = []
    if not req.career_path: missing.append("キャリアパス要件（職位・職責・賃金体系の整備）")
    if req.career_path and not req.salary_rules: missing.append("就業規則・賃金規程の整備")
    if req.career_path and not req.training_plan: missing.append("研修計画の策定と実施実績")
    if can_3 and not req.monthly_salary: missing.append("月給制への移行（加算Ⅱ要件）")
    if can_2 and not req.improvement_plan: missing.append("職場環境等要件（賃金改善計画）")
    if can_2 and not req.all_staff_raise: missing.append("全職員への賃金改善額の配分")
    return {
        "monthly_sales": round(monthly_sales), "achievable_rank": achievable,
        "results": results, "missing_for_next": missing,
        "req_status": {"career_path": req.career_path, "salary_rules": req.salary_rules,
                       "monthly_salary": req.monthly_salary, "training_plan": req.training_plan,
                       "improvement_plan": req.improvement_plan, "all_staff_raise": req.all_staff_raise}
    }

# ── ICT補助金チェックリスト ─────────────────────────────────────
ICT_ITEMS_HOUMON = [
  {"key":"ict_has_system","cat":"現状確認","label":"訪問介護記録システム（タブレット記録等）を導入済み","required":False},
  {"key":"ict_staff_count","cat":"現状確認","label":"常勤職員5名以上（補助金申請要件）","required":True},
  {"key":"ict_jigyosho_no","cat":"現状確認","label":"事業所番号の確認・申請書類の準備","required":True},
  {"key":"ict_subsidy_check","cat":"補助金調査","label":"自治体のICT補助金・助成金の公募情報を確認","required":True},
  {"key":"ict_it_dantai","cat":"補助金調査","label":"IT導入補助金（経済産業省）の対象確認","required":True},
  {"key":"ict_kaigo_ict","cat":"補助金調査","label":"介護テクノロジー導入支援事業（厚労省）の対象確認","required":True},
  {"key":"ict_vendor_quote","cat":"導入準備","label":"介護ソフトベンダーから見積書を取得","required":False},
  {"key":"ict_it_tools","cat":"導入準備","label":"ITツール登録業者リストから対象ソフトを確認","required":False},
  {"key":"ict_apply","cat":"申請","label":"補助金申請書類（事業計画・見積書等）の作成","required":False},
  {"key":"ict_training","cat":"導入後","label":"スタッフへのICTツール研修の実施","required":False},
  {"key":"ict_effect","cat":"導入後","label":"導入効果の測定・報告書作成（補助金精算に必要）","required":False},
]

@app.get("/api/ict-checklist")
async def get_ict(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT item_key, status, note, checked_at FROM inspection_checks WHERE office_id=? AND item_key LIKE 'ict_%'", (oid,)).fetchall()
    db.close()
    saved = {r["item_key"]: dict(r) for r in rows}
    items = [{**item, "status": saved.get(item["key"],{}).get("status","unchecked"), "note": saved.get(item["key"],{}).get("note",""), "checked_at": saved.get(item["key"],{}).get("checked_at","")} for item in ICT_ITEMS_HOUMON]
    ok_count = sum(1 for i in items if i["status"]=="ok")
    return {"items": items, "total": len(items), "ok_count": ok_count, "score": round(ok_count/len(items)*100) if items else 0}

# ── 外部評価対応サポート ─────────────────────────────────────────
EXTERNAL_EVAL_ITEMS = [
  {"key":"eval_self_check","cat":"自己評価","label":"サービス管理者・スタッフによる自己評価の実施","required":True},
  {"key":"eval_user_survey","cat":"利用者調査","label":"利用者（家族）アンケートの実施","required":True},
  {"key":"eval_doc_ready","cat":"書類準備","label":"関係書類（個別支援計画・記録・会議録）の整備","required":True},
  {"key":"eval_complaint_log","cat":"書類準備","label":"苦情受付・対応記録の整備","required":True},
  {"key":"eval_incident_log","cat":"書類準備","label":"事故・ヒヤリハット報告書の整備","required":True},
  {"key":"eval_training_log","cat":"書類準備","label":"職員研修記録の整備","required":True},
  {"key":"eval_select_org","cat":"評価機関","label":"第三者評価機関の選定・申込み","required":True},
  {"key":"eval_interview","cat":"評価実施","label":"評価機関との事前打ち合わせ・訪問日程調整","required":True},
  {"key":"eval_visit","cat":"評価実施","label":"評価機関の訪問・ヒアリング対応","required":True},
  {"key":"eval_report","cat":"評価後","label":"評価結果報告書の受領・確認","required":True},
  {"key":"eval_publish","cat":"評価後","label":"評価結果の公表（WAMネット等）","required":True},
  {"key":"eval_action","cat":"評価後","label":"評価結果に基づく改善計画の策定・実施","required":True},
]

@app.get("/api/external-eval")
async def get_external_eval(oid: int = Depends(current_office)):
    db = get_db(); check_active(oid, db)
    rows = db.execute("SELECT item_key, status, note, checked_at FROM inspection_checks WHERE office_id=? AND item_key LIKE 'eval_%'", (oid,)).fetchall()
    db.close()
    saved = {r["item_key"]: dict(r) for r in rows}
    items = [{**item, "status": saved.get(item["key"],{}).get("status","unchecked"), "note": saved.get(item["key"],{}).get("note",""), "checked_at": saved.get(item["key"],{}).get("checked_at","")} for item in EXTERNAL_EVAL_ITEMS]
    ok_count = sum(1 for i in items if i["status"]=="ok")
    return {"items": items, "total": len(items), "ok_count": ok_count, "score": round(ok_count/len(items)*100) if items else 0}

# __cross_summary_added__
_CROSS_KEY = "roukin-cross-2025-xyz"

@app.get("/api/cross-summary")
async def cross_summary_houmon(request: Request):
    from datetime import datetime, timedelta
    if request.headers.get("X-Cross-Key", "") != _CROSS_KEY:
        raise HTTPException(403)
    db = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    active_offices  = db.execute("SELECT COUNT(*) as c FROM offices WHERE subscription_status!='cancelled'").fetchone()["c"]
    active_users    = db.execute("SELECT COUNT(*) as c FROM clients WHERE is_active=1").fetchone()["c"]
    today_visits    = db.execute("SELECT COUNT(*) as c FROM visit_plans WHERE plan_date=?", (today,)).fetchone()["c"]
    cp_alerts       = db.execute("SELECT COUNT(*) as c FROM care_plans WHERE next_review<? AND next_review!=''", (today,)).fetchone()["c"]
    trend = []
    for i in range(5, -1, -1):
        d = datetime.now().replace(day=1) - timedelta(days=i*28)
        ym = d.strftime("%Y-%m")
        cnt = db.execute("SELECT COUNT(*) as c FROM visit_records WHERE visit_date LIKE ?", (ym+"%",)).fetchone()["c"]
        trend.append({"month": ym, "count": cnt})
    db.close()
    return {"system_type": "houmon", "system_name": "訪問介護", "app_url": "/houmon/", "hq_url": "/houmon/hq/auto-login", "icon": "🚗",
            "active_offices": active_offices, "active_users": active_users,
            "today_activity": today_visits, "today_label": "今日の訪問予定件数",
            "alerts": cp_alerts, "alert_label": "ケアプラン 期限切れ", "monthly_trend": trend}

# ── 音声文字起こし（Whisper API）─────────────────────────────────
@app.post("/api/voice-transcribe")
async def voice_transcribe(audio: UploadFile = File(...)):
    _ALLOWED_AUDIO = {"audio/webm","audio/ogg","audio/mp4","audio/mpeg","audio/wav","video/webm","video/mp4"}
    _MAX_AUDIO = 25 * 1024 * 1024  # 25MB
    base_ct = (audio.content_type or "").split(";")[0].strip()
    if base_ct and base_ct not in _ALLOWED_AUDIO:
        raise HTTPException(400, "許可されていないファイル形式です")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise HTTPException(500, "音声認識が設定されていません")
    try:
        from openai import OpenAI as OpenAIClient
        client = OpenAIClient(api_key=api_key, timeout=30.0)
        data = await audio.read()
        if len(data) > _MAX_AUDIO:
            raise HTTPException(413, "ファイルサイズが大きすぎます(上限25MB)")
        ext = "mp4" if "mp4" in (audio.content_type or "") else "webm"
        transcript = client.audio.transcriptions.create(
            model="whisper-1",
            file=(f"voice.{ext}", data, audio.content_type or "audio/webm"),
            language="ja"
        )
        return JSONResponse({"text": transcript.text})
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "音声認識に失敗しました")

# ── 総務ツール連携API ──────────────────────────────────────────
@app.get("/api/v1/users")
def soumu_users(request: Request):
    api_key = os.environ.get("SOUMU_API_KEY", "")
    if not api_key or request.headers.get("X-API-Key") != api_key:
        raise HTTPException(401, "Unauthorized")
    db = get_db()
    rows = db.execute(
        "SELECT id, name, kana, is_active FROM clients ORDER BY id"
    ).fetchall()
    db.close()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "kana": r["kana"],
            "service_type": "訪問介護",
            "status": "契約中" if r["is_active"] else "終了",
        }
        for r in rows
    ]


def _sync_nicemeet(email: str, plan: str):
    try:
        import sqlite3 as _sqlite3
        nm = _sqlite3.connect("/home/ubuntu/meet/data/booking.db")
        nm.execute("UPDATE users SET plan=? WHERE email=?", (plan, email))
        nm.commit()
        rows = nm.execute("SELECT changes()").fetchone()[0]
        nm.close()
        print(f"[stripe-webhook] NiceMeet sync: {email} -> plan={plan} ({rows} rows)")
    except Exception as e:
        print(f"[stripe-webhook] NiceMeet sync error: {e}")

# ── Stripe 決済 ──────────────────────────────────────────────
from stripe_billing import get_stripe, WEBHOOK_SECRET, PRICES as _STRIPE_PRICES
import stripe as _stripe_lib
try:
    import requests as _requests
except ImportError:
    _requests = None

@app.post("/api/stripe/checkout")
async def stripe_checkout(request: Request, oid: int = Depends(current_office)):
    s = get_stripe()
    if not s: raise HTTPException(503, "Stripe not configured")
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if not office: raise HTTPException(404)
    try:
        customer_id = office["stripe_customer_id"]
    except (IndexError, KeyError):
        customer_id = None
    if not customer_id:
        customer = s.customers.create(
            email=office["email"], name=office["office_name"],
            metadata={"office_id": str(oid), "app": "訪問介護Manager"}
        )
        customer_id = customer.id
        db.execute("UPDATE offices SET stripe_customer_id=? WHERE id=?", (customer_id, oid))
        db.commit()
    plan = (office["plan"] or "standard")
    price_id = _STRIPE_PRICES.get(plan) or _STRIPE_PRICES.get("standard", "")
    if not price_id: raise HTTPException(503, "Price ID not configured")
    session = s.checkout.sessions.create(
        customer=customer_id, payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}], mode="subscription",
        success_url="https://gaiaarts.org/houmon/?stripe=success",
        cancel_url="https://gaiaarts.org/houmon/", locale="ja"
    )
    return {"url": session.url}

@app.get("/api/stripe/portal")
async def stripe_portal(request: Request, oid: int = Depends(current_office)):
    s = get_stripe()
    if not s: raise HTTPException(503, "Stripe not configured")
    db = get_db()
    office = db.execute("SELECT stripe_customer_id FROM offices WHERE id=?", (oid,)).fetchone()
    try:
        cid = office["stripe_customer_id"] if office else None
    except (IndexError, KeyError):
        cid = None
    if not cid: raise HTTPException(400, "no subscription")
    session = s.billing_portal.sessions.create(
        customer=cid, return_url="https://gaiaarts.org/houmon/"
    )
    return RedirectResponse(session.url)

@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    s = get_stripe()
    if not s: raise HTTPException(503, "Stripe not configured")
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = _stripe_lib.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(400, str(e))
    obj = event["data"]["object"]
    customer_id = obj.get("customer")
    if not customer_id: return {"received": True}
    db = get_db()
    office = db.execute("SELECT id, email FROM offices WHERE stripe_customer_id=?", (customer_id,)).fetchone()
    if not office: return {"received": True}
    if event["type"] in ("customer.subscription.created", "customer.subscription.updated", "invoice.payment_succeeded"):
        status = obj.get("status")
        if not status or status in ("active", "trialing"):
            db.execute("UPDATE offices SET subscription_status=\'active\' WHERE id=?", (office["id"],))
            db.commit()
            print(f"[stripe-webhook] activated: offices id={office['id']}")
            _sync_nicemeet(office["email"], "paid")
    elif event["type"] in ("customer.subscription.deleted", "customer.subscription.paused"):
        db.execute("UPDATE offices SET subscription_status=\'cancelled\' WHERE id=?", (office["id"],))
        db.commit()
        print(f"[stripe-webhook] cancelled: offices id={office['id']}")
        _sync_nicemeet(office["email"], "free")
    elif event["type"] == "invoice.payment_failed":
        print(f"[stripe-webhook] payment failed customer={customer_id}")
    return {"received": True}

