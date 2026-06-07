from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, hashlib, secrets, json, os, csv, io, smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jose import jwt
try:
    from openai import OpenAI as OpenAIClient
except ImportError:
    OpenAIClient = None

from database import get_db, init_db

SECRET_KEY = "houmon-manager-secret-2025-vkz8"
ALGORITHM = "HS256"
BASE_PATH = "/houmon"

app = FastAPI(root_path=BASE_PATH)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── auth helpers ──────────────────────────────────────────────
def hash_pw(pw, salt): return hashlib.sha256((pw+salt).encode()).hexdigest()
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
@app.get("/", response_class=HTMLResponse)
@app.get("", response_class=HTMLResponse)
async def index():
    with open("static/index.html", encoding="utf-8") as f: return f.read()

# ── auth ──────────────────────────────────────────────────────
@app.post("/api/register")
async def register(req: RegisterReq):
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
async def login(req: LoginReq):
    db = get_db()
    row = db.execute("SELECT * FROM offices WHERE username=?", (req.username,)).fetchone()
    db.close()
    if not row or hash_pw(req.password, row["pw_salt"]) != row["pw_hash"]: raise HTTPException(401, "invalid")
    return {"token": make_token(row["id"], req.username), "office_name": row["office_name"],
            "plan": row["plan"], "subscription_status": row["subscription_status"]}

@app.get("/api/me")
async def me(oid: int = Depends(current_office)):
    db = get_db()
    row = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end FROM offices WHERE id=?", (oid,)).fetchone()
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
        "cp_overdue": cp_overdue, "cp_soon": cp_soon,
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
    db = get_db()
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
    row = db.execute("SELECT * FROM visit_records WHERE id=?", (rid,)).fetchone()
    db.close()
    return dict(row)

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
    db.close()
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
        notes = f"（{r['helper_notes'][:30]}）" if r.get("helper_notes") else ""
        lines.append(f"{alert}{r['client_name']}様 {r['checkin_time']}〜{r['checkout_time']} 担当:{r['helper_name'] or '未設定'} 体調:{cond_label.get(r['client_condition'],'')} {notes}")
    if not_checked:
        lines.append(f"\n【訪問未完了 {len(not_checked)}件】")
        for v in not_checked:
            lines.append(f"{v['client_name']}様 {v['start_time']} 担当:{v['helper_name'] or '未割当'}")
    text = "\n".join(lines)
    try:
        client = OpenAIClient(api_key=api_key)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=400,
            messages=[
                {"role": "system", "content": "訪問介護事業所の管理者です。本日の訪問記録から、事業所全体の日報サマリーを150字程度で作成してください。体調不良者・未訪問者・特記事項を優先して記載。自然な文体で。"},
                {"role": "user", "content": f"本日（{today}）の訪問記録：\n{text}\n\n日報サマリーを作成してください。"}
            ]
        )
        return {"summary": resp.choices[0].message.content, "records_count": len(records)}
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
async def hq_auto_login():
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
<script>
localStorage.setItem('houmon_hq_token','{token}');
setTimeout(()=>location.href='/houmon/hq/',300);
</script></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/demo/", response_class=HTMLResponse)
@app.get("/demo", response_class=HTMLResponse)
async def app_demo_page():
    with open("static/demo.html", encoding="utf-8") as f: content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control":"no-store"})

@app.get("/auto-login/", response_class=HTMLResponse)
@app.get("/auto-login", response_class=HTMLResponse)
async def auto_login():
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
HQ_SECRET = "houmon-hq-secret-2025-wqz6"

class HqLoginReq(BaseModel):
    username: str; password: str
class HqRegisterReq(BaseModel):
    username: str; org_name: str; email: str; password: str; office_ids: Optional[List[int]]=[]
class HqSmtpReq(BaseModel):
    smtp_host: str; smtp_port: int; smtp_user: str; smtp_pass: str

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
    if key != ADMIN_KEY: raise HTTPException(403)
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
async def hq_login(req: HqLoginReq):
    db = get_db()
    row = db.execute("SELECT * FROM hq_accounts WHERE username=?", (req.username,)).fetchone()
    db.close()
    if not row or hash_pw(req.password, row["pw_salt"]) != row["pw_hash"]: raise HTTPException(401)
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

# ── admin ─────────────────────────────────────────────────────
ADMIN_KEY = "houmon-admin-2025"
class ActivateReq(BaseModel):
    username: str; plan: str

@app.get("/api/admin/offices")
async def admin_offices(key: str):
    if key != ADMIN_KEY: raise HTTPException(403)
    db = get_db()
    rows = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end,created_at FROM offices ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/admin/activate")
async def admin_activate(req: ActivateReq, key: str):
    if key != ADMIN_KEY: raise HTTPException(403)
    db = get_db()
    db.execute("UPDATE offices SET plan=?,subscription_status='active' WHERE username=?", (req.plan, req.username))
    db.commit(); db.close()
    return {"ok": True}
