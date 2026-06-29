from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Cookie, Header
from fastapi.responses import StreamingResponse, JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os, uuid, logging, json, bcrypt, jwt, httpx
import asyncio
import google.generativeai as genai

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# --- KONFIGURASI ENVIRONMENT (SUDAH DIGANTI KE GEMINI) ---
MONGO_URL = os.environ.get('MONGO_URL', os.environ.get('MONGO_URI', 'mongodb://localhost:27017'))
DB_NAME = os.environ.get('DB_NAME', 'journal_guinevere')
JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_MODEL = "gemini-1.5-flash" # Atau gemini-pro

# Use in-memory storage if MongoDB is not available
USE_MOCK_DB = os.environ.get('USE_MOCK_DB', 'false').lower() == 'true'

if USE_MOCK_DB:
    mock_db = {
        "users": [], "user_sessions": [], "chat_sessions": [], "chat_messages": [], "journal_entries": [],
    }
    
    class MockCollection:
        def __init__(self, name): self.name = name; self.data = mock_db.get(name, [])
        async def find_one(self, query, projection=None):
            for item in self.data:
                if all(item.get(k) == v for k, v in query.items()):
                    return item if not projection else {k:v for k,v in item.items() if k != "_id"}
            return None
        async def insert_one(self, doc): self.data.append(doc); return type('obj', (object,), {'inserted_id': 'mock_id'})
        async def update_one(self, query, update):
            for item in self.data:
                if all(item.get(k) == v for k, v in query.items()) and "$set" in update:
                    for k, v in update["$set"].items(): item[k] = v
                    return type('obj', (object,), {'modified_count': 1})
            return type('obj', (object,), {'modified_count': 0})
        async def delete_one(self, query):
            for i, item in enumerate(self.data):
                if all(item.get(k) == v for k, v in query.items()):
                    self.data.pop(i); return type('obj', (object,), {'deleted_count': 1})
            return type('obj', (object,), {'deleted_count': 0})
        def find(self, query, projection=None):
            class MockCursor:
                def __init__(self, data, query, proj):
                    self.data = [i for i in data if all(i.get(k)==v for k,v in query.items())]
                    self.proj = proj; self.sort_key = None; self.sort_rev = False
                def sort(self, key, direction): self.sort_key = key; self.sort_rev = (direction == -1); return self
                async def to_list(self, limit):
                    if self.sort_key: self.data.sort(key=lambda x: x.get(self.sort_key, ''), reverse=self.sort_rev)
                    res = self.data[:limit]
                    if self.proj and "_id" in self.proj and self.proj["_id"] == 0:
                        res = [{k:v for k,v in i.items() if k != "_id"} for i in res]
                    return res
            return MockCursor(self.data, query, projection)
    class MockDB: def __getattr__(self, name): return MockCollection(name)
    db = MockDB()
else:
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]

app = FastAPI(title="Journal-Guin API")
api = APIRouter(prefix="/api")
logger = logging.getLogger("journal_guin")
logging.basicConfig(level=logging.INFO)

# ---------- Models ----------
class SignupIn(BaseModel): email: EmailStr; password: str; name: str
class LoginIn(BaseModel): email: EmailStr; password: str
class SessionIn(BaseModel): session_id: str
class ChatStartIn(BaseModel): title: Optional[str] = None
class ChatMessageIn(BaseModel): session_id: str; message: str
class JournalExtractIn(BaseModel): session_id: str; transcript: str

def now_utc(): return datetime.now(timezone.utc)
def iso(d: datetime): return d.astimezone(timezone.utc).isoformat()

# ---------- Auth helpers ----------
def make_jwt(user_id: str) -> str:
    payload = {"sub": user_id, "iat": int(now_utc().timestamp()), "exp": int((now_utc() + timedelta(days=7)).timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> Optional[str]:
    try: return jwt.decode(token, JWT_SECRET, algorithms=["HS256"]).get("sub")
    except: return None

async def get_current_user(request: Request, session_token: Optional[str] = Cookie(default=None), authorization: Optional[str] = Header(default=None)):
    token = session_token
    if not token and authorization and authorization.lower().startswith("bearer "): token = authorization.split(" ", 1)[1].strip()
    if token:
        sess = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if sess:
            exp = sess["expires_at"]
            if isinstance(exp, str): exp = datetime.fromisoformat(exp)
            if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
            if exp >= now_utc():
                user = await db.users.find_one({"user_id": sess["user_id"]}, {"_id": 0, "password_hash": 0})
                if user: return user
        uid = decode_jwt(token)
        if uid:
            user = await db.users.find_one({"user_id": uid}, {"_id": 0, "password_hash": 0})
            if user: return user
    raise HTTPException(status_code=401, detail="Not authenticated")

# ---------- Auth endpoints ----------
@api.post("/auth/signup")
async def signup(body: SignupIn):
    if await db.users.find_one({"email": body.email.lower()}, {"_id": 0}): raise HTTPException(400, "Email already registered")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    doc = {"user_id": user_id, "email": body.email.lower(), "name": body.name, "picture": None, "auth_provider": "email", "password_hash": pw_hash, "created_at": iso(now_utc())}
    await db.users.insert_one(doc)
    return {"token": make_jwt(user_id), "user": {"user_id": user_id, "email": doc["email"], "name": doc["name"], "picture": None}}

@api.post("/auth/login")
async def login(body: LoginIn):
    user = await db.users.find_one({"email": body.email.lower()}, {"_id": 0})
    if not user or not user.get("password_hash") or not bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")
    return {"token": make_jwt(user["user_id"]), "user": {"user_id": user["user_id"], "email": user["email"], "name": user["name"], "picture": user.get("picture")}}

@api.post("/auth/session")
async def emergent_session(body: SessionIn, response: Response):
    async with httpx.AsyncClient(timeout=15) as cx:
        r = await cx.get("https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data", headers={"X-Session-ID": body.session_id})
    if r.status_code != 200: raise HTTPException(401, "Invalid session_id")
    data = r.json()
    email = data["email"].lower()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user = {"user_id": user_id, "email": email, "name": data.get("name") or email.split("@")[0], "picture": data.get("picture"), "auth_provider": "google", "password_hash": None, "created_at": iso(now_utc())}
        await db.users.insert_one(user)
    else:
        await db.users.update_one({"user_id": user["user_id"]}, {"$set": {"picture": data.get("picture") or user.get("picture"), "name": data.get("name") or user.get("name")}})
    session_token = data["session_token"]
    await db.user_sessions.insert_one({"user_id": user["user_id"], "session_token": session_token, "expires_at": iso(now_utc() + timedelta(days=7)), "created_at": iso(now_utc())})
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=True, samesite="none", path="/", max_age=7*24*3600)
    return {"user": {"user_id": user["user_id"], "email": user["email"], "name": user["name"], "picture": user.get("picture")}}

@api.get("/auth/me")
async def me(user=Depends(get_current_user)): return user

@api.post("/auth/logout")
async def logout(response: Response, session_token: Optional[str] = Cookie(default=None)):
    if session_token: await db.user_sessions.delete_one({"session_token": session_token})
    response.delete_cookie("session_token", path="/")
    return {"ok": True}

# ---------- Chat endpoints (GEMINI) ----------
SYSTEM_PROMPT = """You are Guinevere, a warm, insightful AI growth mentor. Speak like a thoughtful friend. Ask one follow-up question. Notice patterns. Never give medical advice."""

@api.post("/chat/sessions")
async def create_session(body: ChatStartIn, user=Depends(get_current_user)):
    sid = f"chat_{uuid.uuid4().hex[:12]}"
    doc = {"session_id": sid, "user_id": user["user_id"], "title": body.title or "New Reflection", "created_at": iso(now_utc()), "updated_at": iso(now_utc())}
    await db.chat_sessions.insert_one(doc)
    return {"session_id": sid, "title": doc["title"], "created_at": doc["created_at"]}

@api.get("/chat/sessions")
async def list_sessions(user=Depends(get_current_user)):
    return await db.chat_sessions.find({"user_id": user["user_id"]}, {"_id": 0}).sort("updated_at", -1).to_list(200)

@api.get("/chat/sessions/{session_id}/messages")
async def session_messages(session_id: str, user=Depends(get_current_user)):
    sess = await db.chat_sessions.find_one({"session_id": session_id, "user_id": user["user_id"]}, {"_id": 0})
    if not sess: raise HTTPException(404, "Session not found")
    msgs = await db.chat_messages.find({"session_id": session_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)
    return {"session": sess, "messages": msgs}

@api.post("/chat/stream")
async def chat_stream(body: ChatMessageIn, user=Depends(get_current_user)):
    if not GEMINI_API_KEY: raise HTTPException(500, "GEMINI_API_KEY not configured")
    
    sess = await db.chat_sessions.find_one({"session_id": body.session_id, "user_id": user["user_id"]}, {"_id": 0})
    if not sess: raise HTTPException(404, "Session not found")

    user_msg = {"session_id": body.session_id, "role": "user", "content": body.message, "created_at": iso(now_utc())}
    await db.chat_messages.insert_one(user_msg)

    prior = await db.chat_messages.find({"session_id": body.session_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)
    
    # Setup Gemini
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
    
    # Build history for Gemini
    chat_history = []
    for m in prior[:-1]: # Exclude current message which we send separately or append
        role = "user" if m["role"] == "user" else "model"
        chat_history.append({"role": role, "parts": [m["content"]]})
    
    # Start chat with history
    chat = model.start_chat(history=chat_history)
    
    async def event_gen():
        full = ""
        try:
            # Send message and stream response
            response = chat.send_message(body.message, stream=True)
            for chunk in response:
                if chunk.text:
                    full += chunk.text
                    yield f"data: {json.dumps({'delta': chunk.text})}\n\n"
        except Exception as e:
            logger.exception("stream error")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

        await db.chat_messages.insert_one({"session_id": body.session_id, "role": "assistant", "content": full, "created_at": iso(now_utc())})
        await db.chat_sessions.update_one({"session_id": body.session_id}, {"$set": {"updated_at": iso(now_utc())}})
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})

# ---------- Journal extraction (GEMINI) ----------
EXTRACT_PROMPT = """You are a journal-data extractor. Output ONLY a JSON object with schema: {"date": "YYYY-MM-DD", "mood": "string", "mood_score": 1-10, "energy_score": 1-10, "habits": [], "emotions": [], "themes": [], "wins": [], "challenges": [], "summary": "string", "growth_nudge": "string"}."""

@api.post("/journal/extract")
async def journal_extract(body: JournalExtractIn, user=Depends(get_current_user)):
    if not GEMINI_API_KEY: raise HTTPException(500, "GEMINI_API_KEY not configured")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)
    
    today = now_utc().strftime("%Y-%m-%d")
    msg = f"Today's date: {today}\n\nConversation transcript:\n{body.transcript}\n\nReturn only the JSON object."
    
    response = model.generate_content(f"{EXTRACT_PROMPT}\n\n{msg}")
    raw = response.text.strip()
    
    if raw.startswith("```"): raw = raw.strip("`").replace("json", "", 1).strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end != -1: raw = raw[start:end+1]
    
    try: data = json.loads(raw)
    except Exception: raise HTTPException(500, f"Failed to parse extractor output: {raw[:200]}")

    entry_id = f"entry_{uuid.uuid4().hex[:12]}"
    data.update({"entry_id": entry_id, "user_id": user["user_id"], "session_id": body.session_id, "created_at": iso(now_utc())})
    await db.journal_entries.insert_one(data)
    data.pop("_id", None)
    return data

@api.get("/journal/entries")
async def list_entries(user=Depends(get_current_user)):
    return await db.journal_entries.find({"user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)

@api.get("/")
async def root(): return {"app": "Journal-Guin", "status": "ok", "llm": "gemini"}

app.include_router(api)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','), allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown():
    if not USE_MOCK_DB: client.close()
