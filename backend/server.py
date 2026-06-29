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

from emergentintegrations.llm.chat import LlmChat, UserMessage, TextDelta, StreamDone

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'journal_guinevere')
JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret')
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', '')
CLAUDE_MODEL = "claude-sonnet-4-5-20250929"

# Use in-memory storage if MongoDB is not available
USE_MOCK_DB = os.environ.get('USE_MOCK_DB', 'false').lower() == 'true'

if USE_MOCK_DB:
    # In-memory mock database
    mock_db = {
        "users": [],
        "user_sessions": [],
        "chat_sessions": [],
        "chat_messages": [],
        "journal_entries": [],
    }
    
    class MockCollection:
        def __init__(self, name):
            self.name = name
            self.data = mock_db.get(name, [])
        
        async def find_one(self, query, projection=None):
            for item in self.data:
                match = True
                for k, v in query.items():
                    if item.get(k) != v:
                        match = False
                        break
                if match:
                    if projection:
                        if "_id" in projection and projection["_id"] == 0:
                            item_copy = {k: v for k, v in item.items() if k != "_id"}
                            return item_copy
                    return item
            return None
        
        async def insert_one(self, doc):
            self.data.append(doc)
            return type('obj', (object,), {'inserted_id': 'mock_id'})
        
        async def update_one(self, query, update):
            for item in self.data:
                match = True
                for k, v in query.items():
                    if item.get(k) != v:
                        match = False
                        break
                if match and "$set" in update:
                    for k, v in update["$set"].items():
                        item[k] = v
                    return type('obj', (object,), {'modified_count': 1})
            return type('obj', (object,), {'modified_count': 0})
        
        async def delete_one(self, query):
            for i, item in enumerate(self.data):
                match = True
                for k, v in query.items():
                    if item.get(k) != v:
                        match = False
                        break
                if match:
                    self.data.pop(i)
                    return type('obj', (object,), {'deleted_count': 1})
            return type('obj', (object,), {'deleted_count': 0})
        
        def find(self, query, projection=None):
            class MockCursor:
                def __init__(self, data, query, projection):
                    self.data = [item for item in data if all(item.get(k) == v for k, v in query.items())]
                    self.projection = projection
                    self.sort_order = None
                
                def sort(self, key, direction):
                    self.sort_order = (key, direction)
                    if direction == -1:
                        self.data.sort(key=lambda x: x.get(key, ''), reverse=True)
                    else:
                        self.data.sort(key=lambda x: x.get(key, ''))
                    return self
                
                async def to_list(self, limit):
                    result = self.data[:limit]
                    if self.projection:
                        if "_id" in self.projection and self.projection["_id"] == 0:
                            result = [{k: v for k, v in item.items() if k != "_id"} for item in result]
                    return result
            return MockCursor(self.data, query, projection)
    
    class MockDB:
        def __getattr__(self, name):
            return MockCollection(name)
    
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
class SignupIn(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class SessionIn(BaseModel):
    session_id: str

class ChatStartIn(BaseModel):
    title: Optional[str] = None

class ChatMessageIn(BaseModel):
    session_id: str
    message: str

class JournalExtractIn(BaseModel):
    session_id: str
    transcript: str  # full conversation text from frontend


def now_utc():
    return datetime.now(timezone.utc)

def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat()


# ---------- Auth helpers ----------
def make_jwt(user_id: str) -> str:
    payload = {"sub": user_id, "iat": int(now_utc().timestamp()),
               "exp": int((now_utc() + timedelta(days=7)).timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data.get("sub")
    except Exception:
        return None

async def get_current_user(
    request: Request,
    session_token: Optional[str] = Cookie(default=None),
    authorization: Optional[str] = Header(default=None),
):
    # 1. Emergent OAuth session_token (cookie or Bearer)
    token = session_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if token:
        # Try emergent session table
        sess = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if sess:
            expires_at = sess["expires_at"]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at >= now_utc():
                user = await db.users.find_one({"user_id": sess["user_id"]}, {"_id": 0, "password_hash": 0})
                if user:
                    return user

        # Try JWT
        uid = decode_jwt(token)
        if uid:
            user = await db.users.find_one({"user_id": uid}, {"_id": 0, "password_hash": 0})
            if user:
                return user

    raise HTTPException(status_code=401, detail="Not authenticated")


# ---------- Auth endpoints ----------
@api.post("/auth/signup")
async def signup(body: SignupIn):
    existing = await db.users.find_one({"email": body.email.lower()}, {"_id": 0})
    if existing:
        raise HTTPException(400, "Email already registered")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    doc = {
        "user_id": user_id,
        "email": body.email.lower(),
        "name": body.name,
        "picture": None,
        "auth_provider": "email",
        "password_hash": pw_hash,
        "created_at": iso(now_utc()),
    }
    await db.users.insert_one(doc)
    token = make_jwt(user_id)
    return {"token": token, "user": {"user_id": user_id, "email": doc["email"], "name": doc["name"], "picture": None}}


@api.post("/auth/login")
async def login(body: LoginIn):
    user = await db.users.find_one({"email": body.email.lower()}, {"_id": 0})
    if not user or not user.get("password_hash"):
        raise HTTPException(401, "Invalid credentials")
    if not bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")
    token = make_jwt(user["user_id"])
    return {"token": token, "user": {"user_id": user["user_id"], "email": user["email"],
                                     "name": user["name"], "picture": user.get("picture")}}


@api.post("/auth/session")
async def emergent_session(body: SessionIn, response: Response):
    """Exchange Emergent session_id for a session_token, store user, set cookie."""
    async with httpx.AsyncClient(timeout=15) as cx:
        r = await cx.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": body.session_id},
        )
    if r.status_code != 200:
        raise HTTPException(401, "Invalid session_id")
    data = r.json()
    email = data["email"].lower()

    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user = {
            "user_id": user_id, "email": email, "name": data.get("name") or email.split("@")[0],
            "picture": data.get("picture"), "auth_provider": "google",
            "password_hash": None, "created_at": iso(now_utc()),
        }
        await db.users.insert_one(user)
    else:
        await db.users.update_one({"user_id": user["user_id"]},
                                  {"$set": {"picture": data.get("picture") or user.get("picture"),
                                            "name": data.get("name") or user.get("name")}})

    session_token = data["session_token"]
    expires_at = now_utc() + timedelta(days=7)
    await db.user_sessions.insert_one({
        "user_id": user["user_id"],
        "session_token": session_token,
        "expires_at": iso(expires_at),
        "created_at": iso(now_utc()),
    })
    response.set_cookie(
        key="session_token", value=session_token, httponly=True,
        secure=True, samesite="none", path="/", max_age=7*24*3600,
    )
    return {"user": {"user_id": user["user_id"], "email": user["email"],
                     "name": user["name"], "picture": user.get("picture")}}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@api.post("/auth/logout")
async def logout(response: Response, session_token: Optional[str] = Cookie(default=None)):
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    response.delete_cookie("session_token", path="/")
    return {"ok": True}


# ---------- Chat endpoints ----------
SYSTEM_PROMPT = """You are Guinevere, a warm, insightful AI growth mentor who helps the user reflect on their day and grow.

Style:
- Speak like a thoughtful friend, not a clinical therapist. Concise (2-4 short paragraphs).
- Ask one focused follow-up question per response when the user is journaling.
- Notice patterns: mood, energy, habits, emotional triggers, wins, lessons.
- Offer gentle reframes when you spot rumination or self-criticism.
- Never give medical advice; suggest professional help if user mentions self-harm.

When the user has shared enough to summarize the day, you may end your reply with a short structured insight block (mood label, key habits done, emotional theme, one growth nudge). Keep it under 6 lines.
"""

@api.post("/chat/sessions")
async def create_session(body: ChatStartIn, user=Depends(get_current_user)):
    sid = f"chat_{uuid.uuid4().hex[:12]}"
    doc = {
        "session_id": sid, "user_id": user["user_id"],
        "title": body.title or "New Reflection",
        "created_at": iso(now_utc()), "updated_at": iso(now_utc()),
    }
    await db.chat_sessions.insert_one(doc)
    return {"session_id": sid, "title": doc["title"], "created_at": doc["created_at"]}


@api.get("/chat/sessions")
async def list_sessions(user=Depends(get_current_user)):
    rows = await db.chat_sessions.find({"user_id": user["user_id"]}, {"_id": 0}) \
        .sort("updated_at", -1).to_list(200)
    return rows


@api.get("/chat/sessions/{session_id}/messages")
async def session_messages(session_id: str, user=Depends(get_current_user)):
    sess = await db.chat_sessions.find_one({"session_id": session_id, "user_id": user["user_id"]}, {"_id": 0})
    if not sess:
        raise HTTPException(404, "Session not found")
    msgs = await db.chat_messages.find({"session_id": session_id}, {"_id": 0}) \
        .sort("created_at", 1).to_list(1000)
    return {"session": sess, "messages": msgs}


@api.post("/chat/stream")
async def chat_stream(body: ChatMessageIn, user=Depends(get_current_user)):
    sess = await db.chat_sessions.find_one({"session_id": body.session_id, "user_id": user["user_id"]}, {"_id": 0})
    if not sess:
        raise HTTPException(404, "Session not found")

    # Save user message
    user_msg = {"session_id": body.session_id, "role": "user", "content": body.message,
                "created_at": iso(now_utc())}
    await db.chat_messages.insert_one(user_msg)

    # Build chat with all prior messages as system context (LlmChat keeps its own history per instance,
    # so we replay history into a fresh instance each request).
    prior = await db.chat_messages.find({"session_id": body.session_id}, {"_id": 0}) \
        .sort("created_at", 1).to_list(1000)

    chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=body.session_id,
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", CLAUDE_MODEL)

    # Replay all but the latest user message into chat history via send_message? No -
    # emergentintegrations LlmChat manages history when you call send/stream. Simplest:
    # we re-send all prior turns by passing them as part of the user message context.
    # Instead, we pass the latest user message and prepend a compact transcript so the model has context.
    history_text = ""
    for m in prior[:-1]:  # exclude the just-inserted user message
        role = "User" if m["role"] == "user" else "Guinevere"
        history_text += f"{role}: {m['content']}\n"

    composed = body.message
    if history_text:
        composed = f"[Prior conversation, for your context only]\n{history_text}\n[Current user message]\n{body.message}"

    async def event_gen():
        full = ""
        try:
            async for ev in chat.stream_message(UserMessage(text=composed)):
                if isinstance(ev, TextDelta):
                    full += ev.content
                    yield f"data: {json.dumps({'delta': ev.content})}\n\n"
                elif isinstance(ev, StreamDone):
                    break
        except Exception as e:
            logger.exception("stream error")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

        # persist assistant message
        await db.chat_messages.insert_one({
            "session_id": body.session_id, "role": "assistant", "content": full,
            "created_at": iso(now_utc()),
        })
        await db.chat_sessions.update_one(
            {"session_id": body.session_id},
            {"$set": {"updated_at": iso(now_utc())}},
        )
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---------- Journal extraction ----------
EXTRACT_PROMPT = """You are a journal-data extractor. Read the user's reflection conversation and output ONLY a JSON object (no prose, no code fences) with this exact schema:

{
  "date": "YYYY-MM-DD",
  "mood": "one short word: e.g., calm, anxious, hopeful, drained, energized, grateful, frustrated",
  "mood_score": 1-10,
  "energy_score": 1-10,
  "habits": ["short habit strings the user did or skipped, prefix with + for done and - for missed, e.g. '+meditation', '-no-phone-morning'"],
  "emotions": ["1-4 short emotion labels"],
  "themes": ["1-3 short topics, e.g. 'work stress', 'family'"],
  "wins": ["short wins"],
  "challenges": ["short challenges"],
  "summary": "2 sentence summary of the day in third person",
  "growth_nudge": "one short forward-looking suggestion"
}

If a field is unknown, use an empty string or empty array. Always include the date (use today's date if user did not specify)."""


@api.post("/journal/extract")
async def journal_extract(body: JournalExtractIn, user=Depends(get_current_user)):
    extractor = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=f"extract_{body.session_id}_{uuid.uuid4().hex[:6]}",
        system_message=EXTRACT_PROMPT,
    ).with_model("anthropic", CLAUDE_MODEL)

    today = now_utc().strftime("%Y-%m-%d")
    msg = f"Today's date: {today}\n\nConversation transcript:\n{body.transcript}\n\nReturn only the JSON object."

    full = ""
    async for ev in extractor.stream_message(UserMessage(text=msg)):
        if isinstance(ev, TextDelta):
            full += ev.content
        elif isinstance(ev, StreamDone):
            break

    # extract JSON
    raw = full.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1:
        raw = raw[start:end+1]
    try:
        data = json.loads(raw)
    except Exception:
        raise HTTPException(500, f"Failed to parse extractor output: {full[:200]}")

    entry_id = f"entry_{uuid.uuid4().hex[:12]}"
    data["entry_id"] = entry_id
    data["user_id"] = user["user_id"]
    data["session_id"] = body.session_id
    data["created_at"] = iso(now_utc())

    # store cloud copy (lightweight, no full transcript) for analytics
    await db.journal_entries.insert_one({**data})
    data.pop("_id", None)
    return data


@api.get("/journal/entries")
async def list_entries(user=Depends(get_current_user)):
    rows = await db.journal_entries.find({"user_id": user["user_id"]}, {"_id": 0}) \
        .sort("created_at", -1).to_list(500)
    return rows


@api.get("/")
async def root():
    return {"app": "Journal-Guin", "status": "ok"}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    client.close()
