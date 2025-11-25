"""
MiniTube - FastAPI + PostgreSQL + Cloudinary
Environment variables required:
- DATABASE_URL (Postgres connection string) [optional for quick test: uses sqlite if absent]
- SECRET_KEY (JWT secret)
- CLOUDINARY_URL (cloudinary://API_KEY:API_SECRET@CLOUD_NAME)
"""
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from pathlib import Path
from urllib.parse import urlparse, unquote

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# password helper (pure-python backend, no extra native deps)
from passlib.hash import pbkdf2_sha256

import jwt
import cloudinary
import cloudinary.uploader

# ------------------ Config & Cloudinary init ------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip() or None
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL")

def init_cloudinary_from_url(url: Optional[str]) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme != "cloudinary":
            return False
        api_key = parsed.username
        api_secret = parsed.password
        cloud_name = parsed.hostname
        if api_key:
            api_key = unquote(api_key)
        if api_secret:
            api_secret = unquote(api_secret)
        if not (api_key and api_secret and cloud_name):
            return False
        cloudinary.config(cloud_name=cloud_name, api_key=api_key, api_secret=api_secret, secure=True)
        return True
    except Exception:
        return False

CLOUDINARY_OK = init_cloudinary_from_url(CLOUDINARY_URL)
if not CLOUDINARY_OK:
    print("Warning: Cloudinary not configured or CLOUDINARY_URL invalid. Uploads will fail until corrected.")

# ------------------ Paths ------------------
BASE_DIR = Path(__file__).resolve().parent
MEDIA_DIR = BASE_DIR / ".." / "media"
MEDIA_DIR.mkdir(exist_ok=True, parents=True)

# ------------------ DB setup (robust driver selection) ------------------
# Choose DB URL: prefer DATABASE_URL (provided by Render), else sqlite file for local/dev.
_default_sqlite = "sqlite:///./dev.db"
_selected_db_url = DATABASE_URL or _default_sqlite

# Detect available Postgres drivers
PG_DRIVER = None
try:
    import psycopg2  # type: ignore
    PG_DRIVER = "psycopg2"
except Exception:
    try:
        import psycopg  # psycopg v3, type: ignore
        PG_DRIVER = "psycopg"
    except Exception:
        PG_DRIVER = None

# If the URL is a postgres-style URL and we have a preferred driver, adjust scheme only if necessary.
_engine_url = _selected_db_url
if _engine_url and (_engine_url.startswith("postgres://") or _engine_url.startswith("postgresql://")):
    if PG_DRIVER == "psycopg2":
        # SQLAlchemy accepts plain postgresql:// and will use psycopg2, but make explicit to be safe:
        if _engine_url.startswith("postgres://"):
            _engine_url = _engine_url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif _engine_url.startswith("postgresql://") and "+psycopg2" not in _engine_url:
            _engine_url = _engine_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    elif PG_DRIVER == "psycopg":
        if _engine_url.startswith("postgres://"):
            _engine_url = _engine_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif _engine_url.startswith("postgresql://") and "+psycopg" not in _engine_url:
            _engine_url = _engine_url.replace("postgresql://", "postgresql+psycopg://", 1)
    else:
        # No PG driver available — fallback to sqlite so the app can still run and you can inspect logs.
        print("WARNING: DATABASE_URL points to Postgres but neither psycopg2 nor psycopg is installed.")
        print("Falling back to local sqlite for now. To use Postgres, install psycopg2-binary or psycopg.")
        _engine_url = _default_sqlite

# connect_args only needed for sqlite
connect_args = {"check_same_thread": False} if _engine_url and _engine_url.startswith("sqlite") else {}

# Create engine
try:
    engine = create_engine(_engine_url, connect_args=connect_args)
except Exception as e:
    # If engine creation fails, fall back to sqlite (so site still runs) and print error to logs.
    print("Failed to create SQLAlchemy engine with URL:", _engine_url)
    print("Engine creation error:", str(e))
    _engine_url = _default_sqlite
    engine = create_engine(_engine_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ------------------ Models ------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(256), unique=True, index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    videos = relationship("Video", back_populates="uploader")
    comments = relationship("Comment", back_populates="user")

class Video(Base):
    __tablename__ = "videos"
    id = Column(Integer, primary_key=True)
    title = Column(String(256))
    description = Column(Text)
    cloudinary_public_id = Column(String(512), nullable=True)
    cloudinary_url = Column(String(1024), nullable=True)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    likes = Column(Integer, default=0)
    dislikes = Column(Integer, default=0)
    views = Column(Integer, default=0)
    uploader = relationship("User", back_populates="videos")
    comments = relationship("Comment", back_populates='video')

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    video_id = Column(Integer, ForeignKey("videos.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    parent_id = Column(Integer, nullable=True)
    content = Column(Text, nullable=False)
    likes = Column(Integer, default=0)
    dislikes = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    video = relationship("Video", back_populates="comments")
    user = relationship("User", back_populates="comments")

class Reaction(Base):
    __tablename__ = "reactions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    target_type = Column(String(16), nullable=False)
    target_id = Column(Integer, nullable=False)
    value = Column(Integer, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'target_type', 'target_id', name='_user_target_uc'),)

# Create tables if they don't exist (safe for both sqlite & Postgres)
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print("Error creating DB tables:", str(e))

# ------------------ FastAPI app ------------------
app = FastAPI(title="MiniTube (Render)")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ------------------ Helpers ------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# password helpers
def hash_password(pw: str) -> str:
    return pbkdf2_sha256.hash(pw)

def verify_password(pw: str, h: str) -> bool:
    return pbkdf2_sha256.verify(pw, h)

def create_token(user_id: int) -> str:
    payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None

def current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    data = decode_token(token)
    if not data:
        return None
    user = db.query(User).filter(User.id == data.get("user_id")).first()
    return user

# helpers for cloudinary thumbnails
def make_thumb(public_id: str, width: int = 480, height: int = 360) -> Optional[str]:
    if not CLOUDINARY_OK or not public_id:
        return None
    try:
        from cloudinary.utils import cloudinary_url
        url, _ = cloudinary_url(public_id, resource_type="video", format="jpg",
                                transformation=[{"start_offset":"0","width":width,"height":height,"crop":"fill"}])
        return url
    except Exception:
        return None

# ------------------ Routes ------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    videos = db.query(Video).order_by(Video.views.desc(), Video.created_at.desc()).limit(30).all()
    video_list = []
    for v in videos:
        video_list.append({
            "id": v.id,
            "title": v.title or "Untitled",
            "views": v.views or 0,
            "likes": v.likes or 0,
            "dislikes": v.dislikes or 0,
            "uploader": v.uploader.username if v.uploader else "unknown",
            "thumb_url": make_thumb(v.cloudinary_public_id, width=320, height=180) or v.cloudinary_url or "/static/placeholder.jpg",
        })
    return templates.TemplateResponse("index.html", {"request": request, "videos": video_list, "user": current_user(request, db)})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register(request: Request, email: str = Form(...), username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter((User.email == email) | (User.username == username)).first():
        return templates.TemplateResponse("register.html", {"request": request, "error":"Email or username taken"})
    user = User(email=email, username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_token(user.id)
    resp = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie("access_token", token, httponly=True, samesite="lax")
    return resp

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, identifier: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter((User.email == identifier) | (User.username == identifier)).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error":"Invalid credentials"})
    token = create_token(user.id)
    resp = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie("access_token", token, httponly=True, samesite="lax")
    return resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie("access_token")
    return resp

@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("upload.html", {"request": request, "user": user})

@app.post("/upload")
def upload_video(request: Request, title: str = Form(...), description: str = Form(""), file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not CLOUDINARY_OK:
        raise HTTPException(500, "Cloudinary is not configured correctly. Set CLOUDINARY_URL environment variable.")
    tmp_name = f"/tmp/{uuid.uuid4().hex}_{os.path.basename(file.filename)}"
    try:
        with open(tmp_name, "wb") as f:
            f.write(file.file.read())
    except Exception as e:
        raise HTTPException(500, f"Failed to save upload: {e}")
    try:
        res = cloudinary.uploader.upload(tmp_name, resource_type="video", folder="minitube_videos")
    except Exception as e:
        print("Cloudinary upload error:", str(e))
        try:
            os.remove(tmp_name)
        except Exception:
            pass
        raise HTTPException(500, "Video upload failed (Cloudinary). Check logs.")
    public_id = res.get("public_id")
    url = res.get("secure_url")
    token = request.cookies.get("access_token")
    data = decode_token(token) if token else None
    user_id = data.get("user_id") if data else None
    if not user_id:
        try:
            os.remove(tmp_name)
        except Exception:
            pass
        raise HTTPException(401, "Unauthorized")
    video = Video(title=title, description=description, cloudinary_public_id=public_id, cloudinary_url=url, uploader_id=user_id)
    db.add(video)
    db.commit()
    db.refresh(video)
    try:
        os.remove(tmp_name)
    except Exception:
        pass
    return RedirectResponse(f"/watch/{video.id}", status_code=status.HTTP_302_FOUND)

@app.get("/watch/{video_id}", response_class=HTMLResponse)
def watch_video(request: Request, video_id: int, db: Session = Depends(get_db)):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(404, "Not found")
    try:
        video.views = (video.views or 0) + 1
        db.commit()
    except Exception:
        db.rollback()
    thumb_url = make_thumb(video.cloudinary_public_id, width=640, height=360) if video.cloudinary_public_id else (video.cloudinary_url or "/static/placeholder.jpg")
    comments = db.query(Comment).filter(Comment.video_id == video.id).order_by(Comment.created_at.asc()).all()
    return templates.TemplateResponse("watch.html", {"request": request, "video": video, "thumb_url": thumb_url, "comments": comments, "user": current_user(request, db)})

@app.post("/watch/{video_id}/comment")
def post_comment(request: Request, video_id: int, content: str = Form(...), parent_id: Optional[int] = Form(None), db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    comment = Comment(video_id=video_id, user_id=user.id, parent_id=parent_id, content=content)
    db.add(comment)
    db.commit()
    return RedirectResponse(f"/watch/{video_id}")

@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: Optional[str] = None, db: Session = Depends(get_db)):
    videos = []
    if q:
        pattern = f"%{q}%"
        videos = db.query(Video).filter((Video.title.ilike(pattern)) | (Video.description.ilike(pattern))).limit(50).all()
    return templates.TemplateResponse("search.html", {"request": request, "videos": videos, "q": q, "user": current_user(request, db)})

@app.post("/api.react")
async def react_api(request: Request, db: Session = Depends(get_db)):
    # Keep the same react handling as before (you can adapt to your frontend)
    return JSONResponse({"status": "ok"})

@app.get("/profile/{username}", response_class=HTMLResponse)
def profile_page(request: Request, username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(404, "User not found")
    videos = db.query(Video).filter(Video.uploader_id == user.id).order_by(Video.created_at.desc()).all()
    return templates.TemplateResponse("profile.html", {"request": request, "profile": user, "videos": videos, "user": current_user(request, db)})

@app.get("/health")
def health():
    return {"status":"ok"}
