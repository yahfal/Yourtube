"""
MiniTube - FastAPI + PostgreSQL + Cloudinary
Environment variables required:
- DATABASE_URL (Postgres connection string)
- SECRET_KEY (JWT secret)
- CLOUDINARY_URL (cloudinary://API_KEY:API_SECRET@CLOUD_NAME)
"""
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# ⬇️ ЗАМЕНА bcrypt -> argon2
from passlib.hash import argon2

import jwt
import cloudinary
import cloudinary.uploader

# Config
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL")
if CLOUDINARY_URL:
    cloudinary.config(cloudinary_url=CLOUDINARY_URL)

BASE_DIR = Path(__file__).resolve().parent
MEDIA_DIR = BASE_DIR / ".." / "media"
MEDIA_DIR.mkdir(exist_ok=True, parents=True)

# DB setup
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(256), unique=True, index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    videos = relationship("Video", back_populates="uploader")
    comments = relationship("Comment", back_populates="user")

class Video(Base):
    __tablename__ = "videos"
    id = Column(Integer, primary_key=True)
    title = Column(String(256))
    description = Column(Text)
    cloudinary_public_id = Column(String(512), nullable=False)
    cloudinary_url = Column(String(1024), nullable=False)
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

Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="MiniTube (Render)")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Helpers
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ⬇️ ИСПРАВЛЕННЫЕ ФУНКЦИИ ПАРОЛЕЙ
def hash_password(pw: str) -> str:
    return argon2.hash(pw)

def verify_password(pw: str, h: str) -> bool:
    return argon2.verify(pw, h)

def create_token(user_id: int):
    payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

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

# Routes
@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    videos = db.query(Video).order_by(Video.created_at.desc()).limit(30).all()
    return templates.TemplateResponse("index.html", {"request": request, "videos": videos, "user": current_user(request, db)})

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
    if not CLOUDINARY_URL:
        raise HTTPException(500, "CLOUDINARY_URL not configured")
    tmp_name = f"/tmp/{uuid.uuid4().hex}_{file.filename}"
    with open(tmp_name, "wb") as f:
        f.write(file.file.read())
    res = cloudinary.uploader.upload(tmp_name, resource_type="video", folder="minitube_videos")
    public_id = res.get("public_id")
    url = res.get("secure_url")
    token = request.cookies.get("access_token")
    data = decode_token(token) if token else None
    user_id = data.get("user_id") if data else None
    if not user_id:
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
    video.views += 1
    db.commit()
    thumb_url = None
    if video.cloudinary_public_id and CLOUDINARY_URL:
        from cloudinary.utils import cloudinary_url
        thumb_url, _ = cloudinary_url(video.cloudinary_public_id, resource_type="video", format="jpg", transformation=[{"start_offset":"0","width":480,"height":360,"crop":"fill"}])
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

@app.post("/api/react")
def react_api(request: Request, target_type: str = Form(...), target_id: int = Form(...), value: int = Form(...), db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(401, "Unauthorized")
    existing = db.query(Reaction).filter(Reaction.user_id == user.id, Reaction.target_type == target_type, Reaction.target_id == target_id).first()
    if existing and existing.value == value:
        db.delete(existing)
    elif existing and existing.value != value:
        existing.value = value
    else:
        db.add(Reaction(user_id=user.id, target_type=target_type, target_id=target_id, value=value))
    db.commit()
    if target_type == "video":
        v = db.query(Video).filter(Video.id == target_id).first()
        if v:
            likes = db.query(Reaction).filter(Reaction.target_type=="video", Reaction.target_id==v.id, Reaction.value==1).count()
            dislikes = db.query(Reaction).filter(Reaction.target_type=="video", Reaction.target_id==v.id, Reaction.value==-1).count()
            v.likes = likes
            v.dislikes = dislikes
            db.commit()
    return {"status":"ok"}

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
