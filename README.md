# MiniTube (FastAPI) — Render deployment

This is a minimal YouTube-like web app built with FastAPI, SQLAlchemy and Cloudinary (for video storage).
It is intended to be deployed on Render using your GitHub repo.

## Features
- Register / Login (email + username + password)
- Upload videos (stored on Cloudinary)
- Watch videos (served from Cloudinary)
- Comments, simple likes/dislikes system
- Search, profile pages

## Required environment variables (on Render)
- DATABASE_URL - Postgres connection string (Render Postgres or Supabase/Postgres)
- SECRET_KEY - JWT secret
- CLOUDINARY_URL - Cloudinary URL (cloudinary://API_KEY:API_SECRET@CLOUD_NAME)

## Deploy steps (summary)
1. Create a GitHub repo and push this project.
2. Create a Cloudinary account (free) and get CLOUDINARY_URL.
3. On Render: New -> Web Service -> Connect GitHub repo -> Choose 'Python' runtime.
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. In Render dashboard, set environment variables (DATABASE_URL, SECRET_KEY, CLOUDINARY_URL).
   - For DATABASE_URL, create a PostgreSQL database on Render and copy the URL.
5. Deploy. Open the service URL and register a user.

## Notes
- Cloudinary's free plan includes video hosting and transformations. This project uses Cloudinary to store videos and generate thumbnails (no ffmpeg needed).
- For production, tighten security, add rate limiting, sanitization (bleach), background processing for large uploads, and use a CDN.
