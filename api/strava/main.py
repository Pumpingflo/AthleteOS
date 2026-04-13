from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import jwt
import requests
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from jwt import PyJWKClient
from pydantic import BaseModel, Field

app = FastAPI(title="Strivon Strava Sync", version="0.1.0")


def _cors_origins() -> list[str]:
    raw = (os.environ.get("ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return ["*"]
    out: list[str] = []
    for origin in raw.split(","):
        s = origin.strip().rstrip("/")
        if not s:
            continue
        try:
            p = urlparse(s if "://" in s else "https://" + s)
            if p.scheme and p.netloc:
                clean = f"{p.scheme}://{p.netloc}"
                if clean not in out:
                    out.append(clean)
        except Exception:
            if s not in out:
                out.append(s)
    return out if out else ["*"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

SUPABASE_JWT_SECRET = (os.environ.get("SUPABASE_JWT_SECRET") or "").strip().strip('"').strip("'")
STRAVA_CLIENT_ID = (os.environ.get("STRAVA_CLIENT_ID") or "").strip()
STRAVA_CLIENT_SECRET = (os.environ.get("STRAVA_CLIENT_SECRET") or "").strip()
STRAVA_REDIRECT_URI = (os.environ.get("STRAVA_REDIRECT_URI") or "").strip()
STRAVA_SCOPE = (os.environ.get("STRAVA_SCOPE") or "read,activity:read_all").strip()
TOKEN_DB_PATH = (os.environ.get("STRAVA_TOKEN_DB_PATH") or "./strava_tokens.db").strip()
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").strip().rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = (os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
STRAVA_TOKENS_TABLE = (os.environ.get("STRAVA_TOKENS_TABLE") or "strava_tokens").strip()
STRAVA_WEBHOOK_EVENTS_TABLE = (os.environ.get("STRAVA_WEBHOOK_EVENTS_TABLE") or "strava_webhook_events").strip()
STRAVA_WEBHOOK_VERIFY_TOKEN = (os.environ.get("STRAVA_WEBHOOK_VERIFY_TOKEN") or "").strip()
STRAVA_WEBHOOK_LOG_PATH = (os.environ.get("STRAVA_WEBHOOK_LOG_PATH") or "./strava_webhook_events.jsonl").strip()


def _supabase_enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


def _sb_headers() -> dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }


def _sb_rest_url(table: str) -> str:
    return f"{SUPABASE_URL}/rest/v1/{table}"

def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(TOKEN_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strava_tokens (
            user_id TEXT PRIMARY KEY,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _save_token(user_id: str, token: dict[str, Any]) -> None:
    if _supabase_enabled():
        payload = {
            "user_id": user_id,
            "access_token": str(token.get("access_token") or ""),
            "refresh_token": str(token.get("refresh_token") or ""),
            "expires_at": float(token.get("expires_at") or 0),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        upsert_headers = dict(_sb_headers())
        upsert_headers["Prefer"] = "resolution=merge-duplicates,return=minimal"
        res = requests.post(
            _sb_rest_url(STRAVA_TOKENS_TABLE),
            headers=upsert_headers,
            params={"on_conflict": "user_id"},
            json=payload,
            timeout=20,
        )
        if res.ok:
            return
    conn = _db_conn()
    try:
        conn.execute(
            """
            INSERT INTO strava_tokens(user_id, access_token, refresh_token, expires_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              access_token=excluded.access_token,
              refresh_token=excluded.refresh_token,
              expires_at=excluded.expires_at,
              updated_at=excluded.updated_at
            """,
            (
                user_id,
                str(token.get("access_token") or ""),
                str(token.get("refresh_token") or ""),
                float(token.get("expires_at") or 0),
                time.time(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _load_token(user_id: str) -> dict[str, Any] | None:
    if _supabase_enabled():
        res = requests.get(
            _sb_rest_url(STRAVA_TOKENS_TABLE),
            headers=_sb_headers(),
            params={
                "select": "access_token,refresh_token,expires_at",
                "user_id": f"eq.{user_id}",
                "limit": "1",
            },
            timeout=20,
        )
        if res.ok:
            rows = res.json() or []
            if rows:
                row = rows[0]
                return {
                    "access_token": row.get("access_token") or "",
                    "refresh_token": row.get("refresh_token") or "",
                    "expires_at": float(row.get("expires_at") or 0),
                }
    conn = _db_conn()
    try:
        row = conn.execute(
            "SELECT access_token, refresh_token, expires_at FROM strava_tokens WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        return {"access_token": row[0], "refresh_token": row[1], "expires_at": float(row[2] or 0)}
    finally:
        conn.close()


def _delete_token(user_id: str) -> None:
    if _supabase_enabled():
        requests.delete(
            _sb_rest_url(STRAVA_TOKENS_TABLE),
            headers=_sb_headers(),
            params={"user_id": f"eq.{user_id}"},
            timeout=20,
        )
        return
    conn = _db_conn()
    try:
        conn.execute("DELETE FROM strava_tokens WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def _peek_token(token: str) -> dict:
    return jwt.decode(
        token,
        algorithms=["HS256", "RS256", "ES256"],
        options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
    )


def verify_supabase_jwt(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    alg = (header.get("alg") or "HS256").upper()
    leeway = 120
    if alg in ("ES256", "RS256"):
        peek = _peek_token(token)
        iss = (peek.get("iss") or "").rstrip("/")
        if not iss.startswith("https://"):
            raise HTTPException(401, "Token issuer invalid.")
        jwks = PyJWKClient(iss + "/.well-known/jwks.json", cache_keys=True)
        key = jwks.get_signing_key_from_jwt(token)
        try:
            return jwt.decode(token, key.key, algorithms=[alg], audience="authenticated", leeway=leeway)
        except jwt.InvalidAudienceError:
            return jwt.decode(token, key.key, algorithms=[alg], options={"verify_aud": False}, leeway=leeway)
    if not SUPABASE_JWT_SECRET:
        raise HTTPException(500, "SUPABASE_JWT_SECRET fehlt.")
    try:
        return jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated", leeway=leeway)
    except jwt.InvalidAudienceError:
        return jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False}, leeway=leeway)
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Ungültiges Login-Token.") from exc


def _encode_state(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_state(state: str) -> dict[str, Any]:
    padded = state + "=" * (-len(state) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, "Ungültiger OAuth-State") from exc


def _token_for_user(user_id: str) -> dict[str, Any] | None:
    tok = _load_token(user_id)
    if not tok:
        return None
    if float(tok.get("expires_at", 0)) > time.time() + 60:
        return tok
    if not tok.get("refresh_token"):
        return tok
    data = {
        "client_id": STRAVA_CLIENT_ID,
        "client_secret": STRAVA_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
    }
    res = requests.post("https://www.strava.com/oauth/token", data=data, timeout=20)
    if not res.ok:
        return tok
    payload = res.json()
    tok = {
        "access_token": payload.get("access_token", tok.get("access_token")),
        "refresh_token": payload.get("refresh_token", tok.get("refresh_token")),
        "expires_at": float(payload.get("expires_at", tok.get("expires_at", 0))),
    }
    _save_token(user_id, tok)
    return tok


@app.get("/health")
def health():
    return {"status": "ok", "service": "strivon-strava-sync"}


@app.get("/strava/oauth/start")
def strava_oauth_start(
    state: str = Query(...),
    user_id: str = Query(...),
    return_url: str = Query(...),
):
    if not STRAVA_CLIENT_ID or not STRAVA_CLIENT_SECRET or not STRAVA_REDIRECT_URI:
        raise HTTPException(500, "Strava OAuth env vars fehlen (CLIENT_ID/SECRET/REDIRECT_URI).")
    packed_state = _encode_state({"csrf": state, "uid": user_id, "return_url": return_url})
    qs = urlencode(
        {
            "client_id": STRAVA_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": STRAVA_REDIRECT_URI,
            "approval_prompt": "auto",
            "scope": STRAVA_SCOPE,
            "state": packed_state,
        }
    )
    return RedirectResponse(url="https://www.strava.com/oauth/authorize?" + qs, status_code=302)


@app.get("/strava/oauth/callback")
def strava_oauth_callback(code: str = Query(default=""), state: str = Query(default="")):
    if not code or not state:
        raise HTTPException(400, "OAuth callback ohne code/state.")
    decoded = _decode_state(state)
    csrf = str(decoded.get("csrf") or "")
    user_id = str(decoded.get("uid") or "")
    return_url = str(decoded.get("return_url") or "")
    if not user_id or not return_url:
        raise HTTPException(400, "OAuth state unvollständig.")
    data = {
        "client_id": STRAVA_CLIENT_ID,
        "client_secret": STRAVA_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
    }
    res = requests.post("https://www.strava.com/oauth/token", data=data, timeout=25)
    if not res.ok:
        fail_qs = urlencode({"strava_status": "error", "state": csrf})
        return RedirectResponse(url=return_url + "?" + fail_qs, status_code=302)
    payload = res.json()
    _save_token(user_id, {
        "access_token": payload.get("access_token"),
        "refresh_token": payload.get("refresh_token"),
        "expires_at": float(payload.get("expires_at", 0)),
    })
    ok_qs = urlencode({"strava_status": "connected", "state": csrf})
    return RedirectResponse(url=return_url + "?" + ok_qs, status_code=302)


class SyncBody(BaseModel):
    user_id: str | None = Field(default=None, min_length=4)

def _norm_activity(a: dict[str, Any]) -> dict[str, Any]:
    dist_m = float(a.get("distance") or 0)
    moving_s = int(a.get("moving_time") or 0)
    avg_hr = a.get("average_heartrate")
    max_hr = a.get("max_heartrate")
    return {
        "id": str(a.get("id") or ""),
        "name": str(a.get("name") or ""),
        "type": str(a.get("type") or ""),
        "sport_type": str(a.get("sport_type") or ""),
        "start_date_local": str(a.get("start_date_local") or ""),
        "distance_m": dist_m,
        "duration_s": moving_s,
        "distance_km": round(dist_m / 1000.0, 2) if dist_m > 0 else 0,
        "duration_min": round(moving_s / 60.0, 1) if moving_s > 0 else 0,
        "avg_hr": int(avg_hr) if avg_hr else None,
        "max_hr": int(max_hr) if max_hr else None,
    }


def _persist_webhook_event(event: dict[str, Any]) -> None:
    payload = {
        "owner_id": event.get("owner_id"),
        "object_id": event.get("object_id"),
        "aspect_type": event.get("aspect_type"),
        "object_type": event.get("object_type"),
        "event_time": event.get("event_time"),
        "updates": event.get("updates") or {},
        "raw": event,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if _supabase_enabled():
        requests.post(
            _sb_rest_url(STRAVA_WEBHOOK_EVENTS_TABLE),
            headers=_sb_headers(),
            json=payload,
            timeout=15,
        )
        return
    with open(STRAVA_WEBHOOK_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=True) + "\n")


@app.post("/strava/sync")
def strava_sync(body: SyncBody, authorization: str | None = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authorization fehlt.")
    claims = verify_supabase_jwt(authorization[7:].strip())
    uid = claims.get("sub")
    req_uid = body.user_id or uid
    if req_uid != uid:
        raise HTTPException(403, "user_id passt nicht zur Session.")
    token = _token_for_user(uid)
    if not token or not token.get("access_token"):
        raise HTTPException(409, "Kein verbundenes Strava-Konto.")
    headers = {"Authorization": "Bearer " + token["access_token"]}
    params = {"per_page": 100, "page": 1}
    res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers, params=params, timeout=25)
    if not res.ok:
        raise HTTPException(502, "Strava API Fehler beim Laden der Aktivitäten.")
    activities = res.json() or []
    keep = [a for a in activities if a.get("type") in ("Run", "Ride", "VirtualRide", "TrailRun")]
    normalized = [_norm_activity(a) for a in keep][:120]
    return JSONResponse(
        {
            "ok": True,
            "imported": len(normalized),
            "matched": 0,
            "activities": normalized,
            "message": "Aktivitäten geladen.",
        },
        status_code=200,
    )


@app.post("/strava/disconnect")
def strava_disconnect(body: SyncBody, authorization: str | None = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authorization fehlt.")
    claims = verify_supabase_jwt(authorization[7:].strip())
    uid = claims.get("sub")
    req_uid = body.user_id or uid
    if req_uid != uid:
        raise HTTPException(403, "user_id passt nicht zur Session.")
    _delete_token(uid)
    return {"ok": True}


@app.get("/strava/webhook")
def strava_webhook_verify(
    hub_mode: str = Query(default="", alias="hub.mode"),
    hub_verify_token: str = Query(default="", alias="hub.verify_token"),
    hub_challenge: str = Query(default="", alias="hub.challenge"),
):
    if hub_mode != "subscribe":
        raise HTTPException(400, "hub.mode muss subscribe sein.")
    if not STRAVA_WEBHOOK_VERIFY_TOKEN:
        raise HTTPException(500, "STRAVA_WEBHOOK_VERIFY_TOKEN fehlt.")
    if hub_verify_token != STRAVA_WEBHOOK_VERIFY_TOKEN:
        raise HTTPException(403, "verify_token mismatch.")
    return {"hub.challenge": hub_challenge}


@app.post("/strava/webhook")
def strava_webhook_event(payload: Any):
    if not payload:
        raise HTTPException(400, "Empty webhook payload.")
    events: list[dict[str, Any]]
    if isinstance(payload, list):
        events = [e for e in payload if isinstance(e, dict)]
    else:
        events = [payload]
    for event in events:
        _persist_webhook_event(event)
    return {"ok": True, "received": len(events)}
