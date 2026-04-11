"""
Strivon Garmin Sync API — FastAPI
==================================
POST /sync  (Authorization: Bearer <Supabase access_token>)

Env:
  SUPABASE_JWT_SECRET  — Legacy JWT Secret (HS256). Bei neuen «JWT Signing Keys» (ES256/RS256)
                         wird automatisch JWKS unter der URL aus dem Token-Issuer genutzt —
                         Secret kann trotzdem gesetzt bleiben (wird für HS256 genutzt).
  ALLOWED_ORIGINS      — Komma-getrennte Origins für CORS, z.B.
                         https://dein-org.github.io,http://localhost:8080
                         Leer = * (nur für lokale Tests)
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from garmin_engine import sync_workouts_to_garmin

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("strivon-api")

app = FastAPI(title="Strivon Garmin Sync", version="1.0.0")


def _cors_origins() -> list[str]:
    """
    Browser sendet Origin ohne Pfad und ohne Slash am Ende.
    ALLOWED_ORIGINS darf z.B. sein: https://user.github.io,https://user.github.io/Striven
    -> wir normalisieren: nur Schema+Host+Port (Pfad entfernen), kein trailing slash.
    """
    raw = (os.environ.get("ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return ["*"]
    out: list[str] = []
    for o in raw.split(","):
        s = o.strip().rstrip("/")
        if not s:
            continue
        try:
            p = urlparse(s if "://" in s else "https://" + s)
            if p.scheme and p.netloc:
                origin = f"{p.scheme}://{p.netloc}"
                if origin not in out:
                    out.append(origin)
        except Exception:
            if s not in out:
                out.append(s)
    return out if out else ["*"]


_origins = _cors_origins()
log.info("CORS allow_origins: %s", _origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class SyncBody(BaseModel):
    garmin_email: str = Field(..., min_length=3)
    garmin_password: str = Field(default="", max_length=500)
    """Leer erlaubt, wenn garmin_tokens gesetzt ist (OAuth-JSON von garminconnect)."""
    garmin_tokens: str | None = Field(default=None, max_length=600_000)
    workouts: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _need_password_or_tokens(self) -> SyncBody:
        pw = (self.garmin_password or "").strip()
        tok = (self.garmin_tokens or "").strip()
        # Bibliothek: Inline-Token-JSON ist typischerweise >512 Zeichen.
        if len(tok) < 200 and not pw:
            raise ValueError(
                "garmin_password oder garmin_tokens (OAuth-JSON, >ca. 500 Zeichen) erforderlich"
            )
        return self


def _peek_token(token: str) -> dict:
    """Payload ohne Signaturprüfung (nur Issuer/Sub lesen)."""
    return jwt.decode(
        token,
        algorithms=["HS256", "RS256", "ES256"],
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_exp": False,
        },
    )


def verify_supabase_jwt(token: str) -> dict:
    """
    Supabase User Access Token.
    - HS256: SUPABASE_JWT_SECRET (Legacy Secret)
    - ES256 / RS256: JWKS von <iss>/.well-known/jwks.json (neue Supabase Signing Keys)
    """
    LEWAY = 120
    header = jwt.get_unverified_header(token)
    alg = (header.get("alg") or "HS256").upper()

    # ── Asymmetrisch (neue Supabase JWT Signing Keys) ─────────────────────
    if alg in ("ES256", "RS256"):
        try:
            peek = _peek_token(token)
            iss = (peek.get("iss") or "").rstrip("/")
            if not iss.startswith("https://"):
                raise HTTPException(401, "Token ohne gültigen https-Issuer.")
            jwks_url = iss + "/.well-known/jwks.json"
            log.info("JWT verify via JWKS (%s, alg=%s)", jwks_url, alg)
            jwks = PyJWKClient(jwks_url, cache_keys=True)
            signing_key = jwks.get_signing_key_from_jwt(token)
            try:
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[alg],
                    audience="authenticated",
                    leeway=LEWAY,
                )
            except jwt.InvalidAudienceError:
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[alg],
                    options={"verify_aud": False},
                    leeway=LEWAY,
                )
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(401, "Sitzung abgelaufen — bitte neu anmelden.") from exc
        except HTTPException:
            raise
        except Exception as exc:
            log.warning("JWKS-JWT fehlgeschlagen: %s", exc)
            raise HTTPException(
                401,
                "Login-Token konnte nicht geprüft werden (JWKS). Neu anmelden oder Supabase-Projekt prüfen.",
            ) from exc

    # ── Symmetrisch (Legacy JWT Secret) ───────────────────────────────────
    secret = (os.environ.get("SUPABASE_JWT_SECRET") or "").strip().strip('"').strip("'")
    if not secret:
        log.error("SUPABASE_JWT_SECRET is not set (HS256 token)")
        raise HTTPException(
            500,
            "Server: SUPABASE_JWT_SECRET fehlt — oder Token nutzt ES256/RS256; dann JWKS muss erreichbar sein.",
        )

    def _decode_hs(**opts):
        return jwt.decode(token, secret, algorithms=["HS256"], leeway=LEWAY, **opts)

    try:
        return _decode_hs(audience="authenticated")
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(401, "Sitzung abgelaufen — bitte neu anmelden.") from exc
    except jwt.InvalidTokenError as first_err:
        try:
            return _decode_hs(options={"verify_aud": False})
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(401, "Sitzung abgelaufen — bitte neu anmelden.") from exc
        except jwt.InvalidTokenError:
            log.warning("HS256-JWT ungültig: %s", first_err)
            raise HTTPException(
                401,
                "Ungültiges Login-Token. Für HS256: In Render SUPABASE_JWT_SECRET = "
                "«Legacy JWT Secret» (JWT Keys), nicht anon/service_role Key. "
                "Wenn Supabase ES256/RS256 nutzt, sollte der Token automatisch über JWKS laufen — Render-Logs prüfen.",
            ) from first_err


@app.get("/health")
def health():
    return {"status": "ok", "service": "strivon-garmin-sync"}


@app.post("/sync")
def sync(
    body: SyncBody,
    authorization: str | None = Header(None),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authorization: Bearer <Supabase access_token> fehlt")

    token = authorization[7:].strip()
    claims = verify_supabase_jwt(token)
    user_id = claims.get("sub")
    log.info("Sync request for user %s | %d workouts", user_id, len(body.workouts))

    if not body.workouts:
        raise HTTPException(422, "workouts-Liste ist leer")

    try:
        result = sync_workouts_to_garmin(
            body.workouts,
            body.garmin_email,
            body.garmin_password,
            garmin_tokens=body.garmin_tokens,
        )
    except RuntimeError as exc:
        raise HTTPException(401, str(exc)) from exc
    except Exception as exc:
        log.exception("Sync failed")
        raise HTTPException(500, f"Garmin-Sync fehlgeschlagen: {exc}") from exc

    code = 200 if result.get("ok") else 207
    return JSONResponse(content=result, status_code=code)
