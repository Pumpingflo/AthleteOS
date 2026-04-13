# Strivon Strava Sync API

FastAPI-Service für Strava OAuth, Aktivitätsabruf und Webhook-Ingestion.

## Endpoints

- `GET /health`
- `GET /strava/oauth/start?state=...&user_id=...&return_url=...`
- `GET /strava/oauth/callback`
- `POST /strava/sync` (Bearer Supabase Access Token)
- `POST /strava/disconnect` (Bearer Supabase Access Token)
- `GET /strava/webhook` (Strava Subscription Verify)
- `POST /strava/webhook` (Webhook Events)

## Env Vars

- `STRAVA_CLIENT_ID`
- `STRAVA_CLIENT_SECRET`
- `STRAVA_REDIRECT_URI` (zeigt auf `/strava/oauth/callback` dieses Services)
- `STRAVA_SCOPE` (optional, default `read,activity:read_all`)
- `SUPABASE_JWT_SECRET` (für HS256 Supabase Tokens)
- `ALLOWED_ORIGINS` (CORS, z. B. `https://deine-app.com`)
- `SUPABASE_URL` (optional, für REST-Tokenstore/Webhookstore)
- `SUPABASE_SERVICE_ROLE_KEY` (optional, für REST-Tokenstore/Webhookstore)
- `STRAVA_TOKENS_TABLE` (optional, default `strava_tokens`)
- `STRAVA_WEBHOOK_EVENTS_TABLE` (optional, default `strava_webhook_events`)
- `STRAVA_WEBHOOK_VERIFY_TOKEN` (für `GET /strava/webhook`)
- `STRAVA_TOKEN_DB_PATH` (SQLite fallback, default `./strava_tokens.db`)
- `STRAVA_WEBHOOK_LOG_PATH` (Datei fallback, default `./strava_webhook_events.jsonl`)

## Token-Persistenz

Token-Speicherung läuft priorisiert über Supabase REST, falls gesetzt:

- `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` vorhanden -> Upsert/Load/Delete in `STRAVA_TOKENS_TABLE`
- sonst SQLite-Fallback (`STRAVA_TOKEN_DB_PATH`)

Empfohlene Spalten für `strava_tokens`:

- `user_id text primary key`
- `access_token text not null`
- `refresh_token text not null`
- `expires_at double precision not null`
- `updated_at timestamptz not null`

Hinweis: Für Production Tokens verschlüsselt speichern (DB/KMS/pgcrypto).

## Webhook-Ready

- `GET /strava/webhook` beantwortet Strava Challenge-Verifikation.
- `POST /strava/webhook` persistiert Events:
  - bevorzugt in `STRAVA_WEBHOOK_EVENTS_TABLE` (Supabase REST)
  - fallback als JSONL-Datei (`STRAVA_WEBHOOK_LOG_PATH`)

## Nächster Schritt (Production)

- Dedizierte Migrationen + RLS für Token/Event-Tabellen
- Delta-Worker auf Basis Webhook Events (statt nur Pull)
- Feineres Plan-Matching (Session-Type + Intensitätslogik)
