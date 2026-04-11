#!/usr/bin/env python3
"""
Strivon → Garmin Connect Sync
==============================
Reads WORKOUTS_JSON env var (JSON array dispatched by the Strivon PWA via
GitHub Actions workflow_dispatch), converts each workout to Garmin Connect's
internal structured format, creates it via the garminconnect library, and
schedules it on the Garmin Connect calendar.

Required env vars:
  GARMIN_EMAIL     – Garmin Connect account e-mail
  GARMIN_PASSWORD  – Garmin Connect account password (store in GitHub Secrets!)
  WORKOUTS_JSON    – JSON array of workout objects (passed from PWA)
"""

import json
import logging
import os
import sys
from datetime import date

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("strivon-garmin")

# ── Garmin sport/type maps ────────────────────────────────────────────────────
SPORT_MAP = {
    "run": {
        "sportId": 1,
        "sportName": "running",
        "fullDisplayName": "Running",
        "typeId": 1,
        "typeKey": "running",
    },
    "ride": {
        "sportId": 2,
        "sportName": "cycling",
        "fullDisplayName": "Cycling",
        "typeId": 2,
        "typeKey": "cycling",
    },
}

# Strivon intensity code → Garmin step type
# 0 = active, 1 = rest, 2 = warmup, 3 = cooldown
INTENSITY_STEP_TYPE = {
    0: {"stepTypeId": 3, "stepTypeKey": "interval"},
    1: {"stepTypeId": 4, "stepTypeKey": "rest"},
    2: {"stepTypeId": 1, "stepTypeKey": "warmup"},
    3: {"stepTypeId": 2, "stepTypeKey": "cooldown"},
}

_NO_TARGET = {
    "workoutTargetTypeId": 1,
    "workoutTargetTypeKey": "no.target",
    "displayOrder": 1,
    "displayable": True,
}
_HR_TARGET = {
    "workoutTargetTypeId": 4,
    "workoutTargetTypeKey": "heart.rate.zone",
    "displayOrder": 4,
    "displayable": True,
}


# ── Step builder ──────────────────────────────────────────────────────────────

def make_step(order: int, name: str, duration_mins: float,
              intensity: int, hr_low: int = 0, hr_high: int = 0) -> dict:
    """Return a Garmin Connect ExecutableStepDTO dict."""
    step_type = INTENSITY_STEP_TYPE.get(intensity, INTENSITY_STEP_TYPE[0])
    use_hr = hr_low > 0 and hr_high > 0

    return {
        "type": "ExecutableStepDTO",
        "stepOrder": order,
        "stepId": None,
        "stepType": step_type,
        "childStepId": None,
        "description": name,
        "endCondition": {
            "conditionTypeId": 2,
            "conditionTypeKey": "time",
            "displayOrder": 3,
            "displayable": True,
            "audioFinishSupported": False,
        },
        "preferredEndConditionUnit": None,
        "endConditionValue": int(duration_mins * 60),
        "endConditionCompare": None,
        "endConditionZone": None,
        "targetType": _HR_TARGET if use_hr else _NO_TARGET,
        "targetValueOne": float(hr_low) if use_hr else None,
        "targetValueTwo": float(hr_high) if use_hr else None,
        "zoneNumber": None,
        "secondaryTargetType": None,
        "secondaryTargetValueOne": None,
        "secondaryTargetValueTwo": None,
        "secondaryZoneNumber": None,
        "strokeType": None,
        "equipmentType": None,
        "category": None,
        "exerciseName": None,
        "workoutProvider": None,
        "providerExerciseSourceId": None,
    }


# ── Workout type → structured steps ──────────────────────────────────────────

def build_steps(wo: dict) -> list:
    """
    Mirror the step logic from Strivon's workoutToFitSteps() JS function.
    Returns a list of Garmin step dicts.
    """
    steps = []
    wtype = wo.get("type", "")
    sport = wo.get("sport", "run")
    dur = float(wo.get("durationMinutes") or 45)

    # Convenience: create a step and append it, auto-numbering
    def s(name, mins, hl, hh, intensity):
        steps.append(make_step(len(steps) + 1, name, mins, intensity, hl, hh))

    if wtype in ("aerobic", "zone2"):
        warmup = min(10, int(dur * 0.15))
        main = dur - warmup - 5
        s("Einlaufen", warmup, 130, 144, 2)
        s("Zone 2", main, 144, 159, 0)
        s("Auslaufen", 5, 0, 0, 3)

    elif wtype == "longrun":
        s("Einlaufen", 10, 130, 145, 2)
        s("Easy Zone 2", 30, 144, 159, 0)
        s("Steady State", 20, 155, 167, 0)
        s("Progressiv", 15, 165, 176, 0)
        s("Auslaufen", 5, 0, 0, 3)

    elif wtype == "tempo":
        s("Einlaufen", 15, 130, 150, 2)
        s("Tempo 1", 12, 170, 178, 0)
        s("Erholung 1", 3, 130, 150, 1)
        s("Tempo 2", 12, 170, 178, 0)
        s("Erholung 2", 3, 130, 150, 1)
        s("Auslaufen", 10, 0, 0, 3)

    elif wtype == "vo2max":
        s("Einlaufen", 15, 130, 155, 2)
        for i in range(1, 6):
            s(f"Intervall {i}", 4, 183, 189, 0)
            if i < 5:
                s(f"Erholung {i}", 3, 130, 155, 1)
        s("Auslaufen", 10, 0, 0, 3)

    elif wtype == "race":
        warmup = min(10, int(dur * 0.15))
        race_t = int(dur * 0.70)
        sprint = max(1, dur - warmup - race_t)
        s("Einlaufen", warmup, 140, 160, 2)
        s("Renntempo", race_t, 178, 189, 0)
        s("Endspurt", sprint, 183, 199, 0)

    else:
        warmup = 10
        main = max(5, dur - 15)
        s("Einlaufen", warmup, 130, 145, 2)
        s("Hauptteil", main, 144, 170, 0)
        s("Auslaufen", 5, 0, 0, 3)

    return steps


# ── Strivon workout → Garmin Connect payload ──────────────────────────────────

def to_garmin_workout(wo: dict) -> dict:
    """Convert a Strivon workout dict to a Garmin Connect API payload."""
    sport_key = wo.get("sport", "run")
    sport = SPORT_MAP.get(sport_key, SPORT_MAP["run"])
    steps = build_steps(wo)
    total_secs = sum(st["endConditionValue"] for st in steps)
    sport_type = {
        "sportTypeId": sport["typeId"],
        "sportTypeKey": sport["typeKey"],
        "displayOrder": sport["typeId"],
    }

    return {
        "workoutId": None,
        "ownerId": None,
        "workoutName": (wo.get("name") or "Strivon Workout")[:50],
        "description": (wo.get("description") or "")[:512],
        "sportType": sport_type,
        "sport": {
            "sportId": sport["sportId"],
            "sportName": sport["sportName"],
            "displayOrder": sport["sportId"],
            "fullDisplayName": sport["fullDisplayName"],
        },
        "subSport": None,
        "estimatedDurationInSecs": total_secs,
        "estimatedDistanceInMeters": None,
        "averageHR": None,
        "maxHR": None,
        "workoutProvider": "Strivon",
        "atpPlanId": None,
        "workoutSourceId": None,
        "author": None,
        "trainingPlanId": None,
        "locale": None,
        "poolLength": None,
        "poolLengthUnit": None,
        "workoutSegments": [
            {
                "segmentOrder": 1,
                "workoutSegmentId": None,
                "workoutId": None,
                "sportType": dict(sport_type),
                "workoutSteps": steps,
            }
        ],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # 1. Read env vars
    email    = os.environ.get("GARMIN_EMAIL", "").strip()
    password = os.environ.get("GARMIN_PASSWORD", "").strip()
    raw_json = os.environ.get("WORKOUTS_JSON", "").strip()

    if not email or not password:
        log.error("GARMIN_EMAIL and GARMIN_PASSWORD must be set in GitHub Secrets.")
        sys.exit(1)
    if not raw_json:
        log.error("WORKOUTS_JSON is empty – nothing to sync.")
        sys.exit(1)

    # 2. Parse workout list
    try:
        workouts = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error(f"Invalid JSON in WORKOUTS_JSON: {exc}")
        sys.exit(1)

    if not isinstance(workouts, list):
        log.error("WORKOUTS_JSON must be a JSON array.")
        sys.exit(1)

    today = date.today().isoformat()
    upcoming = [w for w in workouts if (w.get("date") or "") >= today]
    log.info(f"Received {len(workouts)} workouts | {len(upcoming)} are upcoming (≥ {today})")

    if not upcoming:
        log.warning("No upcoming workouts to sync. Exiting.")
        sys.exit(0)

    # 3. Authenticate with Garmin Connect
    try:
        from garminconnect import (
            Garmin,
            GarminConnectAuthenticationError,
            GarminConnectTooManyRequestsError,
        )
    except ImportError:
        log.error("garminconnect library not installed. Add it to requirements.")
        sys.exit(1)

    log.info(f"Authenticating with Garmin Connect ({email[:4]}***)")
    try:
        api = Garmin(email, password)
        api.login()
        log.info("✓ Login successful")
    except GarminConnectAuthenticationError as exc:
        log.error(f"Authentication failed: {exc}")
        log.error("→ Check GARMIN_EMAIL / GARMIN_PASSWORD secrets.")
        log.error("→ If you use 2-Factor-Auth: disable it for this account")
        log.error("  or create a dedicated Garmin account without 2FA.")
        sys.exit(1)
    except Exception as exc:
        log.error(f"Unexpected login error: {exc}")
        sys.exit(1)

    # 4. Sync each workout
    success, skipped, failed = [], [], []

    for wo in upcoming:
        name    = wo.get("name") or "Workout"
        wo_date = wo.get("date") or ""
        sport   = wo.get("sport") or "run"
        wtype   = wo.get("type") or ""

        # Skip rest days and unsupported sports (strength etc.)
        if sport in ("rest", "workout") or wtype == "rest":
            reason = "Ruhetag/Kraft"
            log.info(f"  ⏭  [{wo_date}] {name!r:35s} → übersprungen ({reason})")
            skipped.append({"date": wo_date, "name": name, "reason": reason})
            continue

        if sport not in SPORT_MAP:
            reason = f"Sport '{sport}' nicht unterstützt"
            log.info(f"  ⏭  [{wo_date}] {name!r:35s} → übersprungen ({reason})")
            skipped.append({"date": wo_date, "name": name, "reason": reason})
            continue

        log.info(f"  →  [{wo_date}] {name!r:35s}  ({sport}/{wtype}, {wo.get('durationMinutes', '?')}min)")

        try:
            garmin_wo = to_garmin_workout(wo)
            result    = api.upload_workout(garmin_wo)
            workout_id = result.get("workoutId")

            if not workout_id:
                raise ValueError(f"Garmin returned no workoutId: {result}")

            log.info(f"     ✓ Workout erstellt  (ID: {workout_id})")

            # Schedule workout to the calendar
            if wo_date:
                api.schedule_workout(workout_id, wo_date)
                log.info(f"     ✓ Im Kalender terminiert für {wo_date}")

            success.append({"date": wo_date, "name": name, "id": workout_id})

        except GarminConnectTooManyRequestsError:
            log.error("     ✗ Rate-Limit erreicht – Sync wird abgebrochen.")
            failed.append({"date": wo_date, "name": name, "error": "Rate limit"})
            break
        except Exception as exc:
            log.error(f"     ✗ Fehler: {exc}")
            failed.append({"date": wo_date, "name": name, "error": str(exc)})

    # 5. Print summary
    log.info("")
    log.info("╔══════════════════════════════════════════════╗")
    log.info("║           STRIVON → GARMIN  SYNC             ║")
    log.info("╠══════════════════════════════════════════════╣")
    log.info(f"║  ✓  Erfolgreich:   {len(success):>3} Workouts              ║")
    log.info(f"║  ⏭   Übersprungen: {len(skipped):>3} (Ruhe/Kraft/n.u.)     ║")
    log.info(f"║  ✗  Fehler:        {len(failed):>3}                         ║")
    log.info("╚══════════════════════════════════════════════╝")

    if success:
        log.info("\nErfolgreich synchronisierte Workouts:")
        for item in success:
            log.info(f"  ✓ [{item['date']}] {item['name']}  (Garmin ID: {item['id']})")

    if failed:
        log.info("\nFehlgeschlagene Workouts:")
        for item in failed:
            log.info(f"  ✗ [{item['date']}] {item['name']}  → {item['error']}")

    log.info("")

    if failed:
        log.error("Einige Workouts konnten nicht synchronisiert werden.")
        sys.exit(1)

    log.info("✅ Sync abgeschlossen. Öffne die Garmin Connect App und synchronisiere deine Uhr.")


if __name__ == "__main__":
    main()
