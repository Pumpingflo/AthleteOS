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

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import date
from typing import Any

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
    0: {"stepTypeId": 3, "stepTypeKey": "interval", "displayOrder": 3},
    1: {"stepTypeId": 4, "stepTypeKey": "recovery", "displayOrder": 4},
    2: {"stepTypeId": 1, "stepTypeKey": "warmup", "displayOrder": 1},
    3: {"stepTypeId": 2, "stepTypeKey": "cooldown", "displayOrder": 2},
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
    "displayOrder": 2,
    "displayable": True,
}

_STROKE_NONE = {"strokeTypeId": 0, "displayOrder": 0}
_EQUIP_NONE = {"equipmentTypeId": 0, "displayOrder": 0}
_PREFERRED_UNIT_METER = {"unitKey": "meter", "factor": 1.0}


# ── Step builder ──────────────────────────────────────────────────────────────

def make_step(
    order: int,
    name: str,
    intensity: int,
    *,
    duration_mins: float | None = None,
    distance_m: float | None = None,
    hr_low: int = 0,
    hr_high: int = 0,
) -> dict:
    """ExecutableStepDTO: Ende nach Zeit (Sekunden) oder Distanz (Meter)."""
    step_type = INTENSITY_STEP_TYPE.get(intensity, INTENSITY_STEP_TYPE[0])
    use_hr = hr_low > 0 and hr_high > 0

    if distance_m is not None and distance_m > 0:
        end_condition = {
            "conditionTypeId": 1,
            "conditionTypeKey": "distance",
            "displayOrder": 2,
            "displayable": True,
        }
        end_val = float(max(1, int(round(distance_m))))
        preferred_unit = dict(_PREFERRED_UNIT_METER)
    elif duration_mins is not None and duration_mins > 0:
        end_condition = {
            "conditionTypeId": 2,
            "conditionTypeKey": "time",
            "displayOrder": 2,
            "displayable": True,
        }
        end_val = float(int(duration_mins * 60))
        preferred_unit = None
    else:
        raise ValueError("make_step: duration_mins oder distance_m nötig")

    return {
        "type": "ExecutableStepDTO",
        "stepOrder": order,
        "stepId": None,
        "stepType": step_type,
        "childStepId": None,
        "description": name,
        "endCondition": end_condition,
        "preferredEndConditionUnit": preferred_unit,
        "endConditionValue": end_val,
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
        "strokeType": dict(_STROKE_NONE),
        "equipmentType": dict(_EQUIP_NONE),
        "category": None,
        "exerciseName": None,
        "workoutProvider": None,
        "providerExerciseSourceId": None,
    }


def _split_distance_parts(total_m: float, fractions: list[float]) -> list[int]:
    t = max(0.0, float(total_m))
    raw = [t * f for f in fractions]
    out = [max(1, int(round(x))) for x in raw]
    diff = int(round(t)) - sum(out)
    if diff != 0:
        out[-1] = max(1, out[-1] + diff)
    return out


def _estimated_workout_secs(steps: list[dict[str, Any]], fallback_mins: float) -> int:
    pace_m_s = 3.33
    acc = 0
    for st in steps:
        ec = st.get("endCondition") or {}
        key = ec.get("conditionTypeKey")
        val = float(st.get("endConditionValue") or 0)
        if key == "distance":
            acc += int(max(val, 1) / pace_m_s)
        else:
            acc += int(val)
    return max(acc, int(max(fallback_mins, 5) * 60))


# ── Workout type → structured steps ──────────────────────────────────────────

def build_steps(wo: dict) -> list:
    """
    Mirror api/garmin/garmin_engine.py (Zeit wenn keine Distanz, sonst Meter).
    """
    steps: list = []
    wtype = wo.get("type", "")
    dur = float(wo.get("durationMinutes") or 45)
    dist_m = float(wo.get("distanceMeters") or 0)
    use_dist = dist_m > 200

    def s_time(name: str, mins: float, hl: int, hh: int, intensity: int) -> None:
        steps.append(
            make_step(
                len(steps) + 1,
                name,
                intensity,
                duration_mins=mins,
                hr_low=hl,
                hr_high=hh,
            )
        )

    def s_dist(name: str, meters: int, hl: int, hh: int, intensity: int) -> None:
        steps.append(
            make_step(
                len(steps) + 1,
                name,
                intensity,
                distance_m=float(meters),
                hr_low=hl,
                hr_high=hh,
            )
        )

    if wtype in ("aerobic", "zone2"):
        if use_dist:
            warmup = min(10, int(dur * 0.15))
            main = dur - warmup - 5
            total_t = max(dur, 1.0)
            w_m, m_m, c_m = _split_distance_parts(
                dist_m, [warmup / total_t, main / total_t, 5.0 / total_t]
            )
            s_dist("Einlaufen", w_m, 130, 144, 2)
            s_dist("Zone 2", m_m, 144, 159, 0)
            s_dist("Auslaufen", c_m, 0, 0, 3)
        else:
            warmup = min(10, int(dur * 0.15))
            main = dur - warmup - 5
            s_time("Einlaufen", warmup, 130, 144, 2)
            s_time("Zone 2", main, 144, 159, 0)
            s_time("Auslaufen", 5, 0, 0, 3)

    elif wtype == "longrun":
        if use_dist:
            fr = [10 / 80, 30 / 80, 20 / 80, 15 / 80, 5 / 80]
            d0, d1, d2, d3, d4 = _split_distance_parts(dist_m, fr)
            s_dist("Einlaufen", d0, 130, 145, 2)
            s_dist("Easy Zone 2", d1, 144, 159, 0)
            s_dist("Steady State", d2, 155, 167, 0)
            s_dist("Progressiv", d3, 165, 176, 0)
            s_dist("Auslaufen", d4, 0, 0, 3)
        else:
            s_time("Einlaufen", 10, 130, 145, 2)
            s_time("Easy Zone 2", 30, 144, 159, 0)
            s_time("Steady State", 20, 155, 167, 0)
            s_time("Progressiv", 15, 165, 176, 0)
            s_time("Auslaufen", 5, 0, 0, 3)

    elif wtype == "tempo":
        s_time("Einlaufen", 15, 130, 150, 2)
        s_time("Tempo 1", 12, 170, 178, 0)
        s_time("Erholung 1", 3, 130, 150, 1)
        s_time("Tempo 2", 12, 170, 178, 0)
        s_time("Erholung 2", 3, 130, 150, 1)
        s_time("Auslaufen", 10, 0, 0, 3)

    elif wtype == "vo2max":
        s_time("Einlaufen", 15, 130, 155, 2)
        for i in range(1, 6):
            s_time(f"Intervall {i}", 4, 183, 189, 0)
            if i < 5:
                s_time(f"Erholung {i}", 3, 130, 155, 1)
        s_time("Auslaufen", 10, 0, 0, 3)

    elif wtype == "race":
        if use_dist:
            warmup = min(10, int(dur * 0.15))
            race_t = int(dur * 0.70)
            sprint = max(1, dur - warmup - race_t)
            total_t = max(float(warmup + race_t + sprint), 1.0)
            w_m, r_m, sp_m = _split_distance_parts(
                dist_m, [warmup / total_t, race_t / total_t, sprint / total_t]
            )
            s_dist("Einlaufen", w_m, 140, 160, 2)
            s_dist("Renntempo", r_m, 178, 189, 0)
            s_dist("Endspurt", sp_m, 183, 199, 0)
        else:
            warmup = min(10, int(dur * 0.15))
            race_t = int(dur * 0.70)
            sprint = max(1, dur - warmup - race_t)
            s_time("Einlaufen", warmup, 140, 160, 2)
            s_time("Renntempo", race_t, 178, 189, 0)
            s_time("Endspurt", sprint, 183, 199, 0)

    else:
        if use_dist:
            warmup = 10
            main = max(5, dur - 15)
            total_t = max(dur, 1.0)
            w_m, m_m, c_m = _split_distance_parts(
                dist_m, [warmup / total_t, main / total_t, 5.0 / total_t]
            )
            s_dist("Einlaufen", w_m, 130, 145, 2)
            s_dist("Hauptteil", m_m, 144, 170, 0)
            s_dist("Auslaufen", c_m, 0, 0, 3)
        else:
            warmup = 10
            main = max(5, dur - 15)
            s_time("Einlaufen", warmup, 130, 145, 2)
            s_time("Hauptteil", main, 144, 170, 0)
            s_time("Auslaufen", 5, 0, 0, 3)

    return steps


# ── Strivon workout → Garmin Connect payload ──────────────────────────────────

def to_garmin_workout(wo: dict) -> dict:
    """Convert a Strivon workout dict to a Garmin Connect API payload."""
    sport_key = wo.get("sport", "run")
    sport = SPORT_MAP.get(sport_key, SPORT_MAP["run"])
    steps = build_steps(wo)
    dur_fb = float(wo.get("durationMinutes") or 45)
    total_secs = _estimated_workout_secs(steps, dur_fb)
    dist_m = float(wo.get("distanceMeters") or 0)
    est_dist = int(round(dist_m)) if dist_m > 0 else None
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
        "estimatedDistanceInMeters": est_dist,
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
