"""
Garmin Connect workout builder + sync (shared logic for API / CLI).
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any

log = logging.getLogger("strivon-garmin-engine")

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


def make_step(
    order: int,
    name: str,
    duration_mins: float,
    intensity: int,
    hr_low: int = 0,
    hr_high: int = 0,
) -> dict:
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


def build_steps(wo: dict) -> list:
    steps: list = []
    wtype = wo.get("type", "")
    dur = float(wo.get("durationMinutes") or 45)

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


def to_garmin_workout(wo: dict) -> dict:
    sport_key = wo.get("sport", "run")
    sport = SPORT_MAP.get(sport_key, SPORT_MAP["run"])
    steps = build_steps(wo)
    total_secs = sum(st["endConditionValue"] for st in steps)

    return {
        "workoutId": None,
        "ownerId": None,
        "workoutName": (wo.get("name") or "Strivon Workout")[:50],
        "description": (wo.get("description") or "")[:512],
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
                "sportType": {
                    "sportTypeId": sport["typeId"],
                    "sportTypeKey": sport["typeKey"],
                },
                "workoutSteps": steps,
            }
        ],
    }


def sync_workouts_to_garmin(
    workouts: list[dict[str, Any]],
    email: str,
    password: str,
) -> dict[str, Any]:
    """
    Log into Garmin Connect and upload + schedule each upcoming workout.

    Returns a JSON-serialisable summary dict.
    """
    from garminconnect import (
        Garmin,
        GarminConnectAuthenticationError,
        GarminConnectTooManyRequestsError,
    )

    today = date.today().isoformat()
    upcoming = [w for w in workouts if (w.get("date") or "") >= today]

    log.info("Received %d workouts | %d upcoming (≥ %s)", len(workouts), len(upcoming), today)

    if not upcoming:
        return {
            "ok": True,
            "success": [],
            "skipped": [],
            "failed": [],
            "message": "Keine zukünftigen Workouts im Payload.",
        }

    log.info("Garmin login for %s***", email[:3] if email else "")
    try:
        api = Garmin(email.strip(), password)
        api.login()
    except GarminConnectAuthenticationError as exc:
        log.error("Garmin auth failed: %s", exc)
        raise RuntimeError(
            "Garmin-Anmeldung fehlgeschlagen (E-Mail/Passwort oder 2FA). "
            "Für Automation muss 2FA am Garmin-Konto deaktiviert sein."
        ) from exc

    success, skipped, failed = [], [], []

    for wo in upcoming:
        name = wo.get("name") or "Workout"
        wo_date = wo.get("date") or ""
        sport = wo.get("sport") or "run"
        wtype = wo.get("type") or ""

        if sport in ("rest", "workout") or wtype == "rest":
            skipped.append({"date": wo_date, "name": name, "reason": "Ruhetag/Kraft"})
            continue
        if sport not in SPORT_MAP:
            skipped.append({"date": wo_date, "name": name, "reason": f"Sport '{sport}'"})
            continue

        try:
            garmin_wo = to_garmin_workout(wo)
            result = api.upload_workout(garmin_wo)
            workout_id = result.get("workoutId")
            if not workout_id:
                raise ValueError(f"Keine workoutId in Antwort: {result}")
            if wo_date:
                api.schedule_workout(workout_id, wo_date)
            success.append({"date": wo_date, "name": name, "id": workout_id})
        except GarminConnectTooManyRequestsError:
            failed.append({"date": wo_date, "name": name, "error": "Rate limit"})
            break
        except Exception as exc:
            log.exception("Workout failed: %s", name)
            failed.append({"date": wo_date, "name": name, "error": str(exc)})

    ok = len(failed) == 0
    msg = (
        f"{len(success)} ok, {len(skipped)} übersprungen, {len(failed)} Fehler. "
        "Garmin Connect App öffnen und Uhr synchronisieren."
    )
    return {
        "ok": ok,
        "success": success,
        "skipped": skipped,
        "failed": failed,
        "message": msg,
    }
