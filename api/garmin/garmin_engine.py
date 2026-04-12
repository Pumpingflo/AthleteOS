"""
Garmin Connect workout builder + sync (shared logic for API / CLI).
"""
from __future__ import annotations

import logging
import os
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
    # displayOrder muss zu stepTypeId passen (vgl. Garmin sample_workout.json) — sonst kann Connect die Schritte falsch interpretieren (z. B. „Lap“).
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
# Ohne Einheit kann Connect Distanz-Schritte wie „offen/Lap“ behandeln (s. Garmin-Swim-Fixes in Community-Clients).
_PREFERRED_UNIT_METER = {"unitKey": "meter", "factor": 1.0}


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
    """Schritt mit Ende nach Zeit (Sekunden) oder Distanz (Meter)."""
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
    """Teilt total_m auf Anteile; Rundungsrest aufs letzte Segment."""
    t = max(0.0, float(total_m))
    raw = [t * f for f in fractions]
    out = [max(1, int(round(x))) for x in raw]
    diff = int(round(t)) - sum(out)
    if diff != 0:
        out[-1] = max(1, out[-1] + diff)
    return out


def _estimated_workout_secs(steps: list[dict[str, Any]], fallback_mins: float) -> int:
    """Garmin estimatedDurationInSecs: Zeit-Schritte summieren, Distanz grob schätzen."""
    pace_m_s = 3.33  # ~5:00/km
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


def build_steps(wo: dict) -> list:
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
            fr_w = warmup / total_t
            fr_m = main / total_t
            fr_c = 5.0 / total_t
            w_m, m_m, c_m = _split_distance_parts(dist_m, [fr_w, fr_m, fr_c])
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
            # Gleiche Anteile wie bisher (10+30+20+15+5 = 80 min)
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


def to_garmin_workout(wo: dict) -> dict:
    sport_key = wo.get("sport", "run")
    sport = SPORT_MAP.get(sport_key, SPORT_MAP["run"])
    steps = build_steps(wo)
    dur_fb = float(wo.get("durationMinutes") or 45)
    total_secs = _estimated_workout_secs(steps, dur_fb)
    dist_m = float(wo.get("distanceMeters") or 0)
    est_dist = int(round(dist_m)) if dist_m > 0 else None
    # Garmin createWorkout verlangt sportType auf Workout-Root (vgl. garminconnect.BaseWorkout)
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


def sync_workouts_to_garmin(
    workouts: list[dict[str, Any]],
    email: str,
    password: str,
    garmin_tokens: str | None = None,
) -> dict[str, Any]:
    """
    Log into Garmin Connect and upload + schedule each upcoming workout.

    Returns a JSON-serialisable summary dict.
    """
    from garminconnect import (
        Garmin,
        GarminConnectAuthenticationError,
        GarminConnectConnectionError,
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
    tokenstore = (garmin_tokens or os.environ.get("GARMINTOKENS") or "").strip() or None
    try:
        api = Garmin(
            email.strip() or None,
            (password or "").strip() or None,
        )
        api.login(tokenstore=tokenstore)
    except GarminConnectAuthenticationError as exc:
        log.error("Garmin auth failed: %s", exc)
        hint = (
            "Garmin-Anmeldung fehlgeschlagen. Häufige Ursachen: falsches Passwort, "
            "Zwei-Faktor-Auth (ohne Token), oder veraltete garminconnect-Version auf dem Server (neu deployen). "
            "Mit 2FA: optional «OAuth-Token» aus python-garminconnect (lokal einmal login + Token-JSON) in den "
            "Garmin-Einstellungen eintragen, oder 2FA kurz deaktivieren / separates Konto ohne 2FA. "
            f"Technische Meldung: {exc}"
        )
        raise RuntimeError(hint) from exc
    except GarminConnectConnectionError as exc:
        log.error("Garmin connection during login: %s", exc)
        raise RuntimeError(
            "Garmin-Server nicht erreichbar oder Login blockiert (z.B. Rate-Limit, Wartung). "
            f"Details: {exc}"
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
