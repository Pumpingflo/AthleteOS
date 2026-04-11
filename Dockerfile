# Garmin Sync API — Render baut vom Repo-Root (Root Directory in Render: leer).
# Quellcode bleibt in api/garmin/; hier nur die Pfade für COPY.
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY api/garmin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/garmin/garmin_engine.py api/garmin/main.py ./

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
