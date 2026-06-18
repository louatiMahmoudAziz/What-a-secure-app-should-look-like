FROM python:3.12-slim AS base

# Non-root user (Definition of Done: container runs non-root)
RUN groupadd -r app && useradd -r -g app -d /app app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY alembic.ini .

RUN mkdir -p /tmp/steg-artifacts && chown app:app /tmp/steg-artifacts
USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
