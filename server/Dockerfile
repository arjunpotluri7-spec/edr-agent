# EDR Agent server image. Build from the repository root (it needs rules/ too):
#   docker build -f server/Dockerfile -t edr-server .
FROM python:3.12.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 edr && \
    useradd --system --uid 10001 --gid edr --home-dir /app --shell /usr/sbin/nologin edr

WORKDIR /app
COPY server/requirements.txt server/requirements.txt
# Every package, transitive ones included, is pinned in requirements.txt.
RUN pip install --no-deps -r server/requirements.txt

COPY rules/ rules/
COPY server/alembic.ini server/alembic.ini
COPY server/migrations/ server/migrations/
COPY server/src/ server/src/

ENV PYTHONPATH=/app/server/src \
    EDR_RULES_DIR=/app/rules/detections \
    EDR_SCORING_FILE=/app/rules/scoring.yaml

USER edr
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]
# 0.0.0.0 inside the container only; docker-compose.yml publishes the port on 127.0.0.1.
CMD ["python", "-m", "edr_server", "serve", "--host", "0.0.0.0", "--port", "8000"]
