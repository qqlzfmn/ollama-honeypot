FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HONEYPOT_LOG_PATH=/data/events.jsonl

WORKDIR /app

COPY src/ /app/src/
COPY scripts/ /app/scripts/

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data \
    && chown honeypot:honeypot /data

USER honeypot

EXPOSE 11434

ENTRYPOINT ["python", "-m", "honeypot"]
