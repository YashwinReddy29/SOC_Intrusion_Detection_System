FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . .
RUN PYTHONPATH=. python scripts/run_ml_experiment.py

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    DATABASE_URL=sqlite:////app/runtime/soc.db \
    REPORT_DIR=/app/runtime

WORKDIR /app

RUN groupadd --system soc && \
    useradd --system --gid soc --home-dir /nonexistent --shell /usr/sbin/nologin soc

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

RUN mkdir -p /app/runtime && chown -R soc:soc /app/runtime

USER soc

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/ready', timeout=3)"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "--timeout", "30", "run:app"]
