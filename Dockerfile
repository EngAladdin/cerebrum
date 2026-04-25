FROM python:3.11-slim
LABEL service="cerebrum"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -s /bin/false cerebrum && chown -R cerebrum:cerebrum /app
USER cerebrum

EXPOSE ${PORT:-8002}

# تأكد من وجود /healthz في service.py
# أو غيّر المسار إلى /health أو / حسب المتاح عندك
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8002}/health || exit 1

# شغل الـ service مع إعادة تشغيل تلقائي لو فشل
CMD ["sh", "-c", "exec uvicorn service:app --host 0.0.0.0 --port ${PORT:-8002} --log-level info"]
