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

# صحّح الـ HealthCheck - يفحص فقط لو التطبيق شغال (يعطي HTTP 200)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8002}/ || exit 1

# شغل التطبيق
CMD ["sh", "-c", "exec uvicorn service:app --host 0.0.0.0 --port ${PORT:-8002} --log-level info"]
