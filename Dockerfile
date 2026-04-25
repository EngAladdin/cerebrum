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

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8002}/healthz || exit 1

# service.py عنده Redis consumer جوّاه — مش محتاج ملف تاني
CMD ["sh", "-c", "uvicorn service:app --host 0.0.0.0 --port ${PORT:-8002} --log-level info"]
