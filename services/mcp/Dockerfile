FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY services/mcp/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

COPY shared/ shared/
COPY services/api/app/ app/
COPY services/mcp/ mcp/

ENV PYTHONPATH=/app

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/tools')" || exit 1

CMD ["uvicorn", "mcp.server:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1"]
