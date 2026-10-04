FROM python:3.11-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables procps openresolv ca-certificates && \
    (apt-get install -y --no-install-recommends wireguard-go || true) && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000 DATA_DIR=/app/data
EXPOSE 8000
EXPOSE 51820/udp
CMD ["python", "app.py"]
