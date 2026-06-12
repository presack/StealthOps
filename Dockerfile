FROM python:3.12-slim

WORKDIR /app

# gcc is needed to compile some pip packages on certain architectures
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    tor \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

COPY . .

# Cloud mode always on inside the container.
ENV CLOUD_MODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
# Cache lives in the mounted volume so it survives restarts.
ENV CACHE_PATH=/data/cache/stealthops.db

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "main.py", "--web", "--host", "0.0.0.0", "--port", "8000"]
