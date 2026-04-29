FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir pytest==9.0.3

COPY . .

RUN chmod +x /app/scripts/validate.sh

ENTRYPOINT ["/app/scripts/validate.sh"]
