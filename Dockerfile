FROM python:3.11-slim

WORKDIR /app

# Installera systempaket som behövs
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    python3-dev \
    build-essential \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Kopiera hela app-mappen från build context till /app i imagen
COPY app/ .

# Installera requirements från /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# app.py och __init__.py kopierades också med föregående COPY

# Exponera porten som appen körs på
EXPOSE 8000

# Hälsokontroll
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# Kör applikationen från /app/app.py
CMD ["python", "app.py"]