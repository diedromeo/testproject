# Use Python 3.12 (for Django 6 support)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install deps
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy code
COPY . /app/

# Static folder
RUN mkdir -p /app/staticfiles

# Expose port
EXPOSE 8000

# Start app (safe version)
CMD bash -c "python manage.py migrate --noinput && gunicorn threat_intel.wsgi:application --bind 0.0.0.0:${PORT:-8000}"
