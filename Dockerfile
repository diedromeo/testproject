# Use Python 3.12 (supports Django 5+ & future safe)
FROM python:3.12-slim

# Environment settings
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project code
COPY . /app/

# Create static directory
RUN mkdir -p /app/staticfiles

# Expose port (Railway uses PORT env variable)
EXPOSE 8000

# Run everything safely at runtime
CMD bash -c "\
python manage.py collectstatic --noinput && \
python manage.py migrate --noinput && \
gunicorn threat_intel.wsgi:application --bind 0.0.0.0:${PORT:-8000}\
"
