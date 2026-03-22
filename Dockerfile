# Use an official Python runtime as a parent image
FROM python:3.11-slim-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /app

# Install system dependencies required for Django and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the project code into the container
COPY . /app/

# Create a directory for static files
RUN mkdir -p /app/staticfiles

# Run collectstatic during the build phase
RUN python manage.py collectstatic --noinput

# Expose the standard port
EXPOSE 8000

# The CMD includes everything required for booting up the application on Render:
# 1. Run migrations
# 2. Boot Gunicorn using the ASGI or WSGI app
# Note: Render provides the PORT environment variable.
CMD python manage.py migrate --noinput && gunicorn threat_intel.wsgi:application --bind 0.0.0.0:${PORT:-8000}
