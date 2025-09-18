# Minimal Dockerfile for HelpDesk Flask app
FROM python:3.13-slim

# Environment settings
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

# Workdir
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app

# Ensure uploads dir exists (used by the app)
RUN mkdir -p /app/uploads

# Expose Gunicorn port
EXPOSE 8000

# Run as non-root for security
RUN groupadd -g 10001 app && useradd -u 10000 -g app -s /sbin/nologin -m app \
    && chown -R app:app /app
USER app

# Default command: run with Gunicorn (robust logging/timeouts)
# app:app -> module:file-variable where Flask instance is defined in app.py
CMD ["gunicorn", "-w", "3", "-k", "gthread", "--threads", "2", "--timeout", "60", "--graceful-timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "-b", "0.0.0.0:8000", "app:app"]