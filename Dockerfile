# Use Python 3.11 slim image for security and size optimization
FROM python:3.11-slim

# Set environment variables for security and performance
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Create non-root user for security
RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/bash --create-home app

# Install system dependencies and security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        build-essential \
        libpq-dev \
        curl \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /home/app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies as root, then switch to app user
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories with proper permissions
RUN mkdir -p logs media staticfiles && \
    chown -R app:app /home/app

# Switch to non-root user
USER app

# Copy application code
COPY --chown=app:app . .

# Create additional directories for app user
RUN mkdir -p /home/app/temp && \
    chmod 700 /home/app/temp

# Collect static files
RUN python manage.py collectstatic --noinput --settings=finops_dashboard.settings

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# Expose port
EXPOSE 8000

# Security: Run with read-only root filesystem
# The container runtime should mount /tmp and other writable directories

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "sync", "--worker-connections", "1000", "--max-requests", "1000", "--max-requests-jitter", "100", "--timeout", "30", "--keepalive", "2", "--access-logfile", "-", "--error-logfile", "-", "finops_dashboard.wsgi:application"]
