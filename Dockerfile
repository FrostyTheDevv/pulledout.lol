# Use Python 3.13 slim image
FROM python:3.13-slim

# Install system dependencies for Chrome/Chromium
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create volume mount point for database persistence
RUN mkdir -p /data && chmod 777 /data

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (Railway will set PORT env var)
EXPOSE 8080

# Run gunicorn (use shell form to allow variable expansion)
CMD ["sh", "-c", "gunicorn web_server:app --bind 0.0.0.0:${PORT:-8080} --workers 4 --timeout 120"]
