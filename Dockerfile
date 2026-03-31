# Use Python 3.13 slim image
FROM python:3.13-slim

# Install system dependencies for Chrome/Chromium and Node.js
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    chromium \
    chromium-driver \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create volume mount point for database persistence
RUN mkdir -p /data && chmod 777 /data

# Copy package files for frontend
COPY frontend/package*.json ./frontend/

# Install frontend dependencies
RUN cd frontend && npm ci --legacy-peer-deps

# Copy frontend source and build configuration
COPY frontend/src ./frontend/src
COPY frontend/public ./frontend/public
COPY frontend/index.html ./frontend/index.html
COPY frontend/vite.config.ts ./frontend/vite.config.ts
COPY frontend/tsconfig.json ./frontend/tsconfig.json
COPY frontend/tailwind.config.js ./frontend/tailwind.config.js
COPY frontend/postcss.config.js ./frontend/postcss.config.js
COPY frontend/.eslintrc.json ./frontend/.eslintrc.json

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code (excluding node_modules and dist via .dockerignore)
COPY . .

# Build frontend (outputs to static/dist as configured in vite.config.ts)
# Set NODE_OPTIONS to increase memory limit for build
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN cd frontend && npm run build 2>&1 || (echo "Build failed!" && cat /tmp/build.log && exit 1)

# Verify build output
RUN ls -la static/dist || echo "Build output directory not found!"

# Expose port (Railway will set PORT env var)
EXPOSE 8080

# Run start script which launches both web server and Discord bot
CMD ["python", "start.py"]
