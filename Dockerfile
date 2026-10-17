# Multi-Stage Production Build for VIGIL (Single-Container Full-Stack)
# Stage 1: Compile Vite + React TypeScript Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Python Runtime Gateway & VIGIL Pipeline
FROM python:3.11-slim
WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend, centralized thresholds, and evidence
COPY backend/ ./backend/
COPY config/ ./config/
COPY evidence/ ./evidence/

# Copy compiled frontend from Stage 1 into frontend/dist
COPY --from=frontend-builder /app/dist ./frontend/dist

# Expose application port ($PORT is dynamically injected by Railway / Render / Fly.io)
ENV PORT=8000
EXPOSE 8000

# Launch Uvicorn on $PORT
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
