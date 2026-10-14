FROM python:3.11-slim

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install dependencies first for caching
COPY requirements.txt ./backend/
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy the rest of the backend application code
COPY . ./backend/

# Expose the FastAPI port
EXPOSE 8000

# Start server from workspace with package context
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
