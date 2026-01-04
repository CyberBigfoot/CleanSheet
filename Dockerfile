# Dockerfile for main web service
FROM python:3.11-slim

# Install Docker CLI to spawn worker containers
RUN apt-get update && apt-get install -y \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p /app/uploads /app/output

EXPOSE 10400

CMD ["python", "app.py"]