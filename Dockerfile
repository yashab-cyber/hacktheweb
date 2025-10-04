FROM python:3.11-slim

LABEL maintainer="YashAB Cyber Security <support@hacktheweb.io>"
LABEL description="HackTheWeb - AI-Powered Web Application Penetration Testing Tool"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    nmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install HackTheWeb
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /app/config /app/data /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Entry point
ENTRYPOINT ["hacktheweb"]
CMD ["--help"]
