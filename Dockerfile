# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies including git
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and poetry.lock (if using poetry) or just pyproject.toml
COPY pyproject.toml .
# If you have a poetry.lock or setup.py, copy it too
# COPY poetry.lock .

# Install pip and upgrade
RUN pip install --no-cache-dir --upgrade pip

# Install python-multipart for file uploads
RUN pip install --no-cache-dir python-multipart

# Install document processing libraries
RUN pip install --no-cache-dir PyPDF2 python-docx

# Install the package and its dependencies
# If using poetry:
# RUN pip install poetry && poetry config virtualenvs.create false && poetry install --no-dev --no-interaction --no-ansi

# If using pip with pyproject.toml:
RUN pip install --no-cache-dir .

# Copy application code AFTER installing dependencies
COPY . .

# Install in editable mode with all dependencies
RUN pip install --no-cache-dir -e .

# Create directory for temporary files
RUN mkdir -p /tmp/code_review_temp && chmod 777 /tmp/code_review_temp

# Expose port (Azure Web Apps uses PORT environment variable)
EXPOSE 8004

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8004/health')"

# Run the application with uvicorn
# Azure Web Apps will use the PORT environment variable
# Make sure the module path matches your project structure
CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8004}"]