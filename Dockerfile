FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip

# If these are already in pyproject deps, remove this line
RUN pip install --no-cache-dir python-multipart PyPDF2 python-docx

# Copy the rest of the code
COPY . .

# ✅ Install your app once, with extras
RUN pip install --no-cache-dir -e ".[dev,security]"

RUN mkdir -p /tmp/code_review_temp && chmod 777 /tmp/code_review_temp

EXPOSE 8004

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Recommended: let Azure do health checks instead of Docker HEALTHCHECK
CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8004}"]
