# Multi-stage build for smaller final image
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for better caching
COPY pyproject.toml .

# Install pip and dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies and tools needed for scanners
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Install the package (needed for src module resolution)
RUN pip install --no-cache-dir -e .

# =============================================================================
# Install Security Scanners
# =============================================================================

# Python-based scanners
RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    pip-audit \
    safety \
    detect-secrets \
    nodejsscan \
    pylint

# Node.js-based scanners
RUN npm install -g eslint eslint-plugin-security

# Install Gitleaks (secret scanner)
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Install Trivy (vulnerability scanner)
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -O /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    chmod +x /usr/local/bin/trivy

# =============================================================================
# Optional: Language-specific scanners (uncomment if needed)
# =============================================================================

# Install Go and Gosec (for Go code scanning)
# RUN apt-get update && apt-get install -y golang-go && \
#     go install github.com/securego/gosec/v2/cmd/gosec@latest && \
#     mv /root/go/bin/gosec /usr/local/bin/

# Install Ruby and Brakeman (for Ruby/Rails scanning)
# RUN apt-get update && apt-get install -y ruby ruby-dev && \
#     gem install brakeman

# =============================================================================
# Runtime Configuration
# =============================================================================

# Create directory for temporary files with restricted permissions
RUN mkdir -p /tmp/code_review_temp && chmod 755 /tmp/code_review_temp

# Expose port (Azure Web Apps uses PORT environment variable)
EXPOSE 8004

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Add npm global bin to PATH
ENV PATH="/usr/local/bin:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8004/health')"

# Run the application with uvicorn
# Azure Web Apps will use the PORT environment variable
CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8004}"]
