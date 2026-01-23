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

# Detect architecture for binary downloads
ARG TARGETARCH
ARG TARGETPLATFORM

# Install runtime dependencies and tools needed for scanners
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    gnupg \
    ca-certificates \
    # Node.js for JS/TS scanners
    nodejs \
    npm \
    # Ruby for Brakeman
    ruby \
    ruby-dev \
    # PHP for PHP_CodeSniffer
    php \
    php-xml \
    php-tokenizer \
    # Go for Gosec
    golang-go \
    # Java for SpotBugs
    default-jdk \
    default-jre \
    # .NET for Security Code Scan
    apt-transport-https \
    # Build tools needed for some gems
    make \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install .NET SDK for Security Code Scan
RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0 --install-dir /usr/share/dotnet && \
    ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet || true

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Install the package (needed for src module resolution)
RUN pip install --no-cache-dir -e .

# =============================================================================
# Install Security Scanners - Multi-Language
# =============================================================================

# Semgrep - Multi-language SAST with OWASP rules
# Trivy - installed later as binary
# Snyk CLI - Advanced SAST
RUN pip install --no-cache-dir semgrep && \
    npm install -g snyk

# =============================================================================
# Install Security Scanners - Python
# =============================================================================

# Bandit - Python SAST
# Pylint - Python linting (security checks via bandit)
# pip-audit - Python dependency CVE scanner
# Safety - Alternative Python dependency scanner
# detect-secrets - Secret detection
# NodeJsScan - Node.js security scanner (Python-based)
RUN pip install --no-cache-dir \
    bandit \
    pylint \
    pip-audit \
    safety \
    detect-secrets \
    nodejsscan

# =============================================================================
# Install Security Scanners - JavaScript/TypeScript
# =============================================================================

# ESLint Security Plugin - JS/TS security linting
# npm audit - built into npm
RUN npm install -g \
    eslint \
    eslint-plugin-security \
    @eslint/js

# =============================================================================
# Install Security Scanners - Go
# =============================================================================

# Gosec - Go security checker
ENV GOPATH=/root/go
ENV PATH="$PATH:$GOPATH/bin"
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

# =============================================================================
# Install Security Scanners - Ruby
# =============================================================================

# Brakeman - Ruby on Rails security scanner
RUN gem install brakeman

# =============================================================================
# Install Security Scanners - Java
# =============================================================================

# SpotBugs with Find Security Bugs plugin
ENV SPOTBUGS_VERSION=4.8.6
ENV FIND_SEC_BUGS_VERSION=1.12.0
RUN mkdir -p /opt/spotbugs && \
    wget --no-check-certificate "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" -O /tmp/spotbugs.tgz && \
    tar -xzf /tmp/spotbugs.tgz -C /opt/spotbugs --strip-components=1 && \
    rm /tmp/spotbugs.tgz && \
    chmod +x /opt/spotbugs/bin/spotbugs && \
    ln -s /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs && \
    # Install Find Security Bugs plugin
    mkdir -p /opt/spotbugs/plugin && \
    wget --no-check-certificate "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FIND_SEC_BUGS_VERSION}/findsecbugs-plugin-${FIND_SEC_BUGS_VERSION}.jar" \
        -O /opt/spotbugs/plugin/findsecbugs-plugin.jar

# =============================================================================
# Install Security Scanners - PHP
# =============================================================================

# PHP_CodeSniffer - PHP security standards checker
RUN curl -OL https://squizlabs.github.io/PHP_CodeSniffer/phpcs.phar && \
    chmod +x phpcs.phar && \
    mv phpcs.phar /usr/local/bin/phpcs && \
    curl -OL https://squizlabs.github.io/PHP_CodeSniffer/phpcbf.phar && \
    chmod +x phpcbf.phar && \
    mv phpcbf.phar /usr/local/bin/phpcbf

# =============================================================================
# Install Security Scanners - .NET/C#
# =============================================================================

# Security Code Scan - .NET security analyzer (installed as dotnet tool)
RUN dotnet tool install --global security-scan || echo "Security Code Scan installation skipped - may require project context"

# Add dotnet tools to PATH
ENV PATH="$PATH:/root/.dotnet/tools"

# =============================================================================
# Install Security Scanners - Secrets Detection
# =============================================================================

# Gitleaks - Comprehensive secret scanner (architecture-aware)
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then ARCH="x64"; fi && \
    if [ "$ARCH" = "arm64" ]; then ARCH="arm64"; fi && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Trivy - Filesystem, vulnerability, config, and secret scanning (architecture-aware)
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then TRIVY_ARCH="64bit"; fi && \
    if [ "$ARCH" = "arm64" ]; then TRIVY_ARCH="ARM64"; fi && \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -O /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    chmod +x /usr/local/bin/trivy

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

# Add all tool paths
ENV PATH="/usr/local/bin:$GOPATH/bin:/root/.dotnet/tools:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8004/health')"

# Run the application with uvicorn
# Azure Web Apps will use the PORT environment variable
CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8004}"]
