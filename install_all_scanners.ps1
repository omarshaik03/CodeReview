# PowerShell Script to Install All Security Scanners for CodeReview
# Run this script as Administrator for best results

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installing All Security Scanners" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Warning: Not running as Administrator. Some installations may fail." -ForegroundColor Yellow
    Write-Host "Consider running: Start-Process powershell -Verb runAs" -ForegroundColor Yellow
    Write-Host ""
}

# Step 1: Install Python-based scanners
Write-Host "[1/5] Installing Python-based scanners..." -ForegroundColor Green
try {
    pip install --upgrade pip
    pip install semgrep bandit pip-audit safety detect-secrets nodejsscan pylint pylint-secure-coding-standard
    Write-Host "✓ Python scanners installed successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Error installing Python scanners: $_" -ForegroundColor Red
}
Write-Host ""

# Step 2: Install Node.js-based scanners
Write-Host "[2/5] Installing Node.js-based scanners..." -ForegroundColor Green
try {
    $nodeVersion = node --version 2>$null
    if ($nodeVersion) {
        Write-Host "Node.js version: $nodeVersion" -ForegroundColor Gray
        npm install -g eslint eslint-plugin-security snyk
        Write-Host "✓ Node.js scanners installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Node.js not found. Install from https://nodejs.org/" -ForegroundColor Yellow
        Write-Host "  Skipping: eslint, snyk" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error installing Node.js scanners: $_" -ForegroundColor Red
}
Write-Host ""

# Step 3: Install binary tools via Chocolatey
Write-Host "[3/5] Installing binary tools (gitleaks, trivy)..." -ForegroundColor Green
try {
    $chocoVersion = choco --version 2>$null
    if ($chocoVersion) {
        Write-Host "Chocolatey version: $chocoVersion" -ForegroundColor Gray
        choco install gitleaks trivy -y
        Write-Host "✓ Binary tools installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Chocolatey not found. Install from https://chocolatey.org/" -ForegroundColor Yellow
        Write-Host "  Or run: Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" -ForegroundColor Gray
        Write-Host "  Manual download links:" -ForegroundColor Yellow
        Write-Host "  - Gitleaks: https://github.com/gitleaks/gitleaks/releases" -ForegroundColor Yellow
        Write-Host "  - Trivy: https://github.com/aquasecurity/trivy/releases" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error installing binary tools: $_" -ForegroundColor Red
}
Write-Host ""

# Step 4: Install Ruby-based scanners
Write-Host "[4/5] Installing Ruby-based scanners (Brakeman)..." -ForegroundColor Green
try {
    $rubyVersion = ruby --version 2>$null
    if ($rubyVersion) {
        Write-Host "Ruby version: $rubyVersion" -ForegroundColor Gray
        gem install brakeman
        Write-Host "✓ Brakeman installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Ruby not found. Install from https://rubyinstaller.org/" -ForegroundColor Yellow
        Write-Host "  Skipping: brakeman" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error installing Ruby scanners: $_" -ForegroundColor Red
}
Write-Host ""

# Step 5: Install Go-based scanners
Write-Host "[5/5] Installing Go-based scanners (Gosec)..." -ForegroundColor Green
try {
    $goVersion = go version 2>$null
    if ($goVersion) {
        Write-Host "Go version: $goVersion" -ForegroundColor Gray
        go install github.com/securego/gosec/v2/cmd/gosec@latest
        Write-Host "✓ Gosec installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Go not found. Install from https://go.dev/dl/" -ForegroundColor Yellow
        Write-Host "  Skipping: gosec" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error installing Go scanners: $_" -ForegroundColor Red
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Verifying installations..." -ForegroundColor Yellow
Write-Host ""

$installed = @()
$notInstalled = @()

# Check each scanner
$scanners = @{
    "semgrep" = "semgrep --version"
    "bandit" = "bandit --version"
    "pip-audit" = "pip-audit --version"
    "safety" = "safety --version"
    "detect-secrets" = "detect-secrets --version"
    "nodejsscan" = "nodejsscan --version"
    "pylint" = "pylint --version"
    "gitleaks" = "gitleaks version"
    "trivy" = "trivy --version"
    "eslint" = "eslint --version"
    "snyk" = "snyk --version"
    "brakeman" = "brakeman --version"
    "gosec" = "gosec -version"
}

foreach ($scanner in $scanners.Keys) {
    try {
        $output = Invoke-Expression $scanners[$scanner] 2>$null
        if ($LASTEXITCODE -eq 0 -or $output) {
            $installed += $scanner
            Write-Host "✓ $scanner" -ForegroundColor Green
        } else {
            $notInstalled += $scanner
            Write-Host "✗ $scanner" -ForegroundColor Red
        }
    } catch {
        $notInstalled += $scanner
        Write-Host "✗ $scanner" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Installed: $($installed.Count) / $($scanners.Count)" -ForegroundColor Cyan
Write-Host ""

if ($notInstalled.Count -gt 0) {
    Write-Host "Not Installed:" -ForegroundColor Yellow
    foreach ($scanner in $notInstalled) {
        Write-Host "  - $scanner" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Additional tools that need manual installation
Write-Host "Manual Installation Required:" -ForegroundColor Yellow
Write-Host "  - SpotBugs (Java): https://spotbugs.github.io/" -ForegroundColor Yellow
Write-Host "  - Security Code Scan (C#): Install via NuGet in .NET projects" -ForegroundColor Yellow
Write-Host "  - PHPCS Security (PHP): composer global require squizlabs/php_codesniffer" -ForegroundColor Yellow
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "Test with: cd c:\Users\Omars\Repos\TestRepo" -ForegroundColor Cyan
Write-Host "           semgrep --config=auto ." -ForegroundColor Cyan
