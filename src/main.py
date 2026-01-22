from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import zipfile
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List
from io import StringIO

from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
from rich.console import Console

from langchain_openai import AzureChatOpenAI, ChatOpenAI

from src.commit_ingest import GitRepository
from src.config import Settings, settings
from src.review import LangChainReviewAgent
from src.services import ReviewService
from src.security import SecurityScanner

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Git Commit Review API",
    description="Review Git commits with a LangChain-powered LLM",
    version="1.0.0",
)

# Configure CORS - use environment variable for allowed origins
# Set CORS_ORIGINS env var to comma-separated list of allowed origins
# Example: CORS_ORIGINS=https://your-frontend.azurewebsites.net,http://localhost:5173
cors_origins_str = os.getenv("CORS_ORIGINS", "*")
if cors_origins_str == "*":
    cors_origins = ["*"]
else:
    cors_origins = [origin.strip() for origin in cors_origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewRequest(BaseModel):
    repo_path: str = Field(..., description="Path to the Git repository")

    # Commit reference filtering (mutually exclusive with date filtering)
    from_ref: Optional[str] = Field(None, description="Oldest commit (inclusive) - cannot be used with date filters")
    to_ref: str = Field("HEAD", description="Newest commit (inclusive) - cannot be used with date filters")

    # Date-based filtering (mutually exclusive with commit reference filtering)
    since: Optional[datetime] = Field(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref. Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
    until: Optional[datetime] = Field(None, description="End date (inclusive) - cannot be used with from_ref/to_ref. Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")

    max_commits: Optional[int] = Field(None, ge=1, description="Limit number of commits")
    format: str = Field("json", description="Output format: 'json' or 'text'")
    review_guidelines: Optional[str] = Field(None, description="Custom review guidelines text")

    @model_validator(mode='after')
    def validate_filtering_mode(self):
        """Ensure either commit refs OR dates are used, not both."""
        using_refs = self.from_ref is not None or (self.to_ref != "HEAD" and self.to_ref is not None)
        using_dates = self.since is not None or self.until is not None

        if using_refs and using_dates:
            raise ValueError(
                "Cannot use both commit references (from_ref/to_ref) and date filters (since/until). "
                "Please use either commit references OR date ranges, not both."
            )

        return self

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "description": "Review using commit references",
                    "value": {
                        "repo_path": "/path/to/repo",
                        "from_ref": "HEAD~2",
                        "to_ref": "HEAD",
                        "max_commits": 10,
                        "format": "json",
                        "review_guidelines": "Focus on security and performance issues."
                    }
                },
                {
                    "description": "Review using date range",
                    "value": {
                        "repo_path": "/path/to/repo",
                        "since": "2024-01-01T00:00:00",
                        "until": "2024-12-31T23:59:59",
                        "max_commits": 10,
                        "format": "json",
                        "review_guidelines": "Focus on security and performance issues."
                    }
                }
            ]
        }


class RepoUrlRequest(BaseModel):
    repo_url: HttpUrl = Field(..., description="Git repository URL (e.g., https://github.com/user/repo.git)")

    # Commit reference filtering (mutually exclusive with date filtering)
    from_ref: Optional[str] = Field(None, description="Oldest commit (inclusive) - cannot be used with date filters")
    to_ref: str = Field("HEAD", description="Newest commit (inclusive) - cannot be used with date filters")

    # Date-based filtering (mutually exclusive with commit reference filtering)
    since: Optional[datetime] = Field(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref. Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
    until: Optional[datetime] = Field(None, description="End date (inclusive) - cannot be used with from_ref/to_ref. Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")

    max_commits: Optional[int] = Field(None, ge=1, description="Limit number of commits")
    format: str = Field("json", description="Output format: 'json' or 'text'")
    branch: Optional[str] = Field(None, description="Specific branch to clone (optional)")
    review_guidelines: Optional[str] = Field(None, description="Custom review guidelines text")

    @model_validator(mode='after')
    def validate_filtering_mode(self):
        """Ensure either commit refs OR dates are used, not both."""
        using_refs = self.from_ref is not None or (self.to_ref != "HEAD" and self.to_ref is not None)
        using_dates = self.since is not None or self.until is not None

        if using_refs and using_dates:
            raise ValueError(
                "Cannot use both commit references (from_ref/to_ref) and date filters (since/until). "
                "Please use either commit references OR date ranges, not both."
            )

        return self

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "description": "Review using commit references",
                    "value": {
                        "repo_url": "https://github.com/username/repository.git",
                        "from_ref": "HEAD~5",
                        "to_ref": "HEAD",
                        "max_commits": 10,
                        "format": "json",
                        "branch": "main",
                        "review_guidelines": "Focus on security and performance issues."
                    }
                },
                {
                    "description": "Review using date range",
                    "value": {
                        "repo_url": "https://github.com/username/repository.git",
                        "since": "2024-01-01",
                        "until": "2024-12-31",
                        "max_commits": 10,
                        "format": "json",
                        "branch": "main",
                        "review_guidelines": "Focus on security and performance issues."
                    }
                }
            ]
        }


class Finding(BaseModel):
    severity: str
    file: str
    message: str
    solution: Optional[str] = None
    original_code: Optional[str] = None


class SecurityFindingResponse(BaseModel):
    finding_type: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    title: str
    description: str
    cve_id: Optional[str] = None
    recommendation: str
    solution: Optional[str] = None
    original_code: Optional[str] = None


class SecuritySummary(BaseModel):
    risk_level: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[SecurityFindingResponse]


class CommitReview(BaseModel):
    commit_hash: str
    commit_message: str
    summary: str
    findings: List[Finding]
    security_summary: Optional[SecuritySummary] = None


class ReviewResponse(BaseModel):
    success: bool
    commit_count: int
    reviews: List[CommitReview]


class TextReviewResponse(BaseModel):
    success: bool
    commit_count: int
    output: str


def _ensure_api_key(cfg: Settings) -> None:
    if cfg.llm_provider == "azure-openai":
        if cfg.azure_openai_api_key:
            os.environ.setdefault("AZURE_OPENAI_API_KEY", cfg.azure_openai_api_key)
        if cfg.azure_openai_endpoint:
            os.environ.setdefault("AZURE_OPENAI_ENDPOINT", cfg.azure_openai_endpoint)
        if cfg.azure_openai_api_version:
            os.environ.setdefault("AZURE_OPENAI_API_VERSION", cfg.azure_openai_api_version)
        if cfg.azure_openai_deployment:
            os.environ.setdefault("AZURE_OPENAI_DEPLOYMENT", cfg.azure_openai_deployment)
    elif cfg.openai_api_key:
        os.environ.setdefault("OPENAI_API_KEY", cfg.openai_api_key)


def _build_llm(cfg: Settings) -> ChatOpenAI:
    if cfg.llm_provider == "azure-openai":
        required = {
            "AZURE_OPENAI_API_KEY": cfg.azure_openai_api_key,
            "AZURE_OPENAI_ENDPOINT": cfg.azure_openai_endpoint,
            "AZURE_OPENAI_DEPLOYMENT": cfg.azure_openai_deployment,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            missing_env = ", ".join(missing)
            raise ValueError(
                "Missing Azure OpenAI configuration. Please set: " + missing_env
            )

        azure_kwargs: dict[str, Any] = {}
        if cfg.max_output_tokens:
            azure_kwargs["max_tokens"] = cfg.max_output_tokens

        return AzureChatOpenAI(
            azure_deployment=cfg.azure_openai_deployment,
            azure_endpoint=cfg.azure_openai_endpoint,
            api_version=cfg.azure_openai_api_version,
            api_key=cfg.azure_openai_api_key,
            temperature=cfg.openai_temperature,
            **azure_kwargs,
        )

    openai_kwargs: dict[str, Any] = {}
    if cfg.max_output_tokens:
        openai_kwargs["max_tokens"] = cfg.max_output_tokens

    return ChatOpenAI(
        model=cfg.openai_model,
        temperature=cfg.openai_temperature,
        **openai_kwargs,
    )


def _build_service(cfg: Settings) -> ReviewService:
    repository = GitRepository(cfg.repo_path)
    llm = _build_llm(cfg)
    agent = LangChainReviewAgent(
        model=cfg.openai_model,
        temperature=cfg.openai_temperature,
        max_output_tokens=cfg.max_output_tokens,
        llm=llm,
    )
    return ReviewService(repository, agent)


async def _extract_document_text(file: UploadFile) -> str:
    """
    Extract text from PDF or DOCX files.
    """
    try:
        content = await file.read()
        
        if file.filename.lower().endswith('.pdf'):
            # PDF extraction using PyPDF2
            try:
                import PyPDF2
                from io import BytesIO
                
                pdf_reader = PyPDF2.PdfReader(BytesIO(content))
                text = []
                for page in pdf_reader.pages:
                    text.append(page.extract_text())
                return "\n".join(text)
            except ImportError:
                raise HTTPException(
                    status_code=500,
                    detail="PDF support not installed. Please install PyPDF2."
                )
        
        elif file.filename.lower().endswith('.docx'):
            # DOCX extraction using python-docx
            try:
                import docx
                from io import BytesIO
                
                doc = docx.Document(BytesIO(content))
                text = []
                for paragraph in doc.paragraphs:
                    text.append(paragraph.text)
                return "\n".join(text)
            except ImportError:
                raise HTTPException(
                    status_code=500,
                    detail="DOCX support not installed. Please install python-docx."
                )
        
        elif file.filename.lower().endswith('.txt'):
            # Plain text
            return content.decode('utf-8')
        
        else:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file format. Please upload PDF, DOCX, or TXT files."
            )
    
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to extract text from document: {str(exc)}"
        )


def _parse_reports_to_structured(reports: List[Any]) -> List[CommitReview]:
    """
    Parse ReviewReport objects into structured CommitReview objects.
    """
    structured_reviews = []

    for report in reports:
        # Parse suggestions into findings
        findings = []
        for suggestion in report.suggestions:
            findings.append(Finding(
                severity=suggestion.severity,
                file=suggestion.file_path,
                message=suggestion.message,
                solution=suggestion.solution,
                original_code=suggestion.original_code
            ))

        # Parse security findings if present
        security_summary = None
        if report.security_report:
            sec_report = report.security_report
            security_findings = []

            for sec_finding in sec_report.findings:
                security_findings.append(SecurityFindingResponse(
                    finding_type=sec_finding.finding_type.value,
                    severity=sec_finding.severity.value,
                    file_path=sec_finding.file_path,
                    line_number=sec_finding.line_number,
                    title=sec_finding.title,
                    description=sec_finding.description,
                    cve_id=sec_finding.cve_id,
                    recommendation=sec_finding.recommendation,
                    solution=sec_finding.solution,
                    original_code=sec_finding.original_code,
                ))

            security_summary = SecuritySummary(
                risk_level=sec_report.risk_level,
                total_findings=len(sec_report.findings),
                critical_count=sec_report.critical_count,
                high_count=sec_report.high_count,
                medium_count=sec_report.medium_count,
                low_count=sec_report.low_count,
                findings=security_findings,
            )

        structured_reviews.append(CommitReview(
            commit_hash=report.commit.sha,
            commit_message=report.commit.summary,
            summary=report.summary,
            findings=findings,
            security_summary=security_summary,
        ))

    return structured_reviews


@app.get("/")
async def root():
    return {
        "message": "Git Commit Review API",
        "version": "1.0.0",
        "endpoints": {
            "POST /review": "Submit a local repository path for review",
            "POST /review/upload": "Upload a .zip file of a repository for review",
            "POST /review/url": "Clone and review a repository from URL",
            "POST /security/scan": "Run comprehensive security scan on entire repository",
            "GET /health": "Check API health"
        }
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/security/scan")
async def scan_repository_security(request: ReviewRequest):
    """
    Run a comprehensive security scan on the entire repository.
    Returns security findings without per-commit analysis.

    This is useful for getting an overall security posture of the repository.
    """
    repo_path = Path(request.repo_path)

    if not repo_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Repository path does not exist: {repo_path}"
        )

    try:
        scanner = SecurityScanner(repo_path)
        # Run full repo scan (no changed_files filter)
        security_report = scanner.scan()

        # Convert to response format
        security_findings = []
        for finding in security_report.findings:
            security_findings.append(SecurityFindingResponse(
                finding_type=finding.finding_type.value,
                severity=finding.severity.value,
                file_path=finding.file_path,
                line_number=finding.line_number,
                title=finding.title,
                description=finding.description,
                cve_id=finding.cve_id,
                recommendation=finding.recommendation,
                solution=finding.solution,
                original_code=finding.original_code,
            ))

        return SecuritySummary(
            risk_level=security_report.risk_level,
            total_findings=len(security_report.findings),
            critical_count=security_report.critical_count,
            high_count=security_report.high_count,
            medium_count=security_report.medium_count,
            low_count=security_report.low_count,
            findings=security_findings,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {str(exc)}"
        )


@app.post("/review")
async def review_commits(request: ReviewRequest):
    """
    Review commits in a Git repository using an LLM.
    
    Returns structured JSON by default or formatted text output if format='text'.
    """
    cfg = settings.model_copy(update={
        "repo_path": Path(request.repo_path),
        "start_ref": request.from_ref,
        "end_ref": request.to_ref,
        "max_commits": request.max_commits,
    })

    _ensure_api_key(cfg)

    try:
        service = _build_service(cfg)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Configuration error: {str(exc)}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize service: {str(exc)}"
        )

    try:
        # Pass review guidelines and date filters to the service
        reports = service.review(
            start_ref=cfg.start_ref,
            end_ref=cfg.end_ref,
            max_commits=cfg.max_commits,
            since=request.since,
            until=request.until,
            custom_guidelines=request.review_guidelines,
        )
        
        # Return formatted text output
        if request.format.lower() == "text":
            output = StringIO()
            console = Console(file=output, width=cfg.console_width, force_terminal=True)
            service.render_console_summary(reports, console=console)
            summary = output.getvalue()
            
            return TextReviewResponse(
                success=True,
                commit_count=len(reports),
                output=summary,
            )
        
        # Return structured JSON (default)
        structured_reviews = _parse_reports_to_structured(reports)
        
        return ReviewResponse(
            success=True,
            commit_count=len(reports),
            reviews=structured_reviews,
        )
        
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Review failed: {str(exc)}"
        )


@app.get("/review")
async def review_commits_get(
    repo_path: str = Query(..., description="Path to the Git repository"),
    from_ref: Optional[str] = Query(None, description="Oldest commit (inclusive) - cannot be used with date filters"),
    to_ref: str = Query("HEAD", description="Newest commit (inclusive) - cannot be used with date filters"),
    since: Optional[datetime] = Query(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref"),
    until: Optional[datetime] = Query(None, description="End date (inclusive) - cannot be used with from_ref/to_ref"),
    max_commits: Optional[int] = Query(None, ge=1, description="Limit number of commits"),
    format: str = Query("json", description="Output format: 'json' or 'text'"),
):
    """
    GET endpoint for reviewing commits (alternative to POST).
    Supports both commit reference filtering and date-based filtering (mutually exclusive).
    """
    request = ReviewRequest(
        repo_path=repo_path,
        from_ref=from_ref,
        to_ref=to_ref,
        since=since,
        until=until,
        max_commits=max_commits,
        format=format,
    )
    return await review_commits(request)


@app.post("/review/upload")
async def review_zip_upload(
    file: UploadFile = File(..., description="Zip file containing the repository"),
    guidelines_file: Optional[UploadFile] = File(None, description="Optional PDF/DOCX with review guidelines"),
    from_ref: Optional[str] = Form(None, description="Oldest commit (inclusive) - cannot be used with date filters"),
    to_ref: str = Form("HEAD", description="Newest commit (inclusive) - cannot be used with date filters"),
    since: Optional[str] = Form(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref"),
    until: Optional[str] = Form(None, description="End date (inclusive) - cannot be used with from_ref/to_ref"),
    max_commits: Optional[int] = Form(None, description="Limit number of commits"),
    format: str = Form("json", description="Output format: 'json' or 'text'"),
):
    """
    Upload a .zip file containing a Git repository for review.
    Optionally upload a guidelines document (PDF, DOCX, or TXT) to guide the review.
    The zip should contain the repository with its .git directory.
    """
    if not file.filename.endswith('.zip'):
        raise HTTPException(
            status_code=400,
            detail="File must be a .zip archive"
        )

    # Parse date strings to datetime objects
    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            since_dt = datetime.strptime(since, "%Y-%m-%d")

    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            until_dt = datetime.strptime(until, "%Y-%m-%d")

    # Extract guidelines if provided
    review_guidelines = None
    if guidelines_file:
        review_guidelines = await _extract_document_text(guidelines_file)
    
    temp_dir = None
    try:
        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="code_review_")
        zip_path = Path(temp_dir) / file.filename
        
        # Save uploaded file
        with open(zip_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Extract zip file
        extract_dir = Path(temp_dir) / "extracted"
        extract_dir.mkdir()
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Find the .git directory (might be in a subdirectory)
        git_dir = None
        for root, dirs, files in os.walk(extract_dir):
            if '.git' in dirs:
                git_dir = Path(root)
                break
        
        if not git_dir:
            raise HTTPException(
                status_code=400,
                detail="No .git directory found in the uploaded zip. Please upload a valid Git repository."
            )
        
        # Create review request with the extracted path
        request = ReviewRequest(
            repo_path=str(git_dir),
            from_ref=from_ref,
            to_ref=to_ref,
            since=since_dt,
            until=until_dt,
            max_commits=max_commits,
            format=format,
            review_guidelines=review_guidelines,
        )
        
        result = await review_commits(request)
        return result
        
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Invalid zip file"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process uploaded file: {str(exc)}"
        )
    finally:
        # Cleanup temporary directory
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as cleanup_exc:
                logger.warning(f"Failed to cleanup temp directory: {cleanup_exc}")


@app.post("/review/url")
async def review_from_url(
    repo_url: str = Form(..., description="Git repository URL"),
    guidelines_file: Optional[UploadFile] = File(None, description="Optional PDF/DOCX with review guidelines"),
    from_ref: Optional[str] = Form(None, description="Oldest commit (inclusive) - cannot be used with date filters"),
    to_ref: str = Form("HEAD", description="Newest commit (inclusive) - cannot be used with date filters"),
    since: Optional[str] = Form(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref"),
    until: Optional[str] = Form(None, description="End date (inclusive) - cannot be used with from_ref/to_ref"),
    max_commits: Optional[int] = Form(None, description="Limit number of commits"),
    format: str = Form("json", description="Output format: 'json' or 'text'"),
    branch: Optional[str] = Form(None, description="Specific branch to clone"),
):
    """
    Clone a Git repository from a URL and review it.
    Optionally upload a guidelines document (PDF, DOCX, or TXT) to guide the review.
    Supports GitHub, GitLab, Bitbucket, and any Git-compatible URL.
    """
    # Parse date strings to datetime objects
    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            since_dt = datetime.strptime(since, "%Y-%m-%d")

    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            until_dt = datetime.strptime(until, "%Y-%m-%d")

    # Extract guidelines if provided
    review_guidelines = None
    if guidelines_file:
        review_guidelines = await _extract_document_text(guidelines_file)
    
    temp_dir = None
    try:
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix="code_review_clone_")
        clone_path = Path(temp_dir) / "repo"
        
        # Build git clone command
        clone_cmd = ["git", "clone"]
        
        # Add branch if specified
        if branch:
            clone_cmd.extend(["-b", branch])
        
        # Add URL and destination
        clone_cmd.extend([repo_url, str(clone_path)])
        
        # Clone the repository
        result = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to clone repository: {result.stderr}"
            )
        
        # Create review request with the cloned path
        review_request = ReviewRequest(
            repo_path=str(clone_path),
            from_ref=from_ref,
            to_ref=to_ref,
            since=since_dt,
            until=until_dt,
            max_commits=max_commits,
            format=format,
            review_guidelines=review_guidelines,
        )
        
        result = await review_commits(review_request)
        return result
        
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail="Repository clone timed out (exceeded 5 minutes)"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clone and review repository: {str(exc)}"
        )
    finally:
        # Cleanup temporary directory
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as cleanup_exc:
                logger.warning(f"Failed to cleanup temp directory: {cleanup_exc}")


@app.post("/review/url/stream")
async def review_from_url_stream(
    repo_url: str = Form(..., description="Git repository URL"),
    guidelines_file: Optional[UploadFile] = File(None, description="Optional PDF/DOCX with review guidelines"),
    from_ref: Optional[str] = Form(None, description="Oldest commit (inclusive) - cannot be used with date filters"),
    to_ref: str = Form("HEAD", description="Newest commit (inclusive) - cannot be used with date filters"),
    since: Optional[str] = Form(None, description="Start date (inclusive) - cannot be used with from_ref/to_ref"),
    until: Optional[str] = Form(None, description="End date (inclusive) - cannot be used with from_ref/to_ref"),
    max_commits: Optional[int] = Form(None, description="Limit number of commits"),
    branch: Optional[str] = Form(None, description="Specific branch to clone"),
):
    """
    Clone a Git repository and review it with streaming progress updates.
    Returns Server-Sent Events (SSE) with progress and results.
    """
    # Parse date strings to datetime objects
    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            since_dt = datetime.strptime(since, "%Y-%m-%d")

    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            # Try parsing as date only (YYYY-MM-DD)
            until_dt = datetime.strptime(until, "%Y-%m-%d")

    async def generate():
        temp_dir = None
        try:
            # Extract guidelines if provided
            review_guidelines = None
            if guidelines_file:
                yield f"data: {json.dumps({'type': 'status', 'message': 'Extracting guidelines...'})}\n\n"
                review_guidelines = await _extract_document_text(guidelines_file)

            # Create temporary directory for cloning
            temp_dir = tempfile.mkdtemp(prefix="code_review_clone_")
            clone_path = Path(temp_dir) / "repo"

            yield f"data: {json.dumps({'type': 'status', 'message': 'Cloning repository...'})}\n\n"

            # Build git clone command with shallow clone for speed
            clone_cmd = ["git", "clone", "--depth", "100"]  # Shallow clone for faster downloads

            if branch:
                clone_cmd.extend(["-b", branch])

            clone_cmd.extend([repo_url, str(clone_path)])

            # Clone the repository
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout for clone
            )

            if result.returncode != 0:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Failed to clone repository: {result.stderr}'})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'status', 'message': 'Repository cloned. Analyzing commits...'})}\n\n"

            # Initialize components
            cfg = settings.model_copy(update={
                "repo_path": clone_path,
                "start_ref": from_ref,
                "end_ref": to_ref,
                "max_commits": max_commits,
            })

            _ensure_api_key(cfg)
            service = _build_service(cfg)

            # Get commits first to know total count
            from src.commit_ingest import CommitQuery
            query = CommitQuery(
                start_ref=from_ref,
                end_ref=to_ref,
                max_count=max_commits,
                since=since_dt,
                until=until_dt
            )

            repository = GitRepository(clone_path)
            commits = repository.get_commits(query)
            total_commits = len(commits)

            if total_commits == 0:
                yield f"data: {json.dumps({'type': 'status', 'message': 'No commits found matching criteria.'})}\n\n"
                yield f"data: {json.dumps({'type': 'complete', 'reviews': [], 'commit_count': 0})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'total', 'total': total_commits})}\n\n"

            # Process commits one by one with progress updates
            reviews = []
            agent = service._agent

            for idx, change in enumerate(commits, start=1):
                yield f"data: {json.dumps({'type': 'progress', 'current': idx, 'total': total_commits, 'commit': change.sha[:8], 'message': change.summary[:50]})}\n\n"

                try:
                    report = agent.review(change, custom_guidelines=review_guidelines, repo_path=clone_path)

                    # Parse and add the review
                    review_data = {
                        "commit_hash": report.commit.sha[:8],
                        "commit_message": report.commit.summary,
                        "author": report.commit.author_name,
                        "date": report.commit.authored_date.isoformat() if report.commit.authored_date else None,
                        "summary": report.summary,
                        "findings": [
                            {
                                "severity": s.severity,
                                "file": s.file_path,
                                "message": s.message,
                                "solution": s.solution,
                                "original_code": s.original_code,
                            }
                            for s in report.suggestions
                        ],
                        "security_summary": None
                    }

                    # Add security report if present
                    if report.security_report:
                        review_data["security_summary"] = {
                            "risk_level": report.security_report.risk_level,
                            "critical_count": report.security_report.critical_count,
                            "high_count": report.security_report.high_count,
                            "medium_count": report.security_report.medium_count,
                            "low_count": report.security_report.low_count,
                            "findings": [
                                {
                                    "finding_type": f.finding_type.value,
                                    "severity": f.severity.value,
                                    "file_path": f.file_path,
                                    "line_number": f.line_number,
                                    "title": f.title,
                                    "description": f.description,
                                    "cve_id": f.cve_id,
                                    "recommendation": f.recommendation,
                                    "solution": f.solution,
                                    "original_code": f.original_code,
                                }
                                for f in report.security_report.findings
                            ]
                        }

                    reviews.append(review_data)

                    # Send the individual review result
                    yield f"data: {json.dumps({'type': 'review', 'index': idx, 'review': review_data})}\n\n"

                    # Delay between commits to avoid rate limiting (5 seconds)
                    # This helps spread out API calls and reduces 429 errors
                    if idx < total_commits:
                        await asyncio.sleep(5.0)

                except Exception as exc:
                    error_msg = str(exc)
                    logger.error(f"Failed to review commit {change.sha[:8]}: {exc}")

                    # Check if it's a rate limit error
                    if '429' in error_msg or 'RateLimitReached' in error_msg or 'rate limit' in error_msg.lower():
                        yield f"data: {json.dumps({'type': 'rate_limit', 'message': f'Rate limit reached on commit {change.sha[:8]}. Waiting 60s before retrying...', 'commit': change.sha[:8]})}\n\n"
                        # Wait longer for rate limit errors
                        await asyncio.sleep(60)
                        # Retry the commit once after waiting
                        try:
                            report = agent.review(change, custom_guidelines=review_guidelines, repo_path=clone_path)
                            review_data = {
                                "commit_hash": report.commit.sha[:8],
                                "commit_message": report.commit.summary,
                                "author": report.commit.author_name,
                                "date": report.commit.authored_date.isoformat() if report.commit.authored_date else None,
                                "summary": report.summary,
                                "findings": [
                                    {"severity": s.severity, "file": s.file_path, "message": s.message, "solution": s.solution, "original_code": s.original_code}
                                    for s in report.suggestions
                                ],
                                "security_summary": None
                            }
                            if report.security_report:
                                review_data["security_summary"] = {
                                    "risk_level": report.security_report.risk_level,
                                    "critical_count": report.security_report.critical_count,
                                    "high_count": report.security_report.high_count,
                                    "medium_count": report.security_report.medium_count,
                                    "low_count": report.security_report.low_count,
                                    "findings": [
                                        {"finding_type": f.finding_type.value, "severity": f.severity.value, "file_path": f.file_path, "line_number": f.line_number, "title": f.title, "description": f.description, "cve_id": f.cve_id, "recommendation": f.recommendation, "solution": f.solution, "original_code": f.original_code}
                                        for f in report.security_report.findings
                                    ]
                                }
                            reviews.append(review_data)
                            yield f"data: {json.dumps({'type': 'review', 'index': idx, 'review': review_data})}\n\n"
                        except Exception as retry_exc:
                            logger.error(f"Retry failed for commit {change.sha[:8]}: {retry_exc}")
                            yield f"data: {json.dumps({'type': 'error', 'message': f'Failed to review commit {change.sha[:8]} after retry: {str(retry_exc)}'})}\n\n"
                    else:
                        yield f"data: {json.dumps({'type': 'error', 'message': f'Error reviewing commit {change.sha[:8]}: {error_msg}'})}\n\n"
                    continue

            # Send completion message
            yield f"data: {json.dumps({'type': 'complete', 'reviews': reviews, 'commit_count': len(reviews)})}\n\n"

        except subprocess.TimeoutExpired:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Repository clone timed out'})}\n\n"
        except Exception as exc:
            logger.error(f"Stream review failed: {exc}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"
        finally:
            # Cleanup
            if temp_dir and Path(temp_dir).exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)

# For Azure Web Apps and production deployment
# The app instance is exported at module level for uvicorn to find it