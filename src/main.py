from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
import subprocess
import logging
from pathlib import Path
from typing import Any, Optional, List
from io import StringIO

from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from rich.console import Console

from langchain_openai import AzureChatOpenAI, ChatOpenAI

from src.commit_ingest import GitRepository
from src.config import Settings, settings
from src.review import LangChainReviewAgent
from src.services import ReviewService

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Git Commit Review API",
    description="Review Git commits with a LangChain-powered LLM",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins like ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewRequest(BaseModel):
    repo_path: str = Field(..., description="Path to the Git repository")
    from_ref: Optional[str] = Field(None, description="Oldest commit (exclusive)")
    to_ref: str = Field("HEAD", description="Newest commit (inclusive)")
    max_commits: Optional[int] = Field(None, ge=1, description="Limit number of commits")
    format: str = Field("json", description="Output format: 'json' or 'text'")
    review_guidelines: Optional[str] = Field(None, description="Custom review guidelines text")
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_path": "/path/to/repo",
                "from_ref": "HEAD~2",
                "to_ref": "HEAD",
                "max_commits": 10,
                "format": "json",
                "review_guidelines": "Focus on security and performance issues."
            }
        }


class RepoUrlRequest(BaseModel):
    repo_url: HttpUrl = Field(..., description="Git repository URL (e.g., https://github.com/user/repo.git)")
    from_ref: Optional[str] = Field(None, description="Oldest commit (exclusive)")
    to_ref: str = Field("HEAD", description="Newest commit (inclusive)")
    max_commits: Optional[int] = Field(None, ge=1, description="Limit number of commits")
    format: str = Field("json", description="Output format: 'json' or 'text'")
    branch: Optional[str] = Field(None, description="Specific branch to clone (optional)")
    review_guidelines: Optional[str] = Field(None, description="Custom review guidelines text")
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repository.git",
                "from_ref": "HEAD~5",
                "to_ref": "HEAD",
                "max_commits": 10,
                "format": "json",
                "branch": "main",
                "review_guidelines": "Focus on security and performance issues."
            }
        }


class Finding(BaseModel):
    severity: str
    file: str
    message: str


class CommitReview(BaseModel):
    commit_hash: str
    commit_message: str
    summary: str
    findings: List[Finding]


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
                message=suggestion.message
            ))
        
        structured_reviews.append(CommitReview(
            commit_hash=report.commit.sha,
            commit_message=report.commit.summary,
            summary=report.summary,
            findings=findings
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
            "GET /health": "Check API health"
        }
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


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
        # Pass review guidelines to the service
        reports = service.review(
            start_ref=cfg.start_ref,
            end_ref=cfg.end_ref,
            max_commits=cfg.max_commits,
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
    from_ref: Optional[str] = Query(None, description="Oldest commit (exclusive)"),
    to_ref: str = Query("HEAD", description="Newest commit (inclusive)"),
    max_commits: Optional[int] = Query(None, ge=1, description="Limit number of commits"),
    format: str = Query("json", description="Output format: 'json' or 'text'"),
):
    """
    GET endpoint for reviewing commits (alternative to POST).
    """
    request = ReviewRequest(
        repo_path=repo_path,
        from_ref=from_ref,
        to_ref=to_ref,
        max_commits=max_commits,
        format=format,
    )
    return await review_commits(request)


@app.post("/review/upload")
async def review_zip_upload(
    file: UploadFile = File(..., description="Zip file containing the repository"),
    guidelines_file: Optional[UploadFile] = File(None, description="Optional PDF/DOCX with review guidelines"),
    from_ref: Optional[str] = Form(None, description="Oldest commit (exclusive)"),
    to_ref: str = Form("HEAD", description="Newest commit (inclusive)"),
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
    from_ref: Optional[str] = Form(None, description="Oldest commit (exclusive)"),
    to_ref: str = Form("HEAD", description="Newest commit (inclusive)"),
    max_commits: Optional[int] = Form(None, description="Limit number of commits"),
    format: str = Form("json", description="Output format: 'json' or 'text'"),
    branch: Optional[str] = Form(None, description="Specific branch to clone"),
):
    """
    Clone a Git repository from a URL and review it.
    Optionally upload a guidelines document (PDF, DOCX, or TXT) to guide the review.
    Supports GitHub, GitLab, Bitbucket, and any Git-compatible URL.
    """
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)

# For Azure Web Apps and production deployment
# The app instance is exported at module level for uvicorn to find it