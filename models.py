# models.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class FileMeta(BaseModel):
    path: str
    extension: str
    size: int
    lines: int




class ContextSnippet(BaseModel):
    file_path: str
    symbol: Optional[str] = Field(None, description="Function/class name if applicable")
    snippet: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None


    @field_validator("symbol", mode="before")
    @classmethod
    def _normalize_symbol(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            s = v.strip()
            if s.lower() in {"", "none", "null", "n/a", "na"}:
                return None
            return s
        return None  # anything non-string -> None


class VulnFinding(BaseModel):
    file: str
    vulnerability_type: str
    code_snippet: str
    line_number: Optional[int] = None
    impact: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    poc: List[str] = Field(default_factory=list)
    edge_cases: List[str] = Field(default_factory=list)
    suggested_fixes: List[str] = Field(default_factory=list)
    dataflow_info: Optional[Dict[str, Any]] = None
    related_context: List[ContextSnippet] = Field(default_factory=list)

    @field_validator("vulnerability_type")
    @classmethod
    def trim_vtype(cls, v: str) -> str:
        return v.strip()


class DeepDivePass(BaseModel):
    finding: VulnFinding
    updated_dataflow_info: Optional[Dict[str, Any]] = None
    new_context: List[ContextSnippet] = Field(default_factory=list)
    updated_pocs: List[str] = Field(default_factory=list)
    updated_suggested_fixes: List[str] = Field(default_factory=list)
    updated_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    notes: Optional[str] = None


class ConvergedFinding(BaseModel):
    final: VulnFinding
    iterations: int
    converged_reason: str  # "no_new_context" | "max_iterations"
    lineage: List[DeepDivePass] = Field(default_factory=list)


class FileDiscoveryResult(BaseModel):
    directory: str
    files: List[FileMeta]
    total_files: int


class AnalysisSummary(BaseModel):
    total_files_analyzed: int
    total_findings: int
    by_type: Dict[str, int] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VulnerabilityJSON(BaseModel):
    file: str
    vulnerability_type: str
    context_functions: List[str] = Field(default_factory=list)
    dataflow_info: Dict[str, Any] = Field(default_factory=dict)
    poc: List[str] = Field(default_factory=list)
    confidence: float
    edge_cases: List[str] = Field(default_factory=list)
    suggested_fixes: List[str] = Field(default_factory=list)

    @classmethod
    def from_converged(cls, c: ConvergedFinding) -> "VulnerabilityJSON":
        f = c.final
        # NEW: defensively filter bogus symbol strings
        def _ok(sym: Optional[str]) -> bool:
            return bool(sym) and sym.strip().lower() not in {"none", "null", "n/a", "na", ""}

        return cls(
            file=f.file,
            vulnerability_type=f.vulnerability_type,
            context_functions=[sn.symbol for sn in f.related_context if _ok(sn.symbol)],
            dataflow_info=f.dataflow_info or {},
            poc=f.poc,
            confidence=f.confidence,
            edge_cases=f.edge_cases,
            suggested_fixes=f.suggested_fixes,
        )


class AggregateMarkdown(BaseModel):
    summary: AnalysisSummary
    vulnerabilities: List[VulnerabilityJSON]


# ---------------------------
# Output wrappers for Task.output_pydantic
# ---------------------------

class FindingsList(BaseModel):
    """Wrapper for a list of VulnFinding (used by vulnerability_analysis_task)."""
    items: List[VulnFinding]


class ConvergedList(BaseModel):
    """Wrapper for a list of ConvergedFinding (used by aggregate steps when needed)."""
    items: List[ConvergedFinding]


class ReportArtifacts(BaseModel):
    """Paths produced by the report task."""
    json_paths: List[str]
    report_path: str
