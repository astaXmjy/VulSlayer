# models.py
from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
from datetime import datetime, timezone


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


class VulnFinding(BaseModel):
    file: str
    vulnerability_type: str
    code_snippet: str
    line_number: Optional[int] = None
    impact: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    poc: List[str] = []
    edge_cases: List[str] = []
    suggested_fixes: List[str] = []
    dataflow_info: Optional[Dict[str, Any]] = None
    related_context: List[ContextSnippet] = []

    @validator("vulnerability_type")
    def trim_vtype(cls, v):
        return v.strip()


class DeepDivePass(BaseModel):
    finding: VulnFinding
    updated_dataflow_info: Optional[Dict[str, Any]] = None
    new_context: List[ContextSnippet] = []
    updated_pocs: List[str] = []
    updated_suggested_fixes: List[str] = []
    updated_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    notes: Optional[str] = None


class ConvergedFinding(BaseModel):
    final: VulnFinding
    iterations: int
    converged_reason: str  # "no_new_context" | "max_iterations"
    lineage: List[DeepDivePass] = []


class FileDiscoveryResult(BaseModel):
    directory: str
    files: List[FileMeta]
    total_files: int


class AnalysisSummary(BaseModel):
    total_files_analyzed: int
    total_findings: int
    by_type: Dict[str, int] = {}
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VulnerabilityJSON(BaseModel):
    file: str
    vulnerability_type: str
    context_functions: List[str] = []
    dataflow_info: Dict[str, Any] = {}
    poc: List[str] = []
    confidence: float
    edge_cases: List[str] = []
    suggested_fixes: List[str] = []

    @classmethod
    def from_converged(cls, c: ConvergedFinding) -> "VulnerabilityJSON":
        f = c.final
        # Map to the PDF-friendly structure
        return cls(
            file=f.file,
            vulnerability_type=f.vulnerability_type,
            context_functions=[sn.symbol for sn in f.related_context if sn.symbol] or [],
            dataflow_info=f.dataflow_info or {},
            poc=f.poc,
            confidence=f.confidence,
            edge_cases=f.edge_cases,
            suggested_fixes=f.suggested_fixes,
        )


class AggregateMarkdown(BaseModel):
    summary: AnalysisSummary
    vulnerabilities: List[VulnerabilityJSON]
