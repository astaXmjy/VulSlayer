# security_tools.py
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional, ClassVar, Pattern

from crewai.tools import BaseTool
from pydantic import BaseModel, Field, ValidationError

from models import (
    FileMeta,
    FileDiscoveryResult,
    ContextSnippet,
    ConvergedFinding,
    VulnerabilityJSON,
    AggregateMarkdown,
)

# ---------------------------
# Small helpers
# ---------------------------
def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def _is_under_any(path: Path, folders: tuple[str, ...]) -> bool:
    parts = set(path.parts)
    return any(x in parts for x in folders)

# ---------------------------
# FileSearchTool
# ---------------------------
class FileSearchToolSchema(BaseModel):
    directory: str = Field(..., description="Root directory to search from")
    extensions: Optional[list[str]] = Field(
        default=None, description="File extensions to include; default includes code + html + json/yaml."
    )
    include_globs: Optional[list[str]] = Field(default=None, description="Glob patterns to include (relative to root).")
    exclude_globs: Optional[list[str]] = Field(
        default=["**/node_modules/**", "**/.venv/**", "**/venv/**", "**/dist/**", "**/build/**", "**/.git/**"],
        description="Glob patterns to exclude (relative to root).",
    )
    max_size_bytes: int = Field(default=1_000_000, ge=1, description="Skip files larger than this (per file).")
    follow_symlinks: bool = Field(default=False, description="Follow symlinks during discovery.")

class FileSearchTool(BaseTool):
    name: str = Field(default="File Search Tool")
    description: str = Field(default="Recursively lists source/support files with globs, size caps, and symlink control.")
    args_schema = FileSearchToolSchema

    def _run(
        self,
        directory: str,
        extensions: Optional[list[str]] = None,
        include_globs: Optional[list[str]] = None,
        exclude_globs: Optional[list[str]] = None,
        max_size_bytes: int = 1_000_000,
        follow_symlinks: bool = False,
    ) -> dict:
        root = Path(directory).resolve()
        if extensions is None:
            extensions = [
                ".py", ".js", ".ts", ".java", ".kt", ".scala", ".go", ".rs", ".c", ".cpp",
                ".cs", ".php", ".rb", ".swift", ".m", ".mm",
                ".html", ".htm", ".vue", ".svelte",
                ".json", ".yaml", ".yml",
            ]
        if exclude_globs is None:
            exclude_globs = []
        vendor_dirs = ("node_modules", ".venv", "venv", "dist", "build", ".git")

        files: list[FileMeta] = []

        def eligible(fp: Path) -> bool:
            if not follow_symlinks and fp.is_symlink():
                return False
            if _is_under_any(fp, vendor_dirs):
                return False
            if exclude_globs and any(fp.match(g) for g in exclude_globs):
                return False
            if include_globs and not any(fp.match(g) for g in include_globs):
                return False
            if fp.suffix.lower() not in extensions:
                return False
            try:
                if fp.stat().st_size > max_size_bytes:
                    return False
            except Exception:
                return False
            return True

        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if not eligible(fp):
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
                line_count = text.count("\n") + 1
                size = len(text.encode("utf-8", errors="ignore"))
            except Exception:
                line_count, size = 0, 0
            files.append(FileMeta(path=str(fp), extension=fp.suffix.lower(), size=size, lines=line_count))

        payload = FileDiscoveryResult(directory=str(root), files=files, total_files=len(files))
        return payload.model_dump()

# ---------------------------
# ContentLoaderTool (chunked reads)
# ---------------------------
class ContentLoaderToolSchema(BaseModel):
    file_path: str
    offset: int = Field(0, ge=0, description="Byte offset to start from")
    length: int = Field(20_000, ge=1, le=2_000_000, description="How many bytes to read")

class ContentLoaderTool(BaseTool):
    name: str = Field(default="Content Loader Tool")
    description: str = Field(default="Reads a slice of a file (by bytes) for large files; returns utf-8 text.")
    args_schema = ContentLoaderToolSchema

    def _run(self, file_path: str, offset: int = 0, length: int = 20_000) -> dict:
        fp = Path(file_path)
        if not fp.exists() or not fp.is_file():
            return {"file_path": str(fp), "content": "", "start": 0, "end": 0, "ok": False, "warning": "File not found"}
        data = fp.read_bytes()
        end = min(offset + length, len(data))
        text = data[offset:end].decode("utf-8", errors="ignore")
        return {"file_path": str(fp), "content": text, "start": offset, "end": end, "ok": True}

# ---------------------------
# UniversalReferenceTool (language-agnostic ref finder)
# ---------------------------
class UniversalReferenceToolSchema(BaseModel):
    file_path: str = Field(..., description="Current file path (absolute or relative)")
    content: Optional[str] = Field(default=None, description="Optional content; reads from disk if omitted.")
    accelerate_scan: bool = Field(default=True, description="If ripgrep exists, accelerate project-wide discovery.")

class UniversalReferenceTool(BaseTool):
    name: str = Field(default="Universal Reference Tool")
    description: str = Field(
        default="Finds cross-file references (import/require/include/config reads) across languages; optional ripgrep accel."
    )
    args_schema = UniversalReferenceToolSchema

    RE_REQUIRE: ClassVar[Pattern[str]] = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
    RE_IMPORT_FROM: ClassVar[Pattern[str]] = re.compile(r"""from\s+['"]([^'"]+)['"]""")
    RE_IMPORT: ClassVar[Pattern[str]] = re.compile(r"""import\s+[^'"]+\s+from\s+['"]([^'"]+)['"]""")
    RE_TS_IMPORT: ClassVar[Pattern[str]] = re.compile(r"""import\s+['"]([^'"]+)['"]""")
    RE_JSON_READ: ClassVar[Pattern[str]] = re.compile(r"""readFileSync\s*\(\s*['"]([^'"]+\.json)['"]""")
    RE_FETCH_JSON: ClassVar[Pattern[str]] = re.compile(r"""(open|load|read)\s*\(\s*['"]([^'"]+\.json)['"]""")
    RE_PHP_INCLUDE: ClassVar[Pattern[str]] = re.compile(r"""(include|require)(_once)?\s*\(?\s*['"]([^'"]+)['"]""")
    RE_C_IMPORT: ClassVar[Pattern[str]] = re.compile(r"""#\s*include\s*["<]([^">]+)[">]""")
    RE_JAVA_IMPORT: ClassVar[Pattern[str]] = re.compile(r"""^\s*import\s+([a-zA-Z0-9_.]+);""")
    RE_SQL_FILE: ClassVar[Pattern[str]] = re.compile(r"""(SOURCE|\.read)\s+['"]([^'"]+\.sql)['"]""", re.IGNORECASE)

    def _resolve_rel(self, base: Path, ref: str) -> Optional[str]:
        if not ref or not ref.startswith("."):
            return None
        candidates = [
            base.parent / (ref + ext)
            for ext in (".js", ".ts", ".jsx", ".tsx", ".json", ".py", ".php", ".java", ".go", ".rb", ".c", ".cpp", ".h", ".html")
        ] + [base.parent / ref]
        for c in candidates:
            if c.exists():
                return str(c.resolve())
        return None

    def _scan_text(self, fp: Path, text: str) -> list[dict]:
        lines = text.splitlines()
        refs: list[dict] = []
        for i, line in enumerate(lines, start=1):
            for m in self.RE_REQUIRE.finditer(line):
                t = m.group(1); refs.append({"type": "require", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_IMPORT_FROM.finditer(line):
                t = m.group(1); refs.append({"type": "import", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_IMPORT.finditer(line):
                t = m.group(1); refs.append({"type": "import", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_TS_IMPORT.finditer(line):
                t = m.group(1); refs.append({"type": "import", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_JSON_READ.finditer(line):
                t = m.group(1); refs.append({"type": "json_read", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_FETCH_JSON.finditer(line):
                t = m.group(2); refs.append({"type": "json_read", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_PHP_INCLUDE.finditer(line):
                t = m.group(3); refs.append({"type": "php_include", "target": self._resolve_rel(fp, t) or t, "start_line": i})
            for m in self.RE_C_IMPORT.finditer(line):
                t = m.group(1); refs.append({"type": "c_include", "target": t, "start_line": i})
            for m in self.RE_JAVA_IMPORT.finditer(line):
                t = m.group(1); refs.append({"type": "java_import", "target": t, "start_line": i})
            for m in self.RE_SQL_FILE.finditer(line):
                t = m.group(2); refs.append({"type": "sql_script", "target": self._resolve_rel(fp, t) or t, "start_line": i})
        return refs

    def _rg_available(self) -> bool:
        return shutil.which("rg") is not None

    def _rg_scan(self, root: Path, patterns: list[str]) -> list[str]:
        cmd = ["rg", "--no-messages", "--hidden", "--smart-case", "-l"]
        cmd += [p for pat in patterns for p in ["-e", pat]]
        cmd.append(str(root))
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if out.returncode not in (0, 1):
                return []
            return [line.strip() for line in out.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _run(self, file_path: str, content: Optional[str] = None, accelerate_scan: bool = True) -> dict:
        fp = Path(file_path).resolve()
        if content is None:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
        refs = self._scan_text(fp, content)

        project_refs: list[str] = []
        if accelerate_scan and self._rg_available():
            project_refs = self._rg_scan(fp.parent, [
                r"\brequire\s*\(", r"\bimport\b", r"readFileSync", r"\binclude\b|\brequire\b",
                r"#\s*include", r"\bSOURCE\b|\.\s*read\s+['\"].*\.sql['\"]",
            ])
        return {"file": str(fp), "references": refs, "accelerated_candidates": project_refs}

# ---------------------------
# ContextExtractionTool (now safe on missing files)
# ---------------------------
class ContextExtractionToolSchema(BaseModel):
    file_path: str
    symbols: Optional[list[str]] = None
    lines: Optional[list[int]] = None
    window: int = Field(20, ge=1, le=500)

class ContextExtractionTool(BaseTool):
    name: str = Field(default="Context Extraction Tool")
    description: str = Field(default="Extracts minimal, relevant context snippets near suspicious lines/symbols.")
    args_schema = ContextExtractionToolSchema

    def _run(self, file_path: str, symbols: Optional[list[str]] = None, lines: Optional[list[int]] = None, window: int = 20) -> dict:
        try:
            fp = Path(file_path)
            abs_fp = fp if fp.is_absolute() else (Path.cwd() / fp)
            exists = abs_fp.exists() and abs_fp.is_file()
        except Exception:
            abs_fp = Path(file_path)
            exists = False

        if not exists:
            return {"snippets": [], "ok": False, "warning": f"File not found: {abs_fp}"}

        try:
            content = abs_fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            return {"snippets": [], "ok": False, "warning": f"Failed to read file: {abs_fp} ({e})"}

        snippets: list[ContextSnippet] = []

        if lines:
            for ln in lines:
                start = max(ln - window, 1)
                end = min(ln + window, len(content))
                snippet = "\n".join(content[start - 1 : end])
                if snippet.strip():
                    snippets.append(ContextSnippet(file_path=str(abs_fp), snippet=snippet, start_line=start, end_line=end))

        if symbols:
            joined = "\n".join(content)
            for sym in symbols:
                idx = joined.find(sym)
                if idx >= 0:
                    ln = max(len(joined[:idx].splitlines()), 1)
                    start = max(ln - window, 1)
                    end = min(ln + window, len(content))
                    snippet = "\n".join(content[start - 1 : end])
                    if snippet.strip():
                        snippets.append(ContextSnippet(file_path=str(abs_fp), symbol=sym, snippet=snippet, start_line=start, end_line=end))

        # dedupe
        uniq, seen = [], set()
        for s in snippets:
            h = _sha1(f"{s.file_path}:{s.start_line}:{s.end_line}:{s.snippet[:120]}")
            if h in seen:
                continue
            seen.add(h)
            uniq.append(s)

        return {"snippets": [s.model_dump() for s in uniq], "ok": True}

# ---------------------------
# TerminalCommandTool
# ---------------------------
class TerminalCommandToolSchema(BaseModel):
    command: str

class TerminalCommandTool(BaseTool):
    name: str = Field(default="Terminal Command Tool")
    description: str = Field(default="Executes terminal commands with a short timeout.")
    args_schema = TerminalCommandToolSchema

    def _run(self, command: str) -> dict:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return {"command": command, "return_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "success": result.returncode == 0}
        except subprocess.TimeoutExpired:
            return {"command": command, "return_code": -1, "stdout": "", "stderr": "Command timed out", "success": False}
        except Exception as e:
            return {"command": command, "return_code": -1, "stdout": "", "stderr": str(e), "success": False}

# ---------------------------
# VulnerabilityJSONWriter (v2-safe)
# ---------------------------
class VulnerabilityJSONWriterSchema(BaseModel):
    out_dir: str
    converged: dict  # validated to ConvergedFinding inside

class VulnerabilityJSONWriter(BaseTool):
    name: str = Field(default="Vulnerability JSON Writer")
    description: str = Field(default="Saves a single converged vulnerability result to JSON (1 file per vuln).")
    args_schema = VulnerabilityJSONWriterSchema

    def _run(self, out_dir: str, converged: dict) -> dict:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        try:
            conv = ConvergedFinding.model_validate(converged)
            payload = VulnerabilityJSON.from_converged(conv)
            safe_name = (f"{Path(payload.file).name}_{payload.vulnerability_type}".replace(" ", "_").replace("/", "_").replace("\\", "_"))
            fp = Path(out_dir) / f"{safe_name}.json"
            fp.write_text(payload.model_dump_json(indent=2), encoding="utf-8")
            return {"path": str(fp), "ok": True}
        except ValidationError as ve:
            return {"ok": False, "error": ve.errors()}

# ---------------------------
# AggregateMarkdownWriter
# ---------------------------
class AggregateMarkdownWriterSchema(BaseModel):
    json_dir: str
    out_path: str = Field("security_output/report.md")

class AggregateMarkdownWriter(BaseTool):
    name: str = Field(default="Aggregate Markdown Writer")
    description: str = Field(default="Combines all per-vuln JSON files into a single report.md with summaries and details.")
    args_schema = AggregateMarkdownWriterSchema

    def _run(self, json_dir: str, out_path: str = "security_output/report.md") -> dict:
        jd = Path(json_dir)
        vulns: list[VulnerabilityJSON] = []
        for jf in jd.glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                vulns.append(VulnerabilityJSON.model_validate(data))
            except Exception:
                continue

        by_type: dict[str, int] = {}
        for v in vulns:
            by_type[v.vulnerability_type] = by_type.get(v.vulnerability_type, 0) + 1

        summary = {"total_files_analyzed": 0, "total_findings": len(vulns), "by_type": by_type}
        agg = AggregateMarkdown.model_validate({"summary": summary, "vulnerabilities": [v.model_dump() for v in vulns]})

        lines: list[str] = [
            "# Security Analysis Report", "", "## Executive Summary",
            f"- Total findings: **{agg.summary.total_findings}**",
        ]
        if agg.summary.by_type:
            lines.append("- Findings by type:")
            for k, v in agg.summary.by_type.items():
                lines.append(f"  - {k}: {v}")
        lines.append("")
        lines.append("## Detailed Findings")
        for v in agg.vulnerabilities:
            lines.append(f"### {v.vulnerability_type} — `{v.file}`")
            if v.poc:
                lines.append(f"- **PoC(s):**")
                lines += [f"  - {p}" for p in v.poc]
            lines.append(f"- **Confidence:** {v.confidence}")
            if v.edge_cases:
                lines.append(f"- **Edge cases:** " + ", ".join(v.edge_cases))
            if v.suggested_fixes:
                lines.append(f"- **Suggested fixes:**")
                lines += [f"  - {s}" for s in v.suggested_fixes]
            if v.dataflow_info:
                lines.append(f"- **Dataflow:** `{json.dumps(v.dataflow_info)}`")
            lines.append("")

        outp = Path(out_path)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text("\n".join(lines), encoding="utf-8")
        return {"path": str(outp), "count": len(vulns), "ok": True}
