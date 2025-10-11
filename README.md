# vulReaper – LLM-Driven, Explainable AppSec Scanner

`vulReaper` is a language-agnostic, explainable security scanner built on **CrewAI** (agents + tasks) and **Pydantic v2** (strict, validated outputs). It discovers code, reasons about vulnerabilities, **pulls minimal cross-file context** (file → file → config), iterates until convergence, and emits **one JSON per finding** plus an aggregate `report.md`.

## ✨ Highlights

- **Language-agnostic context chasing:** follows `import/require/include` and config reads across JS/TS, Python, PHP, Java/C/C++, etc.
- **Explainable artifacts:** per-vuln JSON (with PoCs, fixes, confidence, dataflow), and a readable Markdown report.
- **Robust agents:** guardrails avoid made-up paths, tools fail gracefully, and deep-dives converge within limits.
- **Pydantic v2 clean:** `model_validate` / `model_dump_json` everywhere; deterministic shapes for agents and tools.
- **Scales to big repos:** glob includes/excludes, size caps, chunked file reads, optional `ripgrep` acceleration.

---

## 🗂️ Project Structure

```
.
├─ config.py                 # LLM + global settings (model, temperature, extensions, limits)
├─ models.py                 # Pydantic v2 schemas for all agent/tool I/O
├─ security_tools.py         # Tools (discovery, content, reference, context, writers)
├─ security_agents.py        # Agent definitions + tool wiring
├─ security_tasks.py         # Task prompts and expected outputs (the pipeline)
├─ security_crew.py          # Orchestrator: builds crew, wires dependencies, runs analysis
├─ simple_analysis.py        # Thin wrapper to run the scanner on a project path
└─ security_output/          # Generated JSONs + report.md + raw audit
```

---

## ⚙️ Requirements

- Python 3.10+
- A Mistral API key (set in `.env`)
- Optional: `ripgrep` (`rg`) on PATH to accelerate reference discovery (not required)

### Install

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

pip install -U pip
pip install crewai python-dotenv
```

### Configure `.env`

Create a `.env` in the project root:

```
MISTRAL_API_KEY=YOUR_KEY
MISTRAL_MODEL=codestral-2501
MISTRAL_TEMPERATURE=0.2
MAX_DEEPDIVE_ITER=8
```

> Lower `MISTRAL_TEMPERATURE` (0.1–0.3) for crisper, less chatty outputs.

---

## 🚀 Quick Start

Scan a target directory:

```bash
# Windows
python security_crew.py "C:\path\to\your\project"

# macOS / Linux
python security_crew.py "/absolute/path/to/your/project"
```

Artifacts appear in `security_output/`:
```
security_output/
├─ <file>_<vulnerability_type>.json   # one JSON per vuln
├─ report.md                          # human-readable rollup
└─ raw_output_YYYYMMDD_HHMMSS.json    # audit blob (stringified crew output)
```

---

## 🧠 How It Works (Pipeline)

1. **File Discovery**  
   Agent: *File Discovery Specialist* → `FileSearchTool`  
   - Recursively lists files by extension (includes code + `.html`/`.json`/`.yml`) with size/line counts.  
   - Includes glob includes/excludes and size caps to keep big repos responsive.  
   - **No security logic** here—just inventory.

2. **Vulnerability Analysis**  
   Agent: *Security Vulnerability Analyst* → `ContentLoaderTool`, `UniversalReferenceTool`, `ContextExtractionTool`  
   - Reads code (chunked for large files), proposes `VulnFinding` objects (type, file, snippet, PoC, fixes, confidence, etc.).  
   - Extracts **cross-file references** (import/require/include/config reads) and pulls **minimal context** from referenced files.  
   - Guardrails: **uses only discovered paths**; never invents `path/to/...`.

3. **Deep-Dive Iteration**  
   Agent: *Vulnerability Deep-Dive Specialist* → `UniversalReferenceTool`, `ContextExtractionTool`, `ContentLoaderTool`  
   - Iteratively follows **context-of-context** (file → file → config), updates PoCs/fixes/confidence/dataflow.  
   - Stops when no new relevant context is found or **`MAX_DEEPDIVE_ITER`** reached.  
   - Emits a `ConvergedFinding` with full lineage (`DeepDivePass[]`).

4. **Data-Flow Analysis**  
   Agent: *Data Flow Analysis Expert* → `UniversalReferenceTool`, `ContextExtractionTool`, `ContentLoaderTool`  
   - Annotates `ConvergedFinding.dataflow_info`: **Source → Propagation → Sink**, trust boundaries, control-flow notes.

5. **Report Generation**  
   Agent: *Security Report Generator* → `VulnerabilityJSONWriter`, `AggregateMarkdownWriter`  
   - Writes **one JSON per vulnerability** (stable shape).  
   - Produces a combined `report.md` (counts, per-vuln details, PoCs, fixes, confidence).

---

## 🧾 Data Models (Pydantic v2)

Key schemas in `models.py`:

- `VulnFinding`
  ```py
  file: str
  vulnerability_type: str
  code_snippet: str
  line_number: int | None
  impact: str | None
  confidence: float  # 0..1
  poc: list[str]
  edge_cases: list[str]
  suggested_fixes: list[str]
  dataflow_info: dict | None
  related_context: list[ContextSnippet]
  ```

- `ContextSnippet` — minimal window from any file (can be a second/third hop).

- `DeepDivePass` → `ConvergedFinding` — refinement lineage and final result.

- `VulnerabilityJSON` — stable per-vuln JSON derived from `ConvergedFinding`.

---

## 🛠️ Tools Overview

- **FileSearchTool** — discovers files (code + templates/config), excludes vendor dirs by default, supports globs & size caps.  
- **ContentLoaderTool** — reads file slices by byte offsets (good for huge files).  
- **UniversalReferenceTool** — cross-language reference finder (imports/requires/includes/config reads). Optional `ripgrep` accel.  
- **ContextExtractionTool** — tight line windows; **gracefully handles missing files** (returns warnings, not crashes).  
- **VulnerabilityJSONWriter** — validates & writes one JSON per vulnerability.  
- **AggregateMarkdownWriter** — reads JSONs and composes `report.md`.

_All tools define `args_schema` and use Pydantic v2 (`model_validate` / `model_dump_json`)._

---

## 🧑‍💻 Agents

- `create_file_discovery_agent()`  
- `create_vulnerability_analyzer_agent()`  
- `create_deepdive_agent()`  
- `create_dataflow_analyzer_agent()`  
- `create_report_generator_agent()`

Each uses only the tools it needs (single responsibility) and runs on the LLM from `SecurityAnalysisConfig.get_llm()`.

---

## 🪜 Task Guardrails

- **Only use discovered paths.** If a referenced file can’t be resolved, skip it.  
- **Minimal context windows.** Don’t paste entire files; include just enough to justify PoCs/fixes.  
- **PoC & Fix required.** Every finding should include at least one proof-of-concept and one concrete remediation step.  
- **Convergence cap.** Stop deep-diving after `MAX_DEEPDIVE_ITER` passes.

---

## 📦 Outputs

### Per-vuln JSON (example)
```json
{
  "file": "routes/admin.js",
  "vulnerability_type": "SQL Injection",
  "context_functions": ["router.get('/user'...)"],
  "dataflow_info": {
    "source": "req.query.name",
    "propagation": ["string concat in admin.js", "db.query in utils/db.js"],
    "sink": "mysql",
    "config_touchpoints": ["config/featureFlags.json"]
  },
  "poc": ["GET /admin/user?name=' OR '1'='1"],
  "confidence": 0.9,
  "edge_cases": ["unicode quote", "empty name"],
  "suggested_fixes": ["Use parameterized queries"]
}
```

### `report.md` (snippet)
```
# Security Analysis Report

## Executive Summary
- Total findings: **7**
- Findings by type:
  - SQL Injection: 1
  - Command Injection: 1
  - Path Traversal: 1
  - Cross-Site Scripting (XSS): 1
  - Code Injection: 1
  - Weak Authentication: 1
  - Insecure Logging: 1
...
```

---

## 🧭 Examples

Scan a Node.js app (Windows path needs quotes):

```powershell
python security_crew.py "C:\Users\Ashish Yadav\Downloads\vulnerable_node_context_nesting\vulnerable_node_context_nesting"
```

Scan a POSIX path:

```bash
python security_crew.py "/home/me/projects/myservice"
```

Programmatic:

```python
from simple_analysis import ProjectSecurityScanner
scanner = ProjectSecurityScanner("/abs/path/to/repo")
result = scanner.run_security_scan()
print(result)
```

---

## 🧩 Extending

- Add languages: extend `TARGET_EXTENSIONS` in `config.py`.  
- Speed: adjust `max_size_bytes` or pass include/exclude globs to discovery.  
- New export formats: add a writer tool (e.g., SARIF/CSV/HTML).  
- Custom checks: nudge task prompts (JWT, deserialization, SSRF, etc.).

---

## 🛡️ Reliability

- Tools never crash on missing files; they return warnings.  
- Agents use only discovered paths; no placeholder paths.  
- Iterations are capped; outputs are Pydantic-validated.

---

## 🙌 Acknowledgements

- Built with **CrewAI** and **Pydantic v2**.
- Portable, language-agnostic reference mapping that works across mixed stacks.
