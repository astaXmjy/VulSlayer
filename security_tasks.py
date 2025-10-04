# security_tasks.py
from __future__ import annotations

from crewai import Task
from config import SecurityAnalysisConfig
from models import VulnFinding, DeepDivePass, ConvergedFinding
from security_agents import SecurityAgents

MAX_ITERATIONS = SecurityAnalysisConfig.MAX_DEEPDIVE_ITER

class SecurityTasks:
    def __init__(self, target_directory: str = "."):
        self.target_directory = target_directory
        self.agents = SecurityAgents()

    def file_discovery_task(self):
        agent = self.agents.create_file_discovery_agent()
        return Task(
            description=(
                f"Enumerate source and relevant support files in {self.target_directory} "
                f"(by extension: code + html + json/yaml) and return a Pydantic-serializable "
                f"FileDiscoveryResult. Do not analyze; only list files and metadata."
            ),
            agent=agent,
            expected_output="JSON-serializable dict matching FileDiscoveryResult schema.",
        )

    def vulnerability_analysis_task(self):
        agent = self.agents.create_vulnerability_analyzer_agent()
        return Task(
            description="""
RULES:
- Only operate on files returned by File Discovery (use the exact absolute paths from FileDiscoveryResult.files[].path).
- Never invent or guess file paths. If a referenced file cannot be resolved to an existing path, skip it and continue.

Using only LLM reasoning (no static pattern matching), scan each discovered file's content
and propose a list of VulnFinding objects.

Must DO:
1) Use ContentLoaderTool to read large files in chunks when needed (avoid loading entire huge files).
2) Call UniversalReferenceTool to extract referenced files (import/require/include/config reads).
3) For each referenced file, call ContextExtractionTool to fetch a MINIMAL snippet
   around the relevant reference lines; add those as related_context.
4) Keep only the smallest necessary context windows; do NOT paste entire files.

For each finding include:
- vulnerability_type, file, code_snippet, optional line_number,
- potential impact, confidence [0..1],
- poc list, edge_cases list, suggested_fixes,
- minimal related_context (ContextSnippet[]).

Also check:
- HTML/templates for XSS (e.g., direct innerHTML/unsafe DOM sinks).
- middleware/auth for hardcoded secrets and naive/timing-sensitive comparisons.
- logging utilities for concatenation of user-supplied strings and config-driven toggles.
""".strip(),
            agent=agent,
            expected_output="List[dict] matching VulnFinding schema.",
        )

    def deepdive_iteration_task(self):
        agent = self.agents.create_deepdive_agent()
        return Task(
            description=f"""
RULES:
- Only call tools with existing, discovered file paths. Do not invent 'path/to/...' placeholders.
- If UniversalReferenceTool returns a target that does not exist, skip it.

For each VulnFinding, run iterative refinement passes.

In each pass, return DeepDivePass with:
- updated_dataflow_info, new_context, updated_pocs, updated_suggested_fixes,
  updated_confidence, notes.

If a snippet references another file (import/require/include or JSON/config read),
call UniversalReferenceTool on the current file/snippet, then use ContextExtractionTool
to pull a minimal snippet from EACH newly identified referenced file; repeat until no new
context is discovered OR after {MAX_ITERATIONS} iterations.

Produce a final ConvergedFinding per input finding, with lineage of DeepDivePass items.
""".strip(),
            agent=agent,
            expected_output="List[dict] matching ConvergedFinding schema.",
        )

    def dataflow_analysis_task(self):
        agent = self.agents.create_dataflow_analyzer_agent()
        return Task(
            description="""
For each vulnerability, analyze data flow:
- Source → Propagation → Sink paths
- Trust boundaries crossed
- Potential control-flow hijacks
Use any context collected across files (file → file → config) to build an accurate chain.

Return updated ConvergedFinding objects with dataflow_info populated.
""".strip(),
            agent=agent,
            expected_output="List[dict] matching ConvergedFinding schema, with dataflow_info.",
        )

    def report_generation_task(self):
        agent = self.agents.create_report_generator_agent()
        return Task(
            description="""
Write one JSON file per vulnerability (VulnerabilityJSON) and then create an aggregate
Markdown report (report.md) combining them, including summaries, PoCs, snippets, fixes,
and confidence. Ensure complete inclusion of all per-vuln JSONs.
""".strip(),
            agent=agent,
            expected_output="Paths to created JSON files and the final report.md.",
        )
