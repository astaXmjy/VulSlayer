# security_tasks.py
from __future__ import annotations

import json
from crewai import Task
from config import SecurityAnalysisConfig
from models import (
    FileDiscoveryResult,
    FindingsList,
    ConvergedFinding,
    ReportArtifacts,
    VulnFinding,
)

MAX_ITERATIONS = SecurityAnalysisConfig.MAX_DEEPDIVE_ITER


class SecurityTasks:
    def __init__(self, target_directory: str = "."):
        self.target_directory = target_directory

    # 1) Inventory
    def file_discovery_task(self, agents):
        agent = agents.create_file_discovery_agent()
        return Task(
            description=(
                f"Enumerate source and relevant support files in {self.target_directory} "
                f"(by extension: code + html + json/yaml) and return a Pydantic-serializable "
                f"FileDiscoveryResult. Do not analyze; only list files and metadata."
            ),
            agent=agent,
            expected_output="JSON-serializable object matching FileDiscoveryResult schema.",
            output_pydantic=FileDiscoveryResult,
        )

    # 2) Initial vulnerability analysis
    def vulnerability_analysis_task(self, agents):
        agent = agents.create_vulnerability_analyzer_agent()
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

PERSISTENCE (MANDATORY):
- After assembling the full FindingsList, call JSON Blob Writer with:
    out_path="security_output/first_pass_findings.json"
    payload=<the exact FindingsList object>
- This file will be used to spawn per-vulnerability deep-dive tasks.

Output the FindingsList as your final answer as well.
""".strip(),
            agent=agent,
            expected_output="List of VulnFinding in a strict schema (wrapped).",
            output_pydantic=FindingsList,
        )

    # 3) Per-vulnerability deep-dive task factory
    def deepdive_per_finding_task(self, agents, finding: VulnFinding):
        """
        Creates a Task that processes ONE VulnFinding, converges it, and persists:
          - simplified per-vuln JSON to security_output/vulns/
          - full ConvergedFinding JSON to security_output/converged/
        """
        agent = agents.create_deepdive_agent()
        finding_json = json.dumps(finding.model_dump(), indent=2)
        return Task(
            description=f"""
You are given ONE vulnerability to refine and converge, then persist artifacts.

INPUT FINDING (strict JSON):
{finding_json}

GOALS:
- Iterate (up to {MAX_ITERATIONS}) using UniversalReferenceTool + ContextExtractionTool to chase context-of-context.
- Build a ConvergedFinding for this single vulnerability (include lineage of DeepDivePass items).
- PERSIST artifacts:
    1) Simplified per-vuln JSON: call Vulnerability JSON Writer with
          out_dir="security_output/vulns"
          converged=<your ConvergedFinding>
    2) Full converged JSON: call JSON Blob Writer with
          out_path="security_output/converged/<file_basename>_<vuln_type>.json"
          payload=<your ConvergedFinding>

RULES:
- Only use existing, discovered file paths. Do not invent 'path/to/...' placeholders.
- Keep snippets minimal; never dump entire files.

Return the SINGLE ConvergedFinding as your final answer.
""".strip(),
            agent=agent,
            expected_output="A single ConvergedFinding (strict Pydantic).",
            output_pydantic=ConvergedFinding,
        )

    # 4) Per-converged data-flow task factory
    def dataflow_per_converged_task(self, agents, converged: ConvergedFinding):
        agent = agents.create_dataflow_analyzer_agent()
        conv_json = json.dumps(converged.model_dump(), indent=2)
        return Task(
            description=f"""
You are given ONE ConvergedFinding to enrich with data flow (Source→Propagation→Sink) and persist.

INPUT CONVERGED FINDING (strict JSON):
{conv_json}

GOALS:
- Analyze data flow (source, propagation steps, sink), trust boundaries, potential control-flow hijacks.
- Update the ConvergedFinding accordingly.
- PERSIST simplified per-vuln JSON: call Vulnerability JSON Writer with
      out_dir="security_output/dataflow"
      converged=<your ENRICHED ConvergedFinding>

RULES:
- Use minimal necessary snippets; only operate on existing paths.

Return the SINGLE, ENRICHED ConvergedFinding as your final answer.
""".strip(),
            agent=agent,
            expected_output="A single ConvergedFinding (strict Pydantic) with dataflow_info populated.",
            output_pydantic=ConvergedFinding,
        )

    # 5) Report from deep-dive JSONs
    def report_generation_task(self, agents):
        agent = agents.create_report_generator_agent()
        return Task(
            description="""
Read ALL per-vulnerability JSONs from security_output/vulns/ and create an aggregate
Markdown report at security_output/report.md using AggregateMarkdownWriter.
Do NOT derive from raw model output; derive strictly from JSON files to ensure reproducibility.

Also return the list of JSON paths used and the final report path.
""".strip(),
            agent=agent,
            expected_output="Paths to the deep-dive JSON files and the final report.md.",
            output_pydantic=ReportArtifacts,
        )
