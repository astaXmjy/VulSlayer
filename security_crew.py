# security_crew.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from crewai import Crew, Process

from config import SecurityAnalysisConfig
from models import FindingsList, ConvergedFinding
from security_agents import SecurityAgents
from security_tasks import SecurityTasks


class SecurityAnalysisCrew:
    def __init__(self, target_directory: str = "."):
        self.target_directory = target_directory
        self.agents = SecurityAgents()
        self.tasks = SecurityTasks(target_directory=self.target_directory)

    def _run_crew(self, agents, tasks):
        crew = Crew(
            agents=agents,
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
        )
        return crew.kickoff()

    def run_analysis(self):
        out_root = Path("security_output"); out_root.mkdir(parents=True, exist_ok=True)

        # -------- Phase 1: Discovery + First Pass --------
        t_discovery = self.tasks.file_discovery_task(self.agents)
        t_vuln = self.tasks.vulnerability_analysis_task(self.agents)
        t_vuln.context = [t_discovery]

        self._run_crew(
            agents=[
                self.agents.create_file_discovery_agent(),
                self.agents.create_vulnerability_analyzer_agent(),
            ],
            tasks=[t_discovery, t_vuln],
        )

        # Load first-pass findings written by the analyzer task
        findings_path = out_root / "first_pass_findings.json"
        if not findings_path.exists():
            raise RuntimeError(f"First pass findings not found at {findings_path}. "
                               f"Ensure the analyzer task called JSON Blob Writer as instructed.")

        findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = FindingsList.model_validate(findings_data).items

        # -------- Phase 2: Per-Finding Deep-Dive (each its own Task) --------
        deep_tasks = [self.tasks.deepdive_per_finding_task(self.agents, f) for f in findings]
        self._run_crew(
            agents=[self.agents.create_deepdive_agent()],
            tasks=deep_tasks,
        )
        # As a byproduct, each deep-dive task has written:
        #   - simplified JSONs to security_output/vulns/
        #   - full converged JSONs to security_output/converged/

        # Gather converged findings from disk (full objects) for data-flow phase
        converged_dir = out_root / "converged"
        converged_dir.mkdir(parents=True, exist_ok=True)
        converged_items: List[ConvergedFinding] = []
        for jf in converged_dir.glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                converged_items.append(ConvergedFinding.model_validate(data))
            except Exception:
                continue

        # -------- Phase 3: Per-Converged Data-Flow (each its own Task) --------
        flow_tasks = [self.tasks.dataflow_per_converged_task(self.agents, cf) for cf in converged_items]
        if flow_tasks:
            self._run_crew(
                agents=[self.agents.create_dataflow_analyzer_agent()],
                tasks=flow_tasks,
            )

        # -------- Phase 4: Report from deep-dive JSONs --------
        t_report = self.tasks.report_generation_task(self.agents)
        self._run_crew(
            agents=[self.agents.create_report_generator_agent()],
            tasks=[t_report],
        )

        # Save orchestration log
        raw_path = out_root / f"raw_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            raw_path.write_text(json.dumps({"status": "ok"}, indent=2), encoding="utf-8")
        except Exception:
            raw_path.write_text("ok", encoding="utf-8")

        print(f"\nSaved artifacts under: {out_root.resolve()}\n- {raw_path.name}")
        return {"output_dir": str(out_root.resolve())}


if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Starting security analysis of directory: {target_dir}")
    crew = SecurityAnalysisCrew(target_directory=target_dir)
    crew.run_analysis()
