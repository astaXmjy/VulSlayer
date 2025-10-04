# security_crew.py
from crewai import Crew, Process
from security_agents import SecurityAgents
from security_tasks import SecurityTasks
from config import SecurityAnalysisConfig
from pathlib import Path
from datetime import datetime
import json
from typing import List, Dict, Any


class SecurityAnalysisCrew:
    def __init__(self, target_directory: str = "."):
        self.target_directory = target_directory
        self.agents = SecurityAgents()
        self.tasks = SecurityTasks(target_directory=self.target_directory)

    def run_analysis(self):
        # Create tasks
        t_discovery = self.tasks.file_discovery_task()
        t_vuln = self.tasks.vulnerability_analysis_task()
        t_deep = self.tasks.deepdive_iteration_task()
        t_flow = self.tasks.dataflow_analysis_task()
        t_report = self.tasks.report_generation_task()

        # Wire dependencies
        t_vuln.context = [t_discovery]
        t_deep.context = [t_vuln]
        t_flow.context = [t_deep]
        t_report.context = [t_discovery, t_flow]

        crew = Crew(
            agents=[
                self.agents.create_file_discovery_agent(),
                self.agents.create_vulnerability_analyzer_agent(),
                self.agents.create_deepdive_agent(),
                self.agents.create_dataflow_analyzer_agent(),
                self.agents.create_report_generator_agent(),
            ],
            tasks=[t_discovery, t_vuln, t_deep, t_flow, t_report],
            process=Process.sequential,
            verbose=True
        )

        result = crew.kickoff()

        # Persist the full crew output as an audit artifact
        out_dir = Path("security_output")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")  # fixed format
        raw_path = out_dir / f"raw_output_{ts}.json"
        try:
            # crew returns mixed types—serialize conservatively
            raw_path.write_text(json.dumps({"result": str(result)}, indent=2), encoding="utf-8")
        except Exception:
            raw_path.write_text(str(result), encoding="utf-8")

        print(f"\nSaved artifacts under: {out_dir.resolve()}\n- {raw_path.name}")
        return result


if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Starting security analysis of directory: {target_dir}")
    crew = SecurityAnalysisCrew(target_directory=target_dir)
    crew.run_analysis()
