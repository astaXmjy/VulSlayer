# integrate_with_project.py / simple_analysis.py
from security_crew import SecurityAnalysisCrew

class ProjectSecurityScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.scanner = SecurityAnalysisCrew(project_path)

    def run_security_scan(self):
        print(f"🚀 Starting security scan for: {self.project_path}")
        try:
            result = self.scanner.run_analysis()
            return {"status": "success", "project_path": self.project_path, "report": str(result)}
        except Exception as e:
            return {"status": "error", "error": str(e), "project_path": self.project_path}

if __name__ == "__main__":
    scanner = ProjectSecurityScanner(r".")
    scanner.run_security_scan()
