# security_agents.py
from __future__ import annotations

from crewai import Agent
from security_tools import (
    FileSearchTool,
    TerminalCommandTool,
    ContentLoaderTool,
    UniversalReferenceTool,
    ContextExtractionTool,
    JSONBlobWriter,            # NEW
    VulnerabilityJSONWriter,
    AggregateMarkdownWriter,
)
from config import SecurityAnalysisConfig
from models import FileDiscoveryResult, FindingsList, ConvergedList, ReportArtifacts


class SecurityAgents:
    def __init__(self):
        # discovery / shell
        self.file_search_tool = FileSearchTool()
        self.terminal_tool = TerminalCommandTool()

        # analysis helpers
        self.content_loader_tool = ContentLoaderTool()
        self.ref_tool = UniversalReferenceTool()
        self.context_tool = ContextExtractionTool()

        # writers
        self.json_blob_writer = JSONBlobWriter()
        self.json_writer = VulnerabilityJSONWriter()
        self.markdown_writer = AggregateMarkdownWriter()

        # LLM
        self.llm = SecurityAnalysisConfig.get_llm()

    def create_file_discovery_agent(self) -> Agent:
        return Agent(
            role="File Discovery Specialist",
            goal="Discover all source and support files to analyze",
            backstory="You comprehensively enumerate code files across languages, efficiently and accurately.",
            tools=[self.file_search_tool, self.terminal_tool],
            llm=self.llm, verbose=True, allow_delegation=False,
            output_pydantic=FileDiscoveryResult,
        )

    def create_vulnerability_analyzer_agent(self) -> Agent:
        return Agent(
            role="Security Vulnerability Analyst",
            goal="Identify true security vulnerabilities using LLM reasoning only.",
            backstory=("You read files in chunks when large, follow imports/requires/includes/config reads, "
                       "and attach only minimal, relevant snippets."),
            tools=[self.content_loader_tool, self.ref_tool, self.context_tool, self.json_blob_writer],
            llm=self.llm, verbose=True, allow_delegation=False,
            output_pydantic=FindingsList,
        )

    def create_deepdive_agent(self) -> Agent:
        return Agent(
            role="Vulnerability Deep-Dive Specialist",
            goal="For a single finding: converge with minimal context and persist both simplified and full JSONs.",
            backstory=("You trace context-of-context chains (file → file → config), update PoCs/fixes/confidence, "
                       "and persist artifacts immediately."),
            tools=[self.ref_tool, self.context_tool, self.content_loader_tool, self.json_writer, self.json_blob_writer],
            llm=self.llm, verbose=True, allow_delegation=False,
            # per-vuln tasks return a single ConvergedFinding (Task sets output_pydantic)
        )

    def create_dataflow_analyzer_agent(self) -> Agent:
        return Agent(
            role="Data Flow Analysis Expert",
            goal="Enrich a single converged finding with Source→Propagation→Sink and persist simplified JSON.",
            backstory="You map trust boundaries and attack paths using minimal but sufficient evidence.",
            tools=[self.ref_tool, self.context_tool, self.content_loader_tool, self.json_writer],
            llm=self.llm, verbose=True, allow_delegation=False,
            # per-vuln tasks return a single ConvergedFinding (Task sets output_pydantic)
        )

    def create_report_generator_agent(self) -> Agent:
        return Agent(
            role="Security Report Generator",
            goal="Produce an aggregate Markdown report from deep-dive JSONs.",
            backstory="You write concise, actionable security reports with precise evidence and fixes.",
            tools=[self.markdown_writer],
            llm=self.llm, verbose=True, allow_delegation=False,
            output_pydantic=ReportArtifacts,
        )
