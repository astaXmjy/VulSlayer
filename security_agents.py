# security_agents.py
from __future__ import annotations

from crewai import Agent
from security_tools import (
    FileSearchTool,
    TerminalCommandTool,
    ContentLoaderTool,
    UniversalReferenceTool,
    ContextExtractionTool,
    VulnerabilityJSONWriter,
    AggregateMarkdownWriter,
)
from config import SecurityAnalysisConfig

class SecurityAgents:
    def __init__(self):
        self.file_search_tool = FileSearchTool()
        self.terminal_tool = TerminalCommandTool()
        self.content_loader_tool = ContentLoaderTool()
        self.ref_tool = UniversalReferenceTool()
        self.context_tool = ContextExtractionTool()
        self.json_writer = VulnerabilityJSONWriter()
        self.markdown_writer = AggregateMarkdownWriter()
        self.llm = SecurityAnalysisConfig.get_llm()

    def create_file_discovery_agent(self) -> Agent:
        return Agent(
            role="File Discovery Specialist",
            goal="Discover all source and support files to analyze",
            backstory="You comprehensively enumerate code files across languages, efficiently and accurately.",
            tools=[self.file_search_tool, self.terminal_tool],
            llm=self.llm, verbose=True, allow_delegation=False,
        )

    def create_vulnerability_analyzer_agent(self) -> Agent:
        return Agent(
            role="Security Vulnerability Analyst",
            goal="Identify true security vulnerabilities using LLM reasoning only (no static pattern matching).",
            backstory=("You read files in chunks when large, find referenced files, and attach only minimal, relevant snippets."),
            tools=[self.content_loader_tool, self.ref_tool, self.context_tool],
            llm=self.llm, verbose=True, allow_delegation=False,
        )

    def create_deepdive_agent(self) -> Agent:
        return Agent(
            role="Vulnerability Deep-Dive Specialist",
            goal="Iteratively refine each finding, following cross-file references and converging with minimal context.",
            backstory=("You trace context-of-context chains, update PoCs/fixes/confidence, and stop when no new context appears."),
            tools=[self.ref_tool, self.context_tool, self.content_loader_tool],
            llm=self.llm, verbose=True, allow_delegation=False,
        )

    def create_dataflow_analyzer_agent(self) -> Agent:
        return Agent(
            role="Data Flow Analysis Expert",
            goal="Trace data flow from source → propagation → sink using the gathered cross-file context.",
            backstory="You map trust boundaries and attack paths using minimal but sufficient evidence.",
            tools=[self.ref_tool, self.context_tool, self.content_loader_tool],
            llm=self.llm, verbose=True, allow_delegation=False,
        )

    def create_report_generator_agent(self) -> Agent:
        return Agent(
            role="Security Report Generator",
            goal="Produce per-vulnerability JSON files and an aggregate Markdown report.",
            backstory="You write concise, actionable security reports with precise evidence and fixes.",
            tools=[self.json_writer, self.markdown_writer],
            llm=self.llm, verbose=True, allow_delegation=False,
        )
