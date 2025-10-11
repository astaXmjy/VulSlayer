# config.py
from __future__ import annotations

import os
from typing import List
from dotenv import load_dotenv
from crewai import LLM

load_dotenv()


class SecurityAnalysisConfig:
    MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
    MISTRAL_MODEL = os.getenv("MISTRAL_MODEL", "codestral-2501")
    MISTRAL_TEMPERATURE = float(os.getenv("MISTRAL_TEMPERATURE", "0.2"))
    MAX_DEEPDIVE_ITER = int(os.getenv("MAX_DEEPDIVE_ITER", "8"))

    if not MISTRAL_API_KEY:
        raise ValueError("MISTRAL_API_KEY not found in .env file.")

    @staticmethod
    def get_llm():
        return LLM(
            model=f"mistral/{SecurityAnalysisConfig.MISTRAL_MODEL}",
            api_key=SecurityAnalysisConfig.MISTRAL_API_KEY,
            temperature=SecurityAnalysisConfig.MISTRAL_TEMPERATURE,
        )

    TARGET_EXTENSIONS: List[str] = [
        ".py", ".js", ".ts", ".java", ".kt", ".scala", ".go", ".rs", ".c", ".cpp",
        ".cs", ".php", ".rb", ".swift", ".m", ".mm",
        ".html", ".htm", ".vue", ".svelte",
        ".json", ".yaml", ".yml",
    ]

    VULNERABILITY_CATEGORIES = [
        "injection", "authentication", "authorization", "cryptography",
        "input_validation", "memory_management", "file_handling",
        "network_security", "data_exposure",
    ]
