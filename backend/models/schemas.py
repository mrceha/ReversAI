"""
ReversAI Pydantic Models
Data schemas for analysis results and reports.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PYTHON = "python"
    JAVA = "java"
    SCRIPT = "script"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    filename: str = ""
    file_type: FileType = FileType.UNKNOWN
    file_size: int = 0
    mime_type: str = ""
    md5: str = ""
    sha256: str = ""
    entropy: float = 0.0
    architecture: str = ""
    description: str = ""


@dataclass
class StringResult:
    value: str = ""
    category: str = "unknown"  # url, ip, path, credential, crypto, suspicious, api, other
    offset: int = 0


@dataclass
class FunctionInfo:
    name: str = ""
    address: int = 0
    size: int = 0
    disassembly: str = ""
    decompiled: str = ""
    callees: list[str] = field(default_factory=list)


@dataclass
class SecurityCheck:
    name: str = ""
    status: str = ""  # "enabled", "disabled", "unknown"
    severity: Severity = Severity.INFO
    description: str = ""
    recommendation: str = ""


@dataclass
class ImportInfo:
    library: str = ""
    function: str = ""
    is_dangerous: bool = False
    risk_note: str = ""


@dataclass
class Finding:
    title: str = ""
    severity: Severity = Severity.INFO
    category: str = ""  # vulnerability, hardening, quality, crypto, info
    description: str = ""
    location: str = ""
    recommendation: str = ""
    cwe: str = ""
    evidence: str = ""


@dataclass
class AnalysisReport:
    session_id: str = ""
    filename: str = ""
    file_info: FileInfo = field(default_factory=FileInfo)
    strings: list[StringResult] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    security_checks: list[SecurityCheck] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ai_summary: str = ""
    ai_analysis: str = ""
    risk_score: int = 0  # 0-100
    analysis_duration: float = 0.0
    timestamp: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert report to dictionary for JSON serialization."""
        import dataclasses
        
        def _convert(obj):
            if dataclasses.is_dataclass(obj):
                result = {}
                for f in dataclasses.fields(obj):
                    value = getattr(obj, f.name)
                    result[f.name] = _convert(value)
                return result
            elif isinstance(obj, list):
                return [_convert(item) for item in obj]
            elif isinstance(obj, Enum):
                return obj.value
            return obj
        
        return _convert(self)
