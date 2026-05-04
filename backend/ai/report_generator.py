"""
ReversAI Report Generator
Compiles all analysis results into a final report.
"""

import dataclasses
from datetime import datetime
from backend.models.schemas import (
    AnalysisReport, FileInfo, Finding, SecurityCheck, Severity,
    StringResult, FunctionInfo, ImportInfo
)


def calculate_risk_score(security_checks: list[SecurityCheck],
                         findings: list[Finding],
                         ai_risk_score: int) -> int:
    """Calculate overall risk score (0-100)."""
    score = 0
    
    # Security mitigations (up to 30 points)
    disabled_checks = [c for c in security_checks if c.status in ("disabled", "violated")]
    score += min(30, len(disabled_checks) * 5)
    
    # Findings severity (up to 50 points)
    severity_weights = {
        Severity.CRITICAL: 15, Severity.HIGH: 10,
        Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0,
    }
    for f in findings:
        score += severity_weights.get(f.severity, 0)
    score = min(80, score)
    
    # Blend with AI score
    if ai_risk_score > 0:
        score = int(score * 0.6 + ai_risk_score * 0.4)
    
    return min(100, max(0, score))


def compile_report(
    session_id: str,
    file_info: FileInfo,
    strings: list[StringResult],
    functions: list[FunctionInfo],
    security_checks: list[SecurityCheck],
    imports: list[ImportInfo],
    static_findings: list[Finding],
    ai_findings: list[Finding],
    ai_summary: str,
    ai_risk_score: int,
    duration: float,
) -> AnalysisReport:
    """Compile all results into a final report."""
    
    # Merge findings, deduplicate by title
    all_findings = []
    seen_titles = set()
    
    # AI findings first (usually more detailed)
    for f in ai_findings:
        if f.title not in seen_titles:
            seen_titles.add(f.title)
            all_findings.append(f)
    
    # Then static findings
    for f in static_findings:
        if f.title not in seen_titles:
            seen_titles.add(f.title)
            all_findings.append(f)
    
    # Add findings for dangerous imports
    for imp in imports:
        if imp.is_dangerous:
            title = f"Dangerous import: {imp.function}"
            if title not in seen_titles:
                seen_titles.add(title)
                all_findings.append(Finding(
                    title=title,
                    severity=Severity.MEDIUM,
                    category="suspicious",
                    description=f"{imp.risk_note} (from {imp.library})",
                    location=f"Import table: {imp.library}",
                    recommendation=f"Review usage of {imp.function}() for security implications.",
                ))
    
    # Sort by severity
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    
    risk_score = calculate_risk_score(security_checks, all_findings, ai_risk_score)
    
    return AnalysisReport(
        session_id=session_id,
        filename=file_info.filename,
        file_info=file_info,
        strings=strings[:200],  # Cap for report size
        functions=functions,
        security_checks=security_checks,
        imports=imports,
        findings=all_findings,
        ai_summary=ai_summary,
        risk_score=risk_score,
        analysis_duration=round(duration, 2),
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
