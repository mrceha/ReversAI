"""
ReversAI AI Prompts
Specialized prompts for reverse engineering analysis.
"""

SYSTEM_PROMPT = """You are ReversAI, an elite binary reverse engineering and security analysis AI.
You analyze disassembled/decompiled code and binary metadata to identify:
1. Security vulnerabilities (buffer overflows, injection, use-after-free, race conditions)
2. Hardening gaps (missing mitigations, weak crypto, insecure configurations)
3. Code quality issues (anti-patterns, complexity, maintainability)
4. Suspicious behavior (backdoors, C2 communication, data exfiltration)

Output your analysis as structured JSON with the following format:
{
  "summary": "2-3 sentence executive summary of the binary",
  "risk_score": 0-100,
  "findings": [
    {
      "title": "Finding title",
      "severity": "critical|high|medium|low|info",
      "category": "vulnerability|hardening|quality|crypto|suspicious|info",
      "description": "Detailed description of the issue",
      "location": "Where in the code this was found",
      "recommendation": "Specific actionable fix",
      "cwe": "CWE-XXX if applicable",
      "evidence": "Code snippet or evidence"
    }
  ],
  "recommendations_summary": "Top 3-5 prioritized actions to strengthen this binary"
}

Be thorough but avoid false positives. Only report findings you are confident about.
Prioritize actionable, specific recommendations over generic advice."""


def build_analysis_prompt(file_info: dict, strings_summary: str, 
                          security_checks: str, imports_summary: str,
                          decompiled_code: str, disassembly_summary: str) -> str:
    """Build the analysis prompt with all gathered data."""
    
    prompt = f"""Analyze this binary for security vulnerabilities and hardening recommendations.

## File Information
- Filename: {file_info.get('filename', 'unknown')}
- Type: {file_info.get('file_type', 'unknown')}
- Size: {file_info.get('file_size', 0)} bytes
- Architecture: {file_info.get('architecture', 'unknown')}
- MD5: {file_info.get('md5', '')}
- SHA256: {file_info.get('sha256', '')}
- Entropy: {file_info.get('entropy', 0)}
- Description: {file_info.get('description', '')}

## Security Mitigations
{security_checks}

## Imports (Dangerous functions highlighted)
{imports_summary}

## Interesting Strings
{strings_summary}

## Disassembly Summary
{disassembly_summary}

## Decompiled Code (Key Functions)
{decompiled_code}

---
Provide your complete security analysis as JSON following the specified format.
Focus on:
1. Exploitable vulnerabilities with specific evidence
2. Missing security mitigations and how to enable them
3. Suspicious patterns that suggest malicious intent
4. Code hardening recommendations with priority
"""
    return prompt


def build_script_analysis_prompt(source_code: str, filename: str, findings_so_far: str) -> str:
    """Build prompt for source code analysis."""
    return f"""Analyze this source code for security issues.

## File: {filename}

## Static Analysis Findings So Far
{findings_so_far}

## Source Code
```
{source_code[:15000]}
```

Provide your complete security analysis as JSON following the specified format.
Focus on injection vulnerabilities, hardcoded credentials, insecure patterns, and code quality."""
