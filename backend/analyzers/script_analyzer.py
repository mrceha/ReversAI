"""
ReversAI Script Analyzer
Analyzes source code files (Python, Shell, JavaScript, etc.).
"""

import ast
import re
from backend.models.schemas import Finding, Severity


DANGEROUS_PYTHON_CALLS = {
    'eval': ('Arbitrary code execution via eval()', Severity.CRITICAL),
    'exec': ('Arbitrary code execution via exec()', Severity.CRITICAL),
    'compile': ('Dynamic code compilation', Severity.HIGH),
    'os.system': ('Shell command execution', Severity.HIGH),
    'os.popen': ('Shell command execution', Severity.HIGH),
    'subprocess.call': ('Subprocess execution — check for injection', Severity.MEDIUM),
    'subprocess.Popen': ('Subprocess execution — check for injection', Severity.MEDIUM),
    'subprocess.run': ('Subprocess execution — check for shell=True', Severity.MEDIUM),
    'pickle.loads': ('Deserialization vulnerability — arbitrary code execution', Severity.CRITICAL),
    'pickle.load': ('Deserialization vulnerability — arbitrary code execution', Severity.CRITICAL),
    'yaml.load': ('Unsafe YAML loading — use yaml.safe_load()', Severity.HIGH),
    'marshal.loads': ('Unsafe deserialization', Severity.HIGH),
    '__import__': ('Dynamic import — potential for code injection', Severity.MEDIUM),
    'input': ('Python 2 input() executes code — use raw_input()', Severity.MEDIUM),
}

DANGEROUS_SHELL_PATTERNS = [
    (r'curl\s+.*\|\s*(?:bash|sh|zsh)', 'Pipe to shell — remote code execution risk', Severity.CRITICAL),
    (r'wget\s+.*\|\s*(?:bash|sh|zsh)', 'Pipe to shell — remote code execution risk', Severity.CRITICAL),
    (r'chmod\s+777', 'World-writable permissions', Severity.HIGH),
    (r'chmod\s+\+s', 'SUID bit set — privilege escalation risk', Severity.HIGH),
    (r'eval\s+', 'Shell eval — code injection risk', Severity.HIGH),
    (r'\$\(.*\)', 'Command substitution — check for injection', Severity.MEDIUM),
    (r'`.*`', 'Backtick command substitution — check for injection', Severity.MEDIUM),
    (r'rm\s+-rf\s+/', 'Dangerous recursive delete from root', Severity.CRITICAL),
    (r'>(?: |/dev/null)\s*2>&1', 'Output suppression — may hide errors', Severity.LOW),
]

CREDENTIAL_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', 'Hardcoded password', Severity.CRITICAL),
    (r'(?:api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key', Severity.CRITICAL),
    (r'(?:secret|token)\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret/token', Severity.HIGH),
    (r'(?:aws_access_key|AWS_ACCESS_KEY)\s*=\s*["\'][A-Z0-9]{16,}["\']', 'AWS key detected', Severity.CRITICAL),
    (r'(?:ssh-rsa|ssh-ed25519)\s+\S{20,}', 'SSH key in source', Severity.HIGH),
]


def analyze_python(filepath: str) -> list[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        # AST analysis
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ''
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            func_name = f'{node.func.value.id}.{node.func.attr}'
                    if func_name in DANGEROUS_PYTHON_CALLS:
                        desc, sev = DANGEROUS_PYTHON_CALLS[func_name]
                        findings.append(Finding(
                            title=f"Dangerous call: {func_name}()",
                            severity=sev, category="vulnerability",
                            description=desc,
                            location=f"Line {node.lineno}",
                            recommendation=f"Review usage of {func_name}() and consider safer alternatives.",
                        ))
        except SyntaxError:
            findings.append(Finding(
                title="Syntax Error in Python file",
                severity=Severity.INFO, category="quality",
                description="Could not parse Python AST — file may have syntax errors.",
            ))
        # Credential patterns
        for pattern, desc, sev in CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[:match.start()].count('\n') + 1
                findings.append(Finding(
                    title=desc, severity=sev, category="credential",
                    description=f"Found: {match.group()[:80]}...",
                    location=f"Line {line_num}",
                    recommendation="Use environment variables or a secrets manager instead of hardcoded credentials.",
                ))
    except Exception as e:
        findings.append(Finding(
            title="Script Analysis Error", severity=Severity.INFO, category="info",
            description=str(e),
        ))
    return findings


def analyze_shell(filepath: str) -> list[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        for pattern, desc, sev in DANGEROUS_SHELL_PATTERNS:
            for match in re.finditer(pattern, source):
                line_num = source[:match.start()].count('\n') + 1
                findings.append(Finding(
                    title=desc, severity=sev, category="vulnerability",
                    description=f"Found: {match.group()[:100]}",
                    location=f"Line {line_num}",
                    recommendation="Review this pattern for potential security issues.",
                ))
        for pattern, desc, sev in CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[:match.start()].count('\n') + 1
                findings.append(Finding(
                    title=desc, severity=sev, category="credential",
                    description=f"Found: {match.group()[:80]}",
                    location=f"Line {line_num}",
                    recommendation="Use environment variables instead.",
                ))
    except Exception as e:
        findings.append(Finding(
            title="Script Analysis Error", severity=Severity.INFO,
            category="info", description=str(e),
        ))
    return findings


def analyze_script(filepath: str, file_type: str) -> list[Finding]:
    if file_type == 'python':
        return analyze_python(filepath)
    return analyze_shell(filepath)
