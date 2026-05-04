"""
ReversAI String Analyzer
Extracts and categorizes interesting strings from binaries.
"""

import re
import subprocess
from backend.models.schemas import StringResult


# Patterns for categorizing strings
PATTERNS = {
    'url': re.compile(r'https?://[^\s\x00"\'<>]{5,200}', re.IGNORECASE),
    'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'),
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'path_win': re.compile(r'[A-Z]:\\(?:[^\\\s\x00]{1,50}\\){1,10}[^\\\s\x00]{1,50}'),
    'path_unix': re.compile(r'(?:/[a-zA-Z0-9._-]{1,50}){2,10}'),
    'registry': re.compile(r'HKEY_[A-Z_]+\\[^\s\x00]{5,200}', re.IGNORECASE),
    'credential': re.compile(
        r'(?:password|passwd|pwd|secret|token|api_key|apikey|auth|credential)'
        r'\s*[=:]\s*\S+', re.IGNORECASE
    ),
    'crypto': re.compile(
        r'(?:AES|RSA|DES|MD5|SHA[0-9]*|HMAC|CBC|ECB|BEGIN\s+(?:RSA\s+)?(?:PUBLIC|PRIVATE)\s+KEY)',
        re.IGNORECASE
    ),
    'sql': re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.{5,100}',
        re.IGNORECASE
    ),
    'suspicious': re.compile(
        r'(?:cmd\.exe|/bin/sh|/bin/bash|powershell|eval\s*\(|exec\s*\(|system\s*\(|'
        r'ShellExecute|CreateProcess|VirtualAlloc|WriteProcessMemory|'
        r'NtCreateThread|LoadLibrary|GetProcAddress)',
        re.IGNORECASE
    ),
}

# Minimum string length for general extraction
MIN_STRING_LENGTH = 6


def extract_strings_raw(filepath: str, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    """Extract printable strings from a binary using the `strings` command."""
    try:
        result = subprocess.run(
            ['strings', '-n', str(min_length), filepath],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except Exception:
        # Fallback: manual extraction
        return _extract_strings_manual(filepath, min_length)


def _extract_strings_manual(filepath: str, min_length: int) -> list[str]:
    """Manually extract printable ASCII strings from binary data."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception:
        return []

    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_length:
        strings.append(''.join(current))
    
    return strings


def categorize_string(s: str) -> str:
    """Categorize a string based on pattern matching."""
    for category, pattern in PATTERNS.items():
        if pattern.search(s):
            return category.replace('path_win', 'path').replace('path_unix', 'path')
    return 'other'


def analyze_strings(filepath: str, max_strings: int = 500) -> list[StringResult]:
    """Extract and categorize strings from a file."""
    raw_strings = extract_strings_raw(filepath)
    
    results = []
    seen = set()
    
    # First pass: categorized (interesting) strings — always include
    for s in raw_strings:
        if s in seen or len(s) > 500:
            continue
        category = categorize_string(s)
        if category != 'other':
            seen.add(s)
            results.append(StringResult(value=s, category=category))
    
    # Second pass: fill up with generic strings if under limit
    for s in raw_strings:
        if len(results) >= max_strings:
            break
        if s in seen or len(s) > 500 or len(s) < 8:
            continue
        seen.add(s)
        results.append(StringResult(value=s, category='other'))
    
    return results[:max_strings]
