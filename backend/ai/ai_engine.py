"""
ReversAI AI Engine
Orchestrates AI analysis using OpenAI or Anthropic.
"""

import json
import re
from backend.config import Config
from backend.ai.prompts import SYSTEM_PROMPT, build_analysis_prompt, build_script_analysis_prompt
from backend.models.schemas import Finding, Severity


def _parse_ai_response(response_text: str) -> dict:
    """Parse AI JSON response, handling markdown code blocks."""
    text = response_text.strip()
    # Remove markdown code blocks
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return {"summary": response_text[:500], "findings": [], "risk_score": 0}


async def analyze_with_openai(prompt: str) -> dict:
    """Send analysis to OpenAI."""
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=Config.OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model=Config.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
            response_format={"type": "json_object"},
        )
        return _parse_ai_response(response.choices[0].message.content)
    except Exception as e:
        return {"summary": f"OpenAI error: {str(e)}", "findings": [], "risk_score": 0}


async def analyze_with_anthropic(prompt: str) -> dict:
    """Send analysis to Anthropic Claude."""
    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=Config.ANTHROPIC_API_KEY)
        response = await client.messages.create(
            model=Config.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        return _parse_ai_response(text)
    except Exception as e:
        return {"summary": f"Anthropic error: {str(e)}", "findings": [], "risk_score": 0}


async def run_ai_analysis(prompt: str) -> dict:
    """Run AI analysis using the configured provider."""
    provider = Config.get_active_provider()
    if provider == "openai":
        return await analyze_with_openai(prompt)
    elif provider == "anthropic":
        return await analyze_with_anthropic(prompt)
    return {
        "summary": "No AI API key configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env file.",
        "findings": [],
        "risk_score": 0,
        "recommendations_summary": "Configure an AI provider for intelligent analysis."
    }


def convert_ai_findings(ai_result: dict) -> tuple[list[Finding], str, int]:
    """Convert AI response findings to Finding objects."""
    findings = []
    severity_map = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }
    for f in ai_result.get("findings", []):
        findings.append(Finding(
            title=f.get("title", "Untitled"),
            severity=severity_map.get(f.get("severity", "info"), Severity.INFO),
            category=f.get("category", "info"),
            description=f.get("description", ""),
            location=f.get("location", ""),
            recommendation=f.get("recommendation", ""),
            cwe=f.get("cwe", ""),
            evidence=f.get("evidence", ""),
        ))
    summary = ai_result.get("summary", "")
    if ai_result.get("recommendations_summary"):
        summary += "\n\n**Top Recommendations:**\n" + ai_result["recommendations_summary"]
    risk_score = min(100, max(0, int(ai_result.get("risk_score", 0))))
    return findings, summary, risk_score
