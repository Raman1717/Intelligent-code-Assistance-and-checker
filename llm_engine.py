"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 4: Answer Generation
Contains: Gemini API call, prompt construction, retry & error handling
"""
import time
import requests
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
API_KEY = "........................................"
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"


def call_gemini(prompt: str) -> str:
    """Call Gemini API with retry logic"""
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "topK": 1,
            "topP": 0.95,
            "maxOutputTokens": 2048,
        },
        "safetySettings": [
            {"category": cat, "threshold": "BLOCK_NONE"}
            for cat in ["HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH", 
                       "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"]
        ]
    }
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(API_URL, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and result['candidates']:
                    return result['candidates'][0]['content']['parts'][0]['text']
                return "⚠️ No response generated"
            
            elif response.status_code == 503:
                if attempt < max_retries - 1:
                    wait = 2 * (attempt + 1)
                    logger.warning(f"Model busy, retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                return "⚠️ AI model temporarily overloaded. Please retry."
            
            elif response.status_code == 429:
                return "⚠️ Rate limit exceeded. Please wait and retry."
            
            else:
                logger.error(f"API error {response.status_code}: {response.text[:200]}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                return f"❌ API Error {response.status_code}"
                
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                logger.warning("Request timeout, retrying...")
                time.sleep(2)
                continue
            return "⚠️ Request timeout. Please retry."
        
        except Exception as e:
            logger.error(f"API call failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
                continue
            return f"❌ Error: {str(e)}"
    
    return "❌ Failed after retries"


def generate_answer(question: str, chunks: List[Dict], q_type, use_code_check: bool, code_check_report=None) -> str:
    """Generate answer using retrieved chunks and code check results"""
    
    context_parts = []
    
    # Add code checker results if relevant and available
    if use_code_check and code_check_report:
        if code_check_report.get("status") == "skipped":
            context_parts.append("### ⚠️ Code Quality Analysis (Skipped)")
            context_parts.append("Code checking tools are not installed.")
            context_parts.append("To enable full analysis, install:")
            context_parts.append("```bash\npip install flake8 pylint bandit black\n```")
        else:
            context_parts.append("### 🔍 Code Quality Analysis")
            
            if "summary" in code_check_report:
                summary = code_check_report["summary"]
                status_emoji = {
                    "excellent": "✅",
                    "minor_issues": "⚠️",
                    "needs_improvement": "🔧",
                    "critical": "❌"
                }
                emoji = status_emoji.get(summary['overall_status'], "ℹ️")
                context_parts.append(f"**Overall Status:** {emoji} {summary['overall_status'].upper()}")
                context_parts.append(f"**Total Issues:** {summary['total_issues']}")
                context_parts.append(f"**Critical Issues:** {summary['critical_issues']}")
            
            # Add specific issues from tools
            if "pylint" in code_check_report and isinstance(code_check_report["pylint"], dict):
                pylint = code_check_report["pylint"]
                if pylint.get("score") is not None:
                    context_parts.append(f"\n**Code Quality Score (Pylint):** {pylint['score']}/10")
                    # Add some specific issues if available
                    if pylint.get("issues") and len(pylint["issues"]) > 0:
                        context_parts.append(f"**Top Pylint Issues:**")
                        for issue in pylint["issues"][:3]:
                            context_parts.append(f"- Line {issue['line']}: {issue['code']} - {issue['message']}")
            
            if "bandit" in code_check_report and isinstance(code_check_report["bandit"], dict):
                bandit = code_check_report["bandit"]
                if bandit.get("severity_high", 0) > 0:
                    context_parts.append(f"\n**Security Issues (Bandit):** {bandit['severity_high']} high severity issues")
                    if bandit.get("issues") and len(bandit["issues"]) > 0:
                        context_parts.append("**Top Security Issues:**")
                        for issue in bandit["issues"][:3]:
                            if issue.get("severity") == "HIGH":
                                context_parts.append(f"- Line {issue['line']}: {issue['message']}")
            
            if "flake8" in code_check_report and isinstance(code_check_report["flake8"], dict):
                flake8 = code_check_report["flake8"]
                if flake8.get("issue_count", 0) > 0:
                    context_parts.append(f"\n**Style Issues (Flake8):** {flake8['issue_count']} issues")
                    if flake8.get("issues") and len(flake8["issues"]) > 0:
                        context_parts.append("**Top Style Issues:**")
                        for issue in flake8["issues"][:3]:
                            context_parts.append(f"- Line {issue['line']}: {issue['code']} - {issue['message']}")
        
        context_parts.append("\n")
    
    # Add code chunks
    for i, chunk in enumerate(chunks[:3], 1):  # Limit to 3 chunks for context
        context_parts.append(
            f"### Chunk {i}: {chunk['name']} ({chunk['chunk_type']})\n"
            f"```python\n{chunk['content'][:500]}{'...' if len(chunk['content']) > 500 else ''}\n```"
        )
    
    context = "\n\n".join(context_parts)
    
    # Build optimized prompt
    prompt = f"""You are an expert Python code analyst. Answer the question based on the provided code and analysis.

**Question:** {question}

**Question Type:** {q_type.value}

**Analysis Context:**
{context}

**Instructions:**
1. Be CONCISE and PRECISE
2. Reference specific functions/classes and line numbers when relevant
3. Use bullet points for clarity
4. Provide code examples for suggestions
5. If security or quality issues are mentioned, prioritize those in your answer
6. If code checker tools are not installed, mention this clearly
7. Keep answer under 400 words

**Answer:**"""
    
    return call_gemini(prompt)