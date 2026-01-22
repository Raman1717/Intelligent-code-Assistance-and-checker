"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 4: Answer Generation (FIXED)
Contains: Gemini API call, prompt construction, retry & error handling
"""
import time
import requests
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
API_KEY = ".........................................."
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
                # FIXED: Use .get() and handle both 'status' and 'overall_status' keys
                status = summary.get('status', summary.get('overall_status', 'unknown')).lower()
                emoji = status_emoji.get(status, "ℹ️")
                context_parts.append(f"**Overall Status:** {emoji} {status.upper()}")
                
                # FIXED: Use .get() with default values to prevent KeyError
                context_parts.append(f"**Total Issues:** {summary.get('total_issues', 0)}")
                context_parts.append(f"**Critical Issues:** {summary.get('critical_issues', 0)}")
            
            # Add specific issues from tools
            if "pylint" in code_check_report and isinstance(code_check_report["pylint"], dict):
                pylint = code_check_report["pylint"]
                if pylint.get("score") is not None:
                    context_parts.append(f"\n**Code Quality Score (Pylint):** {pylint['score']}/10")
                    if pylint.get("issues") and len(pylint["issues"]) > 0:
                        context_parts.append(f"**Top Pylint Issues:**")
                        for issue in pylint["issues"][:3]:
                            context_parts.append(f"- Line {issue.get('line', 'N/A')}: {issue.get('code', 'N/A')} - {issue.get('message', 'N/A')}")
            
            if "bandit" in code_check_report and isinstance(code_check_report["bandit"], dict):
                bandit = code_check_report["bandit"]
                if bandit.get("severity_high", 0) > 0:
                    context_parts.append(f"\n**Security Issues (Bandit):** {bandit['severity_high']} high severity issues")
                    if bandit.get("issues") and len(bandit["issues"]) > 0:
                        context_parts.append("**Top Security Issues:**")
                        for issue in bandit["issues"][:3]:
                            if issue.get("severity") == "HIGH":
                                context_parts.append(f"- Line {issue.get('line', 'N/A')}: {issue.get('message', 'N/A')}")
            
            if "flake8" in code_check_report and isinstance(code_check_report["flake8"], dict):
                flake8 = code_check_report["flake8"]
                if flake8.get("issue_count", 0) > 0:
                    context_parts.append(f"\n**Style Issues (Flake8):** {flake8['issue_count']} issues")
                    if flake8.get("issues") and len(flake8["issues"]) > 0:
                        context_parts.append("**Top Style Issues:**")
                        for issue in flake8["issues"][:3]:
                            context_parts.append(f"- Line {issue.get('line', 'N/A')}: {issue.get('code', 'N/A')} - {issue.get('message', 'N/A')}")
        
        context_parts.append("\n")
    
    # ============ IMPROVED CHUNK PRESENTATION ============
    # Add code chunks with better formatting and NO truncation for small chunks
    for i, chunk in enumerate(chunks[:3], 1):  # Limit to 3 chunks for context
        chunk_name = chunk.get('name', 'Unknown')
        content = chunk.get('content', '')
        
        # Smart truncation: only truncate if really large
        if len(content) > 1500:
            displayed_content = content[:1500] + "\n... (truncated)"
        else:
            displayed_content = content
        
        # Add line number info if available
        line_info = ""
        if 'start_line' in chunk and 'end_line' in chunk:
            line_info = f" (lines {chunk['start_line']}-{chunk['end_line']})"
        elif 'line' in chunk:
            line_info = f" (line {chunk['line']})"
        
        context_parts.append(
            f"### {chunk_name}{line_info}\n"
            f"```python\n{displayed_content}\n```"
        )
    
    context = "\n\n".join(context_parts)
    
    # ============ IMPROVED PROMPT ============
    prompt = f"""You are an expert Python code analyst. Answer the question based on the provided code and analysis.

**Question:** {question}

**Question Type:** {q_type.value}

**Code Context:**
{context}

**CRITICAL INSTRUCTIONS:**
1. Answer DIRECTLY and CONCISELY based on the code chunks shown above
2. Reference code elements by their NAME (function/class/variable name), NOT by invented line numbers
3. If line numbers are provided in chunk headers, you MAY reference them. Otherwise, DO NOT invent line numbers
4. Use bullet points only when listing multiple items
5. Quote relevant code snippets directly from the chunks when helpful
6. If security or quality issues are mentioned, address them specifically
7. If code checker tools are not installed, acknowledge this limitation
8. Keep answer focused and under 400 words

**Format your answer like this:**
- Start with a direct answer to the question
- Reference specific code elements by name (e.g., "in the `transaction_details` function...")
- Only cite line numbers if they were explicitly provided in the chunk headers above
- Provide code examples from the chunks when helpful
- End with any important caveats or recommendations

**Answer:**"""
    
    return call_gemini(prompt)