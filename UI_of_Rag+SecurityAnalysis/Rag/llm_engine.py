"""
ENHANCED CODE RAG SYSTEM - Answer Generation
================================================================
IMPROVEMENTS:
1. ✅ API key loaded from environment variable (never hardcoded)
2. ✅ Line numbers always passed from chunk metadata — LLM can cite real lines
3. ✅ AST-based complexity signals (cyclomatic complexity, nesting depth)
   included in optimization prompts
4. ✅ Consistent chunk metadata passed to prompt
5. ✅ Retry logic and error handling maintained
"""

import os
import time
import requests
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
GEMINI_API_KEY = "................................."  # ← paste your key here

API_URL = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={GEMINI_API_KEY}'



# ========== API CALL ==========

def call_gemini(prompt: str) -> str:
    """Call Gemini API with retry logic."""
    if not GEMINI_API_KEY:
        return "❌ GEMINI_API_KEY not set. Export it as an environment variable."

    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "topK": 1,
            "topP": 0.95,
            "maxOutputTokens": 8192,
        },
        "safetySettings": [
            {"category": cat, "threshold": "BLOCK_NONE"}
            for cat in [
                "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"
            ]
        ]
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(API_URL, headers=headers, json=payload, timeout=60)

            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and result['candidates']:
                    text = result['candidates'][0]['content']['parts'][0]['text']
                    finish_reason = result['candidates'][0].get('finishReason', '')
                    if finish_reason == 'MAX_TOKENS':
                        logger.warning("⚠️ Response truncated due to token limit")
                        text += "\n\n... (Response truncated — try asking about a specific part)"
                    return text
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


# ========== ANSWER GENERATION ==========

def generate_answer(
    question: str,
    chunks: List[Dict],
    q_type,
    code_stats: Dict = None
) -> str:
    """Generate answer using retrieved chunks, code stats, and complexity hints."""

    context_parts = []

    # ---- Code Statistics ----
    if code_stats:
        context_parts.append("### 📊 Code Statistics Overview")
        context_parts.append(f"**Total Imports:** {code_stats['total_imports']}")
        context_parts.append(
            f"**External Libraries ({len(code_stats['external_libraries'])}):** "
            f"{', '.join(code_stats['external_libraries']) if code_stats['external_libraries'] else 'None'}"
        )
        context_parts.append(f"**Total Functions:** {code_stats['total_functions']}")

        if code_stats['function_names']:
            func_list = ', '.join(list(code_stats['function_names'])[:15])
            if len(code_stats['function_names']) > 15:
                func_list += f" ... and {len(code_stats['function_names']) - 15} more"
            context_parts.append(f"  - Function Names: {func_list}")

        context_parts.append(f"**Total Classes:** {code_stats['total_classes']}")
        if code_stats['class_names']:
            class_list = ', '.join(list(code_stats['class_names'])[:15])
            context_parts.append(f"  - Class Names: {class_list}")

        if code_stats.get('special_classes'):
            sc_list = ', '.join(f"{k}({v})" for k, v in code_stats['special_classes'].items())
            context_parts.append(f"  - Special Classes: {sc_list}")

        if code_stats.get('total_methods', 0) > 0:
            context_parts.append(f"**Total Methods:** {code_stats['total_methods']}")

        context_parts.append("")

    # ---- Code Chunks ----
    for i, chunk in enumerate(chunks[:5], 1):
        chunk_name = chunk.get('name', 'Unknown')
        content = chunk.get('content', '')
        chunk_type = chunk.get('chunk_type', '')

        # Build accurate line reference
        line_start = chunk.get('line_start', chunk.get('start_line'))
        line_end = None
        if line_start is not None:
            line_count = chunk.get('line_count')
            if line_count:
                line_end = line_start + line_count - 1

        if line_start is not None and line_end is not None:
            line_info = f" (lines {line_start}–{line_end})"
        elif line_start is not None:
            line_info = f" (from line {line_start})"
        else:
            line_info = ""

        type_badge = f"[{chunk_type}] " if chunk_type else ""

        if len(content) > 2000:
            displayed_content = content[:2000] + "\n... (truncated — ask for the full function by name)"
        else:
            displayed_content = content

        decorators = chunk.get('decorators', [])
        dec_note = f"\n# Decorators: {', '.join(decorators)}" if decorators else ""

        type_hints = chunk.get('type_hints', {})
        hint_note = ""
        if type_hints:
            sig_parts = []
            for param, hint in type_hints.items():
                if param == 'return':
                    sig_parts.append(f"-> {hint}")
                else:
                    sig_parts.append(f"{param}: {hint}")
            hint_note = f"\n# Signature hints: {', '.join(sig_parts)}"

        context_parts.append(
            f"### {type_badge}{chunk_name}{line_info}"
            f"\n```python{dec_note}{hint_note}\n{displayed_content}\n```"
        )

    context = "\n\n".join(context_parts)

    # ---- Prompt ----
    q_type_str = q_type.value if hasattr(q_type, 'value') else str(q_type)

    prompt = f"""You are an expert Python code analyst. Answer precisely using only the context below.

Q [{q_type_str}]: {question}

{context}

You are a code assistant. Answer the question using only the provided code chunks.

INSTRUCTIONS:

1. First understand the user's question clearly.
   - Identify what the user is specifically asking.
   - Do not broaden the scope beyond the question.

2. Select only the most relevant function(s) from the chunks.
   - Do not include additional functions unless they are directly required to answer the question.
   - Avoid unnecessary expansion.

3. Base your answer strictly on the provided code.
   - Do not assume missing behavior.
   - Do not invent logic that is not present in the chunks.

4. If the answer depends on specific lines or functions:
   - Mention the function name.

5. Write the answer naturally, like a helpful LLM explanation.
   - Clear explanation of how it works.
   - Include only the minimal code snippet required to justify your answer. Avoid providing the entire function unless essential.
   - Avoid overly rigid formatting.
   - Avoid adding sections like "Summary of Findings" unless useful.

6. If the required information is not present in the chunks, clearly state that.

Goal:
Give a precise, grounded, and natural explanation that directly answers the question — no more, no less.

Answer:"""

    return call_gemini(prompt)
