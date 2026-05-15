"""
BANDIT RUNNER MODULE
=====================
Runs Bandit for security analysis
Fixed for venv + Windows encoding
"""

import os
import json
import subprocess
import tempfile
import sys
from typing import List, Dict


class BanditRunner:
    """Runs Bandit security analyzer"""

    def __init__(self):
        self.available = self._detect_bandit()
        self.code_lines = []

    # ------------------------------------------------
    # Detect Bandit
    # ------------------------------------------------
    def _detect_bandit(self) -> bool:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="ignore"
            )
            if result.returncode in (0, 1):
                print("   ✓ Bandit detected")
                return True
        except Exception:
            pass

        print("   ✗ Bandit not detected")
        return False

    # ------------------------------------------------
    # Run Bandit
    # ------------------------------------------------
    def run(self, code: str) -> List[Dict]:
        self.code_lines = code.split("\n")

        with tempfile.NamedTemporaryFile(
            suffix=".py",
            delete=False,
            mode="w",
            encoding="utf-8"
        ) as f:
            f.write(code)
            path = f.name

        try:
            if not self.available:
                print("   ⚠ Bandit not available")
                return []

            return self._run_bandit(path)

        finally:
            try:
                os.remove(path)
            except Exception:
                pass

    # ------------------------------------------------
    # Internal Bandit Execution
    # ------------------------------------------------
    def _run_bandit(self, path: str) -> List[Dict]:
        print("   → Running Bandit security scanner...")

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bandit",
                    path,
                    "-f",
                    "json"
                ],
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="ignore"
            )

            if not result.stdout.strip():
                print("   ✓ Bandit: No issues found")
                return []

            data = json.loads(result.stdout)
            issues = []

            for item in data.get("results", []):
                line = item.get("line_number", 0)

                issues.append({
                    "line": line,
                    "rule": item.get("test_id", ""),
                    "message": item.get("issue_text", ""),
                    "source": "bandit",
                    "suggestion": self._get_suggestion(item.get("test_id", "")),
                    "code_snippet": self._get_code_snippet(line)
                })

            print(f"   ✓ Bandit found {len(issues)} issues")
            return issues

        except Exception as e:
            print(f"   ✗ Bandit error: {str(e)[:200]}")
            return []

    # ------------------------------------------------
    # Code Snippet
    # ------------------------------------------------
    def _get_code_snippet(self, line: int, context: int = 1) -> str:
        if not self.code_lines or line < 1:
            return ""

        start = max(0, line - context - 1)
        end = min(len(self.code_lines), line + context)

        snippet = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            snippet.append(prefix + self.code_lines[i])

        return "\n".join(snippet)

    # ------------------------------------------------
    # Suggestions
    # ------------------------------------------------
    def _get_suggestion(self, test_id: str) -> str:
        suggestions = {
            "B301": "Avoid pickle - use json instead",
            "B303": "Use SHA256 or stronger instead of MD5",
            "B311": "Use secrets module instead of random",
            "B602": "Avoid shell=True",
            "B608": "Use parameterized queries to prevent SQL injection",
        }