"""
V1 - TOOL-BASED FOUNDATION (IMPROVED)
======================================
Wrapper for external static analysis tools with better deduplication
"""
import os
import re
import json
import subprocess
import tempfile
from typing import Dict, Any, List, Set, Tuple
from concurrent.futures import ThreadPoolExecutor


class ToolRunner:
    """Runs external code quality tools in parallel"""
    
    def __init__(self):
        self.available_tools = self._detect_tools()
    
    def _detect_tools(self) -> List[str]:
        """Check which tools are installed"""
        tools = {
            'flake8': ['python', '-m', 'flake8', '--version'],
            'pylint': ['python', '-m', 'pylint', '--version'],
            'bandit': ['python', '-m', 'bandit', '--version'],
            'black': ['python', '-m', 'black', '--version']
        }
        
        available = []
        for name, cmd in tools.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
                if result.returncode in [0, 1]:
                    available.append(name)
            except Exception:
                pass
        
        return available
    
    def run_all(self, code: str) -> Dict[str, Any]:
        """Run all available tools on the code"""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            temp_path = f.name
        
        try:
            results = {}
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}
                
                if 'flake8' in self.available_tools:
                    futures['flake8'] = executor.submit(self._run_flake8, temp_path)
                if 'pylint' in self.available_tools:
                    futures['pylint'] = executor.submit(self._run_pylint, temp_path)
                if 'bandit' in self.available_tools:
                    futures['bandit'] = executor.submit(self._run_bandit, temp_path)
                if 'black' in self.available_tools:
                    futures['black'] = executor.submit(self._run_black, temp_path)
                
                for tool_name, future in futures.items():
                    try:
                        results[tool_name] = future.result(timeout=30)
                    except Exception as e:
                        results[tool_name] = {"status": "error", "message": str(e)}
            
            return results
        finally:
            try:
                os.remove(temp_path)
            except Exception:
                pass
    
    def _run_flake8(self, filepath: str) -> Dict:
        """Run flake8 with smart severity mapping"""
        try:
            result = subprocess.run(
                ['python', '-m', 'flake8', filepath, '--max-line-length=100'],
                capture_output=True, text=True, timeout=20
            )
            
            issues = []
            for line in result.stdout.split('\n'):
                match = re.match(r'.+:(\d+):(\d+):\s*([A-Z]\d+)\s*(.+)', line)
                if match:
                    code = match.group(3)
                    
                    # Smart severity mapping - softer for style issues
                    if code.startswith('E9') or code in ['E711', 'E712', 'E721', 'E722']:
                        severity = "high"
                    elif code.startswith('F') and code not in ['F401', 'F841']:  # F401=unused import, F841=unused var
                        severity = "high"  # Undefined names, etc.
                    elif code in ['F401', 'F841']:  # Unused imports/vars
                        severity = "low"  # Not dangerous, just cleanup
                    elif code.startswith('E') and code not in ['E501', 'E231', 'E226', 'E302', 'E303', 'E305']:
                        severity = "medium"
                    else:
                        severity = "low"
                    
                    issues.append({
                        "line": int(match.group(1)),
                        "column": int(match.group(2)),
                        "code": code,
                        "message": match.group(4).strip(),
                        "severity": severity,
                        "confidence": "high",
                        "source": "flake8",
                        "category": self._categorize_flake8(code)
                    })
            
            return {
                "status": "clean" if not issues else "issues_found",
                "issue_count": len(issues),
                "issues": issues
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _categorize_flake8(self, code: str) -> str:
        """Categorize flake8 codes"""
        if code.startswith('F') and code not in ['F401']:  # F401 = unused import
            return "logic"
        elif code in ['E501', 'W291', 'W292', 'W293', 'E231', 'E226', 'F401']:
            return "style"
        else:
            return "maintainability"
    
    def _run_pylint(self, filepath: str) -> Dict:
        """Run pylint with correct parsing"""
        try:
            result = subprocess.run(
                ['python', '-m', 'pylint', filepath, '--score=yes', '--output-format=text'],
                capture_output=True, text=True, timeout=30
            )
            
            combined_output = result.stdout + result.stderr
            score_match = re.search(r'rated at ([\d.]+)/10', combined_output)
            score = float(score_match.group(1)) if score_match else None
            
            issues = []
            for line in combined_output.split('\n'):
                pattern = r'.+:(\d+):(\d+):\s*([CRWEF]\d+):\s*(.+?)(?:\s*\([\w-]+\))?$'
                match = re.match(pattern, line)
                
                if match:
                    code = match.group(3)
                    msg = match.group(4).strip()
                    
                    # Softer severity mapping for pylint
                    if code.startswith('E'):  # Error (logic/runtime)
                        severity = "high"
                    elif code.startswith('W'):  # Warning (potential bugs)
                        severity = "medium"
                    elif code.startswith('R'):  # Refactor (design)
                        severity = "low"  # Changed from medium - refactoring suggestions aren't urgent
                    elif code.startswith('C'):  # Convention (style)
                        severity = "low"
                    else:  # F (fatal)
                        severity = "high"
                    
                    issues.append({
                        "line": int(match.group(1)),
                        "column": int(match.group(2)),
                        "code": code,
                        "message": msg,
                        "severity": severity,
                        "confidence": "high",
                        "source": "pylint",
                        "category": self._categorize_pylint(code)
                    })
            
            return {
                "status": "completed",
                "score": score,
                "issue_count": len(issues),
                "issues": issues
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _categorize_pylint(self, code: str) -> str:
        """Categorize pylint codes"""
        if code.startswith('E'):
            return "logic"
        elif code.startswith('W'):
            return "maintainability"
        elif code.startswith('R'):
            return "maintainability"
        else:
            return "style"
    
    def _run_bandit(self, filepath: str) -> Dict:
        """Run bandit security checks"""
        try:
            result = subprocess.run(
                ['python', '-m', 'bandit', '-r', filepath, '-f', 'json', '-q'],
                capture_output=True, text=True, timeout=20
            )
            
            issues = []
            severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for item in data.get("results", []):
                        severity = item.get("issue_severity", "LOW")
                        severity_counts[severity] += 1
                        
                        issues.append({
                            "line": item.get("line_number"),
                            "severity": severity.lower(),
                            "confidence": item.get("issue_confidence", "MEDIUM").lower(),
                            "test_id": item.get("test_id"),
                            "message": item.get("issue_text", ""),
                            "code_snippet": item.get("code", "").strip(),
                            "source": "bandit",
                            "category": "security"
                        })
                except Exception:
                    pass
            
            return {
                "status": "clean" if not issues else "vulnerabilities_found",
                "issue_count": len(issues),
                "severity_counts": severity_counts,
                "issues": issues
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _run_black(self, filepath: str) -> Dict:
        """Check black formatting"""
        try:
            result = subprocess.run(
                ['python', '-m', 'black', '--check', filepath],
                capture_output=True, text=True, timeout=15
            )
            
            return {
                "status": "formatted" if result.returncode == 0 else "needs_formatting",
                "needs_formatting": result.returncode != 0,
                "message": "Properly formatted" if result.returncode == 0 else "Formatting needed"
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}