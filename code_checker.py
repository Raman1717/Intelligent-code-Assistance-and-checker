"""
INTELLIGENT CODE QUALITY ANALYZER
==================================
A unified static analysis engine with confidence-aware insights
"""
import os
import json
import time
import re
import subprocess
import tempfile
import ast
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# CORE ANALYZER - Main Controller
# ============================================================================

class CodeQualityAnalyzer:
    """Main controller that orchestrates code quality analysis"""
    
    def __init__(self):
        self.tool_runner = ToolRunner()
        self.ast_analyzer = ASTAnalyzer()
        self.scorer = QualityScorer()
        self.reporter = ReportFormatter()
        
        if self.tool_runner.available_tools:
            logger.debug(f"✓ Analyzer ready with: {', '.join(self.tool_runner.available_tools)}")
        else:
            logger.debug("⚠️ No external tools available - basic analysis only")
    
    def analyze(self, code: str, filename: str = "input.py") -> Dict[str, Any]:
        """Run comprehensive code analysis"""
        start_time = time.time()
        
        results = {
            "filename": filename,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "code_size": len(code),
            "lines_of_code": len(code.split('\n'))
        }
        
        # AST analysis (always available)
        results["ast_analysis"] = self.ast_analyzer.analyze(code)
        
        # External tools (if available)
        if self.tool_runner.available_tools:
            results["tool_results"] = self.tool_runner.run_all(code, filename)
        else:
            results["tool_results"] = None
            results["recommendation"] = "Install tools: pip install flake8 pylint bandit black"
        
        # Generate scores and summary
        results["scores"] = self.scorer.calculate_scores(results)
        results["summary"] = self._generate_summary(results)
        results["execution_time"] = time.time() - start_time
        
        return results
    
    def format_report(self, results: Dict) -> str:
        """Format analysis results as readable report"""
        return self.reporter.format(results)
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate executive summary"""
        ast_data = results.get("ast_analysis", {})
        tool_data = results.get("tool_results", {})
        scores = results.get("scores", {})
        
        # Count all issues with confidence tracking
        issues_by_confidence = {"high": 0, "medium": 0, "low": 0}
        critical_issues = []  # Changed to list to track sources
        security_issues = 0
        
        # AST issues
        for issue in ast_data.get("issues", []):
            conf = issue.get("confidence", "medium")
            issues_by_confidence[conf] = issues_by_confidence.get(conf, 0) + 1
            if issue.get("severity") == "high":
                critical_issues.append({
                    "source": "AST",
                    "message": issue.get("message", "Unknown issue"),
                    "line": issue.get("line")
                })
        
        # Tool issues
        if tool_data:
            for tool_name, tool_result in tool_data.items():
                if isinstance(tool_result, dict):
                    for issue in tool_result.get("issues", []):
                        conf = issue.get("confidence", "high")
                        issues_by_confidence[conf] = issues_by_confidence.get(conf, 0) + 1
                        if issue.get("severity") == "high":
                            critical_issues.append({
                                "source": tool_name.upper(),
                                "message": issue.get("message", "Unknown issue"),
                                "line": issue.get("line")
                            })
                        if tool_name == "bandit":
                            security_issues += 1
        
        total_issues = sum(issues_by_confidence.values())
        
        # Determine status
        overall_score = scores.get("overall", 0)
        if overall_score >= 90:
            status = "excellent"
        elif overall_score >= 70:
            status = "good"
        elif overall_score >= 50:
            status = "needs_improvement"
        else:
            status = "critical"
        
        return {
            "status": status,
            "total_issues": total_issues,
            "issues_by_confidence": issues_by_confidence,
            "critical_issues": critical_issues,  # Now includes source info
            "security_issues": security_issues,
            "recommendations": self._build_recommendations(results)
        }
    
    def _build_recommendations(self, results: Dict) -> List[str]:
        """Build actionable recommendations based on analysis"""
        recs = []
        scores = results.get("scores", {})
        tool_data = results.get("tool_results", {})
        ast_data = results.get("ast_analysis", {})
        
        # Security recommendations (highest priority)
        if scores.get("security", 100) < 70:
            recs.append("🔒 Security issues detected - review bandit findings immediately")
        
        # Code quality recommendations
        if scores.get("quality", 100) < 60:
            recs.append("📉 Code quality below standards - refactor complex functions")
        
        # AST-based specific recommendations
        for func in ast_data.get("functions", []):
            if func.get("length", 0) > 50:
                recs.append(f"✂️ Split function '{func['name']}' ({func['length']} lines) into smaller units")
                break  # Only show first to avoid spam
        
        for func in ast_data.get("functions", []):
            if func.get("args_count", 0) > 5:
                recs.append(f"📦 Reduce parameters in '{func['name']}' ({func['args_count']} params) - consider using data classes")
                break
        
        # Style recommendations
        if tool_data and "flake8" in tool_data:
            issue_count = tool_data["flake8"].get("issue_count", 0)
            if issue_count > 20:
                recs.append(f"🎨 Fix {issue_count} style issues flagged by flake8")
            elif issue_count > 5:
                recs.append("🎨 Address style issues to improve code consistency")
        
        # Formatting recommendations
        if tool_data and tool_data.get("black", {}).get("needs_formatting"):
            recs.append("✨ Run 'black .' to auto-format code")
        
        # Success message if code is good
        if not recs:
            recs.append("✅ Code quality is excellent - keep up the standards!")
        
        return recs[:5]  # Limit to top 5 recommendations


# ============================================================================
# AST ANALYZER - Deep Code Structure Analysis
# ============================================================================

class ASTAnalyzer:
    """Analyzes code structure using Abstract Syntax Tree"""
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """Perform AST-based analysis"""
        try:
            tree = ast.parse(code)
            
            issues = []
            functions = []
            classes = []
            
            for node in ast.walk(tree):
                # Analyze functions
                if isinstance(node, ast.FunctionDef):
                    func_info = self._analyze_function(node, code)
                    functions.append(func_info)
                    issues.extend(func_info.get("issues", []))
                
                # Analyze classes
                elif isinstance(node, ast.ClassDef):
                    class_info = self._analyze_class(node)
                    classes.append(class_info)
                
                # Check for bare except
                elif isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        issues.append({
                            "line": node.lineno,
                            "type": "bare_except",
                            "message": "Bare except clause - specify exception types",
                            "severity": "high",
                            "confidence": "high",
                            "source": "ast"
                        })
            
            return {
                "valid": True,
                "functions": functions,
                "classes": classes,
                "issues": issues,
                "metrics": {
                    "function_count": len(functions),
                    "class_count": len(classes)
                }
            }
        
        except SyntaxError as e:
            return {
                "valid": False,
                "syntax_error": {
                    "message": str(e),
                    "line": e.lineno,
                    "offset": e.offset
                }
            }
    
    def _analyze_function(self, node: ast.FunctionDef, code: str) -> Dict:
        """Analyze individual function"""
        lines = code.split('\n')
        
        # Calculate function length using AST
        start_line = node.lineno
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
        func_length = end_line - start_line + 1
        
        issues = []
        
        # Check function length
        if func_length > 50:
            issues.append({
                "line": start_line,
                "type": "function_too_long",
                "message": f"Function '{node.name}' is {func_length} lines (consider splitting)",
                "severity": "high",
                "confidence": "high",
                "source": "ast"
            })
        
        # Check argument count
        arg_count = len(node.args.args)
        if arg_count > 5:
            issues.append({
                "line": start_line,
                "type": "too_many_args",
                "message": f"Function '{node.name}' has {arg_count} parameters (max 5 recommended)",
                "severity": "high",
                "confidence": "high",
                "source": "ast"
            })
        
        return {
            "name": node.name,
            "line": start_line,
            "length": func_length,
            "args_count": arg_count,
            "issues": issues
        }
    
    def _analyze_class(self, node: ast.ClassDef) -> Dict:
        """Analyze individual class"""
        methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
        return {
            "name": node.name,
            "line": node.lineno,
            "methods": methods,
            "method_count": len(methods)
        }


# ============================================================================
# TOOL RUNNER - External Static Analysis Tools
# ============================================================================

class ToolRunner:
    """Runs external code analysis tools in parallel"""
    
    def __init__(self):
        self.available_tools = self._detect_tools()
    
    def _detect_tools(self) -> List[str]:
        """Detect installed analysis tools"""
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
            except:
                pass
        
        return available
    
    def run_all(self, code: str, filename: str) -> Dict[str, Any]:
        """Run all available tools in parallel"""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            temp_path = f.name
        
        try:
            results = {}
            
            # Run tools in parallel
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
                
                # Collect results
                for tool_name, future in futures.items():
                    try:
                        results[tool_name] = future.result(timeout=30)
                    except Exception as e:
                        results[tool_name] = {"status": "error", "message": str(e)}
            
            return results
        
        finally:
            try:
                os.remove(temp_path)
            except:
                pass
    
    def _run_flake8(self, filepath: str) -> Dict:
        """Run flake8 style checker"""
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
                    issues.append({
                        "line": int(match.group(1)),
                        "column": int(match.group(2)),
                        "code": code,
                        "message": match.group(4).strip(),
                        "severity": "high" if code.startswith('E') else "medium",
                        "confidence": "high",
                        "source": "flake8"
                    })
            
            return {
                "status": "clean" if not issues else "issues_found",
                "issue_count": len(issues),
                "issues": issues[:20]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _run_pylint(self, filepath: str) -> Dict:
        """Run pylint quality checker"""
        try:
            result = subprocess.run(
                ['python', '-m', 'pylint', filepath, '--score=yes', '--rcfile=/dev/null'],
                capture_output=True, text=True, timeout=30
            )
            
            # Extract score
            score_match = re.search(r'rated at ([\d.]+)/10', result.stdout)
            score = float(score_match.group(1)) if score_match else None
            
            # Parse issues
            issues = []
            for line in result.stdout.split('\n'):
                match = re.match(r'.+:(\d+):(\d+):\s*([CRWEF]\d+):\s*(.+)', line)
                if match:
                    code = match.group(3)
                    issues.append({
                        "line": int(match.group(1)),
                        "column": int(match.group(2)),
                        "code": code,
                        "message": match.group(4).strip(),
                        "severity": "high" if code.startswith('E') else "medium",
                        "confidence": "high",
                        "source": "pylint"
                    })
            
            return {
                "status": "completed",
                "score": score,
                "issue_count": len(issues),
                "issues": issues[:20]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _run_bandit(self, filepath: str) -> Dict:
        """Run bandit security scanner"""
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
                            "source": "bandit"
                        })
                except:
                    pass
            
            return {
                "status": "clean" if not issues else "vulnerabilities_found",
                "issue_count": len(issues),
                "severity_counts": severity_counts,
                "issues": issues[:15]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _run_black(self, filepath: str) -> Dict:
        """Run black formatter check"""
        try:
            result = subprocess.run(
                ['python', '-m', 'black', '--check', filepath],
                capture_output=True, text=True, timeout=15
            )
            
            return {
                "status": "formatted" if result.returncode == 0 else "needs_formatting",
                "needs_formatting": result.returncode != 0,
                "message": "Code is properly formatted" if result.returncode == 0 else "Formatting needed"
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}


# ============================================================================
# QUALITY SCORER - Weighted Scoring System
# ============================================================================

class QualityScorer:
    """Calculates weighted quality scores with calibrated ranges"""
    
    def calculate_scores(self, results: Dict) -> Dict[str, float]:
        """Calculate composite quality score"""
        scores = {}
        
        # Quality score (40% weight) - from pylint
        tool_results = results.get("tool_results", {})
        if tool_results and "pylint" in tool_results:
            pylint_score = tool_results["pylint"].get("score")
            if pylint_score is not None:
                scores["quality"] = pylint_score * 10  # Convert to 0-100
            else:
                scores["quality"] = 70  # Default
        else:
            scores["quality"] = 70
        
        # Security score (30% weight) - from bandit
        if tool_results and "bandit" in tool_results:
            bandit_data = tool_results["bandit"]
            severity = bandit_data.get("severity_counts", {})
            high = severity.get("HIGH", 0)
            medium = severity.get("MEDIUM", 0)
            
            # Deduct points for issues
            security_score = 100
            security_score -= high * 20
            security_score -= medium * 5
            scores["security"] = max(0, security_score)
        else:
            scores["security"] = 100
        
        # Style score (20% weight) - from flake8 with calibrated scale
        if tool_results and "flake8" in tool_results:
            flake8_issues = tool_results["flake8"].get("issue_count", 0)
            style_score = self._calculate_style_score(flake8_issues)
            scores["style"] = style_score
        else:
            scores["style"] = 100
        
        # Formatting score (10% weight) - from black
        if tool_results and "black" in tool_results:
            scores["formatting"] = 100 if not tool_results["black"].get("needs_formatting") else 50
        else:
            scores["formatting"] = 100
        
        # Calculate weighted overall score
        scores["overall"] = (
            scores["quality"] * 0.4 +
            scores["security"] * 0.3 +
            scores["style"] * 0.2 +
            scores["formatting"] * 0.1
        )
        
        return scores
    
    def _calculate_style_score(self, issue_count: int) -> float:
        """
        Calculate style score with realistic calibration
        Never returns 0 unless code is completely broken
        """
        if issue_count == 0:
            return 100.0
        elif issue_count <= 5:
            return 95.0 - (issue_count * 1.0)  # 90-95 range
        elif issue_count <= 20:
            return 80.0 - ((issue_count - 5) * 1.3)  # 60-80 range
        elif issue_count <= 50:
            return 50.0 - ((issue_count - 20) * 0.67)  # 30-50 range
        else:
            # For 50+ issues, approach 10 but never hit 0
            return max(10.0, 30.0 - ((issue_count - 50) * 0.4))


# ============================================================================
# REPORT FORMATTER - Clean, Readable Output
# ============================================================================

class ReportFormatter:
    """Formats analysis results into readable reports"""
    
    def format(self, results: Dict) -> str:
        """Format comprehensive report"""
        lines = [
            "=" * 80,
            "🔍 INTELLIGENT CODE QUALITY REPORT",
            f"📁 {results.get('filename', 'Unknown')}",
            "=" * 80,
            ""
        ]
        
        # Summary
        summary = results.get("summary", {})
        scores = results.get("scores", {})
        
        lines.extend(self._format_summary(summary, scores))
        
        # AST Analysis
        ast_data = results.get("ast_analysis", {})
        if ast_data.get("valid"):
            lines.extend(self._format_ast_section(ast_data))
        
        # Tool Results
        tool_data = results.get("tool_results")
        if tool_data:
            lines.extend(self._format_tool_section(tool_data))
        
        # Recommendations
        if summary.get("recommendations"):
            lines.extend(self._format_recommendations(summary["recommendations"]))
        
        lines.append(f"\n⏱️  Analysis completed in {results.get('execution_time', 0):.2f}s")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _format_summary(self, summary: Dict, scores: Dict) -> List[str]:
        """Format executive summary"""
        lines = ["📊 SUMMARY", "─" * 80]
        
        status_emoji = {
            "excellent": "✅", "good": "👍",
            "needs_improvement": "⚠️", "critical": "❌"
        }
        emoji = status_emoji.get(summary.get("status"), "ℹ️")
        
        lines.append(f"{emoji} Status: {summary.get('status', 'unknown').upper()}")
        lines.append(f"🎯 Overall Score: {scores.get('overall', 0):.1f}/100")
        lines.append(f"📝 Total Issues: {summary.get('total_issues', 0)}")
        
        # Enhanced critical issues display with sources
        critical_issues = summary.get("critical_issues", [])
        if critical_issues:
            lines.append(f"🚨 Critical Issues: {len(critical_issues)}")
            for issue in critical_issues[:3]:  # Show top 3
                source = issue.get("source", "Unknown")
                msg = issue.get("message", "Unknown issue")[:50]
                line_num = issue.get("line", "?")
                lines.append(f"    • [{source}] Line {line_num}: {msg}")
        else:
            lines.append("🚨 Critical Issues: 0")
        
        lines.append(f"🔒 Security Issues: {summary.get('security_issues', 0)}")
        lines.append("")
        
        # Score breakdown
        lines.append("📈 SCORE BREAKDOWN")
        lines.append(f"  Quality:    {scores.get('quality', 0):>5.1f}/100 (40% weight)")
        lines.append(f"  Security:   {scores.get('security', 0):>5.1f}/100 (30% weight)")
        lines.append(f"  Style:      {scores.get('style', 0):>5.1f}/100 (20% weight)")
        lines.append(f"  Formatting: {scores.get('formatting', 0):>5.1f}/100 (10% weight)")
        lines.append("")
        
        return lines
    
    def _format_ast_section(self, ast_data: Dict) -> List[str]:
        """Format AST analysis section with clearer labeling"""
        lines = ["🔬 CODE STRUCTURE (AST-based)", "─" * 80]
        
        metrics = ast_data.get("metrics", {})
        lines.append(f"  Functions: {metrics.get('function_count', 0)}")
        lines.append(f"  Classes: {metrics.get('class_count', 0)}")
        
        issues = ast_data.get("issues", [])
        if issues:
            lines.append(f"\n  Structural Issues: {len(issues)}")
            for issue in issues[:5]:
                conf_emoji = {"high": "✓", "medium": "~", "low": "?"}.get(issue.get("confidence"), "?")
                lines.append(f"    {conf_emoji} Line {issue['line']}: {issue['message'][:60]}")
        else:
            lines.append(f"\n  Structural Issues: 0")
        
        lines.append("")
        return lines
    
    def _format_tool_section(self, tool_data: Dict) -> List[str]:
        """Format external tool results"""
        lines = ["🔧 TOOL ANALYSIS", "─" * 80]
        
        for tool_name, result in tool_data.items():
            if isinstance(result, dict):
                status = result.get("status", "unknown")
                lines.append(f"  {tool_name.upper()}: {status}")
                
                if tool_name == "pylint" and result.get("score") is not None:
                    lines.append(f"    Score: {result['score']:.1f}/10")
                
                if result.get("issue_count"):
                    lines.append(f"    Issues: {result['issue_count']}")
        
        lines.append("")
        return lines
    
    def _format_recommendations(self, recommendations: List[str]) -> List[str]:
        """Format recommendations"""
        lines = ["💡 RECOMMENDATIONS", "─" * 80]
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")
        lines.append("")
        return lines


# ============================================================================
# PUBLIC API
# ============================================================================

def analyze_code(code: str, filename: str = "input.py") -> Dict[str, Any]:
    """
    Analyze Python code quality
    
    Args:
        code: Python source code to analyze
        filename: Name of the file being analyzed
        
    Returns:
        Dictionary containing analysis results
    """
    analyzer = CodeQualityAnalyzer()
    return analyzer.analyze(code, filename)


def get_report(code: str, filename: str = "input.py") -> str:
    """
    Get formatted code quality report
    
    Args:
        code: Python source code to analyze
        filename: Name of the file being analyzed
        
    Returns:
        Formatted text report
    """
    analyzer = CodeQualityAnalyzer()
    results = analyzer.analyze(code, filename)
    return analyzer.format_report(results)