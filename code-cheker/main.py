"""
MAIN - CODE QUALITY ANALYZER (IMPROVED)
========================================
Fixed scoring model and better deduplication
"""
import sys
import time
from typing import Dict, Any, Set, Tuple
from v1 import ToolRunner
from v2 import SemanticAnalyzer


class CodeQualityAnalyzer:
    """Main orchestrator with improved scoring"""
    
    def __init__(self):
        self.tool_runner = ToolRunner()
        self.semantic_analyzer = SemanticAnalyzer()
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a Python file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except FileNotFoundError:
            return {"error": f"File not found: {filepath}"}
        except Exception as e:
            return {"error": f"Error reading file: {e}"}
        
        return self.analyze_code(code, filepath)
    
    def analyze_code(self, code: str, filename: str = "input.py") -> Dict[str, Any]:
        """Run comprehensive analysis"""
        start_time = time.time()
        
        results = {
            "filename": filename,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "code_size": len(code),
            "lines_of_code": len(code.split('\n'))
        }
        
        # Semantic analysis
        print("Running semantic analysis...")
        results["semantic_analysis"] = self.semantic_analyzer.analyze(code)
        
        # Tool-based analysis
        if self.tool_runner.available_tools:
            print(f"Running external tools: {', '.join(self.tool_runner.available_tools)}...")
            results["tool_results"] = self.tool_runner.run_all(code)
        else:
            print("No external tools available")
            results["tool_results"] = {}
        
        # Generate summary with smart deduplication
        results["summary"] = self._generate_summary(results)
        results["scores"] = self._calculate_scores(results)
        results["execution_time"] = time.time() - start_time
        
        return results
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary with intelligent deduplication"""
        semantic = results.get("semantic_analysis", {})
        tools = results.get("tool_results", {})
        
        # Track issues by category + line to avoid duplicates
        seen_issues: Set[Tuple[int, str]] = set()
        total_issues = 0
        issues_by_type = {"security": 0, "logic": 0, "maintainability": 0, "style": 0}
        issues_by_severity = {"high": 0, "medium": 0, "low": 0}
        critical_issues = []
        
        # PRIORITY 1: Semantic findings (most accurate)
        for finding in semantic.get("findings", []):
            line = finding.get("line", 0)
            category = finding.get("category", "unknown")
            issue_id = (line, category)
            
            if issue_id in seen_issues:
                continue
            seen_issues.add(issue_id)
            
            total_issues += 1
            issue_type = finding.get("type", "maintainability")
            severity = finding.get("severity", "medium")
            
            issues_by_type[issue_type] = issues_by_type.get(issue_type, 0) + 1
            issues_by_severity[severity] = issues_by_severity.get(severity, 0) + 1
            
            if severity == "high":
                critical_issues.append({
                    "source": "semantic",
                    "line": line,
                    "type": issue_type,
                    "severity": severity,
                    "message": finding.get("message"),
                    "suggestion": finding.get("suggestion")
                })
        
        # PRIORITY 2: Tool findings (skip semantic duplicates)
        for tool_name, tool_result in tools.items():
            if not isinstance(tool_result, dict):
                continue
            
            for issue in tool_result.get("issues", []):
                line = issue.get("line", 0)
                category = issue.get("category", "unknown")
                
                # Smart deduplication: skip if semantic already found this type at this line
                if tool_name in ["flake8", "pylint"] and category in seen_issues:
                    # Allow tool to report if it's a different category at same line
                    issue_id = (line, category)
                    if issue_id in seen_issues:
                        continue
                else:
                    issue_id = (line, category)
                
                if issue_id in seen_issues:
                    continue
                seen_issues.add(issue_id)
                
                total_issues += 1
                severity = issue.get("severity", "medium")
                issues_by_severity[severity] = issues_by_severity.get(severity, 0) + 1
                
                # Categorize by tool
                if tool_name == "bandit":
                    issues_by_type["security"] += 1
                    if severity == "high":
                        critical_issues.append({
                            "source": "bandit",
                            "line": line,
                            "type": "security",
                            "severity": severity,
                            "message": issue.get("message"),
                            "test_id": issue.get("test_id", "")
                        })
                else:
                    # Use tool's category if available
                    cat = issue.get("category", "style")
                    if cat in issues_by_type:
                        issues_by_type[cat] += 1
                    elif severity == "high":
                        issues_by_type["logic"] += 1
                        critical_issues.append({
                            "source": tool_name,
                            "line": line,
                            "type": "logic",
                            "severity": severity,
                            "message": issue.get("message"),
                            "code": issue.get("code", "")
                        })
                    elif severity == "medium":
                        issues_by_type["maintainability"] += 1
                    else:
                        issues_by_type["style"] += 1
        
        # Status determination (more balanced and forgiving)
        security_count = issues_by_type.get("security", 0)
        logic_count = issues_by_type.get("logic", 0)
        high_severity_count = issues_by_severity.get("high", 0)
        
        # More nuanced status levels
        if security_count >= 4 or high_severity_count >= 7:
            status = "critical"
        elif security_count >= 2 or high_severity_count >= 4 or logic_count >= 5:
            status = "needs_improvement"
        elif total_issues <= 8 and high_severity_count == 0:  # More forgiving
            status = "excellent"
        elif total_issues <= 20 and high_severity_count <= 1:
            status = "good"
        else:
            status = "needs_improvement"
        
        return {
            "status": status,
            "total_issues": total_issues,
            "issues_by_type": issues_by_type,
            "issues_by_severity": issues_by_severity,
            "critical_issues": sorted(critical_issues, key=lambda x: (
                0 if x['type'] == 'security' else 1,
                x.get('line', 999)
            ))[:10]
        }
    
    def _calculate_scores(self, results: Dict) -> Dict[str, float]:
        """FIXED scoring formula with proper gradient degradation"""
        tools = results.get("tool_results", {})
        summary = results.get("summary", {})
        semantic = results.get("semantic_analysis", {})
        
        scores = {}
        issues_by_severity = summary.get("issues_by_severity", {})
        issues_by_type = summary.get("issues_by_type", {})
        
        # 1. QUALITY SCORE (40% weight) - MORE FORGIVING
        # Based on: pylint score, complexity, logic issues
        if "pylint" in tools and tools["pylint"].get("score") is not None:
            base_quality = tools["pylint"]["score"] * 10
        else:
            base_quality = 85.0
        
        # Penalize high complexity (softer)
        complex_funcs = sum(1 for f in semantic.get("functions", [])
                           if f.get("complexity", {}).get("cyclomatic", 0) > 10)
        complexity_penalty = min(12, complex_funcs * 3)  # Reduced from 4
        
        # Penalize logic issues (softer)
        logic_issues = issues_by_type.get("logic", 0)
        logic_penalty = min(20, logic_issues * 5)  # Reduced from 6
        
        scores["quality"] = max(20, base_quality - complexity_penalty - logic_penalty)  # Floor at 20
        
        # 2. SECURITY SCORE (40% weight) - BALANCED FORMULA
        # Start at 100, deduct based on severity (more forgiving)
        security_issues = issues_by_type.get("security", 0)
        
        if security_issues == 0:
            scores["security"] = 100.0
        else:
            # Estimate security issues by severity
            high_count = issues_by_severity.get("high", 0)
            medium_count = issues_by_severity.get("medium", 0)
            low_count = issues_by_severity.get("low", 0)
            
            # Approximate security breakdown
            sec_high = min(security_issues, high_count)
            sec_medium = min(security_issues - sec_high, medium_count)
            sec_low = max(0, security_issues - sec_high - sec_medium)
            
            # MORE FORGIVING: HIGH = -25, MEDIUM = -12, LOW = -4
            security_deduction = (sec_high * 25) + (sec_medium * 12) + (sec_low * 4)
            scores["security"] = max(15, 100 - security_deduction)  # Floor at 15, not 0
        
        # 3. MAINTAINABILITY SCORE (10% weight) - MORE FORGIVING
        maint_issues = issues_by_type.get("maintainability", 0)
        
        if maint_issues == 0:
            scores["maintainability"] = 100.0
        else:
            # More forgiving gradient
            if maint_issues <= 5:
                scores["maintainability"] = 100 - (maint_issues * 3)  # Lose 3 per issue
            elif maint_issues <= 15:
                scores["maintainability"] = 85 - ((maint_issues - 5) * 2.5)  # Gentler slope
            else:
                scores["maintainability"] = max(30, 60 - ((maint_issues - 15) * 1.5))  # Floor at 30
        
        # 4. STYLE SCORE (10% weight)
        style_issues = issues_by_type.get("style", 0)
        
        if style_issues == 0:
            scores["style"] = 100.0
        elif style_issues <= 10:
            scores["style"] = 100 - (style_issues * 3)
        else:
            scores["style"] = max(40, 70 - ((style_issues - 10) * 2))
        
        # Black bonus
        if "black" in tools and not tools["black"].get("needs_formatting"):
            scores["style"] = min(100, scores["style"] + 5)
        
        # 5. OVERALL SCORE (weighted average)
        scores["overall"] = (
            scores["quality"] * 0.40 +
            scores["security"] * 0.40 +
            scores["maintainability"] * 0.10 +
            scores["style"] * 0.10
        )
        
        return {k: round(v, 1) for k, v in scores.items()}
    
    def format_report(self, results: Dict) -> str:
        """Generate human-readable report"""
        lines = []
        lines.append("\n" + "="*70)
        lines.append("📊 CODE QUALITY ANALYSIS REPORT")
        lines.append("="*70)
        
        lines.append(f"\n📄 File: {results.get('filename')}")
        lines.append(f"📅 Analyzed: {results.get('timestamp')}")
        lines.append(f"📏 Size: {results.get('lines_of_code')} lines, {results.get('code_size')} chars")
        
        # Scores
        scores = results.get("scores", {})
        if scores:
            lines.append("\n" + "-"*70)
            lines.append("🎯 QUALITY SCORES")
            lines.append("-"*70)
            overall = scores.get('overall', 0)
            lines.append(f"Overall:         {self._format_score(overall)}")
            lines.append(f"Quality:         {self._format_score(scores.get('quality', 0))}")
            lines.append(f"Security:        {self._format_score(scores.get('security', 0))}")
            lines.append(f"Maintainability: {self._format_score(scores.get('maintainability', 0))}")
            lines.append(f"Style:           {self._format_score(scores.get('style', 0))}")
            
            # Add interpretation note for low scores
            if overall < 50:
                lines.append(f"\n💡 Note: Scores reflect code quality issues found.")
                lines.append(f"   Lower scores indicate areas needing improvement.")
        
        # Summary
        summary = results.get("summary", {})
        if summary:
            lines.append("\n" + "-"*70)
            lines.append("📋 SUMMARY")
            lines.append("-"*70)
            
            status_icons = {
                "excellent": "✅ EXCELLENT",
                "good": "👍 GOOD",
                "needs_improvement": "⚠️  NEEDS IMPROVEMENT",
                "critical": "❌ CRITICAL"
            }
            status = summary.get("status", "unknown")
            lines.append(f"Status: {status_icons.get(status, status.upper())}")
            lines.append(f"Total Issues: {summary.get('total_issues', 0)}")
            
            by_type = summary.get("issues_by_type", {})
            by_severity = summary.get("issues_by_severity", {})
            
            lines.append(f"\nIssues by Type:")
            lines.append(f"  🔒 Security:       {by_type.get('security', 0)}")
            lines.append(f"  🐛 Logic:          {by_type.get('logic', 0)}")
            lines.append(f"  📉 Maintainability: {by_type.get('maintainability', 0)}")
            lines.append(f"  🎨 Style:          {by_type.get('style', 0)}")
            
            lines.append(f"\nIssues by Severity:")
            lines.append(f"  🔴 High:   {by_severity.get('high', 0)}")
            lines.append(f"  🟡 Medium: {by_severity.get('medium', 0)}")
            lines.append(f"  🟢 Low:    {by_severity.get('low', 0)}")
        
        # Critical issues
        critical = summary.get("critical_issues", [])
        if critical:
            lines.append("\n" + "-"*70)
            lines.append("🚨 CRITICAL ISSUES")
            lines.append("-"*70)
            for i, issue in enumerate(critical[:5], 1):
                lines.append(f"\n{i}. [{issue.get('source', 'N/A')}] Line {issue.get('line', '?')} - {issue.get('type', 'unknown').upper()}")
                lines.append(f"   {issue.get('message', 'No description')}")
                if issue.get("suggestion"):
                    lines.append(f"   💡 {issue['suggestion']}")
        
        # Semantic metrics
        semantic = results.get("semantic_analysis", {})
        if semantic and semantic.get("valid"):
            metrics = semantic.get("metrics", {})
            lines.append("\n" + "-"*70)
            lines.append("📊 CODE METRICS")
            lines.append("-"*70)
            lines.append(f"Functions: {metrics.get('function_count', 0)}")
            lines.append(f"Classes:   {metrics.get('class_count', 0)}")
            lines.append(f"Imports:   {metrics.get('import_count', 0)}")
            
            # Complex functions
            complex_funcs = [
                f for f in semantic.get("functions", [])
                if f.get("complexity", {}).get("cyclomatic", 0) > 10
            ]
            if complex_funcs:
                lines.append("\n⚠️  High Complexity Functions:")
                for func in complex_funcs[:3]:
                    complexity = func.get("complexity", {})
                    lines.append(
                        f"  • {func['name']} (line {func['line']}): "
                        f"complexity {complexity.get('cyclomatic')} "
                        f"({complexity.get('risk_level')})"
                    )
        
        # Tool results summary
        tools = results.get("tool_results", {})
        if "pylint" in tools and tools["pylint"].get("score") is not None:
            lines.append(f"\nPylint Score: {tools['pylint']['score']:.2f}/10")
        
        lines.append("\n" + "="*70)
        lines.append(f"⏱️  Completed in {results.get('execution_time', 0):.2f}s")
        lines.append("="*70 + "\n")
        
        return "\n".join(lines)
    
    def _format_score(self, score: float) -> str:
        """Format score with emoji and interpretation"""
        score_str = f"{score:5.1f}/100"
        if score >= 90:
            return f"🟢 {score_str} (Excellent)"
        elif score >= 70:
            return f"🟡 {score_str} (Good)"
        elif score >= 50:
            return f"🟠 {score_str} (Needs Work)"
        elif score >= 30:
            return f"🔴 {score_str} (Major Issues)"
        else:
            return f"🔴 {score_str} (Critical)"


def main():
    """Main entry point"""
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
    else:
        print("="*70)
        print("📊 CODE QUALITY ANALYZER")
        print("="*70)
        filepath = input("\n📁 Enter file path: ").strip()
        
        if filepath.startswith('"') and filepath.endswith('"'):
            filepath = filepath[1:-1]
        if filepath.startswith("'") and filepath.endswith("'"):
            filepath = filepath[1:-1]
        
        if not filepath:
            print("❌ No file path provided. Exiting.")
            sys.exit(1)
    
    print(f"\n🔍 Analyzing: {filepath}\n")
    
    analyzer = CodeQualityAnalyzer()
    results = analyzer.analyze_file(filepath)
    
    if "error" in results:
        print(f"❌ Error: {results['error']}")
        sys.exit(1)
    
    # Print report
    report = analyzer.format_report(results)
    print(report)
    
    # Save JSON
    import json
    json_output = filepath.replace(".py", "_analysis.json")
    with open(json_output, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"📝 Detailed results saved to: {json_output}")


if __name__ == "__main__":
    main()