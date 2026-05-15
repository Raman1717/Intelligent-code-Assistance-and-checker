"""
MAIN MODULE
===========
Controls the full security analysis pipeline:
  1. ASTEngine       - Parses code and builds AST
  2. SecurityChecker - Runs security checks
  3. BanditRunner    - Runs external Bandit scanner
  4. MergeFilter     - Merges and deduplicates all findings

Severity Levels:
  HIGH   → Exploitable vulnerabilities (RCE, injection, data breach)
  MEDIUM → Security weaknesses / risky coding practices
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from astengine import ASTEngine
from security import SecurityChecker
from tools import BanditRunner
from merge_filter import MergeFilter


# ------------------------------------------------
# Severity label helpers
# ------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1}

SEV_LABEL = {
    "HIGH":   "HIGH  ",   # padded for alignment
    "MEDIUM": "MEDIUM",
}


# ------------------------------------------------
# Pipeline
# ------------------------------------------------

def run_analysis(code, filename):
    print()
    print("=" * 55)
    print("  Running Security Analysis:", filename)
    print("=" * 55)

    # Step 1: Parse code
    print()
    print("[1/4] Parsing code...")
    engine = ASTEngine()
    result = engine.parse_code(code)

    if not result.get("valid"):
        err = result.get("syntax_error", {})
        print("   Error: Syntax error at line", err.get("line"), "-", err.get("message"))
        return {
            "filename": filename,
            "syntax_valid": False,
            "syntax_error": err,
            "total_issues": 0,
            "high_count": 0,
            "medium_count": 0,
            "final_issues": [],
            "metrics": {},
        }

    metrics = engine.calculate_metrics()
    print("   OK -", metrics["lines_of_code"], "lines,",
          metrics["function_count"], "functions,",
          metrics["class_count"], "classes")

    # Step 2: Run SecurityChecker
    print()
    print("[2/4] Running SecurityChecker...")
    checker = SecurityChecker(engine)
    security_issues = checker.run_all_checks()
    print("   SecurityChecker found", len(security_issues), "issue(s)")

    # Step 3: Run Bandit
    print()
    print("[3/4] Running Bandit scanner...")
    bandit = BanditRunner()
    bandit_issues = bandit.run(code)
    print("   Bandit found", len(bandit_issues), "issue(s)")

    # Step 4: Merge and deduplicate
    print()
    print("[4/4] Merging and deduplicating findings...")
    merger = MergeFilter()
    merged = merger.merge_all(security_issues + bandit_issues)
    print("   Final unique issues:", merged["total_issues"],
          "  [HIGH:", merged["high_count"],
          "| MEDIUM:", merged["medium_count"], "]")

    return {
        "filename": filename,
        "syntax_valid": True,
        "syntax_error": None,
        "total_issues": merged["total_issues"],
        "high_count": merged["high_count"],
        "medium_count": merged["medium_count"],
        "final_issues": merged["final_issues"],
        "metrics": metrics,
    }


# ------------------------------------------------
# Save Report to TXT
# ------------------------------------------------

def save_txt_report(result):

    report_path = Path("security_report.txt")

    with open(report_path, "w", encoding="utf-8") as f:

        f.write("=" * 60 + "\n")
        f.write("PYTHON SECURITY ANALYSIS REPORT\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"File         : {result['filename']}\n")
        f.write(f"Syntax Valid : {result['syntax_valid']}\n")

        if not result["syntax_valid"]:
            err = result["syntax_error"]
            f.write(f"Syntax Error at line {err.get('line')} - {err.get('message')}\n")
            return

        m = result["metrics"]
        f.write(f"Lines of Code: {m.get('lines_of_code')}\n")
        f.write(f"Functions    : {m.get('function_count')}\n")
        f.write(f"Classes      : {m.get('class_count')}\n")
        f.write(f"Max Complexity: {m.get('max_complexity')}\n")

        # ── Severity Summary ──────────────────────────────────
        f.write("\n" + "=" * 60 + "\n")
        f.write("SEVERITY SUMMARY\n")
        f.write("=" * 60 + "\n\n")

        total   = result["total_issues"]
        high    = result["high_count"]
        medium  = result["medium_count"]

        f.write(f"  Total Issues  : {total}\n\n")
        f.write(f"  {'Severity':<10}  {'Count':>5}  {'Description'}\n")
        f.write(f"  {'-'*10}  {'-'*5}  {'-'*42}\n")
        f.write(f"  {'HIGH':<10}  {high:>5}  Exploitable (RCE / injection / data breach)\n")
        f.write(f"  {'MEDIUM':<10}  {medium:>5}  Weakness / risky coding practice\n")

        if not result["final_issues"]:
            f.write("\nNo vulnerabilities detected.\n")
            return

        # ── High Severity Section ─────────────────────────────
        high_issues = [i for i in result["final_issues"] if i.get("severity") == "HIGH"]
        medium_issues = [i for i in result["final_issues"] if i.get("severity") == "MEDIUM"]

        if high_issues:
            f.write("\n\n" + "=" * 60 + "\n")
            f.write(f"HIGH SEVERITY  ({len(high_issues)} issue(s))\n")
            f.write("Exploitable vulnerabilities — RCE, injection, data breach\n")
            f.write("=" * 60 + "\n")
            _write_issues_block(f, high_issues)

        # ── Medium Severity Section ───────────────────────────
        if medium_issues:
            f.write("\n\n" + "=" * 60 + "\n")
            f.write(f"MEDIUM SEVERITY  ({len(medium_issues)} issue(s))\n")
            f.write("Security weaknesses / risky coding practices\n")
            f.write("=" * 60 + "\n")
            _write_issues_block(f, medium_issues)

        f.write("\n" + "=" * 60 + "\n")

    print("\nReport saved to:", report_path.resolve())


def _write_issues_block(f, issues):
    """Write a list of issues into the txt report file."""
    for i, issue in enumerate(issues, 1):

        sources = issue.get("sources", [])
        source  = "+".join(s.upper() for s in sources) if sources else "?"
        sev     = issue.get("severity", "MEDIUM")
        rule    = issue.get("rule", "")
        line    = issue.get("line", "?")
        msg     = issue.get("message", "")
        tip     = issue.get("suggestion", "")
        snip    = issue.get("code_snippet", "")

        f.write(f"\n  [{i}] [{sev}] [{source}] Line {line}  ---  {rule}\n")
        f.write(f"  Message    : {msg}\n")

        if tip:
            f.write(f"  Suggestion : {tip}\n")

        if snip:
            f.write("\n  Code Snippet:\n")
            for ln in snip.splitlines():
                f.write("    " + ln + "\n")

        f.write("  " + "-" * 56 + "\n")


# ------------------------------------------------
# Report Printer (Console)
# ------------------------------------------------

def print_report(result):

    print()
    print("=" * 55)
    print("  SECURITY ANALYSIS REPORT")
    print("=" * 55)

    print("  File         :", result["filename"])
    print("  Syntax Valid :", result["syntax_valid"])

    if not result["syntax_valid"]:
        err = result["syntax_error"]
        print("  Syntax Error at line", err.get("line"), "-", err.get("message"))
        return

    m = result["metrics"]
    print("  Lines        :", m.get("lines_of_code", "?"))
    print("  Functions    :", m.get("function_count", "?"),
          " | Classes:", m.get("class_count", "?"),
          " | Max Complexity:", m.get("max_complexity", "?"))

    # ── Severity Summary ──────────────────────────────────────
    print()
    print("  " + "-" * 53)
    print("  SEVERITY SUMMARY")
    print("  " + "-" * 53)
    print(f"  {'Severity':<10}  {'Count':>5}  Description")
    print(f"  {'-'*10}  {'-'*5}  {'-'*32}")
    print(f"  {'HIGH':<10}  {result['high_count']:>5}  Exploitable vulnerabilities")
    print(f"  {'MEDIUM':<10}  {result['medium_count']:>5}  Weaknesses / risky practices")
    print(f"  {'TOTAL':<10}  {result['total_issues']:>5}")
    print("  " + "-" * 53)

    if not result["final_issues"]:
        print("\n  No security issues found!\n")
        return

    # ── High Severity ─────────────────────────────────────────
    high_issues   = [i for i in result["final_issues"] if i.get("severity") == "HIGH"]
    medium_issues = [i for i in result["final_issues"] if i.get("severity") == "MEDIUM"]

    if high_issues:
        print()
        print("  " + "=" * 53)
        print(f"  HIGH SEVERITY  ({len(high_issues)} issue(s))")
        print("  " + "=" * 53)
        _print_issues_block(high_issues)

    # ── Medium Severity ───────────────────────────────────────
    if medium_issues:
        print()
        print("  " + "=" * 53)
        print(f"  MEDIUM SEVERITY  ({len(medium_issues)} issue(s))")
        print("  " + "=" * 53)
        _print_issues_block(medium_issues)

    print()
    print("=" * 55)
    print()


def _print_issues_block(issues):
    """Print a list of issues to the console."""
    for i, issue in enumerate(issues, 1):

        sources = issue.get("sources", [])
        source  = "+".join(s.upper() for s in sources) if sources else "?"
        sev     = issue.get("severity", "MEDIUM")
        rule    = issue.get("rule", "")
        line    = issue.get("line", "?")
        msg     = issue.get("message", "")
        tip     = issue.get("suggestion", "")
        snip    = issue.get("code_snippet", "")

        print()
        print(f"  [{i}] [{sev}] [{source}] Line {line}  ---  {rule}")
        print(f"       {msg}")

        if tip:
            print(f"       Suggestion: {tip}")

        if snip:
            print()
            for ln in snip.splitlines():
                print("       ", ln)


# ------------------------------------------------
# Entry Point
# ------------------------------------------------

def main():

    print("=" * 55)
    print("  Python Security Analyzer")
    print("=" * 55)

    file_path = input("\nEnter path to Python file to analyze: ").strip().strip('"').strip("'")

    path = Path(file_path)

    if not path.exists():
        print("  Error: File not found:", path)
        sys.exit(1)

    if path.suffix != ".py":
        print("  Warning: not a .py file, analysing anyway.")

    code = path.read_text(encoding="utf-8", errors="ignore")

    result = run_analysis(code, str(path))

    print_report(result)

    # Save detailed txt report
    save_txt_report(result)

    sys.exit(1 if result["total_issues"] > 0 else 0)


if __name__ == "__main__":
    main()