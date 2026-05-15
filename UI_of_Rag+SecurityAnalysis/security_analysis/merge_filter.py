from typing import List, Dict, Tuple


class MergeFilter:

    def __init__(self):
        pass

    # ------------------------------------------------
    # Normalize rules into vulnerability categories
    # ------------------------------------------------
    def _normalize_rule(self, rule: str) -> str:
        """
        Convert different scanner rules into a unified category.
        """

        rule_map = {

            # -------------------------
            # Weak Cryptography
            # -------------------------
            "weak_hash_md5": "weak_crypto",
            "weak_hash_sha1": "weak_crypto",
            "B324": "weak_crypto",
            "B303": "weak_crypto",

            # -------------------------
            # Command Injection
            # -------------------------
            "command_injection_danger": "command_injection",
            "shell_injection": "command_injection",
            "B602": "command_injection",
            "B605": "command_injection",

            # -------------------------
            # SQL Injection
            # -------------------------
            "sql_injection_variable": "sql_injection",
            "B608": "sql_injection",

            # -------------------------
            # Insecure Deserialization
            # -------------------------
            "insecure_pickle": "insecure_deserialization",
            "insecure_yaml": "insecure_deserialization",
            "B301": "insecure_deserialization",
            "B506": "insecure_deserialization",

            # -------------------------
            # Weak Random
            # -------------------------
            "weak_random_crypto": "weak_random",
            "B311": "weak_random",

            # -------------------------
            # Hardcoded Secrets
            # -------------------------
            "hardcoded_password": "hardcoded_secret",
            "hardcoded_token": "hardcoded_secret",
            "B105": "hardcoded_secret",

            # -------------------------
            # Dangerous Execution
            # -------------------------
            "B307": "dangerous_eval_exec",
            "B102": "dangerous_eval_exec",

            # -------------------------
            # Insecure Temp Files
            # -------------------------
            "B306": "insecure_temp_file",

            # -------------------------
            # Assert usage
            # -------------------------
            "B101": "assert_used",

            # -------------------------------------------------------
            # Unsafe Imports (MEDIUM — module imported, not yet used)
            # B403 = import pickle/marshal/shelve  → MEDIUM warning
            # B404 = import subprocess             → MEDIUM warning
            # B401 = import telnetlib              → MEDIUM warning
            # B402 = import ftplib                 → MEDIUM warning
            # import_* rules from SecurityChecker  → MEDIUM warning
            # -------------------------------------------------------
            "B403": "unsafe_imports",          # was wrongly → insecure_deserialization
            "B404": "unsafe_imports",          # was wrongly → command_injection
            "B401": "unsafe_imports",
            "B402": "unsafe_imports",
            "import_subprocess":  "unsafe_imports",
            "import_pickle":      "unsafe_imports",
            "import_yaml":        "unsafe_imports",
            "import_marshal":     "unsafe_imports",
            "import_shelve":      "unsafe_imports",
            "import_telnetlib":   "unsafe_imports",
            "import_ftplib":      "unsafe_imports",
            "import_os":          "unsafe_imports",
            "import_ctypes":      "unsafe_imports",

            # -------------------------
            # Path Traversal
            # -------------------------
            "path_traversal": "path_traversal",
            "B609": "path_traversal",

            # -------------------------
            # XML External Entity (XXE)
            # -------------------------
            "xxe_injection":     "xxe",
            "xxe_vulnerability": "xxe",     # emitted by SecurityChecker
            "B410": "xxe",
            "B411": "xxe",

            # -------------------------
            # SSRF
            # -------------------------
            "ssrf_danger":       "ssrf",
            "ssrf_vulnerability":"ssrf",    # emitted by SecurityChecker

            # -------------------------
            # Privilege Escalation
            # -------------------------
            "privilege_escalation": "privilege_escalation",

            # -------------------------
            # Format String Injection
            # -------------------------
            "format_string_injection": "format_string_injection",

            # -------------------------
            # Race Condition (TOCTOU)
            # -------------------------
            "race_condition":       "race_condition",
            "race_condition_toctou":"race_condition",  # emitted by SecurityChecker
            "toctou":               "race_condition",

            # -------------------------
            # Integer Overflow
            # -------------------------
            "integer_overflow":      "integer_overflow",
            "integer_overflow_risk": "integer_overflow",  # emitted by SecurityChecker

            # -------------------------
            # Open Redirect
            # -------------------------
            "open_redirect": "open_redirect",

            # -------------------------
            # Timing Attack
            # -------------------------
            "timing_attack": "timing_attack",

            # -------------------------
            # Resource Exhaustion / DoS
            # -------------------------
            "resource_exhaustion": "resource_exhaustion",
            "dos_risk": "resource_exhaustion",

            # -------------------------
            # Insecure File Permissions
            # -------------------------
            "insecure_file_permissions": "insecure_file_permissions",
            "insecure_permissions":      "insecure_file_permissions",  # emitted by SecurityChecker
            "B103": "insecure_file_permissions",

            # -------------------------
            # Dynamic / Unsafe Imports
            # -------------------------
            "dynamic_import": "unsafe_imports",  # emitted by SecurityChecker (__import__)

            # -------------------------
            # Hardcoded Secrets (extra aliases)
            # -------------------------
            "hardcoded_api_key": "hardcoded_secret",  # emitted by SecurityChecker
            "hardcoded_secret":  "hardcoded_secret",  # emitted by SecurityChecker
            "B106": "hardcoded_secret",
            "B107": "hardcoded_secret",

        }

        return rule_map.get(rule, rule)

    # ------------------------------------------------
    # Assign severity to a normalized category
    # ------------------------------------------------
    def _get_severity(self, category: str) -> str:
        """
        Return HIGH or MEDIUM based on vulnerability category.

        HIGH   → Exploitable vulnerabilities that can lead to RCE,
                 data breach, or full system compromise.
        MEDIUM → Security weaknesses or risky coding practices.
        """

        high_severity = {
            "dangerous_eval_exec",       # eval / exec usage
            "command_injection",         # OS command injection
            "sql_injection",             # SQL injection
            "hardcoded_secret",          # Hardcoded passwords / tokens
            "insecure_deserialization",  # pickle / yaml.load
            "path_traversal",            # Directory traversal
            "xxe",                       # XML External Entity
            "ssrf",                      # Server-Side Request Forgery
            "privilege_escalation",      # Privilege escalation
            "format_string_injection",   # Format string attacks
        }

        medium_severity = {
            "weak_crypto",               # MD5 / SHA1 hashing
            "weak_random",               # random instead of secrets
            "race_condition",            # TOCTOU race conditions
            "insecure_temp_file",        # Insecure temp file creation
            "integer_overflow",          # Integer overflow risk
            "open_redirect",             # Open redirect
            "timing_attack",             # Non-constant time comparison
            "resource_exhaustion",       # DoS / resource exhaustion
            "insecure_file_permissions", # Overly permissive file perms
            "unsafe_imports",            # Dangerous module imports
            "assert_used",               # assert in production code
        }

        if category in high_severity:
            return "HIGH"
        elif category in medium_severity:
            return "MEDIUM"
        else:
            return "MEDIUM"  # Safe default for unknown categories

    # ------------------------------------------------
    # Merge + deduplicate issues
    # ------------------------------------------------
    def merge_all(self, all_issues: List[Dict]) -> Dict:
        """
        Merge issues from all scanners, remove duplicates,
        and attach severity levels to each finding.
        """

        merged: Dict[Tuple, Dict] = {}

        for issue in all_issues:

            line = issue.get("line", 0)
            rule = issue.get("rule", "")
            source = issue.get("source", "unknown")

            category = self._normalize_rule(rule)
            severity = self._get_severity(category)

            key = (line, category)

            if key not in merged:

                merged[key] = {
                    "line": line,
                    "rule": category,
                    "severity": severity,
                    "message": issue.get("message", ""),
                    "suggestion": issue.get("suggestion", ""),
                    "sources": [source],
                    "code_snippet": issue.get("code_snippet", "")
                }

            else:
                # Add additional source if found again
                if source not in merged[key]["sources"]:
                    merged[key]["sources"].append(source)

                # Prefer longer message if current is missing
                if not merged[key]["message"]:
                    merged[key]["message"] = issue.get("message", "")

                if not merged[key]["suggestion"]:
                    merged[key]["suggestion"] = issue.get("suggestion", "")

        # Convert dictionary to list
        final_issues = list(merged.values())

        # Sort: HIGH severity first, then by line number
        severity_order = {"HIGH": 0, "MEDIUM": 1}
        final_issues.sort(
            key=lambda x: (
                severity_order.get(x.get("severity", "MEDIUM"), 1),
                int(x.get("line") or 0)
            )
        )

        # Count by severity
        high_count = sum(1 for i in final_issues if i.get("severity") == "HIGH")
        medium_count = sum(1 for i in final_issues if i.get("severity") == "MEDIUM")

        return {
            "final_issues": final_issues,
            "total_issues": len(final_issues),
            "high_count": high_count,
            "medium_count": medium_count,
        }