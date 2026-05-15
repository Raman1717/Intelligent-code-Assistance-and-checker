"""
ADVANCED SECURITY ANALYZER
===========================
Detects 18+ security vulnerabilities including hidden issues
FIXED: SQL injection flow analysis, constant detection, privilege escalation
"""

import ast
import re
from typing import List, Dict, Set
from .astengine import ASTEngine


class SecurityChecker:

    def __init__(self, engine: ASTEngine):
        self.engine = engine
        self.issues: List[Dict] = []
        self.seen_issues: Set[tuple] = set()  # For deduplication

    def run_all_checks(self) -> List[Dict]:
        self.issues = []
        self.seen_issues = set()

        # Level 1: Import-level warnings (MEDIUM — potential risk, not yet a vulnerability)
        self._check_risky_imports()                 # 0. Risky module imports

        # Core security checks
        self._check_dangerous_functions()           # 1. eval/exec
        self._check_sql_injection()                 # 2. SQL injection (FIXED)
        self._check_command_injection()             # 3. Command injection
        self._check_hardcoded_secrets()             # 4. Hardcoded secrets
        self._check_weak_crypto()                   # 5. Weak crypto (MD5/SHA1)
        self._check_insecure_deserialization()      # 6. Pickle/YAML
        self._check_weak_random()                   # 7. random vs secrets
        
        # Advanced/Hidden vulnerability checks
        self._check_path_traversal()                # 8. Path traversal (FIXED)
        self._check_xxe_vulnerabilities()           # 9. XML External Entity
        self._check_race_conditions()               # 10. TOCTOU race conditions
        self._check_insecure_temp_files()           # 11. Temp file creation
        self._check_integer_overflow()              # 12. Integer overflow risks
        self._check_format_string_vulnerabilities() # 13. Format string issues
        self._check_insecure_redirects()            # 14. Open redirects
        self._check_timing_attacks()                # 15. Timing attack vulnerabilities
        self._check_resource_exhaustion()           # 16. DoS via resource exhaustion
        self._check_insecure_permissions()          # 17. File permissions
        self._check_server_side_request_forgery()   # 18. SSRF vulnerabilities
        self._check_privilege_escalation()          # 19. Privilege escalation (NEW)

        return self.issues

    # ------------------------------------------------
    # HELPER: Emit issue with deduplication
    # ------------------------------------------------

    def _emit(self, line, rule, message, suggestion):
        """Emit issue only if not duplicate"""
        key = (line, rule)
        if key in self.seen_issues:
            return  # Skip duplicate
        
        self.seen_issues.add(key)
        self.issues.append({
            "line": line,
            "source": "security",
            "rule": rule,
            "message": message,
            "suggestion": suggestion,
            "code_snippet": self.engine.get_code_snippet(line),
        })

    # ------------------------------------------------
    # 0. RISKY IMPORTS  (Level 1 — MEDIUM warning)
    # ------------------------------------------------
    # Key principle: importing a module is NOT a vulnerability.
    # We emit MEDIUM to warn the developer to review usage.
    # The actual HIGH issues are caught by checks 1–19 below
    # when dangerous *usage* patterns are confirmed.
    # ------------------------------------------------

    # Modules that are safe to import but dangerous when misused.
    # Maps module name → (rule, warning message, suggestion)
    _RISKY_IMPORT_MAP = {
        "subprocess": (
            "import_subprocess",
            "subprocess imported — safe only when shell=False and args are a list. "
            "Never pass user input with shell=True.",
            "Review all subprocess calls. Use subprocess.run(['cmd', arg], shell=False).",
        ),
        "pickle": (
            "import_pickle",
            "pickle imported — deserializing untrusted data with pickle allows "
            "arbitrary code execution.",
            "Use json.loads() for untrusted data. Never unpickle data from external sources.",
        ),
        "marshal": (
            "import_marshal",
            "marshal imported — like pickle, can execute arbitrary code when "
            "loading untrusted bytes.",
            "Avoid marshal for untrusted data. Prefer JSON or MessagePack.",
        ),
        "shelve": (
            "import_shelve",
            "shelve imported — uses pickle internally. Same deserialization risks apply.",
            "Do not use shelve with data from untrusted sources.",
        ),
        "yaml": (
            "import_yaml",
            "yaml imported — yaml.load() without Loader= is unsafe and can run "
            "arbitrary Python.",
            "Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        ),
        "telnetlib": (
            "import_telnetlib",
            "telnetlib imported — Telnet sends credentials in plaintext.",
            "Replace with an SSH library such as paramiko.",
        ),
        "ftplib": (
            "import_ftplib",
            "ftplib imported — FTP transmits credentials in plaintext.",
            "Replace with SFTP (paramiko) or FTPS.",
        ),
        "ctypes": (
            "import_ctypes",
            "ctypes imported — direct memory manipulation can bypass Python's "
            "safety guarantees.",
            "Audit all ctypes usage carefully. Never expose ctypes calls to user input.",
        ),
        "os": (
            "import_os",
            "os imported — os.system() and os.popen() are vulnerable to command "
            "injection if called with unsanitized input.",
            "Prefer subprocess.run([...], shell=False) over os.system(). "
            "Audit all os.* calls that accept external data.",
        ),
    }

    def _check_risky_imports(self):
        """
        Level 1 detection — flag risky module imports as MEDIUM warnings.

        Rule: importing a module is NOT a vulnerability by itself.
              The danger only appears when the module is used insecurely.

        Example:
            import subprocess          →  MEDIUM  (this check)
            subprocess.run(x, shell=True) →  HIGH  (_check_command_injection)
        """
        for node in ast.walk(self.engine.tree):

            # import pickle  /  import subprocess
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base = alias.name.split(".")[0]
                    if base in self._RISKY_IMPORT_MAP:
                        rule, msg, tip = self._RISKY_IMPORT_MAP[base]
                        self._emit_with_severity(
                            node.lineno, rule, "MEDIUM", "IMPORT", msg, tip
                        )

            # from pickle import loads  /  from subprocess import run
            elif isinstance(node, ast.ImportFrom):
                base = (node.module or "").split(".")[0]
                if base in self._RISKY_IMPORT_MAP:
                    rule, msg, tip = self._RISKY_IMPORT_MAP[base]
                    self._emit_with_severity(
                        node.lineno, rule, "MEDIUM", "IMPORT", msg, tip
                    )

    def _emit_with_severity(self, line, rule, severity, detection, message, suggestion):
        """
        Extended emit that attaches severity + detection level.
        Falls back gracefully — existing checks that use _emit() are unaffected.
        """
        key = (line, rule)
        if key in self.seen_issues:
            return
        self.seen_issues.add(key)
        self.issues.append({
            "line":         line,
            "source":       "security",
            "rule":         rule,
            "severity":     severity,    # HIGH / MEDIUM
            "detection":    detection,   # IMPORT / USAGE / EXPLOIT
            "message":      message,
            "suggestion":   suggestion,
            "code_snippet": self.engine.get_code_snippet(line),
        })

    # ------------------------------------------------
    # 1. DANGEROUS FUNCTIONS (eval, exec)
    # ------------------------------------------------

    def _check_dangerous_functions(self):
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)

            if fn in ("eval", "exec"):
                self._emit(
                    node.lineno,
                    "dangerous_eval_exec",
                    f"Use of {fn}() allows arbitrary code execution",
                    "Remove eval/exec or use ast.literal_eval for safe parsing",
                )

            if fn == "__import__" and not self._is_safe_import(node):
                self._emit(
                    node.lineno,
                    "dynamic_import",
                    "Dynamic __import__() can load malicious modules",
                    "Use standard import statements or validate module names",
                )

    def _is_safe_import(self, node):
        """Check if __import__ uses a constant string"""
        if node.args and isinstance(node.args[0], ast.Constant):
            return True
        return False

    # ------------------------------------------------
    # 2. SQL INJECTION  (IMPROVED — false-positive safe)
    # ------------------------------------------------
    #
    # Detection flow:
    #
    #   cursor.execute(query, params)   → SAFE  (parameterized)
    #   cursor.execute("SELECT..." + x) → HIGH  (concatenation)
    #   cursor.execute(f"SELECT {x}")   → HIGH  (f-string)
    #   cursor.execute(q.format(x))     → HIGH  (.format injection)
    #   cursor.execute(query)           → trace variable assignment
    #       query = "SELECT..." + x     → HIGH
    #       query = "SELECT ... %s"     → SAFE  (placeholder)
    #
    # Known taint sources (basic taint analysis):
    #   input(), request.args, request.form, sys.argv, os.environ
    # ------------------------------------------------

    # Variables that are known to carry user-controlled data
    TAINT_SOURCES = {"input", "request", "argv", "environ", "form", "args",
                     "params", "data", "body", "get_json"}

    # Safe placeholders — if a query string contains these it is parameterized
    SQL_PLACEHOLDERS = ("%s", "?", ":name", "$1", "%(", ":%(")

    def _check_sql_injection(self):
        """
        Improved SQL injection detection with false-positive reduction.

        Key improvements over previous version:
          1. Parameterized queries are never flagged (placeholder check)
          2. Variable lookup traces the actual assignment, not just the name
          3. Taint analysis flags user-controlled values reaching execute()
          4. Direct inline concatenation is always caught
        """

        # ── Stage 1: Direct injection inside execute() call ──────────────
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            if not (fn and "execute" in fn.lower()):
                continue

            for arg in node.args:
                # Skip if query is safely parameterized
                if self._is_parameterized_query(arg):
                    break

                # Inline unsafe string building
                if self._is_unsafe_sql_build(arg):
                    tainted = self._contains_taint_source(arg)
                    self._emit(
                        node.lineno,
                        "sql_injection",
                        "SQL query built with "
                        + ("user-controlled input" if tainted else "string concatenation/formatting")
                        + " — injection risk",
                        "Use parameterized queries: "
                        "cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
                    )
                    break

                # Variable passed as query — trace its assignment
                if isinstance(arg, ast.Name):
                    assigned_value = self._find_variable_assignment(arg.id)
                    if assigned_value is None:
                        continue  # Unknown origin — don't guess, skip

                    # Safe if assigned value is a parameterized string literal
                    if self._is_parameterized_query(assigned_value):
                        break

                    # Unsafe if assigned value is built unsafely
                    if self._is_unsafe_sql_build(assigned_value):
                        tainted = self._contains_taint_source(assigned_value)
                        self._emit(
                            node.lineno,
                            "sql_injection_variable",
                            f"Variable '{arg.id}' passed to execute() was built with "
                            + ("user-controlled input" if tainted else "string formatting")
                            + " — injection risk",
                            "Build SQL with placeholders only, pass values as parameters.",
                        )
                        break

        # ── Stage 2: Assignment builds unsafe SQL, later used in execute() ─
        # Catches:  condition = f"username = '{username}'"
        #           cursor.execute("SELECT … WHERE " + condition)
        for node in ast.walk(self.engine.tree):
            if not isinstance(node, ast.Assign):
                continue

            if not self._is_unsafe_sql_build(node.value):
                continue

            # Skip if the value itself is parameterized (safe multi-line strings)
            if self._is_parameterized_query(node.value):
                continue

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                var_name = target.id
                if self._variable_used_in_sql_execute(var_name, node.lineno):
                    self._emit(
                        node.lineno,
                        "sql_injection_variable",
                        f"SQL fragment built with string formatting in '{var_name}' "
                        "and passed to execute() — injection risk",
                        "Use parameterized queries instead of building SQL strings.",
                    )

    # ── SQL helpers ────────────────────────────────────────────────────────

    def _is_parameterized_query(self, node) -> bool:
        """
        Return True if the node is a string literal that already contains
        safe parameter placeholders (%s  ?  :name  $1).

        Only constant strings are checked — dynamic nodes cannot be safe
        by this criterion and return False (caller decides).
        """
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            return False
        query = node.value
        return any(p in query for p in self.SQL_PLACEHOLDERS)

    def _is_unsafe_sql_build(self, node) -> bool:
        """
        Return True if the node builds a SQL string unsafely:
          • f-string  (ast.JoinedStr)
          • concatenation / % format  (ast.BinOp with Add or Mod)
          • .format() call on a string containing SQL keywords
          • variable whose assignment is unsafe (recursive one level)
        """
        # f-string: f"SELECT ... {var}"
        if isinstance(node, ast.JoinedStr):
            return self._contains_sql_keywords(node)

        # "SELECT ..." + var   or   "SELECT ... %s" % var
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return (
                self._contains_sql_keywords(node.left)
                or self._contains_sql_keywords(node.right)
                or self._is_unsafe_sql_build(node.left)
                or self._is_unsafe_sql_build(node.right)
            )

        # "SELECT ...".format(var)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return self._contains_sql_keywords(node.func.value)

        # Variable — look up its assignment (one level only to avoid recursion)
        if isinstance(node, ast.Name):
            assigned = self._find_variable_assignment(node.id)
            if assigned is not None and not isinstance(assigned, ast.Name):
                return self._is_unsafe_sql_build(assigned)

        return False

    def _is_sql_string_building(self, node) -> bool:
        """Alias kept for Stage 2 backward compat."""
        return self._is_unsafe_sql_build(node)

    def _find_variable_assignment(self, var_name):
        """
        Locate the most recent assignment of var_name in the AST.
        Returns the RHS node, or None if not found.

        This replaces the old _variable_contains_sql() name-guessing
        with real assignment tracing — eliminates false positives on
        variables like `query` that hold safe parameterized strings.
        """
        result = None
        for node in ast.walk(self.engine.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        result = node.value  # keep last assignment
        return result

    def _contains_taint_source(self, node) -> bool:
        """
        Basic taint analysis — return True if the node contains
        a known user-input source (input(), request.*, sys.argv, etc.).
        """
        for child in ast.walk(node):
            # Function call: input(), request.get_json(), etc.
            if isinstance(child, ast.Call):
                fn = self.engine.get_call_name(child)
                if fn and any(src in fn for src in self.TAINT_SOURCES):
                    return True
            # Name: argv, request, data
            if isinstance(child, ast.Name) and child.id in self.TAINT_SOURCES:
                return True
            # Attribute: request.args, request.form
            if isinstance(child, ast.Attribute) and child.attr in self.TAINT_SOURCES:
                return True
        return False

    def _variable_used_in_sql_execute(self, var_name, assignment_line) -> bool:
        """Check if var_name appears as an argument to execute() after its assignment."""
        for call_node in self.engine.calls:
            fn = self.engine.get_call_name(call_node)
            if not (fn and "execute" in fn.lower()):
                continue
            if call_node.lineno <= assignment_line:
                continue
            for arg in call_node.args:
                if isinstance(arg, ast.Name) and arg.id == var_name:
                    return True
                # Also catches: execute("SELECT … WHERE " + condition)
                if isinstance(arg, ast.BinOp):
                    for child in ast.walk(arg):
                        if isinstance(child, ast.Name) and child.id == var_name:
                            return True
        return False

    def _contains_sql_keywords(self, node) -> bool:
        """Return True if node contains a string constant with SQL keywords."""
        sql_keywords = (
            "SELECT", "INSERT", "UPDATE", "DELETE",
            "FROM", "WHERE", "DROP", "ALTER", "AND", "OR",
        )
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                upper = child.value.upper()
                if any(k in upper for k in sql_keywords):
                    return True
        return False

    # ------------------------------------------------
    # 3. COMMAND INJECTION
    # ------------------------------------------------

    def _check_command_injection(self):
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)

            # Check dangerous functions
            if fn in ("os.popen", "os.system", "commands.getoutput"):
                self._emit(
                    node.lineno,
                    "command_injection_danger",
                    f"{fn}() executes shell commands - injection risk",
                    "Use subprocess.run() with shell=False and pass arguments as list",
                )

            # Check subprocess with shell=True
            if fn and "subprocess" in fn:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                        self._emit(
                            node.lineno,
                            "shell_injection",
                            "subprocess with shell=True enables command injection",
                            "Set shell=False and pass command as list: ['ls', '-la']",
                        )

    # ------------------------------------------------
    # 4. HARDCODED SECRETS (improved detection)
    # ------------------------------------------------

    def _check_hardcoded_secrets(self):
        patterns = {
            "password": r'password\s*=\s*["\']([^"\']+)["\']',
            "api_key": r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
            "secret": r'secret\s*=\s*["\']([^"\']{8,})["\']',
            "token": r'token\s*=\s*["\']([^"\']{8,})["\']',
        }

        for i, line in enumerate(self.engine.code_lines, 1):
            # Skip if using environment variables or config
            if any(skip in line.lower() for skip in ("os.environ", "getenv", "config.get", ".get(", "input(")):
                continue
            
            # Skip if it's a variable or f-string (not literal)
            if any(indicator in line for indicator in ['f"', "f'", '.format', '{', '}']):
                continue

            for key, pat in patterns.items():
                match = re.search(pat, line, re.IGNORECASE)
                if match:
                    value = match.group(1)
                    # Only flag if looks like real secret (not placeholder)
                    if not any(placeholder in value.lower() for placeholder in ['your_', 'example', 'test', 'xxx', '***']):
                        self._emit(
                            i,
                            f"hardcoded_{key}",
                            f"Hardcoded {key} detected: '{value[:20]}...'",
                            f"Store {key} in environment variables or secrets manager",
                        )
                    break

    # ------------------------------------------------
    # 5. WEAK CRYPTOGRAPHY
    # ------------------------------------------------

    def _check_weak_crypto(self):
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            if not fn:
                continue
            
            fn_lower = fn.lower()
            
            # Detect weak hash algorithms
            if "md5" in fn_lower:
                self._emit(
                    node.lineno,
                    "weak_hash_md5",
                    "MD5 is cryptographically broken - collision attacks possible",
                    "Use hashlib.sha256() or hashlib.blake2b() instead",
                )
            
            elif "sha1" in fn_lower:
                self._emit(
                    node.lineno,
                    "weak_hash_sha1",
                    "SHA-1 is deprecated - collision attacks demonstrated",
                    "Use SHA-256 or stronger (SHA-3, BLAKE2)",
                )

    # ------------------------------------------------
    # 6. INSECURE DESERIALIZATION
    # ------------------------------------------------

    def _check_insecure_deserialization(self):
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            if fn in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
                self._emit(
                    node.lineno,
                    "insecure_pickle",
                    "pickle.loads() can execute arbitrary code during deserialization",
                    "Use json.loads() for data or implement signature verification",
                )
            
            elif fn in ("yaml.load", "yaml.unsafe_load"):
                self._emit(
                    node.lineno,
                    "insecure_yaml",
                    "yaml.load() can execute arbitrary Python code",
                    "Use yaml.safe_load() instead",
                )

    # ------------------------------------------------
    # 7. WEAK RANDOM (cryptographic context)
    # ------------------------------------------------

    def _check_weak_random(self):
        """Detect use of random module in security contexts"""
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            if fn and fn.startswith("random."):
                # Check context - look for security keywords nearby
                code_context = self.engine.get_code_snippet(node.lineno, context=3).lower()
                
                security_keywords = ['password', 'token', 'key', 'secret', 'salt', 'nonce', 'crypto', 'session']
                if any(keyword in code_context for keyword in security_keywords):
                    self._emit(
                        node.lineno,
                        "weak_random_crypto",
                        "random module is not cryptographically secure",
                        "Use secrets module: secrets.token_bytes(), secrets.token_hex()",
                    )

    # ------------------------------------------------
    # 8. PATH TRAVERSAL (FIXED - Constant Detection)
    # ------------------------------------------------

    def _check_path_traversal(self):
        """
        FIXED: Detect path operations with user input
        Ignores module-level constants (CACHE_FILE, REPORT_DIR)
        """
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            # Check file operations
            if fn in ("open", "os.path.join", "pathlib.Path"):
                # Check if path is constructed from user input
                for arg in node.args:
                    if self._is_user_controlled_path(arg):
                        self._emit(
                            node.lineno,
                            "path_traversal",
                            "File path constructed from user input - directory traversal risk",
                            "Validate path with os.path.abspath() and check it's within allowed directory",
                        )
                        break

    def _is_user_controlled_path(self, node):
        """
        FIXED: Check if path is user-controlled (not a constant)
        Returns False for module-level constants like CACHE_FILE, REPORT_DIR
        """
        # Literal strings are safe
        if isinstance(node, ast.Constant):
            return False
        
        # Module-level constants (uppercase names) are safe
        if isinstance(node, ast.Name):
            # Check if it's an uppercase constant (convention for module constants)
            if node.id.isupper():
                return False  # CACHE_FILE, REPORT_DIR, etc.
            # Otherwise it's a variable
            return True
        
        # String operations (concatenation, f-strings) could be dangerous
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
            # Check if it contains any non-constant parts
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    # If it contains a non-constant variable, it's user-controlled
                    if not child.id.isupper():
                        return True
            # If all variables are constants, still check for parameters
            return True  # Conservative: flag concatenations
        
        return False

    # ------------------------------------------------
    # 9. XXE (XML External Entity) VULNERABILITIES
    # ------------------------------------------------

    def _check_xxe_vulnerabilities(self):
        """Detect XML parsing without protection against XXE"""
        xml_modules = ['xml.etree.ElementTree', 'xml.sax', 'xml.dom.minidom', 'lxml.etree']
        
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)

            # Guard: get_call_name() can return None for complex expressions
            if not fn:
                continue

            if any(xml_mod in fn for xml_mod in xml_modules):
                if 'parse' in fn.lower() or 'fromstring' in fn.lower():
                    self._emit(
                        node.lineno,
                        "xxe_vulnerability",
                        "XML parsing without XXE protection - can read arbitrary files",
                        "Use defusedxml library or disable external entities",
                    )

    # ------------------------------------------------
    # 10. RACE CONDITIONS (TOCTOU)
    # ------------------------------------------------

    def _check_race_conditions(self):
        """Detect Time-of-Check-Time-of-Use race conditions"""
        
        # Look for pattern: os.path.exists() followed by file operation
        for i, node in enumerate(self.engine.calls):
            fn = self.engine.get_call_name(node)
            
            if fn in ("os.path.exists", "os.path.isfile", "os.access"):
                line = node.lineno
                
                # Check next few lines for file operations
                for next_node in self.engine.calls[i+1:i+5]:
                    next_fn = self.engine.get_call_name(next_node)
                    if next_fn in ("open", "os.remove", "os.unlink", "os.rename", "os.makedirs"):
                        if abs(next_node.lineno - line) <= 5:
                            self._emit(
                                line,
                                "race_condition_toctou",
                                "Time-of-check-time-of-use race condition detected",
                                "Use try/except or file locks instead of checking existence first",
                            )
                            break

    # ------------------------------------------------
    # 11. INSECURE TEMP FILES
    # ------------------------------------------------

    def _check_insecure_temp_files(self):
        """Detect insecure temporary file creation"""
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            if fn in ("tempfile.mktemp", "os.tempnam", "os.tmpnam"):
                self._emit(
                    node.lineno,
                    "insecure_temp_file",
                    f"{fn}() is insecure - race condition and predictable names",
                    "Use tempfile.mkstemp() or tempfile.TemporaryFile() instead",
                )

    # ------------------------------------------------
    # 12. INTEGER OVERFLOW (hidden vulnerability)
    # ------------------------------------------------

    def _check_integer_overflow(self):
        """Detect potential integer overflow in calculations"""
        for node in ast.walk(self.engine.tree):
            if isinstance(node, ast.BinOp):
                # Check for multiplication or power operations
                if isinstance(node.op, (ast.Mult, ast.Pow)):
                    # Check if result is used in array/buffer allocation
                    parent = self._find_parent_call(node)
                    if parent:
                        fn = self.engine.get_call_name(parent)
                        if fn in ("bytearray", "bytes", "list", "array.array"):
                            self._emit(
                                node.lineno,
                                "integer_overflow_risk",
                                "Integer calculation in buffer allocation - overflow could cause DoS",
                                "Validate calculation result before allocation",
                            )

    def _find_parent_call(self, node):
        """Find if node is argument to a function call"""
        for call_node in self.engine.calls:
            if node in ast.walk(call_node):
                return call_node
        return None

    # ------------------------------------------------
    # 13. FORMAT STRING VULNERABILITIES
    # ------------------------------------------------

    def _check_format_string_vulnerabilities(self):
        """Detect format string vulnerabilities"""
        for node in self.engine.calls:
            # Check str.format() with user input
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                # Check if format string itself is dynamic
                if self._is_dynamic_value(node.func.value):
                    self._emit(
                        node.lineno,
                        "format_string_injection",
                        "Format string constructed from user input - injection risk",
                        "Use fixed format strings with user data only in arguments",
                    )

    def _is_dynamic_value(self, node):
        """Check if value is dynamic (not a constant)"""
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, (ast.Name, ast.Call, ast.BinOp, ast.JoinedStr)):
            return True
        return False

    # ------------------------------------------------
    # 14. OPEN REDIRECTS
    # ------------------------------------------------

    def _check_insecure_redirects(self):
        """Detect open redirect vulnerabilities"""
        redirect_keywords = ['redirect', 'location', 'url', 'return_url', 'next']
        
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            # Check web framework redirects
            if fn and 'redirect' in fn.lower():
                for arg in node.args:
                    if self._is_dynamic_value(arg):
                        self._emit(
                            node.lineno,
                            "open_redirect",
                            "Redirect URL from user input - phishing risk",
                            "Validate redirect URL against whitelist of allowed domains",
                        )
                        break

    # ------------------------------------------------
    # 15. TIMING ATTACKS
    # ------------------------------------------------

    def _check_timing_attacks(self):
        """
        Detect timing attack vulnerabilities in secret comparisons.

        Strategy: walk AST Compare nodes (not raw lines) so we can inspect
        exactly what is being compared and filter out safe patterns.

        False positive filters applied:
          • Skip comparisons against None / True / False / integer literals
            (e.g. `if public_key != None:` is a None-check, not a timing risk)
          • Skip if hmac.compare_digest is already used on the same line
          • Require BOTH sides of the comparison to be non-constant, OR
            at least one side to be a Name/Attribute that looks like a secret
        """
        secret_names = {'password', 'passwd', 'pwd', 'token', 'secret',
                        'api_key', 'apikey', 'auth', 'credential', 'passphrase'}

        # Singleton constants that are safe to compare with ==
        _safe_singletons = (type(None), bool)

        for node in ast.walk(self.engine.tree):
            if not isinstance(node, ast.Compare):
                continue

            # Only flag == and != operators
            if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                continue

            # Collect all operands (left + all comparators)
            operands = [node.left] + list(node.comparators)

            # Filter 1: skip if any operand is None/True/False/integer constant
            # These are existence/type checks, not secret comparisons
            def _is_safe_singleton(n):
                if isinstance(n, ast.Constant):
                    return isinstance(n.value, _safe_singletons) or isinstance(n.value, int)
                return False

            if any(_is_safe_singleton(op) for op in operands):
                continue

            # Filter 2: collect variable/attribute names involved
            def _extract_name(n):
                if isinstance(n, ast.Name):
                    return n.id.lower()
                if isinstance(n, ast.Attribute):
                    return n.attr.lower()
                return ""

            names_in_comparison = [_extract_name(op) for op in operands]

            # Filter 3: only flag if at least one operand name looks like a secret
            if not any(
                any(secret in name for secret in secret_names)
                for name in names_in_comparison
                if name
            ):
                continue

            # Filter 4: skip if compare_digest is already used on this line
            line_text = (self.engine.code_lines[node.lineno - 1]
                         if node.lineno <= len(self.engine.code_lines) else "")
            if 'compare_digest' in line_text or 'hmac' in line_text.lower():
                continue

            self._emit(
                node.lineno,
                "timing_attack",
                "Secret value compared with == / != — vulnerable to timing attacks. "
                "Attacker can infer secret byte-by-byte by measuring response time.",
                "Use hmac.compare_digest(a, b) for constant-time comparison of secrets.",
            )

    # ------------------------------------------------
    # 16. RESOURCE EXHAUSTION / DoS
    # ------------------------------------------------

    def _check_resource_exhaustion(self):
        """Detect potential resource exhaustion DoS"""
        
        # Check for unbounded loops with network/file I/O
        for loop_node in self.engine.loops:
            # Check if loop has no obvious bounds
            if isinstance(loop_node, ast.While):
                # While True without break is suspicious
                if isinstance(loop_node.test, ast.Constant) and loop_node.test.value is True:
                    # Check for I/O operations inside
                    has_io = False
                    for node in ast.walk(loop_node):
                        if isinstance(node, ast.Call):
                            fn = self.engine.get_call_name(node)
                            if fn and any(io_fn in fn for io_fn in ['read', 'recv', 'get', 'fetch']):
                                has_io = True
                                break
                    
                    if has_io:
                        self._emit(
                            loop_node.lineno,
                            "resource_exhaustion",
                            "Unbounded loop with I/O operations - DoS risk",
                            "Add timeout, rate limiting, or maximum iteration count",
                        )

    # ------------------------------------------------
    # 17. INSECURE FILE PERMISSIONS
    # ------------------------------------------------

    def _check_insecure_permissions(self):
        """Detect insecure file permissions"""
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)
            
            if fn in ("os.chmod", "os.fchmod"):
                # Check permission argument
                if node.args and len(node.args) >= 2:
                    perm_arg = node.args[1]
                    if isinstance(perm_arg, ast.Constant):
                        # Check for overly permissive (0o777, 0o666)
                        perm_value = perm_arg.value
                        if isinstance(perm_value, int):
                            # Check for world-writable
                            if perm_value & 0o002 or perm_value & 0o020:
                                self._emit(
                                    node.lineno,
                                    "insecure_permissions",
                                    f"Overly permissive file permissions: {oct(perm_value)}",
                                    "Use restrictive permissions (0o600 for sensitive files)",
                                )

    # ------------------------------------------------
    # 18. SSRF (Server-Side Request Forgery)
    # ------------------------------------------------

    def _check_server_side_request_forgery(self):
        """Detect SSRF vulnerabilities"""
        http_functions = ['requests.get', 'requests.post', 'urllib.request.urlopen', 'http.client.request']
        
        for node in self.engine.calls:
            fn = self.engine.get_call_name(node)

            # Guard: get_call_name() can return None for complex expressions
            if not fn:
                continue

            if any(http_fn in fn for http_fn in http_functions):
                # Check if URL is dynamic
                if node.args and self._is_dynamic_value(node.args[0]):
                    self._emit(
                        node.lineno,
                        "ssrf_vulnerability",
                        "HTTP request with dynamic URL - SSRF attack risk",
                        "Validate URL against whitelist and block internal IP ranges",
                    )

    # ------------------------------------------------
    # 19. PRIVILEGE ESCALATION (NEW)
    # ------------------------------------------------

    def _check_privilege_escalation(self):
        
        for func_name, func_node in self.engine.functions.items():
            # Check function parameters
            for arg in func_node.args.args:
                param_name = arg.arg
                
                # Check if parameter suggests privilege/role
                if any(priv in param_name.lower() for priv in ['role', 'permission', 'privilege', 'access', 'level']):
                    # Check if there's validation in the function body
                    has_validation = self._has_privilege_validation(func_node, param_name)
                    
                    if not has_validation:
                        self._emit(
                            func_node.lineno,
                            "privilege_escalation",
                            f"Function '{func_name}' accepts '{param_name}' without validation - privilege escalation risk",
                            f"Validate '{param_name}' against allowed values before use",
                        )

    def _has_privilege_validation(self, func_node, param_name):
        
        for node in ast.walk(func_node):

            # Pattern: if role in ALLOWED_ROLES / if role == 'admin'
            if isinstance(node, ast.If):
                for child in ast.walk(node.test):
                    if isinstance(child, ast.Name) and child.id == param_name:
                        return True

            # Pattern: assert role in VALID_ROLES
            if isinstance(node, ast.Assert):
                for child in ast.walk(node.test):
                    if isinstance(child, ast.Name) and child.id == param_name:
                        return True

            # Pattern: raise ValueError if param used in a raise expression
            if isinstance(node, ast.Raise) and node.exc is not None:
                for child in ast.walk(node.exc):
                    if isinstance(child, ast.Name) and child.id == param_name:
                        return True

        return False