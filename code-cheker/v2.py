"""
V2 - SEMANTIC ANALYSIS + SAST-LITE (IMPROVED)
==============================================
Enhanced AST analysis with better logic detection
"""
import ast
import re
from typing import Dict, Any, List, Set
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a single finding"""
    line: int
    type: str  # 'logic' | 'maintainability' | 'security'
    severity: str  # 'high' | 'medium' | 'low'
    confidence: str  # 'high' | 'medium' | 'low'
    message: str
    suggestion: str = ""
    code_snippet: str = ""
    category: str = ""  # For deduplication


class ComplexityAnalyzer:
    """Calculates cyclomatic complexity and nesting depth"""
    
    def analyze_function(self, node: ast.FunctionDef) -> Dict[str, int]:
        """Calculate complexity metrics for a function"""
        cyclomatic = self._calc_cyclomatic(node)
        nesting = self._calc_nesting(node)
        
        return {
            "cyclomatic": cyclomatic,
            "nesting_depth": nesting,
            "risk_level": self._get_risk_level(cyclomatic)
        }
    
    def _calc_cyclomatic(self, node: ast.AST) -> int:
        """McCabe cyclomatic complexity"""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.IfExp):
                complexity += 1
            elif isinstance(child, ast.Match):
                complexity += len(child.cases)
        
        return complexity
    
    def _calc_nesting(self, node: ast.AST) -> int:
        """Calculate maximum nesting depth"""
        max_depth = 0
        
        def visit(n, depth):
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            
            if isinstance(n, (ast.If, ast.While, ast.For, ast.AsyncFor, 
                            ast.With, ast.Try, ast.FunctionDef)):
                depth += 1
            
            for child in ast.iter_child_nodes(n):
                visit(child, depth)
        
        visit(node, 0)
        return max_depth
    
    def _get_risk_level(self, cyclomatic: int) -> str:
        if cyclomatic <= 5:
            return "LOW"
        elif cyclomatic <= 10:
            return "MEDIUM"
        elif cyclomatic <= 15:
            return "HIGH"
        else:
            return "CRITICAL"


class SASTLiteAnalyzer:
    """Lightweight security static analysis"""
    
    DANGEROUS_SINKS = {'eval', 'exec', 'compile', '__import__'}
    DANGEROUS_MODULES = {'os.system', 'subprocess.call', 'subprocess.run', 
                         'subprocess.Popen', 'pickle.loads', 'yaml.load'}
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\'](.+)["\']', 'hardcoded password'),
        (r'api[_-]?key\s*=\s*["\'](.+)["\']', 'hardcoded API key'),
        (r'secret\s*=\s*["\'](.+)["\']', 'hardcoded secret'),
        (r'token\s*=\s*["\'](.+)["\']', 'hardcoded token'),
    ]
    
    def analyze(self, tree: ast.AST, code: str) -> List[Finding]:
        """Run SAST-lite security checks"""
        findings = []
        
        findings.extend(self._check_dangerous_sinks(tree))
        findings.extend(self._check_sql_injection(tree))
        findings.extend(self._check_hardcoded_secrets(code))
        findings.extend(self._check_insecure_deserialization(tree))
        
        return findings
    
    def _check_dangerous_sinks(self, tree: ast.AST) -> List[Finding]:
        """Detect eval/exec with user input"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                
                if func_name in self.DANGEROUS_SINKS:
                    findings.append(Finding(
                        line=node.lineno,
                        type='security',
                        severity='high',
                        confidence='high',
                        message=f"Dangerous function '{func_name}' allows arbitrary code execution",
                        suggestion="Avoid eval/exec. Use safer alternatives like ast.literal_eval",
                        category="dangerous_sink"
                    ))
                
                if func_name in self.DANGEROUS_MODULES:
                    findings.append(Finding(
                        line=node.lineno,
                        type='security',
                        severity='high',
                        confidence='medium',
                        message=f"Potentially dangerous call to '{func_name}'",
                        suggestion="Validate inputs. Use subprocess with shell=False",
                        category="dangerous_module"
                    ))
        
        return findings
    
    def _check_sql_injection(self, tree: ast.AST) -> List[Finding]:
        """Detect SQL queries built with string concatenation"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
                if self._looks_like_sql(node):
                    findings.append(Finding(
                        line=node.lineno,
                        type='security',
                        severity='high',
                        confidence='medium',
                        message="Possible SQL injection: query built with string concatenation",
                        suggestion="Use parameterized queries (e.g., cursor.execute(query, params))",
                        category="sql_injection"
                    ))
        
        return findings
    
    def _looks_like_sql(self, node: ast.BinOp) -> bool:
        """Heuristic: does this look like SQL being built?"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
        
        def get_str_value(n):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return n.value.upper()
            return ""
        
        left_str = get_str_value(node.left)
        right_str = get_str_value(node.right)
        
        return any(kw in left_str or kw in right_str for kw in sql_keywords)
    
    def _check_hardcoded_secrets(self, code: str) -> List[Finding]:
        """Detect hardcoded passwords, API keys, tokens"""
        findings = []
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, secret_type in self.SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        line=i,
                        type='security',
                        severity='high',
                        confidence='medium',
                        message=f"Potential {secret_type} in source code",
                        suggestion="Use environment variables or a secrets manager",
                        category="hardcoded_secret"
                    ))
        
        return findings
    
    def _check_insecure_deserialization(self, tree: ast.AST) -> List[Finding]:
        """Detect pickle.loads, yaml.load without safe loader"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                
                if func_name == 'pickle.loads':
                    findings.append(Finding(
                        line=node.lineno,
                        type='security',
                        severity='high',
                        confidence='high',
                        message="pickle.loads() can execute arbitrary code",
                        suggestion="Only unpickle data from trusted sources. Consider JSON",
                        category="insecure_deserialization"
                    ))
                
                if func_name == 'yaml.load':
                    safe_loader_used = any(
                        isinstance(kw.value, ast.Attribute) and 
                        kw.value.attr in ['SafeLoader', 'BaseLoader']
                        for kw in node.keywords if kw.arg == 'Loader'
                    )
                    
                    if not safe_loader_used:
                        findings.append(Finding(
                            line=node.lineno,
                            type='security',
                            severity='medium',
                            confidence='high',
                            message="yaml.load() without SafeLoader can execute code",
                            suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                            category="insecure_deserialization"
                        ))
        
        return findings


class SemanticAnalyzer:
    """Main semantic analysis engine"""
    
    def __init__(self):
        self.complexity_analyzer = ComplexityAnalyzer()
        self.sast_analyzer = SASTLiteAnalyzer()
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """Perform full semantic analysis"""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "valid": False,
                "syntax_error": {
                    "message": str(e),
                    "line": e.lineno,
                    "offset": e.offset
                }
            }
        
        findings = []
        functions = []
        classes = []
        imports = self._extract_imports(tree)
        
        defined_funcs = set()
        called_funcs = set()
        
        # Analyze functions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                defined_funcs.add(node.name)
                func_info = self._analyze_function(node, code)
                functions.append(func_info)
                findings.extend(func_info.get("findings", []))
                
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        called_funcs.add(child.func.id)
            
            elif isinstance(node, ast.ClassDef):
                class_info = self._analyze_class(node)
                classes.append(class_info)
                if class_info.get("is_god_class"):
                    findings.append(Finding(
                        line=node.lineno,
                        type='maintainability',
                        severity='medium',
                        confidence='medium',
                        message=f"Class '{node.name}' has {class_info['method_count']} methods (god class)",
                        suggestion="Break into smaller, focused classes",
                        category="god_class"
                    ))
            
            elif isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(Finding(
                    line=node.lineno,
                    type='logic',
                    severity='high',
                    confidence='high',
                    message="Bare except catches all exceptions, hiding bugs",
                    suggestion="Catch specific exception types (e.g., except ValueError:)",
                    category="bare_except"
                ))
        
        # Check for math precedence bugs (ADDED)
        findings.extend(self._check_precedence_bugs(tree, code))
        
        # SAST-lite security
        sast_findings = self.sast_analyzer.analyze(tree, code)
        findings.extend(sast_findings)
        
        # File operations
        findings.extend(self._check_unsafe_file_ops(tree))
        
        # Main guard
        has_main_guard = self._has_main_guard(tree)
        has_executable_code = self._has_top_level_executable(tree)
        if has_executable_code and not has_main_guard:
            findings.append(Finding(
                line=1,
                type='maintainability',
                severity='low',  # Reduced from medium
                confidence='high',
                message="Script has executable code but no 'if __name__ == \"__main__\":' guard",
                suggestion="Add guard to prevent code execution on import",
                category="missing_main_guard"
            ))
        
        return {
            "valid": True,
            "functions": functions,
            "classes": classes,
            "imports": list(imports),
            "findings": [self._finding_to_dict(f) for f in findings],
            "metrics": {
                "function_count": len(functions),
                "class_count": len(classes),
                "import_count": len(imports),
                "defined_functions": len(defined_funcs),
                "called_functions": len(called_funcs)
            }
        }
    
    def _check_precedence_bugs(self, tree: ast.AST, code: str) -> List[Finding]:
        """Detect division followed by multiplication without parentheses"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp):
                # Pattern: (a / b) * c or similar
                if isinstance(node.op, ast.Mult):
                    if isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Div):
                        findings.append(Finding(
                            line=node.lineno,
                            type='logic',
                            severity='high',
                            confidence='medium',
                            message="Division followed by multiplication - operator precedence may cause bugs",
                            suggestion="Use parentheses to clarify: (a / b) * c or a / (b * c)",
                            category="precedence_bug"
                        ))
        
        return findings
    
    def _extract_imports(self, tree: ast.AST) -> Set[str]:
        """Extract all imported modules"""
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
        return imports
    
    def _analyze_function(self, node: ast.FunctionDef, code: str) -> Dict:
        """Analyze a single function"""
        start_line = node.lineno
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
        func_length = end_line - start_line + 1
        arg_count = len(node.args.args)
        
        complexity = self.complexity_analyzer.analyze_function(node)
        findings = []
        
        # High complexity
        if complexity["cyclomatic"] > 10:
            findings.append(Finding(
                line=start_line,
                type='maintainability',
                severity='high' if complexity["cyclomatic"] > 15 else 'medium',
                confidence='high',
                message=f"Function '{node.name}' has cyclomatic complexity {complexity['cyclomatic']}",
                suggestion=f"Refactor into smaller functions (complexity: {complexity['cyclomatic']}, nesting: {complexity['nesting_depth']})",
                category="high_complexity"
            ))
        
        # Long function
        if func_length > 50:
            findings.append(Finding(
                line=start_line,
                type='maintainability',
                severity='medium',
                confidence='high',
                message=f"Function '{node.name}' is {func_length} lines long",
                suggestion="Split into smaller functions with single responsibilities",
                category="long_function"
            ))
        
        # Too many parameters
        if arg_count > 5:
            findings.append(Finding(
                line=start_line,
                type='maintainability',
                severity='medium',
                confidence='high',
                message=f"Function '{node.name}' has {arg_count} parameters",
                suggestion="Consider using a dataclass, dict, or **kwargs",
                category="many_params"
            ))
        
        return {
            "name": node.name,
            "line": start_line,
            "length": func_length,
            "args_count": arg_count,
            "complexity": complexity,
            "findings": findings
        }
    
    def _analyze_class(self, node: ast.ClassDef) -> Dict:
        """Analyze a class"""
        methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
        return {
            "name": node.name,
            "line": node.lineno,
            "methods": methods,
            "method_count": len(methods),
            "is_god_class": len(methods) > 10
        }
    
    def _has_main_guard(self, tree: ast.AST) -> bool:
        """Check for if __name__ == '__main__': guard"""
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare):
                    if (isinstance(test.left, ast.Name) and test.left.id == '__name__' and
                        any(isinstance(comp, ast.Constant) and comp.value == '__main__' 
                            for comp in test.comparators)):
                        return True
        return False
    
    def _has_top_level_executable(self, tree: ast.AST) -> bool:
        """Check for executable code at module level"""
        for node in tree.body:
            if isinstance(node, (ast.Expr, ast.Assign, ast.AugAssign)):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    continue
                return True
            elif isinstance(node, ast.If) and not self._is_main_guard(node):
                return True
        return False
    
    def _is_main_guard(self, node: ast.If) -> bool:
        """Check if this is the __main__ guard"""
        test = node.test
        if isinstance(test, ast.Compare):
            return (isinstance(test.left, ast.Name) and test.left.id == '__name__' and
                   any(isinstance(comp, ast.Constant) and comp.value == '__main__' 
                       for comp in test.comparators))
        return False
    
    def _check_unsafe_file_ops(self, tree: ast.AST) -> List[Finding]:
        """Detect open() calls without context manager"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'open':
                    is_safe = False
                    for parent in ast.walk(tree):
                        if isinstance(parent, ast.With):
                            for item in parent.items:
                                if item.context_expr == node:
                                    is_safe = True
                                    break
                    
                    if not is_safe:
                        findings.append(Finding(
                            line=node.lineno,
                            type='logic',
                            severity='medium',
                            confidence='high',
                            message="File opened without context manager",
                            suggestion="Use 'with open(...) as f:' to ensure file is closed",
                            category="unsafe_file_op"
                        ))
        
        return findings
    
    def _finding_to_dict(self, finding: Finding) -> Dict:
        """Convert Finding to dict"""
        return {
            "line": finding.line,
            "type": finding.type,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "message": finding.message,
            "suggestion": finding.suggestion,
            "code_snippet": finding.code_snippet,
            "category": finding.category
        }