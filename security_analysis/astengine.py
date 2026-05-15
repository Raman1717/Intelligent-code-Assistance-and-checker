"""
AST ENGINE MODULE
=================
Contains: Finding dataclass, Shared AST utilities
"""
import ast
from typing import List, Set, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class Finding:
    """A single code quality finding"""
    line: int
    category: str
    severity: str
    confidence: str
    message: str
    check_id: str
    blocking: bool = False
    suggestion: str = ""
    code_snippet: str = ""
    source: str = "ast"
    
    def to_dict(self):
        return {
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "check_id": self.check_id,
            "blocking": self.blocking,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet,
            "source": self.source
        }


class ASTEngine:
    """Shared AST traversal utilities"""
    
    def __init__(self):
        self.code_lines: List[str] = []
        self.tree: Optional[ast.AST] = None
        
        # Cached collections
        self.calls: List[ast.Call] = []
        self.functions = {}
        self.classes = {}
        self.loops: List[ast.For] = []
        self.if_statements: List[ast.If] = []
        self.try_blocks: List[ast.Try] = []
        self.with_statements: List[ast.With] = []
        
        self.defined_vars = defaultdict(set)
        self.used_vars = defaultdict(set)
        self.loop_vars: Set[str] = set()
        self.imports: Set[str] = set()
    
    def parse_code(self, code: str):
        """Parse code and collect all nodes"""
        self.code_lines = code.split('\n')
        
        try:
            self.tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "valid": False,
                "syntax_error": {
                    "line": e.lineno,
                    "offset": e.offset,
                    "message": str(e)
                }
            }
        
        self._collect_all_nodes()
        return {"valid": True}
    
    def _collect_all_nodes(self):
        """Cache all nodes"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self.calls.append(node)
            elif isinstance(node, ast.FunctionDef):
                self.functions[node.name] = node
                for arg in node.args.args:
                    self.defined_vars[arg.arg].add(node.lineno)
            elif isinstance(node, ast.ClassDef):
                self.classes[node.name] = node
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self.loops.append(node)
                if isinstance(node.target, ast.Name):
                    self.loop_vars.add(node.target.id)
            elif isinstance(node, ast.If):
                self.if_statements.append(node)
            elif isinstance(node, ast.Try):
                self.try_blocks.append(node)
            elif isinstance(node, ast.With):
                self.with_statements.append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.imports.add(alias.name.split('.')[0])
                elif node.module:
                    self.imports.add(node.module.split('.')[0])
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in ast.walk(node):
                    if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
                        self.defined_vars[target.id].add(node.lineno)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.used_vars[node.id].add(node.lineno)
    
    def get_code_snippet(self, line_num: int, context: int = 2) -> str:
        """Extract code snippet"""
        if not self.code_lines or line_num < 1:
            return ""
        
        start = max(0, line_num - context - 1)
        end = min(len(self.code_lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{self.code_lines[i]}")
        
        return "\n".join(snippet_lines)
    
    def get_call_name(self, node: ast.Call) -> str:
        """Get full name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            base = self._get_full_name(node.func.value)
            return f"{base}.{node.func.attr}" if base else node.func.attr
        return ""
    
    def _get_full_name(self, node: ast.AST) -> str:
        """Get full qualified name"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_full_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""
    
    def calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
    
    def calculate_nesting_depth(self, node: ast.AST, depth: int = 0) -> int:
        """Calculate maximum nesting depth"""
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                child_depth = self.calculate_nesting_depth(child, depth + 1)
                max_depth = max(max_depth, child_depth)
        return max_depth
    
    def is_in_with_statement(self, target_node: ast.AST) -> bool:
        """Check if node is in with statement"""
        for node in self.with_statements:
            for item in node.items:
                if item.context_expr is target_node:
                    return True
        return False
    
    def is_in_try_block(self, target_node: ast.AST) -> bool:
        """Check if node is in try block"""
        for node in self.try_blocks:
            for stmt in node.body:
                if target_node in ast.walk(stmt):
                    return True
        return False
    
    def has_main_guard(self) -> bool:
        """Check if code has __main__ guard"""
        for node in self.if_statements:
            test = node.test
            if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
                if test.left.id == '__name__':
                    for comp in test.comparators:
                        if isinstance(comp, ast.Constant) and comp.value == '__main__':
                            return True
        return False
    
    def has_top_level_executable(self) -> bool:
        """Check if code has top-level executable statements"""
        for node in self.tree.body:
            if isinstance(node, (ast.Expr, ast.Assign)):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    continue
                return True
        return False
    
    def calculate_metrics(self):
        """Calculate code metrics"""
        return {
            "function_count": len(self.functions),
            "class_count": len(self.classes),
            "import_count": len(self.imports),
            "lines_of_code": len(self.code_lines),
            "max_complexity": self._max_complexity()
        }
    
    def _max_complexity(self) -> int:
        if not self.functions:
            return 0
        return max(self.calculate_complexity(f) for f in self.functions.values())
    
    def get_function_info(self):
        """Get function information"""
        return [
            {
                "name": func.name,
                "line": func.lineno,
                "length": (func.end_lineno or func.lineno) - func.lineno + 1,
                "params": len(func.args.args),
                "complexity": self.calculate_complexity(func)
            }
            for func in self.functions.values()
        ]
    
    def get_class_info(self):
        """Get class information"""
        return [
            {
                "name": cls.name,
                "line": cls.lineno,
                "methods": sum(1 for n in cls.body if isinstance(n, ast.FunctionDef))
            }
            for cls in self.classes.values()
        ]
