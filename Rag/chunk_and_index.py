"""
ENHANCED CODE RAG SYSTEM - Code Chunking + Metadata Indexing
================================================================
IMPROVEMENTS APPLIED:
1. ✅ Decorator capture (decorators stay with their function)
2. ✅ Nested function handling (closures indexed separately)
3. ✅ Type hint extraction (return types, parameter types)
4. ✅ __init__ method indexed separately from class
5. ✅ dataclass / TypedDict / Protocol class detection
6. ✅ Fixed fuzzy_match using difflib (no more false positives)
7. ✅ Fixed double AST parsing (CodeAnalyzer result passed through)
8. ✅ Function call graph used for query expansion signals
9. ✅ Weighted keyword importance (function names > variables)
10. ✅ Docstring extraction for semantic understanding
11. ✅ FIXED: Incomplete chunks — blank lines no longer trigger early block pop
12. ✅ FIXED: Block collection now uses AST line numbers as ground truth
"""

import os
import re
import ast
import pickle
import difflib
from typing import List, Dict, Any, Tuple, Set, Optional
from collections import defaultdict, Counter
import logging

try:
    from nltk.corpus import stopwords
    import nltk
    try:
        STOPWORDS = set(stopwords.words('english'))
    except LookupError:
        nltk.download('stopwords', quiet=True)
        STOPWORDS = set(stopwords.words('english'))

    PYTHON_KEYWORDS = {
        'def', 'class', 'if', 'elif', 'else', 'for', 'while', 'in', 'and', 'or',
        'not', 'with', 'as', 'from', 'import', 'return', 'yield', 'self', 'cls',
        'true', 'false', 'none', 'try', 'except', 'finally', 'pass', 'break',
        'continue', 'async', 'await', 'lambda', 'raise', 'assert', 'del', 'global',
        'nonlocal', 'is', 'print', 'len', 'range', 'str', 'int', 'float', 'list',
        'dict', 'set', 'tuple', 'type', 'object', 'super'
    }
    STOPWORDS.update(PYTHON_KEYWORDS)
except ImportError:
    logging.warning("NLTK not available, using minimal stopwords")
    STOPWORDS = {
        'the', 'is', 'at', 'on', 'def', 'class', 'if', 'for', 'in', 'and', 'or',
        'as', 'with', 'from', 'import', 'return', 'self', 'true', 'false', 'none',
        'try', 'except', 'pass', 'async', 'await', 'elif', 'else', 'while'
    }

logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
CHUNK_SIZE_MIN = 800
CHUNK_SIZE_MAX = 2500
CHUNK_OVERLAP = 150
FUNCTION_SPLIT_THRESHOLD = 2500

# ✅ METADATA BOOST WEIGHTS
DEFAULT_METADATA_BOOST = {
    'exact_match': 2.8,
    'name': 2.2,
    'keywords': 1.5,
    'chunk_type': 0.8,
    'function_calls': 1.0,
    'docstring_match': 1.2,
    'type_hint_match': 1.1,
    'decorator_match': 0.9
}

# ✅ Python-specific special class types
SPECIAL_CLASS_TYPES = {
    'dataclass', 'TypedDict', 'Protocol', 'ABC', 'NamedTuple', 'Enum', 'IntEnum'
}


class CodeAnalyzer:
    """
    Analyzes Python code structure to extract relationships, type hints, decorators.
    Single source of truth — result is passed through, never re-parsed.
    """

    def __init__(self):
        self.function_calls = defaultdict(set)
        self.called_by = defaultdict(set)
        self.imports = set()
        self.external_libs = set()
        self.all_functions = set()
        self.all_classes = set()
        self.decorators = defaultdict(list)
        self.type_hints = defaultdict(dict)
        self.nested_functions = defaultdict(list)
        self.special_classes = defaultdict(str)
        self.init_methods = set()
        # ✅ NEW: Store AST node line ranges for accurate block extraction
        self.node_line_ranges = {}   # name -> (lineno, end_lineno)
        self.node_decorators_start = {}  # name -> decorator start line (1-based)

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Analyze code structure using AST — called ONCE, result passed everywhere."""
        try:
            tree = ast.parse(code)
            self._extract_structure(tree)
            return self._build_result()
        except SyntaxError as e:
            logger.warning(f"Syntax error in code analysis: {e}")
            return self._fallback_analysis(code)

    def _build_result(self) -> Dict[str, Any]:
        return {
            'function_calls': dict(self.function_calls),
            'called_by': dict(self.called_by),
            'imports': list(self.imports),
            'external_libs': list(self.external_libs),
            'all_functions': list(self.all_functions),
            'all_classes': list(self.all_classes),
            'decorators': dict(self.decorators),
            'type_hints': dict(self.type_hints),
            'nested_functions': dict(self.nested_functions),
            'special_classes': dict(self.special_classes),
            'init_methods': list(self.init_methods),
            # ✅ NEW: Pass line ranges so chunker doesn't need to re-detect them
            'node_line_ranges': dict(self.node_line_ranges),
            'node_decorators_start': dict(self.node_decorators_start),
        }

    def _extract_structure(self, tree):
        """Extract function calls, relationships, type hints, decorators from AST."""

        # First pass — collect class info
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self.all_classes.add(node.name)
                dec_names = self._get_decorator_names(node)
                if dec_names:
                    self.decorators[node.name] = dec_names

                # ✅ Store line range (AST lines are 1-based)
                dec_start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
                self.node_line_ranges[node.name] = (node.lineno, node.end_lineno)
                self.node_decorators_start[node.name] = dec_start

                for dec in dec_names:
                    if dec in SPECIAL_CLASS_TYPES:
                        self.special_classes[node.name] = dec

                for base in node.bases:
                    base_name = self._get_name(base)
                    if base_name in SPECIAL_CLASS_TYPES:
                        self.special_classes[node.name] = base_name

                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == '__init__':
                        self.init_methods.add(node.name)

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.add(alias.name)
                    self.external_libs.add(alias.name.split('.')[0])

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.imports.add(node.module)
                    self.external_libs.add(node.module.split('.')[0])

        # Second pass — collect functions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                self.all_functions.add(func_name)

                dec_names = self._get_decorator_names(node)
                if dec_names:
                    self.decorators[func_name] = dec_names

                self.type_hints[func_name] = self._extract_type_hints(node)

                # ✅ Store accurate line range from AST
                dec_start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
                self.node_line_ranges[func_name] = (node.lineno, node.end_lineno)
                self.node_decorators_start[func_name] = dec_start

                for child in ast.walk(node):
                    if child is node:
                        continue
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                        self.nested_functions[func_name].append(child.name)
                    if isinstance(child, ast.Call):
                        called_name = self._get_call_name(child)
                        if called_name:
                            self.function_calls[func_name].add(called_name)
                            self.called_by[called_name].add(func_name)

    def _get_decorator_names(self, node) -> List[str]:
        names = []
        for dec in node.decorator_list:
            name = self._get_name(dec)
            if name:
                names.append(name)
        return names

    def _get_name(self, node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        return None

    def _extract_type_hints(self, node) -> Dict[str, str]:
        hints = {}
        if node.returns:
            hints['return'] = ast.unparse(node.returns) if hasattr(ast, 'unparse') else 'annotated'

        args = node.args
        all_args = args.args + args.posonlyargs + args.kwonlyargs
        if args.vararg:
            all_args.append(args.vararg)
        if args.kwarg:
            all_args.append(args.kwarg)

        for arg in all_args:
            if arg.annotation:
                try:
                    hints[arg.arg] = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else 'annotated'
                except Exception:
                    hints[arg.arg] = 'annotated'

        return hints

    def _get_call_name(self, call_node) -> Optional[str]:
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr
        return None

    def _fallback_analysis(self, code: str) -> Dict[str, Any]:
        functions = set(re.findall(r'def\s+(\w+)', code))
        classes = set(re.findall(r'class\s+(\w+)', code))
        imports = set(re.findall(r'import\s+(\w+)', code))
        return {
            'function_calls': {},
            'called_by': {},
            'imports': list(imports),
            'external_libs': list(imports),
            'all_functions': list(functions),
            'all_classes': list(classes),
            'decorators': {},
            'type_hints': {},
            'nested_functions': {},
            'special_classes': {},
            'init_methods': [],
            'node_line_ranges': {},
            'node_decorators_start': {},
        }


class PythonChunker:
    """
    Enhanced Python code chunker.
    ✅ FIX: Uses AST line numbers as ground truth for block boundaries.
    No more early block termination due to blank lines or indent misdetection.
    """

    def __init__(self, min_size: int = CHUNK_SIZE_MIN, max_size: int = CHUNK_SIZE_MAX,
                 overlap: int = CHUNK_OVERLAP):
        self.min_size = min_size
        self.max_size = max_size
        self.overlap = overlap
        self.function_split_threshold = FUNCTION_SPLIT_THRESHOLD
        self.code_structure = {}

    def chunk_code(self, code: str, source_name: str = "input.py",
                   precomputed_structure: Optional[Dict] = None) -> List[Dict]:
        """
        Chunk Python code with enhanced metadata extraction.
        Uses AST line ranges to ensure complete, accurate blocks.
        """
        if precomputed_structure:
            self.code_structure = precomputed_structure
            logger.info("✓ Using pre-computed code structure (no re-parse)")
        else:
            analyzer = CodeAnalyzer()
            self.code_structure = analyzer.analyze_code(code)

        logger.info(f"✓ Code structure: {len(self.code_structure['all_functions'])} functions, "
                    f"{len(self.code_structure['all_classes'])} classes")

        lines = code.split('\n')

        # ✅ PRIMARY PATH: Use AST line ranges (accurate, complete blocks)
        blocks = self._identify_blocks_from_ast(lines)

        if not blocks:
            # Fallback to regex-based identification if AST ranges unavailable
            blocks = self._identify_blocks_regex_fallback(lines)

        if blocks:
            chunks = []
            for block in blocks:
                chunks.extend(self._chunk_block(block, source_name))

            chunks.extend(self._extract_init_chunks(lines, source_name))
            chunks.extend(self._extract_nested_function_chunks(lines, source_name))
            chunks = self._enrich_with_relationships(chunks)
            return chunks

        return self._simple_chunk(lines, source_name)

    # =========================================================
    # ✅ NEW PRIMARY METHOD: AST-based block identification
    # =========================================================

    def _identify_blocks_from_ast(self, lines: List[str]) -> List[Dict]:
        """
        ✅ CORE FIX: Build blocks directly from AST line number data.
        
        AST gives us exact (lineno, end_lineno) for every function/class,
        so blank lines, indent quirks, and multiline strings can never
        cause early termination of block collection.
        
        Lines in AST are 1-based; list index is 0-based.
        """
        node_ranges = self.code_structure.get('node_line_ranges', {})
        node_dec_starts = self.code_structure.get('node_decorators_start', {})

        if not node_ranges:
            logger.warning("No AST line ranges available — falling back to regex")
            return []

        all_functions = set(self.code_structure.get('all_functions', []))
        all_classes = set(self.code_structure.get('all_classes', []))

        # Build import block first
        import_lines = []
        import_start = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                if import_start is None:
                    import_start = i
                import_lines.append(line)

        blocks = []

        if import_lines and import_start is not None:
            blocks.append({
                'type': 'imports',
                'name': 'imports',
                'start': import_start,          # 0-based
                'lines': import_lines,
                'indent': 0,
                'docstring': None,
                'decorators': [],
                'type_hints': {},
                'special_type': None,
                'is_async': False,
            })

        # Build a set of class names so we can skip methods defined inside them
        # (they'll be included as part of the class block)
        class_ranges = {}
        for name in all_classes:
            if name in node_ranges:
                start_1, end_1 = node_ranges[name]
                class_ranges[name] = (start_1, end_1)

        def is_inside_class(func_lineno: int) -> bool:
            """Return True if this function's line falls inside any class body."""
            for cls_start, cls_end in class_ranges.values():
                if cls_start < func_lineno <= cls_end:
                    return True
            return False

        # ✅ Add top-level classes
        for name in all_classes:
            if name not in node_ranges:
                continue
            lineno, end_lineno = node_ranges[name]          # 1-based
            dec_start = node_dec_starts.get(name, lineno)   # 1-based

            # Convert to 0-based slice indices
            start_idx = dec_start - 1
            end_idx = end_lineno          # exclusive in slice = end_lineno (1-based) maps to index end_lineno-1

            block_lines = lines[start_idx:end_idx]

            blocks.append({
                'type': 'class',
                'name': name,
                'start': start_idx,
                'lines': block_lines,
                'indent': len(lines[lineno - 1]) - len(lines[lineno - 1].lstrip()),
                'docstring': self._extract_docstring(lines, lineno),   # lineno is 1-based → index lineno-1+1 = lineno
                'decorators': self.code_structure.get('decorators', {}).get(name, []),
                'type_hints': {},
                'special_type': self.code_structure.get('special_classes', {}).get(name),
                'is_async': False,
            })

        # ✅ Add top-level functions (skip methods inside classes)
        for name in all_functions:
            if name not in node_ranges:
                continue
            lineno, end_lineno = node_ranges[name]
            dec_start = node_dec_starts.get(name, lineno)

            # Skip methods (they live inside a class block already)
            if is_inside_class(lineno):
                continue

            start_idx = dec_start - 1
            end_idx = end_lineno

            block_lines = lines[start_idx:end_idx]

            # Detect async
            def_line = lines[lineno - 1].lstrip()
            is_async = def_line.startswith('async ')

            blocks.append({
                'type': 'function',
                'name': name,
                'start': start_idx,
                'lines': block_lines,
                'indent': len(lines[lineno - 1]) - len(lines[lineno - 1].lstrip()),
                'docstring': self._extract_docstring(lines, lineno),
                'decorators': self.code_structure.get('decorators', {}).get(name, []),
                'type_hints': self.code_structure.get('type_hints', {}).get(name, {}),
                'special_type': None,
                'is_async': is_async,
            })

        # Sort blocks by their start line so output is ordered naturally
        blocks.sort(key=lambda b: b['start'])
        return blocks

    # =========================================================
    # Fallback: original regex-based identification (FIXED)
    # =========================================================

    def _identify_blocks_regex_fallback(self, lines: List[str]) -> List[Dict]:
        """
        Regex-based fallback block identification with the blank-line fix applied.
        Only used when AST line ranges are unavailable (e.g. after a SyntaxError fallback).
        
        ✅ FIX vs original: blank lines are now skipped in the indent-pop check,
        preventing premature block termination.
        """
        blocks = []
        stack = []
        in_multiline = None
        pending_decorators = []

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # ── Multiline string handling ──────────────────────────────────
            if in_multiline:
                if stack:
                    stack[-1]['lines'].append(line)
                if in_multiline in stripped and stripped.index(in_multiline) > 0:
                    in_multiline = None
                continue

            for quote in ['"""', "'''"]:
                if stripped.startswith(quote) and stripped.count(quote) == 1:
                    in_multiline = quote
                    if stack:
                        stack[-1]['lines'].append(line)
                    break

            if in_multiline:
                continue

            # ── Decorator collection ───────────────────────────────────────
            if stripped.startswith('@') and not stack:
                pending_decorators.append(line)
                continue

            # ── ✅ FIXED: Pop completed blocks ─────────────────────────────
            # OLD (buggy): fired on blank lines because indent==0 <= anything
            # NEW: skip blank lines entirely; only pop on real non-empty lines
            if stripped:   # ← KEY FIX: ignore blank lines for pop decision
                while stack and indent <= stack[-1]['indent'] and i > stack[-1]['start'] + 1:
                    if not stripped.startswith(('#', '"""', "'''", '@', ')', ']', '}')):
                        blocks.append(stack.pop())
                    else:
                        break

            # ── Class definition ───────────────────────────────────────────
            if match := re.match(r'(async\s+)?class\s+(\w+)', stripped):
                block = {
                    'type': 'class',
                    'name': match.group(2),
                    'start': i - len(pending_decorators),
                    'lines': pending_decorators + [line],
                    'indent': indent,
                    'docstring': None,
                    'decorators': [d.strip() for d in pending_decorators],
                    'special_type': self.code_structure.get('special_classes', {}).get(match.group(2)),
                    'is_async': False,
                    'type_hints': {},
                }
                pending_decorators = []
                stack.append(block)

            # ── Function definition ────────────────────────────────────────
            elif match := re.match(r'(async\s+)?def\s+(\w+)', stripped):
                if stack and stack[-1]['type'] == 'class' and indent > stack[-1]['indent']:
                    # Method inside class — add to class block
                    stack[-1]['lines'].extend(pending_decorators)
                    stack[-1]['lines'].append(line)
                    pending_decorators = []
                else:
                    func_name = match.group(2)
                    block = {
                        'type': 'function',
                        'name': func_name,
                        'start': i - len(pending_decorators),
                        'lines': pending_decorators + [line],
                        'indent': indent,
                        'is_async': bool(match.group(1)),
                        'docstring': None,
                        'decorators': [d.strip() for d in pending_decorators],
                        'type_hints': self.code_structure.get('type_hints', {}).get(func_name, {}),
                        'special_type': None,
                    }
                    pending_decorators = []

                    if i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line.startswith('"""') or next_line.startswith("'''"):
                            block['docstring'] = self._extract_docstring(lines, i + 1)

                    stack.append(block)

            # ── Import line ────────────────────────────────────────────────
            elif 'import' in stripped and not stack:
                pending_decorators = []
                if blocks and blocks[-1]['type'] == 'imports':
                    blocks[-1]['lines'].append(line)
                else:
                    blocks.append({
                        'type': 'imports',
                        'name': 'imports',
                        'start': i,
                        'lines': [line],
                        'indent': 0,
                        'docstring': None,
                        'decorators': [],
                        'type_hints': {},
                        'special_type': None,
                        'is_async': False,
                    })

            # ── Line belongs to current open block ─────────────────────────
            elif stack:
                if pending_decorators:
                    stack[-1]['lines'].extend(pending_decorators)
                    pending_decorators = []
                stack[-1]['lines'].append(line)

            else:
                pending_decorators = []

        # Flush remaining stack
        blocks.extend(stack)
        return blocks

    # =========================================================
    # Docstring extractor (unchanged)
    # =========================================================

    def _extract_docstring(self, lines: List[str], start_idx: int) -> Optional[str]:
        """
        Extract docstring starting at start_idx (0-based or 1-based handled by caller).
        We treat start_idx as 0-based here.
        """
        # Normalise: AST gives 1-based lineno; add 1 to get the line after 'def'
        # The caller passes lineno (1-based def line), we want the next line (index = lineno)
        idx = start_idx  # already adjusted by caller
        docstring_lines = []
        quote_type = None

        for i in range(idx, min(idx + 20, len(lines))):
            line = lines[i].strip()
            if not quote_type:
                if line.startswith('"""'):
                    quote_type = '"""'
                elif line.startswith("'''"):
                    quote_type = "'''"
                else:
                    break
            docstring_lines.append(line)
            if quote_type and line.endswith(quote_type) and len(docstring_lines) > 1:
                break

        if docstring_lines:
            docstring = ' '.join(docstring_lines)
            docstring = docstring.replace('"""', '').replace("'''", '').strip()
            return docstring[:300]
        return None

    # =========================================================
    # __init__ chunk extractor (unchanged logic, minor cleanup)
    # =========================================================

    def _extract_init_chunks(self, lines: List[str], source_name: str) -> List[Dict]:
        """Extract __init__ methods as separate indexed chunks."""
        init_chunks = []
        in_class = None
        in_init = False
        init_lines = []
        init_start = 0
        class_indent = 0

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if class_match := re.match(r'class\s+(\w+)', stripped):
                in_class = class_match.group(1)
                class_indent = indent
                in_init = False
                init_lines = []

            if in_class and re.match(r'def\s+__init__\s*\(', stripped):
                in_init = True
                init_start = i
                init_lines = [line]
                continue

            if in_init:
                if stripped and indent <= class_indent + 4 and re.match(r'def\s+', stripped) and 'def __init__' not in stripped:
                    if init_lines:
                        init_chunks.append({
                            'content': '\n'.join(init_lines),
                            'metadata': {
                                'source': source_name,
                                'chunk_type': 'init_method',
                                'name': f"{in_class}.__init__",
                                'parent_class': in_class,
                                'line_start': init_start,
                                'line_count': len(init_lines),
                                'is_async': False,
                                'docstring': self._extract_docstring(lines, init_start + 1)
                            }
                        })
                    in_init = False
                    init_lines = []
                else:
                    init_lines.append(line)

        if in_init and init_lines:
            init_chunks.append({
                'content': '\n'.join(init_lines),
                'metadata': {
                    'source': source_name,
                    'chunk_type': 'init_method',
                    'name': f"{in_class}.__init__",
                    'parent_class': in_class,
                    'line_start': init_start,
                    'line_count': len(init_lines),
                    'is_async': False,
                    'docstring': None
                }
            })

        return init_chunks

    # =========================================================
    # Nested function chunk extractor (unchanged)
    # =========================================================

    def _extract_nested_function_chunks(self, lines: List[str], source_name: str) -> List[Dict]:
        """Extract nested/closure functions as separate retrievable chunks."""
        nested_chunks = []
        nested_map = self.code_structure.get('nested_functions', {})

        if not nested_map:
            return []

        all_nested_names = set()
        for nested_list in nested_map.values():
            all_nested_names.update(nested_list)

        if not all_nested_names:
            return []

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if indent > 0:
                if match := re.match(r'(async\s+)?def\s+(\w+)', stripped):
                    func_name = match.group(2)
                    if func_name in all_nested_names:
                        nested_lines = [line]
                        j = i + 1
                        while j < len(lines):
                            next_line = lines[j]
                            next_stripped = next_line.lstrip()
                            next_indent = len(next_line) - len(next_stripped)
                            if next_stripped and next_indent <= indent and not next_stripped.startswith(('#',)):
                                break
                            nested_lines.append(next_line)
                            j += 1

                        parent = None
                        for p, children in nested_map.items():
                            if func_name in children:
                                parent = p
                                break

                        nested_chunks.append({
                            'content': '\n'.join(nested_lines),
                            'metadata': {
                                'source': source_name,
                                'chunk_type': 'nested_function',
                                'name': f"{parent}.{func_name}" if parent else func_name,
                                'parent_function': parent,
                                'line_start': i,
                                'line_count': len(nested_lines),
                                'is_async': bool(match.group(1)),
                                'docstring': self._extract_docstring(lines, i + 1)
                            }
                        })
                        i = j
                        continue
            i += 1

        return nested_chunks

    # =========================================================
    # Block → chunk conversion (unchanged)
    # =========================================================

    def _chunk_block(self, block: Dict, source_name: str) -> List[Dict]:
        content = '\n'.join(block['lines'])
        size_threshold = self.function_split_threshold if block['type'] == 'function' else self.max_size

        if len(content) <= size_threshold:
            func_name = block['name']
            metadata = {
                'source': source_name,
                'chunk_type': block['type'],
                'name': func_name,
                'line_start': block['start'],
                'line_count': len(block['lines']),
                'is_async': block.get('is_async', False),
                'docstring': block.get('docstring'),
                'calls': list(self.code_structure.get('function_calls', {}).get(func_name, [])),
                'called_by': list(self.code_structure.get('called_by', {}).get(func_name, [])),
                'decorators': block.get('decorators', []),
                'type_hints': block.get('type_hints', {}),
                'special_type': block.get('special_type')
            }
            return [{'content': content, 'metadata': metadata}]

        return self._semantic_split(block, content, source_name)

    def _semantic_split(self, block: Dict, content: str, source_name: str) -> List[Dict]:
        chunks = []
        lines = content.split('\n')
        chunk_num = 0
        pos = 0

        while pos < len(lines):
            chunk_lines = []
            char_count = 0
            end_pos = pos

            for i in range(pos, len(lines)):
                line_len = len(lines[i]) + 1
                if char_count + line_len > self.max_size and chunk_lines:
                    break
                chunk_lines.append(lines[i])
                char_count += line_len
                end_pos = i + 1

            if char_count > self.min_size and end_pos < len(lines):
                break_point = self._find_semantic_break(chunk_lines)
                if break_point > len(chunk_lines) // 2:
                    chunk_lines = chunk_lines[:break_point]
                    end_pos = pos + break_point

            chunk_content = '\n'.join(chunk_lines)
            chunks.append({
                'content': chunk_content.strip(),
                'metadata': {
                    'source': source_name,
                    'chunk_type': block['type'],
                    'name': f"{block['name']}_part{chunk_num}",
                    'line_start': block['start'] + pos,
                    'line_count': len(chunk_lines),
                    'is_partial': True,
                    'is_async': block.get('is_async', False),
                    'parent_function': block['name'],
                    'decorators': block.get('decorators', []) if chunk_num == 0 else []
                }
            })

            overlap_lines = min(self.overlap // 50, len(chunk_lines) // 3)
            pos = max(end_pos - overlap_lines, end_pos - 5)
            chunk_num += 1

        return chunks

    def _find_semantic_break(self, lines: List[str]) -> int:
        for i in range(len(lines) - 1, max(0, len(lines) - 20), -1):
            stripped = lines[i].strip()
            if not stripped:
                return i + 1
            if stripped and not stripped.startswith(('#', 'elif', 'else', 'except', 'finally')):
                indent = len(lines[i]) - len(stripped)
                if i < len(lines) - 1:
                    next_indent = len(lines[i + 1]) - len(lines[i + 1].lstrip())
                    if next_indent < indent:
                        return i + 1
        return len(lines)

    def _simple_chunk(self, lines: List[str], source_name: str) -> List[Dict]:
        chunks = []
        current_lines = []
        current_size = 0
        chunk_num = 0

        for i, line in enumerate(lines):
            line_size = len(line) + 1
            if current_size + line_size > self.max_size and current_lines:
                chunk_type, name = self._identify_chunk_type('\n'.join(current_lines))
                chunks.append({
                    'content': '\n'.join(current_lines),
                    'metadata': {
                        'source': source_name,
                        'chunk_type': chunk_type,
                        'name': f"{name}_{chunk_num}",
                        'line_start': i - len(current_lines),
                        'line_count': len(current_lines)
                    }
                })

                overlap_lines = []
                overlap_size = 0
                for j in range(len(current_lines) - 1, -1, -1):
                    ln = len(current_lines[j]) + 1
                    if overlap_size + ln <= self.overlap:
                        overlap_lines.insert(0, current_lines[j])
                        overlap_size += ln
                    else:
                        break

                current_lines = overlap_lines
                current_size = overlap_size
                chunk_num += 1

            current_lines.append(line)
            current_size += line_size

        if current_lines:
            chunk_type, name = self._identify_chunk_type('\n'.join(current_lines))
            chunks.append({
                'content': '\n'.join(current_lines),
                'metadata': {
                    'source': source_name,
                    'chunk_type': chunk_type,
                    'name': f"{name}_{chunk_num}",
                    'line_start': len(lines) - len(current_lines),
                    'line_count': len(current_lines)
                }
            })

        return chunks

    def _identify_chunk_type(self, content: str) -> Tuple[str, str]:
        for line in content.strip().split('\n')[:5]:
            if match := re.search(r'(async\s+)?class\s+(\w+)', line):
                return 'class', match.group(2)
            if match := re.search(r'(async\s+)?def\s+(\w+)', line):
                return 'function', match.group(2)
            if 'import' in line:
                return 'imports', 'imports'
        return 'code_block', 'code'

    def _enrich_with_relationships(self, chunks: List[Dict]) -> List[Dict]:
        for chunk in chunks:
            name = chunk['metadata'].get('name', '')
            base_name = name.split('_part')[0]

            if base_name in self.code_structure.get('all_functions', []):
                chunk['metadata']['related_functions'] = list(
                    self.code_structure.get('function_calls', {}).get(base_name, set()) |
                    self.code_structure.get('called_by', {}).get(base_name, set())
                )

        return chunks


# =========================================================
# MetadataIndex (unchanged except pickling new fields)
# =========================================================

class MetadataIndex:
    """
    Fast keyword and name-based chunk lookup with:
    - Fixed fuzzy matching (difflib, no false positives)
    - Type hint indexing
    - Decorator indexing
    """

    def __init__(self):
        self.name_idx = defaultdict(set)
        self.type_idx = defaultdict(set)
        self.keyword_idx = defaultdict(set)
        self.exact_match_idx = defaultdict(set)
        self.docstring_idx = defaultdict(set)
        self.function_calls_idx = defaultdict(set)
        self.related_functions_idx = defaultdict(set)
        self.type_hint_idx = defaultdict(set)
        self.decorator_idx = defaultdict(set)
        self.all_keywords = set()

    def add(self, chunk_id: int, metadata: Dict, content: str):
        if name := metadata.get('name'):
            name_lower = name.lower()
            self.name_idx[name_lower].add(chunk_id)
            self.exact_match_idx[name_lower].add(chunk_id)

        if chunk_type := metadata.get('chunk_type'):
            self.type_idx[chunk_type.lower()].add(chunk_id)

        if docstring := metadata.get('docstring'):
            for word in docstring.lower().split():
                if len(word) > 3 and word not in STOPWORDS:
                    self.docstring_idx[word].add(chunk_id)

        if calls := metadata.get('calls'):
            for called_func in calls:
                self.function_calls_idx[called_func.lower()].add(chunk_id)

        if related := metadata.get('related_functions'):
            for rel_func in related:
                self.related_functions_idx[rel_func.lower()].add(chunk_id)

        if type_hints := metadata.get('type_hints'):
            for param, hint_type in type_hints.items():
                for token in re.findall(r'\w+', hint_type.lower()):
                    if len(token) > 2:
                        self.type_hint_idx[token].add(chunk_id)

        if decorators := metadata.get('decorators'):
            for dec in decorators:
                dec_clean = dec.lstrip('@').split('(')[0].lower()
                self.decorator_idx[dec_clean].add(chunk_id)

        for kw, _ in self._extract_keywords_weighted(metadata, content):
            kw_lower = kw.lower()
            self.keyword_idx[kw_lower].add(chunk_id)
            self.all_keywords.add(kw_lower)

    def _extract_keywords_weighted(self, metadata: Dict, content: str) -> List[Tuple[str, float]]:
        keywords = []

        if name := metadata.get('name'):
            keywords.extend([(part, 1.0) for part in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)', name)])
            keywords.extend([(part, 1.0) for part in name.split('_')])

        if source := metadata.get('source'):
            base = os.path.splitext(os.path.basename(source))[0]
            keywords.extend([(part, 0.7) for part in base.split('_')])

        if type_hints := metadata.get('type_hints'):
            for hint_type in type_hints.values():
                for token in re.findall(r'\w+', hint_type):
                    keywords.append((token, 0.8))

        if decorators := metadata.get('decorators'):
            for dec in decorators:
                dec_clean = dec.lstrip('@').split('(')[0]
                keywords.append((dec_clean, 0.8))

        code_sample = content[:500]

        for pattern in [r'\bdef\s+(\w+)', r'\bclass\s+(\w+)']:
            for match in re.finditer(pattern, code_sample):
                keywords.append((match.group(1), 0.9))

        for match in re.finditer(r'\b([A-Z][a-z]+[A-Z]\w*)', code_sample):
            keywords.append((match.group(1), 0.6))

        for match in re.finditer(r'\b([a-z_][a-z0-9_]{3,})\b', code_sample):
            word = match.group(1)
            if word not in STOPWORDS:
                keywords.append((word, 0.4))

        filtered = {}
        for kw, weight in keywords:
            if kw and len(kw) > 2 and kw.lower() not in STOPWORDS:
                if kw not in filtered or filtered[kw] < weight:
                    filtered[kw] = weight

        return list(filtered.items())

    def get_matches(self, query_terms: List[str]) -> Dict[str, Set[int]]:
        matches = defaultdict(set)

        for term in query_terms:
            term_lower = term.lower()

            if term_lower in self.exact_match_idx:
                matches['exact_match'].update(self.exact_match_idx[term_lower])

            for name, ids in self.name_idx.items():
                if self._fuzzy_match(term_lower, name):
                    matches['name'].update(ids)

            if term_lower in self.docstring_idx:
                matches['docstring_match'].update(self.docstring_idx[term_lower])

            if term_lower in self.function_calls_idx:
                matches['function_calls'].update(self.function_calls_idx[term_lower])

            if term_lower in self.related_functions_idx:
                matches['function_calls'].update(self.related_functions_idx[term_lower])

            if term_lower in self.type_hint_idx:
                matches['type_hint_match'].update(self.type_hint_idx[term_lower])

            if term_lower in self.decorator_idx:
                matches['decorator_match'].update(self.decorator_idx[term_lower])

            if term_lower in self.type_idx:
                matches['chunk_type'].update(self.type_idx[term_lower])

            for kw, ids in self.keyword_idx.items():
                if self._fuzzy_match(term_lower, kw):
                    matches['keywords'].update(ids)

        return matches

    def _fuzzy_match(self, term: str, target: str) -> bool:
        """
        Use difflib instead of character overlap.
        Requires 0.75 sequence similarity threshold.
        """
        if term == target:
            return True
        if term in target or target in term:
            if len(term) >= 5:
                return True
            if target.startswith(term) and len(term) >= 3:
                return True
            return False

        if len(term) >= 4 and len(target) >= 4:
            ratio = difflib.SequenceMatcher(None, term, target).ratio()
            return ratio >= 0.75

        return False

    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump({
                'name_idx': dict(self.name_idx),
                'type_idx': dict(self.type_idx),
                'keyword_idx': dict(self.keyword_idx),
                'exact_match_idx': dict(self.exact_match_idx),
                'docstring_idx': dict(self.docstring_idx),
                'function_calls_idx': dict(self.function_calls_idx),
                'related_functions_idx': dict(self.related_functions_idx),
                'type_hint_idx': dict(self.type_hint_idx),
                'decorator_idx': dict(self.decorator_idx),
                'all_keywords': list(self.all_keywords)
            }, f)

    @classmethod
    def load(cls, path: str) -> Optional['MetadataIndex']:
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)

            idx = cls()
            idx.name_idx = defaultdict(set, {k: set(v) for k, v in data['name_idx'].items()})
            idx.type_idx = defaultdict(set, {k: set(v) for k, v in data['type_idx'].items()})
            idx.keyword_idx = defaultdict(set, {k: set(v) for k, v in data['keyword_idx'].items()})
            idx.exact_match_idx = defaultdict(set, {k: set(v) for k, v in data['exact_match_idx'].items()})
            idx.docstring_idx = defaultdict(set, {k: set(v) for k, v in data.get('docstring_idx', {}).items()})
            idx.function_calls_idx = defaultdict(set, {k: set(v) for k, v in data.get('function_calls_idx', {}).items()})
            idx.related_functions_idx = defaultdict(set, {k: set(v) for k, v in data.get('related_functions_idx', {}).items()})
            idx.type_hint_idx = defaultdict(set, {k: set(v) for k, v in data.get('type_hint_idx', {}).items()})
            idx.decorator_idx = defaultdict(set, {k: set(v) for k, v in data.get('decorator_idx', {}).items()})
            idx.all_keywords = set(data['all_keywords'])

            logger.info(f"✓ Loaded enhanced index: {len(idx.all_keywords)} keywords")
            return idx
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return None


# =========================================================
# Reranking utilities (unchanged)
# =========================================================

def rerank_by_keyword_overlap(results: List[Dict], query: str) -> List[Dict]:
    q_terms = set(query.lower().split())
    q_terms = {t for t in q_terms if t not in STOPWORDS and len(t) > 2}

    for result in results:
        content_lower = result['content'].lower()
        name_lower = result.get('name', '').lower()

        content_overlap = sum(1 for term in q_terms if term in content_lower)
        name_overlap = sum(1 for term in q_terms if term in name_lower)

        result['score'] += 0.04 * content_overlap + 0.12 * name_overlap
        result['keyword_overlap'] = content_overlap + name_overlap

    return sorted(results, key=lambda x: x['score'], reverse=True)


def apply_noise_penalty(results: List[Dict]) -> List[Dict]:
    for result in results:
        content_len = len(result['content'])
        if content_len < 50:
            result['score'] *= 0.6
            result['noise_penalty'] = True
        elif content_len > 5000:
            result['score'] *= 0.85
            result['noise_penalty'] = True
        else:
            result['noise_penalty'] = False
    return results