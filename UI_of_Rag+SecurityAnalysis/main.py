# ── Standard library ──────────────────────────────────────────────
import sys
import os
import json
import time
import math
import shutil
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import Counter, defaultdict

# ── Make sibling packages importable when running from project root ──
sys.path.insert(0, str(Path(__file__).parent))


# ══════════════════════════════════════════════════════════════════
#  SECTION 1 — SECURITY ANALYZER
#  Imports and helpers for the static-analysis pipeline.
# ══════════════════════════════════════════════════════════════════

from security_analysis.astengine   import ASTEngine
from security_analysis.security    import SecurityChecker
from security_analysis.tools       import BanditRunner
from security_analysis.merge_filter import MergeFilter


# ── Severity ordering (used when sorting report output) ───────────
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1}

SEV_LABEL = {
    "HIGH":   "HIGH  ",   # trailing space aligns columns
    "MEDIUM": "MEDIUM",
}


# ── Security pipeline ─────────────────────────────────────────────

def run_security_analysis(code: str, filename: str) -> Dict[str, Any]:
    """
    Run the full security analysis pipeline on *code* and return a
    structured result dict.

    Steps:
      1. Parse code with ASTEngine and collect code metrics.
      2. Run SecurityChecker (custom rule-based checks).
      3. Run BanditRunner (external Bandit scanner).
      4. Merge + deduplicate findings with MergeFilter.

    Returns:
        {
          "filename":      str,
          "syntax_valid":  bool,
          "syntax_error":  dict | None,
          "total_issues":  int,
          "high_count":    int,
          "medium_count":  int,
          "final_issues":  list[dict],
          "metrics":       dict,
        }
    """
    print()
    print("=" * 55)
    print("  Running Security Analysis:", filename)
    print("=" * 55)

    # Step 1 — Parse -----------------------------------------------
    print("\n[1/4] Parsing code...")
    engine = ASTEngine()
    result = engine.parse_code(code)

    if not result.get("valid"):
        err = result.get("syntax_error", {})
        print("   Error: Syntax error at line", err.get("line"), "-", err.get("message"))
        return {
            "filename":     filename,
            "syntax_valid": False,
            "syntax_error": err,
            "total_issues": 0,
            "high_count":   0,
            "medium_count": 0,
            "final_issues": [],
            "metrics":      {},
        }

    metrics = engine.calculate_metrics()
    print(f"   OK — {metrics['lines_of_code']} lines, "
          f"{metrics['function_count']} functions, "
          f"{metrics['class_count']} classes")

    # Step 2 — SecurityChecker -------------------------------------
    print("\n[2/4] Running SecurityChecker...")
    checker = SecurityChecker(engine)
    security_issues = checker.run_all_checks()
    print(f"   SecurityChecker found {len(security_issues)} issue(s)")

    # Step 3 — Bandit ----------------------------------------------
    print("\n[3/4] Running Bandit scanner...")
    bandit = BanditRunner()
    bandit_issues = bandit.run(code)
    print(f"   Bandit found {len(bandit_issues)} issue(s)")

    # Step 4 — Merge & deduplicate ---------------------------------
    print("\n[4/4] Merging and deduplicating findings...")
    merger = MergeFilter()
    merged = merger.merge_all(security_issues + bandit_issues)
    print(f"   Final unique issues: {merged['total_issues']}  "
          f"[HIGH: {merged['high_count']} | MEDIUM: {merged['medium_count']}]")

    return {
        "filename":     filename,
        "syntax_valid": True,
        "syntax_error": None,
        "total_issues": merged["total_issues"],
        "high_count":   merged["high_count"],
        "medium_count": merged["medium_count"],
        "final_issues": merged["final_issues"],
        "metrics":      metrics,
    }


# ── Security report helpers ───────────────────────────────────────

def _write_issues_block(f, issues: list) -> None:
    """Write a numbered list of issues into an open text file *f*."""
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


def _print_issues_block(issues: list) -> None:
    """Print a numbered list of issues to stdout."""
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


def save_security_txt_report(result: Dict[str, Any]) -> None:
    """Save a human-readable security report to *security_report.txt*."""
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
        f.write(f"Lines of Code : {m.get('lines_of_code')}\n")
        f.write(f"Functions     : {m.get('function_count')}\n")
        f.write(f"Classes       : {m.get('class_count')}\n")
        f.write(f"Max Complexity: {m.get('max_complexity')}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("SEVERITY SUMMARY\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"  Total Issues  : {result['total_issues']}\n\n")
        f.write(f"  {'Severity':<10}  {'Count':>5}  Description\n")
        f.write(f"  {'-'*10}  {'-'*5}  {'-'*42}\n")
        f.write(f"  {'HIGH':<10}  {result['high_count']:>5}  Exploitable (RCE / injection / data breach)\n")
        f.write(f"  {'MEDIUM':<10}  {result['medium_count']:>5}  Weakness / risky coding practice\n")

        if not result["final_issues"]:
            f.write("\nNo vulnerabilities detected.\n")
            return

        high_issues   = [i for i in result["final_issues"] if i.get("severity") == "HIGH"]
        medium_issues = [i for i in result["final_issues"] if i.get("severity") == "MEDIUM"]

        if high_issues:
            f.write("\n\n" + "=" * 60 + "\n")
            f.write(f"HIGH SEVERITY  ({len(high_issues)} issue(s))\n")
            f.write("Exploitable vulnerabilities — RCE, injection, data breach\n")
            f.write("=" * 60 + "\n")
            _write_issues_block(f, high_issues)

        if medium_issues:
            f.write("\n\n" + "=" * 60 + "\n")
            f.write(f"MEDIUM SEVERITY  ({len(medium_issues)} issue(s))\n")
            f.write("Security weaknesses / risky coding practices\n")
            f.write("=" * 60 + "\n")
            _write_issues_block(f, medium_issues)

        f.write("\n" + "=" * 60 + "\n")

    print("\nReport saved to:", report_path.resolve())


def print_security_report(result: Dict[str, Any]) -> None:
    """Print a formatted security report to stdout."""
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
    print(f"  Functions    : {m.get('function_count', '?')}"
          f"  | Classes: {m.get('class_count', '?')}"
          f"  | Max Complexity: {m.get('max_complexity', '?')}")

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

    high_issues   = [i for i in result["final_issues"] if i.get("severity") == "HIGH"]
    medium_issues = [i for i in result["final_issues"] if i.get("severity") == "MEDIUM"]

    if high_issues:
        print()
        print("  " + "=" * 53)
        print(f"  HIGH SEVERITY  ({len(high_issues)} issue(s))")
        print("  " + "=" * 53)
        _print_issues_block(high_issues)

    if medium_issues:
        print()
        print("  " + "=" * 53)
        print(f"  MEDIUM SEVERITY  ({len(medium_issues)} issue(s))")
        print("  " + "=" * 53)
        _print_issues_block(medium_issues)

    print()
    print("=" * 55)
    print()


# ══════════════════════════════════════════════════════════════════
#  SECTION 2 — CODE RAG SYSTEM
#  Classes and helpers for the retrieval-augmented Q&A pipeline.
# ══════════════════════════════════════════════════════════════════

# ── RAG imports (optional deps handled gracefully) ────────────────
from Rag.chunk_and_index import (
    PythonChunker,
    MetadataIndex,
    CodeAnalyzer,
    CHUNK_SIZE_MIN,
    CHUNK_SIZE_MAX,
    CHUNK_OVERLAP,
    FUNCTION_SPLIT_THRESHOLD,
    DEFAULT_METADATA_BOOST,
    rerank_by_keyword_overlap,
    apply_noise_penalty,
)
from Rag.retrieval_engine import (
    QuestionRouter,
    QuestionType,
    ClassificationResult,
    expand_query_terms,
)
from Rag.llm_engine import generate_answer

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("⚠️  sentence-transformers not installed. Run: pip install sentence-transformers")

try:
    import numpy as np
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("⚠️  FAISS / numpy not installed. Run: pip install faiss-cpu numpy")


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ── RAG configuration ─────────────────────────────────────────────
EMBEDDING_MODEL    = "sentence-transformers/all-mpnet-base-v2"
VECTOR_STORE_DIR   = "vector_store"
INDEX_FILE         = os.path.join(VECTOR_STORE_DIR, "faiss_index.bin")
METADATA_FILE      = os.path.join(VECTOR_STORE_DIR, "metadata.json")
METADATA_INDEX_FILE = os.path.join(VECTOR_STORE_DIR, "metadata_index.pkl")


@dataclass
class CodeChunk:
    """Represents a single indexed chunk of source code."""
    chunk_id: int
    content:  str
    metadata: Dict[str, Any]
    vector:   Optional[List[float]] = None

    def __repr__(self):
        return (f"CodeChunk(id={self.chunk_id}, "
                f"type={self.metadata.get('chunk_type')}, "
                f"lines={self.metadata.get('line_count')})")


class BM25:
    """
    BM25 keyword-based ranker used in hybrid (semantic + keyword) retrieval.

    Parameters:
        k1 — term-frequency saturation (default 1.5)
        b  — length normalisation factor (default 0.75)
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b  = b
        self.doc_freqs  = defaultdict(int)
        self.idf        = {}
        self.doc_lengths = []
        self.avgdl      = 0
        self.corpus     = []

    def fit(self, corpus: List[str]) -> None:
        """Index *corpus* (list of document strings)."""
        self.corpus    = corpus
        doc_count      = len(corpus)

        for doc in corpus:
            for token in set(doc.lower().split()):
                self.doc_freqs[token] += 1

        for token, freq in self.doc_freqs.items():
            self.idf[token] = math.log((doc_count - freq + 0.5) / (freq + 0.5) + 1)

        self.doc_lengths = [len(doc.split()) for doc in corpus]
        self.avgdl       = sum(self.doc_lengths) / doc_count if doc_count > 0 else 0

    def score(self, query: str, doc_id: int) -> float:
        """Return the BM25 relevance score of document *doc_id* for *query*."""
        if doc_id >= len(self.corpus):
            return 0.0

        doc     = self.corpus[doc_id]
        doc_len = self.doc_lengths[doc_id]
        score   = 0.0
        token_freqs = Counter(doc.lower().split())

        for token in query.lower().split():
            if token in self.idf:
                tf          = token_freqs.get(token, 0)
                numerator   = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * (doc_len / self.avgdl))
                score      += self.idf[token] * (numerator / denominator)

        return score


class CodeRAG:
    """
    Enhanced RAG system for querying Python codebases in natural language.

    Key design decisions:
      - Single AST parse   : CodeAnalyzer runs once; result is reused by the
                             chunker — no redundant re-parsing.
      - Complete chunks    : AST line-range data ensures function/class chunks
                             are never truncated.
      - Adaptive hybrid    : semantic/BM25 ratio varies per query type
                             (e.g. definition queries use 50/50, flow queries
                             favour semantic at 80/20).
      - Call-graph expansion: query terms are expanded using the call graph
                             extracted from the AST.
      - Rich metadata      : type hints, decorators, __init__, nested functions
                             are all indexed and used during re-ranking.

    Typical workflow:
        rag = CodeRAG()
        rag.load_code(source_code, "my_module.py")  # index
        rag.save_index()                             # persist to disk
        result = rag.query("How does authentication work?")
        print(result["answer"])
    """

    def __init__(self):
        self.embed_model    = None
        self.faiss_index    = None
        self.bm25           = None
        self.metadata       = []
        self.meta_idx       = MetadataIndex()
        self.router         = QuestionRouter()
        self.chunker        = PythonChunker(
            min_size=CHUNK_SIZE_MIN,
            max_size=CHUNK_SIZE_MAX,
            overlap=CHUNK_OVERLAP,
        )
        self.original_code  = None
        self.code_stats     = {}
        self.code_structure = {}
        self.stats          = {
            "total_chunks":  0,
            "total_queries": 0,
            "avg_retrieval_time": 0,
            "precision_improvements": {
                "noise_penalties_applied": 0,
                "reranking_applied":       0,
                "hybrid_search_used":      0,
                "neighbor_retrieval_used": 0,
            },
        }

    # ── Indexing ──────────────────────────────────────────────────

    def load_code(self, code: str, source_name: str = "input.py") -> bool:
        """
        Parse *code*, chunk it, embed each chunk, and build FAISS + BM25 indexes.

        This is the only place CodeAnalyzer is called — the result is passed
        directly to PythonChunker, avoiding a second AST parse.

        Args:
            code:        Raw Python source as a string.
            source_name: Label used in metadata (e.g. the filename).

        Returns:
            True on success, False on any error.
        """
        logger.info("=" * 60)
        logger.info("📝 LOADING CODE")
        logger.info("=" * 60)

        try:
            self.original_code = code

            # Single AST parse —————————————————————————————————————
            logger.info("📊 Analyzing code structure (single AST parse)...")
            analyzer = CodeAnalyzer()
            self.code_structure = analyzer.analyze_code(code)
            n_ranges = len(self.code_structure.get("node_line_ranges", {}))
            logger.info(f"✓ AST line ranges captured for {n_ranges} nodes")

            self.code_stats = self._build_code_stats(code, self.code_structure)
            logger.info(f"✓ {self.code_stats['total_functions']} functions, "
                        f"{self.code_stats['total_classes']} classes")

            # Chunking (reuses pre-parsed structure) ———————————————
            logger.info("\n🔪 Chunking code...")
            raw_chunks = self.chunker.chunk_code(
                code, source_name,
                precomputed_structure=self.code_structure,
            )
            if not raw_chunks:
                logger.error("No chunks created.")
                return False

            avg_size = sum(len(c["content"]) for c in raw_chunks) / len(raw_chunks)
            logger.info(f"✓ {len(raw_chunks)} chunks (avg {avg_size:.0f} chars)")

            tiny = [c for c in raw_chunks
                    if len(c["content"]) < 80
                    and c["metadata"].get("chunk_type") in ("function", "class")]
            if tiny:
                logger.warning(f"⚠️  {len(tiny)} suspiciously small function/class chunks — "
                               f"AST fallback may have triggered.")

            # Embeddings ———————————————————————————————————————————
            if not EMBEDDINGS_AVAILABLE:
                logger.error("sentence-transformers not available.")
                return False

            logger.info("\n🔢 Generating embeddings...")
            self.embed_model = SentenceTransformer(EMBEDDING_MODEL)
            texts      = [c["content"] for c in raw_chunks]
            embeddings = self.embed_model.encode(
                texts, batch_size=32, show_progress_bar=True, convert_to_numpy=True
            )

            # BM25 ——————————————————————————————————————————————————
            logger.info("\n🔍 Building BM25 index...")
            self.bm25 = BM25()
            self.bm25.fit(texts)

            # FAISS ——————————————————————————————————————————————————
            if not FAISS_AVAILABLE:
                logger.error("FAISS not available.")
                return False

            logger.info("\n💾 Building FAISS index...")
            chunks  = []
            for i, (raw, emb) in enumerate(zip(raw_chunks, embeddings)):
                chunk = CodeChunk(
                    chunk_id=i,
                    content=raw["content"],
                    metadata=raw["metadata"],
                    vector=emb.tolist(),
                )
                chunks.append(chunk)

            vectors = np.array([c.vector for c in chunks]).astype("float32")
            self.faiss_index = faiss.IndexFlatL2(vectors.shape[1])
            self.faiss_index.add(vectors)

            for chunk in chunks:
                meta = {
                    "chunk_id":        chunk.chunk_id,
                    "content":         chunk.content,
                    "chunk_type":      chunk.metadata.get("chunk_type"),
                    "name":            chunk.metadata.get("name", ""),
                    "line_start":      chunk.metadata.get("line_start", 0),
                    "line_count":      chunk.metadata.get("line_count", 0),
                    "source":          chunk.metadata.get("source", source_name),
                    "docstring":       chunk.metadata.get("docstring"),
                    "calls":           chunk.metadata.get("calls", []),
                    "called_by":       chunk.metadata.get("called_by", []),
                    "related_functions": chunk.metadata.get("related_functions", []),
                    "decorators":      chunk.metadata.get("decorators", []),
                    "type_hints":      chunk.metadata.get("type_hints", {}),
                    "special_type":    chunk.metadata.get("special_type"),
                    "parent_class":    chunk.metadata.get("parent_class"),
                    "parent_function": chunk.metadata.get("parent_function"),
                }
                self.metadata.append(meta)
                self.meta_idx.add(chunk.chunk_id, chunk.metadata, chunk.content)

            self.stats["total_chunks"] = len(chunks)
            logger.info(f"✓ Indexed {self.faiss_index.ntotal} vectors")
            logger.info("\n✅ CODE LOADED SUCCESSFULLY")
            return True

        except Exception as e:
            logger.error(f"Failed to load code: {e}")
            import traceback; traceback.print_exc()
            return False

    def _build_code_stats(self, code: str, structure: Dict) -> Dict[str, Any]:
        """
        Derive human-readable code statistics from the already-parsed
        *structure* dict.  Does NOT re-parse the source.
        """
        import_lines = [ln.strip() for ln in code.split("\n") if "import" in ln]
        method_names = []

        try:
            import ast
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_names.append(f"{node.name}.{item.name}")
        except Exception:
            pass  # Non-fatal — method names are optional

        return {
            "total_imports":      len(structure.get("imports", [])),
            "external_libraries": list(structure.get("external_libs", [])),
            "total_functions":    len(structure.get("all_functions", [])),
            "function_names":     list(structure.get("all_functions", [])),
            "total_classes":      len(structure.get("all_classes", [])),
            "class_names":        list(structure.get("all_classes", [])),
            "total_methods":      len(method_names),
            "method_names":       method_names,
            "function_calls":     {k: list(v) for k, v in structure.get("function_calls", {}).items()},
            "import_details":     import_lines,
            "special_classes":    structure.get("special_classes", {}),
            "decorators":         structure.get("decorators", {}),
            "type_hints":         structure.get("type_hints", {}),
            "nested_functions":   structure.get("nested_functions", {}),
            "init_methods":       structure.get("init_methods", []),
        }

    # ── Persistence ───────────────────────────────────────────────

    def save_index(self) -> bool:
        """
        Persist the FAISS index, BM25 index, and metadata to *VECTOR_STORE_DIR*.

        Uses an atomic write (write-to-temp → verify → rename) to prevent
        truncated JSON if the process is interrupted mid-write.

        Note: node_line_ranges / node_decorators_start are intentionally
        excluded from the saved metadata — they are only needed during
        chunking (load_code) and regenerated on each re-index.
        """
        try:
            os.makedirs(VECTOR_STORE_DIR, exist_ok=True)

            # FAISS ——————————————————————————————————————————————————
            faiss.write_index(self.faiss_index, INDEX_FILE)
            logger.info("✓ FAISS index saved")

            # Deduplicate metadata by chunk_id ———————————————————————
            unique = {m["chunk_id"]: m for m in self.metadata}
            sorted_meta = [unique[i] for i in sorted(unique)]
            logger.info(f"✓ Deduplicated: {len(self.metadata)} → {len(sorted_meta)} chunks")

            # Clean code_stats (cap list lengths for JSON size) ———————
            s = self.code_stats
            clean_stats = {
                "total_imports":      s.get("total_imports", 0),
                "external_libraries": list(s.get("external_libraries", []))[:50],
                "total_functions":    s.get("total_functions", 0),
                "function_names":     list(s.get("function_names", []))[:100],
                "total_classes":      s.get("total_classes", 0),
                "class_names":        list(s.get("class_names", []))[:50],
                "total_methods":      s.get("total_methods", 0),
                "method_names":       list(s.get("method_names", []))[:50],
                "function_call_summary": {
                    fn: list(calls)[:10]
                    for fn, calls in list(s.get("function_calls", {}).items())[:50]
                },
                "import_details": list(s.get("import_details", []))[:20],
                "special_classes": s.get("special_classes", {}),
                "init_methods":    list(s.get("init_methods", []))[:50],
            }

            # Clean code_structure (node_line_ranges excluded) ————————
            cs = self.code_structure
            clean_structure = {
                "function_calls": {k: list(v)[:10] for k, v in list(cs.get("function_calls", {}).items())[:50]},
                "called_by":      {k: list(v)[:10] for k, v in list(cs.get("called_by", {}).items())[:50]},
                "imports":        list(cs.get("imports", []))[:50],
                "external_libs":  list(cs.get("external_libs", []))[:50],
                "all_functions":  list(cs.get("all_functions", []))[:100],
                "all_classes":    list(cs.get("all_classes", []))[:100],
                "decorators":     {k: v[:5] for k, v in list(cs.get("decorators", {}).items())[:50]},
                "type_hints":     {k: v for k, v in list(cs.get("type_hints", {}).items())[:50]},
                "special_classes": cs.get("special_classes", {}),
                "nested_functions": {k: v[:10] for k, v in list(cs.get("nested_functions", {}).items())[:30]},
                "init_methods":   list(cs.get("init_methods", []))[:50],
            }

            payload = {
                "metadata":       sorted_meta,
                "original_code":  self.original_code,
                "code_stats":     clean_stats,
                "code_structure": clean_structure,
                "version":        "enhanced_v4",
                "config": {
                    "chunk_size_max":          CHUNK_SIZE_MAX,
                    "function_split_threshold": FUNCTION_SPLIT_THRESHOLD,
                    "metadata_boost_weights":  DEFAULT_METADATA_BOOST,
                    "hybrid_search_enabled":   True,
                    "adaptive_hybrid_ratio":   True,
                    "ast_based_chunking":      True,
                },
            }

            # Atomic write ——————————————————————————————————————————
            tmp = METADATA_FILE + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                    f.flush(); os.fsync(f.fileno())

                with open(tmp, "r", encoding="utf-8") as f:
                    verified = json.load(f)

                assert "metadata" in verified
                assert len(verified["metadata"]) == len(sorted_meta), (
                    f"Metadata count mismatch: {len(verified['metadata'])} != {len(sorted_meta)}"
                )
                shutil.move(tmp, METADATA_FILE)
                logger.info(f"✓ Metadata saved: {len(sorted_meta)} chunks, "
                            f"{os.path.getsize(METADATA_FILE):,} bytes")
            except Exception as e:
                if os.path.exists(tmp):
                    os.remove(tmp)
                raise e

            # BM25 ——————————————————————————————————————————————————
            if self.bm25:
                bm25_path = os.path.join(VECTOR_STORE_DIR, "bm25_index.json")
                with open(bm25_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "doc_freqs":   dict(self.bm25.doc_freqs),
                        "idf":         self.bm25.idf,
                        "doc_lengths": self.bm25.doc_lengths,
                        "avgdl":       self.bm25.avgdl,
                        "corpus":      self.bm25.corpus,
                    }, f, indent=2)
                    f.flush(); os.fsync(f.fileno())
                logger.info("✓ BM25 index saved")

            self.meta_idx.save(METADATA_INDEX_FILE)
            logger.info("✓ Metadata index saved")
            logger.info(f"\n✅ INDEX SAVED to {VECTOR_STORE_DIR}/")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to save index: {e}")
            import traceback; traceback.print_exc()
            return False

    def load_index(self) -> bool:
        """
        Load a previously saved index from *VECTOR_STORE_DIR*.

        Emits a warning if the index was built before the AST-complete-chunk
        fix (version enhanced_v3 or earlier), as those may contain truncated
        function/class chunks.

        Returns:
            True if an index was found and loaded, False otherwise.
        """
        if not os.path.exists(INDEX_FILE):
            return False

        try:
            self.faiss_index = faiss.read_index(INDEX_FILE)

            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.metadata       = data.get("metadata", [])
            self.original_code  = data.get("original_code")
            self.code_stats     = data.get("code_stats", {})
            self.code_structure = data.get("code_structure", {})
            version             = data.get("version", "legacy")
            config              = data.get("config", {})
            logger.info(f"✓ Loading {version} index")

            if version in ("legacy", "enhanced_v3") or not config.get("ast_based_chunking"):
                logger.warning(
                    "⚠️  Pre-fix index detected — function chunks may be truncated. "
                    "Re-index your code to get complete chunks."
                )

            bm25_path = os.path.join(VECTOR_STORE_DIR, "bm25_index.json")
            if os.path.exists(bm25_path):
                with open(bm25_path, "r") as f:
                    bd = json.load(f)
                self.bm25             = BM25()
                self.bm25.doc_freqs   = defaultdict(int, bd["doc_freqs"])
                self.bm25.idf         = bd["idf"]
                self.bm25.doc_lengths = bd["doc_lengths"]
                self.bm25.avgdl       = bd["avgdl"]
                self.bm25.corpus      = bd["corpus"]
                logger.info("✓ BM25 index loaded")

            self.meta_idx = MetadataIndex.load(METADATA_INDEX_FILE)
            if not self.meta_idx:
                logger.warning("Rebuilding metadata index from scratch...")
                self.meta_idx = MetadataIndex()
                for meta in self.metadata:
                    self.meta_idx.add(meta["chunk_id"], meta, meta["content"])
                self.meta_idx.save(METADATA_INDEX_FILE)

            self.embed_model           = SentenceTransformer(EMBEDDING_MODEL)
            self.stats["total_chunks"] = self.faiss_index.ntotal
            logger.info(f"✓ Loaded index with {self.faiss_index.ntotal} vectors")
            return True

        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            import traceback; traceback.print_exc()
            return False

    # ── Querying ──────────────────────────────────────────────────

    def query(self, question: str, k: int = 5) -> Dict[str, Any]:
        """
        Answer *question* using hybrid retrieval over the indexed codebase.

        Steps:
          1. Classify the question type (definition / flow / counting / …).
          2. Expand query terms via call-graph relationships.
          3. Retrieve top-k chunks with adaptive semantic + BM25 weighting.
          4. Re-rank by keyword overlap and apply noise penalties.
          5. Generate an answer with the LLM engine.

        Args:
            question: Natural-language question about the code.
            k:        Number of chunks to pass to the LLM (default 5).

        Returns:
            {
              "success":         bool,
              "answer":          str,
              "query_type":      str,
              "chunks_used":     int,
              "retrieval_time":  float,
              "chunks":          list[dict],
              "classification":  dict,
            }
        """
        if not self.faiss_index or not self.embed_model:
            return {"success": False, "error": "System not initialized — call load_code() or load_index() first."}

        start = time.time()
        self.stats["total_queries"] += 1

        logger.info("\n" + "=" * 60)
        logger.info(f"❓ QUERY: {question}")
        logger.info("=" * 60)

        # Classify & configure retrieval ——————————————————————————
        classification = self.router.classify(question)
        q_type         = classification.primary_intent.question_type
        params         = self.router.get_retrieval_params(classification)

        logger.info(f"🎯 Query type: {q_type.value} "
                    f"(confidence: {classification.primary_intent.confidence:.2f})")
        logger.info(f"⚖️  Hybrid ratio: semantic={params['semantic_weight']:.0%} "
                    f"/ bm25={params['bm25_weight']:.0%}")

        # Expand query via call graph ——————————————————————————————
        expanded = expand_query_terms(question, classification, self.code_structure)
        if len(expanded) > 1:
            logger.info(f"🔗 Query expanded with {len(expanded) - 1} related term(s)")

        query_info = {
            "entities":     classification.entities,
            "quoted_terms": classification.quoted_terms,
            "keywords":     classification.keywords + expanded[1:],
            "confidence":   classification.primary_intent.confidence,
        }

        retrieved = self._retrieve_hybrid(
            question,
            params["k"],
            params["prefer_types"],
            params["boost_exact_match"],
            query_info,
            classification,
            semantic_weight=params.get("semantic_weight", 0.7),
            bm25_weight=params.get("bm25_weight", 0.3),
        )

        logger.info(f"✓ Retrieved {len(retrieved)} chunks")

        answer = generate_answer(question, retrieved, q_type, self.code_stats)

        elapsed = time.time() - start
        n = self.stats["total_queries"]
        self.stats["avg_retrieval_time"] = (
            (self.stats["avg_retrieval_time"] * (n - 1) + elapsed) / n
        )
        logger.info(f"⏱️  {elapsed:.2f}s")
        logger.info("=" * 60)

        return {
            "success":        True,
            "answer":         answer,
            "query_type":     q_type.value,
            "chunks_used":    len(retrieved),
            "retrieval_time": elapsed,
            "chunks":         retrieved,
            "classification": {
                "primary":     q_type.value,
                "confidence":  classification.primary_intent.confidence,
                "is_counting": classification.is_counting,
                "is_listing":  classification.is_listing,
            },
        }

    # ── Private retrieval helpers ─────────────────────────────────

    def _retrieve_hybrid(
        self,
        query:          str,
        k:              int,
        prefer_types:   List[str],
        boost_exact:    bool,
        query_info:     Dict,
        classification: ClassificationResult,
        semantic_weight: float = 0.7,
        bm25_weight:     float = 0.3,
    ) -> List[Dict]:
        """
        Hybrid retrieval combining FAISS semantic search and BM25 keyword search.

        The final score for each candidate chunk is:
            score = semantic_weight * cosine_sim  +  bm25_weight * bm25_score

        After scoring, metadata boosting, noise penalties, and keyword overlap
        re-ranking are applied in sequence.
        """
        try:
            # Semantic (FAISS) ————————————————————————————————————
            q_vec    = self.embed_model.encode([query], convert_to_numpy=True)
            search_k = min(k * 3, self.faiss_index.ntotal)
            dists, idxs = self.faiss_index.search(q_vec.astype("float32"), search_k)

            candidates = {}
            for dist, idx in zip(dists[0], idxs[0]):
                if idx >= len(self.metadata):
                    continue
                meta = self.metadata[idx]
                sim  = 1 / (1 + float(dist))
                candidates[idx] = {
                    "chunk_id":       meta["chunk_id"],
                    "content":        meta["content"],
                    "chunk_type":     meta["chunk_type"],
                    "name":           meta["name"],
                    "source":         meta["source"],
                    "line_start":     meta.get("line_start", 0),
                    "line_count":     meta.get("line_count", 0),
                    "decorators":     meta.get("decorators", []),
                    "type_hints":     meta.get("type_hints", {}),
                    "parent_class":   meta.get("parent_class"),
                    "parent_function": meta.get("parent_function"),
                    "similarity":     sim,
                    "semantic_score": sim,
                    "bm25_score":     0.0,
                    "score":          sim,
                }

            # BM25 blending ——————————————————————————————————————
            if self.bm25:
                self.stats["precision_improvements"]["hybrid_search_used"] += 1
                for idx, cand in candidates.items():
                    bm25_raw = self.bm25.score(query, idx)
                    norm_bm25 = min(bm25_raw / 10.0, 1.0)
                    cand["bm25_score"] = norm_bm25
                    cand["score"]      = (semantic_weight * cand["semantic_score"]
                                          + bm25_weight   * norm_bm25)

            results = list(candidates.values())
            results = self._apply_metadata_boost(results, query_info, prefer_types, boost_exact, query)
            results = apply_noise_penalty(results)
            results = rerank_by_keyword_overlap(results, query)
            self.stats["precision_improvements"]["reranking_applied"] += 1

            results.sort(key=lambda x: x["score"], reverse=True)

            # Neighbour chunks for flow-type queries ——————————————
            if k > 3 and classification.primary_intent.question_type == QuestionType.FLOW_EXPLANATION:
                results = self._add_neighbor_chunks(results, k)
                self.stats["precision_improvements"]["neighbor_retrieval_used"] += 1

            return results[:k]

        except Exception as e:
            logger.error(f"Retrieval error: {e}")
            import traceback; traceback.print_exc()
            return []

    def _apply_metadata_boost(
        self,
        results:      List[Dict],
        query_info:   Dict,
        prefer_types: List[str],
        boost_exact:  bool,
        query:        str,
    ) -> List[Dict]:
        """
        Boost chunk scores based on metadata signals:
          - Exact name match, keyword match, docstring match
          - Function-call graph match
          - Type-hint and decorator matches
          - Preferred chunk type (per query type)
        """
        entities  = query_info.get("entities", [])
        quoted    = query_info.get("quoted_terms", [])
        all_terms = entities + quoted + query_info.get("keywords", [])
        meta_matches = self.meta_idx.get_matches(all_terms)

        query_func_names = {
            e.lower() for e in entities
            if e in self.code_stats.get("function_names", [])
        }

        for result in results:
            chunk_id  = result["chunk_id"]
            base_sim  = result.get("semantic_score", result["similarity"])

            if boost_exact and chunk_id in meta_matches.get("exact_match", set()):
                result["score"] += DEFAULT_METADATA_BOOST["exact_match"] * base_sim

            if chunk_id in meta_matches.get("name", set()):
                result["score"] += DEFAULT_METADATA_BOOST["name"] * base_sim

            if query_func_names and result.get("name", "").lower() in query_func_names:
                result["score"] += 0.5 * base_sim

            if chunk_id in meta_matches.get("keywords", set()):
                result["score"] += DEFAULT_METADATA_BOOST["keywords"] * base_sim

            if chunk_id in meta_matches.get("docstring_match", set()):
                result["score"] += DEFAULT_METADATA_BOOST["docstring_match"] * base_sim

            if chunk_id in meta_matches.get("function_calls", set()):
                result["score"] += DEFAULT_METADATA_BOOST["function_calls"] * base_sim

            if chunk_id in meta_matches.get("type_hint_match", set()):
                result["score"] += DEFAULT_METADATA_BOOST.get("type_hint_match", 1.1) * base_sim

            if chunk_id in meta_matches.get("decorator_match", set()):
                result["score"] += DEFAULT_METADATA_BOOST.get("decorator_match", 0.9) * base_sim

            if result["chunk_type"] in prefer_types:
                result["score"] += DEFAULT_METADATA_BOOST["chunk_type"] * base_sim

        return results

    def _add_neighbor_chunks(self, results: List[Dict], k: int) -> List[Dict]:
        """
        Append the immediately adjacent chunks (±1 chunk_id) of the top-3
        results.  Used for FLOW_EXPLANATION queries to capture surrounding
        context.  Neighbour score = parent score × 0.7.
        """
        seen = {r["chunk_id"] for r in results}
        extras = []

        for result in results[:3]:
            for nid in (result["chunk_id"] - 1, result["chunk_id"] + 1):
                if 0 <= nid < len(self.metadata) and nid not in seen:
                    meta = self.metadata[nid]
                    extras.append({
                        "chunk_id":   meta["chunk_id"],
                        "content":    meta["content"],
                        "chunk_type": meta["chunk_type"],
                        "name":       meta["name"],
                        "source":     meta["source"],
                        "line_start": meta.get("line_start", 0),
                        "line_count": meta.get("line_count", 0),
                        "score":      result["score"] * 0.7,
                        "is_neighbor": True,
                    })
                    seen.add(nid)

        combined = results + extras
        combined.sort(key=lambda x: x["score"], reverse=True)
        return combined

    # ── Stats ─────────────────────────────────────────────────────

    def print_stats(self) -> None:
        """Print a summary of indexing and retrieval statistics."""
        print("\n" + "=" * 60)
        print("📊 SYSTEM STATISTICS")
        print("=" * 60)
        print(f"Total Chunks   : {self.stats['total_chunks']}")
        print(f"Total Queries  : {self.stats['total_queries']}")
        print(f"Avg Retrieval  : {self.stats['avg_retrieval_time']:.2f}s")

        if self.code_stats:
            sc = self.code_stats
            print(f"\n📈 Code:")
            print(f"  Functions  : {sc.get('total_functions', 0)}")
            print(f"  Classes    : {sc.get('total_classes', 0)}")
            print(f"  Methods    : {sc.get('total_methods', 0)}")
            print(f"  Ext. Libs  : {len(sc.get('external_libraries', []))}")
            if sc.get("special_classes"):
                print(f"  Special    : {', '.join(f'{k}({v})' for k, v in sc['special_classes'].items())}")
            nested = sc.get("nested_functions", {})
            if nested:
                print(f"  Nested Fns : {sum(len(v) for v in nested.values())}")

        imp = self.stats["precision_improvements"]
        print(f"\n🎯 Precision:")
        print(f"  Hybrid Search    : {imp['hybrid_search_used']} queries")
        print(f"  Reranking        : {imp['reranking_applied']} queries")
        print(f"  Neighbour chunks : {imp['neighbor_retrieval_used']} queries")
        print(f"  Noise penalties  : {imp['noise_penalties_applied']} applied")
        print("=" * 60)


# ── RAG Q&A loop ──────────────────────────────────────────────────

def run_rag_qa_loop(rag: CodeRAG) -> None:
    """
    Interactive Q&A loop for the RAG system.
    Type 'exit' to quit, 'stats' for system statistics, 'help' for examples.
    """
    print("\n" + "=" * 70)
    print("💬 Q&A MODE  (type 'exit' to quit, 'stats', or 'help')")
    print("=" * 70 + "\n")

    while True:
        try:
            question = input("\n❓ Question: ").strip()
            if not question:
                continue

            if question.lower() == "exit":
                print("\n👋 Goodbye!")
                break
            elif question.lower() == "stats":
                rag.print_stats()
                continue
            elif question.lower() == "help":
                print("\n📝 Example questions:")
                print("  • How does authentication work?")
                print("  • What security vulnerabilities exist?")
                print("  • How many functions are there?")
                print("  • List all classes")
                print("  • What external libraries are used?")
                print("  • Which functions are decorated with @property?")
                print("  • Which functions return a list?")
                continue

            result = rag.query(question)

            if result["success"]:
                print("\n" + "=" * 70)
                print("🤖 ANSWER")
                print("=" * 70)
                print(result["answer"])
                print("=" * 70)
                cls = result.get("classification", {})
                print(f"🎯 [{cls.get('primary')}] | {result['chunks_used']} chunks | {result['retrieval_time']:.2f}s")
            else:
                print(f"\n❌ {result.get('error')}")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback; traceback.print_exc()


# ── RAG tool entry point ──────────────────────────────────────────

def run_rag_tool(file_path: str) -> None:
    """
    Index *file_path* and start the interactive Q&A loop.

    Called automatically by main() after the Security Analyzer finishes,
    so the developer can immediately ask questions about the same file.

    Args:
        file_path: Path to the .py file that was already security-analyzed.
    """
    print("\n" + "=" * 70)
    print("🤖 CODE RAG SYSTEM — Enhanced v4")
    print("=" * 70)
    print("✅ Single AST parse          ✅ Complete function/class chunks")
    print("✅ Adaptive hybrid ratio     ✅ Call-graph query expansion")
    print("✅ __init__ + nested indexed ✅ Type hints + decorators boosted")
    print("✅ Stale-index detection     ✅ Real line numbers in LLM prompts")
    print("=" * 70)

    if not EMBEDDINGS_AVAILABLE or not FAISS_AVAILABLE:
        print("\n❌ Missing required libraries.")
        print("   pip install sentence-transformers faiss-cpu numpy")
        return

    rag = CodeRAG()

    # Offer to reuse an existing index ———————————————————————————
    if rag.load_index():
        print("\n✓ Existing index found.")
        if input("Use it? (y/n): ").strip().lower() == "y":
            run_rag_qa_loop(rag)
            return

    # Index the file that was just security-analyzed
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    print(f"✓ Indexing {len(code):,} characters from {file_path}")

    if rag.load_code(code, os.path.basename(file_path)):
        if input("\n💾 Save index? (y/n): ").strip().lower() == "y":
            if rag.save_index():
                print("✅ Index saved.")
            else:
                print("❌ Failed to save index.")
        run_rag_qa_loop(rag)
    else:
        print("❌ Failed to process code.")


# ══════════════════════════════════════════════════════════════════
#  SECTION 3 — UNIFIED ENTRY POINT
#  Presents a top-level menu so developers can choose which tool to
#  run, or use --tool / --file flags for non-interactive scripting.
# ══════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse optional CLI flags for non-interactive use."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Python Security Analyzer → Code RAG Q&A System",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to the Python file to analyze and index.",
    )
    return parser.parse_args()


def main() -> None:
    """
    Unified entry point — runs both tools sequentially on the same file:

      Step 1 : Security Analyzer
               Scans the file for vulnerabilities and saves security_report.txt.

      Step 2 : Code RAG
               Indexes the same file so the developer can ask questions about it.

    Usage:
        python main.py                   # prompts for file path interactively
        python main.py --file my_app.py  # non-interactive
    """
    args = parse_args()

    print()
    print("=" * 55)
    print("  Python Developer Toolkit")
    print("=" * 55)

    # Resolve file path ————————————————————————————————————————————
    file_path = args.file
    if not file_path:
        file_path = input("\nEnter path to Python file: ").strip().strip('"').strip("'")

    path = Path(file_path)
    if not path.exists():
        print(f"  Error: File not found: {path}")
        sys.exit(1)
    if path.suffix != ".py":
        print("  Warning: not a .py file — analysing anyway.")

    code = path.read_text(encoding="utf-8", errors="ignore")

    # ── Step 1: Security Analysis ──────────────────────────────────
    result = run_security_analysis(code, str(path))
    print_security_report(result)
    save_security_txt_report(result)

    # ── Step 2: Code RAG ───────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  Starting Code RAG on the same file...")
    print("=" * 55)
    run_rag_tool(file_path=str(path))


if __name__ == "__main__":
    main()