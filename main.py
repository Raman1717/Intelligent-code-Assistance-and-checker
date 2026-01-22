"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE QUALITY ANALYZER
================================================================
File 5: Orchestration & User Interface
Contains: CodeRAG class, main(), run_qa_mode(), CLI interaction
"""
import os
import json
import pickle
import time
import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import Counter
import logging

# Import the refactored code quality analyzer
from code_checker import CodeQualityAnalyzer, analyze_code, get_report

# Import from other files
from chunk_and_index import PythonChunker, MetadataIndex, CHUNK_SIZE, CHUNK_OVERLAP
from retrieval_engine import QuestionRouter, QuestionType, METADATA_BOOST
from llm_engine import generate_answer

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("⚠️ sentence-transformers not installed. Run: pip install sentence-transformers")

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("⚠️ FAISS not installed. Run: pip install faiss-cpu")

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
VECTOR_STORE_DIR = "vector_store"
INDEX_FILE = os.path.join(VECTOR_STORE_DIR, "faiss_index.bin")
METADATA_FILE = os.path.join(VECTOR_STORE_DIR, "metadata.pkl")
METADATA_INDEX_FILE = os.path.join(VECTOR_STORE_DIR, "metadata_index.pkl")


@dataclass
class CodeChunk:
    """Represents a code chunk with metadata and embeddings"""
    chunk_id: int
    content: str
    metadata: Dict[str, Any]
    vector: Optional[List[float]] = None
    
    def __repr__(self):
        return f"CodeChunk(id={self.chunk_id}, type={self.metadata.get('chunk_type')}, lines={self.metadata.get('line_count')})"


class CodeRAG:
    """Main RAG system with integrated code quality analyzer"""
    
    def __init__(self):
        self.embed_model = None
        self.faiss_index = None
        self.metadata = []
        self.meta_idx = MetadataIndex()
        self.router = QuestionRouter()
        self.chunker = PythonChunker()
        self.code_analyzer = CodeQualityAnalyzer()
        self.code_analysis_report = None
        self.original_code = None
        self.stats = {"total_chunks": 0, "total_queries": 0, "avg_retrieval_time": 0}
    
    def load_code(self, code: str, source_name: str = "input.py") -> bool:
        """Load and process code with quality checking"""
        logger.info("="*60)
        logger.info("📝 LOADING CODE")
        logger.info("="*60)
        
        try:
            self.original_code = code
            
            # STEP 1: Run code quality analysis
            logger.info("🔎 Running code quality & security analysis...")
            self.code_analysis_report = self.code_analyzer.analyze(code, source_name)
            
            # Check if tools are available
            tools_available = self.code_analyzer.tool_runner.available_tools
            
            if not tools_available:
                logger.warning("⚠️ Code analysis using basic checks only - no external tools")
            else:
                logger.info(f"✓ Analysis completed with tools: {', '.join(tools_available)}")
            
            # Display enhanced summary with critical issue details
            if self.code_analysis_report.get("summary"):
                summary = self.code_analysis_report["summary"]
                status_emoji = {
                    "excellent": "✅",
                    "good": "👍",
                    "needs_improvement": "⚠️",
                    "critical": "❌"
                }
                emoji = status_emoji.get(summary["status"], "ℹ️")
                logger.info(f"   Status: {emoji} {summary['status'].upper()}")
                logger.info(f"   Total Issues: {summary['total_issues']}")
                
                # Show critical issues with sources (formatted properly)
                critical_issues = summary.get('critical_issues', [])
                if isinstance(critical_issues, list) and critical_issues:
                    logger.info(f"   Critical Issues: {len(critical_issues)}")
                    for issue in critical_issues[:2]:  # Show top 2
                        source = issue.get('source', 'Unknown')
                        msg = issue.get('message', '')[:60]
                        line_num = issue.get('line', '?')
                        logger.info(f"      • [{source}] Line {line_num}: {msg}")
                elif isinstance(critical_issues, int):
                    logger.info(f"   Critical Issues: {critical_issues}")
                else:
                    logger.info(f"   Critical Issues: 0")
                
                # Show overall score if available
                scores = self.code_analysis_report.get("scores", {})
                if scores.get("overall"):
                    logger.info(f"   Overall Score: {scores['overall']:.1f}/100")
            
            # STEP 2: Chunk the code
            logger.info("\n🔪 Chunking code...")
            raw_chunks = self.chunker.chunk_code(code, source_name)
            
            if not raw_chunks:
                logger.error("No chunks created from code")
                return False
            
            logger.info(f"✓ Created {len(raw_chunks)} chunks")
            
            chunk_types = Counter(c['metadata']['chunk_type'] for c in raw_chunks)
            logger.info(f"  Chunk types: {dict(chunk_types)}")
            
            # STEP 3: Generate embeddings
            if not EMBEDDINGS_AVAILABLE:
                logger.error("sentence-transformers not available")
                return False
            
            logger.info("\n🔢 Generating embeddings...")
            self.embed_model = SentenceTransformer(EMBEDDING_MODEL)
            
            texts = [c['content'] for c in raw_chunks]
            embeddings = self.embed_model.encode(
                texts, 
                batch_size=32, 
                show_progress_bar=True,
                convert_to_numpy=True
            )
            
            logger.info(f"✓ Generated {len(embeddings)} embeddings")
            
            # STEP 4: Build FAISS index
            if not FAISS_AVAILABLE:
                logger.error("FAISS not available")
                return False
            
            logger.info("\n💾 Building FAISS index...")
            
            chunks = []
            for i, (raw_chunk, emb) in enumerate(zip(raw_chunks, embeddings)):
                chunk = CodeChunk(
                    chunk_id=i,
                    content=raw_chunk['content'],
                    metadata=raw_chunk['metadata'],
                    vector=emb.tolist()
                )
                chunks.append(chunk)
            
            vectors = np.array([c.vector for c in chunks]).astype('float32')
            self.faiss_index = faiss.IndexFlatL2(vectors.shape[1])
            self.faiss_index.add(vectors)
            
            for chunk in chunks:
                meta = {
                    'chunk_id': chunk.chunk_id,
                    'content': chunk.content,
                    'chunk_type': chunk.metadata.get('chunk_type'),
                    'name': chunk.metadata.get('name', ''),
                    'line_start': chunk.metadata.get('line_start', 0),
                    'line_count': chunk.metadata.get('line_count', 0),
                    'source': chunk.metadata.get('source', source_name)
                }
                self.metadata.append(meta)
                self.meta_idx.add(chunk.chunk_id, chunk.metadata, chunk.content)
            
            self.stats['total_chunks'] = len(chunks)
            
            logger.info(f"✓ Indexed {self.faiss_index.ntotal} vectors")
            logger.info("\n" + "="*60)
            logger.info("✅ CODE LOADED SUCCESSFULLY")
            logger.info("="*60)
            
            # Show code analysis report
            if self.code_analysis_report:
                print("\n" + self.code_analyzer.format_report(self.code_analysis_report))
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load code: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_index(self) -> bool:
        """Save index to disk for reuse"""
        try:
            os.makedirs(VECTOR_STORE_DIR, exist_ok=True)
            
            faiss.write_index(self.faiss_index, INDEX_FILE)
            with open(METADATA_FILE, 'wb') as f:
                pickle.dump({
                    'metadata': self.metadata,
                    'code_analysis_report': self.code_analysis_report,
                    'original_code': self.original_code
                }, f)
            self.meta_idx.save(METADATA_INDEX_FILE)
            
            logger.info("✓ Index saved to disk")
            return True
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            return False
    
    def load_index(self) -> bool:
        """Load existing index from disk"""
        if not os.path.exists(INDEX_FILE):
            return False
        
        try:
            self.faiss_index = faiss.read_index(INDEX_FILE)
            with open(METADATA_FILE, 'rb') as f:
                data = pickle.load(f)
                self.metadata = data.get('metadata', data) if isinstance(data, dict) else data
                
                # Handle both old and new report names
                self.code_analysis_report = (
                    data.get('code_analysis_report') or 
                    data.get('code_check_report')
                ) if isinstance(data, dict) else None
                
                self.original_code = data.get('original_code') if isinstance(data, dict) else None
            
            self.meta_idx = MetadataIndex.load(METADATA_INDEX_FILE)
            
            if not self.meta_idx:
                logger.warning("Rebuilding metadata index...")
                self.meta_idx = MetadataIndex()
                for meta in self.metadata:
                    self.meta_idx.add(
                        meta['chunk_id'],
                        {'name': meta['name'], 'chunk_type': meta['chunk_type'], 'source': meta['source']},
                        meta['content']
                    )
                self.meta_idx.save(METADATA_INDEX_FILE)
            
            self.embed_model = SentenceTransformer(EMBEDDING_MODEL)
            self.stats['total_chunks'] = self.faiss_index.ntotal
            
            logger.info(f"✓ Loaded index with {self.faiss_index.ntotal} vectors")
            return True
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return False
    
    def query(self, question: str, k: int = 5) -> Dict[str, Any]:
        """Query the RAG system with code analysis integration"""
        if not self.faiss_index or not self.embed_model:
            return {"success": False, "error": "System not initialized"}
        
        start_time = time.time()
        self.stats['total_queries'] += 1
        
        logger.info("\n" + "="*60)
        logger.info(f"❓ QUERY: {question}")
        logger.info("="*60)
        
        # Classify question
        q_type, q_info = self.router.classify(question)
        params = self.router.get_retrieval_params(q_type)
        
        logger.info(f"🎯 Query type: {q_type.value}")
        logger.info(f"📊 Retrieval params: k={params['k']}, types={params['prefer_types']}")
        
        # Check if code quality tools are needed but not available
        if q_type == QuestionType.CODE_QUALITY:
            tools_available = self.code_analyzer.tool_runner.available_tools
            
            if not tools_available:
                logger.warning("⚠️ Code quality tools not available - using basic analysis")
        
        # Retrieve relevant chunks
        retrieved = self._retrieve(
            question, 
            params['k'], 
            params['prefer_types'],
            params['boost_exact_match'],
            q_info
        )
        
        logger.info(f"✓ Retrieved {len(retrieved)} chunks")
        
        # Generate answer (pass the analysis report)
        answer = generate_answer(
            question, 
            retrieved, 
            q_type, 
            params.get('use_code_check', False),
            self.code_analysis_report
        )
        
        retrieval_time = time.time() - start_time
        self.stats['avg_retrieval_time'] = (
            (self.stats['avg_retrieval_time'] * (self.stats['total_queries'] - 1) + retrieval_time) 
            / self.stats['total_queries']
        )
        
        logger.info(f"⏱️  Time: {retrieval_time:.2f}s")
        logger.info("="*60)
        
        # Check if tools are available
        tools_available = bool(self.code_analyzer.tool_runner.available_tools)
        
        return {
            "success": True,
            "answer": answer,
            "query_type": q_type.value,
            "chunks_used": len(retrieved),
            "retrieval_time": retrieval_time,
            "chunks": retrieved[:3],
            "used_code_check": params.get('use_code_check', False),
            "code_check_available": tools_available
        }
    
    def _retrieve(
        self, 
        query: str, 
        k: int, 
        prefer_types: List[str],
        boost_exact: bool,
        query_info: Dict
    ) -> List[Dict]:
        """Retrieve relevant chunks with intelligent boosting"""
        try:
            query_vec = self.embed_model.encode([query], convert_to_numpy=True)
            
            search_k = min(k * 3, self.faiss_index.ntotal)
            distances, indices = self.faiss_index.search(query_vec.astype('float32'), search_k)
            
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx >= len(self.metadata):
                    continue
                
                meta = self.metadata[idx]
                similarity = 1 / (1 + float(dist))
                
                result = {
                    'chunk_id': meta['chunk_id'],
                    'content': meta['content'],
                    'chunk_type': meta['chunk_type'],
                    'name': meta['name'],
                    'source': meta['source'],
                    'similarity': similarity,
                    'score': similarity
                }
                results.append(result)
            
            results = self._apply_metadata_boost(
                results, 
                query_info, 
                prefer_types, 
                boost_exact
            )
            
            results.sort(key=lambda x: x['score'], reverse=True)
            
            return results[:k]
            
        except Exception as e:
            logger.error(f"Retrieval error: {e}")
            return []
    
    def _apply_metadata_boost(
        self, 
        results: List[Dict], 
        query_info: Dict,
        prefer_types: List[str],
        boost_exact: bool
    ) -> List[Dict]:
        """Apply intelligent metadata-based boosting"""
        
        entities = query_info.get('entities', [])
        quoted = query_info.get('quoted_terms', [])
        all_terms = entities + quoted
        
        meta_matches = self.meta_idx.get_matches(all_terms)
        
        for result in results:
            chunk_id = result['chunk_id']
            base_sim = result['similarity']
            
            if boost_exact and chunk_id in meta_matches.get('exact_match', set()):
                result['score'] += METADATA_BOOST['exact_match'] * base_sim
            
            if chunk_id in meta_matches.get('name', set()):
                result['score'] += METADATA_BOOST['name'] * base_sim
            
            if chunk_id in meta_matches.get('keywords', set()):
                result['score'] += METADATA_BOOST['keywords'] * base_sim
            
            if result['chunk_type'] in prefer_types:
                result['score'] += METADATA_BOOST['chunk_type'] * base_sim
        
        return results
    
    def print_stats(self):
        """Print system statistics"""
        print("\n" + "="*60)
        print("📊 SYSTEM STATISTICS")
        print("="*60)
        print(f"Total Chunks: {self.stats['total_chunks']}")
        print(f"Total Queries: {self.stats['total_queries']}")
        print(f"Avg Retrieval Time: {self.stats['avg_retrieval_time']:.3f}s")
        if self.faiss_index:
            print(f"Vector Store Size: {self.faiss_index.ntotal} vectors")
            print(f"Vector Dimension: {self.faiss_index.d}")
        print(f"Metadata Keywords: {len(self.meta_idx.all_keywords)}")
        
        # Show available analysis tools
        tools = self.code_analyzer.tool_runner.available_tools
        if tools:
            print(f"Code Analysis Tools: {', '.join(tools)}")
        else:
            print("Code Analysis Tools: Basic only (install flake8, pylint, bandit, black)")
        
        # Show last analysis status with enhanced details
        if self.code_analysis_report:
            summary = self.code_analysis_report.get("summary", {})
            status = summary.get("status", "unknown")
            print(f"Last Analysis Status: {status}")
            
            # Show critical issues count
            critical_issues = summary.get('critical_issues', [])
            if isinstance(critical_issues, list):
                print(f"Last Critical Issues: {len(critical_issues)}")
            else:
                print(f"Last Critical Issues: {critical_issues}")
            
            # Show overall score
            if self.code_analysis_report.get("scores", {}).get("overall"):
                score = self.code_analysis_report["scores"]["overall"]
                print(f"Last Overall Score: {score:.1f}/100")
        print("="*60)
    
    def show_code_report(self):
        """Display the full code quality report"""
        if not self.code_analysis_report:
            print("\n❌ No code quality report available")
            return
        
        print("\n" + self.code_analyzer.format_report(self.code_analysis_report))


def main():
    """Main interactive interface"""
    print("\n" + "="*70)
    print("🤖 CODE RAG SYSTEM - WITH INTELLIGENT CODE QUALITY ANALYZER")
    print("="*70)
    print("\nRequired libraries:")
    print("  pip install sentence-transformers faiss-cpu numpy requests")
    print("\nOptional (for advanced code analysis):")
    print("  pip install flake8 pylint bandit black")
    print("="*70)
    
    if not EMBEDDINGS_AVAILABLE or not FAISS_AVAILABLE:
        print("\n❌ Missing required libraries!")
        print("Install with: pip install sentence-transformers faiss-cpu numpy requests")
        return
    
    rag = CodeRAG()
    
    if rag.load_index():
        print("\n✓ Found existing index")
        use_existing = input("Use it? (y/n): ").strip().lower()
        if use_existing == 'y':
            run_qa_mode(rag)
            return
    
    print("\n" + "="*60)
    print("📁 LOAD PYTHON CODE FROM FILE")
    print("="*60)
    
    file_path = input("Enter file path: ").strip()
    
    if not file_path:
        print("❌ No file path provided!")
        return
    
    try:
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return
        
        if not file_path.endswith('.py'):
            print("⚠️ Warning: File doesn't have .py extension")
            proceed = input("Continue anyway? (y/n): ").strip().lower()
            if proceed != 'y':
                return
        
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        if not code.strip():
            print("❌ File is empty!")
            return
        
        print(f"✓ Loaded {len(code)} characters from {file_path}")
        
    except Exception as e:
        print(f"❌ Failed to read file: {e}")
        return
    
    print("\n🔄 Processing code...")
    
    source_name = os.path.basename(file_path)
    
    if rag.load_code(code, source_name):
        save = input("\n💾 Save index for later use? (y/n): ").strip().lower()
        if save == 'y':
            rag.save_index()
        
        run_qa_mode(rag)
    else:
        print("❌ Failed to process code")


def run_qa_mode(rag: CodeRAG):
    """Interactive Q&A mode"""
    print("\n" + "="*70)
    print("💬 Q&A MODE")
    print("="*70)
    print("\nCommands:")
    print("  'exit' - Exit the program")
    print("  'stats' - Show system statistics")
    print("  'report' - Show full code quality report")
    print("  'help' - Show sample questions")
    print("="*70 + "\n")
    
    sample_questions = [
        "What does the main function do?",
        "Find all class definitions",
        "Are there any security vulnerabilities?",
        "What are the code quality issues?",
        "Show me style problems",
        "How can I improve this code?",
        "What libraries are imported?",
        "Are there any lint errors?",
    ]
    
    while True:
        try:
            question = input("\n❓ Your question: ").strip()
            
            if not question:
                continue
            
            if question.lower() == 'exit':
                print("\n👋 Goodbye!")
                break
            
            elif question.lower() == 'stats':
                rag.print_stats()
                continue
            
            elif question.lower() == 'report':
                rag.show_code_report()
                continue
            
            elif question.lower() == 'help':
                print("\n📝 Sample Questions:")
                for i, q in enumerate(sample_questions, 1):
                    print(f"  {i}. {q}")
                continue
            
            print("\n🔄 Searching...")
            result = rag.query(question)
            
            if result['success']:
                print("\n" + "="*70)
                print(f"🤖 ANSWER ({result['query_type']})")
                print("="*70)
                print(result['answer'])
                print("="*70)
                status_line = f"\n📊 Used {result['chunks_used']} chunks"
                if result.get('used_code_check'):
                    status_line += " + Code Analyzer"
                if result.get('code_check_available'):
                    status_line += " (Tools: Available)"
                else:
                    status_line += " (Tools: Basic only)"
                status_line += f" | ⏱️  {result['retrieval_time']:.2f}s"
                print(status_line)
            else:
                print(f"\n❌ {result.get('error', 'Unknown error')}")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()