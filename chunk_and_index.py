"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 2: Code Chunking + Metadata Indexing
Contains: PythonChunker, MetadataIndex, chunk creation, keyword extraction
"""
import os
import re
import pickle
from typing import List, Dict, Any, Tuple, Set, Optional
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

# ========== CONFIGURATION ==========
CHUNK_SIZE = 600
CHUNK_OVERLAP = 100


class PythonChunker:
    """Intelligent Python code chunker that respects code structure"""
    
    def __init__(self, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP):
        self.chunk_size = chunk_size
        self.overlap = overlap
    
    def chunk_code(self, code: str, source_name: str = "input.py") -> List[Dict]:
        """Chunk Python code intelligently by functions, classes, and blocks"""
        lines = code.split('\n')
        chunks = []
        
        blocks = self._identify_blocks(lines)
        
        if blocks:
            for block in blocks:
                block_chunks = self._chunk_block(block, source_name)
                chunks.extend(block_chunks)
        else:
            chunks = self._simple_chunk(lines, source_name)
        
        return chunks
    
    def _identify_blocks(self, lines: List[str]) -> List[Dict]:
        """Identify classes, functions, and import blocks"""
        blocks = []
        current_block = None
        indent_stack = []
        
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            
            if match := re.match(r'class\s+(\w+)', stripped):
                if current_block:
                    blocks.append(current_block)
                current_block = {
                    'type': 'class',
                    'name': match.group(1),
                    'start': i,
                    'lines': [line],
                    'indent': indent
                }
                indent_stack = [indent]
            
            elif match := re.match(r'def\s+(\w+)', stripped):
                if current_block and current_block['type'] == 'class':
                    current_block['lines'].append(line)
                else:
                    if current_block:
                        blocks.append(current_block)
                    current_block = {
                        'type': 'function',
                        'name': match.group(1),
                        'start': i,
                        'lines': [line],
                        'indent': indent
                    }
                    indent_stack = [indent]
            
            elif 'import' in stripped and not current_block:
                if blocks and blocks[-1]['type'] == 'imports':
                    blocks[-1]['lines'].append(line)
                else:
                    blocks.append({
                        'type': 'imports',
                        'name': 'imports',
                        'start': i,
                        'lines': [line],
                        'indent': 0
                    })
            
            elif current_block:
                current_block['lines'].append(line)
                
                if stripped and indent <= current_block['indent'] and i > current_block['start'] + 1:
                    if not stripped.startswith(('#', '"""', "'''")):
                        blocks.append(current_block)
                        current_block = None
        
        if current_block:
            blocks.append(current_block)
        
        return blocks
    
    def _chunk_block(self, block: Dict, source_name: str) -> List[Dict]:
        """Chunk a code block if it's too large"""
        content = '\n'.join(block['lines'])
        
        if len(content) <= self.chunk_size:
            return [{
                'content': content,
                'metadata': {
                    'source': source_name,
                    'chunk_type': block['type'],
                    'name': block['name'],
                    'line_start': block['start'],
                    'line_count': len(block['lines'])
                }
            }]
        
        chunks = []
        lines = block['lines']
        i = 0
        chunk_num = 0
        
        while i < len(lines):
            end = min(i + self.chunk_size // 10, len(lines))
            chunk_lines = lines[i:end]
            
            chunks.append({
                'content': '\n'.join(chunk_lines),
                'metadata': {
                    'source': source_name,
                    'chunk_type': block['type'],
                    'name': f"{block['name']}_part{chunk_num}",
                    'line_start': block['start'] + i,
                    'line_count': len(chunk_lines),
                    'is_partial': True
                }
            })
            
            i = end - self.overlap // 10 if end < len(lines) else end
            chunk_num += 1
        
        return chunks
    
    def _simple_chunk(self, lines: List[str], source_name: str) -> List[Dict]:
        """Simple line-based chunking fallback"""
        chunks = []
        chunk_size_lines = self.chunk_size // 50
        overlap_lines = self.overlap // 50
        
        i = 0
        while i < len(lines):
            end = min(i + chunk_size_lines, len(lines))
            chunk_lines = lines[i:end]
            content = '\n'.join(chunk_lines)
            
            chunk_type, name = self._identify_chunk_type(content)
            
            chunks.append({
                'content': content,
                'metadata': {
                    'source': source_name,
                    'chunk_type': chunk_type,
                    'name': name,
                    'line_start': i,
                    'line_count': len(chunk_lines)
                }
            })
            
            i = end - overlap_lines if end < len(lines) else end
        
        return chunks
    
    def _identify_chunk_type(self, content: str) -> Tuple[str, str]:
        """Identify chunk type from content"""
        for line in content.strip().split('\n')[:5]:
            if match := re.search(r'class\s+(\w+)', line):
                return 'class', match.group(1)
            if match := re.search(r'def\s+(\w+)', line):
                return 'function', match.group(1)
            if 'import' in line:
                return 'imports', 'imports'
        return 'code_block', 'code'


class MetadataIndex:
    """Fast metadata-based lookup index"""
    
    def __init__(self):
        self.name_idx = defaultdict(set)
        self.type_idx = defaultdict(set)
        self.keyword_idx = defaultdict(set)
        self.exact_match_idx = defaultdict(set)
        self.all_keywords = set()
    
    def add(self, chunk_id: int, metadata: Dict, content: str):
        """Index a chunk by its metadata"""
        if name := metadata.get('name'):
            self.name_idx[name.lower()].add(chunk_id)
            self.exact_match_idx[name.lower()].add(chunk_id)
        
        if chunk_type := metadata.get('chunk_type'):
            self.type_idx[chunk_type.lower()].add(chunk_id)
        
        keywords = self._extract_keywords(metadata, content)
        for kw in keywords:
            kw_lower = kw.lower()
            self.keyword_idx[kw_lower].add(chunk_id)
            self.all_keywords.add(kw_lower)
    
    def _extract_keywords(self, metadata: Dict, content: str) -> Set[str]:
        """Extract searchable keywords from metadata and content"""
        keywords = set()
        
        if name := metadata.get('name'):
            keywords.update(re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)', name))
            keywords.update(name.split('_'))
        
        if source := metadata.get('source'):
            source_base = os.path.splitext(os.path.basename(source))[0]
            keywords.update(source_base.split('_'))
        
        patterns = [
            r'\bdef\s+(\w+)',
            r'\bclass\s+(\w+)',
            r'\b([A-Z][a-z]+[A-Z]\w*)',
            r'\b(\w+)_(\w+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content[:500])
            if isinstance(matches[0] if matches else None, tuple):
                keywords.update(sum(matches, ()))
            else:
                keywords.update(matches)
        
        stopwords = {'the', 'is', 'at', 'which', 'on', 'def', 'class', 'if', 'for', 'in', 'and', 'or'}
        keywords = {k for k in keywords if len(k) > 2 and k.lower() not in stopwords}
        
        return keywords
    
    def get_matches(self, query_terms: List[str]) -> Dict[str, Set[int]]:
        """Get chunk IDs matching query terms"""
        matches = defaultdict(set)
        
        for term in query_terms:
            term_lower = term.lower()
            
            if term_lower in self.exact_match_idx:
                matches['exact_match'].update(self.exact_match_idx[term_lower])
            
            for name, ids in self.name_idx.items():
                if term_lower in name or name in term_lower:
                    matches['name'].update(ids)
            
            if term_lower in self.type_idx:
                matches['chunk_type'].update(self.type_idx[term_lower])
            
            for kw, ids in self.keyword_idx.items():
                if term_lower in kw or kw in term_lower:
                    matches['keywords'].update(ids)
        
        return matches
    
    def save(self, path: str):
        """Save index to disk"""
        with open(path, 'wb') as f:
            pickle.dump({
                'name_idx': dict(self.name_idx),
                'type_idx': dict(self.type_idx),
                'keyword_idx': dict(self.keyword_idx),
                'exact_match_idx': dict(self.exact_match_idx),
                'all_keywords': list(self.all_keywords)
            }, f)
    
    @classmethod
    def load(cls, path: str) -> Optional['MetadataIndex']:
        """Load index from disk"""
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
            idx.all_keywords = set(data['all_keywords'])
            
            logger.info(f"✓ Loaded metadata index with {len(idx.all_keywords)} keywords")
            return idx
        except Exception as e:
            logger.error(f"Failed to load metadata index: {e}")
            return None