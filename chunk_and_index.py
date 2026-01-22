"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 2: Code Chunking + Metadata Indexing
Contains: PythonChunker, MetadataIndex, chunk creation, keyword extraction

IMPROVEMENTS (Keeping Original Logic):
- Fixed character/line mixing bug
- Added async def support
- Better multiline string handling
- Enhanced stopwords
- Added fuzzy matching to index
- Better error handling
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
        multiline_string = None  # FIX: Track multiline strings
        
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            
            # FIX: Handle multiline strings properly
            if multiline_string:
                if current_block:
                    current_block['lines'].append(line)
                if multiline_string in stripped:
                    multiline_string = None
                continue
            
            # Detect multiline string start
            for quote in ['"""', "'''"]:
                if stripped.startswith(quote) and stripped.count(quote) == 1:
                    multiline_string = quote
                    if current_block:
                        current_block['lines'].append(line)
                    break
            
            if multiline_string:
                continue
            
            # FIX: Support async class
            if match := re.match(r'(async\s+)?class\s+(\w+)', stripped):
                if current_block:
                    blocks.append(current_block)
                current_block = {
                    'type': 'class',
                    'name': match.group(2),
                    'start': i,
                    'lines': [line],
                    'indent': indent
                }
                indent_stack = [indent]
            
            # FIX: Support async def
            elif match := re.match(r'(async\s+)?def\s+(\w+)', stripped):
                if current_block and current_block['type'] == 'class':
                    current_block['lines'].append(line)
                else:
                    if current_block:
                        blocks.append(current_block)
                    current_block = {
                        'type': 'function',
                        'name': match.group(2),
                        'start': i,
                        'lines': [line],
                        'indent': indent,
                        'is_async': bool(match.group(1))  # FIX: Track async
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
                
                # FIX: Better block end detection (ignore comments and docstrings)
                if stripped and indent <= current_block['indent'] and i > current_block['start'] + 1:
                    if not stripped.startswith(('#', '"""', "'''", '@')):
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
                    'line_count': len(block['lines']),
                    'is_async': block.get('is_async', False)  # FIX: Include async flag
                }
            }]
        
        # FIX: Use character-based splitting instead of line/10 confusion
        chunks = []
        chunk_num = 0
        pos = 0
        
        while pos < len(content):
            # Get chunk by character count
            chunk_end = min(pos + self.chunk_size, len(content))
            
            # FIX: Try to break at line boundary for cleaner chunks
            if chunk_end < len(content):
                # Look for newline in last 20% of chunk
                search_start = max(pos, chunk_end - int(self.chunk_size * 0.2))
                last_newline = content.rfind('\n', search_start, chunk_end)
                if last_newline > pos:
                    chunk_end = last_newline + 1
            
            chunk_content = content[pos:chunk_end]
            line_count = chunk_content.count('\n') + 1
            
            chunks.append({
                'content': chunk_content.strip(),
                'metadata': {
                    'source': source_name,
                    'chunk_type': block['type'],
                    'name': f"{block['name']}_part{chunk_num}",
                    'line_start': block['start'] + content[:pos].count('\n'),
                    'line_count': line_count,
                    'is_partial': True,
                    'is_async': block.get('is_async', False)
                }
            })
            
            # FIX: Move position with proper overlap
            pos = chunk_end - self.overlap if chunk_end < len(content) else chunk_end
            chunk_num += 1
        
        return chunks
    
    def _simple_chunk(self, lines: List[str], source_name: str) -> List[Dict]:
        """Simple line-based chunking fallback"""
        chunks = []
        current_chunk_lines = []
        current_size = 0
        chunk_num = 0
        
        for i, line in enumerate(lines):
            line_size = len(line) + 1  # +1 for newline
            
            # FIX: Use character count instead of arbitrary line count
            if current_size + line_size > self.chunk_size and current_chunk_lines:
                content = '\n'.join(current_chunk_lines)
                chunk_type, name = self._identify_chunk_type(content)
                
                chunks.append({
                    'content': content,
                    'metadata': {
                        'source': source_name,
                        'chunk_type': chunk_type,
                        'name': f"{name}_{chunk_num}",
                        'line_start': i - len(current_chunk_lines),
                        'line_count': len(current_chunk_lines)
                    }
                })
                
                # FIX: Calculate overlap by characters, not arbitrary lines
                overlap_lines = []
                overlap_size = 0
                for j in range(len(current_chunk_lines) - 1, -1, -1):
                    line_len = len(current_chunk_lines[j]) + 1
                    if overlap_size + line_len <= self.overlap:
                        overlap_lines.insert(0, current_chunk_lines[j])
                        overlap_size += line_len
                    else:
                        break
                
                current_chunk_lines = overlap_lines
                current_size = overlap_size
                chunk_num += 1
            
            current_chunk_lines.append(line)
            current_size += line_size
        
        # Add final chunk
        if current_chunk_lines:
            content = '\n'.join(current_chunk_lines)
            chunk_type, name = self._identify_chunk_type(content)
            
            chunks.append({
                'content': content,
                'metadata': {
                    'source': source_name,
                    'chunk_type': chunk_type,
                    'name': f"{name}_{chunk_num}",
                    'line_start': len(lines) - len(current_chunk_lines),
                    'line_count': len(current_chunk_lines)
                }
            })
        
        return chunks
    
    def _identify_chunk_type(self, content: str) -> Tuple[str, str]:
        """Identify chunk type from content"""
        for line in content.strip().split('\n')[:5]:
            # FIX: Support async class/function
            if match := re.search(r'(async\s+)?class\s+(\w+)', line):
                return 'class', match.group(2)
            if match := re.search(r'(async\s+)?def\s+(\w+)', line):
                return 'function', match.group(2)
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
            r'@(\w+)',  # FIX: Add decorator support
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content[:500])
            if matches and isinstance(matches[0], tuple):
                keywords.update(sum(matches, ()))
            else:
                keywords.update(matches)
        
        # FIX: Enhanced stopwords list
        stopwords = {
            'the', 'is', 'at', 'which', 'on', 'def', 'class', 'if', 'for', 'in', 'and', 'or',
            'as', 'with', 'from', 'import', 'return', 'self', 'true', 'false', 'none',
            'try', 'except', 'finally', 'pass', 'break', 'continue', 'async', 'await'
        }
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
                # FIX: Add fuzzy matching
                if self._fuzzy_match(term_lower, name):
                    matches['name'].update(ids)
            
            if term_lower in self.type_idx:
                matches['chunk_type'].update(self.type_idx[term_lower])
            
            for kw, ids in self.keyword_idx.items():
                # FIX: Add fuzzy matching
                if self._fuzzy_match(term_lower, kw):
                    matches['keywords'].update(ids)
        
        return matches
    
    def _fuzzy_match(self, term: str, target: str) -> bool:
        """FIX: Simple fuzzy matching for typos"""
        # Exact or substring match
        if term in target or target in term:
            return True
        
        # Similar length and high character overlap (handles typos)
        if len(term) >= 4 and len(target) >= 4:
            matches = sum(1 for c in term if c in target)
            similarity = matches / max(len(term), len(target))
            if similarity >= 0.7:
                return True
        
        return False
    
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