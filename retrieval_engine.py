"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 3: Question Understanding + Retrieval
Contains: QuestionType, QuestionRouter, retrieval logic, metadata boosting
"""
import re
from typing import List, Dict, Any, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# Metadata boost weights
METADATA_BOOST = {
    "exact_match": 1.0,
    "name": 0.5,
    "chunk_type": 0.3,
    "keywords": 0.4,
    "file_context": 0.2
}


class QuestionType(Enum):
    """Intelligent question classification"""
    DEFINITION_LOOKUP = "definition_lookup"
    FLOW_EXPLANATION = "flow_explanation"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    ERROR_ANALYSIS = "error_analysis"
    CODE_REVIEW = "code_review"
    PATTERN_ANALYSIS = "pattern_analysis"
    SECURITY_CHECK = "security_check"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    CODE_QUALITY = "code_quality"
    GENERAL_QUERY = "general_query"


class QuestionRouter:
    """Routes questions to appropriate retrieval strategies"""
    
    PATTERNS = {
        QuestionType.DEFINITION_LOOKUP: [
            r'where is .* defined', r'find (class|function|def)', 
            r'locate', r'show me .* (class|function)'
        ],
        QuestionType.FLOW_EXPLANATION: [
            r'how does .* work', r'explain.*flow', r'what happens when',
            r'trace', r'workflow', r'process'
        ],
        QuestionType.DEPENDENCY_ANALYSIS: [
            r'what (does|libraries|packages|imports)', r'dependencies',
            r'uses? which', r'requires?'
        ],
        QuestionType.ERROR_ANALYSIS: [
            r'(why|what).*error', r'debug', r'fix', r'bug', 
            r'not working', r'exception', r'fails?'
        ],
        QuestionType.CODE_REVIEW: [
            r'improve', r'optimize', r'review', r'refactor',
            r'best practice', r'clean up'
        ],
        QuestionType.PATTERN_ANALYSIS: [
            r'pattern', r'similar', r'duplicate', r'repeated'
        ],
        QuestionType.SECURITY_CHECK: [
            r'security', r'vulnerability', r'vulnerabilities', r'safe', r'injection',
            r'exploit', r'risk'
        ],
        QuestionType.PERFORMANCE_ANALYSIS: [
            r'performance', r'slow', r'bottleneck', r'memory',
            r'faster', r'efficiency'
        ],
        QuestionType.CODE_QUALITY: [
            r'lint', r'quality', r'static analysis', r'pylint', r'flake8',
            r'bandit', r'code check', r'style issues', r'formatting'
        ]
    }
    
    @classmethod
    def classify(cls, query: str) -> Tuple[QuestionType, Dict]:
        """Classify query type and extract entities"""
        q_lower = query.lower()
        
        for q_type, patterns in cls.PATTERNS.items():
            if any(re.search(p, q_lower) for p in patterns):
                return q_type, cls._extract_entities(query, q_type)
        
        return QuestionType.GENERAL_QUERY, cls._extract_entities(query, QuestionType.GENERAL_QUERY)
    
    @staticmethod
    def _extract_entities(query: str, q_type: QuestionType) -> Dict:
        """Extract function/class names and keywords from query"""
        entities = re.findall(r'\b([A-Z][a-zA-Z0-9_]*|[a-z_][a-z0-9_]*)\b', query)
        quoted = re.findall(r'["\']([^"\']+)["\']', query)
        
        return {
            "type": q_type.value,
            "query": query,
            "entities": entities,
            "quoted_terms": quoted,
            "keywords": [e.lower() for e in entities if len(e) > 2]
        }
    
    @staticmethod
    def get_retrieval_params(q_type: QuestionType) -> Dict:
        """Get optimized retrieval parameters for question type"""
        params_map = {
            QuestionType.DEFINITION_LOOKUP: {
                "k": 3,
                "prefer_types": ["class", "function"],
                "boost_exact_match": True,
                "use_code_check": False
            },
            QuestionType.FLOW_EXPLANATION: {
                "k": 7,
                "prefer_types": ["function", "class", "code_block"],
                "boost_exact_match": False,
                "use_code_check": False
            },
            QuestionType.DEPENDENCY_ANALYSIS: {
                "k": 10,
                "prefer_types": ["imports", "class", "function"],
                "boost_exact_match": False,
                "use_code_check": False
            },
            QuestionType.ERROR_ANALYSIS: {
                "k": 6,
                "prefer_types": ["function", "class"],
                "boost_exact_match": True,
                "use_code_check": True
            },
            QuestionType.CODE_REVIEW: {
                "k": 8,
                "prefer_types": ["function", "class"],
                "boost_exact_match": False,
                "use_code_check": True
            },
            QuestionType.PATTERN_ANALYSIS: {
                "k": 12,
                "prefer_types": ["function", "class"],
                "boost_exact_match": False,
                "use_code_check": False
            },
            QuestionType.SECURITY_CHECK: {
                "k": 8,
                "prefer_types": ["function", "class"],
                "boost_exact_match": False,
                "use_code_check": True
            },
            QuestionType.PERFORMANCE_ANALYSIS: {
                "k": 6,
                "prefer_types": ["function", "loop", "class"],
                "boost_exact_match": False,
                "use_code_check": True
            },
            QuestionType.CODE_QUALITY: {
                "k": 3,
                "prefer_types": [],
                "boost_exact_match": False,
                "use_code_check": True,
                "require_code_check": True
            }
        }
        return params_map.get(q_type, {"k": 5, "prefer_types": [], "boost_exact_match": False, "use_code_check": False})