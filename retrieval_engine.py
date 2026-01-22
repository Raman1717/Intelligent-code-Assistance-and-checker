"""
OPTIMIZED CODE RAG SYSTEM - WITH INTEGRATED CODE CHECKER
================================================================
File 3: Question Understanding + Retrieval (IMPROVED)
Contains: QuestionType, QuestionRouter, retrieval logic, metadata boosting
"""
import re
from typing import List, Dict, Any, Tuple
from enum import Enum
import logging

# Try to import NLTK stopwords, fallback to basic set if unavailable
try:
    from nltk.corpus import stopwords
    import nltk
    try:
        STOPWORDS = set(stopwords.words('english'))
    except LookupError:
        nltk.download('stopwords', quiet=True)
        STOPWORDS = set(stopwords.words('english'))
except ImportError:
    # Minimal fallback if NLTK not available
    STOPWORDS = {
        'does', 'works', 'explain', 'show', 'tell', 'find', 'get', 'the', 'this',
        'that', 'with', 'from', 'have', 'what', 'when', 'where', 'which', 'who',
        'how', 'why', 'can', 'should', 'would', 'could', 'will', 'make', 'use'
    }

logger = logging.getLogger(__name__)

# Dynamic metadata boost weights (base values)
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
    
    # Patterns now with weights for confidence scoring
    PATTERNS = {
        QuestionType.DEFINITION_LOOKUP: [
            (r'where is .* defined', 1.0),
            (r'find (class|function|def)', 1.0),
            (r'locate', 0.8),
            (r'show me .* (class|function)', 0.9),
            (r'what is (the )?(class|function|method)', 0.7)
        ],
        QuestionType.FLOW_EXPLANATION: [
            (r'how does .* work', 1.0),
            (r'explain.*flow', 1.0),
            (r'what happens when', 0.9),
            (r'trace', 0.8),
            (r'workflow', 0.9),
            (r'process', 0.6),
            (r'walk me through', 0.9),
            (r'step by step', 0.8)
        ],
        QuestionType.DEPENDENCY_ANALYSIS: [
            (r'what (does|libraries|packages|imports)', 0.9),
            (r'dependencies', 1.0),
            (r'uses? which', 0.7),
            (r'requires?', 0.8)
        ],
        QuestionType.ERROR_ANALYSIS: [
            (r'(why|what).*error', 1.0),
            (r'debug', 0.9),
            (r'fix', 0.7),
            (r'bug', 0.8),
            (r'not working', 0.8),
            (r'exception', 1.0),
            (r'fails?', 0.8),
            (r'crash', 0.9),
            (r'wrong with', 0.7)
        ],
        QuestionType.CODE_REVIEW: [
            (r'improve', 0.8),
            (r'optimize', 0.9),
            (r'review', 1.0),
            (r'refactor', 1.0),
            (r'best practice', 1.0),
            (r'clean up', 0.8)
        ],
        QuestionType.PATTERN_ANALYSIS: [
            (r'pattern', 1.0),
            (r'similar', 0.8),
            (r'duplicate', 0.9),
            (r'repeated', 0.9)
        ],
        QuestionType.SECURITY_CHECK: [
            (r'security', 1.0),
            (r'vulnerability', 1.0),
            (r'vulnerabilities', 1.0),
            (r'safe', 0.6),
            (r'injection', 1.0),
            (r'exploit', 1.0),
            (r'risk', 0.7)
        ],
        QuestionType.PERFORMANCE_ANALYSIS: [
            (r'performance', 1.0),
            (r'slow', 0.8),
            (r'bottleneck', 1.0),
            (r'memory', 0.7),
            (r'faster', 0.8),
            (r'efficiency', 0.9)
        ],
        QuestionType.CODE_QUALITY: [
            (r'lint', 1.0),
            (r'quality', 0.7),
            (r'static analysis', 1.0),
            (r'pylint', 1.0),
            (r'flake8', 1.0),
            (r'bandit', 1.0),
            (r'code check', 1.0),
            (r'style issues', 0.9),
            (r'formatting', 0.8)
        ]
    }
    
    
    @classmethod
    def classify(cls, query: str) -> Tuple[QuestionType, Dict]:
        """Classify query type using confidence-based scoring"""
        q_lower = query.lower()
        scores = {}
        
        # Score each question type
        for q_type, patterns in cls.PATTERNS.items():
            type_score = 0.0
            matched_patterns = []
            
            for pattern, weight in patterns:
                if re.search(pattern, q_lower):
                    type_score += weight
                    matched_patterns.append(pattern)
            
            if type_score > 0:
                scores[q_type] = {
                    'score': type_score,
                    'patterns': matched_patterns
                }
        
        # Get best match with confidence threshold
        if scores:
            best_type = max(scores.keys(), key=lambda k: scores[k]['score'])
            confidence = scores[best_type]['score']
            
            # Low confidence threshold for fallback
            if confidence < 0.5:
                logger.info(f"Low confidence ({confidence:.2f}) for classification, using GENERAL_QUERY")
                return QuestionType.GENERAL_QUERY, cls._extract_entities(query, QuestionType.GENERAL_QUERY, 0.0)
            
            logger.info(f"Classified as {best_type.value} with confidence {confidence:.2f}")
            return best_type, cls._extract_entities(query, best_type, confidence)
        
        # No patterns matched
        return QuestionType.GENERAL_QUERY, cls._extract_entities(query, QuestionType.GENERAL_QUERY, 0.0)
    
    @classmethod
    def _extract_entities(cls, query: str, q_type: QuestionType, confidence: float) -> Dict:
        """Extract function/class names and keywords with improved filtering"""
        # Extract potential entities
        raw_entities = re.findall(r'\b([A-Z][a-zA-Z0-9_]*|[a-z_][a-z0-9_]*)\b', query)
        quoted = re.findall(r'["\']([^"\']+)["\']', query)
        
        # Filter entities
        filtered_entities = []
        for entity in raw_entities:
            entity_lower = entity.lower()
            # Skip if stopword or too short
            if entity_lower in STOPWORDS or len(entity) <= 2:
                continue
            # Prioritize camelCase or snake_case patterns
            if '_' in entity or (entity[0].isupper() and any(c.isupper() for c in entity[1:])):
                filtered_entities.append(entity)
            elif len(entity) > 3:  # Keep longer words
                filtered_entities.append(entity)
        
        # Extract keywords (prioritize quoted terms and code-like tokens)
        keywords = []
        for term in quoted:
            keywords.append(term.lower())
        
        for entity in filtered_entities:
            if len(entity) > 3:
                keywords.append(entity.lower())
        
        return {
            "type": q_type.value,
            "query": query,
            "entities": filtered_entities,
            "quoted_terms": quoted,
            "keywords": keywords,
            "confidence": confidence
        }
    
    @staticmethod
    def get_retrieval_params(q_type: QuestionType, confidence: float = 1.0, 
                            retrieval_context: Dict = None) -> Dict:
        """Get dynamic retrieval parameters based on question type and context"""
        
        # Base parameters
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
        
        params = params_map.get(q_type, {
            "k": 5, 
            "prefer_types": [], 
            "boost_exact_match": False, 
            "use_code_check": False
        })
        
        # Apply dynamic adjustments based on confidence
        if confidence < 0.7:
            # Low confidence - broaden search
            params["k"] = min(params["k"] + 3, 15)
            params["boost_exact_match"] = False
            logger.info(f"Low confidence, increased k to {params['k']}")
        
        # Apply context-based adjustments
        if retrieval_context:
            # If no exact matches were found in previous attempt
            if retrieval_context.get("no_exact_matches"):
                params["boost_exact_match"] = False
                params["k"] = min(params["k"] + 2, 15)
                logger.info("No exact matches found, widening search")
            
            # If all results were same type, diversify
            if retrieval_context.get("all_same_type"):
                params["prefer_types"] = []
                logger.info("Results were homogeneous, removing type preference")
            
            # If chunks were too small, retrieve neighbors
            if retrieval_context.get("chunks_too_small"):
                params["retrieve_neighbors"] = True
                logger.info("Previous chunks too small, will retrieve neighbors")
        
        return params
    
    @staticmethod
    def get_dynamic_boost_weights(q_type: QuestionType, confidence: float, 
                                  has_exact_matches: bool) -> Dict[str, float]:
        """Calculate dynamic metadata boost weights based on context"""
        weights = METADATA_BOOST.copy()
        
        # Adjust exact_match boost based on confidence
        if confidence > 0.8 and has_exact_matches:
            weights["exact_match"] = 1.3  # Increase when confident
        elif not has_exact_matches:
            weights["exact_match"] = 0.0  # No boost if no matches
            weights["keywords"] = 0.6  # Increase keyword importance
        
        # Question-type specific adjustments
        if q_type == QuestionType.DEFINITION_LOOKUP:
            weights["name"] = 0.7  # Prioritize name matches
        elif q_type == QuestionType.FLOW_EXPLANATION:
            weights["file_context"] = 0.4  # Context is important
        elif q_type == QuestionType.PATTERN_ANALYSIS:
            weights["chunk_type"] = 0.5  # Type similarity matters
        
        return weights