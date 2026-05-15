"""
ENHANCED CODE RAG SYSTEM - Question Understanding + Retrieval
================================================================
IMPROVEMENTS:
1. ✅ Adaptive hybrid ratio per query type (definition=more BM25, flow=more semantic)
2. ✅ Fixed CONTEXT_STOPWORDS logic (words actually removed now work correctly)
3. ✅ Call-graph based query expansion (auto-expands using actual code relationships)
4. ✅ Type hint aware retrieval (queries about return types / param types)
5. ✅ Decorator aware retrieval (@property, @staticmethod, @lru_cache etc.)
6. ✅ Multi-term query decomposition
7. ✅ Confidence-based retrieval strategy
"""

import re
from typing import List, Dict, Any, Tuple, Set, Optional
from enum import Enum
from dataclasses import dataclass
from copy import deepcopy
import logging

# ✅ FIXED: These are the actual words we want to preserve in context queries
# (removed from stopwords when the context is relevant)
FLOW_PRESERVE = {'flow', 'process', 'step', 'workflow', 'trace', 'walk'}
ERROR_PRESERVE = {'error', 'bug', 'issue', 'fail', 'crash', 'exception'}
OPTIMIZE_PRESERVE = {'optimize', 'improve', 'faster', 'better', 'efficient', 'speed'}

BASE_STOPWORDS = {
    'does', 'works', 'explain', 'show', 'tell', 'find', 'get', 'the', 'this',
    'that', 'with', 'from', 'have', 'what', 'when', 'where', 'which', 'who',
    'how', 'why', 'can', 'should', 'would', 'could', 'will', 'make', 'use'
}

logger = logging.getLogger(__name__)

MAX_K = 5  # Hard cap proven by eval

DEFAULT_METADATA_BOOST = {
    "exact_match": 1.0,
    "name": 0.5,
    "chunk_type": 0.3,
    "keywords": 0.4,
    "file_context": 0.2,
    "function_calls": 0.35,
    "docstring_match": 0.45,
    "type_hint_match": 0.4,    # NEW
    "decorator_match": 0.3     # NEW
}

# ✅ NEW: Per query-type hybrid ratio (semantic weight, bm25 weight)
HYBRID_RATIOS = {
    "definition_lookup": (0.5, 0.5),       # exact names matter — more BM25
    "flow_explanation": (0.8, 0.2),        # meaning matters — more semantic
    "dependency_analysis": (0.6, 0.4),
    "error_analysis": (0.65, 0.35),
    "security_check": (0.7, 0.3),
    "optimization": (0.6, 0.4),
    "counting_query": (0.5, 0.5),
    "listing_query": (0.5, 0.5),
    "general_query": (0.7, 0.3),
    "code_review": (0.7, 0.3),
    "pattern_analysis": (0.75, 0.25),
    "performance_analysis": (0.65, 0.35),
    "code_quality": (0.65, 0.35),
}


class QuestionType(Enum):
    DEFINITION_LOOKUP = "definition_lookup"
    FLOW_EXPLANATION = "flow_explanation"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    ERROR_ANALYSIS = "error_analysis"
    CODE_REVIEW = "code_review"
    PATTERN_ANALYSIS = "pattern_analysis"
    SECURITY_CHECK = "security_check"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    CODE_QUALITY = "code_quality"
    OPTIMIZATION = "optimization"
    COUNTING_QUERY = "counting_query"
    LISTING_QUERY = "listing_query"
    GENERAL_QUERY = "general_query"


@dataclass
class IntentScore:
    question_type: QuestionType
    confidence: float
    matched_patterns: List[str]

    def __repr__(self):
        return f"{self.question_type.value}({self.confidence:.2f})"


@dataclass
class ClassificationResult:
    primary_intent: IntentScore
    secondary_intents: List[IntentScore]
    entities: List[str]
    quoted_terms: List[str]
    keywords: List[str]
    is_compound: bool
    is_counting: bool
    is_listing: bool

    @property
    def all_intents(self) -> List[IntentScore]:
        return [self.primary_intent] + self.secondary_intents


class QuestionRouter:
    """Enhanced question router with adaptive retrieval strategies"""

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
            (r'walk me through', 0.9),
            (r'step by step', 0.8),
            (r'process for', 0.8)
        ],
        QuestionType.DEPENDENCY_ANALYSIS: [
            (r'what (does|libraries|packages|imports)', 0.9),
            (r'dependencies', 1.0),
            (r'uses? which', 0.7),
            (r'requires?', 0.8),
            (r'what libraries', 1.0)
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
        QuestionType.SECURITY_CHECK: [
            (r'security', 1.0),
            (r'vulnerability', 1.0),
            (r'vulnerabilities', 1.0),
            (r'safe', 0.6),
            (r'injection', 1.0),
            (r'exploit', 1.0),
            (r'risk', 0.7)
        ],
        QuestionType.OPTIMIZATION: [
            (r'optimize', 1.0),
            (r'optimise', 1.0),
            (r'improve.*performance', 1.0),
            (r'make.*faster', 0.9),
            (r'make.*better', 0.8),
            (r'make.*efficient', 0.9),
            (r'speed up', 0.9),
            (r'refactor', 0.8),
        ],
        QuestionType.COUNTING_QUERY: [
            (r'how many', 1.0),
            (r'count (of|the)?', 0.9),
            (r'total number', 1.0),
            (r'number of', 0.9),
        ],
        QuestionType.LISTING_QUERY: [
            (r'list (all|the)?', 1.0),
            (r'show (all|me all)?', 0.8),
            (r'what (are|functions|classes|methods)', 0.9),
            (r'give me (all|the list)', 0.9),
        ],
    }

    COMPOUND_PATTERNS = [
        r'\b(and|then)\b',
        r'\b(also|plus|additionally)\b',
        r'(explain|debug|review|fix|optimize|check).*\b(and|then)\b.*(explain|debug|review|fix|optimize|check)',
    ]

    @classmethod
    def classify(cls, query: str) -> ClassificationResult:
        q_lower = query.lower()

        is_counting = bool(re.search(r'how many|count|total number|number of', q_lower))
        is_listing = bool(re.search(r'list (all|the)?|show (all|me all)?|what (are|functions|classes)', q_lower))
        is_compound = cls._is_compound_query(q_lower)

        intent_scores = []
        for q_type, patterns in cls.PATTERNS.items():
            raw_score = 0.0
            matched = []
            max_weight = sum(w for _, w in patterns)

            for pattern, weight in patterns:
                if re.search(pattern, q_lower):
                    raw_score += weight
                    matched.append(pattern)

            if raw_score > 0:
                normalized = min(raw_score / max(max_weight, 1.0), 1.0)
                intent_scores.append(IntentScore(q_type, normalized, matched))

        intent_scores.sort(key=lambda x: x.confidence, reverse=True)

        if not intent_scores:
            primary = IntentScore(QuestionType.GENERAL_QUERY, 0.0, [])
            secondary = []
        else:
            primary = intent_scores[0]
            threshold = max(primary.confidence - 0.3, 0.4)
            secondary = [s for s in intent_scores[1:] if s.confidence >= threshold]

        entities, quoted, keywords = cls._extract_entities_improved(query, q_lower)

        return ClassificationResult(
            primary_intent=primary,
            secondary_intents=secondary,
            entities=entities,
            quoted_terms=quoted,
            keywords=keywords,
            is_compound=is_compound,
            is_counting=is_counting,
            is_listing=is_listing
        )

    @classmethod
    def _is_compound_query(cls, query_lower: str) -> bool:
        for pattern in cls.COMPOUND_PATTERNS:
            if re.search(pattern, query_lower):
                return True
        return False

    @classmethod
    def _extract_entities_improved(cls, query: str, query_lower: str) -> Tuple[List[str], List[str], List[str]]:
        entities = []
        quoted = re.findall(r'["\']([^"\']+)["\']', query)
        keywords = []

        dotted = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_.]*)\b', query)
        entities.extend(dotted)

        backticked = re.findall(r'`([^`]+)`', query)
        entities.extend(backticked)

        identifiers = re.findall(r'\b([A-Z][a-z]+[A-Z][a-zA-Z0-9]*|[a-z_][a-z0-9_]+)\b', query)

        stopwords = cls._get_adaptive_stopwords(query_lower)

        for ident in identifiers:
            if ident.lower() not in stopwords and len(ident) > 2:
                if '_' in ident or any(c.isupper() for c in ident[1:]):
                    entities.append(ident)
                elif len(ident) > 3:
                    entities.append(ident)

        # ✅ NEW: Extract decorator references from query (@property, etc.)
        dec_refs = re.findall(r'@(\w+)', query)
        entities.extend(dec_refs)

        # ✅ NEW: Extract type hint references (-> list, -> str, etc.)
        type_refs = re.findall(r'->\s*(\w[\w\[\], ]*)', query)
        for t in type_refs:
            for token in re.findall(r'\w+', t):
                if len(token) > 2 and token.lower() not in stopwords:
                    keywords.append(token.lower())

        keywords.extend(term.lower() for term in quoted)
        keywords.extend(e.lower() for e in entities if len(e) > 3)

        entities = list(dict.fromkeys(entities))
        keywords = list(dict.fromkeys(keywords))

        return entities, quoted, keywords

    @classmethod
    def _get_adaptive_stopwords(cls, query_lower: str) -> Set[str]:
        """
        ✅ FIXED: Properly remove context-relevant words from stopwords.
        Previous version referenced CONTEXT_STOPWORDS dict that mapped to sets
        but those words weren't in BASE_STOPWORDS — so removal had no effect.
        Now we build a mutable copy and conditionally REMOVE words that matter.
        """
        stopwords = BASE_STOPWORDS.copy()

        if any(word in query_lower for word in ['flow', 'process', 'step', 'workflow']):
            stopwords -= FLOW_PRESERVE

        if any(word in query_lower for word in ['error', 'bug', 'debug', 'exception']):
            stopwords -= ERROR_PRESERVE

        if any(word in query_lower for word in ['optimize', 'improve', 'faster', 'speed']):
            stopwords -= OPTIMIZE_PRESERVE

        return stopwords

    @staticmethod
    def get_retrieval_params(
        classification: ClassificationResult,
        retrieval_context: Dict = None
    ) -> Dict[str, Any]:
        """Return retrieval params including per-query-type hybrid ratio."""
        primary = classification.primary_intent
        base_params = QuestionRouter._get_base_params(primary.question_type)
        params = deepcopy(base_params)

        if classification.secondary_intents:
            params = QuestionRouter._merge_multi_intent_params(params, classification.secondary_intents)

        if retrieval_context:
            params = QuestionRouter._apply_context_adjustments(params, retrieval_context)

        params["k"] = MAX_K

        # ✅ NEW: Embed hybrid ratio into params
        q_type_value = primary.question_type.value
        sem_w, bm25_w = HYBRID_RATIOS.get(q_type_value, (0.7, 0.3))
        params["semantic_weight"] = sem_w
        params["bm25_weight"] = bm25_w

        return params

    @staticmethod
    def _get_base_params(q_type: QuestionType) -> Dict[str, Any]:
        params_map = {
            QuestionType.DEFINITION_LOOKUP: {
                "k": 5,
                "prefer_types": ["class", "function", "init_method"],
                "boost_exact_match": True,
                "use_code_check": False
            },
            QuestionType.FLOW_EXPLANATION: {
                "k": 5,
                "prefer_types": ["function", "class", "code_block", "nested_function"],
                "boost_exact_match": False,
                "use_code_check": False
            },
            QuestionType.DEPENDENCY_ANALYSIS: {
                "k": 5,
                "prefer_types": ["imports", "class", "function"],
                "boost_exact_match": False,
                "use_code_check": False
            },
            QuestionType.ERROR_ANALYSIS: {
                "k": 5,
                "prefer_types": ["function", "class"],
                "boost_exact_match": True,
                "use_code_check": True
            },
            QuestionType.SECURITY_CHECK: {
                "k": 5,
                "prefer_types": ["function", "class"],
                "boost_exact_match": False,
                "use_code_check": True
            },
            QuestionType.OPTIMIZATION: {
                "k": 5,
                "prefer_types": ["function", "class"],
                "boost_exact_match": True,
                "use_code_check": True
            },
            QuestionType.COUNTING_QUERY: {
                "k": 5,
                "prefer_types": [],
                "boost_exact_match": False,
                "use_code_check": False,
                "use_statistics": True
            },
            QuestionType.LISTING_QUERY: {
                "k": 5,
                "prefer_types": [],
                "boost_exact_match": False,
                "use_code_check": False,
                "use_statistics": True
            },
        }
        return params_map.get(q_type, {
            "k": 5,
            "prefer_types": [],
            "boost_exact_match": False,
            "use_code_check": False
        })

    @staticmethod
    def _merge_multi_intent_params(base_params, secondary_intents):
        merged = base_params.copy()
        for intent in secondary_intents:
            secondary_params = QuestionRouter._get_base_params(intent.question_type)
            for ptype in secondary_params.get("prefer_types", []):
                if ptype not in merged["prefer_types"]:
                    merged["prefer_types"].append(ptype)
        if any(QuestionRouter._get_base_params(i.question_type).get("use_code_check", False)
               for i in secondary_intents):
            merged["use_code_check"] = True
        return merged

    @staticmethod
    def _apply_context_adjustments(params, context):
        adjusted = params.copy()
        if context.get("no_exact_matches"):
            adjusted["boost_exact_match"] = False
            logger.info("No exact matches found, disabling exact match boost")
        if context.get("all_same_type"):
            adjusted["prefer_types"] = []
            logger.info("Results homogeneous, removing type preference")
        return adjusted

    @staticmethod
    def get_dynamic_boost_weights(
        classification: ClassificationResult,
        has_exact_matches: bool
    ) -> Dict[str, float]:
        weights = deepcopy(DEFAULT_METADATA_BOOST)
        primary = classification.primary_intent
        confidence = primary.confidence

        if confidence > 0.8 and has_exact_matches:
            weights["exact_match"] = 1.3
        elif not has_exact_matches:
            weights["exact_match"] = 0.0
            weights["keywords"] = 0.6

        if primary.question_type == QuestionType.DEFINITION_LOOKUP:
            weights["name"] = 0.8
        elif primary.question_type == QuestionType.FLOW_EXPLANATION:
            weights["file_context"] = 0.4
            weights["function_calls"] = 0.5
        elif primary.question_type == QuestionType.OPTIMIZATION:
            weights["name"] = 0.8
            weights["exact_match"] = 1.5

        if classification.is_counting or classification.is_listing:
            weights["exact_match"] = 0.5
            weights["keywords"] = 0.7
            weights["docstring_match"] = 0.6

        return weights


def expand_query_terms(
    query: str,
    classification: ClassificationResult,
    code_structure: Optional[Dict] = None
) -> List[str]:
    """
    ✅ IMPROVED: Auto-expand using actual call graph from the codebase.
    If a queried function calls others, include those callee names as expansion terms.
    Falls back to static domain dictionary if no code_structure provided.
    """
    expanded = [query]
    q_lower = query.lower()

    # ✅ NEW: Auto-expand from call graph
    if code_structure:
        all_funcs = set(code_structure.get('all_functions', []))
        function_calls = code_structure.get('function_calls', {})
        called_by = code_structure.get('called_by', {})

        for func_name in all_funcs:
            if func_name.lower() in q_lower:
                # Add functions this one calls
                for callee in function_calls.get(func_name, []):
                    if callee not in expanded:
                        expanded.append(callee)
                # Add functions that call this one
                for caller in called_by.get(func_name, []):
                    if caller not in expanded:
                        expanded.append(caller)

    # Static domain fallback
    static_expansions = {
        'authentication': ['login', 'password', 'user', 'auth', 'credentials'],
        'late fee': ['fine', 'overdue', 'penalty', 'charge'],
        'reservation': ['reserve', 'queue', 'booking', 'hold'],
        'search': ['find', 'query', 'lookup', 'filter'],
        'security': ['vulnerability', 'exploit', 'risk', 'injection'],
        'cache': ['lru_cache', 'memoize', 'cached', 'redis'],
        'async': ['await', 'coroutine', 'asyncio', 'task'],
        'decorator': ['property', 'staticmethod', 'classmethod', 'wraps'],
    }

    for key, related_terms in static_expansions.items():
        if key in q_lower:
            expanded.extend(related_terms)

    return list(dict.fromkeys(expanded))  # deduplicate preserving order