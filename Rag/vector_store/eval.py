import sys
import os
import numpy as np

EVAL_QUERIES = [
    {
        "query": "which function constructs a car data dictionary with availability set to true and appends it to the global fleet list",
        "relevant": ["add_car"]
    },
    {
        "query": "where does the system mutate the global fleet list in-place while checking active rentals and reservation queue for orphaned references before deletion",
        "relevant": ["remove_car"]
    },
    {
        "query": "which function simultaneously initializes a zero float in late_fees and an empty list in payment_records keyed by the same customer identifier",
        "relevant": ["register_customer"]
    },
    {
        "query": "where is a plain-text license number retrieved from a dictionary and compared directly without any hashing or encoding step",
        "relevant": ["authenticate_customer"]
    },
    {
        "query": "which function enforces an upper bound on active rentals by comparing list length against a module-level constant before modifying car availability",
        "relevant": ["rent_car_part0"]
    },
    {
        "query": "which function applies a 1.25 multiplier only after crossing a 7 day threshold on top of a base plus per-day product already stored in a local variable",
        "relevant": ["calculate_late_fee"]
    },
    {
        "query": "which function restores a car availability flag to true removes it from active rentals and delegates fee computation to two separate helper functions",
        "relevant": ["return_car_part0"]
    },
 {
        "query": "which function restores a car availability flag to true removes it from active rentals and delegates fee computation to two separate helper functions",
        "relevant": ["return_car_part0", "return_car_part1"]
    },
    {
        "query": "which function iterates the global fleet to tally available and damaged counts then prints a formatted percentage but returns None on an empty fleet before reaching any output",
        "relevant": ["generate_report_part0"]
    },
    {
        "query": "where is eval() called directly on file contents read from disk making the function vulnerable to arbitrary code execution",
        "relevant": ["load_config"]
    }
]

# ==============================
# METRICS
# ==============================

def hit_at_k(retrieved, relevant, k):
    """1 if any relevant chunk appears in the top-k retrieved, else 0."""
    return int(any(r in retrieved[:k] for r in relevant))


def recall_at_k(retrieved, relevant, k):
    """Fraction of relevant chunks found in top-k."""
    if not relevant:
        return 0.0
    return sum(1 for r in retrieved[:k] if r in relevant) / len(relevant)


def mrr(retrieved, relevant):
    """Mean Reciprocal Rank — rewards finding a relevant chunk early."""
    for i, r in enumerate(retrieved):
        if r in relevant:
            return 1 / (i + 1)
    return 0.0


def ndcg_at_k(retrieved, relevant, k):
    """Normalised Discounted Cumulative Gain at k."""
    dcg   = sum(1 / np.log2(i + 2) for i, r in enumerate(retrieved[:k]) if r in relevant)
    ideal = sum(1 / np.log2(i + 2) for i in range(min(len(relevant), k)))
    return dcg / ideal if ideal > 0 else 0.0


# ==============================
# EVALUATE
# ==============================

def evaluate_rag(rag, k=5):
    hits, recalls, mrrs, ndcgs = [], [], [], []
    failed = []

    print("\n" + "=" * 65)
    print(f"  RAG EVALUATION  (k={k})  —  check.py (Library System)")
    print("=" * 65)

    results_table = []

    for sample in EVAL_QUERIES:
        query    = sample["query"]
        relevant = sample["relevant"]   # list of function names now

        result    = rag.query(query, k=k)
        chunks    = result.get("chunks", [])
        # ✅ Use chunk name instead of chunk_id for matching
        retrieved = [c.get("name", "") for c in chunks]

        if not retrieved:
            failed.append(query)
            print(f"\n⚠️  No chunks returned for: {query!r}")
            continue

        h = hit_at_k(retrieved, relevant, k)
        r = recall_at_k(retrieved, relevant, k)
        m = mrr(retrieved, relevant)
        n = ndcg_at_k(retrieved, relevant, k)

        hits.append(h)
        recalls.append(r)
        mrrs.append(m)
        ndcgs.append(n)

        results_table.append({"query": query, "hit": h, "recall": r, "mrr": m, "ndcg": n})

        status = "✅" if h else "❌"
        print(f"\n{status} {query!r}")
        print(f"   Retrieved : {retrieved}")
        print(f"   Relevant  : {relevant}")
        print(f"   Hit@{k}: {h}  Recall: {r:.2f}  MRR: {m:.2f}  NDCG: {n:.2f}")

    # ── SUMMARY TABLE ─────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  QUERY-LEVEL SUMMARY")
    print("=" * 65)
    print(f"  {'Query':<48} Hit  MRR")
    print(f"  {'-'*48} ---  ----")
    for r in results_table:
        short_q = r["query"][:46] + ".." if len(r["query"]) > 48 else r["query"]
        status  = "✅" if r["hit"] else "❌"
        print(f"  {status} {short_q:<47} {r['hit']}   {r['mrr']:.2f}")

    # ── FINAL SCORES ──────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  FINAL SCORES")
    print("=" * 65)

    if hits:
        print(f"  Hit@{k}    : {np.mean(hits):.3f}   (1.0 = perfect)")
        print(f"  Recall@{k}  : {np.mean(recalls):.3f}")
        print(f"  MRR       : {np.mean(mrrs):.3f}   (1.0 = always rank-1)")
        print(f"  NDCG@{k}   : {np.mean(ndcgs):.3f}")
        print(f"\n  Evaluated : {len(hits)}/{len(EVAL_QUERIES)} queries")

        avg_hit = np.mean(hits)
        if avg_hit >= 0.9:
            grade = "🟢 Excellent"
        elif avg_hit >= 0.75:
            grade = "🟡 Good"
        elif avg_hit >= 0.5:
            grade = "🟠 Needs improvement"
        else:
            grade = "🔴 Poor — check chunking or embedding model"
        print(f"  Grade     : {grade}")
    else:
        print("  No results — is the index loaded?")

    if failed:
        print(f"\n  ⚠️  {len(failed)} queries returned no chunks:")
        for q in failed:
            print(f"     - {q}")

    print("=" * 65)


if __name__ == "__main__":
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Add parent directory to path so main.py can be found
    PARENT_DIR = os.path.dirname(THIS_DIR)
    if PARENT_DIR not in sys.path:
        sys.path.insert(0, PARENT_DIR)

    from main import CodeRAG

    rag = CodeRAG()
    if not rag.load_index():
        print("❌ No index found — run main.py first to build and save the index")
        sys.exit(1)

    evaluate_rag(rag, k=5)