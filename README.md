<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Intelligent Code Assistance and Checker — README</title>
</head>
<body>

<h1 align="center">🤖 Intelligent Code Assistance and Checker</h1>
<p align="center">
  <em>A sophisticated Python Security Analysis + Retrieval-Augmented Generation (RAG) system that scans code for vulnerabilities, indexes it with AI embeddings, and lets you ask natural-language questions about your codebase.</em>
</p>

<hr>

<h2>✨ Features</h2>

<h3>🔐 Security Analysis</h3>
<ul>
  <li><b>19+ Vulnerability Checks:</b> Covers RCE, SQL injection, command injection, hardcoded secrets, weak crypto, insecure deserialization, path traversal, XXE, SSRF, privilege escalation, timing attacks, and more</li>
  <li><b>Dual-Scanner Pipeline:</b> Custom AST-based SecurityChecker combined with Bandit for comprehensive coverage</li>
  <li><b>Severity Classification:</b> Issues categorized as HIGH (exploitable) or MEDIUM (risky practices) with deduplication via MergeFilter</li>
  <li><b>Code Snippet Context:</b> Each finding includes the surrounding code for immediate understanding</li>
  <li><b>Fix Suggestions:</b> Every vulnerability comes with an actionable remediation tip</li>
</ul>

<h3>💬 Intelligent RAG Q&amp;A</h3>
<ul>
  <li><b>AI-Powered Answers</b> using Google's Gemini API with context-aware retrieval</li>
  <li><b>Hybrid Retrieval:</b> Combines FAISS semantic search with BM25 keyword ranking — ratio adapts per query type</li>
  <li><b>Single AST Parse:</b> CodeAnalyzer runs once; result is reused by the chunker — no redundant re-parsing</li>
  <li><b>Call-Graph Query Expansion:</b> Automatically expands queries using actual function call relationships in your code</li>
  <li><b>Rich Metadata Indexing:</b> Type hints, decorators, docstrings, <code>__init__</code> methods, and nested functions are all indexed and used during re-ranking</li>
  <li><b>Adaptive Hybrid Ratio:</b> Definition queries use 50/50 semantic/BM25; flow queries favor 80/20 semantic</li>
</ul>

<h3>🗂️ Session Management</h3>
<ul>
  <li>Multiple Analysis Sessions per user stored in MySQL</li>
  <li>Automatic session history saving with full chat replay</li>
  <li>Switch easily between different code sessions from the sidebar</li>
  <li>Rename and delete sessions with confirmation</li>
  <li>Duplicate code detection — re-uploads update title instead of creating a new row</li>
</ul>

<h3>🎨 User Interface</h3>
<ul>
  <li>Modern dark-themed interface with skeleton loading states</li>
  <li>Donut chart showing findings by severity + Top Vulnerabilities bar chart</li>
  <li>Filter &amp; search panel — filter by HIGH / MEDIUM, search by rule name or message</li>
  <li>Expandable issue cards with code snippets and fix suggestions</li>
  <li>Real-time typing indicator and RAG suggestion chips</li>
  <li>Responsive sidebar with session history and floating toggle</li>
</ul>

<hr>

<h2>🛠️ Technology Stack</h2>

<h3>Backend</h3>
<ul>
  <li><b>FastAPI</b> – Web framework with async support and auto-generated API docs</li>
  <li><b>MySQL</b> – Persistent session, findings, chat, and chunk storage</li>
  <li><b>Sentence Transformers</b> – Text embeddings (<code>all-mpnet-base-v2</code>)</li>
  <li><b>FAISS</b> – Vector similarity search for semantic retrieval</li>
  <li><b>BM25</b> – Custom keyword-based ranker for hybrid retrieval</li>
  <li><b>Google Gemini API</b> – LLM for natural-language answer generation</li>
  <li><b>Bandit</b> – External Python security scanner</li>
</ul>

<h3>Frontend</h3>
<ul>
  <li>HTML5 / CSS3 – Modern responsive dark design</li>
  <li>Vanilla JavaScript – No framework dependencies</li>
  <li>CSS Grid &amp; Flexbox – Layout management</li>
  <li>Canvas API – Donut chart for severity visualization</li>
</ul>

<h3>Analysis Libraries</h3>
<ul>
  <li><code>ast</code> – Python AST parsing (single parse, result shared across pipeline)</li>
  <li><code>difflib</code> – Fuzzy matching in MetadataIndex (replaces false-positive-prone character overlap)</li>
  <li><code>NLTK</code> – Stopword filtering for keyword extraction</li>
  <li><code>numpy</code> – Vector operations for FAISS</li>
  <li><code>mysql-connector-python</code> – Database connectivity</li>
</ul>

<hr>

<h2>📋 Prerequisites</h2>
<ul>
  <li>Python 3.8+</li>
  <li>MySQL Server 8.0+</li>
  <li>Google Gemini API Key</li>
  <li>Bandit (<code>pip install bandit</code>) for external security scanning</li>
</ul>

<hr>

<h2>🚀 Installation</h2>

<ol>
  <li><b>Database Setup</b><br>
    Create the MySQL database and run the provided SQL schema to set up:
    <ul>
      <li><code>sessions</code> — stores each analysis run with title, code hash, and severity counts</li>
      <li><code>security_findings</code> — individual vulnerability findings per session (CASCADE)</li>
      <li><code>chat_messages</code> — full Q&amp;A conversation history (CASCADE)</li>
      <li><code>code_chunks</code> — RAG chunk texts with line ranges (CASCADE)</li>
      <li><code>analysis_cache</code> — optional query response cache</li>
    </ul>
  </li>

  <li><b>Python Dependencies</b><br>
    Install required packages:
    <ul>
      <li>FastAPI, uvicorn</li>
      <li>mysql-connector-python</li>
      <li>sentence-transformers, faiss-cpu, numpy</li>
      <li>nltk, requests</li>
      <li>bandit</li>
    </ul>
  </li>

  <li><b>Configuration</b><br>
    Set the following environment variables or update <code>db.py</code> / <code>llm_engine.py</code>:
    <ul>
      <li><code>DB_HOST</code>, <code>DB_PORT</code>, <code>DB_USER</code>, <code>DB_PASSWORD</code>, <code>DB_NAME</code></li>
      <li><code>GEMINI_API_KEY</code> — your Google Gemini API key</li>
    </ul>
  </li>

  <li><b>Start the Server</b><br>
    <pre>python -m uvicorn app:app --host 0.0.0.0 --port 8080 --reload</pre>
    The browser opens automatically at <code>http://localhost:8080</code>.
  </li>
</ol>

<hr>

<h2>🎯 Usage</h2>
<ol>
  <li>Open the web app in your browser</li>
  <li>Enter a <b>Session Title</b> (e.g. "Auth module review")</li>
  <li>Drop or browse to upload your <code>.py</code> file</li>
  <li>Click <b>Run Analysis</b> — security results appear immediately</li>
  <li>Switch to the <b>RAG Q&amp;A</b> tab and ask questions about your code</li>
  <li>Reload anytime — all sessions, findings, and chats persist in MySQL</li>
</ol>

<h3>Security Panel</h3>
<ul>
  <li>Summary cards for HIGH, MEDIUM, and TOTAL findings</li>
  <li>Donut chart (severity split) + Top Vulnerabilities bar chart</li>
  <li>Filter by severity or search by rule/message text</li>
  <li>Expandable issue cards with description, fix suggestion, and code snippet</li>
</ul>

<h3>RAG Q&amp;A Panel</h3>
<ul>
  <li>Suggestion chips for common questions ("What security issues exist?", "List all functions", etc.)</li>
  <li>Supports natural-language queries about functions, classes, flows, dependencies</li>
  <li>Each answer shows query type, chunks used, and retrieval time</li>
  <li>Full conversation history replayed when loading a past session</li>
</ul>

<hr>

<h2>🔧 API Endpoints</h2>

<ul>
  <li><b>POST</b> <code>/api/analyze</code> — Run security analysis + build RAG index for uploaded code</li>
  <li><b>POST</b> <code>/api/query</code> — Answer a natural-language question using the session's RAG index</li>
  <li><b>GET</b> <code>/api/sessions</code> — List all past sessions (newest first)</li>
  <li><b>GET</b> <code>/api/sessions/{id}</code> — Load full session data including security report and chat history</li>
  <li><b>POST</b> <code>/api/sessions/{id}/rename</code> — Rename a session</li>
  <li><b>POST</b> <code>/api/sessions/{id}/delete</code> — Delete session and all related data (CASCADE)</li>
</ul>

<hr>

<h2>📁 Project Structure</h2>
<ul>
  <li><code>app.py</code> — FastAPI entry point with all route definitions and lifespan management</li>
  <li><code>backend.py</code> — Business logic: analysis orchestration, per-session RAG store, DB wrappers</li>
  <li><code>main.py</code> — Unified pipeline: Security Analyzer + CodeRAG with interactive CLI mode</li>
  <li><code>db.py</code> — MySQL helper: save/load sessions, findings, chat messages, and chunks</li>
  <li><code>security_analysis/</code>
    <ul>
      <li><code>astengine.py</code> — Shared AST traversal utilities and Finding dataclass</li>
      <li><code>security.py</code> — SecurityChecker with 19+ vulnerability detectors</li>
      <li><code>tools.py</code> — BanditRunner wrapper</li>
      <li><code>merge_filter.py</code> — MergeFilter: deduplication, normalization, severity assignment</li>
    </ul>
  </li>
  <li><code>Rag/</code>
    <ul>
      <li><code>chunk_and_index.py</code> — CodeAnalyzer, PythonChunker, MetadataIndex, BM25</li>
      <li><code>retrieval_engine.py</code> — QuestionRouter, QuestionType, query expansion</li>
      <li><code>llm_engine.py</code> — Gemini API call, prompt construction, answer generation</li>
    </ul>
  </li>
  <li><code>index.html</code> — Full frontend (single-file: HTML + CSS + JS)</li>
  <li><code>schema.sql</code> — MySQL schema for all tables</li>
</ul>

<hr>

<h2>⚙️ Configuration Options</h2>
<ul>
  <li><b>Database Settings:</b> Configure via environment variables <code>DB_HOST</code>, <code>DB_PORT</code>, <code>DB_USER</code>, <code>DB_PASSWORD</code>, <code>DB_NAME</code></li>
  <li><b>API Configuration:</b> Set <code>GEMINI_API_KEY</code> as environment variable or in <code>llm_engine.py</code></li>
  <li><b>Chunking Settings:</b> Adjust <code>CHUNK_SIZE_MIN</code>, <code>CHUNK_SIZE_MAX</code>, <code>CHUNK_OVERLAP</code>, <code>FUNCTION_SPLIT_THRESHOLD</code> in <code>chunk_and_index.py</code></li>
  <li><b>Retrieval Settings:</b> Tune <code>DEFAULT_METADATA_BOOST</code> weights and <code>HYBRID_RATIOS</code> per query type in <code>retrieval_engine.py</code></li>
  <li><b>Embedding Model:</b> Change <code>EMBEDDING_MODEL</code> in <code>main.py</code> (default: <code>all-mpnet-base-v2</code>)</li>
</ul>

<hr>

<h2>🐛 Troubleshooting</h2>
<ul>
  <li><b>Database Connection Errors:</b> Check MySQL service is running and credentials match <code>DB_CONFIG</code> in <code>db.py</code></li>
  <li><b>Bandit Not Found:</b> Run <code>pip install bandit</code> in the same Python environment used by uvicorn</li>
  <li><b>Gemini API Errors:</b> Validate your API key; 503 errors are retried automatically up to 3 times</li>
  <li><b>FAISS / numpy Missing:</b> Run <code>pip install faiss-cpu numpy</code></li>
  <li><b>Sentence Transformers Slow:</b> First run downloads the model — subsequent runs use the local cache</li>
  <li><b>Stale RAG Index:</b> Indexes built before <code>enhanced_v4</code> may have truncated chunks — re-analyze the file to rebuild</li>
</ul>

<hr>

<h2>🔒 Security Features</h2>
<ul>
  <li>Parameterized MySQL queries throughout — no SQL injection in the application itself</li>
  <li>Code hash deduplication to avoid redundant processing</li>
  <li>File type validation — only <code>.py</code> files accepted for upload</li>
  <li>Per-session RAG isolation — no cross-session data leakage via the in-memory store</li>
  <li>ON DELETE CASCADE ensures all child data (findings, chat, chunks) is removed with a session</li>
  <li>Gemini API key loaded from environment variable — never hardcoded in production</li>
</ul>

<hr>

<h3 align="center">🚀 Built by  using FastAPI, FAISS, BM25, API keys etc</h3>

</body>
</html>
