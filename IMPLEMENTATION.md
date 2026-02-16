# RAG MCP - Implementation Guide

Technical details for developers and contributors.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RAG MCP Server                                    │
│                                                                             │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────┐  │
│  │  MCP Server  │────│    RAGIndex      │────│      ChromaDB            │  │
│  │  (server.py) │    │    (index.py)    │    │   (data/chroma/)         │  │
│  │              │    │                  │    │                          │  │
│  │  - search    │    │  - load()        │    │  Collection: ir_knowledge│  │
│  │  - list_src  │    │  - search()      │    │  23 online sources        │  │
│  │  - get_stats │    │  - get_stats()   │    │  23 online sources       │  │
│  └──────────────┘    └──────────────────┘    └──────────────────────────┘  │
│                              │                                              │
│                    ┌─────────▼─────────┐                                   │
│                    │ SentenceTransformer│                                   │
│                    │ BAAI/bge-base-en  │                                   │
│                    │ (768 dimensions)  │                                   │
│                    └───────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                              ▲
                              │ Build/Refresh
                              │
┌─────────────────────────────┴───────────────────────────────────────────────┐
│                         Knowledge Pipeline                                  │
│                                                                             │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────────────────┐  │
│  │   sources.py   │   │   build.py     │   │       refresh.py           │  │
│  │                │   │                │   │                            │  │
│  │  23 online     │──▶│  Full rebuild  │   │  Incremental updates       │  │
│  │  sources       │   │  (5 min)       │   │  (seconds)                 │  │
│  │                │   │                │   │                            │  │
│  │  - Fetch       │   └────────────────┘   └────────────────────────────┘  │
│  │  - Parse       │                                                        │
│  │  - Cache       │   ┌────────────────┐   ┌────────────────────────────┐  │
│  └────────────────┘   │   ingest.py    │   │       status.py            │  │
│                       │                │   │                            │  │
│                       │  User docs     │   │  Index status reporting    │  │
│                       │  - Watched     │   │                            │  │
│                       │  - Ingested    │   │                            │  │
│                       └────────────────┘   └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### server.py - MCP Server
- Exposes tools: `search`, `list_sources`, `get_stats`
- Input validation (length limits, type checking)
- Async execution with thread pool for CPU-bound operations
- Loads index at startup for fast queries

### index.py - Search Engine
- ChromaDB collection wrapper
- Embedding model management (BGE with model allowlist)
- **Query augmentation**: Expands MITRE IDs with technique names
- **Hybrid search**: Semantic similarity + keyword boosting
- MITRE technique ID detection and boosting
- **Source filtering**: `source` (substring) and `source_ids` (exact match list)
- **Query logging**: Metrics and attention logging for tuning
- Loads configurable thresholds from tuning_config.json

### sources.py - Online Source Management
- 23 source configurations (repo, branch, parser)
- GitHub API integration (commits, releases, feeds)
- Parser functions for each source format (23 parsers)
- State management (versions, sync timestamps)
- **Network hardening**: HTTPS-only, size limits, host allowlist, SSRF protection
- **Retry logic**: Exponential backoff with jitter for transient failures

### ingest.py - User Document Processing
- Format validation (.txt, .md, .json, .jsonl)
- Semantic chunking (respects headers, paragraphs)
- Watched documents (knowledge/ folder)
- One-time ingested documents (friendly names)

### build.py - Full Index Builder
- 5-phase build: online → user docs → ingested → embed → save
- **MITRE text augmentation**: Enriches document text before embedding
- Metadata sanitization for ChromaDB
- State file generation
- **Sentinel creation**: Creates `.rag_mcp_managed` files in managed directories

### refresh.py - Incremental Updates
- Version checking against upstream (commit SHA, release tags)
- Selective source updates
- User document change detection (file hash comparison)
- **JSON structured logging**: Refresh summary logged to `rag_mcp.refresh_summary` for observability

### status.py - Status Reporting
- Index statistics
- Source version/sync status
- Document counts

### config.py - Centralized Configuration
- Single source of truth for all configuration values
- Environment variable loading with validation
- Cached singleton pattern for performance
- Type-safe Config dataclass

### fs_safety.py - Filesystem Safety
- Sentinel-based deletion guards (`.rag_mcp_managed` file required by default)
- `require_sentinel_file=False` mode for first-time setup (all other guards remain active)
- Forbidden path protection (/, /home, /root, etc.)
- Minimum depth checks (MIN_DELETE_DEPTH=3)
- Root containment validation
- Safe directory removal with `safe_rmtree()` - the only approved deletion method

### constants.py - Project Constants
- Project paths (PROJECT_ROOT, DATA_ROOT, KNOWLEDGE_ROOT)
- Sentinel file name (MANAGED_SENTINEL)
- Forbidden paths list
- Depth limits and other safety constants

### utils.py - Shared Utilities
- Metadata sanitization (ChromaDB type requirements)
- File hashing, atomic JSON writes
- **MITRE lookup loading**: Dynamic technique ID → name mapping
- **Text augmentation**: Shared function for build and query time

### tuning_config.py - Configuration Management
- Configurable thresholds per query type
- Source boost multipliers
- Keyword boost setting
- Full audit trail of configuration changes
- Safe bounds enforcement (0.40-0.70 for thresholds)

### analyze_queries.py - Query Analysis Tool
- Parses query metrics and attention logs
- Generates statistics by query type
- Produces recommendations with rationale
- **Interactive approval workflow** for tuning changes
- Exports analysis to JSON for external processing

## Data Flow

### Build Process

```
1. Online Sources (sources.py)
   ├── Fetch from GitHub/feeds
   ├── Parse to JSONL
   └── Cache in data/sources/*.jsonl

2. User Documents (ingest.py)
   ├── Scan knowledge/ folder
   ├── Validate formats
   └── Chunk text content

3. MITRE Lookup (utils.py)
   ├── Load technique mappings from mitre_attack.jsonl
   └── 835 technique ID → name mappings

4. Text Augmentation (build.py)
   ├── Expand MITRE IDs in document text
   └── "Detect T1003" → "Detect T1003 OS Credential Dumping"

5. ChromaDB Index (build.py)
   ├── Load embedding model
   ├── Batch embed augmented text
   ├── Create ir_knowledge collection
   └── Save state files
```

### Search Process

```
1. Query received via MCP
2. Validate inputs (length, types)
3. Load tuning config (thresholds, boosts)
4. Augment query with MITRE technique names
   └── "T1003" → "T1003 OS Credential Dumping"
5. Extract boost terms from query
6. Embed augmented query with BGE model
7. ChromaDB cosine similarity search
8. Apply filters:
   - source: Substring match (e.g., "mitre" matches mitre_attack, mitre_car)
   - source_ids: Exact match list (deterministic filtering)
   - technique: MITRE ATT&CK technique ID
   - platform: Target platform
9. Apply source boosts for authoritative sources
10. Apply keyword boosts (hybrid search)
11. Boost MITRE ID matches if applicable
12. Log query metrics (all queries + attention-worthy)
13. Return ranked results
```

### Query Tuning Process

```
1. Configure logging for rag_mcp.query_metrics and rag_mcp.attention
2. Run queries in production (logs accumulate)
3. Run: python -m rag_mcp.analyze_queries
4. Review statistics and recommendations
5. Approve/reject each recommendation interactively
6. Approved changes saved to data/tuning_config.json
7. Index loads updated config on next query
```

## Source Configurations

Each source is defined in `SOURCES` dict:

```python
SourceConfig(
    name="sigma",                    # Unique identifier
    description="SigmaHQ Rules",     # Human-readable
    source_type="github_commits",    # Version tracking method
    repo="SigmaHQ/sigma",           # GitHub owner/repo
    branch="master",                 # Branch to track
    parser="parse_sigma",            # Parser function name
    paths=["rules/"]                 # Paths to parse within repo
)
```

### Source Types
- `github_commits`: Track latest commit SHA
- `github_releases`: Track latest release tag
- `json_feed`: Track feed version field

### Parser Functions
Each parser takes `(repo_dir, output_path)` and returns record count.
Outputs JSONL with `{text, metadata}` per line.

## Online Sources (23)

| Source | Type | Description |
|--------|------|-------------|
| sigma | github_commits | SigmaHQ Detection Rules (~3,100) |
| mitre_attack | github_releases | ATT&CK techniques, groups, malware (~2,100) |
| atomic | github_commits | Atomic Red Team Tests (~1,800) |
| elastic | github_releases | Elastic Detection Rules (~1,500) |
| cisa_kev | json_feed | Known Exploited Vulnerabilities (~1,500) |
| capec | github_commits | MITRE CAPEC Attack Patterns (~1,500) |
| splunk_security | github_releases | Splunk Security Content (~1,000) |
| kape | github_commits | KAPE Targets & Modules (~800) |
| forensic_artifacts | github_commits | ForensicArtifacts Definitions (~700) |
| mbc | github_commits | MITRE MBC Malware Behavior Catalog (~650) |
| hijacklibs | github_commits | DLL Hijacking Database (~600) |
| loldrivers | github_commits | Vulnerable Driver Database (~500) |
| mitre_d3fend | json_feed | D3FEND Countermeasures (~490) |
| gtfobins | github_commits | GTFOBins (~450) |
| velociraptor | github_commits | Velociraptor Artifacts (~300) |
| hayabusa | github_commits | Hayabusa Built-in Detection Rules (~190) |
| lolbas | github_commits | LOLBAS Project (~130) |
| chainsaw | github_commits | Chainsaw Forensic Detection Rules (~110) |
| mitre_car | github_commits | MITRE CAR Analytics (~100) |
| stratus_red_team | github_releases | Cloud Attack Techniques (~80) |
| mitre_atlas | github_commits | ATLAS AI/ML Attacks (~50) |
| mitre_engage | github_commits | MITRE Engage Adversary Engagement (~45) |
| forensic_clarifications | static | Authoritative Forensic Artifact Clarifications (5) |

## State Files

### sources_state.json
```json
{
  "version": 1,
  "sources": {
    "sigma": {
      "version": "abc123def456",
      "last_sync": "2024-01-31T08:00:00",
      "records": 3101,
      "cache_hash": "sha256:..."
    }
  }
}
```

### user_state.json
```json
{
  "version": 1,
  "files": {
    "my-doc.md": {
      "hash": "sha256:...",
      "records": 5,
      "record_ids": ["user_my-doc_0", ...],
      "processed_at": "2024-01-31T08:00:00"
    }
  }
}
```

### ingested_state.json
```json
{
  "version": 1,
  "documents": {
    "friendly-name": {
      "original_filename": "doc.txt",
      "records": 10,
      "record_ids": ["ingested_friendly-name_0", ...],
      "ingested_at": "2024-01-31T08:00:00"
    }
  }
}
```

### tuning_config.json
```json
{
  "version": "1.0",
  "thresholds": {
    "general": 0.50,
    "mitre_id": 0.55,
    "detection": 0.55,
    "forensic": 0.55
  },
  "source_boosts": {
    "forensic_clarifications": 1.15
  },
  "keyword_boost": 1.15,
  "low_score_threshold": 0.50,
  "weak_mitre_threshold": 0.60,
  "last_modified": "2026-02-02T10:00:00",
  "last_modified_by": "analyst",
  "modification_history": [
    {
      "timestamp": "2026-02-02T10:00:00",
      "parameter": "threshold:detection",
      "old_value": 0.55,
      "new_value": 0.52,
      "approved_by": "analyst",
      "reason": "12% of detection queries below threshold"
    }
  ]
}
```

## ChromaDB Schema

**Collection**: `ir_knowledge`
- **Metric**: Cosine similarity (HNSW)
- **Dimensions**: 768 (BGE model)

**Document Fields**:
- `id`: Unique identifier (e.g., `sigma_rule_123`)
- `text`: Searchable content (max 1500 chars in results)
- `metadata`:
  - `source`: Source identifier
  - `title`: Optional title
  - `mitre_techniques`: Comma-separated technique IDs
  - `platform`: Target platform(s)

## Search Enhancements

### MITRE ID Augmentation
Queries and documents containing MITRE technique IDs are automatically expanded with official technique names before embedding. This dramatically improves search quality for alphanumeric IDs that have no semantic meaning on their own.

**Query time**: "T1003" → "T1003 OS Credential Dumping"
**Index time**: Document text is enriched before embedding

The lookup table is loaded dynamically from `mitre_attack.jsonl` and contains 835 technique mappings. It updates automatically when MITRE data is refreshed.

### Hybrid Search
Combines semantic similarity with exact keyword matching:

1. **Semantic score**: ChromaDB cosine similarity (0-1)
2. **Source boost**: Authoritative sources get multiplied boost (e.g., 1.15x)
3. **Keyword boost**: Results containing query terms get 15% boost (configurable)

Final score = min(1.0, semantic_score × source_boost × keyword_boost)

### Query Logging
Two logging levels for production monitoring. **Both are OFF by default** for privacy (query text is logged verbatim). See README for opt-in instructions.

**rag_mcp.query_metrics (INFO)**
All queries with: query_type, top_score, result_count, augmented flag

**rag_mcp.attention (WARNING)**
Problematic queries flagged for review:
- `zero_results`: No matches found (content gap)
- `low_score:<score>`: Top score below threshold
- `unknown_mitre_ids:<ids>`: MITRE ID not in lookup
- `weak_mitre_match:<score>`: Augmented query still scored poorly

## Security Considerations

### Filesystem Safety (v2.1.0)

Sentinel-based deletion guards prevent accidental data loss:

1. **Sentinel File**: `.rag_mcp_managed` must exist in directory before `safe_rmtree()` can delete it
2. **Unified Deletion**: All deletions go through `safe_rmtree()` - no fallback to naked `shutil.rmtree()`
3. **First-Time Setup**: Sentinel requirement can be relaxed via `require_sentinel_file=False`, but all other safety checks remain active
4. **Forbidden Paths**: /, /home, /root, /etc, /usr, /var blocked regardless of sentinel
5. **Minimum Depth**: Directories must be at least 3 levels deep from root
6. **Root Containment**: Deletions must be within project root boundaries
7. **Build Integration**: `build.py` creates sentinels in managed directories after deletion

### Network Hardening (v2.1.0)

All network fetches in `sources.py` include:

1. **HTTPS-Only**: HTTP URLs rejected by default (configurable via `RAG_ALLOW_HTTP`)
2. **Size Limits**: Downloads capped at 60MB (`RAG_MAX_DOWNLOAD_BYTES`)
3. **Host Allowlist**: Only approved hosts (github.com, raw.githubusercontent.com, etc.)
4. **IP Literal Blocking**: Direct IP addresses blocked to prevent SSRF
5. **Redirect Validation**: Redirect targets validated against host allowlist
6. **Retry with Backoff**: Transient failures (429, 5xx, timeouts) retried with exponential backoff and jitter

### Code-Level Controls

1. **Model Allowlist**: Only approved embedding models can be loaded (`utils.py:ALLOWED_MODELS`)
2. **Input Validation**: Query/filter length limits prevent DoS (`server.py`)
3. **Path Disclosure**: Internal paths not exposed in API responses (`index.py`)
4. **Metadata Sanitization**: Lists/dicts converted to strings for ChromaDB (`utils.py`)
5. **URL Host Allowlist**: SSRF protection for feed fetching (`sources.py`)
6. **Git Parameter Validation**: Repo/branch format validation prevents injection (`sources.py`)
7. **Tuning Bounds**: Automated adjustments stay within safe limits 0.40-0.70 (`analyze_queries.py`)
8. **Query Logging Off by Default**: Privacy protection - logs contain verbatim query text (`index.py`)
9. **Audit Trail Continuity**: Overflow entries logged before truncation, max 100 in config (`tuning_config.py`)
10. **File Size Limits**: 10MB max for user documents prevents memory exhaustion (`ingest.py`)
11. **ID Sanitization**: Alphanumeric-only pattern prevents injection (`ingest.py`)
12. **Atomic File Writes**: Prevents corruption from concurrent access (`utils.py`)

### Operational Security

**GITHUB_TOKEN**: If used, create with minimal permissions:
- Public repositories read-only
- No private repo access
- No write permissions

**Network Exposure**: Server uses stdio only. Do NOT expose over network without:
- Authentication layer
- Rate limiting
- TLS encryption

**Dependency Scanning**: Run `pip-audit` periodically to detect CVEs in dependencies.

**Audit Trail**: Config changes are tracked with 100-entry rolling history. For compliance, capture `rag_mcp.tuning_config` logs to external storage.

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test categories
pytest tests/test_rag_comprehensive.py -v           # Comprehensive tests
pytest tests/test_extended_nlp.py -v                 # Extended NLP tests

# Test search functionality
python -c "
from rag_mcp import RAGIndex
idx = RAGIndex()
idx.load()
print(idx.search('credential dumping', top_k=3))
"

# Test MITRE augmentation
python -c "
from rag_mcp.utils import load_mitre_lookup, augment_text_with_mitre
from pathlib import Path
lookup = load_mitre_lookup(Path('data/sources'))
print(f'Loaded {len(lookup)} techniques')
print(augment_text_with_mitre('Detect T1003 and T1059.001', lookup))
"

# Test query analysis (report only)
python -m rag_mcp.analyze_queries --report-only
```

## Adding a New Source

1. Add `SourceConfig` to `SOURCES` dict in sources.py
2. Create parser function `parse_newname(repo_dir, output_path) -> int`
3. Register parser in `PARSERS` dict
4. Add any new URL hosts to `ALLOWED_URL_HOSTS` if needed
5. Run `python -m rag_mcp.build --force-fetch`

## Performance

| Operation | Time |
|-----------|------|
| First build (all sources) | ~5 minutes |
| Incremental refresh | ~10 seconds |
| Search query | ~50ms |
| Model load | ~5 seconds |

## Query Tuning Workflow

The system supports interactive threshold tuning based on production query patterns:

### 1. Enable Logging
```python
import logging

# Log all queries
logging.getLogger("rag_mcp.query_metrics").setLevel(logging.INFO)
handler = logging.FileHandler("logs/query_metrics.log")
logging.getLogger("rag_mcp.query_metrics").addHandler(handler)

# Log attention-worthy queries
logging.getLogger("rag_mcp.attention").setLevel(logging.WARNING)
handler = logging.FileHandler("logs/attention.log")
logging.getLogger("rag_mcp.attention").addHandler(handler)
```

### 2. Accumulate Query Data
Run the system in production. Logs capture:
- Query type classification (general, mitre_id, detection, forensic)
- Top scores and result counts
- Augmentation effectiveness
- Attention triggers (zero results, low scores, unknown IDs)

### 3. Run Analysis
```bash
python -m rag_mcp.analyze_queries
```

The tool presents:
- Statistics by query type (count, avg, P25, min scores)
- Current configuration
- Attention issues summary
- Content gaps (zero-result queries)
- Specific recommendations with rationale

### 4. Approve Changes
For each recommendation:
- Review description, rationale, and confidence level
- Enter Y to approve, N to skip, Q to quit
- Approved changes are applied to tuning_config.json
- Full audit trail recorded

### 5. Verify
Changes take effect immediately on next query (index reloads config).
Run targeted searches to verify improved behavior.

## Dependencies

- `chromadb`: Vector store
- `sentence-transformers`: Embedding model
- `mcp`: Model Context Protocol
- `pyyaml`: YAML parsing
- `toml`: TOML parsing (Elastic rules)
