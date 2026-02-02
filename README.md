# RAG-MCP: Incident Response Knowledge Server

MCP server providing semantic search over 22K+ incident response knowledge records from 22 authoritative security sources.

## Quick Start

```bash
# Install dependencies
pip install -e .

# Build the index (fetches online sources, ~5 minutes first time)
python -m rag_mcp.build

# Check status
python -m rag_mcp.status

# Run MCP server (for Claude Code integration)
python -m rag_mcp.server
```

## Features

- **22 Online Sources**: Auto-synced from authoritative security repositories
- **Semantic Search**: BGE embeddings with ChromaDB vector store
- **MCP Integration**: Tools for Claude Code (search, list_sources, get_stats)
- **User Documents**: Add your own knowledge via watched folder or one-time ingest
- **Incremental Updates**: Fast refresh without full rebuild
- **Filesystem Safety**: Sentinel-based deletion guards prevent accidental data loss
- **Network Hardening**: HTTPS-only, size limits, retry with backoff, SSRF protection
- **Exact Source Filtering**: Deterministic `source_ids` filter for reliable results

## Online Sources

| Source | Description | Records |
|--------|-------------|---------|
| sigma | SigmaHQ Detection Rules | ~3,100 |
| mitre_attack | MITRE ATT&CK (techniques, groups, malware, campaigns, mitigations) | ~2,100 |
| atomic | Atomic Red Team Tests | ~1,800 |
| elastic | Elastic Detection Rules | ~1,500 |
| cisa_kev | CISA Known Exploited Vulnerabilities | ~1,500 |
| capec | MITRE CAPEC Attack Patterns | ~1,500 |
| splunk_security | Splunk Security Content | ~1,000 |
| kape | KAPE Targets & Modules | ~800 |
| forensic_artifacts | ForensicArtifacts Definitions | ~700 |
| hijacklibs | DLL Hijacking Database | ~600 |
| loldrivers | LOLDrivers Vulnerable Driver Database | ~500 |
| mitre_d3fend | MITRE D3FEND Countermeasures | ~490 |
| gtfobins | GTFOBins (Linux) | ~450 |
| velociraptor | Velociraptor Artifacts | ~300 |
| lolbas | LOLBAS Project | ~130 |
| mitre_car | MITRE CAR Analytics | ~100 |
| stratus_red_team | Cloud Attack Techniques | ~80 |
| mbc | MITRE MBC Malware Behavior Catalog | ~650 |
| mitre_atlas | MITRE ATLAS AI/ML Attack Framework | ~50 |
| chainsaw | Chainsaw Forensic Detection Rules | ~110 |
| hayabusa | Hayabusa Built-in Detection Rules | ~190 |
| forensic_clarifications | Authoritative Forensic Artifact Clarifications | 5 |

## Commands

### Build Index

```bash
# Full build (fetch all sources)
python -m rag_mcp.build

# Use cached sources only (offline mode)
python -m rag_mcp.build --skip-online

# Force re-fetch all sources
python -m rag_mcp.build --force-fetch

# Preview what would be built
python -m rag_mcp.build --dry-run
```

### Refresh Index

```bash
# Check for updates and apply
python -m rag_mcp.refresh

# Check only (don't apply)
python -m rag_mcp.refresh --check-only

# Refresh specific source
python -m rag_mcp.refresh --source sigma
```

### Check Status

```bash
# Show status
python -m rag_mcp.status

# JSON output
python -m rag_mcp.status --json

# Skip update checks (faster)
python -m rag_mcp.status --no-check
```

## User Documents

### Watched Documents (knowledge/ folder)

Place files in `knowledge/` - they're automatically indexed on build/refresh:

```
knowledge/
├── my-playbook.md      # Markdown
├── ioc-list.txt        # Plain text
└── detections.jsonl    # JSONL records
```

Supported formats: `.txt`, `.md`, `.json`, `.jsonl`

### One-Time Ingestion

For sensitive documents you don't want to keep on disk:

```bash
# Ingest with friendly name
python -m rag_mcp.ingest /path/to/doc.txt --name "my-doc"

# List ingested documents
python -m rag_mcp.ingest --list

# Remove specific document
python -m rag_mcp.ingest --remove "my-doc"

# Remove all ingested
python -m rag_mcp.ingest --remove-all
```

## MCP Tools

When running as MCP server, exposes these tools:

| Tool | Description |
|------|-------------|
| `search` | Semantic search with optional filters |
| `list_sources` | List available knowledge sources |
| `get_stats` | Get index statistics |

### Search Filters

```python
# Filter by source
search(query="credential dumping", source="sigma")

# Filter by MITRE technique
search(query="persistence", technique="T1053")

# Filter by platform
search(query="privilege escalation", platform="windows")
```

## MCP Configuration

Add to your MCP configuration (e.g., `.claude/mcp.json`):

```json
{
  "mcpServers": {
    "rag-knowledge": {
      "command": "/path/to/rag-mcp/venv/bin/python",
      "args": ["-m", "rag_mcp.server"],
      "cwd": "/path/to/rag-mcp",
      "env": {
        "PYTHONPATH": "/path/to/rag-mcp/src"
      }
    }
  }
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RAG_INDEX_DIR` | `./data` | ChromaDB location |
| `RAG_KNOWLEDGE_DIR` | `./knowledge` | User documents |
| `RAG_MODEL_NAME` | `BAAI/bge-base-en-v1.5` | Embedding model |
| `GITHUB_TOKEN` | (optional) | Higher API rate limits (see Security section) |
| `RAG_MAX_DOWNLOAD_BYTES` | `26214400` (25MB) | Maximum download size for network fetches |
| `RAG_ALLOW_HTTP` | `false` | Allow HTTP (not recommended; HTTPS enforced by default) |
| `RAG_FETCH_MAX_RETRIES` | `3` | Max retries for transient network failures |

## Project Structure

```
rag-mcp/
├── src/rag_mcp/
│   ├── server.py      # MCP server
│   ├── index.py       # Search engine wrapper
│   ├── sources.py     # Online source management (22 sources)
│   ├── ingest.py      # User document processing
│   ├── build.py       # Full index builder
│   ├── refresh.py     # Incremental updates
│   ├── status.py      # Status reporting
│   ├── config.py      # Centralized configuration management
│   ├── fs_safety.py   # Filesystem safety guardrails
│   ├── constants.py   # Project-wide constants
│   └── utils.py       # Shared utilities
├── data/              # Built index (gitignored, users rebuild)
│   ├── chroma/        # ChromaDB vector store
│   ├── sources/       # Cached online source JSONL
│   └── *.json         # State files
├── knowledge/         # User documents - .txt, .md, .json, .jsonl (watched folder)
└── tests/             # Test suite
```

## Score Interpretation

| Score | Quality | Action |
|-------|---------|--------|
| 0.85+ | Excellent | High confidence match |
| 0.75-0.84 | Good | Relevant result |
| 0.65-0.74 | Fair | May be tangential |
| < 0.65 | Weak | Likely not relevant |

## Query Analysis and Tuning

The system includes tools for monitoring query quality and tuning thresholds based on actual usage patterns.

### Logging Setup

**Query logging is OFF by default** for privacy. Query text is logged verbatim, which may include sensitive search terms. Only enable logging if you understand the privacy implications.

**Privacy Considerations:**
- Query logs contain the exact text users search for
- In regulated environments (HIPAA, SOX, etc.), consider encrypting log files at rest
- Ensure log file permissions restrict access appropriately

To enable query logging, you must explicitly add handlers:

```python
# In your logging configuration
import logging

# Create handlers FIRST
metrics_handler = logging.FileHandler("logs/query_metrics.log")
attention_handler = logging.FileHandler("logs/attention.log")

# Get loggers and add handlers (this enables logging)
metrics_logger = logging.getLogger("rag_mcp.query_metrics")
metrics_logger.setLevel(logging.INFO)
metrics_logger.addHandler(metrics_handler)
metrics_logger.propagate = True  # Enable propagation if you want console output too

attention_logger = logging.getLogger("rag_mcp.attention")
attention_logger.setLevel(logging.WARNING)
attention_logger.addHandler(attention_handler)
attention_logger.propagate = True
```

### Analyze and Tune

Run the analysis tool periodically to review query performance and adjust thresholds:

```bash
# Full interactive workflow (analyze, recommend, approve)
python -m rag_mcp.analyze_queries

# Just view report without making changes
python -m rag_mcp.analyze_queries --report-only

# Analyze last 7 days only
python -m rag_mcp.analyze_queries --since 7d

# Set approver name for audit trail
python -m rag_mcp.analyze_queries --approver "your-name"

# Export analysis to JSON
python -m rag_mcp.analyze_queries --export analysis.json
```

### Interactive Workflow

The tool is designed for both human operators and AI agents:

1. **Analysis**: Reads query logs and computes statistics
2. **Report**: Shows query type breakdown, attention issues, content gaps
3. **Recommendations**: Generates specific tuning suggestions with rationale
4. **Approval**: Prompts for Y/N approval on each recommendation
5. **Apply**: Saves approved changes to `data/tuning_config.json`
6. **Audit Trail**: Records who approved each change and why

Example session:
```
$ python -m rag_mcp.analyze_queries
Analyzing query logs...

======================================================================
RAG QUERY ANALYSIS REPORT
======================================================================
Period: 2026-01-15 08:00 to 2026-02-02 10:30
Total queries analyzed: 1523

----------------------------------------------------------------------
QUERY TYPE STATISTICS
----------------------------------------------------------------------
Type              Count      Avg      P25      Min     Low%
----------------------------------------------------------------------
general             892    0.712    0.645    0.412     8.2%
mitre_id            456    0.789    0.715    0.521     3.1%
detection           175    0.698    0.621    0.445    12.0%

======================================================================
RECOMMENDATIONS
======================================================================

[1] Lower detection threshold from 0.55 to 0.52
    Type: threshold
    Confidence: medium
    Affected queries: 21
    Rationale: 12.0% of 175 queries scored below current threshold.

----------------------------------------------------------------------
APPROVAL REQUIRED
----------------------------------------------------------------------
[1/1] Lower detection threshold from 0.55 to 0.52
  Rationale: 12.0% of 175 queries scored below current threshold.
  Change: 0.55 -> 0.52
  Confidence: medium

  Approve? [Y/N/Q]: y
  -> APPROVED

1 change(s) applied and saved to tuning_config.json
```

### What Gets Flagged

The attention logger flags these conditions for review:

| Condition | Meaning | Action |
|-----------|---------|--------|
| `zero_results` | No matches found | Content gap - add relevant data |
| `low_score:<score>` | Top score below 0.50 | Poor semantic match |
| `unknown_mitre_ids:<ids>` | MITRE ID not in lookup | Data refresh needed |
| `weak_mitre_match:<score>` | MITRE query scored below 0.60 | Check augmentation |

### Tuning Configuration

Approved changes are saved to `data/tuning_config.json`:

```json
{
  "version": "1.0",
  "thresholds": {
    "general": 0.50,
    "mitre_id": 0.55,
    "detection": 0.52,
    "forensic": 0.55
  },
  "source_boosts": {
    "forensic_clarifications": 1.15
  },
  "keyword_boost": 1.15,
  "last_modified": "2026-02-02T10:45:00",
  "last_modified_by": "analyst",
  "modification_history": [...]
}
```

The index automatically loads this configuration on startup.

### Safe Bounds

Automated recommendations stay within safe limits:
- Thresholds: 0.40 - 0.70 (never too permissive or restrictive)
- Boosts: 1.0 - 1.30 (maximum 30% boost)

### Audit Trail

The tuning configuration maintains a modification history for accountability:
- Maximum 100 entries retained in `tuning_config.json`
- When limit is exceeded, old entries are logged before removal
- Each entry records: timestamp, parameter, old/new values, approver, reason

For long-term audit retention, configure logging to capture `rag_mcp.tuning_config` INFO messages to a persistent log aggregator.

## Security

### Filesystem Safety

The build system uses sentinel-based deletion guards to prevent accidental data loss:

- Managed directories contain a `.rag_mcp_managed` sentinel file
- **All deletions** go through `safe_rmtree()` with full safety checks
- Sentinel requirement can be relaxed for first-time setup, but all other guards remain
- Forbidden paths (/, /home, /root, etc.) are blocked regardless of sentinel
- Minimum depth checks prevent deleting top-level directories
- Root containment ensures deletions stay within project boundaries

### Network Hardening

All network fetches include multiple security layers:

| Protection | Description |
|------------|-------------|
| **HTTPS-only** | HTTP URLs rejected by default (configurable) |
| **Size limits** | Downloads capped at 25MB to prevent resource exhaustion |
| **Host allowlist** | Only approved hosts (github.com, raw.githubusercontent.com, etc.) |
| **IP literal blocking** | Direct IP addresses blocked to prevent SSRF |
| **Redirect validation** | Redirect targets must be on allowlist |
| **Retry with backoff** | Transient failures (429, 5xx, timeouts) retried with exponential backoff |

### GITHUB_TOKEN Permissions

If you set `GITHUB_TOKEN` for higher API rate limits, use minimal permissions:

```bash
# Create a Fine-grained Personal Access Token with:
# - Public Repositories (read-only) - NO other permissions needed
# - No access to private repositories
# - No write permissions

export GITHUB_TOKEN="github_pat_..."
```

The token is only used for:
- Checking latest commit SHAs (version detection)
- Checking latest release tags
- Cloning public repositories

**Never use tokens with write access or private repo access.**

### Dependency Scanning

Periodically scan dependencies for known vulnerabilities:

```bash
# Install pip-audit
pip install pip-audit

# Scan for vulnerabilities
pip-audit

# Or with requirements file
pip-audit -r requirements.txt
```

Consider adding to CI/CD pipelines for automated scanning.

### Network Exposure Warning

The MCP server uses **stdio transport only** (stdin/stdout). This is secure for local use.

**Do NOT expose this server over a network** without additional hardening:
- No authentication is implemented
- No rate limiting on queries
- No TLS/encryption

If network access is required, place behind an authenticated reverse proxy with rate limiting.

## Requirements

- Python 3.10+
- ~2GB disk space (model + index)
- ~1GB RAM for search operations

## Acknowledgments

Development assisted by Claude (Anthropic).

## License

MIT
