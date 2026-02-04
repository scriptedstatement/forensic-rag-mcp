# RAG Index Setup Guide

This guide helps you set up the forensic knowledge RAG index. Claude should walk users through these decisions interactively.

---

## Decision Tree

### Question 1: Do you want online sources only, or also add custom content?

**Option A: Online Sources Only (Recommended for most users)**
- 23 authoritative sources with ~22,000 records
- Includes: MITRE ATT&CK, Sigma rules, Atomic Red Team, KAPE, LOLDrivers, and more
- No additional work required - just run the build command

**Option B: Online Sources + Custom Content**
- Everything from Option A, plus your own documents
- Requires extracting your documents to JSONL format
- Good for: SANS posters, books, internal playbooks, CTI reports

---

## Option A: Build with Online Sources Only

**Note:** These commands assume you're in the parent directory containing `forensic-rag-mcp/`. If you're already inside `forensic-rag-mcp/`, skip the `cd` command.

```bash
cd forensic-rag-mcp
source .venv/bin/activate
python -m rag_mcp.build
```

**What this does:**
1. Downloads 23 knowledge sources from GitHub (MITRE, Sigma, etc.)
2. Parses each source into searchable records
3. Augments text with MITRE technique names for better search
4. Creates ChromaDB vector index in `data/chroma/`

**Time:** First build takes 5-15 minutes depending on network speed.

**Verify success:**
```bash
ls data/chroma/
python -m rag_mcp.status
```

---

## Option B: Add Custom Content

### Step 1: Build Online Sources First

Run Option A above to establish the base index.

### Step 2: Understand Supported Formats

| Format | Best For |
|--------|----------|
| `.jsonl` | Structured knowledge (preferred) |
| `.txt` | Plain text documents |
| `.md` | Markdown documents |
| `.json` | Structured data |

**PDFs require extraction** - the RAG system cannot read PDFs directly.

### Step 3: Decide Where to Put Content

```
knowledge/
├── pdfs/           # Source PDFs + extracted JSONL (paired)
│   ├── SANS/       # SANS posters
│   ├── AIR/        # Applied Incident Response materials
│   └── [your-org]/ # Your materials
├── CTI/            # Curated threat intel (JSONL only)
└── training/       # Training materials (JSONL only)
```

**Rule:** JSONL files go next to their source PDFs with the same basename.

### Step 4: Extract PDFs to JSONL

PDF extraction guidelines:

- **Extract verbatim** - copy text exactly as written, no interpretation
- **One concept per record** - each tool, technique, or fact gets its own record
- **Preserve source attribution** - always track where content came from
- **Use the correct schema:**

```json
{
  "text": "The extracted content - verbatim from source",
  "metadata": {
    "source": "Source_Identifier",
    "title": "Descriptive title",
    "category": "dfir|detection|hunting|memory|disk|logs|tools|reference",
    "platform": "windows|linux|macos"
  }
}
```

### Step 5: Refresh the Index

After adding content to `knowledge/`:

```bash
python -m rag_mcp.refresh
```

This incrementally adds new content without re-downloading online sources.

---

## Verification

### Check Index Status

```bash
python -m rag_mcp.status
```

Shows:
- Total records indexed
- Records per source
- Last build/refresh time

### Test a Search

**Note:** Activate the virtual environment first if not already active: `source .venv/bin/activate`

```bash
python -c "
from rag_mcp import RAGIndex
idx = RAGIndex()
idx.load()
results = idx.search('credential dumping', top_k=3)
for r in results:
    print(f'{r[\"score\"]:.2f} - {r[\"metadata\"][\"source\"]}: {r[\"metadata\"][\"title\"]}')
"
```

---

## Maintenance

### Update Online Sources (Incremental)

```bash
python -m rag_mcp.refresh
```

Checks for updates to online sources and re-indexes only changed content. **Use this for routine updates** - faster than a full rebuild.

### Force Full Rebuild

```bash
python -m rag_mcp.build --force-fetch
```

Re-downloads ALL sources and rebuilds from scratch. **Use when:** index is corrupted, major version upgrade, or you want a clean slate.

### Skip Network (Use Cache Only)

```bash
python -m rag_mcp.build --skip-online
```

Rebuilds using only cached source data (useful offline).

---

## Online Sources Reference

| Source | Records | Description |
|--------|---------|-------------|
| sigma | ~3,100 | SigmaHQ Detection Rules |
| mitre_attack | ~2,100 | MITRE ATT&CK Framework |
| atomic | ~1,800 | Atomic Red Team Tests |
| elastic | ~1,500 | Elastic Detection Rules |
| cisa_kev | ~1,500 | CISA Known Exploited Vulnerabilities |
| capec | ~1,500 | MITRE CAPEC Attack Patterns |
| splunk_security | ~1,000 | Splunk Security Content |
| kape | ~800 | KAPE Targets & Modules |
| forensic_artifacts | ~700 | ForensicArtifacts Definitions |
| mbc | ~650 | MITRE MBC Malware Behavior Catalog |
| hijacklibs | ~600 | HijackLibs DLL Database |
| loldrivers | ~500 | LOLDrivers Vulnerable Drivers |
| mitre_d3fend | ~490 | MITRE D3FEND Countermeasures |
| gtfobins | ~450 | GTFOBins (Linux) |
| velociraptor | ~300 | Velociraptor Artifacts |
| hayabusa | ~190 | Hayabusa Detection Rules |
| lolbas | ~130 | LOLBAS Project |
| chainsaw | ~110 | Chainsaw Forensic Rules |
| mitre_car | ~100 | MITRE CAR Analytics |
| stratus_red_team | ~80 | Cloud Attack Techniques |
| mitre_atlas | ~50 | MITRE ATLAS AI/ML Attacks |
| mitre_engage | ~45 | MITRE Engage Adversary Engagement |
| forensic_clarifications | 5 | Authoritative Forensic Clarifications |

---

## Quick Setup Script

For standalone installation, you can use the setup script instead of manual steps:

```bash
./setup.sh
```

This creates the virtual environment and installs dependencies automatically.

---

## Troubleshooting

### "No module named rag_mcp"

Activate the virtual environment:
```bash
source .venv/bin/activate
```

### Build fails with network errors

Try with cached data:
```bash
python -m rag_mcp.build --skip-online
```

### Search returns no results

Check if index exists:
```bash
ls data/chroma/
```

If empty, run the build again.
