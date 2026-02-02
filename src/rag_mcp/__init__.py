"""
RAG MCP Server - Semantic search over IR knowledge base.

This package provides an MCP server for semantic search across 22K+
incident response knowledge records from 22 authoritative online sources
plus user-provided documents.

Architecture:
    - 22 online sources (Sigma, MITRE ATT&CK, Atomic Red Team, etc.)
    - User documents via knowledge/ folder (auto-watched)
    - One-time document ingestion with friendly names
    - ChromaDB vector store with BGE embeddings
    - Filesystem safety guardrails (sentinel-based deletion)
    - Network fetch hardening (HTTPS, size limits, retry)

Modules:
    server: MCP server exposing search, list_sources, get_stats tools
    index: ChromaDB and embedding model wrapper
    sources: Online source management (22 authoritative sources)
    ingest: User document ingestion (watched and one-time)
    build: Full index builder
    refresh: Incremental index updates
    status: Index status reporting
    config: Centralized configuration management
    fs_safety: Filesystem safety guardrails
    constants: Project-wide constants
    utils: Shared utility functions

Usage:
    # Run MCP server
    python -m rag_mcp.server

    # Build index (first time or full rebuild)
    python -m rag_mcp.build

    # Incremental update
    python -m rag_mcp.refresh

    # Check status
    python -m rag_mcp.status
"""

__version__ = "2.1.0"

from .index import RAGIndex
from .server import RAGServer
from .config import get_config, Config

__all__ = ["RAGIndex", "RAGServer", "get_config", "Config", "__version__"]
