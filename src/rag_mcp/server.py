#!/usr/bin/env python3
"""
RAG MCP Server - Semantic search over IR knowledge base.

Exposes the RAG knowledge base (23K+ records from 23 authoritative security
sources) as MCP tools for Claude Code integration.

Tools:
    search: Semantic search with optional filters (source, technique, platform)
    list_sources: Get available knowledge sources
    get_stats: Get index statistics

Usage:
    # Run directly
    python -m rag_mcp.server

    # Or via entry point after install
    rag-mcp

Configuration:
    RAG_INDEX_DIR: Path to ChromaDB index (default: ./data)
    RAG_MODEL_NAME: Embedding model (default: BAAI/bge-base-en-v1.5)

Security:
    - Model allowlist prevents arbitrary model loading
    - Input length limits prevent DoS
    - Internal paths not disclosed in responses
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .index import RAGIndex
from .utils import MAX_TOP_K

logger = logging.getLogger(__name__)


class _StructuredFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def __init__(self, service_name: str = "rag-mcp") -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }
        if record.levelno >= logging.WARNING:
            log_data["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }
        return json.dumps(log_data, default=str)


def _setup_logging(level: int = logging.INFO, json_format: bool = False) -> None:
    """Configure logging with optional JSON format.

    Args:
        level: Logging level
        json_format: Use JSON formatting (set RAG_LOG_FORMAT=json)
    """
    pkg_logger = logging.getLogger("rag_mcp")
    pkg_logger.setLevel(level)
    pkg_logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    if json_format:
        handler.setFormatter(_StructuredFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))
    pkg_logger.addHandler(handler)
    pkg_logger.propagate = False

# Input validation constants
MAX_QUERY_LENGTH = 1000
MAX_FILTER_LENGTH = 100


def _validate_length(value: Any, max_length: int, field: str) -> None:
    """Validate input length to prevent DoS."""
    if value is not None and isinstance(value, str) and len(value) > max_length:
        raise ValueError(f"{field} exceeds maximum length of {max_length}")


class RAGServer:
    """
    MCP Server for RAG knowledge base search.

    Keeps the embedding model and ChromaDB index loaded in memory
    for fast query responses (~50ms).
    """

    def __init__(self) -> None:
        self.server = Server("rag-knowledge")
        self.index = RAGIndex()
        self._register_tools()

    @staticmethod
    def _error_response(error_code: str, message: str) -> list[TextContent]:
        """Format error response consistently."""
        return [TextContent(
            type="text",
            text=json.dumps({"error": error_code, "message": message})
        )]

    def _register_tools(self) -> None:
        """Register MCP tools."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="search",
                    description=(
                        "Semantic search across 23K+ incident response knowledge records. "
                        "Sources include: Sigma rules, MITRE ATT&CK, Atomic Red Team, "
                        "Splunk Security, KAPE, Velociraptor, LOLBAS, GTFOBins, and more. "
                        "Returns ranked results with relevance scores (0-1, higher is better). "
                        "Scores above 0.85 are excellent matches; 0.75-0.84 are good."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": (
                                    "Natural language search query. Examples: "
                                    "'credential dumping detection', 'lateral movement windows', "
                                    "'T1003' (MITRE technique ID)"
                                )
                            },
                            "top_k": {
                                "type": "integer",
                                "description": "Number of results to return (default: 5, max: 50)",
                                "default": 5
                            },
                            "source": {
                                "type": "string",
                                "description": (
                                    "Filter by source (partial/substring match). Examples: "
                                    "'sigma', 'mitre', 'atomic'. Use source_ids for exact matching."
                                )
                            },
                            "source_ids": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Filter by exact source IDs (deterministic). Examples: "
                                    "['sigma', 'mitre_attack'], ['velociraptor', 'kape']. "
                                    "Use list_sources to see valid IDs. Takes precedence over 'source'."
                                )
                            },
                            "technique": {
                                "type": "string",
                                "description": "Filter by MITRE technique ID (e.g., 'T1003', 'T1059.001')"
                            },
                            "platform": {
                                "type": "string",
                                "description": "Filter by platform",
                                "enum": ["windows", "linux", "macos"]
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="list_sources",
                    description=(
                        "List all available knowledge sources in the RAG index. "
                        "Use this to discover what sources can be used with the 'source' filter."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="get_stats",
                    description="Get RAG index statistics (document count, sources, model info).",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            try:
                if name == "search":
                    result = await self._search(arguments)
                elif name == "list_sources":
                    result = await self._list_sources()
                elif name == "get_stats":
                    result = await self._get_stats()
                else:
                    result = {"error": f"Unknown tool: {name}"}

                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2)
                )]

            except ValueError as e:
                logger.warning(f"Tool {name} validation failed: {e}")
                return self._error_response("validation_error", str(e))
            except Exception as e:
                logger.exception(f"Tool {name} internal error")
                return self._error_response(
                    "internal_error",
                    "An unexpected error occurred. Check server logs."
                )

    async def _search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Execute search tool.

        Args:
            arguments: Tool arguments (query, top_k, source, technique, platform)

        Returns:
            Search results with status, query echo, and ranked matches
        """
        query = arguments.get("query", "")
        top_k = arguments.get("top_k", 5)
        source = arguments.get("source")
        source_ids = arguments.get("source_ids")
        technique = arguments.get("technique")
        platform = arguments.get("platform")

        # Validate inputs
        _validate_length(query, MAX_QUERY_LENGTH, "query")
        _validate_length(source, MAX_FILTER_LENGTH, "source")
        _validate_length(technique, MAX_FILTER_LENGTH, "technique")
        _validate_length(platform, MAX_FILTER_LENGTH, "platform")

        # Validate source_ids if provided
        if source_ids is not None:
            if not isinstance(source_ids, list):
                raise ValueError("source_ids must be a list of strings")
            if len(source_ids) > 20:
                raise ValueError("source_ids cannot contain more than 20 items")
            for sid in source_ids:
                _validate_length(sid, MAX_FILTER_LENGTH, "source_ids item")

        if not query:
            raise ValueError("query is required")

        # Validate top_k is a positive integer
        if not isinstance(top_k, int) or top_k < 1:
            top_k = 5
        elif top_k > MAX_TOP_K:
            top_k = MAX_TOP_K

        # Run search (CPU-bound, so run in thread pool)
        loop = asyncio.get_running_loop()
        search_result = await loop.run_in_executor(
            None,
            lambda: self.index.search(
                query=query,
                top_k=top_k,
                source=source,
                source_ids=source_ids,
                technique=technique,
                platform=platform
            )
        )

        response = {
            "status": "ok",
            "query": query,
            "results": search_result["results"]
        }

        # Add context about filters
        if search_result["source_filter"]:
            if search_result["matched_sources"]:
                response["matched_sources"] = search_result["matched_sources"]
            else:
                response["warning"] = (
                    f"No sources match filter '{source}'. "
                    "Use list_sources tool to see available sources."
                )

        return response

    async def _list_sources(self) -> dict[str, Any]:
        """List available sources."""
        if not self.index.is_loaded:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.index.load)

        return {
            "status": "ok",
            "sources": self.index.available_sources,
            "count": len(self.index.available_sources)
        }

    async def _get_stats(self) -> dict[str, Any]:
        """Get index statistics."""
        loop = asyncio.get_running_loop()
        stats = await loop.run_in_executor(None, self.index.get_stats)
        return {
            "status": "ok",
            **stats
        }

    async def run(self) -> None:
        """Run the MCP server."""
        # Load index at startup
        logger.info("Loading RAG index...")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.index.load)
        logger.info("RAG index loaded, starting MCP server...")

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


def main() -> None:
    """Entry point."""
    log_format = os.getenv("RAG_LOG_FORMAT", "text").lower()
    _setup_logging(json_format=(log_format == "json"))
    server = RAGServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
