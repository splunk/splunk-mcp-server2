from mcp.server.fastmcp import FastMCP, Context
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass
from dotenv import load_dotenv
import asyncio
import os
import sys
import signal
from typing import Optional, List, Dict, Any
from helpers import format_events_as_markdown, format_events_as_csv, format_events_as_summary
from splunk_client import SplunkClient, SplunkAPIError
from guardrails import validate_spl_query, sanitize_output

load_dotenv()

@dataclass
class AppContext:
    """Application context for the server."""
    config: dict
    splunk_client: Optional[SplunkClient] = None

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manages the application lifecycle."""
    # Check if running inside Docker and use appropriate Splunk host
    if os.getenv("RUNNING_INSIDE_DOCKER") == "1":
        splunk_host = os.getenv("SPLUNK_HOST_FOR_DOCKER", "host.docker.internal")
    else:
        splunk_host = os.getenv("SPLUNK_HOST", "localhost")
    
    config = {
        "name": os.getenv("SERVER_NAME"),
        "description": os.getenv("SERVER_DESCRIPTION"),
        "host": os.getenv("HOST"),
        "port": os.getenv("PORT"),
        "transport": os.getenv("TRANSPORT"),
        "log_level": os.getenv("LOG_LEVEL"),
        "splunk_host": splunk_host,
        "splunk_port": int(os.getenv("SPLUNK_PORT", "8089")),
        "splunk_username": os.getenv("SPLUNK_USERNAME"),
        "splunk_password": os.getenv("SPLUNK_PASSWORD"),
        "splunk_token": os.getenv("SPLUNK_TOKEN"),
        "verify_ssl": os.getenv("VERIFY_SSL", "false").lower() == "true",
        "spl_max_events_count": int(os.getenv("SPL_MAX_EVENTS_COUNT", "100000")),
        "spl_risk_tolerance": int(os.getenv("SPL_RISK_TOLERANCE", "75")),
        "spl_safe_timerange": os.getenv("SPL_SAFE_TIMERANGE", "24h"),
        "spl_sanitize_output": os.getenv("SPL_SANITIZE_OUTPUT", "false").lower() == "true"
    }
    
    # Create Splunk client
    splunk_client = SplunkClient(config)
    try:
        await splunk_client.connect()
        yield AppContext(config=config, splunk_client=splunk_client)
    finally:
        await splunk_client.disconnect()

# Initialize FastMCP server
mcp = FastMCP(
    os.getenv("SERVER_NAME", "Splunk MCP"),
    instructions=os.getenv("SERVER_DESCRIPTION", "MCP server for retrieving data from Splunk"),
    lifespan=app_lifespan,
    host=os.getenv("HOST", "0.0.0.0"),
    port=int(os.getenv("PORT", "8050"))
)


@mcp.tool()
async def validate_spl(ctx: Context, query: str) -> Dict[str, Any]:
    """
    Validate an SPL query for potential risks and inefficiencies.
    
    Args:
        query: The SPL query to validate
        
    Returns:
        Dictionary containing:
        - risk_score: Risk score from 0-100
        - risk_message: Explanation of risks found with suggestions
        - risk_tolerance: Current risk tolerance setting
        - would_execute: Whether this query would execute or be blocked
    """
    config = ctx.request_context.lifespan_context.config
    safe_timerange = config.get("spl_safe_timerange", "24h")
    risk_tolerance = config.get("spl_risk_tolerance", 75)
    
    risk_score, risk_message = validate_spl_query(query, safe_timerange)
    
    return {
        "risk_score": risk_score,
        "risk_message": risk_message,
        "risk_tolerance": risk_tolerance,
        "would_execute": risk_score <= risk_tolerance,
        "execution_note": f"Query would be {'executed' if risk_score <= risk_tolerance else 'BLOCKED - no search would be executed and no data would be returned'}"
    }


@mcp.tool()
async def search_oneshot(ctx: Context, query: str, earliest_time: str = "-24h", latest_time: str = "now", max_count: int = 100, output_format: str = "json", risk_tolerance: Optional[int] = None, sanitize_output: Optional[bool] = None) -> Dict[str, Any]:
    """
    Run a oneshot search query in Splunk and return results.
    
    Args:
        query: The Splunk search query (e.g., "index=main | head 10")
        earliest_time: Start time for search (default: -24h)
        latest_time: End time for search (default: now)
        max_count: Maximum number of results to return (default: 100, or SPL_MAX_EVENTS_COUNT from .env, 0 = unlimited)
        output_format: Format for results - json, markdown/md, csv, or summary (default: json)
        risk_tolerance: Override risk tolerance level (default: SPL_RISK_TOLERANCE from .env)
        sanitize_output: Override output sanitization (default: SPL_SANITIZE_OUTPUT from .env)
    
    Returns:
        Dictionary containing search results in the specified format
    """
    if not ctx.request_context.lifespan_context.splunk_client:
        return {"error": "Splunk client not initialized"}
    
    try:
        client = ctx.request_context.lifespan_context.splunk_client
        config = ctx.request_context.lifespan_context.config
        
        # Get risk tolerance and sanitization settings
        if risk_tolerance is None:
            risk_tolerance = config.get("spl_risk_tolerance", 75)
        if sanitize_output is None:
            sanitize_output = config.get("spl_sanitize_output", False)
        
        # Validate query if risk_tolerance < 100
        if risk_tolerance < 100:
            safe_timerange = config.get("spl_safe_timerange", "24h")
            risk_score, risk_message = validate_spl_query(query, safe_timerange)
            
            if risk_score > risk_tolerance:
                return {
                    "error": f"Query exceeds risk tolerance ({risk_score} > {risk_tolerance}). No search was executed and no data was returned.",
                    "risk_score": risk_score,
                    "risk_tolerance": risk_tolerance,
                    "risk_message": risk_message,
                    "search_executed": False,
                    "data_returned": None
                }
        
        # Use configured spl_max_events_count if max_count is default (100)
        if max_count == 100:
            max_count = config.get("spl_max_events_count", 100000)
        
        # Execute search using client
        events = await client.search_oneshot(query, earliest_time, latest_time, max_count)
        
        # Sanitize output if requested
        if sanitize_output:
            from guardrails import sanitize_output as sanitize_fn
            events = sanitize_fn(events)
        
        # Format results based on output_format
        # Handle synonyms
        if output_format == "md":
            output_format = "markdown"
            
        if output_format == "json":
            return {
                "query": query,
                "event_count": len(events),
                "events": events,
                "search_params": {
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "max_count": max_count
                }
            }
        elif output_format == "markdown":
            return {
                "query": query,
                "event_count": len(events),
                "format": "markdown",
                "content": format_events_as_markdown(events, query),
                "search_params": {
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "max_count": max_count
                }
            }
        elif output_format == "csv":
            return {
                "query": query,
                "event_count": len(events),
                "format": "csv",
                "content": format_events_as_csv(events, query),
                "search_params": {
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "max_count": max_count
                }
            }
        elif output_format == "summary":
            return {
                "query": query,
                "event_count": len(events),
                "format": "summary",
                "content": format_events_as_summary(events, query, len(events)),
                "search_params": {
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "max_count": max_count
                }
            }
        else:
            return {"error": f"Invalid output_format: {output_format}. Must be one of: json, markdown (or md), csv, summary"}
        
    except SplunkAPIError as e:
        return {"error": str(e), "details": e.details}
    except Exception as e:
        return {"error": f"Search failed: {str(e)}"}

@mcp.tool()
async def search_export(ctx: Context, query: str, earliest_time: str = "-24h", latest_time: str = "now", max_count: int = 100, output_format: str = "json", risk_tolerance: Optional[int] = None, sanitize_output: Optional[bool] = None) -> Dict[str, Any]:
    """
    Run an export search query in Splunk that streams results immediately.
    
    Args:
        query: The Splunk search query
        earliest_time: Start time for search (default: -24h)
        latest_time: End time for search (default: now)
        max_count: Maximum number of results to return (default: 100, or SPL_MAX_EVENTS_COUNT from .env, 0 = unlimited)
        output_format: Format for results - json, markdown/md, csv, or summary (default: json)
        risk_tolerance: Override risk tolerance level (default: SPL_RISK_TOLERANCE from .env)
        sanitize_output: Override output sanitization (default: SPL_SANITIZE_OUTPUT from .env)
    
    Returns:
        Dictionary containing search results in the specified format
    """
    if not ctx.request_context.lifespan_context.splunk_client:
        return {"error": "Splunk client not initialized"}
    
    try:
        client = ctx.request_context.lifespan_context.splunk_client
        config = ctx.request_context.lifespan_context.config
        
        # Get risk tolerance and sanitization settings
        if risk_tolerance is None:
            risk_tolerance = config.get("spl_risk_tolerance", 75)
        if sanitize_output is None:
            sanitize_output = config.get("spl_sanitize_output", False)
        
        # Validate query if risk_tolerance < 100
        if risk_tolerance < 100:
            safe_timerange = config.get("spl_safe_timerange", "24h")
            risk_score, risk_message = validate_spl_query(query, safe_timerange)
            
            if risk_score > risk_tolerance:
                return {
                    "error": f"Query exceeds risk tolerance ({risk_score} > {risk_tolerance}). No search was executed and no data was returned.",
                    "risk_score": risk_score,
                    "risk_tolerance": risk_tolerance,
                    "risk_message": risk_message,
                    "search_executed": False,
                    "data_returned": None
                }
        
        # Use configured spl_max_events_count if max_count is default (100)
        if max_count == 100:
            max_count = config.get("spl_max_events_count", 100000)
        
        # Execute export search using client
        events = await client.search_export(query, earliest_time, latest_time, max_count)
        
        # Sanitize output if requested
        if sanitize_output:
            from guardrails import sanitize_output as sanitize_fn
            events = sanitize_fn(events)
        
        # Format results based on output_format
        # Handle synonyms
        if output_format == "md":
            output_format = "markdown"
            
        if output_format == "json":
            return {
                "query": query,
                "event_count": len(events),
                "events": events,
                "is_preview": False
            }
        elif output_format == "markdown":
            return {
                "query": query,
                "event_count": len(events),
                "format": "markdown",
                "content": format_events_as_markdown(events, query),
                "is_preview": False
            }
        elif output_format == "csv":
            return {
                "query": query,
                "event_count": len(events),
                "format": "csv",
                "content": format_events_as_csv(events, query),
                "is_preview": False
            }
        elif output_format == "summary":
            return {
                "query": query,
                "event_count": len(events),
                "format": "summary",
                "content": format_events_as_summary(events, query, len(events)),
                "is_preview": False
            }
        else:
            return {"error": f"Invalid output_format: {output_format}. Must be one of: json, markdown (or md), csv, summary"}
        
    except SplunkAPIError as e:
        return {"error": str(e), "details": e.details}
    except Exception as e:
        return {"error": f"Export search failed: {str(e)}"}

@mcp.tool()
async def get_indexes(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available Splunk indexes with detailed information.
    
    Returns:
        Dictionary containing list of indexes with their properties including:
        - name, datatype, event count, size, time range, and more
    """
    if not ctx.request_context.lifespan_context.splunk_client:
        return {"error": "Splunk client not initialized"}
    
    try:
        client = ctx.request_context.lifespan_context.splunk_client
        indexes = await client.get_indexes()
        
        return {"indexes": indexes, "count": len(indexes)}
        
    except SplunkAPIError as e:
        return {"error": str(e), "details": e.details}
    except Exception as e:
        return {"error": f"Failed to get indexes: {str(e)}"}

@mcp.tool()
async def get_saved_searches(ctx: Context) -> Dict[str, Any]:
    """
    Get list of saved searches available in Splunk.
    
    Returns:
        Dictionary containing list of saved searches with their names, queries,
        descriptions, schedules, and other metadata
    """
    if not ctx.request_context.lifespan_context.splunk_client:
        return {"error": "Splunk client not initialized"}
    
    try:
        client = ctx.request_context.lifespan_context.splunk_client
        saved_searches = await client.get_saved_searches()
        
        return {"saved_searches": saved_searches, "count": len(saved_searches)}
        
    except SplunkAPIError as e:
        return {"error": str(e), "details": e.details}
    except Exception as e:
        return {"error": f"Failed to get saved searches: {str(e)}"}

@mcp.tool()
async def run_saved_search(ctx: Context, search_name: str, trigger_actions: bool = False) -> Dict[str, Any]:
    """
    Run a saved search by name.
    
    Args:
        search_name: Name of the saved search to run
        trigger_actions: Whether to trigger the search's actions (default: False)
    
    Returns:
        Dictionary containing search job information and results
    """
    if not ctx.request_context.lifespan_context.splunk_client:
        return {"error": "Splunk client not initialized"}
    
    try:
        client = ctx.request_context.lifespan_context.splunk_client
        result = await client.run_saved_search(search_name, trigger_actions)
        
        return result
        
    except SplunkAPIError as e:
        return {"error": str(e), "details": e.details}
    except Exception as e:
        return {"error": f"Failed to run saved search: {str(e)}"}

@mcp.tool()
async def get_config(ctx: Context) -> dict:
    """Get current server configuration."""
    config = ctx.request_context.lifespan_context.config.copy()
    # Remove sensitive information
    config.pop("splunk_password", None)
    config.pop("splunk_token", None)
    config["splunk_connected"] = ctx.request_context.lifespan_context.splunk_client is not None
    return config

@mcp.resource("splunk://saved-searches")
async def get_saved_searches_resource() -> str:
    """Provide saved searches information as a resource."""
    # Create a temporary client for resource access
    config = {
        "splunk_host": os.getenv("SPLUNK_HOST"),
        "splunk_port": int(os.getenv("SPLUNK_PORT", "8089")),
        "splunk_username": os.getenv("SPLUNK_USERNAME"),
        "splunk_password": os.getenv("SPLUNK_PASSWORD"),
        "splunk_token": os.getenv("SPLUNK_TOKEN"),
        "verify_ssl": os.getenv("VERIFY_SSL", "false").lower() == "true"
    }
    
    try:
        async with SplunkClient(config) as client:
            saved_searches = await client.get_saved_searches()
            
            content = "# Splunk Saved Searches\n\n"
            
            for search in saved_searches:
                content += f"## {search['name']}\n\n"
                if search.get('description'):
                    content += f"**Description:** {search['description']}\n"
                content += f"**Query:** `{search['search']}`\n"
                if search.get('is_scheduled'):
                    content += f"**Schedule:** {search.get('cron_schedule', 'N/A')}\n"
                    if search.get('next_scheduled_time'):
                        content += f"**Next Run:** {search['next_scheduled_time']}\n"
                if search.get('actions'):
                    content += f"**Actions:** {search['actions']}\n"
                content += "\n"
                
            return content
            
    except Exception as e:
        return f"Error retrieving saved searches: {str(e)}"

@mcp.resource("splunk://indexes")
async def get_indexes_resource() -> str:
    """Provide index information as a resource with detailed metadata."""
    # Create a temporary client for resource access
    config = {
        "splunk_host": os.getenv("SPLUNK_HOST"),
        "splunk_port": int(os.getenv("SPLUNK_PORT", "8089")),
        "splunk_username": os.getenv("SPLUNK_USERNAME"),
        "splunk_password": os.getenv("SPLUNK_PASSWORD"),
        "splunk_token": os.getenv("SPLUNK_TOKEN"),
        "verify_ssl": os.getenv("VERIFY_SSL", "false").lower() == "true"
    }
    
    try:
        async with SplunkClient(config) as client:
            indexes = await client.get_indexes()
            
            content = "# Splunk Indexes\n\n"
            content += "| Index | Type | Events | Size (MB) | Max Size | Time Range | Status |\n"
            content += "|-------|------|--------|-----------|----------|------------|--------|\n"
            
            for idx in indexes:
                time_range = "N/A"
                if idx.get('minTime') and idx.get('maxTime'):
                    time_range = f"{idx['minTime']} to {idx['maxTime']}"
                    
                status = "✓ Enabled" if not idx.get('disabled', False) else "✗ Disabled"
                max_size = idx.get('maxDataSize', 'auto')
                
                content += f"| {idx['name']} | {idx.get('datatype', 'event')} | "
                content += f"{idx.get('totalEventCount', 0):,} | "
                content += f"{idx.get('currentDBSizeMB', 0):,.2f} | "
                content += f"{max_size} | {time_range} | {status} |\n"
                
            content += "\n## Index Details\n\n"
            
            for idx in indexes:
                if idx.get('totalEventCount', 0) > 0:  # Only show non-empty indexes
                    content += f"### {idx['name']}\n"
                    content += f"- **Total Events:** {idx.get('totalEventCount', 0):,}\n"
                    content += f"- **Current Size:** {idx.get('currentDBSizeMB', 0):,.2f} MB\n"
                    content += f"- **Max Size:** {idx.get('maxDataSize', 'auto')}\n"
                    if idx.get('frozenTimePeriodInSecs'):
                        frozen_days = int(idx['frozenTimePeriodInSecs']) / 86400
                        content += f"- **Retention:** {frozen_days:.0f} days\n"
                    content += "\n"
                
            return content
            
    except Exception as e:
        return f"Error retrieving indexes: {str(e)}"

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    print("\n\n✨ Server shutdown ...")
    sys.exit(0)

async def _main():
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    transport = os.getenv("TRANSPORT", "sse")
    if transport == "sse":
        await mcp.run_sse_async()
    else:
        await mcp.run_stdio_async()

def main():
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully without printing stack trace
        print("\n\n✨ Server shutdown ...")
        sys.exit(0)

if __name__ == "__main__":
    main()