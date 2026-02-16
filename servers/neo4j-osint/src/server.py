#!/usr/bin/env python3
"""
Neo4j OSINT MCP Server
======================
Graph database tools for OSINT investigations.
"""
import os
import json
import logging
import asyncio
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from dotenv import load_dotenv

from .neo4j_client import Neo4jClient, init_schema
from .algorithms import GraphAlgorithms
from .sync import SQLiteSync

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("neo4j-osint")

server = Server("neo4j-osint")

# Global clients
_neo4j_client: Optional[Neo4jClient] = None
_algorithms: Optional[GraphAlgorithms] = None
_sync: Optional[SQLiteSync] = None


def get_neo4j() -> Neo4jClient:
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
        _neo4j_client.connect()
    return _neo4j_client


def get_algorithms() -> GraphAlgorithms:
    global _algorithms
    if _algorithms is None:
        _algorithms = GraphAlgorithms(get_neo4j())
    return _algorithms


def get_sync() -> SQLiteSync:
    global _sync
    if _sync is None:
        _sync = SQLiteSync(get_neo4j())
    return _sync


def fmt(data: Any) -> str:
    if isinstance(data, (dict, list)):
        return json.dumps(data, indent=2, default=str)
    return str(data)


# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

TOOLS = [
    # --- Database Management ---
    Tool(
        name="neo4j_status",
        description="Check Neo4j database health and get node/relationship counts.",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="neo4j_schema",
        description="Inspect Neo4j labels and property keys (schema discovery).",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="neo4j_init_schema",
        description="Initialize database schema with constraints and indexes.",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="neo4j_query",
        description="Execute a raw Cypher query.",
        inputSchema={
            "type": "object",
            "properties": {
                "cypher": {"type": "string", "description": "Cypher query"},
                "params": {"type": "object", "description": "Query parameters", "default": {}}
            },
            "required": ["cypher"]
        }
    ),
    
    # --- Entity Queries ---
    Tool(
        name="neo4j_find",
        description="Search for entities by name (fuzzy matching).",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Entity name to search"},
                "type": {"type": "string", "enum": ["Person", "Organization", "Address", "any"]},
                "limit": {"type": "integer", "default": 20}
            },
            "required": ["name"]
        }
    ),
    Tool(
        name="neo4j_profile",
        description="Get full entity profile with all connections up to depth.",
        inputSchema={
            "type": "object",
            "properties": {
                "entity": {"type": "string", "description": "Entity name or ID"},
                "depth": {"type": "integer", "default": 2}
            },
            "required": ["entity"]
        }
    ),

    # --- Path Finding ---
    Tool(
        name="neo4j_shortest_path",
        description="Find shortest path between two entities.",
        inputSchema={
            "type": "object",
            "properties": {
                "from_entity": {"type": "string"},
                "to_entity": {"type": "string"},
                "max_depth": {"type": "integer", "default": 10}
            },
            "required": ["from_entity", "to_entity"]
        }
    ),
    Tool(
        name="neo4j_all_paths",
        description="Find ALL paths between two entities.",
        inputSchema={
            "type": "object",
            "properties": {
                "from_entity": {"type": "string"},
                "to_entity": {"type": "string"},
                "max_depth": {"type": "integer", "default": 5},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["from_entity", "to_entity"]
        }
    ),
    Tool(
        name="neo4j_common_connections",
        description="Find entities connected to BOTH entity A and entity B.",
        inputSchema={
            "type": "object",
            "properties": {
                "entity_a": {"type": "string"},
                "entity_b": {"type": "string"}
            },
            "required": ["entity_a", "entity_b"]
        }
    ),
    
    # --- Algorithms ---
    Tool(
        name="neo4j_pagerank",
        description="Rank entities by network centrality/influence (PageRank).",
        inputSchema={
            "type": "object",
            "properties": {
                "node_labels": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 20}
            },
            "required": []
        }
    ),
    Tool(
        name="neo4j_bridges",
        description="Find bridge entities connecting different parts of network (betweenness).",
        inputSchema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 20}},
            "required": []
        }
    ),
    Tool(
        name="neo4j_communities",
        description="Detect natural clusters/communities in the network.",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "enum": ["louvain", "label_propagation", "weakly_connected"], "default": "weakly_connected"},
                "min_size": {"type": "integer", "default": 3}
            },
            "required": []
        }
    ),
    Tool(
        name="neo4j_similar",
        description="Find entities with similar connection patterns (Jaccard similarity).",
        inputSchema={
            "type": "object",
            "properties": {
                "entity": {"type": "string"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["entity"]
        }
    ),
    Tool(
        name="neo4j_triangles",
        description="Find triangular relationships (tight clusters).",
        inputSchema={
            "type": "object",
            "properties": {"entity": {"type": "string"}},
            "required": []
        }
    ),

    # --- Investigation Tools ---
    Tool(
        name="neo4j_money_flow",
        description="Trace grant money flow between organizations.",
        inputSchema={
            "type": "object",
            "properties": {
                "source_org": {"type": "string"},
                "target_org": {"type": "string"},
                "min_amount": {"type": "integer"},
                "years": {"type": "array", "items": {"type": "integer"}}
            },
            "required": []
        }
    ),
    Tool(
        name="neo4j_officer_network",
        description="Find organizations that share officers.",
        inputSchema={
            "type": "object",
            "properties": {"min_shared": {"type": "integer", "default": 1}},
            "required": []
        }
    ),
    Tool(
        name="neo4j_address_cluster",
        description="Find all entities at or connected to an address.",
        inputSchema={
            "type": "object",
            "properties": {"address": {"type": "string"}},
            "required": ["address"]
        }
    ),
    Tool(
        name="neo4j_red_flags",
        description="Detect anomalous patterns: isolated high-value grants, circular funding, address clustering.",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    
    # --- Sync Tools ---
    Tool(
        name="neo4j_sync_sqlite",
        description="Full sync from SQLite source database to Neo4j graph.",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="neo4j_sync_grants",
        description="Sync grant data (from 990 analysis) to Neo4j.",
        inputSchema={
            "type": "object",
            "properties": {
                "grants": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from_org": {"type": "string"},
                            "from_ein": {"type": "string"},
                            "to_org": {"type": "string"},
                            "to_ein": {"type": "string"},
                            "amount": {"type": "number"},
                            "year": {"type": "integer"},
                            "purpose": {"type": "string"}
                        }
                    }
                }
            },
            "required": ["grants"]
        }
    ),
    Tool(
        name="neo4j_sync_officers",
        description="Sync officer data (from 990 analysis) to Neo4j.",
        inputSchema={
            "type": "object",
            "properties": {
                "officers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "person_name": {"type": "string"},
                            "org_name": {"type": "string"},
                            "org_ein": {"type": "string"},
                            "title": {"type": "string"},
                            "compensation": {"type": "number"},
                            "year": {"type": "integer"}
                        }
                    }
                }
            },
            "required": ["officers"]
        }
    ),
]


# =============================================================================
# MCP HANDLERS
# =============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        # Run the potentially blocking tool execution in a separate thread
        # to keep the MCP event loop responsive.
        result = await asyncio.to_thread(_execute_tool_sync, name, arguments)
        return [TextContent(type="text", text=fmt(result))]
    except Exception as e:
        logger.error(f"Tool {name} failed: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


def _execute_tool_sync(name: str, args: dict) -> Any:
    """Route tool calls to implementations (Synchronous version)."""
    
    # --- Database Management ---
    if name == "neo4j_status":
        return get_neo4j().health_check()

    elif name == "neo4j_schema":
        node_props = get_neo4j().execute(
            """
            CALL db.schema.nodeTypeProperties()
            YIELD nodeType, propertyName, propertyTypes, mandatory
            RETURN nodeType,
                   collect({
                       property: propertyName,
                       types: propertyTypes,
                       mandatory: mandatory
                   }) as properties
            ORDER BY nodeType
            """
        )
        rel_props = get_neo4j().execute(
            """
            CALL db.schema.relTypeProperties()
            YIELD relType, propertyName, propertyTypes, mandatory
            RETURN relType,
                   collect({
                       property: propertyName,
                       types: propertyTypes,
                       mandatory: mandatory
                   }) as properties
            ORDER BY relType
            """
        )
        return {"nodes": node_props, "relationships": rel_props}
    
    elif name == "neo4j_init_schema":
        return init_schema(get_neo4j())
    
    elif name == "neo4j_query":
        return get_neo4j().execute(args["cypher"], args.get("params", {}))
    
    # --- Entity Queries ---
    elif name == "neo4j_find":
        entity_type = args.get("type", "any")
        limit = args.get("limit", 20)
        if entity_type == "any":
            query = """
            MATCH (n) WHERE n.name CONTAINS $name OR n.id CONTAINS $name
            RETURN labels(n)[0] as type, n.name as name, n.id as id
            LIMIT $limit
            """
        else:
            query = f"""
            MATCH (n:{entity_type}) WHERE n.name CONTAINS $name OR n.id CONTAINS $name
            RETURN labels(n)[0] as type, n.name as name, n.id as id
            LIMIT $limit
            """
        return get_neo4j().execute(query, {"name": args["name"], "limit": limit})
    
    elif name == "neo4j_profile":
        depth = args.get("depth", 2)
        query = f"""
        MATCH (center) WHERE center.name = $entity OR center.id = $entity
        OPTIONAL MATCH path = (center)-[*1..{depth}]-(connected)
        WITH center, collect(DISTINCT {{
            node: {{type: labels(connected)[0], name: connected.name, id: connected.id}},
            relationship: type(relationships(path)[-1])
        }}) as connections
        RETURN {{
            entity: {{type: labels(center)[0], name: center.name, id: center.id, properties: properties(center)}},
            connections: connections
        }} as profile
        """
        return get_neo4j().execute(query, {"entity": args["entity"]})

    # --- Path Finding ---
    elif name == "neo4j_shortest_path":
        return get_algorithms().shortest_path(
            args["from_entity"],
            args["to_entity"],
            args.get("max_depth", 10)
        )
    
    elif name == "neo4j_all_paths":
        return get_algorithms().all_paths(
            args["from_entity"],
            args["to_entity"],
            args.get("max_depth", 5),
            args.get("limit", 10)
        )
    
    elif name == "neo4j_common_connections":
        return get_algorithms().common_connections(args["entity_a"], args["entity_b"])
    
    # --- Algorithms ---
    elif name == "neo4j_pagerank":
        return get_algorithms().pagerank(
            node_labels=args.get("node_labels"),
            limit=args.get("limit", 20)
        )
    
    elif name == "neo4j_bridges":
        return get_algorithms().betweenness_centrality(args.get("limit", 20))
    
    elif name == "neo4j_communities":
        return get_algorithms().detect_communities(
            algorithm=args.get("algorithm", "weakly_connected"),
            min_community_size=args.get("min_size", 3)
        )
    
    elif name == "neo4j_similar":
        return get_algorithms().similar_entities(args["entity"], args.get("limit", 10))
    
    elif name == "neo4j_triangles":
        return get_algorithms().triangles(args.get("entity"))
    
    # --- Investigation Tools ---
    elif name == "neo4j_money_flow":
        return get_algorithms().money_flow(
            source_org=args.get("source_org"),
            target_org=args.get("target_org"),
            min_amount=args.get("min_amount"),
            years=args.get("years")
        )
    
    elif name == "neo4j_officer_network":
        return get_algorithms().officer_network(args.get("min_shared", 1))
    
    elif name == "neo4j_address_cluster":
        return get_algorithms().address_cluster(args["address"])
    
    elif name == "neo4j_red_flags":
        return get_algorithms().red_flags()
    
    # --- Sync Tools ---
    elif name == "neo4j_sync_sqlite":
        stats = get_sync().full_sync()
        return stats.to_dict()
    
    elif name == "neo4j_sync_grants":
        count = get_sync().sync_grant_data(args["grants"])
        return {"grants_synced": count}
    
    elif name == "neo4j_sync_officers":
        count = get_sync().sync_officer_data(args["officers"])
        return {"officers_synced": count}
    
    else:
        raise ValueError(f"Unknown tool: {name}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def main():
    """Run the MCP server."""
    logger.info("Starting Neo4j OSINT MCP Server...")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
