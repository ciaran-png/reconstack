"""
Neo4j Client - Database connection and query execution
"""
import os
from typing import Any, Optional
from contextlib import contextmanager

from neo4j import GraphDatabase, Driver, Session
from neo4j.exceptions import ServiceUnavailable, AuthError
from dotenv import load_dotenv

load_dotenv()


class Neo4jClient:
    """Neo4j database client for OSINT investigations."""
    
    def __init__(
        self,
        uri: str = None,
        user: str = None,
        password: str = None
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "")
        self._driver: Optional[Driver] = None
    
    def connect(self) -> bool:
        """Establish connection to Neo4j."""
        try:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600
            )
            # Verify connectivity
            self._driver.verify_connectivity()
            return True
        except (ServiceUnavailable, AuthError) as e:
            raise ConnectionError(f"Failed to connect to Neo4j: {e}")
    
    def close(self):
        """Close the database connection."""
        if self._driver:
            self._driver.close()
            self._driver = None
    
    @property
    def driver(self) -> Driver:
        """Get the Neo4j driver, connecting if necessary."""
        if not self._driver:
            self.connect()
        return self._driver
    
    @contextmanager
    def session(self, database: str = "neo4j"):
        """Context manager for Neo4j sessions."""
        session = self.driver.session(database=database)
        try:
            yield session
        finally:
            session.close()
    
    def execute(
        self,
        query: str,
        params: dict = None,
        database: str = "neo4j"
    ) -> list[dict]:
        """Execute a Cypher query and return results as list of dicts."""
        with self.session(database) as session:
            result = session.run(query, params or {})
            return [dict(record) for record in result]
    
    def execute_write(
        self,
        query: str,
        params: dict = None,
        database: str = "neo4j"
    ) -> dict:
        """Execute a write query and return summary."""
        with self.session(database) as session:
            result = session.run(query, params or {})
            summary = result.consume()
            return {
                "nodes_created": summary.counters.nodes_created,
                "nodes_deleted": summary.counters.nodes_deleted,
                "relationships_created": summary.counters.relationships_created,
                "relationships_deleted": summary.counters.relationships_deleted,
                "properties_set": summary.counters.properties_set,
                "labels_added": summary.counters.labels_added
            }
    
    def health_check(self) -> dict:
        """Check database health and return stats."""
        try:
            with self.session() as session:
                # Get node counts
                node_result = session.run(
                    "MATCH (n) RETURN labels(n)[0] as label, count(*) as count"
                )
                node_counts = {r["label"]: r["count"] for r in node_result}
                
                # Get relationship counts
                rel_result = session.run(
                    "MATCH ()-[r]->() RETURN type(r) as type, count(*) as count"
                )
                rel_counts = {r["type"]: r["count"] for r in rel_result}
                
                return {
                    "status": "healthy",
                    "uri": self.uri,
                    "node_counts": node_counts,
                    "relationship_counts": rel_counts,
                    "total_nodes": sum(node_counts.values()),
                    "total_relationships": sum(rel_counts.values())
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Schema creation queries
SCHEMA_CONSTRAINTS = """
// Unique constraints for key identifiers
CREATE CONSTRAINT person_name IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT org_name IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;
CREATE CONSTRAINT address_full IF NOT EXISTS FOR (a:Address) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT ein_number IF NOT EXISTS FOR (e:EIN) REQUIRE e.number IS UNIQUE;
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.domain IS UNIQUE;
CREATE CONSTRAINT email_address IF NOT EXISTS FOR (e:Email) REQUIRE e.address IS UNIQUE;
CREATE CONSTRAINT phone_number IF NOT EXISTS FOR (p:Phone) REQUIRE p.number IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE;
CREATE CONSTRAINT claim_id IF NOT EXISTS FOR (c:Claim) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT section_id IF NOT EXISTS FOR (s:Section) REQUIRE s.id IS UNIQUE;
"""

SCHEMA_INDEXES = """
// Full-text indexes for search
CREATE FULLTEXT INDEX person_search IF NOT EXISTS FOR (p:Person) ON EACH [p.name, p.aliases];
CREATE FULLTEXT INDEX org_search IF NOT EXISTS FOR (o:Organization) ON EACH [o.name, o.aliases];
CREATE FULLTEXT INDEX address_search IF NOT EXISTS FOR (a:Address) ON EACH [a.full_address, a.city, a.state];

// Regular indexes for common queries
CREATE INDEX person_name_idx IF NOT EXISTS FOR (p:Person) ON (p.name);
CREATE INDEX org_name_idx IF NOT EXISTS FOR (o:Organization) ON (o.name);
CREATE INDEX org_ein_idx IF NOT EXISTS FOR (o:Organization) ON (o.ein);
CREATE INDEX address_city_idx IF NOT EXISTS FOR (a:Address) ON (a.city);
CREATE INDEX address_state_idx IF NOT EXISTS FOR (a:Address) ON (a.state);
"""


def init_schema(client: Neo4jClient):
    """Initialize database schema with constraints and indexes."""
    results = []
    
    # Create constraints one at a time (Neo4j requires separate transactions)
    constraints = [
        "CREATE CONSTRAINT person_id IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE",
        "CREATE CONSTRAINT org_id IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE",
        "CREATE CONSTRAINT address_id IF NOT EXISTS FOR (a:Address) REQUIRE a.id IS UNIQUE",
        "CREATE CONSTRAINT ein_number IF NOT EXISTS FOR (e:EIN) REQUIRE e.number IS UNIQUE",
        "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.domain IS UNIQUE",
        "CREATE CONSTRAINT email_address IF NOT EXISTS FOR (e:Email) REQUIRE e.address IS UNIQUE",
        "CREATE CONSTRAINT phone_number IF NOT EXISTS FOR (p:Phone) REQUIRE p.number IS UNIQUE",
        "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
        "CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE",
        "CREATE CONSTRAINT claim_id IF NOT EXISTS FOR (c:Claim) REQUIRE c.id IS UNIQUE",
        "CREATE CONSTRAINT section_id IF NOT EXISTS FOR (s:Section) REQUIRE s.id IS UNIQUE",
    ]
    
    for constraint in constraints:
        try:
            client.execute_write(constraint)
            results.append({"query": constraint, "status": "created"})
        except Exception as e:
            if "already exists" in str(e).lower():
                results.append({"query": constraint, "status": "exists"})
            else:
                results.append({"query": constraint, "status": "error", "error": str(e)})
    
    # Create indexes
    indexes = [
        "CREATE INDEX person_name_idx IF NOT EXISTS FOR (p:Person) ON (p.name)",
        "CREATE INDEX org_name_idx IF NOT EXISTS FOR (o:Organization) ON (o.name)",
        "CREATE INDEX org_ein_idx IF NOT EXISTS FOR (o:Organization) ON (o.ein)",
        "CREATE INDEX address_city_idx IF NOT EXISTS FOR (a:Address) ON (a.city)",
        "CREATE INDEX address_state_idx IF NOT EXISTS FOR (a:Address) ON (a.state)",
    ]
    
    for index in indexes:
        try:
            client.execute_write(index)
            results.append({"query": index, "status": "created"})
        except Exception as e:
            if "already exists" in str(e).lower():
                results.append({"query": index, "status": "exists"})
            else:
                results.append({"query": index, "status": "error", "error": str(e)})
    
    return results
