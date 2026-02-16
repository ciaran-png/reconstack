"""
SQLite Sync - Synchronize SQLite source database to Neo4j graph.
"""
import os
import re
import sqlite3
from typing import Optional
from datetime import datetime
from dataclasses import dataclass

from dotenv import load_dotenv
from .neo4j_client import Neo4jClient, init_schema

load_dotenv()


@dataclass
class SyncStats:
    """Statistics from a sync operation."""
    entities_synced: int = 0
    identifiers_synced: int = 0
    sections_synced: int = 0
    claims_synced: int = 0
    relationships_created: int = 0
    errors: list = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    def to_dict(self) -> dict:
        return {
            "entities_synced": self.entities_synced,
            "identifiers_synced": self.identifiers_synced,
            "sections_synced": self.sections_synced,
            "claims_synced": self.claims_synced,
            "relationships_created": self.relationships_created,
            "errors": self.errors,
            "success": len(self.errors) == 0
        }


class SQLiteSync:
    """Synchronize SQLite source data to Neo4j graph database."""
    
    def __init__(
        self,
        neo4j_client: Neo4jClient,
        sqlite_path: str = None
    ):
        self.neo4j = neo4j_client
        self.db_path = sqlite_path or os.getenv("SQLITE_DB_PATH", "")
    
    def _get_sqlite_connection(self) -> sqlite3.Connection:
        """Get SQLite connection to source database."""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"SQLite database not found: {self.db_path}")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def full_sync(self) -> SyncStats:
        """Perform full synchronization from SQLite to Neo4j."""
        stats = SyncStats()
        
        # Initialize schema
        init_schema(self.neo4j)
        
        # Sync in order of dependencies
        stats.entities_synced = self._sync_entities(stats)
        stats.identifiers_synced = self._sync_identifiers(stats)
        stats.sections_synced = self._sync_sections(stats)
        stats.claims_synced = self._sync_claims(stats)
        stats.relationships_created = self._create_relationships(stats)
        
        return stats
    
    def _sync_entities(self, stats: SyncStats) -> int:
        """Sync entities table to Neo4j Person/Organization/Address nodes."""
        conn = self._get_sqlite_connection()
        cursor = conn.execute("SELECT * FROM entities")
        rows = cursor.fetchall()
        conn.close()
        
        count = 0
        for row in rows:
            try:
                entity_id = f"entity_{row['id']}"
                name = row['name']
                kind = row['kind']  # person, org, place, other
                aliases_json = row['aliases_json'] or "[]"
                
                # Map kind to Neo4j label
                label_map = {
                    "person": "Person",
                    "org": "Organization",
                    "place": "Address",
                    "other": "Entity"
                }
                label = label_map.get(kind, "Entity")
                
                # Parse aliases from JSON
                import json as json_module
                try:
                    alias_list = json_module.loads(aliases_json)
                except:
                    alias_list = []
                
                query = f"""
                MERGE (n:{label} {{id: $id}})
                SET n.name = $name,
                    n.aliases = $aliases,
                    n.kind = $kind,
                    n.source_id = $sourceId,
                    n.synced_at = datetime()
                """

                self.neo4j.execute_write(query, {
                    "id": entity_id,
                    "name": name,
                    "aliases": alias_list,
                    "kind": kind,
                    "sourceId": row['id']
                })
                count += 1
                
            except Exception as e:
                stats.errors.append(f"Entity {row['id']}: {str(e)}")
        
        return count
    
    def _sync_identifiers(self, stats: SyncStats) -> int:
        """Sync identifiers table to Neo4j nodes (EIN, Domain, Email, etc.)."""
        conn = self._get_sqlite_connection()
        cursor = conn.execute("""
            SELECT i.*, e.name as entity_name, e.kind as entity_kind
            FROM identifiers i
            LEFT JOIN entities e ON i.entity_id = e.id
        """)
        rows = cursor.fetchall()
        conn.close()
        
        count = 0
        for row in rows:
            try:
                id_type = row['type']  # ein, domain, email, phone, address, ip, etc.
                value = row['value']
                entity_id = row['entity_id']
                
                # Map identifier type to Neo4j label
                label_map = {
                    "ein": "EIN",
                    "domain": "Domain",
                    "email": "Email",
                    "phone": "Phone",
                    "ip": "IP",
                    "address": "Address",
                    "url": "URL",
                    "gtm": "TrackingID",
                    "ga_ua": "TrackingID",
                    "ga4": "TrackingID",
                    "fb_pixel": "TrackingID",
                    "asn": "ASN"
                }
                label = label_map.get(id_type, "Identifier")
                
                # Create identifier node
                if label == "EIN":
                    query = f"""
                    MERGE (n:EIN {{number: $value}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "Domain":
                    query = f"""
                    MERGE (n:Domain {{domain: $value}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "Email":
                    query = f"""
                    MERGE (n:Email {{address: $value}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "Phone":
                    query = f"""
                    MERGE (n:Phone {{number: $value}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "IP":
                    query = f"""
                    MERGE (n:IP {{address: $value}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "Address":
                    query = f"""
                    MERGE (n:Address {{full_address: $value}})
                    SET n.id = $nodeId,
                        n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                elif label == "TrackingID":
                    query = f"""
                    MERGE (n:TrackingID {{id: $value, type: $idType}})
                    SET n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """
                else:
                    query = f"""
                    MERGE (n:{label} {{value: $value}})
                    SET n.type = $idType,
                        n.source_id = $sourceId,
                        n.synced_at = datetime()
                    """

                self.neo4j.execute_write(query, {
                    "value": value,
                    "idType": id_type,
                    "sourceId": row['id'],
                    "nodeId": f"addr_{row['id']}"
                })
                
                # Link to entity if exists
                if entity_id:
                    rel_query = """
                    MATCH (e) WHERE e.source_id = $entitySourceId
                    MATCH (i) WHERE i.source_id = $identSourceId
                    MERGE (e)-[:HAS_IDENTIFIER]->(i)
                    """
                    self.neo4j.execute_write(rel_query, {
                        "entitySourceId": entity_id,
                        "identSourceId": row['id']
                    })
                
                count += 1
                
            except Exception as e:
                stats.errors.append(f"Identifier {row['id']}: {str(e)}")
        
        return count
    
    def _sync_sections(self, stats: SyncStats) -> int:
        """Sync sections to Neo4j Section nodes."""
        conn = self._get_sqlite_connection()
        cursor = conn.execute("SELECT * FROM sections")
        rows = cursor.fetchall()
        conn.close()

        count = 0
        for row in rows:
            try:
                query = """
                MERGE (s:Section {id: $id})
                SET s.title = $title,
                    s.path = $path,
                    s.heading_level = $level,
                    s.source_id = $sourceId,
                    s.synced_at = datetime()
                """

                self.neo4j.execute_write(query, {
                    "id": f"section_{row['id']}",
                    "title": row['title'],
                    "path": row['path'],
                    "level": row['heading_level'],
                    "sourceId": row['id']
                })
                count += 1
                
            except Exception as e:
                stats.errors.append(f"Section {row['id']}: {str(e)}")
        
        return count
    
    def _sync_claims(self, stats: SyncStats) -> int:
        """Sync claims to Neo4j Claim nodes."""
        conn = self._get_sqlite_connection()
        cursor = conn.execute("SELECT * FROM claims")
        rows = cursor.fetchall()
        conn.close()

        count = 0
        for row in rows:
            try:
                query = """
                MERGE (c:Claim {id: $id})
                SET c.text = $text,
                    c.status = $status,
                    c.confidence = $confidence,
                    c.section_id = $sectionId,
                    c.source_id = $sourceId,
                    c.synced_at = datetime()
                """

                self.neo4j.execute_write(query, {
                    "id": f"claim_{row['id']}",
                    "text": row['claim_text'],
                    "status": row['status'],
                    "confidence": row['confidence'],
                    "sectionId": row['section_id'],
                    "sourceId": row['id']
                })
                
                # Link to section
                if row['section_id']:
                    rel_query = """
                    MATCH (c:Claim {id: $claimId})
                    MATCH (s:Section {id: $sectionId})
                    MERGE (c)-[:IN_SECTION]->(s)
                    """
                    self.neo4j.execute_write(rel_query, {
                        "claimId": f"claim_{row['id']}",
                        "sectionId": f"section_{row['section_id']}"
                    })
                
                count += 1
                
            except Exception as e:
                stats.errors.append(f"Claim {row['id']}: {str(e)}")
        
        return count
    
    def _create_relationships(self, stats: SyncStats) -> int:
        """Create inferred relationships from identifier mentions and patterns."""
        count = 0
        conn = self._get_sqlite_connection()
        
        # 1. Link identifier mentions to sections
        cursor = conn.execute("""
            SELECT im.*, i.type, i.value
            FROM identifier_mentions im
            JOIN identifiers i ON im.identifier_id = i.id
        """)
        mentions = cursor.fetchall()
        
        for mention in mentions:
            try:
                query = """
                MATCH (i) WHERE i.source_id = $identId
                MATCH (s:Section {id: $sectionId})
                MERGE (s)-[:MENTIONS {context: $context}]->(i)
                """
                result = self.neo4j.execute_write(query, {
                    "identId": mention['identifier_id'],
                    "sectionId": f"section_{mention['section_id']}",
                    "context": mention['context'] or ""
                })
                count += result.get("relationships_created", 0)
            except Exception as e:
                stats.errors.append(f"Mention {mention['id']}: {str(e)}")
        
        # 2. Create LOCATED_AT relationships for addresses
        query = """
        MATCH (o:Organization)
        MATCH (a:Address)
        WHERE o.address IS NOT NULL AND o.address = a.full_address
        MERGE (o)-[:LOCATED_AT]->(a)
        """
        try:
            result = self.neo4j.execute_write(query, {})
            count += result.get("relationships_created", 0)
        except Exception:
            pass
        
        # 3. Create HAS_EIN relationships
        query = """
        MATCH (o:Organization)
        MATCH (e:EIN)
        WHERE o.ein IS NOT NULL AND o.ein = e.number
        MERGE (o)-[:HAS_EIN]->(e)
        """
        try:
            result = self.neo4j.execute_write(query, {})
            count += result.get("relationships_created", 0)
        except Exception:
            pass
        
        conn.close()
        return count
    
    def sync_grant_data(self, grants: list[dict]) -> int:
        """
        Sync grant data (from 990 analysis) to Neo4j.
        
        Expected format:
        {
            "from_org": "Foundation Name",
            "from_ein": "12-3456789",
            "to_org": "Recipient Name",
            "to_ein": "98-7654321",
            "amount": 100000,
            "year": 2023,
            "purpose": "General support"
        }
        """
        count = 0
        for grant in grants:
            try:
                query = """
                // Ensure source org exists
                MERGE (source:Organization {ein: $fromEin})
                ON CREATE SET source.name = $fromOrg, source.id = 'org_' + $fromEin
                ON MATCH SET source.name = COALESCE(source.name, $fromOrg)
                
                // Ensure target org exists
                MERGE (target:Organization {ein: $toEin})
                ON CREATE SET target.name = $toOrg, target.id = 'org_' + $toEin
                ON MATCH SET target.name = COALESCE(target.name, $toOrg)
                
                // Create grant relationship
                MERGE (source)-[g:GRANTED_TO {year: $year}]->(target)
                SET g.amount = $amount,
                    g.purpose = $purpose,
                    g.synced_at = datetime()
                """
                
                self.neo4j.execute_write(query, {
                    "fromOrg": grant.get("from_org", "Unknown"),
                    "fromEin": grant.get("from_ein", "unknown"),
                    "toOrg": grant.get("to_org", "Unknown"),
                    "toEin": grant.get("to_ein", "unknown"),
                    "amount": grant.get("amount", 0),
                    "year": grant.get("year", 0),
                    "purpose": grant.get("purpose", "")
                })
                count += 1
                
            except Exception as e:
                print(f"Error syncing grant: {e}")
        
        return count
    
    def sync_officer_data(self, officers: list[dict]) -> int:
        """
        Sync officer data (from 990 analysis) to Neo4j.
        
        Expected format:
        {
            "person_name": "John Doe",
            "org_name": "Foundation Name",
            "org_ein": "12-3456789",
            "title": "President",
            "compensation": 150000,
            "year": 2023
        }
        """
        count = 0
        for officer in officers:
            try:
                # Clean the person name for use as ID
                name_id = re.sub(r'[^a-z0-9]', '_', officer.get("person_name", "unknown").lower())
                
                query = """
                // Ensure person exists
                MERGE (p:Person {id: $personId})
                ON CREATE SET p.name = $personName
                ON MATCH SET p.name = COALESCE(p.name, $personName)
                
                // Ensure org exists
                MERGE (o:Organization {ein: $orgEin})
                ON CREATE SET o.name = $orgName, o.id = 'org_' + $orgEin
                ON MATCH SET o.name = COALESCE(o.name, $orgName)
                
                // Create officer relationship
                MERGE (p)-[r:OFFICER_OF]->(o)
                SET r.title = $title,
                    r.compensation = $compensation,
                    r.year = $year,
                    r.synced_at = datetime()
                """
                
                self.neo4j.execute_write(query, {
                    "personId": f"person_{name_id}",
                    "personName": officer.get("person_name", "Unknown"),
                    "orgEin": officer.get("org_ein", "unknown"),
                    "orgName": officer.get("org_name", "Unknown"),
                    "title": officer.get("title", ""),
                    "compensation": officer.get("compensation", 0),
                    "year": officer.get("year", 0)
                })
                count += 1
                
            except Exception as e:
                print(f"Error syncing officer: {e}")
        
        return count
