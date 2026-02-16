"""
Graph Algorithms - PageRank, Community Detection, Path Finding, etc.
Uses Neo4j Graph Data Science (GDS) library when available, falls back to Cypher.
"""
import uuid
from typing import Optional
from .neo4j_client import Neo4jClient


class GraphAlgorithms:
    """Graph algorithm execution using Neo4j GDS or native Cypher."""
    
    def __init__(self, client: Neo4jClient):
        self.client = client
        self._gds_available = None
        self._gds_anonymous_ok: Optional[bool] = None

    def _is_gds_map_error(self, error: Exception) -> bool:
        return "expected String but was Map" in str(error)

    def _project_graph(
        self,
        node_labels: list[str] = None,
        relationship_types: list[str] = None
    ) -> str:
        graph_name = f"osint_{uuid.uuid4().hex}"
        node_projection = node_labels if node_labels else ["Person", "Organization", "Address"]
        rel_projection = relationship_types if relationship_types else "*"
        self.client.execute(
            "CALL gds.graph.project($name, $nodeLabels, $relTypes)",
            {"name": graph_name, "nodeLabels": node_projection, "relTypes": rel_projection}
        )
        return graph_name

    def _drop_graph(self, graph_name: str) -> None:
        try:
            self.client.execute("CALL gds.graph.drop($name, false)", {"name": graph_name})
        except Exception:
            pass
    
    def check_gds(self) -> bool:
        """Check if Graph Data Science library is available and working."""
        if self._gds_available is None:
            try:
                # Test if GDS is actually functional with a simple call
                result = self.client.execute("CALL gds.list() YIELD name RETURN name LIMIT 1")
                self._gds_available = len(result) > 0
            except Exception:
                self._gds_available = False
        return self._gds_available
    
    # =========================================================================
    # CENTRALITY ALGORITHMS
    # =========================================================================
    
    def pagerank(
        self,
        node_labels: list[str] = None,
        relationship_types: list[str] = None,
        limit: int = 20,
        dampening: float = 0.85,
        iterations: int = 20
    ) -> list[dict]:
        """
        Calculate PageRank to find most influential/central entities.
        
        Returns ranked list of entities by network importance.
        """
        if self.check_gds():
            # Use GDS for better performance
            return self._pagerank_gds(node_labels, relationship_types, limit, dampening, iterations)
        else:
            # Fallback to native Cypher approximation
            return self._pagerank_cypher(node_labels, relationship_types, limit)
    
    def _pagerank_gds(
        self,
        node_labels: list[str],
        relationship_types: list[str],
        limit: int,
        dampening: float,
        iterations: int
    ) -> list[dict]:
        """PageRank using GDS library."""
        node_projection = node_labels if node_labels else ["Person", "Organization", "Address"]
        # In GDS 2.x+, relationshipProjection can be a string, list, or map.
        # '*' means all types.
        rel_projection = relationship_types if relationship_types else "*"

        map_query = """
        CALL gds.pageRank.stream({
            nodeProjection: $nodeLabels,
            relationshipProjection: $relTypes,
            dampingFactor: $dampening,
            maxIterations: $iterations
        })
        YIELD nodeId, score
        WITH gds.util.asNode(nodeId) AS node, score
        RETURN 
            labels(node)[0] as type,
            node.name as name,
            node.id as id,
            score
        ORDER BY score DESC
        LIMIT $limit
        """
        map_params = {
            "nodeLabels": node_projection,
            "relTypes": rel_projection,
            "dampening": dampening,
            "iterations": iterations,
            "limit": limit
        }

        if self._gds_anonymous_ok is not False:
            try:
                result = self.client.execute(map_query, map_params)
                self._gds_anonymous_ok = True
                return result
            except Exception as e:
                if not self._is_gds_map_error(e):
                    return self._pagerank_cypher(node_labels, relationship_types, limit)
                self._gds_anonymous_ok = False

        graph_name = self._project_graph(node_projection, rel_projection)
        try:
            named_query = """
            CALL gds.pageRank.stream($graphName, {
                dampingFactor: $dampening,
                maxIterations: $iterations
            })
            YIELD nodeId, score
            WITH gds.util.asNode(nodeId) AS node, score
            RETURN 
                labels(node)[0] as type,
                node.name as name,
                node.id as id,
                score
            ORDER BY score DESC
            LIMIT $limit
            """
            try:
                return self.client.execute(named_query, {
                    "graphName": graph_name,
                    "dampening": dampening,
                    "iterations": iterations,
                    "limit": limit
                })
            except Exception:
                fallback_query = """
                CALL gds.pageRank.stream($graphName)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                RETURN 
                    labels(node)[0] as type,
                    node.name as name,
                    node.id as id,
                    score
                ORDER BY score DESC
                LIMIT $limit
                """
                return self.client.execute(fallback_query, {"graphName": graph_name, "limit": limit})
        finally:
            self._drop_graph(graph_name)
    
    def _pagerank_cypher(
        self,
        node_labels: list[str],
        relationship_types: list[str],
        limit: int
    ) -> list[dict]:
        """PageRank approximation using native Cypher (degree-based)."""
        # Simple degree centrality as fallback - Neo4j 5.x syntax
        label_filter = ""
        if node_labels:
            label_filter = "WHERE " + " OR ".join([f"n:{l}" for l in node_labels])
        
        query = f"""
        MATCH (n)
        {label_filter}
        WITH n, COUNT {{ (n)--() }} as degree
        RETURN 
            labels(n)[0] as type,
            n.name as name,
            n.id as id,
            degree as score
        ORDER BY degree DESC
        LIMIT $limit
        """
        return self.client.execute(query, {"limit": limit})
    
    def betweenness_centrality(self, limit: int = 20) -> list[dict]:
        """
        Find bridge entities that connect different parts of the network.
        
        High betweenness = entity lies on many shortest paths = network broker.
        """
        if self.check_gds():
            map_query = """
            CALL gds.betweenness.stream({
                nodeProjection: ['Person', 'Organization'],
                relationshipProjection: '*'
            })
            YIELD nodeId, score
            WITH gds.util.asNode(nodeId) AS node, score
            WHERE score > 0
            RETURN 
                labels(node)[0] as type,
                node.name as name,
                node.id as id,
                score
            ORDER BY score DESC
            LIMIT $limit
            """
            if self._gds_anonymous_ok is not False:
                try:
                    result = self.client.execute(map_query, {"limit": limit})
                    self._gds_anonymous_ok = True
                    return result
                except Exception as e:
                    if not self._is_gds_map_error(e):
                        return self._betweenness_cypher(limit)
                    self._gds_anonymous_ok = False

            graph_name = self._project_graph(["Person", "Organization"], "*")
            try:
                named_query = """
                CALL gds.betweenness.stream($graphName)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                WHERE score > 0
                RETURN 
                    labels(node)[0] as type,
                    node.name as name,
                    node.id as id,
                    score
                ORDER BY score DESC
                LIMIT $limit
                """
                return self.client.execute(named_query, {"graphName": graph_name, "limit": limit})
            except Exception:
                return self._betweenness_cypher(limit)
            finally:
                self._drop_graph(graph_name)

        return self._betweenness_cypher(limit)

    def _betweenness_cypher(self, limit: int) -> list[dict]:
        """Fallback betweenness approximation using native Cypher."""
        query = """
        MATCH (n) WHERE n:Person OR n:Organization
        WITH n, COUNT { (n)--() } as connections
        WHERE connections >= 2
        MATCH path = shortestPath((n)-[*..4]-(other))
        WHERE other <> n
        WITH n, count(DISTINCT other) as reachable, connections
        RETURN 
            labels(n)[0] as type,
            n.name as name,
            n.id as id,
            connections * reachable as score
        ORDER BY score DESC
        LIMIT $limit
        """
        return self.client.execute(query, {"limit": limit})
    
    # =========================================================================
    # COMMUNITY DETECTION
    # =========================================================================
    
    def detect_communities(
        self,
        algorithm: str = "louvain",
        min_community_size: int = 3
    ) -> list[dict]:
        """
        Detect natural clusters/communities in the network.
        
        Algorithms:
        - louvain: Best for large networks, finds hierarchical communities
        - label_propagation: Fast, good for well-defined communities
        - weakly_connected: Find disconnected subgraphs
        """
        if algorithm == "weakly_connected":
            return self._weakly_connected_components(min_community_size)
        
        if self.check_gds():
            if algorithm == "louvain":
                return self._louvain_gds(min_community_size)
            elif algorithm == "label_propagation":
                return self._label_propagation_gds(min_community_size)
        
        # Fallback to weakly connected components
        return self._weakly_connected_components(min_community_size)
    
    def _louvain_gds(self, min_size: int) -> list[dict]:
        """Louvain community detection using GDS."""
        node_labels = ["Person", "Organization", "Address"]
        rel_types = "*"

        map_query = """
        CALL gds.louvain.stream({
            nodeProjection: $nodeLabels,
            relationshipProjection: $relTypes
        })
        YIELD nodeId, communityId
        WITH communityId, collect(gds.util.asNode(nodeId)) as members
        WHERE size(members) >= $minSize
        UNWIND members as member
        RETURN 
            communityId,
            labels(member)[0] as type,
            member.name as name,
            member.id as id,
            size(members) as community_size
        ORDER BY community_size DESC, communityId, type, name
        """
        map_params = {"nodeLabels": node_labels, "relTypes": rel_types, "minSize": min_size}

        if self._gds_anonymous_ok is not False:
            try:
                result = self.client.execute(map_query, map_params)
                self._gds_anonymous_ok = True
                return result
            except Exception as e:
                if not self._is_gds_map_error(e):
                    return self._wcc_cypher(min_size)
                self._gds_anonymous_ok = False

        graph_name = self._project_graph(node_labels, rel_types)
        try:
            named_query = """
            CALL gds.louvain.stream($graphName)
            YIELD nodeId, communityId
            WITH communityId, collect(gds.util.asNode(nodeId)) as members
            WHERE size(members) >= $minSize
            UNWIND members as member
            RETURN 
                communityId,
                labels(member)[0] as type,
                member.name as name,
                member.id as id,
                size(members) as community_size
            ORDER BY community_size DESC, communityId, type, name
            """
            return self.client.execute(named_query, {"graphName": graph_name, "minSize": min_size})
        except Exception:
            return self._wcc_cypher(min_size)
        finally:
            self._drop_graph(graph_name)
    
    def _label_propagation_gds(self, min_size: int) -> list[dict]:
        """Label propagation community detection using GDS."""
        node_labels = ["Person", "Organization", "Address"]
        rel_types = "*"

        map_query = """
        CALL gds.labelPropagation.stream({
            nodeProjection: $nodeLabels,
            relationshipProjection: $relTypes
        })
        YIELD nodeId, communityId
        WITH communityId, collect(gds.util.asNode(nodeId)) as members
        WHERE size(members) >= $minSize
        UNWIND members as member
        RETURN 
            communityId,
            labels(member)[0] as type,
            member.name as name,
            member.id as id,
            size(members) as community_size
        ORDER BY community_size DESC, communityId, type, name
        """
        map_params = {"nodeLabels": node_labels, "relTypes": rel_types, "minSize": min_size}

        if self._gds_anonymous_ok is not False:
            try:
                result = self.client.execute(map_query, map_params)
                self._gds_anonymous_ok = True
                return result
            except Exception as e:
                if not self._is_gds_map_error(e):
                    return self._wcc_cypher(min_size)
                self._gds_anonymous_ok = False

        graph_name = self._project_graph(node_labels, rel_types)
        try:
            named_query = """
            CALL gds.labelPropagation.stream($graphName)
            YIELD nodeId, communityId
            WITH communityId, collect(gds.util.asNode(nodeId)) as members
            WHERE size(members) >= $minSize
            UNWIND members as member
            RETURN 
                communityId,
                labels(member)[0] as type,
                member.name as name,
                member.id as id,
                size(members) as community_size
            ORDER BY community_size DESC, communityId, type, name
            """
            return self.client.execute(named_query, {"graphName": graph_name, "minSize": min_size})
        except Exception:
            return self._wcc_cypher(min_size)
        finally:
            self._drop_graph(graph_name)
    
    def _weakly_connected_components(self, min_size: int) -> list[dict]:
        """Find weakly connected components (using GDS if available)."""
        if self.check_gds():
            node_labels = ["Person", "Organization", "Address"]
            rel_types = "*"
            map_query = """
            CALL gds.wcc.stream({
                nodeProjection: $nodeLabels,
                relationshipProjection: $relTypes
            })
            YIELD nodeId, componentId
            WITH componentId, collect(gds.util.asNode(nodeId)) as members
            WHERE size(members) >= $minSize
            UNWIND members as member
            RETURN 
                componentId as communityId,
                labels(member)[0] as type,
                member.name as name,
                member.id as id,
                size(members) as community_size
            ORDER BY community_size DESC, communityId, type, name
            """
            map_params = {"nodeLabels": node_labels, "relTypes": rel_types, "minSize": min_size}

            if self._gds_anonymous_ok is not False:
                try:
                    result = self.client.execute(map_query, map_params)
                    self._gds_anonymous_ok = True
                    return result
                except Exception as e:
                    if not self._is_gds_map_error(e):
                        return self._wcc_cypher(min_size)
                    self._gds_anonymous_ok = False

            graph_name = self._project_graph(node_labels, rel_types)
            try:
                named_query = """
                CALL gds.wcc.stream($graphName)
                YIELD nodeId, componentId
                WITH componentId, collect(gds.util.asNode(nodeId)) as members
                WHERE size(members) >= $minSize
                UNWIND members as member
                RETURN 
                    componentId as communityId,
                    labels(member)[0] as type,
                    member.name as name,
                    member.id as id,
                    size(members) as community_size
                ORDER BY community_size DESC, communityId, type, name
                """
                return self.client.execute(named_query, {"graphName": graph_name, "minSize": min_size})
            except Exception:
                return self._wcc_cypher(min_size)
            finally:
                self._drop_graph(graph_name)

        return self._wcc_cypher(min_size)

    def _wcc_cypher(self, min_size: int) -> list[dict]:
        """Fallback to native Cypher (limited depth to prevent hangs)."""
        query = """
        MATCH (n)
        WHERE n:Person OR n:Organization OR n:Address
        WITH n
        MATCH path = (n)-[*0..3]-(connected)
        WHERE connected:Person OR connected:Organization OR connected:Address
        WITH n, collect(DISTINCT connected) as component
        WHERE size(component) >= $minSize
        WITH component, id(collect(n)[0]) as communityId
        UNWIND component as member
        RETURN 
            communityId,
            labels(member)[0] as type,
            member.name as name,
            member.id as id,
            size(component) as community_size
        ORDER BY community_size DESC, communityId, type, name
        LIMIT 500
        """
        return self.client.execute(query, {"minSize": min_size})
    
    # =========================================================================
    # PATH FINDING
    # =========================================================================
    
    def shortest_path(
        self,
        from_entity: str,
        to_entity: str,
        max_depth: int = 10
    ) -> list[dict]:
        """Find the shortest path between two entities."""
        query = """
        MATCH (start), (end)
        WHERE (start.name = $from OR start.id = $from)
          AND (end.name = $to OR end.id = $to)
        MATCH path = shortestPath((start)-[*..{depth}]-(end))
        UNWIND nodes(path) as node
        UNWIND relationships(path) as rel
        WITH path, 
             collect(DISTINCT {
                 type: labels(node)[0],
                 name: node.name,
                 id: node.id
             }) as path_nodes,
             collect(DISTINCT {
                 type: type(rel),
                 properties: properties(rel)
             }) as path_rels
        RETURN 
            length(path) as path_length,
            path_nodes,
            path_rels
        LIMIT 1
        """.replace("{depth}", str(max_depth))
        
        return self.client.execute(query, {"from": from_entity, "to": to_entity})
    
    def all_paths(
        self,
        from_entity: str,
        to_entity: str,
        max_depth: int = 5,
        limit: int = 10
    ) -> list[dict]:
        """Find all paths between two entities up to max_depth."""
        query = f"""
        MATCH (start), (end)
        WHERE (start.name = $from OR start.id = $from)
          AND (end.name = $to OR end.id = $to)
        MATCH path = (start)-[*1..{max_depth}]-(end)
        WITH path, length(path) as path_length
        ORDER BY path_length
        LIMIT $limit
        UNWIND range(0, length(path)) as idx
        WITH path, path_length, nodes(path)[idx] as node
        WITH path, path_length, collect({{
            type: labels(node)[0],
            name: node.name,
            id: node.id
        }}) as path_nodes
        RETURN path_length, path_nodes
        """
        return self.client.execute(query, {
            "from": from_entity,
            "to": to_entity,
            "limit": limit
        })
    
    def common_connections(
        self,
        entity_a: str,
        entity_b: str
    ) -> list[dict]:
        """Find entities connected to both A and B."""
        query = """
        MATCH (a), (b)
        WHERE (a.name = $entityA OR a.id = $entityA)
          AND (b.name = $entityB OR b.id = $entityB)
        MATCH (a)-[r1]-(common)-[r2]-(b)
        WHERE common <> a AND common <> b
        RETURN DISTINCT
            labels(common)[0] as type,
            common.name as name,
            common.id as id,
            type(r1) as rel_to_a,
            type(r2) as rel_to_b
        ORDER BY type, name
        """
        return self.client.execute(query, {"entityA": entity_a, "entityB": entity_b})
    
    # =========================================================================
    # SIMILARITY & PATTERNS
    # =========================================================================
    
    def similar_entities(
        self,
        entity: str,
        limit: int = 10
    ) -> list[dict]:
        """Find entities with similar connection patterns (Jaccard similarity)."""
        query = """
        MATCH (target)
        WHERE target.name = $entity OR target.id = $entity
        MATCH (target)--(neighbor)
        WITH target, collect(id(neighbor)) as target_neighbors
        
        MATCH (other)
        WHERE other <> target AND labels(other) = labels(target)
        MATCH (other)--(neighbor)
        WITH target, target_neighbors, other, collect(id(neighbor)) as other_neighbors
        
        WITH other,
             [x IN target_neighbors WHERE x IN other_neighbors] as intersection,
             target_neighbors + [x IN other_neighbors WHERE NOT x IN target_neighbors] as union_set
        WITH other, 
             toFloat(size(intersection)) / size(union_set) as jaccard_similarity
        WHERE jaccard_similarity > 0
        
        RETURN 
            labels(other)[0] as type,
            other.name as name,
            other.id as id,
            round(jaccard_similarity * 1000) / 1000 as similarity
        ORDER BY similarity DESC
        LIMIT $limit
        """
        return self.client.execute(query, {"entity": entity, "limit": limit})
    
    def triangles(self, entity: str = None) -> list[dict]:
        """Find triangular relationships (A-B-C-A) - indicates tight clusters."""
        if entity:
            query = """
            MATCH (target)
            WHERE target.name = $entity OR target.id = $entity
            MATCH (target)--(b)--(c)--(target)
            WHERE id(b) < id(c)
            RETURN 
                {type: labels(target)[0], name: target.name, id: target.id} as node_a,
                {type: labels(b)[0], name: b.name, id: b.id} as node_b,
                {type: labels(c)[0], name: c.name, id: c.id} as node_c
            LIMIT 50
            """
            return self.client.execute(query, {"entity": entity})
        else:
            query = """
            MATCH (a)--(b)--(c)--(a)
            WHERE id(a) < id(b) AND id(b) < id(c)
            RETURN 
                {type: labels(a)[0], name: a.name, id: a.id} as node_a,
                {type: labels(b)[0], name: b.name, id: b.id} as node_b,
                {type: labels(c)[0], name: c.name, id: c.id} as node_c
            LIMIT 100
            """
            return self.client.execute(query, {})
    
    # =========================================================================
    # INVESTIGATION-SPECIFIC
    # =========================================================================
    
    def money_flow(
        self,
        source_org: str = None,
        target_org: str = None,
        min_amount: int = None,
        years: list[int] = None
    ) -> list[dict]:
        """Trace grant money flow between organizations."""
        conditions = []
        params = {}
        
        if source_org:
            conditions.append("(source.name = $source OR source.id = $source)")
            params["source"] = source_org
        if target_org:
            conditions.append("(target.name = $target OR target.id = $target)")
            params["target"] = target_org
        if min_amount:
            conditions.append("g.amount >= $minAmount")
            params["minAmount"] = min_amount
        if years:
            conditions.append("g.year IN $years")
            params["years"] = years
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        query = f"""
        MATCH (source:Organization)-[g:GRANTED_TO]->(target:Organization)
        {where_clause}
        RETURN 
            source.name as from_org,
            source.ein as from_ein,
            target.name as to_org,
            target.ein as to_ein,
            g.amount as amount,
            g.year as year,
            g.purpose as purpose
        ORDER BY g.amount DESC
        LIMIT 100
        """
        return self.client.execute(query, params)
    
    def officer_network(self, min_shared: int = 1) -> list[dict]:
        """Find organizations that share officers."""
        query = """
        MATCH (p:Person)-[:OFFICER_OF]->(o1:Organization)
        MATCH (p)-[:OFFICER_OF]->(o2:Organization)
        WHERE id(o1) < id(o2)
        WITH o1, o2, collect(p.name) as shared_officers
        WHERE size(shared_officers) >= $minShared
        RETURN 
            o1.name as org1,
            o1.ein as ein1,
            o2.name as org2,
            o2.ein as ein2,
            shared_officers,
            size(shared_officers) as num_shared
        ORDER BY num_shared DESC
        LIMIT 50
        """
        return self.client.execute(query, {"minShared": min_shared})
    
    def address_cluster(self, address: str) -> list[dict]:
        """Find all entities connected to an address."""
        query = """
        MATCH (addr:Address)
        WHERE addr.full_address CONTAINS $address 
           OR addr.id = $address
        MATCH (addr)<-[:LOCATED_AT|RESIDES_AT]-(entity)
        RETURN 
            addr.full_address as address,
            labels(entity)[0] as entity_type,
            entity.name as entity_name,
            entity.id as entity_id,
            entity.ein as ein
        ORDER BY entity_type, entity_name
        """
        return self.client.execute(query, {"address": address})
    
    def red_flags(self) -> list[dict]:
        """Detect anomalous patterns that warrant investigation."""
        results = []
        
        # 1. Isolated high-value grants (one-time large grants with no other activity)
        query1 = """
        MATCH (source:Organization)-[g:GRANTED_TO]->(target:Organization)
        WHERE g.amount >= 100000
        WITH target, count(DISTINCT source) as num_sources, sum(g.amount) as total
        WHERE num_sources = 1
        RETURN 
            'isolated_high_value_recipient' as flag_type,
            target.name as entity,
            target.ein as ein,
            total as amount,
            'Single source for $100K+ in grants' as description
        ORDER BY total DESC
        LIMIT 10
        """
        results.extend(self.client.execute(query1, {}))
        
        # 2. Circular funding (A funds B funds A)
        query2 = """
        MATCH (a:Organization)-[:GRANTED_TO]->(b:Organization)-[:GRANTED_TO]->(a)
        RETURN 
            'circular_funding' as flag_type,
            a.name + ' <-> ' + b.name as entity,
            null as ein,
            null as amount,
            'Bidirectional grant relationship' as description
        LIMIT 10
        """
        results.extend(self.client.execute(query2, {}))
        
        # 3. Many orgs at same address
        query3 = """
        MATCH (addr:Address)<-[:LOCATED_AT]-(org:Organization)
        WITH addr, collect(org.name) as orgs, count(org) as num_orgs
        WHERE num_orgs >= 5
        RETURN 
            'address_clustering' as flag_type,
            addr.full_address as entity,
            null as ein,
            num_orgs as amount,
            'Multiple organizations at same address' as description
        ORDER BY num_orgs DESC
        LIMIT 10
        """
        results.extend(self.client.execute(query3, {}))
        
        return results
