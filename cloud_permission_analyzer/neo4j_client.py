from collections.abc import Iterable
from contextlib import AbstractContextManager
from typing import Any

from neo4j import GraphDatabase
from neo4j.graph import Node, Path, Relationship

from cloud_permission_analyzer.config import get_settings


def serialize_neo4j(value: Any) -> Any:
    if isinstance(value, Node):
        return {
            "id": value.element_id,
            "labels": sorted(value.labels),
            "properties": dict(value),
        }
    if isinstance(value, Relationship):
        return {
            "id": value.element_id,
            "type": value.type,
            "start": value.start_node.element_id,
            "end": value.end_node.element_id,
            "properties": dict(value),
        }
    if isinstance(value, Path):
        return {
            "nodes": [serialize_neo4j(node) for node in value.nodes],
            "relationships": [serialize_neo4j(rel) for rel in value.relationships],
        }
    if isinstance(value, list):
        return [serialize_neo4j(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_neo4j(item) for key, item in value.items()}
    return value


class Neo4jClient(AbstractContextManager["Neo4jClient"]):
    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        settings = get_settings()
        self.driver = GraphDatabase.driver(
            uri or settings.neo4j_uri,
            auth=(user or settings.neo4j_user, password or settings.neo4j_password),
        )

    def close(self) -> None:
        self.driver.close()

    def __exit__(self, *args: object) -> None:
        self.close()

    def verify(self) -> None:
        self.driver.verify_connectivity()

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        with self.driver.session() as session:
            result = session.run(cypher, params or {})
            return [
                {key: serialize_neo4j(value) for key, value in record.items()}
                for record in result
            ]

    def execute_many(self, statements: Iterable[str]) -> None:
        with self.driver.session() as session:
            for statement in statements:
                session.run(statement).consume()
