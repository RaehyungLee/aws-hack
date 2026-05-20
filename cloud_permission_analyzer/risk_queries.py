from typing import Any

from cloud_permission_analyzer.graph_model import SCHEMA
from cloud_permission_analyzer.neo4j_client import Neo4jClient


TRAVERSAL = "MEMBER_OF|CAN_ASSUME|CAN_PASS_ROLE|CAN_CREATE_LAMBDA_WITH"

READ_ONLY_PREFIXES = ("MATCH", "OPTIONAL MATCH", "RETURN", "WITH", "CALL")


def _path_names(path: dict[str, Any] | None) -> list[str]:
    if not path:
        return []
    names: list[str] = []
    for node in path.get("nodes", []):
        properties = node.get("properties", {})
        names.append(properties.get("name") or properties.get("arn") or properties.get("sid", "node"))
    return names


def _with_chain(row: dict[str, Any]) -> dict[str, Any]:
    chain = _path_names(row.get("path"))
    action = row.get("action")
    resource = row.get("resource")
    if action:
        chain.append(action)
    if resource:
        chain.append(resource)
    return {**row, "chain": " -> ".join(chain)}


def run_readonly_cypher(
    client: Neo4jClient,
    query: str,
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stripped = query.strip().upper()
    if not stripped.startswith(READ_ONLY_PREFIXES):
        raise ValueError("Only read-only Cypher queries are allowed.")
    blocked = (" CREATE ", " MERGE ", " DELETE ", " SET ", " REMOVE ", " DROP ")
    padded = f" {stripped} "
    if any(keyword in padded for keyword in blocked):
        raise ValueError("Mutating Cypher keywords are not allowed.")
    return client.query(query, params)


def find_identity_risks(client: Neo4jClient, identity_name: str) -> list[dict[str, Any]]:
    query = f"""
    MATCH path = (identity:Identity {{name: $identity_name}})
      -[:{TRAVERSAL}*0..5]->(principal:Identity)
    MATCH (principal)-[:ATTACHED_TO]->(policy:Policy)
      -[:HAS_STATEMENT]->(statement:Statement)
      -[:ALLOWS]->(action:Action)
    OPTIONAL MATCH (statement)-[:ON_RESOURCE]->(resource)
    WHERE action.name IN $risky_actions
       OR action.name ENDS WITH ':*'
       OR policy.risk IN ['high', 'critical']
       OR coalesce(resource.sensitivity, '') = 'production'
    RETURN
      path,
      principal.name AS principal,
      policy.name AS policy,
      policy.risk AS policy_risk,
      statement.sid AS statement,
      action.name AS action,
      coalesce(resource.arn, resource.name, 'unknown') AS resource,
      coalesce(resource.sensitivity, 'unknown') AS sensitivity,
      CASE
        WHEN action.name IN ['*', '*:*', 'iam:*'] THEN 'critical'
        WHEN policy.risk = 'critical' THEN 'critical'
        WHEN coalesce(resource.sensitivity, '') = 'production'
             AND action.name CONTAINS 'Delete' THEN 'critical'
        WHEN policy.risk = 'high' THEN 'high'
        ELSE 'medium'
      END AS severity
    ORDER BY severity, principal, policy, action
    LIMIT 25
    """
    rows = client.query(
        query,
        {"identity_name": identity_name, "risky_actions": list(SCHEMA.risky_actions)},
    )
    return [_with_chain(row) for row in rows]


def find_destructive_access(client: Neo4jClient) -> list[dict[str, Any]]:
    destructive_actions = [
        action for action in SCHEMA.risky_actions if "Delete" in action or action in ("*", "*:*")
    ]
    query = f"""
    MATCH path = (identity:Identity)-[:{TRAVERSAL}*0..5]->(principal:Identity)
    MATCH (principal)-[:ATTACHED_TO]->(policy:Policy)
      -[:HAS_STATEMENT]->(statement:Statement)
      -[:ALLOWS]->(action:Action)
    OPTIONAL MATCH (statement)-[:ON_RESOURCE]->(resource)
    WHERE action.name IN $destructive_actions
       OR action.name IN ['*', '*:*']
    RETURN DISTINCT
      identity.name AS identity,
      path,
      principal.name AS principal,
      policy.name AS policy,
      statement.sid AS statement,
      action.name AS action,
      coalesce(resource.arn, resource.name, 'unknown') AS resource,
      coalesce(resource.sensitivity, 'unknown') AS sensitivity,
      CASE
        WHEN coalesce(resource.sensitivity, '') = 'production' THEN 'critical'
        ELSE 'high'
      END AS severity
    ORDER BY severity, identity, action
    LIMIT 50
    """
    return [_with_chain(row) for row in client.query(query, {"destructive_actions": destructive_actions})]


def find_admin_access(client: Neo4jClient) -> list[dict[str, Any]]:
    query = f"""
    MATCH path = (identity:Identity)-[:{TRAVERSAL}*0..5]->(principal:Identity)
    MATCH (principal)-[:ATTACHED_TO]->(policy:Policy)
      -[:HAS_STATEMENT]->(statement:Statement)
      -[:ALLOWS]->(action:Action)
    OPTIONAL MATCH (statement)-[:ON_RESOURCE]->(resource)
    WHERE policy.name = 'AdministratorAccess'
       OR action.name IN ['*', '*:*', 'iam:*']
    RETURN DISTINCT
      identity.name AS identity,
      path,
      principal.name AS principal,
      policy.name AS policy,
      statement.sid AS statement,
      action.name AS action,
      coalesce(resource.arn, resource.name, 'unknown') AS resource,
      'critical' AS severity
    ORDER BY identity, principal
    """
    return [_with_chain(row) for row in client.query(query)]


def find_privilege_escalation_paths(client: Neo4jClient) -> list[dict[str, Any]]:
    query = f"""
    MATCH path = (identity:Identity)-[:{TRAVERSAL}*1..5]->(target:Role)
    WHERE any(rel IN relationships(path)
      WHERE type(rel) IN ['CAN_ASSUME', 'CAN_PASS_ROLE', 'CAN_CREATE_LAMBDA_WITH'])
    OPTIONAL MATCH (target)-[:ATTACHED_TO]->(policy:Policy)
    WITH identity, target, path, collect(DISTINCT policy.name) AS target_policies
    RETURN DISTINCT
      identity.name AS identity,
      target.name AS target_role,
      path,
      target_policies,
      CASE
        WHEN 'AdministratorAccess' IN target_policies THEN 'critical'
        WHEN any(policy IN target_policies WHERE policy CONTAINS 'Admin') THEN 'critical'
        ELSE 'high'
      END AS severity
    ORDER BY severity, identity, target_role
    LIMIT 50
    """
    rows = client.query(query)
    return [{**row, "chain": " -> ".join(_path_names(row.get("path")))} for row in rows]


def find_public_exposure(client: Neo4jClient) -> list[dict[str, Any]]:
    query = """
    MATCH (policy:Policy)-[:HAS_STATEMENT]->(statement:Statement)
      -[:ALLOWS]->(action:Action)
    MATCH (statement)-[:ON_RESOURCE]->(resource:Resource)
    WHERE coalesce(resource.public, false) = true
       OR statement.principal IN ['*', 'anonymous']
       OR resource.arn CONTAINS ':public'
    RETURN
      policy.name AS policy,
      statement.sid AS statement,
      statement.principal AS principal,
      action.name AS action,
      resource.arn AS resource,
      coalesce(resource.sensitivity, 'unknown') AS sensitivity,
      CASE
        WHEN coalesce(resource.sensitivity, '') = 'production' THEN 'critical'
        ELSE 'medium'
      END AS severity
    ORDER BY severity, policy
    """
    return client.query(query)


def find_trust_relationship_risks(client: Neo4jClient) -> list[dict[str, Any]]:
    query = """
    MATCH (principal:Identity)-[rel:CAN_ASSUME|CAN_PASS_ROLE|CAN_CREATE_LAMBDA_WITH]->(role:Role)
    WHERE principal.name IN ['*', 'anonymous']
       OR coalesce(role.trust, '') CONTAINS 'external'
       OR type(rel) IN ['CAN_PASS_ROLE', 'CAN_CREATE_LAMBDA_WITH']
    RETURN
      principal.name AS principal,
      type(rel) AS relationship,
      role.name AS role,
      rel.via AS via_policy,
      role.trust AS trust,
      CASE
        WHEN type(rel) IN ['CAN_PASS_ROLE', 'CAN_CREATE_LAMBDA_WITH'] THEN 'high'
        ELSE 'medium'
      END AS severity
    ORDER BY severity, principal, role
    """
    return client.query(query)


def explain_policy(client: Neo4jClient, policy_name: str) -> list[dict[str, Any]]:
    query = """
    MATCH (policy:Policy {name: $policy_name})-[:HAS_STATEMENT]->(statement:Statement)
      -[:ALLOWS]->(action:Action)
    OPTIONAL MATCH (statement)-[:ON_RESOURCE]->(resource)
    RETURN
      policy.name AS policy,
      policy.risk AS policy_risk,
      statement.sid AS statement,
      statement.effect AS effect,
      action.name AS action,
      coalesce(resource.arn, resource.name, 'unknown') AS resource,
      coalesce(resource.sensitivity, 'unknown') AS sensitivity
    ORDER BY statement, action
    """
    return client.query(query, {"policy_name": policy_name})
