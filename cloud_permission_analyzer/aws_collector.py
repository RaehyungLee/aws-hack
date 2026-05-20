from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import boto3

from cloud_permission_analyzer.config import get_settings
from cloud_permission_analyzer.neo4j_client import Neo4jClient


def _as_list(value: Any) -> list[str]:
    if value is None:
        return ["*"]
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if statement.get("Effect") == "Allow"]


class AwsIamCollector:
    """Read-only IAM collector that normalizes AWS IAM into the Neo4j model."""

    def __init__(self, client: Neo4jClient, region_name: str | None = None) -> None:
        settings = get_settings()
        self.graph = client
        self.iam = boto3.client("iam", region_name=region_name or settings.aws_region)

    def collect(self) -> dict[str, int]:
        counts = {"users": 0, "groups": 0, "roles": 0, "policies": 0}
        for group in self._paginate("list_groups", "Groups"):
            self._merge_identity("Group", group["GroupName"], group)
            self._load_group_policies(group["GroupName"])
            counts["groups"] += 1

        for user in self._paginate("list_users", "Users"):
            self._merge_identity("User", user["UserName"], user)
            for group in self.iam.list_groups_for_user(UserName=user["UserName"])["Groups"]:
                self._merge_member_of(user["UserName"], group["GroupName"])
            self._load_user_policies(user["UserName"])
            counts["users"] += 1

        for role in self._paginate("list_roles", "Roles"):
            self._merge_identity("Role", role["RoleName"], role)
            self._load_role_policies(role["RoleName"])
            self._load_trust_policy(role)
            counts["roles"] += 1

        policy_count = self.graph.query("MATCH (p:Policy) RETURN count(p) AS count")
        counts["policies"] = policy_count[0]["count"] if policy_count else 0
        return counts

    def _paginate(self, operation_name: str, result_key: str) -> Iterable[dict[str, Any]]:
        paginator = self.iam.get_paginator(operation_name)
        for page in paginator.paginate():
            yield from page[result_key]

    def _merge_identity(self, label: str, name: str, properties: dict[str, Any]) -> None:
        safe = {
            key: str(value)
            for key, value in properties.items()
            if key not in {"AssumeRolePolicyDocument", "Tags"}
        }
        safe["name"] = name
        self.graph.query(
            f"""
            MERGE (identity:Identity:{label} {{name: $name}})
            SET identity += $properties
            """,
            {"name": name, "properties": safe},
        )

    def _merge_member_of(self, user_name: str, group_name: str) -> None:
        self.graph.query(
            """
            MATCH (user:User {name: $user_name})
            MATCH (group:Group {name: $group_name})
            MERGE (user)-[:MEMBER_OF]->(group)
            """,
            {"user_name": user_name, "group_name": group_name},
        )

    def _load_user_policies(self, user_name: str) -> None:
        for attached in self.iam.list_attached_user_policies(UserName=user_name)[
            "AttachedPolicies"
        ]:
            self._load_managed_policy("User", user_name, attached["PolicyArn"])
        for policy_name in self.iam.list_user_policies(UserName=user_name)["PolicyNames"]:
            document = self.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            self._load_inline_policy("User", user_name, policy_name, document)

    def _load_group_policies(self, group_name: str) -> None:
        for attached in self.iam.list_attached_group_policies(GroupName=group_name)[
            "AttachedPolicies"
        ]:
            self._load_managed_policy("Group", group_name, attached["PolicyArn"])
        for policy_name in self.iam.list_group_policies(GroupName=group_name)["PolicyNames"]:
            document = self.iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            self._load_inline_policy("Group", group_name, policy_name, document)

    def _load_role_policies(self, role_name: str) -> None:
        for attached in self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]:
            self._load_managed_policy("Role", role_name, attached["PolicyArn"])
        for policy_name in self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            document = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            self._load_inline_policy("Role", role_name, policy_name, document)

    def _load_managed_policy(self, principal_label: str, principal_name: str, policy_arn: str) -> None:
        policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = self.iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy["DefaultVersionId"],
        )["PolicyVersion"]
        self._merge_policy(
            principal_label,
            principal_name,
            policy["PolicyName"],
            policy_arn,
            "managed",
            version["Document"],
        )

    def _load_inline_policy(
        self,
        principal_label: str,
        principal_name: str,
        policy_name: str,
        document: dict[str, Any],
    ) -> None:
        self._merge_policy(
            principal_label,
            principal_name,
            f"{principal_name}:{policy_name}",
            f"inline:{principal_name}:{policy_name}",
            "inline",
            document,
        )

    def _merge_policy(
        self,
        principal_label: str,
        principal_name: str,
        policy_name: str,
        policy_arn: str,
        policy_type: str,
        document: dict[str, Any],
    ) -> None:
        risk = self._policy_risk(document)
        self.graph.query(
            f"""
            MATCH (principal:{principal_label} {{name: $principal_name}})
            MERGE (policy:Policy {{name: $policy_name}})
            SET policy.arn = $policy_arn,
                policy.type = $policy_type,
                policy.risk = $risk
            MERGE (principal)-[:ATTACHED_TO]->(policy)
            """,
            {
                "principal_name": principal_name,
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_type": policy_type,
                "risk": risk,
            },
        )
        for index, statement in enumerate(_statements(document)):
            raw_sid = statement.get("Sid") or f"statement:{index}"
            sid = f"{policy_name}:{raw_sid}"
            self._merge_statement(principal_label, principal_name, policy_name, sid, statement)

    def _merge_statement(
        self,
        principal_label: str,
        principal_name: str,
        policy_name: str,
        sid: str,
        statement: dict[str, Any],
    ) -> None:
        self.graph.query(
            """
            MATCH (policy:Policy {name: $policy_name})
            MERGE (statement:Statement {sid: $sid})
            SET statement.effect = 'Allow'
            MERGE (policy)-[:HAS_STATEMENT]->(statement)
            """,
            {"policy_name": policy_name, "sid": sid},
        )
        for action in _as_list(statement.get("Action")):
            service = action.split(":", 1)[0] if ":" in action else "all"
            self.graph.query(
                """
                MATCH (statement:Statement {sid: $sid})
                MERGE (action:Action {name: $action})
                MERGE (service:Service {name: $service})
                MERGE (statement)-[:ALLOWS]->(action)
                MERGE (action)-[:BELONGS_TO]->(service)
                """,
                {"sid": sid, "action": action, "service": service},
            )
        for resource in _as_list(statement.get("Resource")):
            self.graph.query(
                """
                MATCH (statement:Statement {sid: $sid})
                MERGE (resource:Resource {arn: $resource})
                SET resource.name = $resource
                MERGE (statement)-[:ON_RESOURCE]->(resource)
                """,
                {"sid": sid, "resource": resource},
            )
        self._merge_derived_relationships(principal_label, principal_name, policy_name, statement)

    def _merge_derived_relationships(
        self,
        principal_label: str,
        principal_name: str,
        policy_name: str,
        statement: dict[str, Any],
    ) -> None:
        actions = set(_as_list(statement.get("Action")))
        resources = _as_list(statement.get("Resource"))
        for resource in resources:
            role_name = resource.rsplit("/", 1)[-1]
            if "sts:AssumeRole" in actions:
                self.graph.query(
                    f"""
                    MATCH (principal:{principal_label} {{name: $principal_name}})
                    MATCH (role:Role)
                    WHERE role.name = $role_name OR role.Arn = $resource OR role.arn = $resource
                    MERGE (principal)-[:CAN_ASSUME {{via: $policy_name}}]->(role)
                    """,
                    {
                        "principal_name": principal_name,
                        "role_name": role_name,
                        "resource": resource,
                        "policy_name": policy_name,
                    },
                )
            if "iam:PassRole" in actions:
                self.graph.query(
                    f"""
                    MATCH (principal:{principal_label} {{name: $principal_name}})
                    MATCH (role:Role)
                    WHERE role.name = $role_name OR role.Arn = $resource OR role.arn = $resource
                    MERGE (principal)-[:CAN_PASS_ROLE {{via: $policy_name}}]->(role)
                    """,
                    {
                        "principal_name": principal_name,
                        "role_name": role_name,
                        "resource": resource,
                        "policy_name": policy_name,
                    },
                )

    def _load_trust_policy(self, role: dict[str, Any]) -> None:
        role_name = role["RoleName"]
        document = role.get("AssumeRolePolicyDocument", {})
        for statement in _statements(document):
            principal = statement.get("Principal", {})
            principals = []
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for value in principal.values():
                    principals.extend(_as_list(value))
            for principal_name in principals:
                normalized = principal_name.rsplit("/", 1)[-1]
                if normalized == "*":
                    normalized = "anonymous"
                self.graph.query(
                    """
                    MERGE (principal:Identity {name: $principal_name})
                    WITH principal
                    MATCH (role:Role {name: $role_name})
                    MERGE (principal)-[:CAN_ASSUME {via: 'trust-policy'}]->(role)
                    """,
                    {"principal_name": normalized, "role_name": role_name},
                )

    def _policy_risk(self, document: dict[str, Any]) -> str:
        for statement in _statements(document):
            actions = set(_as_list(statement.get("Action")))
            resources = set(_as_list(statement.get("Resource")))
            if "*" in actions or "*:*" in actions:
                return "critical"
            if any(action in actions for action in ["iam:*", "iam:PassRole"]):
                return "high"
            if "*" in resources and any(action.endswith(":*") for action in actions):
                return "high"
        return "medium"
