from __future__ import annotations

import json
import re
from typing import Any, Callable

from cloud_permission_analyzer.neo4j_client import Neo4jClient
from cloud_permission_analyzer.risk_queries import (
    explain_policy,
    find_admin_access,
    find_destructive_access,
    find_identity_risks,
    find_privilege_escalation_paths,
    find_public_exposure,
    find_trust_relationship_risks,
    run_readonly_cypher,
)

try:
    from strands import Agent, tool

    STRANDS_AVAILABLE = True
except Exception:
    Agent = None  # type: ignore[assignment]
    STRANDS_AVAILABLE = False

    def tool(func: Callable[..., Any]) -> Callable[..., Any]:  # type: ignore[no-redef]
        return func


SYSTEM_PROMPT = """
You are Cloud Permission Risk Analyzer, a concise AWS IAM security assistant.
Use the provided tools to inspect the Neo4j IAM graph. Explain findings with:
1. a direct yes/no or risk summary,
2. the permission path evidence,
3. the practical least-privilege fix.
Never claim a permission path exists unless a tool result supports it.
"""


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


@tool
def run_cypher(query: str, params_json: str = "{}") -> str:
    """Run an approved read-only Cypher query against the IAM graph."""
    params = json.loads(params_json or "{}")
    with Neo4jClient() as client:
        return _json(run_readonly_cypher(client, query, params))


@tool
def find_identity_risks_tool(identity_name: str) -> str:
    """Return risky permission paths reachable by a user, group, or role."""
    with Neo4jClient() as client:
        return _json(find_identity_risks(client, identity_name))


@tool
def find_privilege_escalation_paths_tool() -> str:
    """Return likely privilege escalation chains in the graph."""
    with Neo4jClient() as client:
        return _json(find_privilege_escalation_paths(client))


@tool
def find_destructive_access_tool() -> str:
    """Return identities that can perform destructive actions."""
    with Neo4jClient() as client:
        return _json(find_destructive_access(client))


@tool
def find_admin_access_tool() -> str:
    """Return identities that can reach administrator-level access."""
    with Neo4jClient() as client:
        return _json(find_admin_access(client))


@tool
def find_public_exposure_tool() -> str:
    """Return resources or policy statements with public exposure risk."""
    with Neo4jClient() as client:
        return _json(find_public_exposure(client))


@tool
def find_trust_relationship_risks_tool() -> str:
    """Return risky assume-role, pass-role, or trust relationships."""
    with Neo4jClient() as client:
        return _json(find_trust_relationship_risks(client))


@tool
def explain_policy_tool(policy_name: str) -> str:
    """Explain the actions and resources granted by a policy."""
    with Neo4jClient() as client:
        return _json(explain_policy(client, policy_name))


@tool
def recommend_fix_tool(risk_path: str) -> str:
    """Recommend a least-privilege remediation for a risk path."""
    lower_path = risk_path.lower()
    fixes = []
    if "assume" in lower_path or "can_assume" in lower_path:
        fixes.append("Restrict sts:AssumeRole to the smallest trusted principal set.")
    if "passrole" in lower_path or "can_pass_role" in lower_path:
        fixes.append("Scope iam:PassRole to specific roles and require iam:PassedToService.")
    if "lambda" in lower_path:
        fixes.append("Limit lambda:CreateFunction and deployment roles to approved execution roles.")
    if "s3:delete" in lower_path or "prod-bucket" in lower_path:
        fixes.append("Remove destructive S3 actions from production buckets unless explicitly required.")
    if not fixes:
        fixes.append("Replace broad permissions with resource-scoped, action-scoped grants.")
    return "\n".join(f"- {fix}" for fix in fixes)


TOOLS = [
    run_cypher,
    find_identity_risks_tool,
    find_privilege_escalation_paths_tool,
    find_destructive_access_tool,
    find_admin_access_tool,
    find_public_exposure_tool,
    find_trust_relationship_risks_tool,
    explain_policy_tool,
    recommend_fix_tool,
]


def create_agent() -> Any:
    if not STRANDS_AVAILABLE or Agent is None:
        raise RuntimeError("Strands Agents SDK is not installed or could not be imported.")
    return Agent(system_prompt=SYSTEM_PROMPT, tools=TOOLS)


def _extract_identity(question: str) -> str | None:
    known = ["alice", "bob", "carol", "Developers", "DeployRole", "LambdaAdminRole"]
    lowered = question.lower()
    for name in known:
        if name.lower() in lowered:
            return name
    match = re.search(r"\buser\s+([A-Za-z0-9_-]+)\b", question, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _fallback_answer(question: str) -> dict[str, Any]:
    lowered = question.lower()
    with Neo4jClient() as client:
        if "admin" in lowered:
            rows = find_admin_access(client)
            title = "Administrator access paths"
        elif "escalat" in lowered or "privilege" in lowered:
            rows = find_privilege_escalation_paths(client)
            title = "Privilege escalation paths"
        elif "delete" in lowered or "destructive" in lowered:
            identity = _extract_identity(question)
            rows = find_identity_risks(client, identity) if identity else find_destructive_access(client)
            title = f"Risk paths for {identity}" if identity else "Destructive access paths"
        elif "public" in lowered:
            rows = find_public_exposure(client)
            title = "Public exposure risks"
        elif "trust" in lowered or "assume" in lowered or "passrole" in lowered:
            rows = find_trust_relationship_risks(client)
            title = "Trust relationship risks"
        else:
            identity = _extract_identity(question) or "alice"
            rows = find_identity_risks(client, identity)
            title = f"Risk paths for {identity}"

    if rows:
        evidence = rows[:5]
        summary = (
            f"{title}: found {len(rows)} matching graph result(s). "
            "Review the chains below and remove broad assume-role, pass-role, "
            "or destructive production permissions."
        )
    else:
        evidence = []
        summary = f"{title}: no matching risk path was found in the current graph."

    return {
        "answer": summary,
        "evidence": evidence,
        "used_strands": False,
    }


def answer_question(question: str) -> dict[str, Any]:
    if STRANDS_AVAILABLE:
        try:
            agent = create_agent()
            result = agent(question)
            return {"answer": str(result), "evidence": [], "used_strands": True}
        except Exception as exc:
            fallback = _fallback_answer(question)
            fallback["strands_error"] = str(exc)
            return fallback
    return _fallback_answer(question)
