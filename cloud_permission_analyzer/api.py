from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from cloud_permission_analyzer.aws_collector import AwsIamCollector
from cloud_permission_analyzer.neo4j_client import Neo4jClient
from cloud_permission_analyzer.risk_queries import (
    explain_policy,
    find_admin_access,
    find_destructive_access,
    find_identity_risks,
    find_privilege_escalation_paths,
    find_public_exposure,
    find_trust_relationship_risks,
)
from cloud_permission_analyzer.seed_data import seed_database
from cloud_permission_analyzer.strands_agent import answer_question


app = FastAPI(title="Cloud Permission Risk Analyzer", version="0.1.0")


class QuestionRequest(BaseModel):
    question: str = Field(..., min_length=3)


class IdentityRequest(BaseModel):
    identity_name: str = Field(..., min_length=1)


class PolicyRequest(BaseModel):
    policy_name: str = Field(..., min_length=1)


def _with_client(operation: Any) -> Any:
    try:
        with Neo4jClient() as client:
            return operation(client)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict[str, str]:
    def check(client: Neo4jClient) -> dict[str, str]:
        client.verify()
        return {"status": "ok"}

    return _with_client(check)


@app.post("/seed")
def seed(reset: bool = True) -> dict[str, str]:
    def load(client: Neo4jClient) -> dict[str, str]:
        seed_database(client, reset=reset)
        return {"status": "seeded"}

    return _with_client(load)


@app.post("/collect/aws")
def collect_aws() -> dict[str, int]:
    def collect(client: Neo4jClient) -> dict[str, int]:
        return AwsIamCollector(client).collect()

    return _with_client(collect)


@app.post("/ask")
def ask(request: QuestionRequest) -> dict[str, Any]:
    try:
        return answer_question(request.question)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/risks/identity")
def identity_risks(request: IdentityRequest) -> list[dict[str, Any]]:
    return _with_client(lambda client: find_identity_risks(client, request.identity_name))


@app.get("/risks/destructive")
def destructive_access() -> list[dict[str, Any]]:
    return _with_client(find_destructive_access)


@app.get("/risks/admin")
def admin_access() -> list[dict[str, Any]]:
    return _with_client(find_admin_access)


@app.get("/risks/escalation")
def privilege_escalation() -> list[dict[str, Any]]:
    return _with_client(find_privilege_escalation_paths)


@app.get("/risks/public")
def public_exposure() -> list[dict[str, Any]]:
    return _with_client(find_public_exposure)


@app.get("/risks/trust")
def trust_relationships() -> list[dict[str, Any]]:
    return _with_client(find_trust_relationship_risks)


@app.post("/policy/explain")
def policy_explain(request: PolicyRequest) -> list[dict[str, Any]]:
    return _with_client(lambda client: explain_policy(client, request.policy_name))
