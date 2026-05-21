# Cloud Permission Risk Analyzer

Hackathon MVP for analyzing AWS IAM permission paths with Neo4j and Claude.

The demo models IAM users, groups, roles, policies, actions, resources, and trust relationships as a graph. A user can ask questions such as "Can Alice delete production data?" and receive the exact permission chain plus a least-privilege fix.

## What It Shows

- Seeded IAM graph with a realistic privilege escalation path.
- Neo4j Cypher risk detectors for admin, destructive, escalation, public exposure, and trust risks.
- Claude (Anthropic API) explains each finding as a concise security review.
- FastAPI backend for API demos.
- Streamlit UI for a fast hackathon presentation.
- Optional read-only AWS IAM collector using `boto3`.

## Quick Start

Requires Python 3.10–3.13 and Docker.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
docker compose up -d neo4j
python scripts/seed.py
streamlit run cloud_permission_analyzer/streamlit_app.py
```

Set your Claude API key in `.env`:

```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_claude_api_key
CLAUDE_MODEL=claude-sonnet-4-6
```

Open the Streamlit app and ask:

```text
Can Alice delete production data?
```

Expected graph chain:

```text
alice -> Developers -> DeployRole -> LambdaAdminRole -> s3:DeleteObject -> arn:aws:s3:::prod-bucket/*
```

> **Environment note:** If `python -m venv` fails (for example, a broken Homebrew Python on macOS), [`uv`](https://docs.astral.sh/uv/) is a reliable alternative: `uv venv --python 3.12 && uv pip install -r requirements.txt`.

## LLM Providers

The analyzer selects its provider from `LLM_PROVIDER` in `.env`:

- `anthropic` (default) — calls the Claude API directly. Requires `ANTHROPIC_API_KEY`. The graph query runs first, then Claude explains the result as a security review.
- `strands` — uses a Strands agent backed by AWS Bedrock. Requires AWS credentials with Bedrock model access.
- If the selected provider is unavailable, the app falls back to deterministic Cypher-based graph routing so the demo still works.

## API Demo

Run the API:

```bash
uvicorn cloud_permission_analyzer.api:app --reload
```

Seed the demo graph:

```bash
curl -X POST "http://localhost:8000/seed"
```

Ask a question:

```bash
curl -X POST "http://localhost:8000/ask" \
  -H "Content-Type: application/json" \
  -d '{"question":"Can Alice delete production data?"}'
```

Endpoints:

- `GET /health`
- `POST /seed`
- `POST /collect/aws`
- `POST /ask` with `{"question":"..."}`
- `GET /risks/admin`
- `GET /risks/destructive`
- `GET /risks/escalation`
- `GET /risks/public`
- `GET /risks/trust`
- `POST /risks/identity` with `{"identity_name":"alice"}`
- `POST /policy/explain` with `{"policy_name":"LambdaAdminS3ProductionAccess"}`

## Graph Model

Core labels:

- `Identity`, `User`, `Group`, `Role`
- `Policy`, `Statement`, `Action`, `Resource`, `Service`

Core relationships:

- `MEMBER_OF`
- `ATTACHED_TO`
- `HAS_STATEMENT`
- `ALLOWS`
- `ON_RESOURCE`
- `BELONGS_TO`
- `CAN_ASSUME`
- `CAN_PASS_ROLE`
- `CAN_CREATE_LAMBDA_WITH`

## Strands Agent (optional)

When `LLM_PROVIDER=strands`, the agent in `cloud_permission_analyzer/strands_agent.py` wraps the graph queries as approved tools:

- `run_cypher`
- `find_identity_risks_tool`
- `find_privilege_escalation_paths_tool`
- `find_destructive_access_tool`
- `find_admin_access_tool`
- `find_public_exposure_tool`
- `find_trust_relationship_risks_tool`
- `explain_policy_tool`
- `recommend_fix_tool`

If Strands is unavailable or model credentials are not configured, the app falls back to deterministic graph routing so the demo still works.

## Optional Real AWS Collection

Configure AWS credentials with read-only IAM permissions, then run:

```bash
python scripts/collect_aws.py
```

The collector reads IAM users, groups, roles, attached policies, inline policies, and trust policies, then normalizes them into the same Neo4j model.

Recommended AWS permissions for the collector:

- `iam:ListUsers`
- `iam:ListGroups`
- `iam:ListRoles`
- `iam:ListPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:ListAttachedGroupPolicies`
- `iam:ListAttachedRolePolicies`
- `iam:ListUserPolicies`
- `iam:ListGroupPolicies`
- `iam:ListRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:GetUserPolicy`
- `iam:GetGroupPolicy`
- `iam:GetRolePolicy`

## Demo Story

1. Seed the graph.
2. Ask "Can Alice delete production data?"
3. Show the path from `alice` to `LambdaAdminRole`.
4. Explain that `DeployRole` can pass `LambdaAdminRole` and create Lambda functions.
5. Recommend restricting `sts:AssumeRole`, scoping `iam:PassRole`, and removing destructive S3 access from production resources.
