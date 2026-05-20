from dataclasses import dataclass


@dataclass(frozen=True)
class GraphSchema:
    labels: tuple[str, ...]
    relationships: tuple[str, ...]
    risky_actions: tuple[str, ...]
    escalation_actions: tuple[str, ...]


SCHEMA = GraphSchema(
    labels=(
        "Identity",
        "User",
        "Group",
        "Role",
        "Policy",
        "Statement",
        "Action",
        "Resource",
        "Service",
    ),
    relationships=(
        "MEMBER_OF",
        "ATTACHED_TO",
        "HAS_STATEMENT",
        "ALLOWS",
        "ON_RESOURCE",
        "BELONGS_TO",
        "CAN_ASSUME",
        "CAN_PASS_ROLE",
        "CAN_CREATE_LAMBDA_WITH",
    ),
    risky_actions=(
        "*",
        "*:*",
        "iam:*",
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "dynamodb:DeleteTable",
        "kms:ScheduleKeyDeletion",
        "iam:DeleteUser",
    ),
    escalation_actions=(
        "sts:AssumeRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "lambda:CreateFunction",
    ),
)


SAMPLE_SCENARIO = {
    "question": "Can Alice delete production data?",
    "expected_path": [
        "alice",
        "Developers",
        "DeployRole",
        "LambdaAdminRole",
        "s3:DeleteObject",
        "arn:aws:s3:::prod-bucket/*",
    ],
    "recommended_fix": (
        "Limit Developers' sts:AssumeRole target, restrict DeployRole's "
        "iam:PassRole permission, and scope LambdaAdminRole away from "
        "production S3 resources."
    ),
}
