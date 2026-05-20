from pathlib import Path
from sys import path

path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloud_permission_analyzer.aws_collector import AwsIamCollector
from cloud_permission_analyzer.neo4j_client import Neo4jClient
from cloud_permission_analyzer.seed_data import CONSTRAINTS


def main() -> None:
    with Neo4jClient() as client:
        client.verify()
        client.execute_many(CONSTRAINTS)
        counts = AwsIamCollector(client).collect()
    print(f"Collected AWS IAM graph: {counts}")


if __name__ == "__main__":
    main()
