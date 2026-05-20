from pathlib import Path
from sys import path

path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloud_permission_analyzer.neo4j_client import Neo4jClient
from cloud_permission_analyzer.seed_data import seed_database


def main() -> None:
    with Neo4jClient() as client:
        client.verify()
        seed_database(client, reset=True)
    print("Seeded Neo4j with the sample IAM permission graph.")


if __name__ == "__main__":
    main()
