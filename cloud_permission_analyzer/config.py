from functools import lru_cache
from os import getenv

from dotenv import load_dotenv
from pydantic import BaseModel


class Settings(BaseModel):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    aws_region: str = "us-east-1"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv()
    return Settings(
        neo4j_uri=getenv("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=getenv("NEO4J_USER", "neo4j"),
        neo4j_password=getenv("NEO4J_PASSWORD", "password"),
        aws_region=getenv("AWS_REGION", "us-east-1"),
    )
