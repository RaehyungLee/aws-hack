from pathlib import Path
from sys import path

path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from cloud_permission_analyzer.neo4j_client import Neo4jClient
from cloud_permission_analyzer.risk_queries import (
    find_admin_access,
    find_destructive_access,
    find_identity_risks,
    find_privilege_escalation_paths,
    find_public_exposure,
    find_trust_relationship_risks,
)
from cloud_permission_analyzer.seed_data import seed_database
from cloud_permission_analyzer.strands_agent import answer_question


st.set_page_config(page_title="Cloud Permission Risk Analyzer", layout="wide")

st.title("Cloud Permission Risk Analyzer")
st.caption("Strands agent + Neo4j graph analysis for AWS IAM permission paths")


def run_query(fn):
    with Neo4jClient() as client:
        return fn(client)


with st.sidebar:
    st.header("Demo Setup")
    if st.button("Seed sample IAM graph", type="primary"):
        with st.spinner("Loading sample graph into Neo4j..."):
            run_query(lambda client: seed_database(client, reset=True))
        st.success("Sample IAM graph loaded.")

    st.markdown("Example questions:")
    st.markdown("- Can Alice delete production data?")
    st.markdown("- Which identities can escalate privileges?")
    st.markdown("- Who has administrator access?")
    st.markdown("- What trust relationships are risky?")


question = st.text_input(
    "Ask a security question",
    value="Can Alice delete production data?",
)

if st.button("Analyze") and question:
    with st.spinner("Analyzing permission graph..."):
        response = answer_question(question)
    st.subheader("Agent Answer")
    st.write(response.get("answer", "No answer returned."))
    if response.get("strands_error"):
        st.info(
            "Strands was unavailable, so the deterministic graph fallback answered this question."
        )
        st.code(response["strands_error"])
    evidence = response.get("evidence") or []
    if evidence:
        st.subheader("Graph Evidence")
        st.dataframe(evidence, use_container_width=True)


st.divider()
st.subheader("Risk Detectors")

col1, col2, col3 = st.columns(3)

with col1:
    identity_name = st.text_input("Identity", value="alice")
    if st.button("Find identity risks"):
        st.dataframe(
            run_query(lambda client: find_identity_risks(client, identity_name)),
            use_container_width=True,
        )

with col2:
    if st.button("Find destructive access"):
        st.dataframe(run_query(find_destructive_access), use_container_width=True)
    if st.button("Find admin access"):
        st.dataframe(run_query(find_admin_access), use_container_width=True)

with col3:
    if st.button("Find escalation paths"):
        st.dataframe(run_query(find_privilege_escalation_paths), use_container_width=True)
    if st.button("Find trust risks"):
        st.dataframe(run_query(find_trust_relationship_risks), use_container_width=True)
    if st.button("Find public exposure"):
        st.dataframe(run_query(find_public_exposure), use_container_width=True)
