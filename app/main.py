import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

import streamlit as st

from core.llm_generator import generate_attack_scenario

st.set_page_config(
    page_title="LLM Attack Scenario Generator",
    layout="wide"
)

st.title("LLM-Assisted Attack Scenario Generator")

st.write("""
Generate realistic cyber attack scenarios
for hybrid cyber ranges.
""")

environment = st.selectbox(
    "Environment Type",
    [
        "Enterprise Network",
        "Cloud Environment",
        "Hybrid Infrastructure",
        "Healthcare Network",
        "Industrial Control System"
    ]
)

difficulty = st.selectbox(
    "Difficulty",
    [
        "Easy",
        "Medium",
        "Hard"
    ]
)

attack_type = st.selectbox(
    "Attack Type",
    [
        "Ransomware",
        "Phishing",
        "Insider Threat",
        "APT Attack",
        "Data Exfiltration"
    ]
)

if st.button("Generate Scenario"):

    with st.spinner("Generating attack scenario..."):

        scenario = generate_attack_scenario(
            environment=environment,
            difficulty=difficulty,
            attack_type=attack_type
        )

        st.subheader("Generated Scenario")

        st.code(scenario, language="json")