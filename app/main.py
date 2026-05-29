import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

import json
import streamlit as st

from core.scenario_builder import build_scenario

st.set_page_config(
    page_title="LLM Attack Scenario Generator",
    layout="wide"
)

st.title("LLM-Assisted Dynamic Attack Scenario Generator")

st.write("""
Generate realistic multi-stage cyber attack scenarios
for hybrid cyber ranges.
""")

environment = st.selectbox(
    "Environment Type",
    [
        "Enterprise Network",
        "Cloud Infrastructure",
        "Healthcare Network",
        "Industrial Control System",
        "Hybrid Infrastructure"
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
        "APT Attack",
        "Insider Threat",
        "Credential Theft",
        "Data Exfiltration"
    ]
)

if st.button("Generate Scenario"):

    with st.spinner("Generating dynamic attack scenario..."):

        scenario = build_scenario(
            environment=environment,
            difficulty=difficulty,
            attack_type=attack_type
        )

        st.subheader("Generated Attack Scenario")

        st.json(scenario)

        st.download_button(
            label="Download Scenario JSON",
            data=json.dumps(scenario, indent=4),
            file_name="attack_scenario.json",
            mime="application/json"
        )