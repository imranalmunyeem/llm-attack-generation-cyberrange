import sys
import os
import json
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from core.llm_generator import generate_attack_scenario

st.set_page_config(page_title="LLM Attack Generator", layout="wide")

st.title("LLM-Assisted Cyber Attack Scenario Generator")

environment = st.selectbox(
    "Environment Type",
    ["Enterprise Network", "Cloud Infrastructure", "Healthcare", "ICS"]
)

difficulty = st.selectbox(
    "Difficulty",
    ["Easy", "Medium", "Hard"]
)

attack_type = st.selectbox(
    "Attack Type",
    ["Ransomware", "Phishing", "APT", "Insider Threat"]
)

if st.button("Generate Scenario"):

    with st.spinner("Generating scenario using GPT-4o..."):

        raw_output = generate_attack_scenario(
            environment,
            difficulty,
            attack_type
        )

        # 🔥 SAFE PARSING (NO CRASH)
        try:
            scenario = json.loads(raw_output)
            st.success("Scenario generated successfully")
            st.json(scenario)

            st.download_button(
                "Download JSON",
                json.dumps(scenario, indent=4),
                file_name="scenario.json",
                mime="application/json"
            )

        except Exception as e:
            st.error("JSON Parse Failed")
            st.code(raw_output)
            st.exception(e)