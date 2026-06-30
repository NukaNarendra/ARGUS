import streamlit as st
import pandas as pd
import json
import os

# --- Configuration & Styling ---
st.set_page_config(page_title="ARGUS Dashboard", page_icon="🛡️", layout="wide")

# Custom CSS for better UI
st.markdown("""
    <style>
    .metric-card {
        background-color: #1e1e1e;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #333;
    }
    .metric-value {
        font-size: 36px;
        font-weight: bold;
        color: #ff4b4b;
    }
    .metric-value-safe {
        font-size: 36px;
        font-weight: bold;
        color: #00cc96;
    }
    .metric-label {
        font-size: 14px;
        color: #a0a0a0;
    }
    </style>
""", unsafe_allow_html=True)

# --- Data Loading ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "analysis", "results")


def load_json(filename):
    path = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# Load all datasets
single_agent_baseline = load_json("single_agent_metrics.json")
single_agent_hardened = load_json("hardened_metrics.json")
multimodel_baseline = load_json("multimodel_comparison.json")
multimodel_hardened = load_json("multimodel_hardened_comparison.json")
defense_telemetry = load_json("defense_telemetry.json")

# --- UI Header ---
st.title("🛡️ ARGUS: Vulnerability & Defense Dashboard")
st.markdown("""
This dashboard visualizes the findings of the **ARGUS Framework**, measuring how Large Language Models handle adversarial intent hidden within structured JSON tool outputs versus plain text, and demonstrating the effectiveness of the Constitutional Guard and PAP defenses.
""")

st.divider()

# --- Section 1: The Multi-Model Matrix ---
st.header("📊 Multi-Model Vulnerability Matrix")
st.markdown("Comparing how different architectures handle baseline text attacks versus JSON semantic trust attacks.")

if multimodel_baseline:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("⚠️ Baseline (No Defenses)")
        baseline_data = []
        for model, results in multimodel_baseline.items():
            for res in results:
                fmt = res.get("format", "unknown")
                score = res.get("evaluation", {}).get("cds", {}).get("score", 0.0)
                baseline_data.append({"Model": model, "Format": fmt, "CDS Score (0-1)": score})

        df_baseline = pd.DataFrame(baseline_data)
        if not df_baseline.empty:
            # Group by Model and Format to get averages
            df_baseline_avg = df_baseline.groupby(['Model', 'Format']).mean().reset_index()
            # Pivot table for better display
            pivot_baseline = df_baseline_avg.pivot(index="Model", columns="Format", values="CDS Score (0-1)").fillna(0)

            # Apply styling (heat map) with a graceful fallback if matplotlib is missing
            try:
                st.dataframe(pivot_baseline.style.background_gradient(cmap="Reds", vmin=0, vmax=1), width="stretch")
            except ImportError:
                st.dataframe(pivot_baseline, width="stretch")
                st.warning("💡 Tip: Run `pip install matplotlib` in your terminal to see the heatmap colors!")

    with col2:
        st.subheader("🛡️ Hardened (Guard & PAP Active)")
        if multimodel_hardened:
            hardened_data = []
            for model, results in multimodel_hardened.items():
                for res in results:
                    fmt = res.get("format", "unknown")
                    score = res.get("evaluation", {}).get("cds", {}).get("score", 0.0)
                    hardened_data.append({"Model": model, "Format": fmt, "CDS Score (0-1)": score})

            df_hardened = pd.DataFrame(hardened_data)
            if not df_hardened.empty:
                df_hardened_avg = df_hardened.groupby(['Model', 'Format']).mean().reset_index()
                pivot_hardened = df_hardened_avg.pivot(index="Model", columns="Format",
                                                       values="CDS Score (0-1)").fillna(0)

                try:
                    st.dataframe(pivot_hardened.style.background_gradient(cmap="Greens_r", vmin=0, vmax=1),
                                 width="stretch")
                except ImportError:
                    st.dataframe(pivot_hardened, width="stretch")
        else:
            st.info("Run `python src/pipeline.py --run multimodel-hardened` to see this data.")

else:
    st.info("Run `python src/pipeline.py --run multimodel` to populate this matrix.")

st.divider()

# --- Section 2: Defense Telemetry ---
st.header("🔐 Defense Telemetry")
if defense_telemetry:
    col1, col2, col3, col4 = st.columns(4)

    guard_metrics = defense_telemetry.get("constitutional_guard", {})
    pap_metrics = defense_telemetry.get("pap_protocol", {})

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Guard Inspections</div>
            <div class="metric-value-safe">{guard_metrics.get('total_inspections', 0)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Malicious Fields Redacted</div>
            <div class="metric-value">{guard_metrics.get('redactions_applied', 0)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">PAP Signatures Verified</div>
            <div class="metric-value-safe">{pap_metrics.get('signatures_verified', 0)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Forged Claims Blocked</div>
            <div class="metric-value">{pap_metrics.get('verification_failures', 0) + pap_metrics.get('replay_attacks_blocked', 0)}</div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("Run the hardened pipeline to populate telemetry.")

st.divider()

# --- Section 3: Deep Dive Analytics ---
st.header("🔍 Deep Dive: Attack Vectors")
if single_agent_baseline:
    # Process single agent data
    sa_data = []
    for res in single_agent_baseline:
        sa_data.append({
            "Intent ID": res["intent_id"],
            "Format": res["format"],
            "JSON Type": res.get("json_attack_type", "N/A"),
            "CDS (Constitutional Deviation)": res["evaluation"]["cds"]["score"],
            "PTCI (Trust Confusion)": res["evaluation"]["ptci"]["score"],
            "Violation Flagged": res["evaluation"]["cds"]["flagged"]
        })

    df_sa = pd.DataFrame(sa_data)

    # Filter for JSON attacks
    df_json = df_sa[df_sa["Format"] == "json"]

    if not df_json.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Vulnerability by JSON Attack Type")
            avg_by_type = df_json.groupby("JSON Type")["CDS (Constitutional Deviation)"].mean().sort_values(
                ascending=False)
            st.bar_chart(avg_by_type, color="#ff4b4b")

        with col2:
            st.subheader("Trust Confusion (PTCI)")
            ptci_by_type = df_json.groupby("JSON Type")["PTCI (Trust Confusion)"].mean().sort_values(ascending=False)
            st.bar_chart(ptci_by_type, color="#ffa500")

        st.subheader("Raw Execution Logs")
        st.dataframe(df_sa, width="stretch")
else:
    st.info("Run `python src/pipeline.py --run phase2` to populate deep dive analytics.")