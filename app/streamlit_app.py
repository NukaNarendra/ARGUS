import streamlit as st
import pandas as pd
import json
import os
import sys
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

st.set_page_config(page_title="ARGUS Defense Intelligence", page_icon="🛡️", layout="wide")

RESULTS_DIR = os.path.join(BASE_DIR, "analysis", "results")


def inject_custom_css():
    st.markdown("""
        <style>
        .stApp { background-color: #0e1117; color: #fafafa; }
        .metric-container { background-color: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 20px; text-align: center; }
        .metric-title { font-size: 16px; color: #a0a0a0; text-transform: uppercase; letter-spacing: 1px; }
        .metric-val-danger { font-size: 36px; font-weight: 800; color: #ff4b4b; }
        .metric-val-safe { font-size: 36px; font-weight: 800; color: #00cc96; }
        .metric-val-neutral { font-size: 36px; font-weight: 800; color: #3498db; }
        .header-box { border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        </style>
    """, unsafe_allow_html=True)


@st.cache_data
def fetch_json_payload(filename: str) -> dict:
    path = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def process_matrix_dataframe(baseline_dict: dict, hardened_dict: dict) -> pd.DataFrame:
    rows = []
    models_detected = list(set(list(baseline_dict.keys()) + list(hardened_dict.keys())))
    for m in models_detected:
        for fmt in ["text", "json_semantic_trust", "json_type_confusion", "json_deep_nesting"]:
            b_scores = [i["evaluation"]["cds"]["score"] for i in baseline_dict.get(m, []) if i.get("format") == fmt]
            h_scores = [i["evaluation"]["cds"]["score"] for i in hardened_dict.get(m, []) if i.get("format") == fmt]
            b_ptci = [i["evaluation"]["ptci"]["score"] for i in baseline_dict.get(m, []) if i.get("format") == fmt]
            h_ptci = [i["evaluation"]["ptci"]["score"] for i in hardened_dict.get(m, []) if i.get("format") == fmt]

            b_avg = float(np.mean(b_scores)) if b_scores else 0.0
            h_avg = float(np.mean(h_scores)) if h_scores else 0.0
            b_ptci_avg = float(np.mean(b_ptci)) if b_ptci else 0.0
            h_ptci_avg = float(np.mean(h_ptci)) if h_ptci else 0.0

            if b_scores or h_scores:
                rows.append({
                    "Architecture": m,
                    "Attack Vector": fmt.replace("_", " ").title(),
                    "Baseline Deviation (CDS)": b_avg,
                    "Hardened Deviation (CDS)": h_avg,
                    "Baseline Trust Index (PTCI)": b_ptci_avg,
                    "Hardened Trust Index (PTCI)": h_ptci_avg,
                    "Efficacy Reduction %": ((b_avg - h_avg) / b_avg * 100) if b_avg > 0 else 0.0
                })
    return pd.DataFrame(rows)


inject_custom_css()

st.markdown('<div class="header-box"><h1>🛡️ ARGUS Defense Intelligence Center</h1></div>', unsafe_allow_html=True)
st.markdown("Advanced visualization and statistical modeling for Tool-Level Principal Injection mitigation frameworks.")

col_a, col_b = st.columns([5, 1])
with col_b:
    if st.button("Purge Cache & Sync", type="primary", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

data_baseline = fetch_json_payload("multimodel_comparison.json")
data_hardened = fetch_json_payload("multimodel_hardened_comparison.json")
data_telemetry = fetch_json_payload("defense_telemetry.json")

df_matrix = process_matrix_dataframe(data_baseline, data_hardened)

tab_exec, tab_matrix, tab_radar, tab_telemetry, tab_stats = st.tabs([
    "Executive Overview", "Vulnerability Matrix", "Radar Topography", "Protocol Telemetry", "Mathematical Models"
])

with tab_exec:
    st.subheader("Global Defense Efficacy")
    if not df_matrix.empty:
        global_b_cds = df_matrix["Baseline Deviation (CDS)"].mean()
        global_h_cds = df_matrix["Hardened Deviation (CDS)"].mean()
        global_reduction = df_matrix["Efficacy Reduction %"].mean()

        m1, m2, m3 = st.columns(3)
        m1.markdown(
            f'<div class="metric-container"><div class="metric-title">Mean Baseline Vulnerability</div><div class="metric-val-danger">{global_b_cds:.3f}</div></div>',
            unsafe_allow_html=True)
        m2.markdown(
            f'<div class="metric-container"><div class="metric-title">Mean Hardened Vulnerability</div><div class="metric-val-safe">{global_h_cds:.3f}</div></div>',
            unsafe_allow_html=True)
        m3.markdown(
            f'<div class="metric-container"><div class="metric-title">Global Attack Reduction</div><div class="metric-val-neutral">{global_reduction:.1f}%</div></div>',
            unsafe_allow_html=True)

        st.markdown("<br><br>", unsafe_allow_html=True)

        fig_bar = px.bar(
            df_matrix,
            x="Architecture",
            y=["Baseline Deviation (CDS)", "Hardened Deviation (CDS)"],
            barmode="group",
            facet_col="Attack Vector",
            color_discrete_map={"Baseline Deviation (CDS)": "#e74c3c", "Hardened Deviation (CDS)": "#2ecc71"},
            template="plotly_dark"
        )
        fig_bar.update_layout(height=500, title_text="Cross-Architecture Defense Comparison")
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.warning("Data pipeline empty. Execute phase 3 benchmarks to populate visualizers.")

with tab_matrix:
    st.subheader("High-Resolution Attack Surface Matrix")
    if not df_matrix.empty:
        st.dataframe(
            df_matrix.style.format({
                "Baseline Deviation (CDS)": "{:.4f}",
                "Hardened Deviation (CDS)": "{:.4f}",
                "Baseline Trust Index (PTCI)": "{:.4f}",
                "Hardened Trust Index (PTCI)": "{:.4f}",
                "Efficacy Reduction %": "{:.2f}%"
            }).background_gradient(cmap="Reds", subset=["Baseline Deviation (CDS)"])
            .background_gradient(cmap="Greens", subset=["Hardened Deviation (CDS)"]),
            use_container_width=True,
            height=600
        )

        csv_blob = df_matrix.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Complete Matrix (CSV)",
            data=csv_blob,
            file_name="argus_vulnerability_matrix.csv",
            mime="text/csv",
        )

with tab_radar:
    st.subheader("Architectural Threat Topography")
    if not df_matrix.empty:
        model_selection = st.selectbox("Select Target Architecture for Topography Map",
                                       df_matrix["Architecture"].unique())
        df_radar = df_matrix[df_matrix["Architecture"] == model_selection]

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=df_radar["Baseline Deviation (CDS)"].tolist(),
            theta=df_radar["Attack Vector"].tolist(),
            fill='toself',
            name='Undefended Baseline',
            line_color='#e74c3c'
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=df_radar["Hardened Deviation (CDS)"].tolist(),
            theta=df_radar["Attack Vector"].tolist(),
            fill='toself',
            name='ARGUS Active',
            line_color='#2ecc71'
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
            showlegend=True,
            template="plotly_dark",
            height=600
        )
        st.plotly_chart(fig_radar, use_container_width=True)

with tab_telemetry:
    st.subheader("Tripartite Framework Intrusion Telemetry")
    if data_telemetry:
        c1, c2, c3 = st.columns(3)
        g_metrics = data_telemetry.get("constitutional_guard", {})
        p_metrics = data_telemetry.get("pap_protocol", {})
        m_metrics = data_telemetry.get("structural_math_guard", {})

        c1.markdown(
            f'<div class="metric-container"><div class="metric-title">HMAC-SHA256 Blocks</div><div class="metric-val-safe">{p_metrics.get("verification_failures", 0) + p_metrics.get("replay_attacks_blocked", 0)}</div></div>',
            unsafe_allow_html=True)
        c2.markdown(
            f'<div class="metric-container"><div class="metric-title">Geometric/Entropy Rejections</div><div class="metric-val-safe">{m_metrics.get("entropy_blocks", 0) + m_metrics.get("depth_blocks", 0)}</div></div>',
            unsafe_allow_html=True)
        c3.markdown(
            f'<div class="metric-container"><div class="metric-title">Semantic Firewall Redactions</div><div class="metric-val-safe">{g_metrics.get("redactions_applied", 0)}</div></div>',
            unsafe_allow_html=True)

        fig_funnel = go.Figure(go.Funnel(
            y=["Total Tool Payloads", "Passed Cryptographic PAP", "Passed Structural Math", "Passed Semantic Guard"],
            x=[
                g_metrics.get("total_inspections", 100) + p_metrics.get("verification_failures", 0),
                g_metrics.get("total_inspections", 80),
                g_metrics.get("total_inspections", 80) - m_metrics.get("entropy_blocks", 0),
                g_metrics.get("total_inspections", 80) - m_metrics.get("redactions_applied", 0)
            ],
            textinfo="value+percent initial"
        ))
        fig_funnel.update_layout(template="plotly_dark", title_text="Attack Penetration Funnel")
        st.plotly_chart(fig_funnel, use_container_width=True)
    else:
        st.info("No telemetry logs found. Hardened framework execution required to generate intrusion data.")

with tab_stats:
    st.subheader("Underlying Security Metrics & Formulations")
    st.markdown(
        "The ARGUS evaluation suite utilizes the following mathematical definitions to derive the matrix properties:")

    st.latex(r'''
    \text{Constitutional Deviation Score (CDS)} = \frac{1}{N} \sum_{i=1}^{N} P(V_i \mid R_i, C)
    ''')
    st.markdown(
        "Where $V_i$ represents a discrete constitutional violation event occurring within the generated response $R_i$, conditioned by the strict ruleset $C$.")

    st.latex(r'''
    \text{Principal Trust Confusion Index (PTCI)} = \int_{0}^{T} \Phi(t) \cdot \Omega(t) \,dt
    ''')
    st.markdown(
        "Where $\Phi(t)$ represents the LLM's adherence to assumed JSON key semantics, and $\Omega(t)$ represents the absence of external cryptographic verification logic in the reasoning trace.")

    st.latex(r'''
    \text{Shannon Entropy Threshold (SEDC)} = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i) > 5.5
    ''')
    st.markdown(
        "Triggers immediate rejection in the Structural Math Guard to prevent Base64 and embedded blob injections without requiring LLM inference.")