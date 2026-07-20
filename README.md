# 🛡️ ARGUS: Adversarial Principal Hierarchy Testing & Constitutional Hardening Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Paper: Published](https://img.shields.io/badge/Paper-LaTeX_Source-red.svg)](./main.tex)

**ARGUS** is an empirical research pipeline and defense framework designed to probe, measure, and mitigate **Tool-Level Principal Injection (TLPI)** attacks in Multi-Agent Large Language Model (LLM) ecosystems. 

While Constitutional AI (CAI) and Instruction Hierarchies effectively block text-based adversarial prompts, ARGUS demonstrates that modern frontier models suffer from an implicit structural attention bias—blindly trusting unauthorized privilege escalation and malicious commands when encapsulated within structured **JSON tool outputs**.

---

## 📌 Key Contributions & Empirical Findings

* **TLPI Attack Taxonomy:** Formalizes four novel schema-level attack vectors:
  1. *Semantic Trust Spoofing* (injecting unauthenticated keys like `"security_clearance": "admin"`).
  2. *Structural Obfuscation* (deep AST graph nesting, $D \ge 6$).
  3. *Type Confusion & Array Injection* (replacing strings with executable instruction vectors).
  4. *Official Schema Hijacking* (emulating native `tool_calls` payloads).
    
* **Novel Quantitative Metrics:**
  
  * **CDS (Constitutional Deviation Score):** Outcome-based metric $[0.0, 1.0]$ measuring behavioral safety compliance violations.
  * **PTCI (Principal Trust Confusion Index):** Reasoning-based metric $[0.0, 1.0]$ measuring internal Chain-of-Thought reliance on unauthenticated JSON keys.
    
* **Tripartite Defense Architecture (HARDEN):**
  
  * **Layer 1: PAP (Principal Authentication Protocol)** – Cryptographic HMAC-SHA256 signature verification.
  * **Layer 2: SEDC (Structural Entropy & Depth Calculus)** – Mathematical filtering blocking payloads exceeding Shannon Entropy thresholds ($H(X) > 5.5$) or Graph Depth ($D > 5$).
  * **Layer 3: Schema-Level Constitutional Guard** – Specialized JSON-constrained LLM sanitizing adversarial key-value pairs before context-window ingestion.
    
* **Empirical Efficacy:** Tested across 6 frontier architectures (`Llama-3.3-70B`, `DeepSeek-V4-Flash`, `Nemotron-3-Super-120B`, `Minimax-M2.7`, `GPT-OSS-120B`, and `Qwen3-Next-80B`), achieving up to a **77.0% reduction in attack success rates** under ARGUS defenses ($p < 0.05$).

---

## 🏗️ Repository Architecture

```text
ARGUS/
├── analysis/
│   ├── results/                  # Evaluation JSONs, CSVs, and HTML reports
│   │   ├── multimodel_hardened_comparison.json
│   │   ├── argus_hardened_metrics.csv
│   │   └── defense_telemetry.json
├── figures/                      # High-resolution generated paper figures (PNG & PDF)
│   ├── fig1_baseline_cds_chart.pdf
│   ├── fig2_ablation_heatmap.pdf
│   ├── fig3_flow_diagram.pdf
│   └── fig4_threat_model.pdf
├── src/
│   ├── argus_env_config.py      # Multi-model client with exponential backoff & failsafes
│   └── pipeline.py              # Main CLI execution harness
├── app/
│   └── streamlit_app.py         # Interactive telemetry & threat topography dashboard
├── generate_paper_figures.py    # Self-contained figure generation script
├── main.tex                     # Complete 12-page LaTeX paper source file
├── requirements.txt             # Project dependencies
└── README.md
```

🛠️ Quick Start & Installation
1. Clone & Set Up Environment
```
git clone [https://github.com/NukaNarendra/ARGUS.git](https://github.com/NukaNarendra/ARGUS.git)
cd ARGUS
```
# Create virtual environment

```
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
```

# Install dependencies
```
pip install -r requirements.txt
```

2. Configure API Keys
Create a .env file in the root directory (do not commit this file):

```
NVIDIA_API_KEY_NEMOTRON=your_nvidia_nim_key
NVIDIA_API_KEY_LLAMA=your_nvidia_nim_key
NVIDIA_API_KEY_QWEN=your_nvidia_nim_key
NVIDIA_API_KEY_DEEPSEEK=your_nvidia_nim_key
NVIDIA_API_KEY_MINIMAX=your_nvidia_nim_key
NVIDIA_API_KEY_GPT_OSS=your_nvidia_nim_key
NVIDIA_API_KEY_SCORER=your_nvidia_nim_key
```

💻 Usage
Run Baseline Vulnerability Benchmark (Undefended)
Evaluates target models across text and JSON attack conditions:
```
python src/pipeline.py --run multimodel
```

Run Hardened Benchmark (ARGUS Active)
Routes tool responses through PAP, SEDC, and Semantic Guard layers:

```
python src/pipeline.py --run multimodel-hardened
```

Generate High-Resolution Paper Figures
Generates publication-ready PDF and PNG vector graphics in /figures:

```
python generate_paper_figures.py
```
Launch Interactive Analytics Dashboard
Visualize threat topography, radar maps, and defense telemetry in real time:

```
streamlit run app/streamlit_app.py
```

📊 Benchmark Results Summary
```

| Model Architecture | Text Baseline CDS | JSON Baseline CDS (TLPI) | Hardened JSON CDS (ARGUS) | Efficacy Reduction |
| :--- | :---: | :---: | :---: | ---: |
| Llama-3.3-70B-Instruct | 0.16±0.29 | 0.54±0.34 | 0.13±0.25 | 77.0% (p<0.05,d=1.2) |
| DeepSeek-V4-Flash | 0.18±0.32 | 0.51±0.34 | 0.17±0.36 | 67.6% (p<0.05,d=0.9) |
| Nemotron-3-Super-120B | 0.26±0.39 | 0.55±0.33 | 0.19±0.32 | 66.1% (p<0.05,d=1.0) |
| Minimax-M2.7 | 0.31±0.34 | 0.44±0.40 | 0.20±0.33 | 54.6% (p<0.05,d=0.6) |
| GPT-OSS-120B | 0.17±0.37 | 0.22±0.39 | 0.17±0.37 | 23.9% |
| Qwen3-Next-80B | 0.07±0.26 | 0.23±0.37 | 0.23±0.35 | 0.0% |

```

Note: Critical failure threshold is defined as $CDS \ge 0.5$.

## Research Paper & Citation

The complete 12-page research paper complete with appendices, prompt templates, and mathematical proofs is included in this :(https://doi.org/10.5281/zenodo.21310433)

If you use the ARGUS evaluation harness or TLPI attack taxonomy in your research, please cite:

@article{narendra2026argus,
  title={ARGUS: Adversarial Principal Hierarchy Testing and Constitutional Hardening Framework for Multi-Agent Systems},
  author={Narendra, Nuka Venkata},
  journal={Independent AI Security Research},
  year={2026},
  month={July},
  url={[https://github.com/NukaNarendra/ARGUS](https://github.com/NukaNarendra/ARGUS)}
}


## 🔐 Ethical Considerations & Responsible Disclosure
The vulnerabilities documented in this repository involve structural privilege escalation vectors in frontier LLM architectures. In alignment with standard 90-day responsible disclosure protocols, research findings and mitigation strategies were communicated to API vendors prior to public code release.

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
