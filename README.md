#  ARGUS: Adversarial Principal Hierarchy Testing & Constitutional Hardening Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Paper](https://img.shields.io/badge/Paper-LaTeX_Source-red.svg)](./main.tex)

ARGUS is an empirical research framework for evaluating and mitigating **Tool-Level Principal Injection (TLPI)** attacks in multi-agent Large Language Model (LLM) ecosystems.

While modern alignment techniques such as **Constitutional AI (CAI)** and **Instruction Hierarchies** are effective against traditional prompt injection, ARGUS demonstrates that many frontier LLMs remain susceptible to **implicit trust escalation through structured JSON tool outputs**.

ARGUS provides:

- A reproducible benchmark for TLPI attacks
- Novel security metrics for measuring model behavior
- A three-layer defense architecture for structured tool outputs
- Multi-model evaluation across leading open-source LLMs

---

#  Key Contributions

##  Tool-Level Principal Injection (TLPI) Taxonomy

ARGUS formalizes four previously underexplored schema-level attack classes:

1. **Semantic Trust Spoofing**
   - Injecting unauthorized privilege attributes such as:
   ```json
   {
     "security_clearance": "admin"
   }
   ```

2. **Structural Obfuscation**
   - Deep Abstract Syntax Tree (AST) nesting (`D ≥ 6`) designed to evade reasoning safeguards.

3. **Type Confusion & Array Injection**
   - Replacing expected scalar values with executable instruction vectors.

4. **Official Schema Hijacking**
   - Mimicking native `tool_calls` or system-generated payload structures.

---

##  Novel Evaluation Metrics

### Constitutional Deviation Score (CDS)

Measures behavioral safety violations.

- Range: **0.0 – 1.0**
- Higher values indicate greater constitutional deviation.

---

### Principal Trust Confusion Index (PTCI)

Measures reasoning reliance on unauthenticated JSON metadata.

- Range: **0.0 – 1.0**
- Higher values indicate stronger implicit trust in malicious tool outputs.

---

##  HARDEN Defense Architecture

ARGUS introduces a three-layer defensive pipeline.

### Layer 1 — PAP (Principal Authentication Protocol)

- HMAC-SHA256 authentication
- Rejects unsigned or tampered tool responses

---

### Layer 2 — SEDC (Structural Entropy & Depth Calculus)

Blocks payloads that exceed structural complexity thresholds.

- Shannon Entropy:
  - `H(X) > 5.5`

- Graph Depth:
  - `D > 5`

---

### Layer 3 — Schema-Level Constitutional Guard

A specialized JSON-aware LLM that sanitizes adversarial key-value pairs before they reach downstream agents.

---

#  Experimental Evaluation

ARGUS was evaluated across six frontier LLM architectures:

- Llama-3.3-70B
- DeepSeek-V4-Flash
- Nemotron-3-Super-120B
- Minimax-M2.7
- GPT-OSS-120B
- Qwen3-Next-80B

The proposed defense achieved up to:

> **77.0% reduction in TLPI attack success rate (p < 0.05)**

---

# Repository Structure

```text
ARGUS/
│
├── analysis/
│   └── results/
│       ├── multimodel_hardened_comparison.json
│       ├── argus_hardened_metrics.csv
│       └── defense_telemetry.json
│
├── figures/
│   ├── fig1_baseline_cds_chart.pdf
│   ├── fig2_ablation_heatmap.pdf
│   ├── fig3_flow_diagram.pdf
│   └── fig4_threat_model.pdf
│
├── src/
│   ├── argus_env_config.py
│   └── pipeline.py
│
├── app/
│   └── streamlit_app.py
│
├── generate_paper_figures.py
├── main.tex
├── requirements.txt
└── README.md
```

---

#  Quick Start

## 1. Clone the Repository

```bash
git clone https://github.com/NukaNarendra/ARGUS.git

cd ARGUS
```

---

## 2. Create a Virtual Environment

Linux/macOS

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Configure API Keys

Create a `.env` file in the project root.

```env
NVIDIA_API_KEY_NEMOTRON=your_key
NVIDIA_API_KEY_LLAMA=your_key
NVIDIA_API_KEY_QWEN=your_key
NVIDIA_API_KEY_DEEPSEEK=your_key
NVIDIA_API_KEY_MINIMAX=your_key
NVIDIA_API_KEY_GPT_OSS=your_key
NVIDIA_API_KEY_SCORER=your_key
```

> **Important:** Never commit your `.env` file to version control.

---

#  Usage

## Run Baseline Benchmark

Evaluate models without defenses.

```bash
python src/pipeline.py --run multimodel
```

---

## Run Hardened Benchmark

Enable PAP, SEDC, and the Schema Constitutional Guard.

```bash
python src/pipeline.py --run multimodel-hardened
```

---

## Generate Publication Figures

```bash
python generate_paper_figures.py
```

Figures will be saved under:

```
figures/
```

---

## Launch Interactive Dashboard

```bash
streamlit run app/streamlit_app.py
```

The dashboard includes:

- Threat topology
- CDS analytics
- PTCI distributions
- Defense telemetry
- Comparative model performance

---

#  Benchmark Results

| Model | Text CDS | JSON TLPI CDS | Hardened CDS | Reduction |
|--------|---------:|--------------:|-------------:|----------:|
| Llama-3.3-70B | 0.16 ± 0.29 | 0.54 ± 0.34 | 0.13 ± 0.25 | **77.0%** |
| DeepSeek-V4-Flash | 0.18 ± 0.32 | 0.51 ± 0.34 | 0.17 ± 0.36 | **67.6%** |
| Nemotron-3-Super-120B | 0.26 ± 0.39 | 0.55 ± 0.33 | 0.19 ± 0.32 | **66.1%** |
| Minimax-M2.7 | 0.31 ± 0.34 | 0.44 ± 0.40 | 0.20 ± 0.33 | **54.6%** |
| GPT-OSS-120B | 0.17 ± 0.37 | 0.22 ± 0.39 | 0.17 ± 0.37 | **23.9%** |
| Qwen3-Next-80B | 0.07 ± 0.26 | 0.23 ± 0.37 | 0.23 ± 0.35 | **0.0%** |

> Critical failure threshold: **CDS ≥ 0.5**

---

#  Research Paper

The complete research paper—including methodology, mathematical proofs, prompt templates, appendices, and experimental analysis—is available at:

**DOI**

https://doi.org/10.5281/zenodo.21310433

---

#  Citation

```bibtex
@article{narendra2026argus,
  title={ARGUS: Adversarial Principal Hierarchy Testing and Constitutional Hardening Framework for Multi-Agent Systems},
  author={Narendra, Nuka Venkata},
  journal={Independent AI Security Research},
  year={2026},
  month={July},
  url={https://github.com/NukaNarendra/ARGUS}
}
```

---

#  Responsible Disclosure

The vulnerabilities documented in ARGUS involve structural privilege escalation in frontier LLM ecosystems.

Following responsible disclosure best practices, findings and mitigation strategies were communicated to affected API vendors prior to public release.

---

# License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.
