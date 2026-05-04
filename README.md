<div align="center">

# 🌌 ReversAI 

**The ultimate AI-powered automated reverse engineering & security analysis platform.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![radare2](https://img.shields.io/badge/radare2-v5.9-red?style=for-the-badge&logo=c&logoColor=white)](https://radare.org)
[![OpenAI / Anthropic](https://img.shields.io/badge/AI-GPT--4%20%7C%20Claude-8b5cf6?style=for-the-badge&logo=openai&logoColor=white)]()

<br/>

*Drop a binary. Get an instant, deep-dive vulnerability report.*

</div>

---

## ⚡ What is ReversAI?

**ReversAI** eliminates the tedious manual labor of binary analysis. Whether you're dealing with a stripped ELF, a packed Windows PE, or a suspicious Python script, just drag and drop it into the sleek web interface. 

The system automatically rips it apart—extracting imports, strings, analyzing security mitigations, and leveraging `radare2` to disassemble and decompile the most interesting functions. Finally, it feeds this rich context into advanced AI models (GPT-4 or Claude) to hunt for zero-days, logic flaws, and hardening gaps.

## 🚀 Key Features

*   **🪄 Zero-Click Decompilation**: Automatically uses `radare2` with `r2dec` or `r2ghidra` to pull pseudo-C code from machine instructions.
*   **🧠 LLM Vulnerability Hunting**: Feeds decompiled functions and file metadata directly into advanced AI models to identify complex vulnerabilities like Use-After-Free, buffer overflows, and command injections.
*   **🛡️ Mitigation Analysis**: instantly checks binaries for ASLR, DEP/NX, PIE, RELRO, Stack Canaries, and CFG compliance.
*   **🧬 Universal Support**: 
    *   `Windows PE` (.exe, .dll, .sys)
    *   `Linux ELF` (.so, binaries)
    *   `macOS Mach-O` (.dylib, binaries)
    *   `Scripts` (.py, .sh, .bat, .js)
    *   `Java` (.jar, .class)
*   **🕵️ Threat Intelligence**: Extracts and categorizes IPs, URLs, crypto keys, and hardcoded credentials.
*   **💎 Premium Dark UI**: A beautiful, glassmorphic drag-and-drop web interface with real-time WebSocket progress streaming.

---

## 🏗️ How it Works

```mermaid
graph LR
    A[📁 Drop File] --> B(🕵️ Static Analysis)
    B -->|Metadata, Strings, Imports| C(🔧 r2 Disassembly)
    C -->|ASM & Flow| D(📝 Decompilation)
    D -->|Pseudo-C Code| E{🧠 AI Engine}
    E -->|Vulns & Fixes| F[📊 Risk Report]
    
    style A fill:#00f0ff,stroke:#0f111a,stroke-width:2px,color:#000
    style E fill:#8b5cf6,stroke:#0f111a,stroke-width:2px,color:#fff
    style F fill:#ff007f,stroke:#0f111a,stroke-width:2px,color:#fff
```

---

## ⚙️ Installation & Setup

### Prerequisites
*   Python 3.9+
*   `radare2` (Required for ASM and decompilation)

### 🏎️ Quick Install (Linux / macOS)
Use our auto-installer to set up the Python virtual environment and grab `radare2` + plugins automatically:

```bash
git clone https://github.com/mrceha/ReversAI.git
cd ReversAI
chmod +x setup.sh
./setup.sh
```

### 🛠️ Manual Install
<details>
<summary>Click to view manual installation steps</summary>

1. **Clone & venv:**
   ```bash
   git clone https://github.com/mrceha/ReversAI.git
   cd ReversAI
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Install radare2:**
   *   *macOS*: `brew install radare2`
   *   *Linux*: `sudo apt install radare2`
3. **Install r2dec plugin:**
   ```bash
   r2pm -i r2dec
   ```
</details>

---

## 🔑 Configuration

ReversAI uses AI to do the heavy lifting for vulnerability detection. You'll need an API key.

1. The `setup.sh` script automatically creates a `.env` file. (Or `cp .env.example .env`).
2. Open `.env` and paste your key:

```env
# Use OpenAI...
OPENAI_API_KEY=sk-your-openai-key-here
AI_PROVIDER=openai

# ...or Anthropic
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here
AI_PROVIDER=anthropic
```

*(Note: If you don't provide an API key, ReversAI will still perform static analysis, decompilation, and security checks—it will just skip the final AI reasoning step).*

---

## 💻 Usage

1. Start the FastAPI backend server:
   ```bash
   source venv/bin/activate
   python backend/main.py
   ```
2. Open your browser and navigate to:
   **[http://localhost:8000](http://localhost:8000)**
3. Drag and drop any binary to begin analysis!

---

<div align="center">
  <i>Developed by <a href="https://github.com/mrceha">mrceha</a>. Built for security researchers and reverse engineers.</i>
  <br/><br/>
  <b>⚠️ Disclaimer</b>: This tool is designed for educational purposes, security research, and analyzing software you own or have explicit permission to audit. The authors are not responsible for any misuse.
</div>
