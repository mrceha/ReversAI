# ReversAI

**AI-Powered Automated Reverse Engineering & Security Analysis**

ReversAI is an advanced web-based tool that automates the reverse engineering process. Simply drag and drop a binary (PE, ELF, Mach-O), Python script, or Shell script, and the system will perform deep static analysis, disassembly, and decompilation. It then leverages AI (OpenAI GPT-4 or Anthropic Claude) to reason about the code, identifying vulnerabilities, hardening gaps, and providing actionable remediation steps.

## Features

- **Multi-Format Support**: Windows PE (`.exe`, `.dll`), Linux ELF (`.so`, binaries), macOS Mach-O, Python, Shell, and Java archives.
- **Deep Static Analysis**: Extracts imports, exports, strings (categorized by IPs, URLs, credentials, crypto), and file metadata.
- **Security Mitigations Check**: Automatically checks for ASLR, DEP/NX, PIE, RELRO, Stack Canaries, and CFG.
- **Automated Disassembly & Decompilation**: Uses `radare2` (`r2pipe`) and plugins (`r2dec`/`r2ghidra`) to automatically disassemble and decompile interesting functions.
- **AI Intelligence**: Feeds the extracted context and pseudo-C code to an LLM to identify complex vulnerabilities like use-after-free, logic flaws, and buffer overflows.
- **Premium UI**: A sleek, dark-themed, responsive web interface with real-time WebSocket progress updates.

## Architecture

1. **Frontend**: HTML5, Vanilla JS, CSS3 (No build step required).
2. **Backend**: Python 3.9+ with FastAPI.
3. **Engines**: `radare2`, `capstone`, `pefile`, `pyelftools`, `macholib`.
4. **AI Providers**: OpenAI (default) or Anthropic.

## Installation

### Prerequisites
- Python 3.9+
- `radare2` (Required for disassembly/decompilation)

### Quick Setup

You can use the provided setup script to automatically install radare2 and Python dependencies (Linux/macOS):

```bash
chmod +x setup.sh
./setup.sh
```

### Manual Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mrceha/ReversAI.git
   cd ReversAI
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Install Radare2 (if not using setup.sh):**
   - **macOS:** `brew install radare2`
   - **Linux:** `git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh`
   - **Plugins:** Run `r2pm -i r2dec` to install the decompiler.

4. **Configure AI Keys:**
   Copy the example `.env` file and add your API key.
   ```bash
   cp .env.example .env
   # Edit .env and add your OPENAI_API_KEY or ANTHROPIC_API_KEY
   ```

## Usage

1. **Start the backend server:**
   ```bash
   # Make sure you are in the virtual environment
   python backend/main.py
   ```
   *The server will start on `http://0.0.0.0:8000`.*

2. **Open the UI:**
   Navigate to [http://localhost:8000](http://localhost:8000) in your web browser.

3. **Analyze:**
   Drag and drop any executable file onto the dropzone. Wait for the pipeline to finish and review the comprehensive security report.

## Disclaimer

This tool is designed for educational purposes, security research, and analyzing software you own or have explicit permission to audit. The authors are not responsible for any misuse.

---
*Developed by [mrceha](https://github.com/mrceha)*
