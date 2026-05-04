#!/bin/bash
# ReversAI Setup Script

echo -e "\033[1;36m=====================================\033[0m"
echo -e "\033[1;36m      ReversAI Auto-Installer      \033[0m"
echo -e "\033[1;36m=====================================\033[0m"

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

echo -e "\n\033[1;34m[1/4] Setting up Python virtual environment...\033[0m"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 2. Check radare2
echo -e "\n\033[1;34m[2/4] Checking radare2 installation...\033[0m"
if ! command -v r2 &> /dev/null; then
    echo "⚠️ radare2 not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install radare2
        else
            echo "❌ Homebrew not found. Please install radare2 manually."
        fi
    elif command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y radare2
    else
        echo "Please install radare2 manually: https://github.com/radareorg/radare2"
    fi
else
    echo "✅ radare2 is already installed."
fi

# 3. Install r2dec plugin
if command -v r2pm &> /dev/null; then
    echo -e "\n\033[1;34m[3/4] Installing r2dec decompiler plugin...\033[0m"
    r2pm update
    r2pm -i r2dec
fi

# 4. Environment variables
echo -e "\n\033[1;34m[4/4] Setting up environment...\033[0m"
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env from template."
    echo -e "\033[1;33m⚠️ IMPORTANT: Please edit .env and add your OPENAI_API_KEY or ANTHROPIC_API_KEY\033[0m"
fi

mkdir -p uploads

echo -e "\n\033[1;32m=====================================\033[0m"
echo -e "\033[1;32m         Setup Complete!             \033[0m"
echo -e "\033[1;32m=====================================\033[0m"
echo -e "\nTo start the application:"
echo -e "  \033[1;36msource venv/bin/activate\033[0m"
echo -e "  \033[1;36mpython backend/main.py\033[0m"
echo -e "\nThen open \033[4;34mhttp://localhost:8000\033[0m in your browser."
