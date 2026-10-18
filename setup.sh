#!/bin/bash
# TRACEWISE-Lite Setup Script
# This script sets up the TRACEWISE-Lite environment

set -e

echo "=========================================="
echo "TRACEWISE-Lite Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo -e "${GREEN}Python version: $PYTHON_VERSION${NC}"

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}Error: Python 3.8 or higher is required${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p workspace/{results,seeds,traces}
mkdir -p logs
mkdir -p configs

# Check for AFL++
echo -e "${YELLOW}Checking for AFL++...${NC}"
if command -v afl-fuzz &> /dev/null; then
    echo -e "${GREEN}AFL++ found: $(afl-fuzz --version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}Warning: AFL++ not found. Install it for fuzzing capabilities.${NC}"
    echo "  Ubuntu/Debian: sudo apt install afl++"
    echo "  Or build from source: https://github.com/AFLplusplus/AFLplusplus"
fi

# Check for DynamoRIO
echo -e "${YELLOW}Checking for DynamoRIO...${NC}"
if command -v drrun &> /dev/null; then
    echo -e "${GREEN}DynamoRIO found${NC}"
else
    echo -e "${YELLOW}Warning: DynamoRIO not found. Install it for instrumentation.${NC}"
    echo "  Download from: https://dynamorio.org/"
fi

# Check for Ollama
echo -e "${YELLOW}Checking for Ollama...${NC}"
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}Ollama found${NC}"
    echo -e "${YELLOW}Pulling recommended models...${NC}"
    ollama pull tinyllama 2>/dev/null || echo -e "${YELLOW}Could not pull tinyllama${NC}"
else
    echo -e "${YELLOW}Warning: Ollama not found. Install it for LLM reasoning.${NC}"
    echo "  Install from: https://ollama.com/"
fi

# Build vulnerable samples
echo -e "${YELLOW}Building vulnerable samples...${NC}"
cd vulnerable_samples
make clean 2>/dev/null || true
make all
cd ..

# Create default config
echo -e "${YELLOW}Creating default configuration...${NC}"
cat > configs/default.json << 'EOF'
{
  "project_name": "tracewise-lite",
  "workspace_dir": "./workspace",
  "log_level": "INFO",
  "max_workers": 4,
  "fuzzing": {
    "afl_path": "afl-fuzz",
    "timeout": 300,
    "memory_limit": "none",
    "seeds_dir": "./workspace/seeds",
    "output_dir": "./workspace/fuzzing_out",
    "target_args": "",
    "fork_mode": true
  },
  "instrumentation": {
    "drrun_path": "drrun",
    "client_path": "./build/libtracewise_client.so",
    "trace_dir": "./workspace/traces",
    "trace_memory": true,
    "trace_calls": true,
    "trace_syscalls": true,
    "max_trace_size": 104857600
  },
  "provenance": {
    "max_events": 100000,
    "memory_threshold": 52428800
  },
  "compression": {
    "compression_ratio": 0.1,
    "preserve_taint_paths": true,
    "preserve_crash_context": true,
    "cluster_similar_events": true,
    "abstraction_level": "function",
    "min_path_length": 3
  },
  "llm": {
    "model_name": "tinyllama",
    "ollama_host": "http://localhost:11434",
    "temperature": 0.3,
    "max_tokens": 2048,
    "timeout": 120,
    "context_window": 4096
  }
}
EOF

echo ""
echo "=========================================="
echo -e "${GREEN}TRACEWISE-Lite setup complete!${NC}"
echo "=========================================="
echo ""
echo "To activate the environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run simulation:"
echo "  python3 src/main_pipeline.py --simulate --vuln-type buffer_overflow"
echo ""
echo "To analyze a binary:"
echo "  python3 src/main_pipeline.py ./vulnerable_samples/buffer_overflow --timeout 60"
echo ""
echo "Directory structure:"
echo "  workspace/     - Working files and outputs"
echo "  logs/          - Log files"
echo "  configs/       - Configuration files"
echo "  vulnerable_samples/ - Sample vulnerable programs"
echo ""