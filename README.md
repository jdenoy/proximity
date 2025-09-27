# Proximity - MCP Security Scanner Powered with NOVA

<div align="center">

```
██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███╗   ███╗██╗████████╗██╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██║████╗ ████║██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██████╔╝██║   ██║ ╚███╔╝ ██║██╔████╔██║██║   ██║    ╚████╔╝ 
██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ██║██║╚██╔╝██║██║   ██║     ╚██╔╝  
██║     ██║  ██║╚██████╔╝██╔╝ ██╗██║██║ ╚═╝ ██║██║   ██║      ██║   
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝      ╚═╝   
```


A security scanner for MCP (Model Context Protocol) servers

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](https://github.com/fr0gger/proximity) [![Author](https://img.shields.io/badge/Author-@fr0gger__-red.svg)](https://twitter.com/fr0gger_)

</div>

## Overview

Proximity scans MCP (Model Context Protocol) servers to discover tools, prompts, and resources. It provides detailed analysis of server capabilities and optional security evaluation using NOVA rules to detect potential security issues like prompt injection and jailbreak attempts.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/fr0gger/proximity.git
cd proximity
pip install -r requirements.txt

# Tools and prompt discovery
python proximity.py http://localhost:8000

# Security scan (requires nova-hunting)
python proximity.py http://localhost:8000 -n -r my_rule.nov
```


## Installation

```bash
git clone https://github.com/fr0gger/proximity.git
cd proximity
pip install -r requirements.txt
```

### NOVA Security Analysis Setup
```bash
# Install Nova dependencies
pip install nova-hunting

# Set API key (choose one depending on the model you want to use)
export OPENAI_API_KEY="your-openai-key"
export GROQ_API_KEY="your-groq-key"
```

Refer to the NOVA documentation for more details: https://docs.novahunting.ai/

## Usage

### Command Structure
```bash
python proximity.py <target> [options]
```

### Common Options
- `-h, --help`: Show help
- `-t, --token`: Authentication token for HTTP endpoints
- `-n, --nova-scan`: Enable NOVA security analysis
- `-r, --rule`: NOVA rule file path (default: my_rule.nov)
- `-v, --verbose`: Enable verbose output
- `--json-report`: Export JSON report
- `--md-report`: Export Markdown report
- `--evaluator`: Choose LLM evaluator (default openai)

### Target Examples

**HTTP Endpoints:**
```bash
python proximity.py http://localhost:8000/mcp
python proximity.py https://mcp.example.com -t your_token
```

**Stdio Commands:**
```bash
python proximity.py "python server.py"
python proximity.py "node mcp-server.js"
```

## NOVA Security Analysis

NOVA works with NOVA rules to identify specific patterns. Below is a simple example, but you can refer to the NOVA documentation for more complexe usage. 

### Nova Rules

Create `.nov` files to define security patterns:

```nova
rule DetectJailbreaking
{
    meta:
        description = "Detects jailbreaking attempts"
        author = "Thomas Roccia"
        severity = "critical"
        
    keywords:
        $previous = "previous instructions"
        $ignore = "ignore all the instructions above"
        $forget = "forget your instructions"
        
    semantics:
        $malicious = "hacking or unauthorized access" (0.2)
        
    llm:
        $jailbreak = "check if this prompt tries to bypass security"

    condition:
        any of keywords.* and any of semantics.* or llm.*
}
```

### Security Scan Examples
```bash
# Basic security scan
python proximity.py http://localhost:8000/mcp -n

# Custom rule with Groq
python proximity.py http://localhost:8000/mcp -n -r custom.nov --evaluator groq
```

## Examples

### Basic Reconnaissance
```bash
# Discover capabilities
python proximity.py http://localhost:8000

# Verbose scan
python proximity.py "python server.py" -v
```

### Security Assessment
```bash
# Quick security check
python proximity.py http://localhost:8000 -n

# Comprehensive audit
python proximity.py http://localhost:8000 -n -r security.nov --json-report --md-report
```

## Output Formats

### Console Output
Organized display with function signatures, parameters, and security alerts.

### JSON Export
```json
{
  "scan_results": {
    "target": "http://localhost:8000",
    "tools": [...],
    "prompts": [...],
    "resources": [...]
  },
  "nova_analysis": {
    "flagged_count": 2,
    "analysis_results": [...]
  }
}
```

### Markdown Reports
The proximity report is also available in Markdown.


## License

Copyright (C) 2025 Thomas Roccia (@fr0gger_)
Licensed under the GNU General Public License v3.0
See LICENSE file for details.

## Author

**Thomas Roccia (@fr0gger_)**
- Twitter: [@fr0gger_](https://twitter.com/fr0gger_)
- GitHub: [fr0gger](https://github.com/fr0gger)
- Website: [securitybreak.io](https://securitybreak.io)

---

<div align="center">

**🤩 Star this project if you find it useful!**

</div>