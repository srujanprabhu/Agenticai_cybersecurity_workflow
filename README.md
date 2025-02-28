# Agenticai_cybersecurity_workflow


# LangGraph-Based Agentic Cybersecurity Workflow

## Overview
This project implements an intelligent, autonomous cybersecurity testing workflow using LangGraph and LangChain. The system leverages large language models to interpret natural language security testing requests, convert them into actionable security tests, and dynamically execute a series of security scans while respecting defined scope constraints.

## Features

- **Natural Language Understanding**: Interpret security testing requests in plain English
- **Autonomous Workflow Planning**: Automatically determine which security tools to run
- **Dynamic Test Execution**: Execute security tests like port scanning, SQL injection testing, directory brute-forcing, and subdomain discovery
- **Scope Enforcement**: Respect user-defined scope constraints to prevent unauthorized testing
- **Adaptive Testing**: Dynamically add additional tests based on initial findings
- **Comprehensive Logging**: Maintain detailed logs of all operations and findings
- **User-Friendly Interface**: Streamlit-based UI for easy interaction

## Architecture

The system operates through a modular LangGraph pipeline:

1. **Intent Analysis**: Uses an LLM (Groq's llama3-8b-8192) to determine which security tests to run based on user input
2. **Target Extraction**: Identifies the target domain/IP from the user query
3. **Scope Validation**: Verifies target is within the allowed testing scope
4. **Test Execution**: Runs selected security tools against the target
5. **Dynamic Adaptation**: Adds additional tests based on initial findings
6. **Result Compilation**: Collects and organizes results from all tests
7. **Reporting**: Presents findings in an easy-to-understand format

## Security Tools Integration

The system integrates with several industry-standard security testing tools:

- **Nmap**: Network mapping and port scanning
- **SQLMap**: SQL injection vulnerability testing
- **FFUF**: Web fuzzing and directory brute-forcing
- **Gobuster**: Subdomain enumeration and discovery

## Requirements

### Python Packages
```
langchain-groq
langchain-core
langgraph
streamlit
requests
python-dotenv
numpy
```

### External Tools
- Nmap
- SQLMap
- FFUF
- Gobuster

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/langraph-security-workflow.git
   cd langraph-security-workflow
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Install the required external tools:
   
   **Ubuntu/Debian:**
   ```
   sudo apt update
   sudo apt install nmap
   ```
   
   **macOS:**
   ```
   brew install nmap
   ```
   
   For SQLMap, FFUF, and Gobuster, follow the installation instructions on their respective GitHub repositories.

4. Set up your API keys:
   ```
   export GROQ_API_KEY=your_api_key_here
   ```

5. Update tool paths in the code to match your local environment (look for paths like `ffuf_path`, `gobuster_path`, and `wordlist_path`).

## Usage

1. Run the Streamlit application:
   ```
   streamlit run temptest_1.py
   ```

2. Enter your security testing query in natural language, such as:
   - "Scan testphp.vulnweb.com for open ports and SQL injection vulnerabilities"
   - "Look for hidden directories on github.com"
   - "Find subdomains of leetcode.com"

3. Click "Run Security Test" to start the automated workflow.

4. View the results in the Streamlit interface and download the detailed logs for further analysis.

## Scope Enforcement

For security and ethical reasons, the system only allows testing against a predefined list of websites:
- http://testphp.vulnweb.com/
- https://www.onlinegdb.com/
- https://www.livechat.com/
- https://leetcode.com
- https://github.com
- dns.google

Attempting to test domains outside this scope will be blocked.

## Sample Output

After running a security test, you'll see results for each executed test:
- Port scanning results showing open ports and services
- SQL injection vulnerability detection
- Hidden directories and files
- Subdomain discovery results

## Architecture Diagram

```
User Query → Intent Analysis → Security Tests Selection → Scope Validation → Test Execution → Dynamic Adaptation → Results Compilation → Report Generation
```

## Limitations and Future Work

- Currently supports a limited set of security tools
- Scope enforcement is based on a hardcoded list rather than user-defined scope
- Does not include vulnerability assessment or risk scoring
- Future work will include more advanced tools, user-defined scope, and comprehensive reporting

## License

## Acknowledgements

This project was developed as part of an AI Engineering assignment, leveraging the capabilities of LangGraph, LangChain, and various security testing tools.
