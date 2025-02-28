import json
from dataclasses import dataclass
from langchain_groq import ChatGroq
import subprocess
from langchain_core.tools import tool
import requests
import os
from datetime import datetime
import time
import re
from langgraph.graph import StateGraph, END, START
import socket
import streamlit as st
from urllib.parse import urlparse


if "log_file" not in st.session_state:
    st.session_state.log_file = f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
if "log_contents" not in st.session_state:
    st.session_state.log_contents = ""
if "scan_output" not in st.session_state:
    st.session_state.scan_output = ""

log_file = st.session_state.log_file

def log_result(scan_type, result):
    """Append log messages to a text file and session state."""
    formatted_log = f"🔍 [{scan_type}] Result:\n{result}\n{'-'*50}\n"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(formatted_log)
    st.session_state.log_contents += formatted_log

# LLM USED - GROQ (llama3-8b-8192)
llm = ChatGroq(model="llama3-8b-8192", temperature=0)

@dataclass
class SecurityState:
    user_input: str
    scan_results: dict = None

# Define security scanning tools
@tool
def scan_ports(target: str):
    """Scans open ports on a given target IP or domain using Nmap."""
    log_result("Nmap", f"Started scanning {target}...")
    try:
        # Extract hostname from the target (removes http:// or https://)
        parsed_url = urlparse(target)
        clean_target = parsed_url.hostname if parsed_url.hostname else target
        # Run Nmap with corrected target
        result = subprocess.run(["nmap", "-A", "-p", "1-1000", clean_target], capture_output=True, text=True)
        log_result("Nmap", result.stdout)
        return result.stdout
    except Exception as e:
        log_result("Nmap", f"Error: {str(e)}")
        return f"Error running Nmap: {str(e)}"

SQLMAP_OUTPUT_DIR = os.path.expanduser("~\\AppData\\Local\\sqlmap\\output")

@tool
def test_sql_injection(target: str):
    """Performs an SQL injection attack using SQLMap and extracts vulnerable URLs."""
    log_result("SQLMap", f"Started SQL injection test on {target}...")
    try:
        before_run_files = set(os.listdir(SQLMAP_OUTPUT_DIR))
        # Step 1: Run SQLMap
        command = ["sqlmap", "-u", target, "--crawl", "2", "--batch", "--threads", "10"]
        subprocess.run(command, capture_output=True, text=True)
        # Step 2: Check for new CSV files created AFTER SQLMap run
        after_run_files = set(os.listdir(SQLMAP_OUTPUT_DIR))
        new_files = list(after_run_files - before_run_files)  # Get newly generated files

        # If no new CSV files, return a "No vulnerabilities" message
        if not new_files:
            return "✅ SQL injection test completed, but no vulnerabilities were found."
        # Step 3: Identify the latest result file
        result_files = [f for f in new_files if f.endswith(".csv")]
        if not result_files:
            return "✅ SQL injection test completed, but no relevant data was found."
        latest_result_file = os.path.join(SQLMAP_OUTPUT_DIR, sorted(result_files, key=lambda x: os.path.getctime(os.path.join(SQLMAP_OUTPUT_DIR, x)), reverse=True)[0])

        first_url = None
        import csv
        with open(latest_result_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)  # Read column headers
            try:
                url_index = headers.index("Target URL")
            except ValueError:
                return "✅ SQL injection test completed, but the results are not structured as expected."

            for row in reader:
                if row and len(row) > url_index:
                    first_url = row[url_index].strip()
                    if first_url.startswith("http"):
                        break  # Stop at the first valid URL

        if not first_url:
            return "✅ SQL injection test completed, but no exploitable targets were found."

        # for Debugging -  Print extracted URL
        st.write(f"🔍 **Extracted Target URL:** {first_url}")
        #Run SQLMap again on the extracted valid URL
        final_command = ["sqlmap", "-u", first_url, "--dbs", "--batch"]
        result = subprocess.run(final_command, capture_output=True, text=True)
        log_result("SQLMap", result.stdout)
        return result.stdout

    except Exception as e:
        log_result("SQLMap", f"Error: {str(e)}")
        return f"❌ Error running SQLMap: {str(e)}"

@tool
def brute_force_dirs(target: str, ffuf_path: str = r"C:\Users\srujs\ffuf.exe",wordlist_path: str = r"C:\Users\srujs\common.txt"):
    """Finds hidden directories on a web server using FFUF."""
    log_result("FFUF", f"Started directory brute force on {target}...")
    try:
        if not ffuf_path or not wordlist_path:
            return "Error: FFUF path or wordlist path is not provided."
        result = subprocess.run(
            [ffuf_path, "-w", wordlist_path, "-u", f"{target}/FUZZ", "-fc", "301,404", "-fs", "0"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        if result.returncode != 0:
            return f"FFUF error: {result.stderr.strip()}"
        if not result.stdout:
            return "Error: No output received from FFUF."
        directories = "\n".join(line for line in result.stdout.splitlines() if line.strip() and "[" in line)

        if directories:
            log_result("FFUF", directories)
            return directories
        else:
            return "No directories found."

    except FileNotFoundError:
        return "Error: FFUF executable not found. Check the path."
    except Exception as e:
        log_result("FFUF", f"Error: {str(e)}")
        return f"Error running FFUF: {str(e)}"

def is_subdomain_alive(subdomain):
    """Checks if a subdomain is live by sending an HTTP request."""
    try:
        response = requests.head(f"http://{subdomain}", timeout=3)  # Try HTTP first
        if response.status_code < 400:
            return True

        response = requests.head(f"https://{subdomain}", timeout=3)  # Try HTTPS
        return response.status_code < 400  # Return True if it works
    except requests.RequestException:
        return False  # Failed to connect


@tool
def discover_subdomains(target: str, gobuster_path: str = r"C:\Users\srujs\gobuster.exe",wordlist_path: str = r"C:\Users\srujs\Downloads\subdomains-top1million-5000.txt"):
    """Finds subdomains of a given target using both Gobuster (brute-force) and crt.sh (passive lookup)."""
    log_result("Gobuster", f"Started subdomain enumeration on {target}...")
    parsed_url = urlparse(target)
    target = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    results = {"target": target, "gobuster": [], "crtsh": []}
    max_retries = 3  # 🔹 Number of retries for crt.sh
    for attempt in range(max_retries):
        try:
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            response = requests.get(url, timeout=15)  # 🔹 Increased timeout

            if response.status_code == 200:
                data = response.json()
                subdomains = set(entry["name_value"] for entry in data)
                live_subdomains = [sub for sub in subdomains if is_subdomain_alive(sub)]
                results["crtsh"] = sorted(live_subdomains) if live_subdomains else "No live subdomains found."
                log_result("Gobuster", "\n".join(live_subdomains) if live_subdomains else "No live subdomains found.")
                break
            else:
                results["crtsh"] = f"Error: Received status code {response.status_code} from crt.sh"
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(5)  # 🔹 Wait 5 seconds before retrying
            else:
                results["crtsh"] = "Error: crt.sh took too long to respond after multiple retries"
        except Exception as e:
            results["crtsh"] = f"Error fetching crt.sh data: {str(e)}"
            break

    try:
        gobuster_cmd = [
            gobuster_path, "dns",
            "-d", target,
            "-w", wordlist_path,
            "--timeout", "10s",
            "-q", "--no-color"
        ]

        process = subprocess.run(gobuster_cmd, capture_output=True, text=True, timeout=300)
        if process.returncode == 0:
            found_subdomains = [
                line.strip() for line in process.stdout.split("\n")
                if target in line and not line.startswith("[+]")  # 🔹 Filter out unnecessary lines
            ]
            results["gobuster"] = found_subdomains

        else:
            results["gobuster"] = f"Gobuster error: {process.stderr.strip()}"
    except FileNotFoundError:
        results["gobuster"] = "Error: Gobuster executable not found. Check the path."
    except Exception as e:
        log_result("Gobuster", f"Error: {str(e)}")
        results["gobuster"] = f"Error running Gobuster: {str(e)}"

    return results
def analyze_intent(state: SecurityState):
    """Uses LLM to decide which security functions to call."""
    log_result("Intent Analysis", f"📝 Received user query: {state.user_input}")
    prompt = f"""Analyze the following user request and determine:
        - The correct security tests to run.
        - The target (if specified).
        - must include http or https if target is given

        **Rules:**
        - Only return JSON output. No explanations. ONLY JSON , DON'T EVEN SAY "HERE IS THE JSON FORMAT!" , JUST GIVE JSON OUTPUT!
        - STRICTLY ONLY JSON! DONT GIVE ANY EXTRA LETTER OTHER THAN THAT!
        - Format the response exactly as shown below:
        - You have to give from these functions only - "scan_ports", "test_sql_injection", "brute_force_dirs", "discover_subdomains"

        {{
            "functions": ["scan_ports", "test_sql_injection", "brute_force_dirs", "discover_subdomains"],
            "target": "example.com"
        }}

        **User request:** "{state.user_input}"
        """

    response = llm.invoke(prompt).content  # Get LLM output

    if response.startswith("```json"):
        response = response.replace("```json", "").replace("```", "").strip()

    try:
        parsed_response = json.loads(response)  # ✅ Now, it will parse correctly
        log_result("Intent Analysis", f"✅ Result: {parsed_response}")
        return SecurityState(
            user_input=state.user_input,  # Keep original input
            scan_results=parsed_response  # ✅ Store parsed LLM response in scan_results
        )
    except json.JSONDecodeError:
        log_result("❌ Error: Invalid JSON response from LLM.")
        raise ValueError(f"Invalid JSON response from LLM: {response}")

def execute_security_tests(state: SecurityState, iteration=0, dynamic_scan_added=False):
    """Executes selected security tests based on LLM's decision."""
    if not state.scan_results:
        return SecurityState(user_input=state.user_input, scan_results={"error": "No tests to run"})
    log_result("Security Tests", f"🎯 Running security tests: {state.scan_results}")

    functions_to_run = state.scan_results.get("functions", [])
    target = state.scan_results.get("target", "")

    function_map = {
        "scan_ports": scan_ports,
        "test_sql_injection": test_sql_injection,
        "brute_force_dirs": brute_force_dirs,
        "discover_subdomains": discover_subdomains,
    }

    results = {}
    for func_name in functions_to_run:
        if func_name in function_map:
            results[func_name] = function_map[func_name].invoke(target)
            log_result("Security Tests", f"✅ {func_name} completed:\n{results}")

    if len(results) >= 4:
        print("✅ All tests completed. Stopping further execution.")
        return SecurityState(user_input=state.user_input, scan_results=results)
    if "scan_ports" in results and not dynamic_scan_added:
        open_ports = results["scan_ports"]
        found_ports = re.findall(r"(\d+)/tcp\s+open", open_ports)
        found_ports = [int(port) for port in found_ports]

        if found_ports:  # If any ports are open
            print("🔄 Dynamically adding brute_force_dirs due to open ports detected.")
            # Remove scan_ports and add brute_force_dirs if not already there
            new_functions = [func for func in functions_to_run if func != "scan_ports"]
            if "brute_force_dirs" not in new_functions:
                new_functions.append("brute_force_dirs")

            # Re-run execute_security_tests with the updated list, marking dynamic scan as added
            new_state = SecurityState(
                user_input=state.user_input,
                scan_results={"functions": new_functions, "target": target}
            )
            new_result = execute_security_tests(new_state, iteration + 1, dynamic_scan_added=True)
            new_results = new_result.scan_results
            if "scan_ports" in new_results:
                del new_results["scan_ports"]

            results.update(new_results)

    return SecurityState(user_input=state.user_input, scan_results=results)

# LangGraph state graph
workflow = StateGraph(SecurityState)

# Add nodes
workflow.add_node("analyze_intent", analyze_intent)
workflow.add_node("execute_tests", execute_security_tests)

# execution flow
workflow.add_edge("analyze_intent", "execute_tests")
workflow.add_edge("execute_tests", END)  # ✅ Correct way to terminate

# entry point
workflow.set_entry_point("analyze_intent")

# Compiling thw workflow
graph_executor = workflow.compile()

# ---- Streamlit UI ---- #
st.title("🔍 Agentic Cybersecurity Pipeline")

if 'has_run_scan' not in st.session_state:
    st.session_state.has_run_scan = False
if 'last_scan_results' not in st.session_state:
    st.session_state.last_scan_results = {}

with st.sidebar.expander("📜 View Logs", expanded=False):
    try:
        with open("security_scan.log", "r") as log_f:
            logs = log_f.read()
        st.text_area("📝 Security Scan Logs", logs, height=300)
    except FileNotFoundError:
        st.warning("⚠️ No logs found yet. Run a scan first!")

# User input
user_query = st.text_input("Enter your security test query:", "")

if st.button("Run Security Test"):
    if not user_query:
        st.warning("Please enter a query.")
    else:
        # Step 1: Analyze user intent
        with st.spinner("🔍 Analyzing intent..."):
            response = analyze_intent(SecurityState(user_input=user_query))

        functions_to_run = response.scan_results.get("functions", [])
        target = response.scan_results.get("target", "")
        allowed_websites = [
            "http://testphp.vulnweb.com/",
            "https://www.onlinegdb.com/",
            "https://www.livechat.com/",
            "https: // leetcode.com",
            "https://github.com",
            "dns.google"
        ]

        def resolve_ip_to_domain(ip_address):
            """Tries to resolve an IP address back to a domain name."""
            try:
                domain = socket.gethostbyaddr(ip_address)[0]  # Extract the domain name
                return domain
            except socket.herror:
                return None  # Return None if no domain is found

        if target.replace(".", "").isdigit():
            resolved_domain = resolve_ip_to_domain(target)
            if resolved_domain:
                target = resolved_domain  # Replace IP with resolved domain
                st.success(f"✅ Resolved IP {target} to domain {resolved_domain}")
            else:
                st.error("❌ Domain name not found for the given IP. Cannot proceed with scanning.")
        if not functions_to_run:
            st.error("❌ No security tests were determined from the query.")
        else:
            parsed_url2 = urlparse(target)
            target_domain = parsed_url2.netloc or parsed_url2.path
            print(f"Functions to run : {functions_to_run}")
            print(f"Target: {target}")
            if any(target_domain in site for site in allowed_websites):
                #Run security tests
                log_result("Scope Enforcement", f"✅ Scan authorized for {target}")
                if functions_to_run:
                    with st.spinner("🚀 Running security tests..."):
                        initial_state = SecurityState(user_input=user_query, scan_results=response.scan_results)
                        result = graph_executor.invoke(initial_state)

                    # Get the final scan results after any dynamic function additions
                    if hasattr(result, 'scan_results'):
                        scan_results = result.scan_results
                    else:
                        scan_results = result.get("scan_results", {})

                    st.session_state.has_run_scan = True
                    st.session_state.last_scan_results = scan_results

                    #log file saving to session state for download
                    try:
                        with open(log_file, "r") as f:
                            st.session_state.log_contents = f.read()
                    except:
                        pass

                    # Display results
                    for func_name, output in scan_results.items():
                        if func_name != "functions" and func_name != "target" and func_name != "error":
                            st.text_area(f"📜 Results for {func_name}:", output, height=300)
                    st.success("✅ All security tests completed.")
                    # Download Logs button
                    if 'log_contents' in st.session_state and st.session_state.log_contents:
                        st.download_button(
                            label="📥 Download Logs",
                            data=st.session_state.log_contents,
                            file_name=os.path.basename(log_file),
                            mime="text/plain"
                        )
                    else:
                        st.warning("⚠️ No logs available yet.")
            else:
                log_result("Scope Enforcement",
                           f"⛔ Scan denied: {target} is outside allowed scope user_defined_scope")
                st.warning("⚠️ You are **not authorized** to perform penetration testing on this website.")

elif st.session_state.has_run_scan:
    for func_name, output in st.session_state.last_scan_results.items():
        if func_name != "functions" and func_name != "target" and func_name != "error":
            st.text_area(f"📜 Results for {func_name}:", output, height=300)
    st.success("✅ All security tests completed.")
    if 'log_contents' in st.session_state and st.session_state.log_contents:
        st.download_button(
            label="📥 Download Logs",
            data=st.session_state.log_contents,
            file_name=os.path.basename(log_file),
            mime="text/plain"
        )
    else:
        st.warning("⚠️ No logs available yet.")