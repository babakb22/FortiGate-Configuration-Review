#!/usr/bin/env python3

import os
import re
from datetime import datetime
import csv
import sys
import glob
import logging
import json
from tqdm import tqdm
import ipaddress

class FortiGateCISAudit:
    def __init__(self, config_file):
        self.config_file = config_file
        # Create audit_reports folder if it doesn't exist
        self.reports_dir = "audit_reports"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        # Generate output filenames with timestamp, excluding file extension
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = os.path.splitext(os.path.basename(config_file))  # Remove .conf
        self.csv_file = os.path.join(self.reports_dir, f"AUDIT_{timestamp}_{base_filename}.csv")
        self.html_file = os.path.join(self.reports_dir, f"AUDIT_{timestamp}_{base_filename}.html")
        
        # Load the config content during initialization
        self.config_content = ""
        if self.is_valid_config():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_content = f.read()
            except Exception as e:
                logging.error(f"Error reading config file {self.config_file}: {e}")
                print(f"Error reading config file {self.config_file}: {e}")
        
        # Extract hostname
        self.hostname = self.extract_hostname()
        # Extract firmware version
        self.firmware_version = self.extract_firmware_version()

    def is_valid_config(self):
        """Validate that the config file starts with '#config-version='"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith("#config-version="):
                    return True
                logging.warning(f"Invalid config file {self.config_file}: Does not start with '#config-version='")
                print(f"Skipping {self.config_file}: Invalid config file (must start with '#config-version=')")
                return False
        except Exception as e:
            logging.error(f"Error validating config file {self.config_file}: {e}")
            print(f"Error validating config file {self.config_file}: {e}")
            return False

    def extract_hostname(self):
        """Extract hostname from config file"""
        match = re.search(r'set hostname "([^"]+)"', self.config_content)
        return match.group(1) if match else "Unknown"

    def extract_firmware_version(self):
        """Extract firmware version from config file, excluding model"""
        match = re.search(r'config-version=[A-Za-z0-9]+-([0-9.-]+-FW-build[0-9]+-[0-9]+):opmode', self.config_content)
        return match.group(1) if match else "Unknown"

    def print_banner(self):
        print("========================================")
        print("Tool: FortiGate CIS Benchmark Audit Tool")
        print(f"Config File: {self.config_file}")
        print(f"Hostname: {self.hostname}")
        print(f"Firmware Version: {self.firmware_version}")
        print("========================================")

    def get_fortigate_section(self, section_start_line):
        """
        Extracts a configuration block from a FortiGate config file.
        Handles nested 'config' blocks correctly.
        """
        lines = self.config_content.splitlines()
        captured_lines = []
        capture_mode = False
        # Depth tracks nested configs. 
        # 0 = outside, 1 = inside our target, 2+ = inside a nested block
        depth = 0 
        
        # Clean up the search term (remove extra spaces)
        target_section = section_start_line.strip()

        for line in lines:
            stripped_line = line.strip()
            
            # 1. Look for the start of the section
            if not capture_mode:
                if stripped_line == target_section:
                    capture_mode = True
                    depth = 1
                    captured_lines.append(line)
                continue # Skip to next loop iteration

            # 2. We are now inside the section. Capture the data.
            if capture_mode:
                captured_lines.append(line)

                # If we see a new 'config' start, we are going deeper
                if stripped_line.startswith("config "):
                    depth += 1
                
                # If we see an 'end', we are coming back up
                elif stripped_line == "end":
                    depth -= 1
                
                # 3. If depth hits 0, we found the matching 'end' for our target
                if depth == 0:
                    capture_mode = False
                    # break
      
        if not captured_lines:
            return "None"
            
        return "\n".join(captured_lines)    

    def get_sys_admins_list(self, configlet):
        """
        Extracts the list of admins from "config system admin" section from a FortiGate config file.
        """
        # lines = self.config_content.splitlines()
        lines = configlet.splitlines()
        captured_lines = []
        capture_mode = False
        # Depth tracks nested configs. 
        # 0 = outside, 1 = inside our target, 2+ = inside a nested block
        depth = 0 
        i = 0 
        compliant = False
        _username = ""
        _details = ""

        admins_list = []

        # Clean up the search term (remove extra spaces)
        # target_section = "config system admin" #section_start_line.strip()
        # print("\nconfiglet is: ", configlet, "\n")
        
        for line in lines:
            stripped_line = line.strip()

            if not capture_mode:
                if stripped_line.startswith("edit \""):
                    capture_mode = True
                    depth = 2
                    _username = stripped_line.split('"')[1]
                continue 

            if capture_mode:
                if (stripped_line != "next") and (stripped_line != "end"):
                    captured_lines.append(stripped_line)

                if (stripped_line == "next"):
                    depth -= 1
                    "\n".join(captured_lines)
                    _details = captured_lines
                    new_dic = {"username": _username, "details": _details}
                    admins_list.append(new_dic.copy())
                    capture_mode = False
                    captured_lines = []
        
        if not admins_list:
            return "None"
            
        return admins_list

    def grep_config(self, pattern, configlet):
        """Simulates grep functionality inside a piece of config file (configlet)"""

        try:
            return bool(re.search(pattern , configlet , re.MULTILINE))
        except Exception as e:
            logging.error(f"Error searching config file {self.config_file} with pattern {pattern}: {e}")
            return False

    def evaluate_check(self, check):
        """Evaluate a single check from the checks.json configuration"""
        try:
            benchmark_id = check["id"]
            logic = check["logic"]
            result_message = check["result_message"]

            if logic["type"] == "simple_grep":
                if all(self.grep_config(pattern, self.get_fortigate_section(logic["section"])) for pattern in logic["patterns"]):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            if logic["type"] == "dns_grep":
                if all(self.grep_config(pattern, self.get_fortigate_section(logic["section"])) for pattern in logic["patterns"]):
                    dns_is_set = True
                _configlet = self.get_fortigate_section(logic["section"])
                dns_is_private = False
                lines = _configlet.splitlines()
                for line in lines:
                    if ("primary" in line) or ("secondary" in line):
                        ip_obj = ipaddress.ip_address(line.split()[-1])
                        if ip_obj.is_private:
                            dns_is_private = True

                if dns_is_set and dns_is_private:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "negated_grep":
                if not any(self.grep_config(pattern, self.get_fortigate_section(logic["section"])) for pattern in logic["patterns"]):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "any_grep":
                if any(self.grep_config(pattern, self.get_fortigate_section(logic["section"])) for pattern in logic["patterns"]):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "count_grep":
                if self.grep_config(logic["section"], self.get_fortigate_section(logic["section"])):
                    count = len(re.findall(logic["pattern"], self.get_fortigate_section(logic["section"])))
                    print("count is: ", count)
                    if count >= logic["min_count"]:
                        return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "complex_grep":
                conditions = [
                    self.grep_config(p["pattern"], self.get_fortigate_section(logic["section"])) if not p["negated"] else not self.grep_config(p["pattern"], self.get_fortigate_section(logic["section"]))
                    for p in logic["patterns"]
                ]
                if all(conditions):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "ssl-min-proto_grep":
                conditions = False
                configlet = self.get_fortigate_section(logic["section"])
                if not self.grep_config("set ssl-min-proto-version", configlet):
                    conditions = True
                else:
                    for p in logic["patterns"]:
                        if self.grep_config(p["pattern"], configlet) and p["negated"]:
                            conditions = True
                
                if (conditions):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "admin-ssl-min-proto_grep":
                conditions = False
                configlet = self.get_fortigate_section(logic["section"])
                if not self.grep_config("set admin-https-ssl-versions", configlet):
                    conditions = True
                else:
                    for p in logic["patterns"]:
                        if self.grep_config(p["pattern"], configlet) and p["negated"]:
                            conditions = True
                
                if (conditions):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "pass_policy_grep":
                configlet = self.get_fortigate_section(logic["section"])
                conditions = True
                for pattern in logic["patterns"]:
                    if not pattern in configlet: 
                        conditions = False
                        break

                if (conditions):
                    min_len_found = False
                    lines = configlet.splitlines()
                    for line in lines:
                        if "minimum-length" in line: 
                            min_len_found = True
                            value = int(line.split()[-1])
                            print(value)
                            if value < 16:
                                conditions = False
                                break
                        elif "expire-day" in line:
                            value = int(line.split()[-1])
                            print(value)
                            if value > 90:
                                conditions = False
                                break

                    if not min_len_found:
                        conditions = False

                if conditions:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "snmp_sec_grep":
                
                configlet = self.get_fortigate_section(logic["section"])
                list_of_dic = self.get_sys_admins_list(self.get_fortigate_section(logic["section"]))

                pre_conditions = True
                conditions = True
                
                for user in list_of_dic:
                    for pattern in logic["patterns"]:
                        is_found = any(pattern in item for item in user.get("details"))
                        if not is_found: 
                            pre_conditions = False
                            break

                if (pre_conditions):
                    for user in list_of_dic:
                        auth_proto_found = False
                        priv_proto_found = False

                        is_found = any("auth-proto sha256" in item for item in user.get("details")) or any("auth-proto sha384" in item for item in user.get("details")) or any("auth-proto sha512" in item for item in user.get("details"))
                        if is_found: 
                            auth_proto_found = True
                            auth_conditions = True
                        else:
                            auth_conditions = False
                            break

                        is_found = any("priv-proto des" in item for item in user.get("details"))

                        if is_found:
                            priv_conditions = False
                        else:
                            priv_proto_found = True
                            priv_conditions = True

                        if not auth_proto_found:
                            auth_conditions = False
                        if not priv_proto_found: 
                            priv_conditions = True

                if not (pre_conditions and auth_conditions and priv_conditions):
                        conditions = False

                if conditions:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "admin_lockout_grep":
                
                configlet = self.get_fortigate_section(logic["section"])

                conditions = True
                lock_out_threshold = False
                lockout_duration = False

                lines = configlet.splitlines()
                for line in lines:
                    if "lockout-threshold" in line: 
                        lock_out_threshold = True
                        value = int(line.split()[-1])
                        print(value)
                        if value <= 16:
                            continue
                        else:
                            conditions = False
                            break
                    elif "lockout-duration" in line:
                        lockout_duration = True
                        value = int(line.split()[-1])
                        print(value)
                        if value >= 900:
                            continue
                        else:
                            conditions = False
                            break
                    if (lock_out_threshold and lockout_duration):
                            break

                if not lockout_duration:
                    conditions = False

                if conditions:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "admin_timeout_grep":               
                configlet = self.get_fortigate_section(logic["section"])
                conditions = True
                timeout_value = False

                lines = configlet.splitlines()
                for line in lines:
                    if "admintimeout" in line: 
                        timeout_value = True
                        value = int(line.split()[-1])
                        print(value)
                        if value <= 5:
                            continue
                        else:
                            conditions = False
                            break

                    if (timeout_value):
                            break

                if conditions:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "mapped_grep":

                list_of_dic = self.get_sys_admins_list(self.get_fortigate_section(logic["section"]))
                conditions = True
                for user in list_of_dic:
                    for pattern in logic["patterns"]:
                        is_found = any(pattern in item for item in user.get("details"))
                        if (not is_found):
                            conditions = False
                            break
                    if not conditions:
                        break
                if conditions:
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"


            else:
                logging.error(f"Unknown check logic type {logic['type']} for check {benchmark_id}")
                return f"ERROR: Unknown check logic type for {benchmark_id}"

        except Exception as e:
            logging.error(f"Error evaluating check {benchmark_id} for {self.config_file}: {e}")
            return f"ERROR: Check {benchmark_id} failed ({str(e)})"

    def load_checks(self):
        """Load check definitions from checks.json"""
        try:
            with open("checks.json", 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.critical(f"Error loading checks.json: {e}")
            print(f"Error: Could not load checks.json: {e}")
            sys.exit(1)

    def generate_csv_report(self, results):
        """Generate CSV report from results"""
        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Benchmark ID', 'Description', 'Result', 'Fix Commands'])
                
                for benchmark, result, check in results:
                    benchmark_id = benchmark.split()[0]
                    description = ' '.join(benchmark.split()[1:])
                    # fix_location = self.get_fix_location(benchmark_id)
                    fix_commands = check.get("fix_commands", "No fix commands available") if "FAIL" in result else "No fixes needed"
                    
                    writer.writerow([
                        benchmark_id,
                        description,
                        result,
                        # fix_location,
                        fix_commands
                    ])
            logging.info(f"CSV report generated: {self.csv_file}")
            print(f"CSV report generated: {self.csv_file}")
        except Exception as e:
            logging.error(f"Error generating CSV report for {self.csv_file}: {e}")
            print(f"Error generating CSV report for {self.csv_file}: {e}")

    def generate_html_report(self, results):
        """Generate minimalistic HTML report"""
        total_checks = len(results)
        total_pass = sum(1 for check in results if "PASS" in check[1])
        total_fail = sum(1 for check in results if "FAIL" in check[1])

        html_content = f"""
        <html>
        <head>
            <title>FortiGate CIS Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .error {{ color: red; }}
                .summary {{ margin-bottom: 20px; }}
                .fix-commands {{ background-color: #f8f9fa; padding: 10px; margin-top: 5px; font-family: monospace; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <h1>FortiGate CIS Audit Report</h1>
            <p>Hostname: {self.hostname}</p>
            <p>Firmware Version: {self.firmware_version}</p>
            <div class="summary">
                <p>Total Checks: {total_checks} | Passed: {total_pass} | Failed: {total_fail}</p>
            </div>
            <table>
                <tr>
                    <th>Benchmark</th>
                    <th>Result</th>
                    <th>Fix Commands Example</th>
                </tr>"""

        for benchmark, result, check in results:
            benchmark_id = benchmark.split()[0]
            result_class = "pass" if "PASS" in result else "fail" if "FAIL" in result else "error"
            # fix_location = self.get_fix_location(benchmark_id)
            fix_commands = check.get("fix_commands", "") if "FAIL" in result else ""
            # Replace newlines with <br> for HTML rendering
            fix_commands_html = fix_commands.replace('\n', '<br>') if fix_commands else ""

            html_content += f"""
                <tr>
                    <td>{benchmark}</td>
                    <td class="{result_class}">{result}</td>
                    <td>
                        <div class="fix-commands">{fix_commands_html}</div>
                    </td>
                </tr>"""

        html_content += """
            </table>
        </body>
        </html>"""

        try:
            with open(self.html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logging.info(f"HTML report generated: {self.html_file}")
            print(f"HTML report generated: {self.html_file}")
        except Exception as e:
            logging.error(f"Error generating HTML report for {self.html_file}: {e}")
            print(f"Error generating HTML report for {self.html_file}: {e}")

def setup_logging():
    """Set up logging to a unique file in audit_reports"""
    reports_dir = "audit_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(reports_dir, f"audit_log_{timestamp}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info("Audit log initialized")

def main():
    # Set up logging
    setup_logging()
    
    if len(sys.argv) != 2:
        logging.error("Invalid usage. Usage: python3 FortiGateCISAudit.py <config_folder>")
        print("Usage: python3 FortiGateCISAudit.py <config_folder>")
        sys.exit(1)

    config_folder = sys.argv[1]
    
    # Check if folder exists
    if not os.path.isdir(config_folder):
        logging.error(f"{config_folder} is not a valid directory")
        print(f"Error: {config_folder} is not a valid directory")
        sys.exit(1)

    # Get all .txt and .conf files in the folder
    """"
    config_files = glob.glob(os.path.join(config_folder, "*.txt")) + \
                   glob.glob(os.path.join(config_folder, "*.conf"))

"""
    config_file = ''.join(glob.glob(os.path.join(config_folder, "*.conf")))
    
    if not config_file:
        logging.warning(f"No configuration files found in {config_folder}")
        print(f"No configuration files found in {config_folder}")
        sys.exit(1)

    print("config_file: ", config_file)



    # Load checks from checks.json
    # auditor = FortiGateCISAudit(config_files[0])  # Temporary instance to load checks
    auditor = FortiGateCISAudit(config_file) 

    checks = auditor.load_checks()

    # Process each config file with progress bar
    # print(f"Processing {len(config_files)} config files...")
    # for config_file in tqdm(config_files, desc="Processing files", unit="file"):
    
    logging.info(f"Processing file: {config_file}")
    auditor = FortiGateCISAudit(config_file)
    
    # Skip if config is invalid
    if not auditor.config_content:
        logging.warning(f"Skipping {config_file} due to invalid or unreadable config")
    
    auditor.print_banner()
    
    # Run all checks and collect results
    results = []
    for check in checks:
        try:
            benchmark_id = check["id"]
            result = auditor.evaluate_check(check)
            logging.info(f"Check {benchmark_id} for {config_file}: {result}")
            print(f"{benchmark_id}: {result}")
            results.append((f"{benchmark_id} {check['description']}", result, check))
        except Exception as e:
            logging.error(f"Error executing check {check['id']} for {config_file}: {e}")
            print(f"Error executing check {check['id']}: {e}")
            results.append((f"{check['id']} {check['description']}", f"ERROR: Check failed ({str(e)})", check))
    
    # Generate both HTML and CSV reports
    auditor.generate_html_report(results)
    auditor.generate_csv_report(results)
    logging.info(f"Completed processing: {config_file}")
    print(f"Completed processing: {config_file}\n")
    
    logging.info("All files processed. Review logs and reports in the audit_reports folder.")
    print("All files processed. Review logs and reports in the audit_reports folder.")

if __name__ == "__main__":
    main()
