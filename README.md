# FortiGate-Configuration-Review
Audit FortiGate firewall configuration based on CIS benchmark controls. 

##
Based on previous works on below links:
https://github.com/priyam001/Fortigate_CIS_check
https://github.com/Coldfirex/Fortigate_CIS_check

## What Is New:
  - Considerable number of controls were missing. Added those.
  - Lots of controls did not past the tests and had to be corrected. 
  - I removed the bash script section. 
  - Compared against recent CIS benchmark (7.4.x Benchmark v1.0.0) and updated the script accordingly. 
  - Removed capability to audit multiple configuration files as it seemed unnecessary. 
  - Considered audint configuration file on multi-vdom firewalls and updated code where required. 
  
## Purpose

This tool automates the process of checking FortiGate firewall configurations against CIS (Center for Internet Security) benchmarks. It helps security professionals and network administrators to:

- Audit FortiGate configurations for security best practices
- Identify potential security misconfigurations
- Generate detailed reports in both CSV and HTML formats
- Track compliance with CIS security standards

## Implementations
This tool is available in Python. (`fortigate_cis_checker.py`)

Choose the implementation that best suits your environment and requirements.

## Features
- Automated checking of 30+ CIS benchmark controls
- Detailed pass/fail status for each control
- Current configuration status
- Specific recommendations for failed checks
- HTML report with color-coded results
- CSV output for further analysis
- Summary statistics of overall compliance

### Python Requirement
- Python 3.6 or higher
- Required Python packages:
  ```
  pip install argparse logging typing
  pip install tqdm
  ```
- Access to FortiGate configuration file
- Read permissions for the configuration file

## Output Files

The script generates two output files in the current directory:

1. CSV Report: `AUDIT_YYYYMMDD_HHMMSS.csv`
2. HTML Report: `AUDIT_YYYYMMDD_HHMMSS.html`

## Checks Performed

The script checks device configuration according to CIS benchmark best practice recommendatinos.


## Sample Output

The HTML report includes:

- Summary statistics
- Detailed results table
- Color-coded pass/fail indicators
- Specific recommendations for failed checks

### Output Format
For failed checks, the report shows:
- Status: FAIL
- Recommendation: [specific fix details]

For passed checks, the report shows:
- Status: PASS
- Current: [actual configured value]
- Recommendation: N/A

## Note

- This tool has been tested on FortiOS version 7.0.x. Results may vary for other versions. 
- Always review results and recommendations before implementing changes.

## Troubleshooting

Invalid configuration file
- Ensure the configuration file is in plain text format (with .conf extention)
- Verify file permissions
- Check for file corruption
