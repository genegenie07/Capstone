# SQL Audit Log Monitoring & Alert Prototype (Capstone)

## Overview
This repository contains a passive monitoring tool that analyzes **SQL Server audit logs** to detect potentially suspicious SQL statements and generate **email alerts** for review. The solution is **passive-by-design**: it does not intercept, rewrite, or block live database queries. Instead, it processes audit outputs (Extended Events `.xel` converted to CSV) and applies rule-based checks on captured SQL text.

## Key Features
- **Log conversion (Extended Events → CSV):** Converts SQL Server `.xel` audit files into analysis-ready CSV outputs.
- **SQL normalization:** Standardizes SQL statements (lowercasing, comment stripping, literal masking, whitespace normalization) to improve consistent detection.
- **Rule-based detection:**
  - Flags queries with a `WHERE` clause that do not include `comp_code`
  - Flags `INSERT` statements missing `run_no` / `running_no`
- **Noise reduction filter:** Drops selected benign query patterns to reduce alert fatigue (configurable).
- **Email alerts:** Sends a summarized report via SMTP when suspicious queries are detected.
- **Offline processing:** Operates on CSV logs without requiring direct database access or agent-based interception.

## Repository Structure
├─ Automated.py # Main analyzer: normalize → detect → alert (reads CSV)
├─ AI-tester.py # Prototype tester for rule tuning / quick runs
├─ Watch-Xel-Convert-And-Analyze.ps1# PowerShell pipeline: convert .xel → merge CSV → run analyzer
├─ sample_sql_logs.csv # Sample CSV used for screenshots/tests (safe synthetic data)
├─ print_before_after.py # Helper: prints Statement vs NormalizedQuery for screenshots
├─ filter_impact_report.py # Helper: shows filter impact (before/after counts + dropped rows)
├─ README.md
└─ .gitignore


## Prerequisites
### Software
- **Python 3.10+**
- **PowerShell 7+** (for the `.xel` conversion script)
- **SQL Server PowerShell module** (`SqlServer`) installed on the machine performing `.xel` conversion
- Network access to an SMTP server (e.g., Gmail SMTP) if using email alerts

### Python Packages
Install dependencies:
pip install pandas

**CONFIGURATION (EMAIL)**
Create a .env file in the same directory as Automated.py:

  SMTP_SERVER=smtp.gmail.com
  SMTP_PORT=587
  EMAIL_SENDER=your_sender@gmail.com
  EMAIL_PASSWORD=your_app_password
  EMAIL_RECIPIENT=recipient1@example.com,recipient2@example.com

IMPORTANT
- Do not commit .env into Git.
- For Gmail, use an App Password (requires 2-Step Verification).

USAGE

1) Run the analyzer on a CSV file (Python only)
The CSV must include a Statement column containing SQL text.
  python Automated.py path/to/audit_output.csv

Expected behavior:
- Prints analysis status
- If detections exist → sends an email alert containing counts and sample flagged queries
- If no detections → prints a clean “[OK] No suspicious queries found …” message

2) Convert .xel files and run analysis (PowerShell pipeline)
Edit the paths inside Watch-Xel-Convert-And-Analyze.ps1 (input folder, output folder, Python path), then run:
  pwsh .\Watch-Xel-Convert-And-Analyze.ps1

Expected behavior:
- Scans the .xel folder (skips incomplete download artifacts)
- Converts each .xel into a temporary CSV (parallelized)
- Merges into one daily CSV output
- Triggers Automated.py on the merged CSV

DETECTION LOGIC (CURRENT RULES)
1) WHERE present, missing comp_code
- Flags queries where a WHERE clause exists but comp_code is not found in the WHERE portion
- UPDATE statements are excluded (to reduce noise in current prototype)

2) INSERT missing run_no / running_no
- Flags INSERT statements that omit both field names

LIMITATIONS
- Passive monitoring: detection occurs after queries execute (no blocking).
- Rule-based heuristics: tuned for the project environment; may require adjustment for other systems.
- CSV schema depends on audit export/conversion; missing Statement column will cause analysis to skip safely.

SECURITY NOTES
- Never store credentials directly in source code. Use .env.
- Avoid committing raw audit logs to the repository (may contain sensitive data).
- Redact query content and user identifiers in screenshots intended for reports.

LICENSE / USAGE
This code is provided for capstone/prototyping purposes. Adaptation for production should include:
- secrets management (vault/environment)
- structured logging
- stronger schema validation
- expanded rule set and/or scoring model
- integrations with SIEM/ticketing tools
