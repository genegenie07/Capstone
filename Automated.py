import sys
import os
import re
from pathlib import Path
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# -------- .env LOADER (no external dependency) --------
def load_env_file(env_path: Path, override: bool = False) -> None:
    """
    Minimal .env loader:
      - Ignores blank lines and lines starting with '#'
      - Supports KEY=VALUE (VALUE may be quoted with ' or ")
      - By default, does not override existing environment variables
    """
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')

        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value


# Load .env from the same folder as this script (works even if launched elsewhere)
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_env_file(ENV_PATH)


# -------- CONFIG (from .env / environment variables) --------
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")  # can be comma-separated


def _validate_email_config() -> None:
    missing = []
    if not EMAIL_SENDER:
        missing.append("EMAIL_SENDER")
    if not EMAIL_PASSWORD:
        missing.append("EMAIL_PASSWORD")
    if not EMAIL_RECIPIENT:
        missing.append("EMAIL_RECIPIENT")
    if missing:
        raise ValueError(
            "Missing required email config in .env/environment: "
            + ", ".join(missing)
            + f"\nExpected .env at: {ENV_PATH}"
        )


# -------- EMAIL FUNCTION --------
def send_email(subject: str, body: str):
    try:
        _validate_email_config()

        # Support multiple recipients via comma-separated list
        recipients = [r.strip() for r in EMAIL_RECIPIENT.split(",") if r.strip()]
        if not recipients:
            raise ValueError("EMAIL_RECIPIENT is empty after parsing.")

        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"[SUCCESS] Email sent to {', '.join(recipients)}")

    except Exception as e:
        print(f"[EMAIL ERROR] Could not send email: {e}")


# -------- ANALYSIS LOGIC --------
def normalize_sql(statement):
    if pd.isnull(statement):
        return ""
    statement = statement.lower()
    statement = re.sub(r"--.*?$", "", statement, flags=re.MULTILINE)
    statement = re.sub(r"/\*.*?\*/", "", statement, flags=re.DOTALL)
    statement = re.sub(r"'(?:''|[^'])*'", "?", statement)
    statement = re.sub(r"\b\d+(\.\d+)?\b", "?", statement)
    statement = re.sub(r"\s+", " ", statement).strip()
    return statement


def where_without_comp_code(query):
    if query.startswith("update"):
        return False
    match = re.search(r"\bwhere\b(.*)", query)
    if not match:
        return False
    return "comp_code" not in match.group(1)


def insert_missing_run_no(query):
    if not query.startswith("insert"):
        return False
    return "run_no" not in query and "running_no" not in query


def analyze_and_alert(log_file_path: str):
    print(f"[ANALYZING] {log_file_path}...")

    if not os.path.exists(log_file_path):
        print(f"[ERROR] File not found: {log_file_path}")
        return

    try:
        df = pd.read_csv(log_file_path)
    except Exception as e:
        print(f"[ERROR] Could not read CSV: {e}")
        return

    if "Statement" not in df.columns:
        print(f"[SKIP] No 'Statement' column in {os.path.basename(log_file_path)}")
        return

    df["NormalizedQuery"] = df["Statement"].apply(normalize_sql)

    # Filter out SELECTs with 'key'
    df = df[~((df["NormalizedQuery"].str.startswith("select")) & (df["NormalizedQuery"].str.contains("key")))]

    df["WhereMissingCompCode"] = df["NormalizedQuery"].apply(where_without_comp_code)
    df["InsertMissingRunNo"] = df["NormalizedQuery"].apply(insert_missing_run_no)

    missing_comp_code_df = df[df["WhereMissingCompCode"]]
    missing_run_no_df = df[df["InsertMissingRunNo"]]

    if missing_comp_code_df.empty and missing_run_no_df.empty:
        print(f"[OK] No suspicious queries found in {os.path.basename(log_file_path)}")
        return

    body_parts = []
    body_parts.append(f"File: {log_file_path}\n")

    count_comp = len(missing_comp_code_df)
    body_parts.append(f"Queries with WHERE but missing comp_code: {count_comp}")
    if not missing_comp_code_df.empty:
        body_parts.append("\n".join(missing_comp_code_df["NormalizedQuery"].head(10).tolist()))

    body_parts.append("\n-----------------------------\n")

    count_run = len(missing_run_no_df)
    body_parts.append(f"INSERT queries missing run_no or running_no: {count_run}")
    if not missing_run_no_df.empty:
        body_parts.append("\n".join(missing_run_no_df["NormalizedQuery"].head(10).tolist()))

    send_email(
        subject=f"SQL Alert: Suspicious Queries Detected ({os.path.basename(log_file_path)})",
        body="\n\n".join(body_parts),
    )


# -------- MAIN EXECUTION --------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[USAGE] python Automated.py <path_to_csv_file>")
        sys.exit(1)

    analyze_and_alert(sys.argv[1])
    print("[DONE] Analysis script finished.")