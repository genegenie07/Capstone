import pandas as pd
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- CONFIG ---
log_file = "audit_output_2025-12-11.csv"

# --- EMAIL CONFIG ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "svlogger110@gmail.com"
EMAIL_PASSWORD = "klvaqqlionisjkyr"   # Gmail App Password
EMAIL_RECIPIENT = "eugenetanlx@starvisionit.com"

# --- LOAD LOG FILE ---
df = pd.read_csv(log_file)

# --- Normalize SQL for consistency ---
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

df["NormalizedQuery"] = df["Statement"].apply(normalize_sql)

# --- Ignore SELECT statements that contain 'key' ---
df = df[~(
    (df["NormalizedQuery"].str.startswith("select")) &
    (df["NormalizedQuery"].str.contains("key"))
)]

# --- WHERE without comp_code ---
def where_without_comp_code(query):
    if query.startswith("update"):
        return False
    match = re.search(r"\bwhere\b(.*)", query)
    if not match:
        return False
    return "comp_code" not in match.group(1)

df["WhereMissingCompCode"] = df["NormalizedQuery"].apply(where_without_comp_code)

# --- INSERT missing run_no ---
def insert_missing_run_no(query):
    if not query.startswith("insert"):
        return False
    return "run_no" not in query and "running_no" not in query

df["InsertMissingRunNo"] = df["NormalizedQuery"].apply(insert_missing_run_no)

# --- RESULTS ---
missing_comp_code_df = df[df["WhereMissingCompCode"]]
missing_run_no_df = df[df["InsertMissingRunNo"]]

# --- EMAIL FUNCTION ---
def send_email(subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)

# --- SEND ALERT IF NEEDED ---
if not missing_comp_code_df.empty or not missing_run_no_df.empty:
    body = []

    body.append("Suspicious SQL activity detected.\n")

    body.append(f"Queries with WHERE but missing comp_code: {len(missing_comp_code_df)}")
    if not missing_comp_code_df.empty:
        body.append(
            "\n".join(
                missing_comp_code_df["NormalizedQuery"].head(10).tolist()
            )
        )

    body.append("\n-----------------------------\n")

    body.append(f"INSERT queries missing run_no or running_no: {len(missing_run_no_df)}")
    if not missing_run_no_df.empty:
        body.append(
            "\n".join(
                missing_run_no_df["NormalizedQuery"].head(10).tolist()
            )
        )

    send_email(
        subject="SQL Alert: Suspicious Queries Detected",
        body="\n\n".join(body)
    )

    print("Email alert sent.")
else:
    print("No suspicious queries detected.")
