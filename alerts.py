import os, smtplib, json
from email.message import EmailMessage

try:
    import requests
except Exception:
    requests = None

DRY_RUN = os.getenv("DRY_RUN_ALERTS", "0") == "1"

def _dry_log(where: str, payload):
    print(f"[ALERT-DRYRUN] -> {where}: {payload}")

def send_slack(text: str):
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        return
    if DRY_RUN or requests is None:
        _dry_log("slack", {"text": text}); return
    try:
        requests.post(url, json={"text": text}, timeout=5)
    except Exception:
        pass

def send_email(subject: str, body: str):
    host = os.getenv("SMTP_HOST"); user = os.getenv("SMTP_USER"); pwd = os.getenv("SMTP_PASS")
    to = os.getenv("ALERT_EMAIL_TO")
    if not all([host, user, pwd, to]):
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject; msg["From"] = user; msg["To"] = to
        msg.set_content(body)
        with smtplib.SMTP(host, 587) as s:
            s.starttls(); s.login(user, pwd); s.send_message(msg)
    except Exception:
        pass

def send_webhook(payload: dict):
    url = os.getenv("GENERIC_WEBHOOK_URL")
    if not url:
        return
    if DRY_RUN or requests is None:
        _dry_log("webhook", payload); return
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception:
        pass
