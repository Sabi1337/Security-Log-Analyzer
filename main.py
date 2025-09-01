import os, io, csv
from flask import Flask, request, render_template, jsonify, send_file

from dotenv import load_dotenv
load_dotenv()

from analysis import (
    parse_apache_log, parse_nginx_log, parse_syslog,
    detect_bruteforce, detect_sqli, detect_traversal, detect_sensitive, detect_scanners,
    get_top_ips, summarize_alerts, report_critical
)


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me")

MAX_BYTES = int(os.getenv("MAX_BYTES", "1048576"))  # 1 MB
ENABLE_ACTIVE_ALERTS = os.getenv("ENABLE_ACTIVE_ALERTS", "0") == "1"
MIN_ALERT_SEVERITY = os.getenv("MIN_ALERT_SEVERITY", "critical").lower()

# ---------- Parser: pro Zeile Apache/Nginx/Syslog probieren ----------
def parse_lines(lines):
    parsed = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        e = parse_apache_log(s) or parse_nginx_log(s) or parse_syslog(s)
        if e:
            parsed.append(e)
    return parsed

def build_stats(parsed):
    from collections import Counter
    return {
        "total": len(parsed),
        "top_ips": get_top_ips(parsed, 5),
        "statuses": sorted(
            (k if k else 0, v) for k, v in Counter(e.get("status") for e in parsed if "status" in e).items()
        ),
        "bruteforce": detect_bruteforce(parsed),
        "sqli": detect_sqli(parsed),
        "traversal": detect_traversal(parsed),
        "sensitive": detect_sensitive(parsed),
        "scanners": detect_scanners(parsed),
        "alerts": summarize_alerts(parsed),   # <- für UI
    }

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/analyze")
def analyze():
    # Datei?
    if "file" in request.files and request.files["file"].filename:
        raw = request.files["file"].read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "file too large"}), 413
        text = raw.decode("utf-8", errors="ignore")
    # Text?
    elif request.form.get("content"):
        text = request.form["content"]
        if len(text.encode("utf-8")) > MAX_BYTES:
            return jsonify({"error": "text too large"}), 413
    else:
        return jsonify({"error": "no input"}), 400

    lines = text.splitlines()
    parsed = parse_lines(lines)
    stats = build_stats(parsed)

    # optionale aktive Alerts (Slack/Email/Webhook); DRYRUN in alerts.py
    if ENABLE_ACTIVE_ALERTS:
        global _SENT_ALERTS
        _SENT_ALERTS = globals().get("_SENT_ALERTS", set())
        want_warning = (MIN_ALERT_SEVERITY == "warning")
        for a in stats.get("alerts", []):
            if a["severity"] == "critical" or (want_warning and a["severity"] == "warning"):
                key = (a["type"], a["ip"], a.get("first_ts"), a.get("last_ts"))
                if key in _SENT_ALERTS:  # dedupe während Laufzeit
                    continue
                report_critical({
                    "type": a["type"],
                    "ip": a["ip"],
                    "path": (a.get("samples") or ["-"])[0]
                })
                try:
                    from alerts import send_webhook
                    send_webhook({
                        "source": "security-log-analyzer",
                        "severity": a["severity"],
                        "type": a["type"],
                        "ip": a["ip"],
                        "count": a["count"],
                        "reasons": a.get("reasons"),
                        "first_ts": a.get("first_ts"),
                        "last_ts": a.get("last_ts"),
                        "samples": a.get("samples"),
                    })
                except Exception:
                    pass
                _SENT_ALERTS.add(key)

    return jsonify(stats)

@app.post("/export.csv")
def export_csv():
    # Re-Use von /analyze für Eingabe + Stats
    resp = analyze()
    if isinstance(resp, tuple):  # (json, status) bei Fehler
        return resp
    data = resp.get_json()

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ip", "status", "type"])
    for ip, cnt in data.get("top_ips", []):
        w.writerow([ip, "", "top_ip"])
    for k in ("bruteforce", "sqli", "traversal", "sensitive", "scanners"):
        for ip, cnt in (data.get(k) or {}).items():
            w.writerow([ip, "", k])

    out.seek(0)
    return send_file(io.BytesIO(out.getvalue().encode("utf-8")),
                     mimetype="text/csv", as_attachment=True, download_name="analysis.csv")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
