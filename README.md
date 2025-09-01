# 🔐 Security Log Analyzer

**Stateless** Web-Tool (Flask + Chart.js) zur schnellen Analyse von Access- & Syslog-Dateien – mit **erklärbaren Security-Alerts** (Brute-Force, SSH, SQLi, Traversal, optional Sensitive, Scanner/Recon).

**Live-Demo:**  `https://security-log-analyzer.onrender.com`  
**Stateless:** Es wird nichts gespeichert; Verarbeitung nur im RAM. CSV-Export & Mini-API inklusive.


## Features

* **Stateless Analyse:** Upload **oder** Freitext; Verarbeitung nur im RAM
* **Visualisierungen:** Charts für **Top-IPs** & **Statuscodes** (Chart.js)
* **Erklärbare Alerts:** Gründe, Zeitraum & Beispiel-URLs (Brute-Force, **SSH**, **SQLi**, **Traversal**, optional Sensitive, Scanner/Recon)
* **CSV-Export:** One-Shot Export
* **Konfigurierbar:** Pattern-Dateien (`SQLI_*.txt`, `TRAVERSAL_*.txt`, `SENSITIVE_*.txt`), Whitelist, mehrstufiges URL-Decoding
* **Ops-ready:** Health-Check `/health`, Gunicorn-Start, CI, Docker-bereit

---

## Screenshot

<img width="1251" height="1279" alt="image" src="https://github.com/user-attachments/assets/9c0421fe-ad05-4581-aead-11aeb535ad12" />

---

## Quickstart

Voraussetzung: **Python 3.10+**

```bash
git clone https://github.com/Sabi1337/Security-Log-Analyzer.git
cd Security-Log-Analyzer

python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate

pip install -r requirements.txt
# Windows:
copy .env.example .env
# macOS/Linux:
# cp .env.example .env

python main.py
```

App öffnen: [http://127.0.0.1:8000](http://127.0.0.1:8000)

**Smoke-Test** (im UI → „optional Logtext einfügen“):

```
203.0.113.5 - - [21/May/2025:01:02:10 +0000] "POST /login HTTP/1.1" 401 234
203.0.113.5 - - [21/May/2025:01:02:20 +0000] "POST /login HTTP/1.1" 401 234
203.0.113.2 - - [21/May/2025:13:11:52 +0000] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 404 98
203.0.113.1 - - [21/May/2025:12:44:10 +0000] "GET /login.php?username=admin&password=' OR 1=1 -- HTTP/1.1" 200 1032
```

---

## Konfiguration-Env

Nutze `.env.example` als Vorlage:

```env
FLASK_SECRET_KEY=change-me
MAX_BYTES=1048576

# Detection
BF_THRESHOLD=5
SSH_BF_THRESHOLD=5
WHITELIST_IPS=
IGNORE_PRIVATE_IPS=0   # Demo: 0 (auch 10./172./192.168.* sichtbar), Prod: 1
DECODE_DEPTH=2         # mehrstufiges %-Decoding
SCAN_UA=1
ENABLE_SENSITIVE=0     # optional

# Pattern-Dateien
SQLI_PATTERNS_FILE=SQLI_PATTERNS.txt
TRAVERSAL_PATTERNS_FILE=TRAVERSAL_PATTERNS.txt
SENSITIVE_PATTERNS_FILE=SENSITIVE_PATTERNS.txt

# Aktive Alerts (Demo: nur Konsole)
ENABLE_ACTIVE_ALERTS=1
MIN_ALERT_SEVERITY=warning
DRY_RUN_ALERTS=1

# Ziele (nur setzen, wenn wirklich senden)
SLACK_WEBHOOK_URL=
GENERIC_WEBHOOK_URL=
SMTP_HOST=
SMTP_USER=
SMTP_PASS=
ALERT_EMAIL_TO=
```

**Produktion:** `IGNORE_PRIVATE_IPS=1`, `MIN_ALERT_SEVERITY=critical`, `DRY_RUN_ALERTS=0` + Ziel (Slack/SMTP/Webhook) setzen.  
**Check:** Beim Start erscheint `PATTERN COUNTS: X SQLi, Y Traversal, Z Sensitive`.

---

## Benutzung

### UI

1. Datei wählen **oder** Logtext einfügen  
2. „Analysieren“ → Charts & **Security Alerts**  
3. Optional: **CSV exportieren**

### API

**POST** `/analyze`

* `multipart/form-data` mit `file` **oder**
* `application/x-www-form-urlencoded` mit `content=<logtext>`

Beispiel:

```bash
curl -X POST http://localhost:8000/analyze   -H "Content-Type: application/x-www-form-urlencoded"   --data-urlencode "content=203.0.113.5 - - [..] \"GET /login HTTP/1.1\" 401 123"
```

**POST** `/export.csv` – gleicher Input, liefert CSV-Stream.

---

## Angriffsmuster--Patterns

* **SQL-Injection:** `SQLI_PATTERNS.txt`
* **Directory Traversal:** `TRAVERSAL_PATTERNS.txt`
* **Sensitive Files (optional):** `SENSITIVE_PATTERNS.txt`

Pattern sind **case-insensitive Substrings**. URLs werden bis zu `DECODE_DEPTH` decodiert (erkennt `%2e%2e`, `%27%20or%201%3D1` etc.).  
Tipp: präzise Pfade statt generischer Wörter eintragen.

---

## Tests

Installation & Run:

```bash
pip install -r requirements.txt
pip install pytest
pytest -q
```

Enthalten: Parser-, Detection-, API-, Whitelist- & Pattern-Loader-Tests (`tests/`).

---

## Projektstruktur

```
.
├─ main.py                 # Flask-App (stateless)
├─ analysis.py             # Parser & Detections (erklärbare Alerts)
├─ alerts.py               # Slack/SMTP/Webhook (optional)
├─ templates/index.html    # UI
├─ static/{styles.css,main.js}
├─ SQLI_PATTERNS.txt
├─ TRAVERSAL_PATTERNS.txt
├─ SENSITIVE_PATTERNS.txt  # optional
├─ test_logs/              # Beispiel-Logs
├─ tests/                  # pytest
├─ .github/workflows/ci.yml
└─ requirements.txt
```

---

## Deployment-Render

* **Build:**  
  `pip install --upgrade pip && pip install -r requirements.txt`
* **Start:**  
  `gunicorn -w 2 -k gthread --threads 4 --timeout 60 -b 0.0.0.0:$PORT main:app`
* **Health Check:** `/health`  
* **Env Vars:** siehe `.env.example`

---

## Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_ENV=production
CMD ["bash", "-lc", "gunicorn -w 2 -k gthread --threads 4 --timeout 60 -b 0.0.0.0:$PORT main:app"]
```

---

## Sicherheitshinweise

* **Keine Persistenz**, Limit via `MAX_BYTES`  
* **URL-Fetch** deaktiviert  
* Pattern-basiert → **False Positives** möglich  
* Prod: Private-IPs ignorieren, Severity hochsetzen, echtes Alert-Ziel konfigurieren

---

## Roadmap

* Rate-Limit pro Request
* Light/Dark-Toggle
* Weitere Pattern-Sets (WordPress, Laravel, phpMyAdmin)
* JSON-Export
* OpenAPI-Spec

---

## Mitwirken

PRs willkommen:

1. Fork  
2. Branch: `feat/<kurzname>`  
3. Commit: `feat: <kurze beschreibung>`  
4. PR erstellen

---

## Lizenz

**MIT** – siehe `LICENSE`.
