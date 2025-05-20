# Security Log Analyzer

**Security Log Analyzer** ist ein Python/Flask-Webtool, das Server- und System-Logs auf typische Angriffsmuster, Fehlkonfigurationen und Security-Auffälligkeiten analysiert – visuell und automatisiert im Browser.

---

## Features

- **Unterstützte Logformate:**  
  - Apache `access.log`
  - nginx `access.log`
  - Linux/Unix `syslog`
- **Automatische Security-Checks:**
  - Brute-Force-Erkennung auf Login-Seiten
  - Directory Traversal & Scanner-Erkennung
  - SQL Injection Detection (Pattern-basiert)
  - Erkennung häufiger 4xx/5xx Fehler pro IP
  - Auffällige Zugriffszeiten (z. B. nachts)
  - SSH-Root-Logins (im Syslog)
- **Statistische Auswertung:**
  - Häufigste Endpunkte und IPs
  - Statuscode-Verteilung (als Diagramm)
- **Security Alerts:**
  - Verdächtige Aktivitäten werden direkt hervorgehoben
- **Export** (optional, vorbereitet):  
  - Ergebnisse als CSV/Excel-Datei

---

## Demo
 
![Dashboard Screenshot](https://github.com/user-attachments/assets/c8153694-ffe0-4b50-aef9-e6d22796f075)


---

## Quickstart

**1. Klone das Repo und installiere Abhängigkeiten**
```bash
git clone https://github.com/dein-github-name/security-log-analyzer.git
cd security-log-analyzer
pip install -r requirements.txt
