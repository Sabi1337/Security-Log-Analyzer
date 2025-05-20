# 🔐 Security Log Analyzer

Ein leichtgewichtiges Python-Tool zur Analyse von Webserver-Logs (Apache, Nginx, Syslog) mit Fokus auf die Erkennung von Sicherheitsbedrohungen wie Brute-Force-Angriffe, SQL-Injection und Directory Traversal.

---

## Funktionen

- Unterstützung für gängige Logformate: Apache, Nginx, Syslog
- Erkennung von Angriffsmustern mittels regulärer Ausdrücke
- Webbasiertes Dashboard mit Flask zur Visualisierung der Ergebnisse
- Modularer Aufbau für einfache Erweiterbarkeit
- Integration von Pattern-Dateien für SQL-Injection und Directory Traversal
---

## Installation

### Voraussetzungen

- Python 3.8 oder höher
- Pip (Python Package Installer)

### Schritte
1. Repository klonen:
   ```bash
   git clone https://github.com/Sabi1337/Security-Log-Analyzer.git
   cd Security-Log-Analyzer
   pip install -r requirements.txt
---

## 📂 Projektstruktur

```plaintext
  Security-Log-Analyzer/
  ├── app.py                   # Hauptanwendung mit Flask
  ├── log_parser.py            # Parser für verschiedene Logformate
  ├── pattern_matcher.py       # Erkennung von Angriffsmustern
  ├── templates/
  │   └── index.html           # HTML-Template für das Dashboard
  ├── static/
  │   └── style.css            # CSS-Datei für das Dashboard
  ├── test_logs/
  │   ├── apache.log           # Beispiel-Logdatei für Apache
  │   ├── nginx.log            # Beispiel-Logdatei für Nginx
  │   └── syslog.log           # Beispiel-Logdatei für Syslog
  ├── SQLI_PATTERNS.txt        # Muster für SQL-Injection
  ├── TRAVERSAL_PATTERNS.txt   # Muster für Directory Traversal
  └── README.md                # Diese Dokumentation
```
---

## ⚙️ Nutzung

1. Anwendung starten:
   ```bash
   python app.py

2.Im Browser öffnen:
http://localhost:5000

---

## 🧪 Beispiel-Logdateien

Im Verzeichnis `test_logs/` befinden sich Beispiel-Logdateien für Apache, Nginx und Syslog, die zur Demonstration und zum Testen der Anwendung genutzt werden können.
---

## 🔍 Angriffsmuster

Die Anwendung nutzt reguläre Ausdrücke, um spezifische Angriffsmuster zu erkennen:

- **SQL-Injection:** Definiert in `SQLI_PATTERNS.txt`
- **Directory Traversal:** Definiert in `TRAVERSAL_PATTERNS.txt`

Diese Dateien können erweitert werden, um zusätzliche Muster zu erfassen.
--- 

## 📈 Dashboard

Das integrierte Dashboard bietet eine übersichtliche Darstellung der Analyseergebnisse, einschließlich:

- Anzahl der erkannten Angriffe pro Typ
- Zeitliche Verteilung der Angriffe
- Betroffene IP-Adressen und Endpunkte

---

## 🧩 Erweiterungsmöglichkeiten

- **Weitere Angriffsmuster:** Integration zusätzlicher Pattern-Dateien für andere Angriffstypen
- **Authentifizierung:** Implementierung eines Login-Systems für das Dashboard
- **Datenbankanbindung:** Speicherung der Analyseergebnisse in einer Datenbank
- **Benachrichtigungen:** Versand von Alerts bei Erkennung kritischer Angriffe

---

## 🤝 Mitwirken

Beiträge sind herzlich willkommen! Bitte folge diesen Schritten:

1. Forke das Repository
2. Erstelle einen neuen Branch: `git checkout -b feature/neues-feature`
3. Führe deine Änderungen durch und committe sie: `git commit -m 'Füge neues Feature hinzu'`
4. Pushe den Branch: `git push origin feature/neues-feature`
5. Erstelle einen Pull Request

---

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz. Weitere Informationen findest du in der Datei `LICENSE`.

---

*Diese erweiterte Dokumentation soll sowohl Entwicklern als auch Sicherheitsexperten einen klaren Überblick über die Funktionalitäten und Einsatzmöglichkeiten des Security Log Analyzers bieten.*

