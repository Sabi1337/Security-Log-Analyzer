from __future__ import annotations

import os
import re
import ipaddress
from urllib.parse import unquote, unquote_plus
from datetime import datetime
from collections import defaultdict, Counter
from typing import Iterable, Dict, List, Tuple, Optional

from alerts import send_slack, send_email  # bewusst: KEIN Webhook hier

from dotenv import load_dotenv
load_dotenv()

# -------------------- Konfiguration --------------------
BRUTEFORCE_THRESHOLD    = int(os.getenv("BF_THRESHOLD", "5"))            # HTTP 401 (Web)
SSH_BF_THRESHOLD        = int(os.getenv("SSH_BF_THRESHOLD", "5"))        # SSH (Syslog)

SQLI_PATTERNS_FILE      = os.getenv("SQLI_PATTERNS_FILE", "SQLI_PATTERNS.txt")
TRAVERSAL_PATTERNS_FILE = os.getenv("TRAVERSAL_PATTERNS_FILE", "TRAVERSAL_PATTERNS.txt")
SENSITIVE_PATTERNS_FILE = os.getenv("SENSITIVE_PATTERNS_FILE", "SENSITIVE_PATTERNS.txt")

WHITELIST_IPS           = [s.strip() for s in os.getenv("WHITELIST_IPS", "").split(",") if s.strip()]
IGNORE_PRIVATE_IPS      = os.getenv("IGNORE_PRIVATE_IPS", "1") == "1"     # RFC1918/Loopback/Link-Local ignorieren

DECODE_DEPTH            = int(os.getenv("DECODE_DEPTH", "2"))             # URL-Decoding-Tiefe
SCAN_UA                 = os.getenv("SCAN_UA", "1") == "1"
SCANNER_TOKENS          = [t.strip().lower() for t in os.getenv(
    "SCANNER_TOKENS",
    "nikto,sqlmap,acunetix,wpscan,dirbuster,nmap,masscan,burpsuite,fuzz"
).split(",") if t.strip()]

# -------------------- Regexe --------------------
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

APACHE_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+)\s(?P<url>\S+)\s(?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+)\s(?P<url>\S+)\s(?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$'
)

SSH_FAIL_MARKERS = ("Failed password", "Invalid user")
USER_RE = re.compile(r"for (?:invalid user\s+)?(?P<user>\S+)")

# -------------------- Helfer --------------------
def _parse_apache_dt(s: str) -> Optional[str]:
    try:
        dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return None

def _is_ip_whitelisted(ip: str) -> bool:
    for item in WHITELIST_IPS:
        if not item:
            continue
        if "/" in item:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(item, strict=False):
                    return True
            except Exception:
                pass
        elif ip == item:
            return True
    return False

def _is_internal_ip(ip: str) -> bool:
    try:
        ipobj = ipaddress.ip_address(ip)
        return ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local
    except Exception:
        return False

def _should_ignore_ip(ip: str) -> bool:
    if not ip:
        return False
    if _is_ip_whitelisted(ip):
        return True
    if IGNORE_PRIVATE_IPS and _is_internal_ip(ip):
        return True
    return False

def _url_variants(s: str, depth: int = DECODE_DEPTH) -> List[str]:
    if not s:
        return []
    out = {s}
    cur = s
    for _ in range(depth):
        try:
            cur = unquote(cur)
            out.add(cur)
        except Exception:
            break
    cur = s
    for _ in range(depth):
        try:
            cur = unquote_plus(cur)
            out.add(cur)
        except Exception:
            break
    return list(out)

# -------------------- Parser --------------------
def parse_apache_log(line: str) -> Optional[Dict]:
    m = APACHE_COMBINED_RE.match(line) or APACHE_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    out = {
        "ip": d["ip"],
        "datetime": d["datetime"],
        "timestamp": _parse_apache_dt(d["datetime"]),
        "method": d.get("method"),
        "url": d.get("url"),
        "proto": d.get("proto"),
        "status": int(d["status"]),
        "size": int(d["size"]) if str(d["size"]).isdigit() else 0,
        "type": "apache",
    }
    if "referer" in d: out["referer"] = d.get("referer")
    if "ua" in d:      out["ua"]      = d.get("ua")
    return out

def parse_nginx_log(line: str) -> Optional[Dict]:
    m = NGINX_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    method, url, proto = "-", "-", "-"
    req = d.get("request") or ""
    parts = req.split()
    if len(parts) >= 1: method = parts[0]
    if len(parts) >= 2: url = parts[1]
    if len(parts) >= 3: proto = parts[2]
    return {
        "ip": d["ip"],
        "datetime": d["date"],
        "timestamp": _parse_apache_dt(d["date"]),
        "method": method, "url": url, "proto": proto,
        "status": int(d["status"]),
        "size": int(d["size"]) if str(d["size"]).isdigit() else 0,
        "referer": d.get("referer"),
        "ua": d.get("ua"),
        "type": "nginx",
    }

def parse_syslog(line: str) -> Optional[Dict]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    msg = d["message"]

    ip = None
    ipm = IP_RE.search(msg)
    if ipm:
        ip = ipm.group(0)
    out = {
        "month": d["month"], "day": d["day"], "time": d["time"],
        "host": d["host"], "process": d["service"].strip(), "pid": d.get("pid"),
        "message": msg, "ip": ip, "type": "syslog",
    }

    # eingebettete Access-Zeile erkennen
    em = APACHE_COMBINED_RE.match(msg) or APACHE_RE.match(msg) or NGINX_RE.match(msg)
    if em:
        gd = em.groupdict()
        if "datetime" in gd:
            out["timestamp"] = _parse_apache_dt(gd["datetime"])
            out["method"] = gd.get("method")
            out["url"]    = gd.get("url")
            out["proto"]  = gd.get("proto")
            out["status"] = int(gd["status"]) if gd.get("status") else None
            out["size"]   = int(gd["size"]) if gd.get("size","").isdigit() else 0
            if "referer" in gd: out["referer"] = gd.get("referer")
            if "ua"      in gd: out["ua"]      = gd.get("ua")
        elif "date" in gd:
            req = (gd.get("request") or "").split()
            if len(req) >= 1: out["method"] = req[0]
            if len(req) >= 2: out["url"]    = req[1]
            if len(req) >= 3: out["proto"]  = req[2]
            out["timestamp"] = _parse_apache_dt(gd["date"])
            out["status"]    = int(gd["status"]) if gd.get("status") else None
            out["size"]      = int(gd["size"]) if gd.get("size","").isdigit() else 0
            out["referer"]   = gd.get("referer")
            out["ua"]        = gd.get("ua")

    return out

# -------------------- Pattern-Loader --------------------
def _load_patterns(path: str):
    pats = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = path if os.path.isabs(path) else os.path.join(base_dir, path)
    if not os.path.exists(full_path):
        return pats
    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#") or s == "...":
                continue
            pats.append((re.compile(re.escape(s), re.IGNORECASE), s))
    return pats

SQLI_PATTERNS       = _load_patterns(SQLI_PATTERNS_FILE)
TRAVERSAL_PATTERNS  = _load_patterns(TRAVERSAL_PATTERNS_FILE)
SENSITIVE_PATTERNS  = _load_patterns(SENSITIVE_PATTERNS_FILE)

print("PATTERN COUNTS:",
      len(SQLI_PATTERNS), "SQLi,",
      len(TRAVERSAL_PATTERNS), "Traversal,",
      len(SENSITIVE_PATTERNS), "Sensitive")

# -------------------- Detections --------------------
def detect_bruteforce(logs: Iterable[Dict], threshold: int = BRUTEFORCE_THRESHOLD) -> Dict[str, int]:
    fails = defaultdict(int)
    for e in logs:
        ip = e.get("ip", "")
        if e.get("status") == 401 and not _should_ignore_ip(ip):
            fails[ip] += 1
    return {ip: c for ip, c in fails.items() if c >= threshold}

def detect_ssh_bruteforce(logs: Iterable[Dict], threshold: int = SSH_BF_THRESHOLD) -> Dict[str, Dict]:
    hits: Dict[str, Dict] = {}
    for e in logs:
        if e.get("type") != "syslog":
            continue
        proc = (e.get("process") or "").lower()
        if "sshd" not in proc:
            continue
        msg = e.get("message", "")
        if not any(m in msg for m in SSH_FAIL_MARKERS):
            continue
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue

        d = hits.setdefault(ip, {"count": 0, "users": set(), "first_ts": None, "last_ts": None})
        d["count"] += 1

        m = USER_RE.search(msg)
        if m:
            d["users"].add(m.group("user"))

        ts = f"{e.get('month','')} {e.get('day','')} {e.get('time','')}".strip()
        d["first_ts"] = ts if d["first_ts"] is None else min(d["first_ts"], ts)
        d["last_ts"]  = ts if d["last_ts"]  is None else max(d["last_ts"], ts)

    return {ip: d for ip, d in hits.items() if d["count"] >= threshold}

def detect_sqli(logs: Iterable[Dict]) -> Dict[str, int]:
    hits = defaultdict(int)
    if not SQLI_PATTERNS:
        return {}
    for e in logs:
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue
        for candidate in _url_variants(e.get("url", "")):
            found = False
            for p, _label in SQLI_PATTERNS:
                if p.search(candidate):
                    hits[ip] += 1
                    found = True
                    break
            if found:
                break
    return dict(hits)

def detect_traversal(logs: Iterable[Dict]) -> Dict[str, int]:
    hits = defaultdict(int)
    if not TRAVERSAL_PATTERNS:
        return {}
    for e in logs:
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue
        for candidate in _url_variants(e.get("url", "")):
            found = False
            for p, _label in TRAVERSAL_PATTERNS:
                if p.search(candidate):
                    hits[ip] += 1
                    found = True
                    break
            if found:
                break
    return dict(hits)

def detect_sensitive(logs: Iterable[Dict]) -> Dict[str, int]:
    hits = defaultdict(int)
    if not SENSITIVE_PATTERNS:
        return {}
    for e in logs:
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue
        for candidate in _url_variants(e.get("url", "")):
            found = False
            for p, _label in SENSITIVE_PATTERNS:
                if p.search(candidate):
                    hits[ip] += 1
                    found = True
                    break
            if found:
                break
    return dict(hits)

def detect_scanners(logs: Iterable[Dict]) -> Dict[str, int]:
    if not SCAN_UA:
        return {}
    hits = defaultdict(int)
    for e in logs:
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue
        ua = (e.get("ua") or "").lower()
        ref = (e.get("referer") or "").lower()
        if not ua and not ref:
            continue
        if any(tok in ua or tok in ref for tok in SCANNER_TOKENS):
            hits[ip] += 1
    return dict(hits)

def get_top_ips(logs: Iterable[Dict], n: int = 5) -> List[Tuple[str, int]]:
    counter = Counter(e.get("ip", "-") for e in logs if e.get("ip"))
    return counter.most_common(n)

# -------------------- Alerts / Explainability --------------------
def report_critical(event: Dict):
    text = f"[ALERT] {event['type']} von {event.get('ip','-')} auf {event.get('path','-')}"
    send_slack(text)
    send_email("Security-Log-Analyzer Alert", text)

def _match_patterns_with_evidence(logs: Iterable[Dict], patterns: List[Tuple[re.Pattern, str]]):
    res: Dict[str, Dict] = {}
    if not patterns:
        return res
    for e in logs:
        ip = e.get("ip") or "-"
        if _should_ignore_ip(ip):
            continue
        urls = _url_variants(e.get("url", ""))
        if not urls:
            continue

        matched_label: Optional[str] = None
        for candidate in urls:
            for p, label in patterns:
                if p.search(candidate):
                    matched_label = label
                    break
            if matched_label:
                break
        if not matched_label:
            continue

        r = res.setdefault(ip, {"count": 0, "first_ts": None, "last_ts": None,
                                "patterns": Counter(), "samples": []})
        r["count"] += 1
        r["patterns"][matched_label] += 1

        ts = e.get("timestamp")
        if ts:
            r["first_ts"] = ts if not r["first_ts"] else min(r["first_ts"], ts)
            r["last_ts"]  = ts if not r["last_ts"]  else max(r["last_ts"], ts)

        if len(r["samples"]) < 3 and e.get("url"):
            r["samples"].append(e["url"])
    return res

def summarize_alerts(logs: Iterable[Dict]) -> List[Dict]:
    alerts: List[Dict] = []

    bf = detect_bruteforce(logs)
    for ip, cnt in bf.items():
        sev = "critical" if cnt >= BRUTEFORCE_THRESHOLD * 2 else "warning"
        reasons = [f"{cnt} fehlgeschlagene Logins (HTTP 401, Schwelle {BRUTEFORCE_THRESHOLD})"]
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "BruteForce", "ip": ip, "count": cnt, "severity": sev,
            "reasons": reasons, "first_ts": None, "last_ts": None,
            "samples": [], "top_patterns": []
        })

    ssh = detect_ssh_bruteforce(logs)
    for ip, d in ssh.items():
        users = ", ".join(sorted(d["users"])) if d["users"] else "unbekannt"
        reasons = [f"{d['count']} fehlgeschlagene SSH-Logins (Schwelle {SSH_BF_THRESHOLD})",
                   f"Benutzer: {users}"]
        sev = "critical" if d["count"] >= SSH_BF_THRESHOLD * 2 else "warning"
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "SSH BruteForce", "ip": ip, "count": d["count"], "severity": sev,
            "reasons": reasons, "first_ts": d["first_ts"], "last_ts": d["last_ts"],
            "samples": [], "top_patterns": []
        })

    sqli = _match_patterns_with_evidence(logs, SQLI_PATTERNS)
    trav = _match_patterns_with_evidence(logs, TRAVERSAL_PATTERNS)
    sens = _match_patterns_with_evidence(logs, SENSITIVE_PATTERNS)

    for ip, d in sqli.items():
        top = d["patterns"].most_common(2)
        reasons = [f"{d['count']} URL(s) mit SQLi-Mustern"]
        if top:
            reasons.append("Top-Muster: " + ", ".join(f"„{k}“×{v}" for k, v in top))
        sev = "warning" if d["count"] < 3 else "critical"
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "SQLi", "ip": ip, "count": d["count"], "severity": sev,
            "reasons": reasons, "first_ts": d["first_ts"], "last_ts": d["last_ts"],
            "samples": d["samples"], "top_patterns": [k for k, _ in top]
        })

    for ip, d in trav.items():
        top = d["patterns"].most_common(2)
        reasons = [f"{d['count']} URL(s) mit Path-Traversal-Mustern"]
        if top:
            reasons.append("Top-Muster: " + ", ".join(f"„{k}“×{v}" for k, v in top))
        sev = "warning" if d["count"] < 5 else "critical"
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "Traversal", "ip": ip, "count": d["count"], "severity": sev,
            "reasons": reasons, "first_ts": d["first_ts"], "last_ts": d["last_ts"],
            "samples": d["samples"], "top_patterns": [k for k, _ in top]
        })

    for ip, d in sens.items():
        top = d["patterns"].most_common(2)
        reasons = [f"{d['count']} Probe(n) auf sensible Dateien"]
        if top:
            reasons.append("Top-Ziele: " + ", ".join(f"„{k}“×{v}" for k, v in top))
        sev = "warning" if d["count"] < 3 else "critical"
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "Sensitive Files", "ip": ip, "count": d["count"], "severity": sev,
            "reasons": reasons, "first_ts": d["first_ts"], "last_ts": d["last_ts"],
            "samples": d["samples"], "top_patterns": [k for k, _ in top]
        })

    scn = detect_scanners(logs)
    for ip, cnt in scn.items():
        reasons = [f"{cnt} Request(s) mit bekannten Scanner-User-Agents"]
        if _is_internal_ip(ip):
            reasons.append("interne IP")
        alerts.append({
            "type": "Scanner/Recon", "ip": ip, "count": cnt, "severity": "warning",
            "reasons": reasons, "first_ts": None, "last_ts": None,
            "samples": [], "top_patterns": []
        })

    by_ip = Counter(a["ip"] for a in alerts)
    for a in alerts:
        if by_ip[a["ip"]] >= 2 and a["severity"] == "warning":
            a["severity"] = "critical"
            a["reasons"].append("Mehrere Angriffssignale von derselben IP")

    sev_rank = {"critical": 0, "warning": 1}
    alerts.sort(key=lambda x: (sev_rank.get(x["severity"], 2), -x["count"], x["type"]))
    return alerts
