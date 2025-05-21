import re
from collections import defaultdict, Counter

def detect_bruteforce(logs, threshold=3):
    """
    Sucht nach IPs mit mehr als `threshold` fehlgeschlagenen Logins (Status 401).
    Gibt ein Dict mit gefundenen IPs zurück.
    """
    failed_logins = defaultdict(int)
    for entry in logs:
        if entry['status'] == 401:
            failed_logins[entry['ip']] += 1
    suspicious = {ip: count for ip, count in failed_logins.items() if count >= threshold}
    return suspicious

def get_top_ips(logs, n=5):
    """
    Gibt die n häufigsten IP-Adressen im Log zurück.
    logs: Liste von Log-Einträgen als Dictionaries, z.B. {'ip': '1.2.3.4', ...}
    n: wie viele Top-IPs ausgegeben werden sollen
    Rückgabe: Liste von Tupeln (IP, Anzahl)
    """
    ip_list = [entry['ip'] for entry in logs if 'ip' in entry]
    return Counter(ip_list).most_common(n)

def parse_apache_log(log_line):
    """
    Parst eine Apache Access Log Zeile.
    Gibt ein Dict mit den wichtigsten Infos zurück.
    Beispielzeile:
    127.0.0.1 - - [20/May/2024:13:55:36 +0200] "GET /admin HTTP/1.1" 404 209
    """
    pattern = (
        r'(?P<ip>\S+) '              # IP-Adresse
        r'\S+ \S+ '                  # zwei Felder überspringen
        r'\[(?P<datetime>[^\]]+)\] ' # Datum/Zeit
        r'"(?P<method>\S+) '         # HTTP-Methode
        r'(?P<url>\S+)'              # URL
        r'(?: [^"]*)?" '             # Rest der Anfrage
        r'(?P<status>\d{3}) '        # Statuscode
        r'(?P<size>\d+|-)'           # Response-Größe oder '-'
    )
    match = re.match(pattern, log_line)
    if match:
        data = match.groupdict()
        data['status'] = int(data['status'])
        if data['size'] == '-':
            data['size'] = 0
        else:
            data['size'] = int(data['size'])
        return data
    else:
        return None

def parse_nginx_log(log_line):
    pattern = (
        r'(?P<ip>\S+) '
        r'\S+ \S+ '
        r'\[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\S+) '
        r'(?P<url>\S+)'
        r'(?: [^"]*)?" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\d+|-)'
    )
    match = re.match(pattern, log_line)
    if match:
        data = match.groupdict()
        data['status'] = int(data['status'])
        if data['size'] == '-':
            data['size'] = 0
        else:
            data['size'] = int(data['size'])
        return data
    else:
        return None

def parse_syslog(log_line):
    pattern = (
        r'(?P<month>\w{3})\s+'
        r'(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<message>.*)'
    )
    match = re.match(pattern, log_line)
    if match:
        return match.groupdict()
    else:
        return None