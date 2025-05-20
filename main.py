import os
import re
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_file

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'super-secret-key'

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+)'
)
NGINX_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>.*?)" "(?P<ua>.*?)"'
)
SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.+)$'
)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_patterns(filename):
    patterns = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.lower())
    return patterns

SQLI_PATTERNS = load_patterns("SQLI_PATTERNS.txt")

def parse_apache_log(lines):
    parsed = []
    for line in lines:
        m = APACHE_PATTERN.match(line)
        if m:
            data = m.groupdict()
            try:
                data['datetime'] = datetime.strptime(
                    data['date'].split()[0], '%d/%b/%Y:%H:%M:%S'
                )
            except Exception:
                data['datetime'] = None

            req = data['request']
            parts = req.split()
            if len(parts) >= 3:
                data['method'] = parts[0]
                data['protocol'] = parts[-1]
                data['url'] = " ".join(parts[1:-1])
            else:
                data['method'], data['url'], data['protocol'] = '', '', ''
            parsed.append(data)
    return parsed


def detect_sqli_attempts(parsed_logs, patterns):
    attempts = []
    for entry in parsed_logs:
        url = entry.get('url', '')
        print("Prüfe URL:", url)
        for pat in patterns:
            if pat in url.lower():
                print("Treffer Pattern:", pat, "in", url)
                attempts.append({
                    'ip': entry.get('ip', ''),
                    'url': url,
                    'datetime': entry.get('datetime', '')
                })
                break
    return attempts

def load_traversal_patterns(filename="TRAVERSAL_PATTERNS.txt"):
    patterns = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns

TRAVERSAL_PATTERNS = load_traversal_patterns()

def detect_traversal_attempts(parsed_logs, patterns):
    attempts = []
    for entry in parsed_logs:
        url = entry.get('url', '')
        if any(pat.lower() in url.lower() for pat in patterns):
            attempts.append({
                'ip': entry.get('ip', ''),
                'url': url,
                'datetime': entry.get('datetime', '')
            })
    return attempts

def parse_syslog(lines):
    parsed = []
    for line in lines:
        m = SYSLOG_PATTERN.match(line)
        if m:
            data = m.groupdict()
            try:
                year = datetime.now().year
                dt_str = f"{data['month']} {data['day']} {year} {data['time']}"
                data['datetime'] = datetime.strptime(dt_str, "%b %d %Y %H:%M:%S")
            except Exception:
                data['datetime'] = None
            ip_search = re.search(r'from (\d+\.\d+\.\d+\.\d+)', data['message'])
            data['ip'] = ip_search.group(1) if ip_search else "-"
            parsed.append(data)
    return parsed

def parse_nginx_log(lines):
    parsed = []
    for line in lines:
        m = NGINX_PATTERN.match(line)
        if m:
            data = m.groupdict()
            try:
                data['datetime'] = datetime.strptime(
                    data['date'].split()[0], '%d/%b/%Y:%H:%M:%S'
                )
            except Exception:
                data['datetime'] = None
            req = data['request']
            parts = req.split()
            if len(parts) >= 3:
                data['method'] = parts[0]
                data['protocol'] = parts[-1]
                data['url'] = " ".join(parts[1:-1])
            else:
                data['method'], data['url'], data['protocol'] = '', '', ''
            parsed.append(data)
    return parsed

def detect_log_format(lines):
    for line in lines[:10]:
        if NGINX_PATTERN.match(line):
            return 'nginx'
        if APACHE_PATTERN.match(line):
            return 'apache'
        if SYSLOG_PATTERN.match(line):
            return 'syslog'
    return None

def parse_log_dynamic(lines):
    fmt = detect_log_format(lines)
    if fmt == 'nginx':
        return parse_nginx_log(lines), 'nginx'
    elif fmt == 'apache':
        return parse_apache_log(lines), 'apache'
    elif fmt == 'syslog':
        return parse_syslog(lines), 'syslog'
    else:
        return [], None

def analyze(parsed_logs, log_type):
    stats = {}
    stats['total_requests'] = len(parsed_logs)

    if log_type in ('apache', 'nginx'):
        stats['ip_counter']   = Counter(l['ip'] for l in parsed_logs)
        stats['top_ips']      = stats['ip_counter'].most_common(5)
        stats['url_counter']  = Counter(l['url'] for l in parsed_logs)
        stats['top_urls']     = stats['url_counter'].most_common(5)
        stats['status_counter'] = Counter(l['status'] for l in parsed_logs)
    elif log_type == 'syslog':
        stats['ip_counter']   = Counter(l['ip'] for l in parsed_logs if l.get('ip') and l['ip'] != '-')
        stats['top_ips']      = stats['ip_counter'].most_common(5)
        stats['url_counter']  = Counter(l['service'] for l in parsed_logs if 'service' in l)
        stats['top_urls']     = stats['url_counter'].most_common(5)
        stats['status_counter'] = Counter()

    stats['brute_force'] = []
    if log_type in ('apache', 'nginx'):
        login_failures = defaultdict(list)
        for l in parsed_logs:
            if '/login' in l['url'] and l['status'] in ['401', '403']:
                login_failures[l['ip']].append(l['datetime'])

        for ip, times in login_failures.items():
            times = sorted(t for t in times if t is not None)
            for i in range(len(times) - 4):
                if (times[i + 4] - times[i]).total_seconds() <= 60:
                    stats['brute_force'].append(ip)
                    break
        stats['brute_force'] = list(set(stats['brute_force']))
    elif log_type == 'syslog':
        login_failures = defaultdict(list)
        for l in parsed_logs:
            if 'Failed password' in l.get('message', '') and l.get('ip') != '-':
                login_failures[l['ip']].append(l['datetime'])
        for ip, times in login_failures.items():
            times = sorted(t for t in times if t is not None)
            for i in range(len(times) - 4):
                if (times[i + 4] - times[i]).total_seconds() <= 60:
                    stats['brute_force'].append(ip)
                    break
        stats['brute_force'] = list(set(stats['brute_force']))

    stats['error_ips'] = []
    if log_type in ('apache', 'nginx'):
        for ip in stats['ip_counter']:
            err_count = sum(
                1 for l in parsed_logs
                if l['ip'] == ip and (l['status'].startswith('4') or l['status'].startswith('5'))
            )
            if err_count > 10:
                stats['error_ips'].append(ip)
    elif log_type == 'syslog':
        for ip in stats['ip_counter']:
            err_count = sum(
                1 for l in parsed_logs
                if l['ip'] == ip and (
                    'failed password' in l.get('message', '').lower()
                    or 'error' in l.get('message', '').lower()
                    or 'fail' in l.get('message', '').lower()
                )
            )
            if err_count > 10:
                stats['error_ips'].append(ip)

    # --- Ungewöhnliche Zugriffszeiten (nachts 0-5 Uhr) ---
    stats['night_ips'] = []
    for ip in stats['ip_counter']:
        times = [
            l['datetime'] for l in parsed_logs
            if l['ip'] == ip and l.get('datetime') and l['datetime'].hour < 5
        ]
        if len(times) > 10:
            stats['night_ips'].append(ip)

    stats['traversal_attempts'] = []
    if log_type in ('apache', 'nginx'):
        stats['traversal_attempts'] = detect_traversal_attempts(parsed_logs, TRAVERSAL_PATTERNS)

    stats['sqli_attempts'] = []
    if log_type in ('apache', 'nginx'):
        stats['sqli_attempts'] = detect_sqli_attempts(parsed_logs, SQLI_PATTERNS)

    stats['root_logins'] = []
    if log_type == 'syslog':
        stats['root_logins'] = [
            {
                'ip': l.get('ip', ''),
                'datetime': l.get('datetime', ''),
                'message': l.get('message', '')
            }
            for l in parsed_logs
            if 'sshd' in l.get('service', '')
            and 'Accepted' in l.get('message', '')
            and 'for root' in l.get('message', '')
        ]

    return stats

@app.route('/', methods=['GET', 'POST'])
def index():
    stats = None
    alert = None
    log_type = None
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['logfile']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            parsed_logs, log_type = parse_log_dynamic(lines)
            stats = analyze(parsed_logs, log_type) if parsed_logs else None
            if stats and (stats['brute_force'] or stats['error_ips'] or stats['night_ips']):
                alert = "Suspicious Activity Detected!"
            return render_template('index.html', stats=stats, alert=alert, log_type=log_type)
        else:
            flash('Invalid file type')
    return render_template('index.html', stats=stats, alert=alert, log_type=log_type)

@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    if 'logfile' not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files['logfile']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file"}), 400
    lines = file.read().decode('utf-8', errors='ignore').splitlines()
    parsed_logs, log_type = parse_log_dynamic(lines)
    if not parsed_logs:
        return jsonify({"error": "Unbekanntes Log-Format"}), 400
    stats = analyze(parsed_logs, log_type)
    stats['log_type'] = log_type
    return jsonify(stats)


@app.route('/api/export', methods=['POST'])
def export_csv():
    if 'logfile' not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files['logfile']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file"}), 400
    lines = file.read().decode('utf-8', errors='ignore').splitlines()
    parsed_logs, log_type = parse_log_dynamic(lines)
    if not parsed_logs:
        return jsonify({"error": "Unbekanntes Log-Format"}), 400
    stats = analyze(parsed_logs, log_type)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP', 'URL', 'Status', 'Time', 'BruteForce', 'SQLi', 'Traversal', 'Night', 'Errors'])
    for log in parsed_logs:
        ip = log.get('ip', '')
        url = log.get('url', '')
        status = log.get('status', '')
        dt = log.get('datetime', '')
        is_bf = ip in stats.get('brute_force', [])
        is_sqli = any(at['ip'] == ip and at['url'] == url for at in stats.get('sqli_attempts', []))
        is_trav = any(at['ip'] == ip and at['url'] == url for at in stats.get('traversal_attempts', []))
        is_night = ip in stats.get('night_ips', [])
        is_error = ip in stats.get('error_ips', [])
        writer.writerow([ip, url, status, dt, is_bf, is_sqli, is_trav, is_night, is_error])
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="log_analysis.csv"
    )

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
