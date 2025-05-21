from analysis import parse_apache_log,  parse_nginx_log, parse_syslog

def test_parse_apache_log_full_line():
    log_line = '127.0.0.1 - - [20/May/2024:13:55:36 +0200] "GET /admin HTTP/1.1" 404 209'
    result = parse_apache_log(log_line)
    assert isinstance(result, dict)
    assert result['ip'] == '127.0.0.1'
    assert result['method'] == 'GET'
    assert result['url'] == '/admin'
    assert result['status'] == 404
    assert result['size'] == 209
    assert result['datetime'] == '20/May/2024:13:55:36 +0200'

def test_parse_apache_log_invalid_line():
    log_line = 'unvollständige oder kaputte zeile'
    result = parse_apache_log(log_line)
    assert result is None

def test_parse_nginx_log_full_line():
    log_line = '192.168.0.1 - - [20/May/2024:14:21:17 +0200] "POST /login HTTP/1.1" 403 512'
    result = parse_nginx_log(log_line)
    assert isinstance(result, dict)
    assert result['ip'] == '192.168.0.1'
    assert result['method'] == 'POST'
    assert result['url'] == '/login'
    assert result['status'] == 403
    assert result['size'] == 512
    assert result['datetime'] == '20/May/2024:14:21:17 +0200'

def test_parse_nginx_log_invalid_line():
    log_line = 'keine gültige nginx zeile'
    result = parse_nginx_log(log_line)
    assert result is None

def test_parse_syslog_full_line():
    log_line = 'May 20 14:21:17 servername sshd[12345]: Failed password for root from 192.168.0.1 port 4242 ssh2'
    result = parse_syslog(log_line)
    assert isinstance(result, dict)
    assert result['month'] == 'May'
    assert result['day'] == '20'
    assert result['time'] == '14:21:17'
    assert result['host'] == 'servername'
    assert result['process'] == 'sshd'
    assert result['pid'] == '12345'
    assert result['message'].startswith('Failed password for root')

def test_parse_syslog_invalid_line():
    log_line = 'unbekannte formatierte zeile'
    result = parse_syslog(log_line)
    assert result is None