from analysis import detect_bruteforce, get_top_ips

def test_detect_bruteforce_finds_ip():
    logs = [
        {'ip': '1.2.3.4', 'status': 401, 'timestamp': '2024-05-20T10:00:01'},
        {'ip': '1.2.3.4', 'status': 401, 'timestamp': '2024-05-20T10:00:10'},
        {'ip': '1.2.3.4', 'status': 401, 'timestamp': '2024-05-20T10:00:20'},
        {'ip': '8.8.8.8', 'status': 200, 'timestamp': '2024-05-20T11:00:00'},
    ]

    result = detect_bruteforce(logs, threshold=3)

    assert '1.2.3.4' in result
    assert result['1.2.3.4'] == 3

def test_detect_bruteforce_no_false_positive():
    logs = [
        {'ip': '5.5.5.5', 'status': 401, 'timestamp': '2024-05-20T12:00:00'},
        {'ip': '5.5.5.5', 'status': 401, 'timestamp': '2024-05-20T12:01:00'},
        {'ip': '5.5.5.5', 'status': 200, 'timestamp': '2024-05-20T12:01:30'},
    ]
    result = detect_bruteforce(logs, threshold=3)

    assert '5.5.5.5' not in result

def test_get_top_ips_returns_most_common():
    logs = [
        {'ip': '1.1.1.1', 'status': 200},
        {'ip': '2.2.2.2', 'status': 404},
        {'ip': '1.1.1.1', 'status': 401},
        {'ip': '3.3.3.3', 'status': 200},
        {'ip': '1.1.1.1', 'status': 404},
        {'ip': '2.2.2.2', 'status': 401},
    ]
    result = get_top_ips(logs, n=2)
    # Erwartetes Ergebnis: [('1.1.1.1', 3), ('2.2.2.2', 2)]
    assert result[0][0] == '1.1.1.1' and result[0][1] == 3
    assert result[1][0] == '2.2.2.2' and result[1][1] == 2