from analysis import detect_bruteforce

def test_whitelist_prevents_alerts(monkeypatch):
    monkeypatch.setenv("WHITELIST_IPS", "1.2.3.4")
    logs = [{'ip':'1.2.3.4','status':401},{'ip':'1.2.3.4','status':401},{'ip':'1.2.3.4','status':401}]
    res = detect_bruteforce(logs, threshold=3)
    assert '1.2.3.4' not in res
