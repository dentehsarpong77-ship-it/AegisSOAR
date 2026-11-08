import pytest
from aegissoar.core.detector import DetectionEngine
from aegissoar.core.parser import parse_raw_log
from aegissoar.db import init_db


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


@pytest.mark.asyncio
async def test_sqli_detection_trigger():
    engine = DetectionEngine()
    log = '103.251.167.20 - - [08/Nov/2026:16:35:20 +0000] "GET /catalog?cat=1 UNION SELECT null, username, password FROM users -- HTTP/1.1" 500 500 "-" "curl/7.68.0"'
    event = parse_raw_log(log)

    incident = await engine.process_event(event)
    assert incident is not None
    assert incident.rule_id == "RULE_SQL_INJECTION"
    assert incident.mitre_technique == "T1190"
    assert incident.severity in ["HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_ssh_brute_force_threshold():
    engine = DetectionEngine()
    ip = "192.168.100.99"
    incident = None

    for i in range(4):
        log = f"Nov  8 16:30:{10 + i} server sshd[100]: Failed password for invalid user user{i} from {ip} port 50000 ssh2"
        event = parse_raw_log(log)
        res = await engine.process_event(event)
        if res:
            incident = res

    assert incident is not None
    assert incident.rule_id == "RULE_SSH_BRUTE_FORCE"
    assert incident.mitre_technique == "T1110.001"
    assert incident.source_ip == ip
