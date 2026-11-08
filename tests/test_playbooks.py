import pytest
from aegissoar.core.playbooks import PlaybookEngine
from aegissoar.db import get_blocklist, init_db
from aegissoar.models import Incident


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


@pytest.mark.asyncio
async def test_playbook_firewall_quarantine():
    engine = PlaybookEngine()
    test_ip = "198.51.100.77"

    incident = Incident(
        id="inc_test999",
        title="Automated Test Threat",
        description="Test incident for SOAR containment",
        severity="HIGH",
        status="OPEN",
        source_ip=test_ip,
        mitre_tactic="Initial Access",
        mitre_technique="T1190",
        mitre_technique_name="Exploit Public-Facing App",
        rule_id="RULE_SQL_INJECTION",
        threat_score=85
    )

    execution = await engine.execute_playbook("PB_CONTAIN_IP_QUARANTINE", incident)
    assert execution.status == "SUCCESS"
    assert len(execution.actions_taken) > 0

    blocklist = get_blocklist()
    blocked_ips = [b["ip"] for b in blocklist]
    assert test_ip in blocked_ips
