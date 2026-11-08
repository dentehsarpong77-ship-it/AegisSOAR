import asyncio
from datetime import datetime, timezone
import random
from typing import Dict, List
import uuid
from aegissoar.core.detector import detection_engine
from aegissoar.core.parser import parse_raw_log
from aegissoar.models import SecurityEvent


class AdversarySimulator:
    async def run_scenario(self, scenario_name: str, custom_ip: str = None) -> Dict[str, any]:
        scenario = scenario_name.lower()
        if scenario == "ssh_bruteforce":
            return await self._simulate_ssh_bruteforce(custom_ip or "185.220.101.5")
        elif scenario == "sqli_attack":
            return await self._simulate_sqli(custom_ip or "103.251.167.20")
        elif scenario == "recon_fuzzing":
            return await self._simulate_recon(custom_ip or "45.33.32.156")
        elif scenario == "c2_beacon":
            return await self._simulate_c2(custom_ip or "194.26.29.112")
        else:
            raise ValueError(f"Unknown scenario: {scenario_name}")

    async def _simulate_ssh_bruteforce(self, ip: str) -> Dict[str, any]:
        usernames = ["root", "admin", "ubuntu", "oracle", "deploy", "guest"]
        events_sent = []

        for i in range(5):
            user = usernames[i % len(usernames)]
            raw_log = f"Nov  8 16:30:{10 + i * 2} bastion-host sshd[28491]: Failed password for invalid user {user} from {ip} port {41000 + i} ssh2"
            event = parse_raw_log(raw_log)
            await detection_engine.process_event(event)
            events_sent.append(event.id)
            await asyncio.sleep(0.15)

        return {
            "scenario": "ssh_bruteforce",
            "attacker_ip": ip,
            "events_generated": len(events_sent),
            "summary": f"Simulated 5 rapid SSH brute-force attempts from {ip} targeting administrative accounts."
        }

    async def _simulate_sqli(self, ip: str) -> Dict[str, any]:
        payloads = [
            "/api/v1/search?query=electronics' OR '1'='1' --",
            "/api/v1/user?id=1 UNION SELECT null, username, password_hash FROM information_schema.tables --",
            "/catalog.php?cat_id=10; DROP TABLE audit_logs; --"
        ]
        events_sent = []

        for p in payloads:
            raw_log = f'{ip} - - [08/Nov/2026:16:35:20 +0000] "GET {p} HTTP/1.1" 500 1420 "https://victim-corp.com" "sqlmap/1.6.4#stable"'
            event = parse_raw_log(raw_log)
            await detection_engine.process_event(event)
            events_sent.append(event.id)
            await asyncio.sleep(0.2)

        return {
            "scenario": "sqli_attack",
            "attacker_ip": ip,
            "events_generated": len(events_sent),
            "summary": f"Simulated automated SQL injection attack vectors targeting web application endpoints from {ip}."
        }

    async def _simulate_recon(self, ip: str) -> Dict[str, any]:
        paths = [
            "/.env",
            "/.git/config",
            "/wp-login.php",
            "/phpmyadmin/index.php",
            "/actuator/health",
            "/admin/config.json",
            "/.aws/credentials"
        ]
        events_sent = []

        for p in paths:
            raw_log = f'{ip} - - [08/Nov/2026:16:40:12 +0000] "GET {p} HTTP/1.1" 404 162 "-" "Go-http-client/1.1 (Nikto/2.1.6)"'
            event = parse_raw_log(raw_log)
            await detection_engine.process_event(event)
            events_sent.append(event.id)
            await asyncio.sleep(0.1)

        return {
            "scenario": "recon_fuzzing",
            "attacker_ip": ip,
            "events_generated": len(events_sent),
            "summary": f"Simulated aggressive endpoint recon & directory fuzzing scan from {ip} generating 404 anomalies."
        }

    async def _simulate_c2(self, ip: str) -> Dict[str, any]:
        event = SecurityEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            event_type="network",
            source_ip=ip,
            destination_ip="10.0.0.45",
            service="c2_agent",
            status="FAILURE",
            message=f"Outbound C2 heartbeat communication detected to hostile infrastructure {ip}:443",
            raw_payload="POST /api/v2/telemetry/heartbeat?session=sliver_alpha99",
            metadata={"protocol": "c2", "port": 443}
        )
        await detection_engine.process_event(event)

        return {
            "scenario": "c2_beacon",
            "attacker_ip": ip,
            "events_generated": 1,
            "summary": f"Simulated persistent Command-and-Control beaconing traffic with bulletproof host {ip}."
        }


simulator = AdversarySimulator()
