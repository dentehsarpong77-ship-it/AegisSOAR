import re
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from aegissoar.models import SecurityEvent

APACHE_NGINX_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>.+?)(?:\s+(?P<proto>HTTP/\S+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
)

SSH_FAILED_REGEX = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2'
)

SSH_ACCEPTED_REGEX = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2'
)

SUDO_FAILURE_REGEX = re.compile(
    r'(?P<user>\S+)\s+:\s+\d+\s+incorrect password attempts?.*COMMAND=(?P<cmd>.*)'
)

IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_raw_log(raw_line: str) -> SecurityEvent:
    line = raw_line.strip()
    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # 1. Check Apache/Nginx Web Log
    match = APACHE_NGINX_REGEX.match(line)
    if match:
        ip = match.group("ip")
        status_code = int(match.group("status"))
        path = match.group("path")
        decoded_path = urllib.parse.unquote(path)
        method = match.group("method")
        user = match.group("user") if match.group("user") != "-" else None
        user_agent = match.group("useragent") or "Unknown"

        status = "FAILURE" if status_code >= 400 else "SUCCESS"

        return SecurityEvent(
            id=event_id,
            timestamp=now,
            event_type="http",
            source_ip=ip,
            destination_ip="10.0.0.1",
            service="nginx",
            username=user,
            status=status,
            status_code=status_code,
            message=f"{method} {path} - HTTP {status_code}",
            raw_payload=f"{path} {decoded_path}",
            metadata={"method": method, "path": path, "user_agent": user_agent, "status_code": status_code}
        )

    # 2. Check SSH Failed Password
    match = SSH_FAILED_REGEX.search(line)
    if match:
        user = match.group("user")
        ip = match.group("ip")
        return SecurityEvent(
            id=event_id,
            timestamp=now,
            event_type="auth",
            source_ip=ip,
            destination_ip="10.0.0.1",
            service="sshd",
            username=user,
            status="FAILURE",
            message=f"Failed SSH login attempt for user '{user}' from {ip}",
            raw_payload=line,
            metadata={"service": "sshd", "user": user}
        )

    # 3. Check SSH Accepted Password
    match = SSH_ACCEPTED_REGEX.search(line)
    if match:
        user = match.group("user")
        ip = match.group("ip")
        return SecurityEvent(
            id=event_id,
            timestamp=now,
            event_type="auth",
            source_ip=ip,
            destination_ip="10.0.0.1",
            service="sshd",
            username=user,
            status="SUCCESS",
            message=f"Accepted SSH login for user '{user}' from {ip}",
            raw_payload=line,
            metadata={"service": "sshd", "user": user}
        )

    # 4. Check Sudo Failure
    match = SUDO_FAILURE_REGEX.search(line)
    if match:
        user = match.group("user")
        cmd = match.group("cmd")
        return SecurityEvent(
            id=event_id,
            timestamp=now,
            event_type="auth",
            source_ip="127.0.0.1",
            service="sudo",
            username=user,
            status="FAILURE",
            message=f"Sudo authentication failure for user '{user}' attempting command: {cmd}",
            raw_payload=line,
            metadata={"service": "sudo", "user": user, "command": cmd}
        )

    # 5. Fallback Generic Parser
    ip_match = IPV4_REGEX.search(line)
    source_ip = ip_match.group(0) if ip_match else "127.0.0.1"
    status = "FAILURE" if any(w in line.lower() for w in ["fail", "error", "denied", "invalid", "unauthorized"]) else "INFO"

    return SecurityEvent(
        id=event_id,
        timestamp=now,
        event_type="generic",
        source_ip=source_ip,
        status=status,
        message=line[:200],
        raw_payload=line
    )
