import pytest
from aegissoar.core.parser import parse_raw_log


def test_parse_ssh_failed():
    log = "Nov  8 16:30:10 bastion sshd[28491]: Failed password for invalid user admin from 185.220.101.5 port 41234 ssh2"
    event = parse_raw_log(log)
    assert event.event_type == "auth"
    assert event.service == "sshd"
    assert event.username == "admin"
    assert event.source_ip == "185.220.101.5"
    assert event.status == "FAILURE"


def test_parse_nginx_access():
    log = '103.251.167.20 - - [08/Nov/2026:16:35:20 +0000] "GET /api/v1/users HTTP/1.1" 200 1420 "-" "Mozilla/5.0"'
    event = parse_raw_log(log)
    assert event.event_type == "http"
    assert event.source_ip == "103.251.167.20"
    assert event.status_code == 200
    assert event.status == "SUCCESS"


def test_parse_sudo_failure():
    log = "attacker : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/attacker ; USER=root ; COMMAND=/bin/bash"
    event = parse_raw_log(log)
    assert event.event_type == "auth"
    assert event.service == "sudo"
    assert event.username == "attacker"
    assert event.status == "FAILURE"
