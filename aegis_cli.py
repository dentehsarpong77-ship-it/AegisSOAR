#!/usr/bin/env python3
"""AegisSOAR Command-Line Interface."""
import argparse
import asyncio
import json
import sys
import uvicorn
from aegissoar.core.detector import detection_engine
from aegissoar.core.parser import parse_raw_log
from aegissoar.core.simulator import simulator
from aegissoar.db import get_blocklist, get_dashboard_metrics, get_incidents, init_db


def cmd_start(args):
    """Start the AegisSOAR web platform & SOC dashboard."""
    print("=" * 65)
    print("🛡️  Starting AegisSOAR Cyber Defense & Incident Response Platform")
    print(f"📡  Dashboard URL: http://{args.host}:{args.port}")
    print(f"📖  API Docs:      http://{args.host}:{args.port}/docs")
    print("=" * 65)
    uvicorn.run("aegissoar.main:app", host=args.host, port=args.port, reload=args.reload)


def cmd_simulate(args):
    """Trigger realistic adversary cyber attack scenarios from the terminal."""
    init_db()
    print(f"\n⚔️  Executing attack simulation scenario: [{args.scenario.upper()}] ...")
    result = asyncio.run(simulator.run_scenario(args.scenario, args.ip))
    print(f"✓ Attack Campaign Finished: {result.get('summary')}")
    print(f"✓ Correlated Events: {result.get('events_generated')}")
    print(f"✓ Attacker IP: {result.get('attacker_ip')}\n")


def cmd_status(args):
    """Display real-time security posture and active quarantine."""
    init_db()
    metrics = get_dashboard_metrics()
    print("\n" + "=" * 60)
    print("           AEGIS // SOAR - SECURITY POSTURE REPORT          ")
    print("=" * 60)
    print(f" Total Ingested Events:   {metrics['total_events']}")
    print(f" Active Incidents:        {metrics['active_incidents']}")
    print(f" Critical Threats:        {metrics['critical_incidents']}")
    print(f" Quarantined Blocked IPs: {metrics['blocked_ips']}")
    print("-" * 60)
    print(" ACTIVE INCIDENTS:")
    incidents = get_incidents(limit=5)
    if not incidents:
        print("   (No active incidents)")
    else:
        for inc in incidents:
            print(f"   [{inc['severity']}] {inc['id']} - {inc['title']}")
            print(f"        Attacker: {inc['source_ip']} | Technique: {inc['mitre_technique']} | Status: {inc['status']}")

    print("-" * 60)
    print(" QUARANTINED IPS:")
    blocks = get_blocklist()
    if not blocks:
        print("   (No IPs currently quarantined)")
    else:
        for b in blocks:
            print(f"   🚫 {b['ip']} - Reason: {b['reason']}")
    print("=" * 60 + "\n")


def cmd_ingest(args):
    """Ingest a text log file line by line."""
    init_db()
    count = 0
    with open(args.file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                evt = parse_raw_log(line)
                asyncio.run(detection_engine.process_event(evt))
                count += 1
    print(f"✓ Ingested and processed {count} log events from {args.file}")


def main():
    parser = argparse.ArgumentParser(description="AegisSOAR Security Operations CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_start = subparsers.add_parser("start", help="Start the AegisSOAR API and SOC dashboard")
    p_start.add_argument("--host", default="127.0.0.1", help="Host interface to bind to")
    p_start.add_argument("--port", type=int, default=8000, help="Port to listen on")
    p_start.add_argument("--reload", action="store_true", help="Enable live auto-reload")
    p_start.set_defaults(func=cmd_start)

    p_sim = subparsers.add_parser("simulate", help="Run adversary attack scenarios")
    p_sim.add_argument("--scenario", required=True, choices=["ssh_bruteforce", "sqli_attack", "recon_fuzzing", "c2_beacon"], help="Attack scenario")
    p_sim.add_argument("--ip", default=None, help="Custom attacker IP")
    p_sim.set_defaults(func=cmd_simulate)

    p_status = subparsers.add_parser("status", help="View current security metrics and incidents")
    p_status.set_defaults(func=cmd_status)

    p_ingest = subparsers.add_parser("ingest", help="Ingest a log file")
    p_ingest.add_argument("--file", required=True, help="Path to log file")
    p_ingest.set_defaults(func=cmd_ingest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
