#!/usr/bin/env python3
"""
Portable Fortinet Syslog Sender — No dependencies, just Python 3.
Sends FortiGate logs via TCP syslog to Onum with live timestamps.

Usage:
    python3 portable_sender.py                # Send 10 sample logs
    python3 portable_sender.py --count 50     # Send 50 logs
    python3 portable_sender.py --csv path.csv # Use custom CSV file
"""
import socket
import csv
import re
import sys
import time
import argparse
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────
SYSLOG_HOST = "XXXXX"
SYSLOG_PORT = XXXXX
# ───────────────────────────────────────────────────────────────────

RE_DATE = re.compile(r'date=\d{4}-\d{2}-\d{2}')
RE_TIME = re.compile(r'time=\d{2}:\d{2}:\d{2}')
RE_EVENTTIME = re.compile(r'eventtime=\d+')

# 5 embedded sample logs (no CSV file needed)
BUILTIN_SAMPLES = [
    '<45>date=2024-12-16 time=17:51:01 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371461000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=10.4.153.31 srcport=138 srcintf="internal" srcintfrole="lan" dstip=69.212.37.178 dstport=138 dstintf="unknown" dstintfrole="undefined" srccountry="Reserved" dstcountry="Singapore" sessionid=19861947 proto=17 action="deny" policyid=0 policytype="local-in-policy" service="udp/138" trandisp="noop" app="netbios forward" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat="unscanned" msg="Connection Failed"',
    '<45>date=2024-12-16 time=17:50:55 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371455000000000 tz="+0000" logid="0001000014" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.100 srcport=54321 srcintf="internal" srcintfrole="lan" dstip=8.8.8.8 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=19861900 proto=6 action="accept" policyid=1 policytype="policy" service="HTTPS" trandisp="snat" transip=203.0.113.1 transport=54321 app="SSL" duration=30 sentbyte=1500 rcvdbyte=3200 sentpkt=10 rcvdpkt=15 appcat="web" msg="Session accepted"',
    '<45>date=2024-12-16 time=17:50:50 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371450000000000 tz="+0000" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1734371450" user="admin" ui="ssh(10.0.0.1)" method="ssh" srcip=10.0.0.1 dstip=10.0.0.254 action="login" status="success" msg="Administrator admin logged in successfully from ssh"',
    '<45>date=2024-12-16 time=17:50:45 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371445000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="warning" vd="root" srcip=172.16.0.50 srcport=80 srcintf="dmz" srcintfrole="dmz" dstip=10.10.10.1 dstport=22 dstintf="internal" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=19861800 proto=6 action="deny" policyid=0 policytype="local-in-policy" service="SSH" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 msg="Unauthorized access attempt blocked"',
    '<45>date=2024-12-16 time=17:50:40 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371440000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=45.33.32.156 srcport=12345 srcintf="wan1" srcintfrole="wan" dstip=192.168.1.50 dstport=445 dstintf="internal" dstintfrole="lan" srccountry="United States" dstcountry="Reserved" sessionid=19861750 proto=6 action="dropped" policyid=5 service="SMB" attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" severity="critical" msg="IPS signature matched and blocked"',
]


def rewrite_timestamps(line):
    now = datetime.now(timezone.utc)
    line = RE_DATE.sub(now.strftime('date=%Y-%m-%d'), line, count=1)
    line = RE_TIME.sub(now.strftime('time=%H:%M:%S'), line, count=1)
    ns = int(now.timestamp() * 1_000_000_000)
    line = RE_EVENTTIME.sub(f'eventtime={ns}', line, count=1)
    return line


def load_csv(path, limit):
    logs = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            if row and row[0].strip():
                logs.append(row[0].strip())
    return logs


def main():
    p = argparse.ArgumentParser(description="Portable Fortinet Syslog Sender")
    p.add_argument('--host', default=SYSLOG_HOST, help=f'Syslog host (default: {SYSLOG_HOST})')
    p.add_argument('--port', type=int, default=SYSLOG_PORT, help=f'Syslog port (default: {SYSLOG_PORT})')
    p.add_argument('--count', type=int, default=10, help='Number of logs (default: 10, 0=all)')
    p.add_argument('--csv', type=str, default=None, help='CSV file path (optional, uses built-in samples if omitted)')
    p.add_argument('--delay', type=float, default=0.5, help='Delay between logs in seconds (default: 0.5)')
    args = p.parse_args()

    # Load logs
    if args.csv:
        limit = args.count if args.count > 0 else None
        logs = load_csv(args.csv, limit)
        print(f"Loaded {len(logs)} logs from {args.csv}")
    else:
        logs = BUILTIN_SAMPLES * ((args.count // len(BUILTIN_SAMPLES)) + 1)
        logs = logs[:args.count]
        print(f"Using {len(logs)} built-in sample logs")

    if not logs:
        print("ERROR: No logs to send")
        return 1

    # Show what we'll send
    sample = rewrite_timestamps(logs[0])
    print(f"\nTarget:  {args.host}:{args.port} (TCP)")
    print(f"Count:   {len(logs)}")
    print(f"Delay:   {args.delay}s")
    print(f"Sample:  {sample[:100]}...")
    print()

    # Connect
    print(f"Connecting to {args.host}:{args.port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        sock.connect((args.host, args.port))
    except Exception as e:
        print(f"ERROR: Cannot connect - {e}")
        return 1

    local = sock.getsockname()
    print(f"Connected! Local: {local[0]}:{local[1]}")
    print()

    # Send
    sent = 0
    for i, raw in enumerate(logs):
        rewritten = rewrite_timestamps(raw)
        payload = (rewritten + "\n").encode('utf-8')
        try:
            sock.sendall(payload)
            sent += 1
            print(f"  [{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Sent {i+1}/{len(logs)} ({len(payload)} bytes)")
        except Exception as e:
            print(f"  [{i+1}] FAILED: {e}")
            break

        if args.delay > 0 and i < len(logs) - 1:
            time.sleep(args.delay)

    # Close
    print()
    try:
        sock.shutdown(socket.SHUT_WR)
        time.sleep(1)
    except:
        pass
    sock.close()

    print(f"Done: {sent}/{len(logs)} sent to {args.host}:{args.port}")
    return 0 if sent == len(logs) else 1


if __name__ == "__main__":
    sys.exit(main())
