#!/usr/bin/env python3
"""
Portable Multi-Vendor Syslog Sender — No dependencies, just Python 3.
Sends realistic logs via TCP syslog to Onum with live timestamps.

Supported vendors:
  - fortinet   FortiGate syslog (all subtypes)       default port 514
  - mimecast   Mimecast pipe-delimited logs           default port 514

Each vendor has its own port config. Use --vendor all to send both
vendors simultaneously (interleaved), each to its own port.

When --vendor all --count 0 is used without --csv, logs are sent in
attack-timeline order (scenario mode): baseline → phishing → compromise
→ exfiltration, with normal cover traffic mixed in.

Uses persistent TCP connections for fast throughput (~10s for 100+ logs).

Each log gets its timestamp fields rewritten to the exact moment it is
sent so the downstream parser accepts them.

Usage:
    python3 portable_sender.py                          # 10 FortiGate logs
    python3 portable_sender.py --vendor mimecast        # 10 Mimecast logs
    python3 portable_sender.py --vendor all             # Both vendors
    python3 portable_sender.py --vendor all --count 0   # Scenario mode
    python3 portable_sender.py --count 50               # Send 50 logs
    python3 portable_sender.py --config my_lab.json     # Use custom config
    python3 portable_sender.py --list-vendors           # Show vendors + config
    python3 portable_sender.py --export-samples         # FortiGate parser demo

Setup:
    1. Download portable_sender.py
    2. Set env vars and generate config:
       export SYSLOG_HOST=your-tenant.in.prod.onum.com
       export FORTINET_PORT=2518
       python3 portable_sender.py --init-config
    3. Run: python3 portable_sender.py --vendor all --count 0
"""
import socket
import csv
import json
import os
import re
import sys
import time
import argparse
import random
from datetime import datetime, timezone

# -- Configuration defaults (override with config.json) --------------------
SYSLOG_HOST = "your-tenant.in.prod.onum.com"
SYSLOG_PORT = 514
# --------------------------------------------------------------------------


###########################################################################
#                       CONFIG FILE SUPPORT                               #
###########################################################################

DEFAULT_CONFIG = {
    "syslog_host": SYSLOG_HOST,
    "vendors": {
        "fortinet": {"port": SYSLOG_PORT},
        "mimecast": {"port": SYSLOG_PORT},
    },
    "lab": {
        "domain": "lab.local",
        "machines": {
            "attacker":  {"ip": "10.0.0.21",  "ext_ip": "203.0.113.21"},
            "ubuntu":    {"ip": "10.0.0.40",  "ext_ip": "203.0.113.40"},
            "unmanaged": {"ip": "10.0.0.27",  "ext_ip": "203.0.113.27"},
            "protect":   {"ip": "10.0.0.30",  "ext_ip": "203.0.113.30",
                          "user": "protect-user", "email": "protect-user@lab.local"},
            "detect":    {"ip": "10.0.0.31",  "ext_ip": "203.0.113.31",
                          "user": "detect-user", "email": "detect-user@lab.local"},
        },
    },
}


def load_config(path):
    """Load config from JSON file, merge with defaults, then apply env vars."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path and os.path.isfile(path):
        with open(path, 'r') as f:
            user = json.load(f)
        # Merge top-level keys
        for k, v in user.items():
            if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        # Deep-merge lab.machines
        if 'lab' in user and 'machines' in user['lab']:
            for role, info in user['lab']['machines'].items():
                if role in cfg['lab']['machines']:
                    cfg['lab']['machines'][role].update(info)
                else:
                    cfg['lab']['machines'][role] = info

    # Environment variables override config file / defaults
    if os.environ.get('SYSLOG_HOST'):
        cfg['syslog_host'] = os.environ['SYSLOG_HOST']
    if os.environ.get('FORTINET_PORT'):
        cfg['vendors']['fortinet']['port'] = int(os.environ['FORTINET_PORT'])
    if os.environ.get('MIMECAST_PORT'):
        cfg['vendors']['mimecast']['port'] = int(os.environ['MIMECAST_PORT'])
    if os.environ.get('LAB_DOMAIN'):
        cfg['lab']['domain'] = os.environ['LAB_DOMAIN']
    # Machine IPs: DETECT_IP, DETECT_EXT_IP, ATTACKER_IP, etc.
    # Machine identity: DETECT_USER, DETECT_EMAIL, PROTECT_USER, PROTECT_EMAIL
    for role in list(cfg['lab']['machines'].keys()):
        env_ip = os.environ.get(f'{role.upper()}_IP')
        env_ext = os.environ.get(f'{role.upper()}_EXT_IP')
        env_user = os.environ.get(f'{role.upper()}_USER')
        env_email = os.environ.get(f'{role.upper()}_EMAIL')
        if env_ip:
            cfg['lab']['machines'][role]['ip'] = env_ip
        if env_ext:
            cfg['lab']['machines'][role]['ext_ip'] = env_ext
        if env_user:
            cfg['lab']['machines'][role]['user'] = env_user
        if env_email:
            cfg['lab']['machines'][role]['email'] = env_email

    return cfg


def build_placeholders(cfg):
    """Build {{PLACEHOLDER}} -> value mapping from config."""
    ph = {}
    lab = cfg.get('lab', {})
    machines = lab.get('machines', {})
    for role, info in machines.items():
        key = role.upper()
        ph[f'{{{{{key}_IP}}}}'] = info.get('ip', '10.0.0.1')
        if 'ext_ip' in info:
            ph[f'{{{{{key}_EXT_IP}}}}'] = info['ext_ip']
        if 'user' in info:
            ph[f'{{{{{key}_USER}}}}'] = info['user']
        if 'email' in info:
            ph[f'{{{{{key}_EMAIL}}}}'] = info['email']
    ph['{{LAB_DOMAIN}}'] = lab.get('domain', 'lab.local')
    return ph


def apply_placeholders(line, placeholders):
    """Replace {{PLACEHOLDER}} tokens with config values."""
    for token, value in placeholders.items():
        line = line.replace(token, value)
    return line

# -- Regex for timestamp rewriting -----------------------------------------
RE_DATE = re.compile(r'date=\d{4}-\d{2}-\d{2}')
RE_TIME = re.compile(r'time=\d{2}:\d{2}:\d{2}')
RE_EVENTTIME = re.compile(r'eventtime=\d+')
RE_MIMECAST_DATETIME = re.compile(r'"datetime"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{4}"')
# --------------------------------------------------------------------------


###########################################################################
#                      FORTIGATE BUILTIN SAMPLES                          #
###########################################################################

FORTINET_SAMPLES = [

    # =====================================================================
    # TRAFFIC LOGS - subtype=forward
    # =====================================================================

    # forward: HTTPS web browsing
    '<45>date=2024-12-16 time=17:50:55 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371455000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.100 srcport=54321 srcintf="internal" srcintfrole="lan" dstip=93.184.216.34 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=19861900 proto=6 action="close" policyid=1 policytype="policy" service="HTTPS" trandisp="snat" transip=203.0.113.1 transport=54321 app="SSL" appcat="web.client" duration=30 sentbyte=4520 rcvdbyte=32800 sentpkt=18 rcvdpkt=25 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:dd:ee:01" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # forward: HTTP browsing with app detection
    '<45>date=2024-12-16 time=17:51:10 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371470000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.45 srcport=49210 srcintf="port1" srcintfrole="lan" dstip=198.51.100.80 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Germany" sessionid=20012344 proto=6 action="accept" policyid=3 policytype="policy" service="HTTP" trandisp="snat" transip=203.0.113.5 transport=49210 app="HTTP.BROWSER" appcat="web.client" duration=12 sentbyte=1200 rcvdbyte=54000 sentpkt=8 rcvdpkt=40 osname="macOS" srcswversion="macOS 14" mastersrcmac="aa:bb:cc:dd:ee:02" masterdstmac="11:22:33:44:55:02" msg="Session accepted"',

    # forward: DNS query
    '<45>date=2024-12-16 time=17:52:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371520000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.10.22 srcport=53214 srcintf="internal" srcintfrole="lan" dstip=8.8.8.8 dstport=53 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=20100111 proto=17 action="accept" policyid=2 policytype="policy" service="DNS" trandisp="snat" transip=203.0.113.10 transport=53214 app="DNS" appcat="network.service" duration=1 sentbyte=74 rcvdbyte=180 sentpkt=1 rcvdpkt=1 osname="Linux" srcswversion="Ubuntu 22" mastersrcmac="aa:bb:cc:dd:ee:03" masterdstmac="11:22:33:44:55:03" msg="Session accepted"',

    # forward: Streaming video detected and closed
    '<45>date=2024-12-16 time=17:52:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734371550000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.20.30.55 srcport=61200 srcintf="port5" srcintfrole="lan" dstip=151.101.1.69 dstport=443 dstintf="wan2" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=30122456 proto=6 action="close" policyid=10 policytype="policy" service="HTTPS" trandisp="snat" transip=198.51.100.1 transport=61200 app="YouTube" appcat="video/audio" duration=600 sentbyte=52000 rcvdbyte=15000000 sentpkt=400 rcvdpkt=12000 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:dd:ee:04" masterdstmac="11:22:33:44:55:04" msg="Session closed"',

    # =====================================================================
    # TRAFFIC LOGS - subtype=local
    # =====================================================================

    # local: Management SSH denied
    '<45>date=2024-12-16 time=17:51:01 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371461000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=10.4.153.31 srcport=138 srcintf="internal" srcintfrole="lan" dstip=69.212.37.178 dstport=138 dstintf="unknown" dstintfrole="undefined" srccountry="Reserved" dstcountry="Singapore" sessionid=19861947 proto=17 action="deny" policyid=0 policytype="local-in-policy" service="udp/138" trandisp="noop" app="netbios forward" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat="unscanned" msg="Connection Failed"',

    # local: Server reset on unauthorized access
    '<45>date=2024-12-16 time=17:50:45 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371445000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="warning" vd="root" srcip=172.16.0.50 srcport=80 srcintf="dmz" srcintfrole="dmz" dstip=10.10.10.1 dstport=22 dstintf="internal" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=19861800 proto=6 action="server-rst" policyid=0 policytype="local-in-policy" service="SSH" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 msg="Unauthorized access attempt - server reset"',

    # local: SNMP deny
    '<45>date=2024-12-16 time=17:53:05 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371585000000000 tz="+0000" logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" srcip=192.168.200.10 srcport=45123 srcintf="port3" srcintfrole="lan" dstip=10.0.0.1 dstport=161 dstintf="root" dstintfrole="undefined" srccountry="Reserved" dstcountry="Reserved" sessionid=19872100 proto=17 action="deny" policyid=0 policytype="local-in-policy" service="SNMP" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 msg="SNMP access denied by local-in policy"',

    # =====================================================================
    # TRAFFIC LOGS - subtype=multicast
    # =====================================================================

    # multicast: Multicast UDP traffic
    '<45>date=2024-12-16 time=17:54:00 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734371640000000000 tz="+0000" logid="0002000015" type="traffic" subtype="multicast" level="notice" vd="root" srcip=10.1.1.100 srcport=5004 srcintf="port1" srcintfrole="lan" dstip=239.1.1.1 dstport=5004 dstintf="port2" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=30200100 proto=17 action="accept" policyid=15 policytype="multicast-policy" service="udp/5004" trandisp="noop" duration=120 sentbyte=250000 rcvdbyte=0 sentpkt=2000 rcvdpkt=0 msg="Multicast stream forwarded"',

    # =====================================================================
    # TRAFFIC LOGS - subtype=sniffer
    # =====================================================================

    # sniffer: Packet sniffing with IPS detection
    '<45>date=2024-12-16 time=17:54:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371670000000000 tz="+0000" logid="0003000016" type="traffic" subtype="sniffer" level="notice" vd="root" srcip=10.50.50.20 srcport=443 srcintf="port10" srcintfrole="undefined" dstip=10.50.50.100 dstport=8443 dstintf="port10" dstintfrole="undefined" srccountry="Reserved" dstcountry="Reserved" sessionid=30300200 proto=6 action="accept" policyid=20 policytype="sniffer" service="tcp/8443" trandisp="noop" duration=5 sentbyte=800 rcvdbyte=1200 sentpkt=6 rcvdpkt=8 msg="Sniffer policy matched - IPS inspection applied"',

    # =====================================================================
    # EVENT LOGS - subtype=system
    # =====================================================================

    # system: Admin login success via SSH
    '<45>date=2024-12-16 time=17:50:50 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371450000000000 tz="+0000" logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1734371450" user="admin" ui="ssh(10.0.0.1)" method="ssh" srcip=10.0.0.1 dstip=10.0.0.254 action="login" status="success" msg="Administrator admin logged in successfully from ssh"',

    # system: Admin login failure via HTTPS
    '<45>date=2024-12-16 time=17:55:10 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371710000000000 tz="+0000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" sn="1734371710" user="operator" ui="https(192.168.1.200)" method="https" srcip=192.168.1.200 dstip=10.10.10.1 action="login" status="failed" reason="name_or_pw_invalid" msg="Administrator operator login failed from https"',

    # system: Configuration change
    '<45>date=2024-12-16 time=17:56:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371760000000000 tz="+0000" logid="0100044546" type="event" subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="admin" ui="jsconsole(10.0.0.1)" action="Edit" cfgtid=1734371760 cfgpath="firewall.policy" cfgobj="5" cfgattr="action[accept->deny]" msg="Edit firewall.policy 5"',

    # =====================================================================
    # EVENT LOGS - subtype=router
    # =====================================================================

    # router: OSPF neighbor up
    '<45>date=2024-12-16 time=17:56:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734371790000000000 tz="+0000" logid="0101037130" type="event" subtype="router" level="notice" vd="root" logdesc="OSPF neighbor state change" msg="OSPF neighbor 10.0.0.2 on port1 changed state from Loading to Full" action="ospf-nbr-state-change" neighbor="10.0.0.2" interface="port1" area="0.0.0.0" state="Full"',

    # router: BGP neighbor down
    '<45>date=2024-12-16 time=17:57:00 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734371820000000000 tz="+0000" logid="0101037131" type="event" subtype="router" level="warning" vd="root" logdesc="BGP neighbor state change" msg="BGP neighbor 198.51.100.1 (AS 65001) changed state from Established to Idle: hold timer expired" action="bgp-nbr-state-change" neighbor="198.51.100.1" as="65001" state="Idle" reason="Hold Timer Expired"',

    # =====================================================================
    # EVENT LOGS - subtype=vpn
    # =====================================================================

    # vpn: IPsec phase1 negotiation success
    '<45>date=2024-12-16 time=17:57:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371850000000000 tz="+0000" logid="0101037122" type="event" subtype="vpn" level="notice" vd="root" logdesc="IPsec phase 1 status change" msg="IPsec phase 1 negotiation succeeded: tunnel HQ-to-Branch1 peer 203.0.113.50" action="tunnel-up" remip=203.0.113.50 locip=198.51.100.10 tunneltype="ipsec" tunnelid=1 tunnel="HQ-to-Branch1" phase1status="up"',

    # vpn: IPsec tunnel down
    '<45>date=2024-12-16 time=17:58:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371880000000000 tz="+0000" logid="0101037123" type="event" subtype="vpn" level="warning" vd="root" logdesc="IPsec phase 2 status change" msg="IPsec phase 2 tunnel HQ-to-Branch2 went down: peer unreachable" action="tunnel-down" remip=203.0.113.60 locip=198.51.100.10 tunneltype="ipsec" tunnelid=2 tunnel="HQ-to-Branch2" phase2status="down" reason="peer unreachable"',

    # =====================================================================
    # EVENT LOGS - subtype=user
    # =====================================================================

    # user: RADIUS auth success (Detect user VPN login)
    '<45>date=2024-12-16 time=17:58:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371910000000000 tz="+0000" logid="0102043008" type="event" subtype="user" level="notice" vd="root" logdesc="Authentication success" srcip={{DETECT_IP}} user="{{DETECT_USER}}" server="RADIUS-01" group="VPN-Users" authproto="RADIUS" action="authentication" status="success" msg="User {{DETECT_USER}} authenticated successfully via RADIUS"',

    # user: LDAP auth failure (Protect user failed login)
    '<45>date=2024-12-16 time=17:59:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371940000000000 tz="+0000" logid="0102043009" type="event" subtype="user" level="warning" vd="root" logdesc="Authentication failure" srcip={{PROTECT_IP}} user="{{PROTECT_USER}}" server="LDAP-DC01" group="N/A" authproto="LDAP" action="authentication" status="failure" reason="credential_or_server_error" msg="User {{PROTECT_USER}} failed LDAP authentication"',

    # =====================================================================
    # EVENT LOGS - subtype=ha
    # =====================================================================

    # ha: Failover event
    '<45>date=2024-12-16 time=17:59:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734371970000000000 tz="+0000" logid="0104043552" type="event" subtype="ha" level="critical" vd="root" logdesc="HA failover" msg="HA failover: unit FG3KFTEST00004 became primary, previous primary FG3KFTEST00005 is unreachable" action="ha-failover" new_primary="FG3KFTEST00004" old_primary="FG3KFTEST00005" reason="heartbeat-lost"',

    # ha: Member join
    '<45>date=2024-12-16 time=18:00:00 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372000000000000 tz="+0000" logid="0104043553" type="event" subtype="ha" level="notice" vd="root" logdesc="HA member status change" msg="HA cluster member FG3KFTEST00005 joined the cluster" action="member-join" sn="FG3KFTEST00005" status="joined" cluster_size=2',

    # =====================================================================
    # EVENT LOGS - subtype=wireless
    # =====================================================================

    # wireless: Rogue AP detected
    '<45>date=2024-12-16 time=18:00:30 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372030000000000 tz="+0000" logid="0104043600" type="event" subtype="wireless" level="warning" vd="root" logdesc="Rogue AP detected" msg="Rogue AP detected: SSID=FreeWifi BSSID=de:ad:be:ef:ca:fe channel=6 signal=-45dBm" action="rogue-ap-detected" ssid="FreeWifi" bssid="de:ad:be:ef:ca:fe" channel=6 signal="-45" security="open" onwire="no"',

    # wireless: Fake AP detected
    '<45>date=2024-12-16 time=18:01:00 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372060000000000 tz="+0000" logid="0104043601" type="event" subtype="wireless" level="alert" vd="root" logdesc="Fake AP detected" msg="Fake AP detected spoofing corporate SSID: SSID=CorpNet BSSID=ba:ad:f0:0d:12:34 channel=11" action="fake-ap-detected" ssid="CorpNet" bssid="ba:ad:f0:0d:12:34" channel=11 signal="-30" security="wpa2-personal"',

    # =====================================================================
    # EVENT LOGS - subtype=sdwan
    # =====================================================================

    # sdwan: Health check status change
    '<45>date=2024-12-16 time=18:01:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372090000000000 tz="+0000" logid="0113044544" type="event" subtype="sdwan" level="notice" vd="root" logdesc="Health check state changed" msg="SD-WAN health check Internet_Check on wan1 changed from alive to dead, latency=250ms jitter=45ms packetloss=80%" action="health-check-state-change" interface="wan1" health_check="Internet_Check" old_state="alive" new_state="dead" latency=250 jitter=45 packetloss=80',

    # sdwan: SLA change
    '<45>date=2024-12-16 time=18:02:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372120000000000 tz="+0000" logid="0113044545" type="event" subtype="sdwan" level="warning" vd="root" logdesc="SLA change" msg="SD-WAN SLA VoIP_SLA violated on wan2: latency 150ms exceeds threshold 100ms" action="sla-change" interface="wan2" sla_name="VoIP_SLA" sla_status="fail" measured_latency=150 threshold_latency=100',

    # =====================================================================
    # EVENT LOGS - subtype=connector
    # =====================================================================

    # connector: SDN connector object add
    '<45>date=2024-12-16 time=18:02:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372150000000000 tz="+0000" logid="0110044800" type="event" subtype="connector" level="information" vd="root" logdesc="SDN connector object update" msg="SDN connector Azure-SDN added address object: Azure-Subnet-10.100.0.0/24" action="object-add" connector="Azure-SDN" connector_type="azure" object_name="Azure-Subnet-10.100.0.0/24" object_type="address"',

    # connector: SDN connector object remove
    '<45>date=2024-12-16 time=18:03:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372180000000000 tz="+0000" logid="0110044801" type="event" subtype="connector" level="information" vd="root" logdesc="SDN connector object update" msg="SDN connector AWS-SDN removed address object: AWS-VPC-172.31.0.0/16" action="object-remove" connector="AWS-SDN" connector_type="aws" object_name="AWS-VPC-172.31.0.0/16" object_type="address"',

    # =====================================================================
    # EVENT LOGS - subtype=endpoint
    # =====================================================================

    # endpoint: FortiClient connection add (Detect machine)
    '<45>date=2024-12-16 time=18:03:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372210000000000 tz="+0000" logid="0111044900" type="event" subtype="endpoint" level="notice" vd="root" logdesc="FortiClient endpoint connected" msg="FortiClient endpoint WIN10-DETECT connected, user {{DETECT_USER}}, IP {{DETECT_IP}}, FCT version 7.2.3" action="connection-add" srcip={{DETECT_IP}} user="{{DETECT_USER}}" hostname="WIN10-DETECT" fctver="7.2.3" os="Windows 11" compliance="compliant"',

    # endpoint: FortiClient connection close (Protect machine)
    '<45>date=2024-12-16 time=18:04:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372240000000000 tz="+0000" logid="0111044901" type="event" subtype="endpoint" level="notice" vd="root" logdesc="FortiClient endpoint disconnected" msg="FortiClient endpoint WIN10-PROTECT disconnected, user {{PROTECT_USER}}, IP {{PROTECT_IP}}, reason timeout" action="connection-close" srcip={{PROTECT_IP}} user="{{PROTECT_USER}}" hostname="WIN10-PROTECT" reason="timeout"',

    # =====================================================================
    # EVENT LOGS - subtype=security-rating
    # =====================================================================

    # security-rating: Security audit result
    '<45>date=2024-12-16 time=18:04:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372270000000000 tz="+0000" logid="0112045000" type="event" subtype="security-rating" level="warning" vd="root" logdesc="Security rating check" msg="Security rating check failed: Admin password complexity does not meet recommended policy" action="security-rating" check_name="admin-password-policy" result="fail" score=35 max_score=100 category="system"',

    # =====================================================================
    # EVENT LOGS - subtype=wad
    # =====================================================================

    # wad: SSL certificate error
    '<45>date=2024-12-16 time=18:05:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372300000000000 tz="+0000" logid="0114045100" type="event" subtype="wad" level="warning" vd="root" logdesc="SSL certificate alert" msg="SSL certificate error: certificate has expired for server evil-phishing.example.com (CN=evil-phishing.example.com)" action="ssl-alert" srcip=192.168.1.110 dstip=198.51.100.99 dstport=443 hostname="evil-phishing.example.com" certcn="evil-phishing.example.com" reason="certificate-expired"',

    # =====================================================================
    # EVENT LOGS - subtype=rest-api
    # =====================================================================

    # rest-api: API GET request
    '<45>date=2024-12-16 time=18:05:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372330000000000 tz="+0000" logid="0115045200" type="event" subtype="rest-api" level="information" vd="root" logdesc="REST API request" msg="REST API GET /api/v2/cmdb/firewall/policy from admin_api (10.0.0.5)" action="GET" srcip=10.0.0.5 user="admin_api" path="/api/v2/cmdb/firewall/policy" status=200 duration=45',

    # rest-api: API POST request
    '<45>date=2024-12-16 time=18:06:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372360000000000 tz="+0000" logid="0115045201" type="event" subtype="rest-api" level="notice" vd="root" logdesc="REST API request" msg="REST API POST /api/v2/cmdb/firewall/address from automation_svc (10.0.0.6)" action="POST" srcip=10.0.0.6 user="automation_svc" path="/api/v2/cmdb/firewall/address" status=200 duration=120',

    # =====================================================================
    # EVENT LOGS - subtype=switch-controller
    # =====================================================================

    # switch-controller: FortiSwitch discovery
    '<45>date=2024-12-16 time=18:06:30 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372390000000000 tz="+0000" logid="0116045300" type="event" subtype="switch-controller" level="notice" vd="root" logdesc="FortiSwitch discovered" msg="FortiSwitch S108ETEST00001 discovered on port internal5, model FS-108E, firmware v7.2.5" action="switch-discovery" switch_sn="S108ETEST00001" switch_model="FS-108E" interface="internal5" firmware="v7.2.5"',

    # switch-controller: FortiSwitch tunnel up
    '<45>date=2024-12-16 time=18:07:00 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372420000000000 tz="+0000" logid="0116045301" type="event" subtype="switch-controller" level="notice" vd="root" logdesc="FortiSwitch tunnel status" msg="FortiSwitch S108ETEST00001 tunnel is up on port internal5" action="tunnel-up" switch_sn="S108ETEST00001" interface="internal5" status="up"',

    # switch-controller: Link event
    '<45>date=2024-12-16 time=18:07:30 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372450000000000 tz="+0000" logid="0116045302" type="event" subtype="switch-controller" level="warning" vd="root" logdesc="FortiSwitch link event" msg="FortiSwitch S108ETEST00001 port 5 link went down" action="link-down" switch_sn="S108ETEST00001" switch_port=5 link_status="down"',

    # =====================================================================
    # EVENT LOGS - subtype=fortiextender
    # =====================================================================

    # fortiextender: Cellular connect
    '<45>date=2024-12-16 time=18:08:00 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372480000000000 tz="+0000" logid="0117045400" type="event" subtype="fortiextender" level="notice" vd="root" logdesc="FortiExtender cellular status" msg="FortiExtender FEX100TEST001 cellular modem connected to carrier T-Mobile, signal RSSI=-65dBm RSRP=-90dBm" action="cellular-connect" extender_sn="FEX100TEST001" carrier="T-Mobile" technology="LTE" rssi=-65 rsrp=-90 sim_slot=1',

    # fortiextender: Cellular disconnect
    '<45>date=2024-12-16 time=18:08:30 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372510000000000 tz="+0000" logid="0117045401" type="event" subtype="fortiextender" level="warning" vd="root" logdesc="FortiExtender cellular status" msg="FortiExtender FEX100TEST001 cellular modem disconnected from carrier: signal lost" action="cellular-disconnect" extender_sn="FEX100TEST001" reason="signal-lost" sim_slot=1',

    # fortiextender: SIM change
    '<45>date=2024-12-16 time=18:09:00 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372540000000000 tz="+0000" logid="0117045402" type="event" subtype="fortiextender" level="notice" vd="root" logdesc="FortiExtender SIM change" msg="FortiExtender FEX100TEST001 switched from SIM slot 1 to SIM slot 2, new carrier Verizon" action="sim-change" extender_sn="FEX100TEST001" old_sim=1 new_sim=2 new_carrier="Verizon"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=virus
    # =====================================================================

    # virus: EICAR test file detected
    '<45>date=2024-12-16 time=18:09:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372570000000000 tz="+0000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip=192.168.1.110 srcport=52100 srcintf="internal" srcintfrole="lan" dstip=198.51.100.200 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31000100 proto=6 action="blocked" service="HTTP" policyid=5 hostname="download.example.com" url="/files/test.exe" filename="test.exe" quarskip="File was quarantined" virus="EICAR_TEST_FILE" virusid=2172 dtype="Virus" ref="http://www.fortinet.com/ve?vn=EICAR_TEST_FILE" analyticscksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" analyticssubmit="false" msg="File is infected."',

    # virus: Malware blocked on HTTPS
    '<45>date=2024-12-16 time=18:10:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372600000000000 tz="+0000" logid="0211008192" type="utm" subtype="virus" level="alert" vd="root" srcip=10.20.30.100 srcport=61050 srcintf="port5" srcintfrole="lan" dstip=93.184.216.34 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31000200 proto=6 action="blocked" service="HTTPS" policyid=8 hostname="evil-payload.example.net" url="/dl/invoice.pdf.exe" filename="invoice.pdf.exe" quarskip="File was quarantined" virus="W32/Emotet.A!tr" virusid=8751204 dtype="Virus" ref="http://www.fortinet.com/ve?vn=W32/Emotet.A!tr" msg="File is infected."',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=webfilter
    # =====================================================================

    # webfilter: Malicious URL blocked
    '<45>date=2024-12-16 time=18:10:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372630000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" level="warning" vd="root" srcip=192.168.1.120 srcport=49300 srcintf="internal" srcintfrole="lan" dstip=198.51.100.50 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Netherlands" sessionid=31100100 proto=6 action="blocked" service="HTTPS" policyid=5 hostname="malware-download.example.com" url="/payload" cat=26 catdesc="Malicious Websites" urlsource="fortiguard" msg="URL belongs to a denied category in policy"',

    # webfilter: Category block (gambling)
    '<45>date=2024-12-16 time=18:11:00 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734372660000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" level="warning" vd="root" srcip=192.168.1.55 srcport=50200 srcintf="internal" srcintfrole="lan" dstip=104.20.145.30 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31100200 proto=6 action="blocked" service="HTTPS" policyid=5 hostname="online-casino.example.com" url="/" cat=11 catdesc="Gambling" urlsource="fortiguard" msg="URL belongs to a denied category in policy"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=dns
    # =====================================================================

    # dns: DNS query with DKIM/SPF info
    '<45>date=2024-12-16 time=18:11:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372690000000000 tz="+0000" logid="1501054400" type="utm" subtype="dns" level="notice" vd="root" srcip=192.168.10.55 srcport=53210 srcintf="port1" srcintfrole="lan" dstip=8.8.4.4 dstport=53 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31200100 proto=17 action="pass" policyid=2 qname="mail.example.com" qtype="A" qclass="IN" ipaddr="198.51.100.25" msg="Domain resolved" cat=0 catdesc="Uncategorized"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=app-ctrl
    # =====================================================================

    # app-ctrl: Social media blocked
    '<45>date=2024-12-16 time=18:12:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372720000000000 tz="+0000" logid="1059028704" type="utm" subtype="app-ctrl" level="warning" vd="root" srcip=192.168.1.130 srcport=51200 srcintf="internal" srcintfrole="lan" dstip=157.240.1.35 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31300100 proto=6 action="block" policyid=5 appid=40568 app="Facebook" appcat="social.networking" apprisk="elevated" incidentserialno=101 msg="Application blocked: Facebook"',

    # app-ctrl: Streaming blocked
    '<45>date=2024-12-16 time=18:12:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372750000000000 tz="+0000" logid="1059028704" type="utm" subtype="app-ctrl" level="warning" vd="root" srcip=10.20.30.75 srcport=53100 srcintf="port5" srcintfrole="lan" dstip=23.246.20.100 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31300200 proto=6 action="block" policyid=8 appid=31077 app="Netflix" appcat="video/audio" apprisk="elevated" incidentserialno=102 msg="Application blocked: Netflix"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=ips
    # =====================================================================

    # ips: Critical attack dropped
    '<45>date=2024-12-16 time=17:50:40 devname="FortiGate-60E" devid="FGT60ETEST00001" eventtime=1734371440000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=45.33.32.156 srcport=12345 srcintf="wan1" srcintfrole="wan" dstip=192.168.1.50 dstport=445 dstintf="internal" dstintfrole="lan" srccountry="United States" dstcountry="Reserved" sessionid=19861750 proto=6 action="dropped" policyid=5 service="SMB" attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" severity="critical" attackid=42888 msg="IPS signature matched and blocked"',

    # ips: SQL injection attempt
    '<45>date=2024-12-16 time=18:13:00 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372780000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=198.51.100.77 srcport=44200 srcintf="wan2" srcintfrole="wan" dstip=10.100.0.50 dstport=443 dstintf="port5" dstintfrole="lan" srccountry="Russia" dstcountry="Reserved" sessionid=31400200 proto=6 action="dropped" policyid=12 service="HTTPS" attack="HTTP.URI.SQL.Injection" severity="critical" attackid=38256 msg="SQL injection attempt detected and blocked"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=anomaly
    # =====================================================================

    # anomaly: SYN flood detected
    '<45>date=2024-12-16 time=18:13:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372810000000000 tz="+0000" logid="0720018432" type="utm" subtype="anomaly" level="alert" vd="root" srcip=198.51.100.100 srcintf="wan1" srcintfrole="wan" dstip=10.100.0.80 dstport=80 dstintf="port5" dstintfrole="lan" srccountry="China" dstcountry="Reserved" sessionid=0 proto=6 action="detected" policyid=12 service="HTTP" attackname="tcp_syn_flood" count=10000 threshold=5000 msg="DoS anomaly: SYN flood detected"',

    # anomaly: ICMP flood detected
    '<45>date=2024-12-16 time=18:14:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372840000000000 tz="+0000" logid="0720018432" type="utm" subtype="anomaly" level="alert" vd="root" srcip=203.0.113.99 srcintf="wan1" srcintfrole="wan" dstip=10.0.0.1 dstport=0 dstintf="root" dstintfrole="undefined" srccountry="Brazil" dstcountry="Reserved" sessionid=0 proto=1 action="detected" policyid=0 service="ICMP" attackname="icmp_flood" count=8000 threshold=4000 msg="DoS anomaly: ICMP flood detected"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=dlp
    # =====================================================================

    # dlp: File type blocked (executable upload)
    '<45>date=2024-12-16 time=18:14:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372870000000000 tz="+0000" logid="0954024576" type="utm" subtype="dlp" level="warning" vd="root" srcip=192.168.1.105 srcport=49800 srcintf="internal" srcintfrole="lan" dstip=198.51.100.200 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31500100 proto=6 action="block" policyid=5 service="HTTPS" filename="confidential_report.docx" filesize=2450000 filetype="msoffice" filteridx=1 filtertype="file-type" filtercat="file" severity="medium" msg="DLP rule triggered: sensitive file type upload blocked"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=ssh
    # =====================================================================

    # ssh: SSH channel blocked
    '<45>date=2024-12-16 time=18:15:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372900000000000 tz="+0000" logid="1600060416" type="utm" subtype="ssh" level="warning" vd="root" srcip=192.168.5.60 srcport=55600 srcintf="port3" srcintfrole="lan" dstip=198.51.100.150 dstport=22 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31600100 proto=6 action="blocked" policyid=8 service="SSH" login="root" channel="shell" msg="SSH deep inspection: shell channel blocked by policy"',

    # =====================================================================
    # SECURITY/UTM LOGS - subtype=ssl
    # =====================================================================

    # ssl: Certificate invalid
    '<45>date=2024-12-16 time=18:15:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734372930000000000 tz="+0000" logid="1700062000" type="utm" subtype="ssl" level="warning" vd="root" srcip=192.168.1.140 srcport=52300 srcintf="internal" srcintfrole="lan" dstip=198.51.100.80 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Germany" sessionid=31700100 proto=6 action="blocked" policyid=5 service="HTTPS" hostname="expired-cert.example.com" certcn="expired-cert.example.com" certissuer="Lets Encrypt" certstatus="expired" msg="SSL anomaly: certificate expired"',

    # ssl: Untrusted certificate
    '<45>date=2024-12-16 time=18:16:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372960000000000 tz="+0000" logid="1700062001" type="utm" subtype="ssl" level="warning" vd="root" srcip=10.20.30.90 srcport=54100 srcintf="port5" srcintfrole="lan" dstip=93.184.216.34 dstport=8443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31700200 proto=6 action="blocked" policyid=8 service="HTTPS" hostname="self-signed.example.net" certcn="self-signed.example.net" certissuer="self-signed" certstatus="untrusted" msg="SSL anomaly: untrusted certificate authority"',

    # ssl: SNI mismatch
    '<45>date=2024-12-16 time=18:16:30 devname="FortiGate-3000F" devid="FG3KFTEST00004" eventtime=1734372990000000000 tz="+0000" logid="1700062002" type="utm" subtype="ssl" level="notice" vd="root" srcip=10.50.50.30 srcport=55800 srcintf="port1" srcintfrole="lan" dstip=151.101.1.69 dstport=443 dstintf="wan2" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31700300 proto=6 action="blocked" policyid=12 service="HTTPS" hostname="cdn.example.com" certcn="*.different-domain.com" certstatus="sni-mismatch" msg="SSL anomaly: SNI does not match certificate CN"',

    # ssl: SSL exempt
    '<45>date=2024-12-16 time=18:17:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734373020000000000 tz="+0000" logid="1700062003" type="utm" subtype="ssl" level="information" vd="root" srcip=192.168.1.160 srcport=56200 srcintf="internal" srcintfrole="lan" dstip=140.82.121.3 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31700400 proto=6 action="exempt" policyid=5 service="HTTPS" hostname="github.com" msg="SSL inspection exempt: address matched exemption list"',

    # ssl: SSL negotiation
    '<45>date=2024-12-16 time=18:17:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373050000000000 tz="+0000" logid="1700062004" type="utm" subtype="ssl" level="information" vd="root" srcip=10.20.30.120 srcport=57600 srcintf="port5" srcintfrole="lan" dstip=198.51.100.200 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=31700500 proto=6 action="accept" policyid=8 service="HTTPS" hostname="api.vendor.example.com" ssl_version="TLSv1.3" ssl_cipher="TLS_AES_256_GCM_SHA384" msg="SSL negotiation completed successfully"',

    # =====================================================================
    # LAB ENVIRONMENT TRAFFIC (WARP-DUCK lab machines)
    # Kali {{ATTACKER_IP}} | Ubuntu {{UBUNTU_IP}} | Unmanaged {{UNMANAGED_IP}}
    # Protect {{PROTECT_IP}} | Detect {{DETECT_IP}}
    # =====================================================================

    # Lab: Protect machine normal HTTPS browsing
    '<45>date=2024-12-16 time=18:21:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373260000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=55100 srcintf="port5" srcintfrole="lan" dstip=142.250.80.46 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200100 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=55100 app="Google.Services" appcat="web.client" duration=45 sentbyte=8200 rcvdbyte=125000 sentpkt=35 rcvdpkt=95 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Ubuntu machine apt update
    '<45>date=2024-12-16 time=18:22:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373320000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UBUNTU_IP}} srcport=43500 srcintf="port5" srcintfrole="lan" dstip=91.189.91.49 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United Kingdom" sessionid=40200200 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{UBUNTU_EXT_IP}} transport=43500 app="Ubuntu.Update" appcat="network.service" duration=15 sentbyte=2400 rcvdbyte=450000 sentpkt=12 rcvdpkt=320 osname="Linux" srcswversion="Ubuntu 22.04" mastersrcmac="aa:bb:cc:00:01:40" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Detect machine normal Office365 traffic
    '<45>date=2024-12-16 time=18:22:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373350000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{DETECT_IP}} srcport=51200 srcintf="port5" srcintfrole="lan" dstip=52.96.166.130 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200300 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=51200 app="Microsoft.Office.365" appcat="web.client" duration=180 sentbyte=32000 rcvdbyte=890000 sentpkt=120 rcvdpkt=650 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Unmanaged machine SSH to external (suspicious)
    '<45>date=2024-12-16 time=18:23:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373380000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip={{UNMANAGED_IP}} srcport=61400 srcintf="port5" srcintfrole="lan" dstip=45.33.32.156 dstport=22 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200400 proto=6 action="accept" policyid=5 policytype="policy" service="SSH" trandisp="snat" transip={{UNMANAGED_EXT_IP}} transport=61400 app="SSH" appcat="network.service" duration=300 sentbyte=45000 rcvdbyte=28000 sentpkt=200 rcvdpkt=180 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # Lab: Kali -> Detect internal port scan (IPS)
    '<45>date=2024-12-16 time=18:24:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373440000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip={{ATTACKER_IP}} srcport=0 srcintf="port5" srcintfrole="lan" dstip={{DETECT_IP}} dstport=0 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=0 proto=6 action="dropped" policyid=10 service="tcp" attack="Portscan.Detection" severity="medium" attackid=18432 msg="anomaly: port scan detected from internal host"',

    # Lab: Kali -> Unmanaged lateral movement attempt (SMB)
    '<45>date=2024-12-16 time=18:24:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373470000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip={{ATTACKER_IP}} srcport=44500 srcintf="port5" srcintfrole="lan" dstip={{UNMANAGED_IP}} dstport=445 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40300100 proto=6 action="dropped" policyid=10 service="SMB" attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" severity="critical" attackid=42888 msg="IPS signature matched: SMB exploitation attempt"',

    # =====================================================================
    # DETECTION TRIGGER: Generic - Web - Suspicious HTTP GET Requests
    # Post-compromise recon from Detect machine ({{DETECT_IP}})
    # Correlated with Mimecast phishing email to {{DETECT_EMAIL}}
    # =====================================================================

    # TRIGGER: GET /proc/self/environ on C2 server
    '<45>date=2024-12-16 time=18:25:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373500000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=52100 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400100 proto=6 action="passthrough" policyid=5 service="HTTP" httpmethod="GET" hostname="c2-callback.example.com" url="/proc/self/environ" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # TRIGGER: GET /etc/passwd
    '<45>date=2024-12-16 time=18:25:05 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373505000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=52102 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400102 proto=6 action="passthrough" policyid=5 service="HTTP" httpmethod="GET" hostname="c2-callback.example.com" url="/etc/passwd" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # TRIGGER: GET /etc/security/passwd
    '<45>date=2024-12-16 time=18:25:10 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373510000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=52104 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400104 proto=6 action="passthrough" policyid=5 service="HTTP" httpmethod="GET" hostname="c2-callback.example.com" url="/etc/security/passwd" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # Post-compromise: C2 callback from Detect to external attacker
    '<45>date=2024-12-16 time=18:25:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373530000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=49200 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=4443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400200 proto=6 action="accept" policyid=5 policytype="policy" service="tcp/4443" trandisp="snat" transip={{DETECT_EXT_IP}} transport=49200 app="SSL" appcat="network.service" duration=120 sentbyte=15000 rcvdbyte=85000 sentpkt=45 rcvdpkt=120 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # Post-compromise: Data exfiltration (large upload to external)
    '<45>date=2024-12-16 time=18:26:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373560000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=49250 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400300 proto=6 action="close" policyid=5 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=49250 app="SSL" appcat="network.service" duration=60 sentbyte=5200000 rcvdbyte=4500 sentpkt=3800 rcvdpkt=45 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # =====================================================================
    # NORMAL TRAFFIC — Lab machines SaaS browsing / updates / internal
    # Used in scenario mode to establish benign baseline
    # =====================================================================

    # [67] Protect: Slack HTTPS session
    '<45>date=2024-12-16 time=17:40:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370800000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=52400 srcintf="port5" srcintfrole="lan" dstip=44.236.112.50 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500100 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=52400 app="Slack" appcat="collaboration" duration=120 sentbyte=18500 rcvdbyte=245000 sentpkt=85 rcvdpkt=190 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [68] Protect: Microsoft Teams session
    '<45>date=2024-12-16 time=17:41:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370860000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=53200 srcintf="port5" srcintfrole="lan" dstip=52.112.120.20 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500200 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=53200 app="Microsoft.Teams" appcat="collaboration" duration=300 sentbyte=45000 rcvdbyte=680000 sentpkt=200 rcvdpkt=520 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [69] Protect: Zoom meeting
    '<45>date=2024-12-16 time=17:42:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370920000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=54100 srcintf="port5" srcintfrole="lan" dstip=170.114.52.10 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500300 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=54100 app="Zoom" appcat="video/audio" duration=1800 sentbyte=125000 rcvdbyte=4500000 sentpkt=800 rcvdpkt=3500 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [70] Protect: Salesforce browsing
    '<45>date=2024-12-16 time=17:43:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370980000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=55300 srcintf="port5" srcintfrole="lan" dstip=136.147.46.30 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500400 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=55300 app="Salesforce" appcat="web.client" duration=90 sentbyte=12000 rcvdbyte=185000 sentpkt=50 rcvdpkt=140 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [71] Protect: Windows Update download
    '<45>date=2024-12-16 time=17:44:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371040000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=56200 srcintf="port5" srcintfrole="lan" dstip=13.107.4.50 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500500 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=56200 app="Windows.Update" appcat="network.service" duration=45 sentbyte=5200 rcvdbyte=2800000 sentpkt=25 rcvdpkt=2000 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [72] Protect: Dropbox sync
    '<45>date=2024-12-16 time=17:45:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371100000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=57100 srcintf="port5" srcintfrole="lan" dstip=162.125.64.3 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40500600 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{PROTECT_EXT_IP}} transport=57100 app="Dropbox" appcat="cloud.app" duration=30 sentbyte=34000 rcvdbyte=95000 sentpkt=45 rcvdpkt=70 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [73] Detect: AWS Console session
    '<45>date=2024-12-16 time=17:40:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370830000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{DETECT_IP}} srcport=52800 srcintf="port5" srcintfrole="lan" dstip=54.239.28.85 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40600100 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=52800 app="AWS.Console" appcat="web.client" duration=600 sentbyte=52000 rcvdbyte=320000 sentpkt=180 rcvdpkt=250 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [74] Detect: GitHub HTTPS session
    '<45>date=2024-12-16 time=17:41:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370890000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{DETECT_IP}} srcport=53600 srcintf="port5" srcintfrole="lan" dstip=140.82.121.3 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40600200 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=53600 app="GitHub" appcat="web.client" duration=180 sentbyte=28000 rcvdbyte=410000 sentpkt=100 rcvdpkt=310 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [75] Detect: Google Search
    '<45>date=2024-12-16 time=17:42:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370950000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{DETECT_IP}} srcport=54500 srcintf="port5" srcintfrole="lan" dstip=142.250.80.46 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40600300 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=54500 app="Google.Search" appcat="web.client" duration=15 sentbyte=4800 rcvdbyte=62000 sentpkt=20 rcvdpkt=45 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [76] Detect: O365 Outlook
    '<45>date=2024-12-16 time=17:43:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371010000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{DETECT_IP}} srcport=55400 srcintf="port5" srcintfrole="lan" dstip=40.97.164.10 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40600400 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{DETECT_EXT_IP}} transport=55400 app="Microsoft.Outlook.365" appcat="web.client" duration=240 sentbyte=35000 rcvdbyte=520000 sentpkt=130 rcvdpkt=400 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [77] Ubuntu: NTP sync
    '<45>date=2024-12-16 time=17:40:15 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370815000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UBUNTU_IP}} srcport=42300 srcintf="port5" srcintfrole="lan" dstip=91.189.89.198 dstport=123 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United Kingdom" sessionid=40700100 proto=17 action="accept" policyid=3 policytype="policy" service="NTP" trandisp="snat" transip={{UBUNTU_EXT_IP}} transport=42300 app="NTP" appcat="network.service" duration=1 sentbyte=76 rcvdbyte=76 sentpkt=1 rcvdpkt=1 osname="Linux" srcswversion="Ubuntu 22.04" mastersrcmac="aa:bb:cc:00:01:40" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # [78] Ubuntu: OCSP certificate validation
    '<45>date=2024-12-16 time=17:41:15 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370875000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UBUNTU_IP}} srcport=43100 srcintf="port5" srcintfrole="lan" dstip=93.184.220.29 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40700200 proto=6 action="close" policyid=3 policytype="policy" service="HTTP" trandisp="snat" transip={{UBUNTU_EXT_IP}} transport=43100 app="HTTP.BROWSER" appcat="web.client" duration=2 sentbyte=450 rcvdbyte=1200 sentpkt=4 rcvdpkt=4 osname="Linux" srcswversion="Ubuntu 22.04" mastersrcmac="aa:bb:cc:00:01:40" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [79] Ubuntu: Internal apt mirror
    '<45>date=2024-12-16 time=17:42:15 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370935000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UBUNTU_IP}} srcport=44200 srcintf="port5" srcintfrole="lan" dstip=10.0.0.5 dstport=80 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40700300 proto=6 action="close" policyid=10 policytype="policy" service="HTTP" trandisp="noop" app="HTTP.BROWSER" appcat="web.client" duration=8 sentbyte=3200 rcvdbyte=1250000 sentpkt=15 rcvdpkt=900 osname="Linux" srcswversion="Ubuntu 22.04" mastersrcmac="aa:bb:cc:00:01:40" masterdstmac="11:22:33:44:55:05" msg="Session closed"',

    # [80] Unmanaged: Internal SMB file share access
    '<45>date=2024-12-16 time=17:44:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371070000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UNMANAGED_IP}} srcport=49900 srcintf="port5" srcintfrole="lan" dstip=10.0.0.5 dstport=445 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40800100 proto=6 action="close" policyid=10 policytype="policy" service="SMB" trandisp="noop" app="SMB" appcat="network.service" duration=5 sentbyte=2400 rcvdbyte=85000 sentpkt=12 rcvdpkt=65 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:05" msg="Session closed"',

    # [81] Unmanaged: LDAP auth to domain controller
    '<45>date=2024-12-16 time=17:45:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371130000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UNMANAGED_IP}} srcport=50100 srcintf="port5" srcintfrole="lan" dstip=10.0.0.5 dstport=389 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40800200 proto=6 action="close" policyid=10 policytype="policy" service="LDAP" trandisp="noop" app="LDAP" appcat="network.service" duration=1 sentbyte=850 rcvdbyte=2400 sentpkt=6 rcvdpkt=6 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:05" msg="Session closed"',

    # [82] Protect -> Detect internal HTTPS (intranet)
    '<45>date=2024-12-16 time=17:46:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371160000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{PROTECT_IP}} srcport=58100 srcintf="port5" srcintfrole="lan" dstip={{DETECT_IP}} dstport=443 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40900100 proto=6 action="close" policyid=10 policytype="policy" service="HTTPS" trandisp="noop" app="SSL" appcat="network.service" duration=10 sentbyte=3200 rcvdbyte=18000 sentpkt=15 rcvdpkt=20 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="aa:bb:cc:00:01:31" msg="Session closed"',

    # =====================================================================
    # POST-COMPROMISE RECON — Detect (compromised) probing Protect (BL)
    # Adversary pivoting from victim to another CrowdStrike-managed host
    # =====================================================================

    # [83] Detect -> Protect: SMB probe (adversary checking file shares)
    '<45>date=2024-12-16 time=18:27:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373620000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=49800 srcintf="port5" srcintfrole="lan" dstip={{PROTECT_IP}} dstport=445 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=41000100 proto=6 action="accept" policyid=10 policytype="policy" service="SMB" trandisp="noop" app="SMB" appcat="network.service" duration=3 sentbyte=1800 rcvdbyte=4200 sentpkt=12 rcvdpkt=10 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="aa:bb:cc:00:01:30" msg="Session accepted"',

    # [84] Detect -> Protect: RDP attempt (adversary trying remote desktop)
    '<45>date=2024-12-16 time=18:27:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373650000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=50200 srcintf="port5" srcintfrole="lan" dstip={{PROTECT_IP}} dstport=3389 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=41000200 proto=6 action="accept" policyid=10 policytype="policy" service="RDP" trandisp="noop" app="RDP" appcat="network.service" duration=8 sentbyte=5400 rcvdbyte=12000 sentpkt=25 rcvdpkt=30 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="aa:bb:cc:00:01:30" msg="Session accepted"',

    # [85] Detect -> Protect: Admin share C$ access attempt (lateral movement)
    '<45>date=2024-12-16 time=18:28:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373680000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=50500 srcintf="port5" srcintfrole="lan" dstip={{PROTECT_IP}} dstport=445 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=41000300 proto=6 action="accept" policyid=10 policytype="policy" service="SMB" trandisp="noop" app="SMB" appcat="network.service" duration=2 sentbyte=3200 rcvdbyte=1500 sentpkt=18 rcvdpkt=8 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="aa:bb:cc:00:01:30" msg="Session accepted"',

    # [86] Unmanaged: HTTPS web browsing (contractor checking webmail)
    '<45>date=2024-12-16 time=17:43:15 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734370995000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UNMANAGED_IP}} srcport=52700 srcintf="port5" srcintfrole="lan" dstip=142.250.80.46 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40800300 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip={{UNMANAGED_EXT_IP}} transport=52700 app="Google.Gmail" appcat="web.client" duration=60 sentbyte=15000 rcvdbyte=230000 sentpkt=65 rcvdpkt=175 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # [87] Unmanaged: DNS query to external resolver
    '<45>date=2024-12-16 time=17:44:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734371040000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip={{UNMANAGED_IP}} srcport=51300 srcintf="port5" srcintfrole="lan" dstip=8.8.8.8 dstport=53 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40800400 proto=17 action="accept" policyid=3 policytype="policy" service="DNS" trandisp="snat" transip={{UNMANAGED_EXT_IP}} transport=51300 app="DNS" appcat="network.service" duration=1 sentbyte=74 rcvdbyte=180 sentpkt=1 rcvdpkt=1 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # =====================================================================
    # POST-COMPROMISE: C2 to attacker.lab.local (internal attacker infra)
    # Links to existing payloads in DT Outlook box
    # =====================================================================

    # [88] Detect -> attacker.lab.local: HTTP beacon (payload callback)
    '<45>date=2024-12-16 time=18:25:15 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373515000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=52200 srcintf="port5" srcintfrole="lan" dstip={{ATTACKER_IP}} dstport=80 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40400150 proto=6 action="passthrough" policyid=10 service="HTTP" httpmethod="GET" hostname="attacker.lab.local" url="/api/beacon?id=DT01&t=1734373515" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # [89] Detect -> attacker.lab.local: C2 reverse shell session
    '<45>date=2024-12-16 time=18:25:40 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373540000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=49300 srcintf="port5" srcintfrole="lan" dstip={{ATTACKER_IP}} dstport=4444 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40400250 proto=6 action="accept" policyid=10 policytype="policy" service="tcp/4444" trandisp="noop" app="TCP-Generic" appcat="network.service" duration=300 sentbyte=28000 rcvdbyte=145000 sentpkt=120 rcvdpkt=280 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="aa:bb:cc:00:01:21" msg="Session accepted"',

    # [90] Detect -> attacker.lab.local: staged payload download
    '<45>date=2024-12-16 time=18:25:50 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373550000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" user="{{DETECT_USER}}" srcip={{DETECT_IP}} srcport=52300 srcintf="port5" srcintfrole="lan" dstip={{ATTACKER_IP}} dstport=8080 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40400260 proto=6 action="passthrough" policyid=10 service="HTTP" httpmethod="GET" hostname="attacker.lab.local" url="/payloads/stage2.exe" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',
]


###########################################################################
#                       MIMECAST BUILTIN SAMPLES                          #
###########################################################################

MIMECAST_SAMPLES = [

    # =====================================================================
    # Receipt logs - message accepted / rejected
    # =====================================================================

    # Receipt: Message accepted with TLS, SPF pass, DKIM pass
    '{"datetime":"2024-12-16T17:50:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<msg001@sender.example.com>","Subject":"Quarterly Report Q4","headerFrom":"finance@sender.example.com","Sender":"finance@sender.example.com","senderEnvelope":"finance@sender.example.com","Rcpt":"john.doe@recipient.example.com","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":1,"SpamInfo":"virus score=clean","SpfResult":"pass","DkimResult":"pass","IP":"198.51.100.25","Dir":"Inbound","MsgSz":45200,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Receipt: Message rejected - spam
    '{"datetime":"2024-12-16T17:51:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<spam001@spammer.example.net>","Subject":"YOU HAVE WON $10000000","headerFrom":"prize@spammer.example.net","Sender":"prize@spammer.example.net","senderEnvelope":"bounce@spammer.example.net","Rcpt":"jane.smith@recipient.example.com","Act":"Rej","TlsVer":"TLSv1.2","Cphr":"ECDHE-RSA-AES256-GCM-SHA384","SpamScore":98,"SpamInfo":"virus score=dirty, spam score=98, phish score=high","SpfResult":"fail","DkimResult":"fail","IP":"203.0.113.77","Dir":"Inbound","MsgSz":12400,"RejType":"spam","RejCode":"550","RejInfo":"Message rejected due to spam content"}',

    # Receipt: Outbound message accepted
    '{"datetime":"2024-12-16T17:52:00+0000","aCode":"acc1002","acc":"C0A1","type":"receipt","MsgId":"<out001@company.example.com>","Subject":"Re: Project Update","headerFrom":"alice.wong@company.example.com","Sender":"alice.wong@company.example.com","senderEnvelope":"alice.wong@company.example.com","Rcpt":"partner@external.example.com","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_128_GCM_SHA256","SpamScore":0,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"10.0.0.50","Dir":"Outbound","MsgSz":8500,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # =====================================================================
    # Process logs - with/without attachments, held for review
    # =====================================================================

    # Process: With attachment
    '{"datetime":"2024-12-16T17:53:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<proc001@sender.example.com>","Subject":"Invoice #INV-2024-0891","headerFrom":"billing@sender.example.com","Sender":"billing@sender.example.com","Rcpt":"accounts@recipient.example.com","Act":"Prc","attachments":"invoice_2024_0891.pdf","AttCnt":1,"AttSz":125000,"Route":"inbound","Hld":"N","HldRsn":"N/A"}',

    # Process: Without attachment
    '{"datetime":"2024-12-16T17:54:00+0000","aCode":"acc1002","acc":"C0A1","type":"process","MsgId":"<proc002@company.example.com>","Subject":"Meeting Tomorrow at 3pm","headerFrom":"bob.chen@company.example.com","Sender":"bob.chen@company.example.com","Rcpt":"team@company.example.com","Act":"Prc","attachments":"N/A","AttCnt":0,"AttSz":0,"Route":"internal","Hld":"N","HldRsn":"N/A"}',

    # Process: Held for review (spam)
    '{"datetime":"2024-12-16T17:55:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<proc003@marketing.example.net>","Subject":"Limited Time Offer - Act Now!!!","headerFrom":"deals@marketing.example.net","Sender":"deals@marketing.example.net","Rcpt":"info@recipient.example.com","Act":"Hld","attachments":"offer_brochure.pdf","AttCnt":1,"AttSz":310000,"Route":"inbound","Hld":"Y","HldRsn":"Suspected spam content detected - held for admin review"}',

    # =====================================================================
    # Delivery logs - successful / failed
    # =====================================================================

    # Delivery: Successful
    '{"datetime":"2024-12-16T17:56:00+0000","aCode":"acc1001","acc":"C0A0","type":"delivery","MsgId":"<del001@sender.example.com>","Subject":"Weekly Status Report","headerFrom":"manager@sender.example.com","Sender":"manager@sender.example.com","Rcpt":"team-lead@recipient.example.com","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.recipient.example.com","TlsVer":"TLSv1.3","Latency":1200,"Attempt":1,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Delivery: Failed - timeout
    '{"datetime":"2024-12-16T17:57:00+0000","aCode":"acc1002","acc":"C0A1","type":"delivery","MsgId":"<del002@company.example.com>","Subject":"Contract Renewal","headerFrom":"legal@company.example.com","Sender":"legal@company.example.com","Rcpt":"partner@unreachable.example.com","Act":"Rej","Dlv":"Failed","DlvTo":"mx01.unreachable.example.com","TlsVer":"N/A","Latency":30000,"Attempt":3,"RejType":"connection_timeout","RejCode":"451","RejInfo":"Connection timed out after 30s on attempt 3"}',

    # Delivery: Failed - rejected by remote
    '{"datetime":"2024-12-16T17:58:00+0000","aCode":"acc1001","acc":"C0A0","type":"delivery","MsgId":"<del003@sender.example.com>","Subject":"Follow Up","headerFrom":"sales@sender.example.com","Sender":"sales@sender.example.com","Rcpt":"nouser@strict-mx.example.com","Act":"Rej","Dlv":"Failed","DlvTo":"mx02.strict-mx.example.com","TlsVer":"TLSv1.2","Latency":800,"Attempt":1,"RejType":"remote_reject","RejCode":"550","RejInfo":"550 5.1.1 The email account that you tried to reach does not exist"}',

    # =====================================================================
    # AV logs - virus detected
    # =====================================================================

    # AV: Macro malware BLOCKED — same attacker as successful phish [21]
    # Attacker first attempt: securecorp-benefits.com -> {{DETECT_EMAIL}} — caught by AV
    '{"datetime":"2024-12-16T17:59:00+0000","aCode":"acc1001","acc":"C0A0","type":"av","MsgId":"<av-blocked-001@securecorp-benefits.com>","Subject":"Q4 Benefits Enrollment - Review Required","headerFrom":"hr-admin@securecorp-benefits.com","Sender":"hr-admin@securecorp-benefits.com","Rcpt":"{{DETECT_EMAIL}}","Act":"Hld","FileName":"Q4_Benefits_Enrollment.xlsm","FileExt":"xlsm","FileSz":192000,"Virus":"W97M/Downloader.AKQ","ScanResult":"malicious","Route":"inbound","Dir":"Inbound","IP":"198.51.100.77","SpamScore":18,"SpfResult":"pass","DkimResult":"pass","msg":"Macro malware detected in Excel attachment — held for review"}',

    # AV: Phishing HTML BLOCKED — same attacker as successful phish [23]
    # Attacker first attempt: it-helpdesk-portal.com -> {{PROTECT_EMAIL}} — caught by AV
    '{"datetime":"2024-12-16T18:00:00+0000","aCode":"acc1001","acc":"C0A0","type":"av","MsgId":"<av-blocked-002@it-helpdesk-portal.com>","Subject":"IT Security Alert - Verify Your Account","headerFrom":"noreply@it-helpdesk-portal.com","Sender":"noreply@it-helpdesk-portal.com","Rcpt":"{{PROTECT_EMAIL}}","Act":"Rej","FileName":"account_verification.html","FileExt":"html","FileSz":5200,"Virus":"HTML/Phishing.Agent.B","ScanResult":"malicious","Route":"inbound","Dir":"Inbound","IP":"104.20.145.30","SpamScore":30,"SpfResult":"neutral","DkimResult":"pass","msg":"Phishing content detected in HTML attachment — rejected"}',

    # =====================================================================
    # Spam Event Thread logs
    # =====================================================================

    # Spam: Spam detected and quarantined
    '{"datetime":"2024-12-16T18:01:00+0000","aCode":"acc1001","acc":"C0A0","type":"spam","MsgId":"<spam002@bulk.example.net>","Subject":"Buy Cheap Pharmaceuticals Online","headerFrom":"offers@bulk.example.net","Sender":"offers@bulk.example.net","Rcpt":"admin@recipient.example.com","Act":"Hld","SpamScore":95,"SpamInfo":"spam score=95, bulk sender, suspicious URL","ScanResult":"spam","Route":"inbound","msg":"Spam detected and quarantined"}',

    # =====================================================================
    # TTP Internal Email Protect
    # =====================================================================

    # TTP Internal: Blocked URL in internal email
    '{"datetime":"2024-12-16T18:02:00+0000","aCode":"acc1002","acc":"C0A1","type":"ttp_internal","MsgId":"<ttp-int001@company.example.com>","Subject":"Check this out","headerFrom":"compromised.user@company.example.com","Sender":"compromised.user@company.example.com","Rcpt":"coworker@company.example.com","Act":"Hld","URL":"https://evil-phish.example.net/steal-creds","URLCategory":"phishing","ScanResult":"malicious","Route":"internal","msg":"Blocked malicious URL in internal email - possible account compromise"}',

    # =====================================================================
    # TTP Impersonation Protect
    # =====================================================================

    # TTP Impersonation: Internal name impersonation
    '{"datetime":"2024-12-16T18:03:00+0000","aCode":"acc1001","acc":"C0A0","type":"ttp_impersonation","MsgId":"<imp001@lookalike.example.net>","Subject":"Urgent Wire Transfer Needed","headerFrom":"ceo.name@lookalike.example.net","Sender":"ceo.name@lookalike.example.net","Rcpt":"cfo@recipient.example.com","Act":"Hld","ImpersonationResult":"internal_name_match","ImpersonatedUser":"CEO Name","Confidence":"high","ScanResult":"impersonation","Route":"inbound","msg":"Internal display name impersonation detected - matches CEO identity"}',

    # TTP Impersonation: New external domain
    '{"datetime":"2024-12-16T18:04:00+0000","aCode":"acc1001","acc":"C0A0","type":"ttp_impersonation","MsgId":"<imp002@new-vendor.example.org>","Subject":"Updated Bank Details for Payment","headerFrom":"accounts@new-vendor.example.org","Sender":"accounts@new-vendor.example.org","Rcpt":"payables@recipient.example.com","Act":"Hld","ImpersonationResult":"new_domain","ImpersonatedUser":"N/A","Confidence":"medium","ScanResult":"suspicious","Route":"inbound","msg":"Newly registered domain detected requesting payment changes"}',

    # =====================================================================
    # TTP URL Protect
    # =====================================================================

    # TTP URL: Malicious URL clicked
    '{"datetime":"2024-12-16T18:05:00+0000","aCode":"acc1002","acc":"C0A1","type":"ttp_url","MsgId":"<url001@sender.example.com>","Subject":"Reset Your Password","headerFrom":"it-support@sender.example.com","Sender":"it-support@sender.example.com","Rcpt":"user@recipient.example.com","Act":"Blk","URL":"https://credential-harvest.example.net/login","URLCategory":"credential_phishing","UserAction":"clicked","ScanResult":"malicious","UserAwareness":"warned","Route":"inbound","msg":"User clicked malicious URL - access blocked at click time"}',

    # =====================================================================
    # TTP Attachment Protect
    # =====================================================================

    # TTP Attachment: Malicious attachment detected
    '{"datetime":"2024-12-16T18:06:00+0000","aCode":"acc1001","acc":"C0A0","type":"ttp_attachment","MsgId":"<att001@compromised.example.net>","Subject":"Signed Contract Attached","headerFrom":"legal@compromised.example.net","Sender":"legal@compromised.example.net","Rcpt":"contracts@recipient.example.com","Act":"Hld","FileName":"signed_contract.docx","FileExt":"docx","FileSz":67000,"SandboxResult":"malicious","SandboxDetail":"Document contains obfuscated PowerShell dropper","Confidence":"high","Route":"inbound","msg":"Attachment sandbox analysis detected malicious payload"}',

    # TTP Attachment: Suspicious archive
    '{"datetime":"2024-12-16T18:07:00+0000","aCode":"acc1002","acc":"C0A1","type":"ttp_attachment","MsgId":"<att002@external.example.net>","Subject":"Requested Files","headerFrom":"vendor@external.example.net","Sender":"vendor@external.example.net","Rcpt":"procurement@recipient.example.com","Act":"Hld","FileName":"requested_files.zip","FileExt":"zip","FileSz":2100000,"SandboxResult":"suspicious","SandboxDetail":"Archive contains password-protected executable","Confidence":"medium","Route":"inbound","msg":"Suspicious archive attachment held for review"}',

    # =====================================================================
    # LAB ENVIRONMENT TRAFFIC ({{LAB_DOMAIN}})
    # Correlated with FortiGate attack scenario on Detect {{DETECT_IP}}
    # =====================================================================

    # Legitimate: Internal IT notification
    '{"datetime":"2024-12-16T18:10:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<it-notice-001@{{LAB_DOMAIN}}>","Subject":"Scheduled Maintenance Window - Saturday 2am","headerFrom":"it-ops@{{LAB_DOMAIN}}","Sender":"it-ops@{{LAB_DOMAIN}}","Rcpt":"all-staff@{{LAB_DOMAIN}}","Act":"Acc","attachments":"N/A","AttCnt":0,"AttSz":0,"Route":"internal","Dir":"Internal","Hld":"N","HldRsn":"N/A","MsgSz":3200}',

    # Legitimate: External partner email
    '{"datetime":"2024-12-16T18:11:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<partner-001@acme-corp.com>","Subject":"Re: Joint Project Timeline","headerFrom":"pm@acme-corp.com","Sender":"pm@acme-corp.com","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":0,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"203.0.113.50","Dir":"Inbound","MsgSz":15600,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Legitimate: Outbound from lab user
    '{"datetime":"2024-12-16T18:12:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<outbound-001@{{LAB_DOMAIN}}>","Subject":"Updated Network Diagram","headerFrom":"{{PROTECT_EMAIL}}","Sender":"{{PROTECT_EMAIL}}","Rcpt":"vendor-support@external.example.com","Act":"Acc","attachments":"network_diagram_v2.pdf","AttCnt":1,"AttSz":2400000,"Route":"outbound","Dir":"Outbound","Hld":"N","HldRsn":"N/A","MsgSz":2450000}',

    # =====================================================================
    # DETECTION TRIGGER: Mimecast Suspicious Attachment Type Detected
    # Phishing email with .xlsm macro-enabled attachment to Detect user
    # Correlated with FortiGate suspicious HTTP GETs from {{DETECT_IP}}
    # =====================================================================

    # TRIGGER (process): Phishing with .xlsm accepted — attacker -> {{DETECT_EMAIL}}
    '{"datetime":"2024-12-16T18:15:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","processingId":"proc-2024-atk-00891","MsgId":"<atk001@securecorp-benefits.com>","Subject":"Q4 Benefits Update - Action Required","headerFrom":"hr-admin@securecorp-benefits.com","Sender":"hr-admin@securecorp-benefits.com","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","attachments":"Q4_Benefits_Update.xlsm","AttCnt":1,"AttSz":185000,"numberAttachments":1,"Route":"inbound","Dir":"Inbound","Hld":"N","HldRsn":"N/A","SpamScore":12,"SpfResult":"pass","DkimResult":"pass","IP":"198.51.100.77","MsgSz":195000}',

    # TRIGGER (delivery): Same phishing email delivered successfully
    '{"datetime":"2024-12-16T18:15:02+0000","aCode":"acc1001","acc":"C0A0","type":"delivery","processingId":"proc-2024-atk-00891","MsgId":"<atk001@securecorp-benefits.com>","Subject":"Q4 Benefits Update - Action Required","headerFrom":"hr-admin@securecorp-benefits.com","Sender":"hr-admin@securecorp-benefits.com","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.{{LAB_DOMAIN}}","TlsVer":"TLSv1.3","Latency":850,"Attempt":1,"Dir":"Inbound","delivered":"true","RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # TRIGGER (process): Second phishing with .html credential harvester
    '{"datetime":"2024-12-16T18:16:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","processingId":"proc-2024-atk-00892","MsgId":"<atk002@it-helpdesk-portal.com>","Subject":"Password Expiry Notice - Immediate Action","headerFrom":"noreply@it-helpdesk-portal.com","Sender":"noreply@it-helpdesk-portal.com","Rcpt":"{{PROTECT_EMAIL}}","Act":"Acc","attachments":"password_reset_form.html","AttCnt":1,"AttSz":8200,"numberAttachments":1,"Route":"inbound","Dir":"Inbound","Hld":"N","HldRsn":"N/A","SpamScore":25,"SpfResult":"neutral","DkimResult":"pass","IP":"104.20.145.30","MsgSz":12800}',

    # TRIGGER (delivery): Second phishing delivered
    '{"datetime":"2024-12-16T18:16:03+0000","aCode":"acc1001","acc":"C0A0","type":"delivery","processingId":"proc-2024-atk-00892","MsgId":"<atk002@it-helpdesk-portal.com>","Subject":"Password Expiry Notice - Immediate Action","headerFrom":"noreply@it-helpdesk-portal.com","Sender":"noreply@it-helpdesk-portal.com","Rcpt":"{{PROTECT_EMAIL}}","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.{{LAB_DOMAIN}}","TlsVer":"TLSv1.3","Latency":720,"Attempt":1,"Dir":"Inbound","delivered":"true","RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # =====================================================================
    # NORMAL EMAIL — Benign traffic for scenario baseline
    # =====================================================================

    # [25] Newsletter subscription
    '{"datetime":"2024-12-16T17:35:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<newsletter-001@techdigest.example.com>","Subject":"Tech Digest Weekly - Dec 16 Edition","headerFrom":"noreply@techdigest.example.com","Sender":"noreply@techdigest.example.com","senderEnvelope":"bounce@techdigest.example.com","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":5,"SpamInfo":"clean, bulk sender","SpfResult":"pass","DkimResult":"pass","IP":"198.51.100.30","Dir":"Inbound","MsgSz":82000,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # [26] Calendar invite
    '{"datetime":"2024-12-16T17:36:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<calendar-001@{{LAB_DOMAIN}}>","Subject":"Accepted: Weekly Standup - Tuesday 10am","headerFrom":"{{PROTECT_EMAIL}}","Sender":"{{PROTECT_EMAIL}}","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","attachments":"invite.ics","AttCnt":1,"AttSz":2800,"Route":"internal","Dir":"Internal","Hld":"N","HldRsn":"N/A","MsgSz":8500}',

    # [27] Okta password reset notification
    '{"datetime":"2024-12-16T17:37:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<okta-reset-001@okta.example.com>","Subject":"Your password was successfully changed","headerFrom":"noreply@okta.example.com","Sender":"noreply@okta.example.com","senderEnvelope":"noreply@okta.example.com","Rcpt":"{{PROTECT_EMAIL}}","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_128_GCM_SHA256","SpamScore":0,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"52.21.30.15","Dir":"Inbound","MsgSz":12400,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # [28] Automated report delivery
    '{"datetime":"2024-12-16T17:38:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","MsgId":"<report-001@{{LAB_DOMAIN}}>","Subject":"Daily SIEM Summary Report - Dec 16","headerFrom":"siem-reports@{{LAB_DOMAIN}}","Sender":"siem-reports@{{LAB_DOMAIN}}","Rcpt":"soc-team@{{LAB_DOMAIN}}","Act":"Acc","attachments":"daily_siem_summary_2024-12-16.pdf","AttCnt":1,"AttSz":345000,"Route":"internal","Dir":"Internal","Hld":"N","HldRsn":"N/A","MsgSz":352000}',

    # [29] Vendor invoice (legitimate external)
    '{"datetime":"2024-12-16T17:39:00+0000","aCode":"acc1001","acc":"C0A0","type":"receipt","MsgId":"<invoice-001@acme-corp.com>","Subject":"Invoice #ACM-2024-1247 - December Services","headerFrom":"billing@acme-corp.com","Sender":"billing@acme-corp.com","senderEnvelope":"billing@acme-corp.com","Rcpt":"accounts@{{LAB_DOMAIN}}","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":2,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"203.0.113.50","Dir":"Inbound","MsgSz":95000,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # =====================================================================
    # DETECTION TRIGGER: tstark@workshop.cs-labs.net phishing
    # Links to existing malicious emails in DT Outlook box
    # Same sender lets NGSIEM correlate generated + real detections
    # =====================================================================

    # [30] TRIGGER (process): tstark phishing with malicious link — accepted to DT
    '{"datetime":"2024-12-16T18:14:00+0000","aCode":"acc1001","acc":"C0A0","type":"process","processingId":"proc-2024-atk-00893","MsgId":"<atk003@workshop.cs-labs.net>","Subject":"Stark Industries - Confidential Project Files","headerFrom":"tstark@workshop.cs-labs.net","Sender":"tstark@workshop.cs-labs.net","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","attachments":"Project_Files_Q4.zip","AttCnt":1,"AttSz":342000,"numberAttachments":1,"Route":"inbound","Dir":"Inbound","Hld":"N","HldRsn":"N/A","SpamScore":8,"SpfResult":"neutral","DkimResult":"none","IP":"{{ATTACKER_EXT_IP}}","MsgSz":355000}',

    # [31] TRIGGER (delivery): tstark phishing delivered to DT
    '{"datetime":"2024-12-16T18:14:03+0000","aCode":"acc1001","acc":"C0A0","type":"delivery","processingId":"proc-2024-atk-00893","MsgId":"<atk003@workshop.cs-labs.net>","Subject":"Stark Industries - Confidential Project Files","headerFrom":"tstark@workshop.cs-labs.net","Sender":"tstark@workshop.cs-labs.net","Rcpt":"{{DETECT_EMAIL}}","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.{{LAB_DOMAIN}}","TlsVer":"TLSv1.3","Latency":680,"Attempt":1,"Dir":"Inbound","delivered":"true","RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',
]


###########################################################################
#                        VENDOR REGISTRY                                  #
###########################################################################

VENDOR_REGISTRY = {
    "fortinet": {
        "description": "FortiGate syslog (traffic, event, UTM/security)",
        "samples": FORTINET_SAMPLES,
    },
    "mimecast": {
        "description": "Mimecast email security logs (JSON)",
        "samples": MIMECAST_SAMPLES,
    },
}


###########################################################################
#                    ATTACK TIMELINE SCENARIO                             #
# Ordered phases for --vendor all --count 0 (no CSV)                     #
# Tuples: (vendor, sample_index)                                         #
###########################################################################

SCENARIO_SEQUENCE = [
    # ------------------------------------------------------------------
    # Phase 1: Normal Baseline  (~20 logs)
    # Lab machines doing everyday SaaS browsing, updates, benign email
    # ------------------------------------------------------------------
    ("fortinet", 67),   # Protect: Slack
    ("mimecast", 25),   # Newsletter to {{DETECT_EMAIL}}
    ("fortinet", 68),   # Protect: Teams
    ("fortinet", 77),   # Ubuntu: NTP sync
    ("fortinet", 73),   # Detect: AWS Console
    ("mimecast", 26),   # Calendar invite (internal)
    ("fortinet", 69),   # Protect: Zoom
    ("fortinet", 74),   # Detect: GitHub
    ("mimecast", 27),   # Okta password reset
    ("fortinet", 70),   # Protect: Salesforce
    ("fortinet", 78),   # Ubuntu: OCSP check
    ("fortinet", 75),   # Detect: Google Search
    ("mimecast", 29),   # Vendor invoice
    ("fortinet", 71),   # Protect: Windows Update
    ("fortinet", 79),   # Ubuntu: apt mirror
    ("fortinet", 76),   # Detect: O365 Outlook
    ("mimecast", 28),   # Automated SIEM report
    ("fortinet", 72),   # Protect: Dropbox
    ("fortinet", 80),   # Unmanaged: SMB file share
    ("fortinet", 81),   # Unmanaged: LDAP auth
    ("fortinet", 86),   # Unmanaged: Gmail web browsing
    ("fortinet", 87),   # Unmanaged: DNS query

    # ------------------------------------------------------------------
    # Phase 2: Spearphishing  (~10 logs)
    # First wave BLOCKED by Mimecast, second wave gets through
    # Same attacker domains link the detections in NGSIEM
    # ------------------------------------------------------------------
    ("mimecast", 19),   # Legit: Internal IT notification
    ("mimecast", 9),    # BLOCKED: .xlsm from securecorp-benefits.com -> {{DETECT_EMAIL}}
    ("mimecast", 10),   # BLOCKED: .html from it-helpdesk-portal.com -> {{PROTECT_EMAIL}}
    ("mimecast", 20),   # Legit: External partner email to {{DETECT_EMAIL}}
    ("mimecast", 21),   # TRIGGER: Phishing .xlsm process (same domain, diff subject — evades)
    ("mimecast", 22),   # TRIGGER: Phishing .xlsm delivered to {{DETECT_EMAIL}}
    ("mimecast", 23),   # TRIGGER: Phishing .html process (same domain, diff subject)
    ("mimecast", 24),   # TRIGGER: Phishing .html delivered to {{PROTECT_EMAIL}}
    ("mimecast", 30),   # TRIGGER: tstark@workshop.cs-labs.net -> {{DETECT_EMAIL}} (links to real inbox)
    ("mimecast", 31),   # TRIGGER: tstark phishing delivered to {{DETECT_EMAIL}}

    # ------------------------------------------------------------------
    # Phase 3: Cover Traffic  (~10 logs)
    # More normal activity — victim hasn't opened attachment yet
    # ------------------------------------------------------------------
    ("fortinet", 82),   # Protect -> Detect internal traffic
    ("fortinet", 67),   # Protect: Slack (repeat with variation)
    ("fortinet", 58),   # Protect: Google browsing (original sample)
    ("fortinet", 76),   # Detect: O365 (repeat)
    ("mimecast", 0),    # Receipt: legit accepted
    ("fortinet", 59),   # Ubuntu: apt update (original sample)
    ("fortinet", 74),   # Detect: GitHub (repeat)
    ("mimecast", 4),    # Process: no attachment
    ("fortinet", 68),   # Protect: Teams (repeat)
    ("fortinet", 75),   # Detect: Google Search (repeat)

    # ------------------------------------------------------------------
    # Phase 4: Compromise & Recon  (~8 logs)
    # Detect machine starts suspicious HTTP GETs, mixed with normal
    # ------------------------------------------------------------------
    ("fortinet", 73),   # Detect: AWS Console (normal — still working)
    ("fortinet", 62),   # TRIGGER: GET /proc/self/environ
    ("fortinet", 76),   # Detect: O365 (normal cover)
    ("fortinet", 63),   # TRIGGER: GET /etc/passwd
    ("fortinet", 64),   # TRIGGER: GET /etc/security/passwd
    ("mimecast", 2),    # Outbound email (normal cover)
    ("fortinet", 60),   # Detect: O365 (original sample)
    ("fortinet", 82),   # Internal traffic cover

    # ------------------------------------------------------------------
    # Phase 5: C2 & Lateral Movement  (~9 logs)
    # C2 callback, then adversary probes Protect (BL) from Detect
    # ------------------------------------------------------------------
    ("fortinet", 65),   # C2 callback from Detect -> 185.220.101.45
    ("fortinet", 88),   # C2: Detect -> attacker.lab.local beacon (links to real payloads)
    ("fortinet", 89),   # C2: Detect -> attacker.lab.local reverse shell
    ("fortinet", 90),   # C2: Detect -> attacker.lab.local stage2 download
    ("fortinet", 83),   # RECON: Detect -> Protect SMB probe
    ("fortinet", 84),   # RECON: Detect -> Protect RDP attempt
    ("fortinet", 85),   # RECON: Detect -> Protect admin share C$
    ("fortinet", 61),   # Kali -> Unmanaged SMB exploitation
    ("fortinet", 80),   # Unmanaged: normal SMB (cover)
    ("fortinet", 60),   # Kali -> Detect port scan (IPS)
    ("fortinet", 81),   # Unmanaged: LDAP (cover)
    ("mimecast", 19),   # Internal IT email (cover)

    # ------------------------------------------------------------------
    # Phase 6: Data Exfiltration  (~3 logs)
    # Large upload with cover traffic
    # ------------------------------------------------------------------
    ("fortinet", 75),   # Detect: Google (normal cover)
    ("fortinet", 66),   # TRIGGER: 5.2MB upload exfiltration
    ("mimecast", 5),    # Delivery: legit (cover)
]


def build_scenario_queue(vendor_ports, port_override):
    """Build ordered attack-timeline queue, then append unseen samples shuffled."""
    seen = {"fortinet": set(), "mimecast": set()}
    queue = []

    for vendor, idx in SCENARIO_SEQUENCE:
        samples = VENDOR_REGISTRY[vendor]["samples"]
        if idx >= len(samples):
            continue  # safety: skip if index out of range
        port = port_override if port_override is not None else vendor_ports.get(vendor, SYSLOG_PORT)
        queue.append((vendor, port, samples[idx]))
        seen[vendor].add(idx)

    # Append all unseen samples from both vendors, shuffled (background noise)
    remainder = []
    for vendor in VENDOR_REGISTRY:
        samples = VENDOR_REGISTRY[vendor]["samples"]
        port = port_override if port_override is not None else vendor_ports.get(vendor, SYSLOG_PORT)
        for idx, sample in enumerate(samples):
            if idx not in seen.get(vendor, set()):
                remainder.append((vendor, port, sample))
    random.shuffle(remainder)
    queue.extend(remainder)

    return queue


###########################################################################
#                    PARSER DEMO SAMPLE INDICES                           #
# Curated FortiGate indices covering all type/subtype combos             #
###########################################################################

PARSER_DEMO_INDICES = [
    # traffic/forward
    0,   # HTTPS web browsing
    2,   # DNS query
    # traffic/local
    4,   # Management denied
    5,   # Server reset
    # event/system
    9,   # Admin login success
    10,  # Admin login failure
    # event/router
    12,  # OSPF neighbor up
    # event/vpn
    14,  # IPsec phase1 up
    # utm/virus
    38,  # EICAR test file
    # utm/webfilter
    40,  # Malicious URL blocked
    # utm/dns
    42,  # DNS query pass
    # utm/app-ctrl
    43,  # Social media blocked
    # utm/ips
    45,  # Critical attack dropped
    # utm/anomaly
    47,  # SYN flood
    # utm/dlp
    49,  # DLP file type blocked
    # utm/ssh
    50,  # SSH channel blocked
    # utm/ssl
    51,  # Certificate invalid
    52,  # Untrusted certificate
]


###########################################################################
#                       TIMESTAMP REWRITING                               #
###########################################################################

def rewrite_fortinet_timestamps(line):
    """Replace date=, time=, eventtime= with current UTC time."""
    now = datetime.now(timezone.utc)
    line = RE_DATE.sub(now.strftime('date=%Y-%m-%d'), line, count=1)
    line = RE_TIME.sub(now.strftime('time=%H:%M:%S'), line, count=1)
    ns = int(now.timestamp() * 1_000_000_000)
    line = RE_EVENTTIME.sub(f'eventtime={ns}', line, count=1)
    return line


def rewrite_mimecast_timestamps(line):
    """Replace datetime value with current UTC time in JSON format."""
    now = datetime.now(timezone.utc)
    iso_ts = now.strftime('%Y-%m-%dT%H:%M:%S+0000')
    line = RE_MIMECAST_DATETIME.sub(f'"datetime":"{iso_ts}"', line, count=1)
    return line


# Map vendor -> rewrite function
REWRITE_FN = {
    "fortinet": rewrite_fortinet_timestamps,
    "mimecast": rewrite_mimecast_timestamps,
}


###########################################################################
#                       FIELD RANDOMIZATION                               #
###########################################################################

RE_SRCPORT = re.compile(r'srcport=\d+')
RE_SESSIONID = re.compile(r'sessionid=\d+')
RE_SENTBYTE = re.compile(r'sentbyte=\d+')
RE_RCVDBYTE = re.compile(r'rcvdbyte=\d+')
RE_SENTPKT = re.compile(r'sentpkt=\d+')
RE_RCVDPKT = re.compile(r'rcvdpkt=\d+')
RE_DURATION_VAL = re.compile(r'(?<=\s)duration=\d+')
RE_MC_MSGSZ = re.compile(r'"MsgSz"\s*:\s*\d+')
RE_MC_LATENCY = re.compile(r'"Latency"\s*:\s*\d+')
RE_MC_ATTSZ = re.compile(r'"AttSz"\s*:\s*\d+')
RE_MC_FILESZ = re.compile(r'"FileSz"\s*:\s*\d+')


def _vary(match, lo=0.7, hi=1.3, minimum=1):
    """Vary a key=value numeric field by ±30%."""
    text = match.group()
    eq = text.index('=')
    field = text[:eq + 1]
    val = int(text[eq + 1:])
    return f'{field}{max(minimum, int(val * random.uniform(lo, hi)))}'


def _vary_json(match, lo=0.7, hi=1.3, minimum=1):
    """Vary a JSON numeric field by ±30%."""
    text = match.group()
    parts = text.rsplit(':', 1)
    val = int(parts[1].strip())
    return f'{parts[0]}:{max(minimum, int(val * random.uniform(lo, hi)))}'


def randomize_fortinet(line):
    """Add realistic variation to FortiGate log fields."""
    line = RE_SRCPORT.sub(lambda m: f'srcport={random.randint(49152, 65535)}', line)
    line = RE_SESSIONID.sub(lambda m: f'sessionid={random.randint(10000000, 99999999)}', line)
    line = RE_SENTBYTE.sub(_vary, line)
    line = RE_RCVDBYTE.sub(_vary, line)
    line = RE_SENTPKT.sub(_vary, line)
    line = RE_RCVDPKT.sub(_vary, line)
    line = RE_DURATION_VAL.sub(lambda m: _vary(m, 0.5, 2.0), line)
    return line


def randomize_mimecast(line):
    """Add realistic variation to Mimecast log fields."""
    line = RE_MC_MSGSZ.sub(lambda m: _vary_json(m), line)
    line = RE_MC_LATENCY.sub(lambda m: _vary_json(m, 0.5, 3.0), line)
    line = RE_MC_ATTSZ.sub(lambda m: _vary_json(m), line)
    line = RE_MC_FILESZ.sub(lambda m: _vary_json(m), line)
    return line


RANDOMIZE_FN = {
    "fortinet": randomize_fortinet,
    "mimecast": randomize_mimecast,
}


###########################################################################
#          MIMECAST ECS ENRICHMENT                                        #
#  The mimecast-emailsecurity parser maps specific field names to ECS.    #
#  Our samples use abbreviated Mimecast SIEM API names (Act, Rcpt, etc.) #
#  which land in Vendor.* but don't get ECS-mapped. This function adds   #
#  the parser-expected field names so ECS fields get populated.           #
###########################################################################

def enrich_mimecast_ecs(line):
    """Add parser-expected field names for full ECS mapping."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return line

    # event.action := lower(Vendor.action)
    if 'Act' in obj and 'action' not in obj:
        obj['action'] = obj['Act']

    # email.to.address[] := lower(Vendor.recipientAddress)
    if 'Rcpt' in obj and 'recipientAddress' not in obj:
        obj['recipientAddress'] = obj['Rcpt']

    # email.from.address[] := lower(Vendor.senderEnvelope)
    if 'senderEnvelope' not in obj:
        obj['senderEnvelope'] = obj.get('Sender', obj.get('headerFrom', ''))

    # email.subject := Vendor.subject  (lowercase key)
    if 'Subject' in obj and 'subject' not in obj:
        obj['subject'] = obj['Subject']

    # email.message_id via regex on Vendor.messageId
    if 'MsgId' in obj and 'messageId' not in obj:
        obj['messageId'] = obj['MsgId']

    # email.direction := lower(Vendor.direction)
    if 'Dir' in obj and 'direction' not in obj:
        obj['direction'] = obj['Dir']

    # event.outcome for process/receipt uses Vendor.subtype
    if obj.get('type') in ('process', 'receipt') and 'Act' in obj and 'subtype' not in obj:
        obj['subtype'] = obj['Act']

    return json.dumps(obj)


###########################################################################
#                       LOG SUBTYPE EXTRACTION                            #
###########################################################################

# Regex to extract FortiGate subtype
RE_FG_SUBTYPE = re.compile(r'subtype="([^"]+)"')
RE_FG_TYPE = re.compile(r'type="([^"]+)"')

# Regex to extract Mimecast log type from "Act" field (JSON)
RE_MC_ACT = re.compile(r'"Act"\s*:\s*"([^"]+)"')
RE_MC_SUBJECT = re.compile(r'"Subject"\s*:\s*"([^"]{0,40})')


def extract_log_label(vendor, line):
    """Return a short human-readable label describing this log sample."""
    if vendor == "fortinet":
        m_type = RE_FG_TYPE.search(line)
        m_sub = RE_FG_SUBTYPE.search(line)
        parts = []
        if m_type:
            parts.append(m_type.group(1))
        if m_sub:
            parts.append(m_sub.group(1))
        return "/".join(parts) if parts else "unknown"
    elif vendor == "mimecast":
        m_act = RE_MC_ACT.search(line)
        act = m_act.group(1) if m_act else "unknown"
        m_subj = RE_MC_SUBJECT.search(line)
        subj = m_subj.group(1).strip() if m_subj else ""
        label = f"Act={act}"
        if subj:
            label += f' "{subj}"'
        return label
    return "unknown"


###########################################################################
#                         NETWORK / IO                                    #
###########################################################################

def load_csv(path, limit):
    """Load raw syslog lines from CSV (no header, one syslog per row)."""
    logs = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            if row and row[0].strip():
                logs.append(row[0].strip())
    return logs


def send_one_log(host, port, message, retries=2):
    """Send a single log on a fresh TCP connection (nc -q style) with retry."""
    ip = socket.gethostbyname(host)
    last_err = None
    for attempt in range(1 + retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((ip, port))
            sock.sendall((message + "\n").encode('utf-8'))
            time.sleep(0.3)
            sock.shutdown(socket.SHUT_WR)
            time.sleep(0.2)
            sock.close()
            return  # success
        except Exception as e:
            last_err = e
            try:
                sock.close()
            except Exception:
                pass
            if attempt < retries:
                time.sleep(1)  # brief pause before retry
    raise last_err


class ConnectionPool:
    """Persistent TCP connections keyed by port — DNS resolved once."""

    def __init__(self, host, retries=2, timeout=10):
        self._ip = socket.gethostbyname(host)
        self._host = host
        self._retries = retries
        self._timeout = timeout
        self._sockets = {}  # port -> socket

    def _connect(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((self._ip, port))
        return sock

    def send(self, port, message):
        """Send message on a persistent connection, reconnecting on failure."""
        data = (message + "\n").encode('utf-8')
        last_err = None
        for attempt in range(1 + self._retries):
            sock = self._sockets.get(port)
            if sock is None:
                try:
                    sock = self._connect(port)
                    self._sockets[port] = sock
                except Exception as e:
                    last_err = e
                    if attempt < self._retries:
                        time.sleep(0.5)
                    continue
            try:
                sock.sendall(data)
                return
            except Exception as e:
                last_err = e
                try:
                    sock.close()
                except Exception:
                    pass
                self._sockets.pop(port, None)
                if attempt < self._retries:
                    time.sleep(0.5)
        raise last_err

    def close_all(self):
        for port, sock in self._sockets.items():
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        self._sockets.clear()


###########################################################################
#                              MAIN                                       #
###########################################################################

def main():
    vendor_choices = list(VENDOR_REGISTRY.keys()) + ["all"]
    p = argparse.ArgumentParser(
        description="Portable Multi-Vendor Syslog Sender",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s                              # 10 FortiGate logs\n"
            "  %(prog)s --vendor mimecast --count 20 # 20 Mimecast logs\n"
            "  %(prog)s --vendor all --count 0        # scenario mode (attack timeline)\n"
            "  %(prog)s --config my_lab.json           # use custom config\n"
            "  %(prog)s --list-vendors                # show vendors\n"
            "  %(prog)s --export-samples              # print FortiGate parser demo samples\n"
            "  %(prog)s --init-config                 # generate config.json from env vars\n"
        ),
    )
    p.add_argument('--config', type=str, default='config.json',
                   help='Path to config.json (default: config.json in script dir)')
    p.add_argument('--host', default=None,
                   help='Syslog host (overrides config)')
    p.add_argument('--port', type=int, default=None,
                   help='Syslog port override (overrides per-vendor config port)')
    p.add_argument('--count', type=int, default=10,
                   help='Number of logs to send per vendor, 0=all samples once (default: 10)')
    p.add_argument('--csv', type=str, default=None,
                   help='CSV file with raw logs (optional, overrides built-in samples)')
    p.add_argument('--delay', type=float, default=0.1,
                   help='Delay in seconds between each log (default: 0.1)')
    p.add_argument('--vendor', type=str, default='fortinet',
                   choices=vendor_choices,
                   help='Vendor log format to send (default: fortinet)')
    p.add_argument('--list-vendors', action='store_true',
                   help='List supported vendors and exit')
    p.add_argument('--export-samples', action='store_true',
                   help='Print curated FortiGate samples for AI parser demo and exit')
    p.add_argument('--init-config', action='store_true',
                   help='Generate config.json from defaults + env vars, then exit')
    args = p.parse_args()

    # -- Load config -------------------------------------------------------
    # Try script directory first, then current directory
    config_path = args.config
    if not os.path.isfile(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, config_path)
        if os.path.isfile(alt_path):
            config_path = alt_path
        else:
            config_path = None  # will use defaults

    cfg = load_config(config_path)

    # -- Init config and exit ----------------------------------------------
    if args.init_config:
        out_path = args.config  # default: config.json
        if os.path.isfile(out_path):
            print(f"ERROR: {out_path} already exists. Delete it first or use --config <other>.")
            return 1
        with open(out_path, 'w') as f:
            json.dump(cfg, f, indent=2)
        print(f"Config written to {out_path}")
        print(f"  syslog_host: {cfg.get('syslog_host')}")
        for v, vc in cfg.get('vendors', {}).items():
            print(f"  {v} port: {vc.get('port')}")
        for role, info in cfg.get('lab', {}).get('machines', {}).items():
            print(f"  {role}: ip={info.get('ip')}  ext_ip={info.get('ext_ip', 'N/A')}")
        print("\nEdit this file to change values, or re-run with env vars + --init-config.")
        return 0

    if config_path and os.path.isfile(config_path):
        print(f"Config:  {config_path}")
    else:
        print("Config:  (none found, using defaults — create config.json for your lab)")

    host = args.host or cfg.get('syslog_host', SYSLOG_HOST)
    vendor_ports = {v: cfg.get('vendors', {}).get(v, {}).get('port', SYSLOG_PORT)
                    for v in VENDOR_REGISTRY}
    placeholders = build_placeholders(cfg)

    # -- Quick env var reminder --------------------------------------------
    print("\nTip: Override config values with env vars before running:")
    print("  export SYSLOG_HOST=\"your-tenant.in.prod.onum.com\"")
    print("  export FORTINET_PORT=2518    export MIMECAST_PORT=2519")
    print("  export LAB_DOMAIN=\"warp-duck.lab\"")
    print("  export ATTACKER_IP=x.x.x.x  export DETECT_IP=x.x.x.x")
    print("  export PROTECT_IP=x.x.x.x   export UNMANAGED_IP=x.x.x.x")
    print("  export UBUNTU_IP=x.x.x.x")
    print("  export DETECT_USER=\"warp.duck-dt\"  export DETECT_EMAIL=\"warp.duck-dt@lab.example.com\"")
    print("  export PROTECT_USER=\"warp.duck-bl\"  export PROTECT_EMAIL=\"warp.duck-bl@lab.example.com\"")
    print("  Then run: python3 portable_sender.py --init-config")
    print()

    # -- Export samples and exit -------------------------------------------
    if args.export_samples:
        samples = FORTINET_SAMPLES
        print(f"# FortiGate Parser Demo Samples — {len(PARSER_DEMO_INDICES)} logs")
        print(f"# Generated by portable_sender.py --export-samples")
        print(f"# Covers all type/subtype combinations for AI parser training")
        print()
        for idx in PARSER_DEMO_INDICES:
            if idx >= len(samples):
                continue
            raw = samples[idx]
            rewritten = apply_placeholders(raw, placeholders)
            rewritten = rewrite_fortinet_timestamps(rewritten)
            label = extract_log_label("fortinet", rewritten)
            print(f"# [{idx}] {label}")
            print(rewritten)
            print()
        return 0

    # -- List vendors and exit ---------------------------------------------
    if args.list_vendors:
        print("\nSupported vendors:\n")
        for name, info in VENDOR_REGISTRY.items():
            samples = info["samples"]
            vport = vendor_ports.get(name, SYSLOG_PORT)
            print(f"  {name:<12}  {info['description']}")
            print(f"               {len(samples)} built-in samples, port {vport}")
        print(f"\n  {'all':<12}  Send all vendors interleaved (each to its own port)")
        if placeholders:
            print(f"\nLab placeholders: {len(placeholders)} values loaded")
            for token, value in sorted(placeholders.items()):
                print(f"  {token} = {value}")
        print()
        return 0

    # -- Determine which vendors to send -----------------------------------
    if args.vendor.lower() == "all":
        vendors_to_send = list(VENDOR_REGISTRY.keys())
    else:
        vendor = args.vendor.lower()
        if vendor not in VENDOR_REGISTRY:
            print(f"ERROR: Unknown vendor '{vendor}'. Use --list-vendors.")
            return 1
        vendors_to_send = [vendor]

    # -- Build the send queue: list of (vendor, port, raw_line) tuples -----
    scenario_mode = (args.vendor.lower() == "all" and args.count == 0
                     and not args.csv)

    if scenario_mode:
        queue = build_scenario_queue(vendor_ports, args.port)
        print("  ** Scenario mode: attack timeline ordering **")
        print(f"  {len(queue)} logs (scenario sequence + remaining samples)")
    else:
        queue = []
        for v in vendors_to_send:
            info = VENDOR_REGISTRY[v]
            port = args.port if args.port is not None else vendor_ports.get(v, SYSLOG_PORT)
            builtin = info["samples"]

            if args.csv and len(vendors_to_send) == 1:
                limit = args.count if args.count > 0 else None
                lines = load_csv(args.csv, limit)
                print(f"Loaded {len(lines)} logs from {args.csv}")
            else:
                if args.count == 0:
                    lines = list(builtin)
                else:
                    lines = []
                    idx = 0
                    while len(lines) < args.count:
                        lines.append(builtin[idx % len(builtin)])
                        idx += 1
                print(f"  {v}: {len(lines)} logs ({len(builtin)} unique samples) -> port {port}")

            for line in lines:
                queue.append((v, port, line))

        # Interleave vendors when sending all (shuffle so they mix naturally)
        if len(vendors_to_send) > 1:
            random.shuffle(queue)

    if not queue:
        print("ERROR: No logs to send")
        return 1

    # -- Resolve DNS once --------------------------------------------------
    print(f"\nHost:    {host}")
    print(f"Vendors: {', '.join(vendors_to_send)}")
    print(f"Total:   {len(queue)} logs")
    print(f"Delay:   {args.delay}s")
    print()

    # -- Send using persistent connection pool -----------------------------
    pool = ConnectionPool(host)
    print(f"Resolved: {host} -> {pool._ip}")
    print()

    sent = 0
    failed = 0
    try:
        for i, (v, port, raw) in enumerate(queue):
            rewritten = apply_placeholders(raw, placeholders)
            rewritten = REWRITE_FN[v](rewritten)
            rewritten = RANDOMIZE_FN[v](rewritten)
            if v == "mimecast":
                rewritten = enrich_mimecast_ecs(rewritten)
            label = extract_log_label(v, rewritten)
            try:
                pool.send(port, rewritten)
                sent += 1
                ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
                print(f"  [{ts}] Sent {i+1}/{len(queue)} OK  "
                      f"[{v}:{port}] [{label}]  ({len(rewritten)} bytes)")
            except Exception as e:
                failed += 1
                print(f"  [{i+1}/{len(queue)}] FAILED [{v}:{port}] [{label}]: {e}")

            if args.delay > 0 and i < len(queue) - 1:
                time.sleep(args.delay)
    finally:
        pool.close_all()

    print(f"\nDone: {sent} sent, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
