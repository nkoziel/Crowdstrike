#!/usr/bin/env python3
"""
Portable Multi-Vendor Syslog Sender — No dependencies, just Python 3.
Sends realistic logs via TCP syslog to Onum with live timestamps.

Supported vendors:
  - fortinet   FortiGate syslog (all subtypes)       default port 514
  - mimecast   Mimecast pipe-delimited logs           default port 514

Each vendor has its own port config. Use --vendor all to send both
vendors simultaneously (interleaved), each to its own port.

Each log gets its timestamp fields rewritten to the exact moment it is
sent so the downstream parser accepts them.

Usage:
    python3 portable_sender.py                          # 10 FortiGate logs
    python3 portable_sender.py --vendor mimecast        # 10 Mimecast logs
    python3 portable_sender.py --vendor all             # Both vendors
    python3 portable_sender.py --count 50               # Send 50 logs
    python3 portable_sender.py --csv path.csv           # Use custom CSV
    python3 portable_sender.py --delay 1.0              # 1s between logs
    python3 portable_sender.py --list-vendors           # Show vendors
"""
import socket
import csv
import re
import sys
import time
import argparse
import random
from datetime import datetime, timezone

# -- Configuration ---------------------------------------------------------
SYSLOG_HOST = "your-tenant.in.prod.onum.com"
SYSLOG_PORT = 514
# --------------------------------------------------------------------------

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

    # user: RADIUS auth success
    '<45>date=2024-12-16 time=17:58:30 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371910000000000 tz="+0000" logid="0102043008" type="event" subtype="user" level="notice" vd="root" logdesc="Authentication success" srcip=192.168.1.150 user="jsmith" server="RADIUS-01" group="VPN-Users" authproto="RADIUS" action="authentication" status="success" msg="User jsmith authenticated successfully via RADIUS"',

    # user: LDAP auth failure
    '<45>date=2024-12-16 time=17:59:00 devname="FortiGate-100F" devid="FG100FTEST00002" eventtime=1734371940000000000 tz="+0000" logid="0102043009" type="event" subtype="user" level="warning" vd="root" logdesc="Authentication failure" srcip=192.168.1.175 user="bwilliams" server="LDAP-DC01" group="N/A" authproto="LDAP" action="authentication" status="failure" reason="credential_or_server_error" msg="User bwilliams failed LDAP authentication"',

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

    # endpoint: FortiClient connection add
    '<45>date=2024-12-16 time=18:03:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372210000000000 tz="+0000" logid="0111044900" type="event" subtype="endpoint" level="notice" vd="root" logdesc="FortiClient endpoint connected" msg="FortiClient endpoint DESKTOP-ABC123 connected, user jdoe, IP 192.168.5.22, FCT version 7.2.3" action="connection-add" srcip=192.168.5.22 user="jdoe" hostname="DESKTOP-ABC123" fctver="7.2.3" os="Windows 11" compliance="compliant"',

    # endpoint: FortiClient connection close
    '<45>date=2024-12-16 time=18:04:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734372240000000000 tz="+0000" logid="0111044901" type="event" subtype="endpoint" level="notice" vd="root" logdesc="FortiClient endpoint disconnected" msg="FortiClient endpoint LAPTOP-XYZ789 disconnected, user mking, IP 192.168.5.45, reason timeout" action="connection-close" srcip=192.168.5.45 user="mking" hostname="LAPTOP-XYZ789" reason="timeout"',

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
    # Kali 10.3.108.21 | Ubuntu 10.3.108.40 | Unmanaged 10.3.108.27
    # Protect 10.3.108.30 | Detect 10.3.108.31
    # =====================================================================

    # Lab: Protect machine normal HTTPS browsing
    '<45>date=2024-12-16 time=18:21:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373260000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.3.108.30 srcport=55100 srcintf="port5" srcintfrole="lan" dstip=142.250.80.46 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200100 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip=54.245.154.50 transport=55100 app="Google.Services" appcat="web.client" duration=45 sentbyte=8200 rcvdbyte=125000 sentpkt=35 rcvdpkt=95 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:30" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Ubuntu machine apt update
    '<45>date=2024-12-16 time=18:22:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373320000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.3.108.40 srcport=43500 srcintf="port5" srcintfrole="lan" dstip=91.189.91.49 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United Kingdom" sessionid=40200200 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip=52.36.101.231 transport=43500 app="Ubuntu.Update" appcat="network.service" duration=15 sentbyte=2400 rcvdbyte=450000 sentpkt=12 rcvdpkt=320 osname="Linux" srcswversion="Ubuntu 22.04" mastersrcmac="aa:bb:cc:00:01:40" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Detect machine normal Office365 traffic
    '<45>date=2024-12-16 time=18:22:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373350000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.3.108.31 srcport=51200 srcintf="port5" srcintfrole="lan" dstip=52.96.166.130 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200300 proto=6 action="close" policyid=3 policytype="policy" service="HTTPS" trandisp="snat" transip=18.236.136.74 transport=51200 app="Microsoft.Office.365" appcat="web.client" duration=180 sentbyte=32000 rcvdbyte=890000 sentpkt=120 rcvdpkt=650 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',

    # Lab: Unmanaged machine SSH to external (suspicious)
    '<45>date=2024-12-16 time=18:23:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373380000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=10.3.108.27 srcport=61400 srcintf="port5" srcintfrole="lan" dstip=45.33.32.156 dstport=22 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=40200400 proto=6 action="accept" policyid=5 policytype="policy" service="SSH" trandisp="snat" transip=34.220.166.46 transport=61400 app="SSH" appcat="network.service" duration=300 sentbyte=45000 rcvdbyte=28000 sentpkt=200 rcvdpkt=180 osname="Windows" srcswversion="Windows 10" mastersrcmac="aa:bb:cc:00:01:27" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # Lab: Kali -> Detect internal port scan (IPS)
    '<45>date=2024-12-16 time=18:24:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373440000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.3.108.21 srcport=0 srcintf="port5" srcintfrole="lan" dstip=10.3.108.31 dstport=0 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=0 proto=6 action="dropped" policyid=10 service="tcp" attack="Portscan.Detection" severity="medium" attackid=18432 msg="anomaly: port scan detected from internal host"',

    # Lab: Kali -> Unmanaged lateral movement attempt (SMB)
    '<45>date=2024-12-16 time=18:24:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373470000000000 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.3.108.21 srcport=44500 srcintf="port5" srcintfrole="lan" dstip=10.3.108.27 dstport=445 dstintf="port5" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=40300100 proto=6 action="dropped" policyid=10 service="SMB" attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" severity="critical" attackid=42888 msg="IPS signature matched: SMB exploitation attempt"',

    # =====================================================================
    # DETECTION TRIGGER: Generic - Web - Suspicious HTTP GET Requests
    # Post-compromise recon from Detect machine (10.3.108.31)
    # Correlated with Mimecast phishing email to emily.jones@warp-duck.lab
    # =====================================================================

    # TRIGGER: GET /proc/self/environ on C2 server
    '<45>date=2024-12-16 time=18:25:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373500000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" srcip=10.3.108.31 srcport=52100 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400100 proto=6 action="passthrough" policyid=5 service="HTTP" hostname="c2-callback.example.com" url="/proc/self/environ" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # TRIGGER: GET /etc/passwd
    '<45>date=2024-12-16 time=18:25:05 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373505000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" srcip=10.3.108.31 srcport=52102 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400102 proto=6 action="passthrough" policyid=5 service="HTTP" hostname="c2-callback.example.com" url="/etc/passwd" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # TRIGGER: GET /etc/group
    '<45>date=2024-12-16 time=18:25:10 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373510000000000 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="warning" vd="root" srcip=10.3.108.31 srcport=52104 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=80 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400104 proto=6 action="passthrough" policyid=5 service="HTTP" hostname="c2-callback.example.com" url="/etc/security/passwd" reqtype="direct" cat=26 catdesc="Malicious Websites" msg="URL belongs to a permitted category in policy"',

    # Post-compromise: C2 callback from Detect to external attacker
    '<45>date=2024-12-16 time=18:25:30 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373530000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.3.108.31 srcport=49200 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=4443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400200 proto=6 action="accept" policyid=5 policytype="policy" service="tcp/4443" trandisp="snat" transip=18.236.136.74 transport=49200 app="SSL" appcat="network.service" duration=120 sentbyte=15000 rcvdbyte=85000 sentpkt=45 rcvdpkt=120 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session accepted"',

    # Post-compromise: Data exfiltration (large upload to external)
    '<45>date=2024-12-16 time=18:26:00 devname="FortiGate-200F" devid="FG200FTEST00003" eventtime=1734373560000000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.3.108.31 srcport=49250 srcintf="port5" srcintfrole="lan" dstip=185.220.101.45 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Russia" sessionid=40400300 proto=6 action="close" policyid=5 policytype="policy" service="HTTPS" trandisp="snat" transip=18.236.136.74 transport=49250 app="SSL" appcat="network.service" duration=60 sentbyte=5200000 rcvdbyte=4500 sentpkt=3800 rcvdpkt=45 osname="Windows" srcswversion="Windows 11" mastersrcmac="aa:bb:cc:00:01:31" masterdstmac="11:22:33:44:55:01" msg="Session closed"',
]


###########################################################################
#                       MIMECAST BUILTIN SAMPLES                          #
###########################################################################

MIMECAST_SAMPLES = [

    # =====================================================================
    # Receipt logs - message accepted / rejected
    # =====================================================================

    # Receipt: Message accepted with TLS, SPF pass, DKIM pass
    '{"datetime":"2024-12-16T17:50:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<msg001@sender.example.com>","Subject":"Quarterly Report Q4","headerFrom":"finance@sender.example.com","Sender":"finance@sender.example.com","senderEnvelope":"finance@sender.example.com","Rcpt":"john.doe@recipient.example.com","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":1,"SpamInfo":"virus score=clean","SpfResult":"pass","DkimResult":"pass","IP":"198.51.100.25","Dir":"Inbound","MsgSz":45200,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Receipt: Message rejected - spam
    '{"datetime":"2024-12-16T17:51:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<spam001@spammer.example.net>","Subject":"YOU HAVE WON $10000000","headerFrom":"prize@spammer.example.net","Sender":"prize@spammer.example.net","senderEnvelope":"bounce@spammer.example.net","Rcpt":"jane.smith@recipient.example.com","Act":"Rej","TlsVer":"TLSv1.2","Cphr":"ECDHE-RSA-AES256-GCM-SHA384","SpamScore":98,"SpamInfo":"virus score=dirty, spam score=98, phish score=high","SpfResult":"fail","DkimResult":"fail","IP":"203.0.113.77","Dir":"Inbound","MsgSz":12400,"RejType":"spam","RejCode":"550","RejInfo":"Message rejected due to spam content"}',

    # Receipt: Outbound message accepted
    '{"datetime":"2024-12-16T17:52:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<out001@company.example.com>","Subject":"Re: Project Update","headerFrom":"alice.wong@company.example.com","Sender":"alice.wong@company.example.com","senderEnvelope":"alice.wong@company.example.com","Rcpt":"partner@external.example.com","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_128_GCM_SHA256","SpamScore":0,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"10.0.0.50","Dir":"Outbound","MsgSz":8500,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # =====================================================================
    # Process logs - with/without attachments, held for review
    # =====================================================================

    # Process: With attachment
    '{"datetime":"2024-12-16T17:53:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<proc001@sender.example.com>","Subject":"Invoice #INV-2024-0891","headerFrom":"billing@sender.example.com","Sender":"billing@sender.example.com","Rcpt":"accounts@recipient.example.com","Act":"Prc","AttNames":"invoice_2024_0891.pdf","AttCnt":1,"AttSz":125000,"Route":"inbound","Hld":"N","HldRsn":"N/A"}',

    # Process: Without attachment
    '{"datetime":"2024-12-16T17:54:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<proc002@company.example.com>","Subject":"Meeting Tomorrow at 3pm","headerFrom":"bob.chen@company.example.com","Sender":"bob.chen@company.example.com","Rcpt":"team@company.example.com","Act":"Prc","AttNames":"N/A","AttCnt":0,"AttSz":0,"Route":"internal","Hld":"N","HldRsn":"N/A"}',

    # Process: Held for review (spam)
    '{"datetime":"2024-12-16T17:55:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<proc003@marketing.example.net>","Subject":"Limited Time Offer - Act Now!!!","headerFrom":"deals@marketing.example.net","Sender":"deals@marketing.example.net","Rcpt":"info@recipient.example.com","Act":"Hld","AttNames":"offer_brochure.pdf","AttCnt":1,"AttSz":310000,"Route":"inbound","Hld":"Y","HldRsn":"Suspected spam content detected - held for admin review"}',

    # =====================================================================
    # Delivery logs - successful / failed
    # =====================================================================

    # Delivery: Successful
    '{"datetime":"2024-12-16T17:56:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<del001@sender.example.com>","Subject":"Weekly Status Report","headerFrom":"manager@sender.example.com","Sender":"manager@sender.example.com","Rcpt":"team-lead@recipient.example.com","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.recipient.example.com","TlsVer":"TLSv1.3","Latency":1200,"Attempt":1,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Delivery: Failed - timeout
    '{"datetime":"2024-12-16T17:57:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<del002@company.example.com>","Subject":"Contract Renewal","headerFrom":"legal@company.example.com","Sender":"legal@company.example.com","Rcpt":"partner@unreachable.example.com","Act":"Rej","Dlv":"Failed","DlvTo":"mx01.unreachable.example.com","TlsVer":"N/A","Latency":30000,"Attempt":3,"RejType":"connection_timeout","RejCode":"451","RejInfo":"Connection timed out after 30s on attempt 3"}',

    # Delivery: Failed - rejected by remote
    '{"datetime":"2024-12-16T17:58:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<del003@sender.example.com>","Subject":"Follow Up","headerFrom":"sales@sender.example.com","Sender":"sales@sender.example.com","Rcpt":"nouser@strict-mx.example.com","Act":"Rej","Dlv":"Failed","DlvTo":"mx02.strict-mx.example.com","TlsVer":"TLSv1.2","Latency":800,"Attempt":1,"RejType":"remote_reject","RejCode":"550","RejInfo":"550 5.1.1 The email account that you tried to reach does not exist"}',

    # =====================================================================
    # AV logs - virus detected
    # =====================================================================

    # AV: Macro malware detected
    '{"datetime":"2024-12-16T17:59:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<av001@infected.example.net>","Subject":"Urgent - Review Document","headerFrom":"hr@infected.example.net","Sender":"hr@infected.example.net","Rcpt":"employee@recipient.example.com","Act":"Hld","FileName":"employee_review_2024.xlsm","FileExt":"xlsm","FileSz":89000,"Virus":"W97M/Downloader.AKQ","ScanResult":"malicious","Route":"inbound","msg":"Macro malware detected in Excel attachment"}',

    # AV: Phishing attachment
    '{"datetime":"2024-12-16T18:00:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<av002@phishing.example.net>","Subject":"Your Package Delivery Notification","headerFrom":"support@delivery.example.net","Sender":"noreply@delivery.example.net","Rcpt":"victim@recipient.example.com","Act":"Rej","FileName":"tracking_details.html","FileExt":"html","FileSz":4500,"Virus":"HTML/Phishing.Agent.B","ScanResult":"malicious","Route":"inbound","msg":"Phishing content detected in HTML attachment"}',

    # =====================================================================
    # Spam Event Thread logs
    # =====================================================================

    # Spam: Spam detected and quarantined
    '{"datetime":"2024-12-16T18:01:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<spam002@bulk.example.net>","Subject":"Buy Cheap Pharmaceuticals Online","headerFrom":"offers@bulk.example.net","Sender":"offers@bulk.example.net","Rcpt":"admin@recipient.example.com","Act":"Hld","SpamScore":95,"SpamInfo":"spam score=95, bulk sender, suspicious URL","ScanResult":"spam","Route":"inbound","msg":"Spam detected and quarantined"}',

    # =====================================================================
    # TTP Internal Email Protect
    # =====================================================================

    # TTP Internal: Blocked URL in internal email
    '{"datetime":"2024-12-16T18:02:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<ttp-int001@company.example.com>","Subject":"Check this out","headerFrom":"compromised.user@company.example.com","Sender":"compromised.user@company.example.com","Rcpt":"coworker@company.example.com","Act":"Hld","URL":"https://evil-phish.example.net/steal-creds","URLCategory":"phishing","ScanResult":"malicious","Route":"internal","msg":"Blocked malicious URL in internal email - possible account compromise"}',

    # =====================================================================
    # TTP Impersonation Protect
    # =====================================================================

    # TTP Impersonation: Internal name impersonation
    '{"datetime":"2024-12-16T18:03:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<imp001@lookalike.example.net>","Subject":"Urgent Wire Transfer Needed","headerFrom":"ceo.name@lookalike.example.net","Sender":"ceo.name@lookalike.example.net","Rcpt":"cfo@recipient.example.com","Act":"Hld","ImpersonationResult":"internal_name_match","ImpersonatedUser":"CEO Name","Confidence":"high","ScanResult":"impersonation","Route":"inbound","msg":"Internal display name impersonation detected - matches CEO identity"}',

    # TTP Impersonation: New external domain
    '{"datetime":"2024-12-16T18:04:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<imp002@new-vendor.example.org>","Subject":"Updated Bank Details for Payment","headerFrom":"accounts@new-vendor.example.org","Sender":"accounts@new-vendor.example.org","Rcpt":"payables@recipient.example.com","Act":"Hld","ImpersonationResult":"new_domain","ImpersonatedUser":"N/A","Confidence":"medium","ScanResult":"suspicious","Route":"inbound","msg":"Newly registered domain detected requesting payment changes"}',

    # =====================================================================
    # TTP URL Protect
    # =====================================================================

    # TTP URL: Malicious URL clicked
    '{"datetime":"2024-12-16T18:05:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<url001@sender.example.com>","Subject":"Reset Your Password","headerFrom":"it-support@sender.example.com","Sender":"it-support@sender.example.com","Rcpt":"user@recipient.example.com","Act":"Blk","URL":"https://credential-harvest.example.net/login","URLCategory":"credential_phishing","UserAction":"clicked","ScanResult":"malicious","UserAwareness":"warned","Route":"inbound","msg":"User clicked malicious URL - access blocked at click time"}',

    # =====================================================================
    # TTP Attachment Protect
    # =====================================================================

    # TTP Attachment: Malicious attachment detected
    '{"datetime":"2024-12-16T18:06:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<att001@compromised.example.net>","Subject":"Signed Contract Attached","headerFrom":"legal@compromised.example.net","Sender":"legal@compromised.example.net","Rcpt":"contracts@recipient.example.com","Act":"Hld","FileName":"signed_contract.docx","FileExt":"docx","FileSz":67000,"SandboxResult":"malicious","SandboxDetail":"Document contains obfuscated PowerShell dropper","Confidence":"high","Route":"inbound","msg":"Attachment sandbox analysis detected malicious payload"}',

    # TTP Attachment: Suspicious archive
    '{"datetime":"2024-12-16T18:07:00+0000","aCode":"acc1002","acc":"C0A1","MsgId":"<att002@external.example.net>","Subject":"Requested Files","headerFrom":"vendor@external.example.net","Sender":"vendor@external.example.net","Rcpt":"procurement@recipient.example.com","Act":"Hld","FileName":"requested_files.zip","FileExt":"zip","FileSz":2100000,"SandboxResult":"suspicious","SandboxDetail":"Archive contains password-protected executable","Confidence":"medium","Route":"inbound","msg":"Suspicious archive attachment held for review"}',

    # =====================================================================
    # LAB ENVIRONMENT TRAFFIC (warp-duck.lab)
    # Correlated with FortiGate attack scenario on Detect 10.3.108.31
    # =====================================================================

    # Legitimate: Internal IT notification
    '{"datetime":"2024-12-16T18:10:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<it-notice-001@warp-duck.lab>","Subject":"Scheduled Maintenance Window - Saturday 2am","headerFrom":"it-ops@warp-duck.lab","Sender":"it-ops@warp-duck.lab","Rcpt":"all-staff@warp-duck.lab","Act":"Acc","AttNames":"N/A","AttCnt":0,"AttSz":0,"Route":"internal","Dir":"Internal","Hld":"N","HldRsn":"N/A","MsgSz":3200}',

    # Legitimate: External partner email
    '{"datetime":"2024-12-16T18:11:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<partner-001@acme-corp.com>","Subject":"Re: Joint Project Timeline","headerFrom":"pm@acme-corp.com","Sender":"pm@acme-corp.com","Rcpt":"emily.jones@warp-duck.lab","Act":"Acc","TlsVer":"TLSv1.3","Cphr":"TLS_AES_256_GCM_SHA384","SpamScore":0,"SpamInfo":"clean","SpfResult":"pass","DkimResult":"pass","IP":"203.0.113.50","Dir":"Inbound","MsgSz":15600,"RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # Legitimate: Outbound from lab user
    '{"datetime":"2024-12-16T18:12:00+0000","aCode":"acc1001","acc":"C0A0","MsgId":"<outbound-001@warp-duck.lab>","Subject":"Updated Network Diagram","headerFrom":"admin@warp-duck.lab","Sender":"admin@warp-duck.lab","Rcpt":"vendor-support@external.example.com","Act":"Acc","AttNames":"network_diagram_v2.pdf","AttCnt":1,"AttSz":2400000,"Route":"outbound","Dir":"Outbound","Hld":"N","HldRsn":"N/A","MsgSz":2450000}',

    # =====================================================================
    # DETECTION TRIGGER: Mimecast Suspicious Attachment Type Detected
    # Phishing email with .xlsm macro-enabled attachment to Detect user
    # Correlated with FortiGate suspicious HTTP GETs from 10.3.108.31
    # =====================================================================

    # TRIGGER (process): Phishing with .xlsm accepted — attacker -> emily.jones
    '{"datetime":"2024-12-16T18:15:00+0000","aCode":"acc1001","acc":"C0A0","processingId":"proc-2024-atk-00891","MsgId":"<atk001@securecorp-benefits.com>","Subject":"Q4 Benefits Update - Action Required","headerFrom":"hr-admin@securecorp-benefits.com","Sender":"hr-admin@securecorp-benefits.com","Rcpt":"emily.jones@warp-duck.lab","Act":"Acc","AttNames":"Q4_Benefits_Update.xlsm","AttCnt":1,"AttSz":185000,"numberAttachments":1,"Route":"inbound","Dir":"Inbound","Hld":"N","HldRsn":"N/A","SpamScore":12,"SpfResult":"pass","DkimResult":"pass","IP":"198.51.100.77","MsgSz":195000}',

    # TRIGGER (delivery): Same phishing email delivered successfully
    '{"datetime":"2024-12-16T18:15:02+0000","aCode":"acc1001","acc":"C0A0","processingId":"proc-2024-atk-00891","MsgId":"<atk001@securecorp-benefits.com>","Subject":"Q4 Benefits Update - Action Required","headerFrom":"hr-admin@securecorp-benefits.com","Sender":"hr-admin@securecorp-benefits.com","Rcpt":"emily.jones@warp-duck.lab","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.warp-duck.lab","TlsVer":"TLSv1.3","Latency":850,"Attempt":1,"Dir":"Inbound","delivered":"true","RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',

    # TRIGGER (process): Second phishing with .html credential harvester
    '{"datetime":"2024-12-16T18:16:00+0000","aCode":"acc1001","acc":"C0A0","processingId":"proc-2024-atk-00892","MsgId":"<atk002@it-helpdesk-portal.com>","Subject":"Password Expiry Notice - Immediate Action","headerFrom":"noreply@it-helpdesk-portal.com","Sender":"noreply@it-helpdesk-portal.com","Rcpt":"admin@warp-duck.lab","Act":"Acc","AttNames":"password_reset_form.html","AttCnt":1,"AttSz":8200,"numberAttachments":1,"Route":"inbound","Dir":"Inbound","Hld":"N","HldRsn":"N/A","SpamScore":25,"SpfResult":"neutral","DkimResult":"pass","IP":"104.20.145.30","MsgSz":12800}',

    # TRIGGER (delivery): Second phishing delivered
    '{"datetime":"2024-12-16T18:16:03+0000","aCode":"acc1001","acc":"C0A0","processingId":"proc-2024-atk-00892","MsgId":"<atk002@it-helpdesk-portal.com>","Subject":"Password Expiry Notice - Immediate Action","headerFrom":"noreply@it-helpdesk-portal.com","Sender":"noreply@it-helpdesk-portal.com","Rcpt":"admin@warp-duck.lab","Act":"Acc","Dlv":"Delivered","DlvTo":"mx01.warp-duck.lab","TlsVer":"TLSv1.3","Latency":720,"Attempt":1,"Dir":"Inbound","delivered":"true","RejType":"N/A","RejCode":"N/A","RejInfo":"N/A"}',
]


###########################################################################
#                        VENDOR REGISTRY                                  #
###########################################################################

VENDOR_REGISTRY = {
    "fortinet": {
        "description": "FortiGate syslog (traffic, event, UTM/security)",
        "samples": FORTINET_SAMPLES,
        "port": SYSLOG_PORT,
    },
    "mimecast": {
        "description": "Mimecast email security logs (pipe-delimited)",
        "samples": MIMECAST_SAMPLES,
        "port": SYSLOG_PORT,
    },
}


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
            "  %(prog)s --vendor all --count 0        # all samples, both vendors\n"
            "  %(prog)s --list-vendors                # show vendors\n"
        ),
    )
    p.add_argument('--host', default=SYSLOG_HOST,
                   help=f'Syslog host (default: {SYSLOG_HOST})')
    p.add_argument('--port', type=int, default=None,
                   help='Syslog port override (default: per-vendor port)')
    p.add_argument('--count', type=int, default=10,
                   help='Number of logs to send per vendor, 0=all samples once (default: 10)')
    p.add_argument('--csv', type=str, default=None,
                   help='CSV file with raw logs (optional, overrides built-in samples)')
    p.add_argument('--delay', type=float, default=0.5,
                   help='Delay in seconds between each log (default: 0.5)')
    p.add_argument('--vendor', type=str, default='fortinet',
                   choices=vendor_choices,
                   help='Vendor log format to send (default: fortinet)')
    p.add_argument('--list-vendors', action='store_true',
                   help='List supported vendors and exit')
    args = p.parse_args()

    # -- List vendors and exit ---------------------------------------------
    if args.list_vendors:
        print("Supported vendors:\n")
        for name, info in VENDOR_REGISTRY.items():
            samples = info["samples"]
            print(f"  {name:<12}  {info['description']}")
            print(f"               {len(samples)} built-in samples, default port {info['port']}")
        print(f"\n  {'all':<12}  Send all vendors interleaved (each to its own port)")
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
    queue = []
    for v in vendors_to_send:
        info = VENDOR_REGISTRY[v]
        port = args.port if args.port is not None else info["port"]
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

    if not queue:
        print("ERROR: No logs to send")
        return 1

    # Interleave vendors when sending all (shuffle so they mix naturally)
    if len(vendors_to_send) > 1:
        random.shuffle(queue)

    # -- Resolve DNS once --------------------------------------------------
    ip = socket.gethostbyname(args.host)
    print(f"\nHost:    {args.host} ({ip})")
    print(f"Vendors: {', '.join(vendors_to_send)}")
    print(f"Total:   {len(queue)} logs")
    print(f"Delay:   {args.delay}s")
    print()

    # -- Send each log on its own connection (like nc -q) ------------------
    sent = 0
    failed = 0
    for i, (v, port, raw) in enumerate(queue):
        rewritten = REWRITE_FN[v](raw)
        rewritten = RANDOMIZE_FN[v](rewritten)
        label = extract_log_label(v, rewritten)
        try:
            send_one_log(args.host, port, rewritten)
            sent += 1
            ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
            print(f"  [{ts}] Sent {i+1}/{len(queue)} OK  "
                  f"[{v}:{port}] [{label}]  ({len(rewritten)} bytes)")
        except Exception as e:
            failed += 1
            print(f"  [{i+1}/{len(queue)}] FAILED [{v}:{port}] [{label}]: {e}")

        if args.delay > 0 and i < len(queue) - 1:
            time.sleep(args.delay)

    print(f"\nDone: {sent} sent, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
