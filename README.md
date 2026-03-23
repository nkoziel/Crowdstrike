# Portable Syslog Log Generator

Zero-dependency Python 3 tool that sends realistic, multi-vendor syslog logs to CrowdStrike NGSIEM via Onum. Built for demos, detection testing, and parser validation.

## Quick Start

```bash
# Download
curl -O https://raw.githubusercontent.com/nkoziel/Crowdstrike/main/portable_sender.py
curl -O https://raw.githubusercontent.com/nkoziel/Crowdstrike/main/config.example.json

# Configure
cp config.example.json config.json
nano config.json   # Edit with your Onum host, ports, and lab IPs

# Send logs
python3 portable_sender.py --vendor all --count 0
```

## Requirements

- Python 3.6+ (stdlib only, no pip install needed)
- TCP connectivity to your Onum syslog listener
- A `config.json` file with your environment details

## Configuration

Copy `config.example.json` to `config.json` and fill in your values:

```json
{
    "syslog_host": "your-tenant-id.in.prod.onum.com",
    "vendors": {
        "fortinet": {"port": 2518},
        "mimecast": {"port": 2519}
    },
    "lab": {
        "domain": "yourlab.local",
        "machines": {
            "attacker":  {"ip": "10.0.0.21",  "ext_ip": "203.0.113.21"},
            "ubuntu":    {"ip": "10.0.0.40",  "ext_ip": "203.0.113.40"},
            "unmanaged": {"ip": "10.0.0.27",  "ext_ip": "203.0.113.27"},
            "protect":   {"ip": "10.0.0.30",  "ext_ip": "203.0.113.30"},
            "detect":    {"ip": "10.0.0.31",  "ext_ip": "203.0.113.31"}
        }
    }
}
```

| Field | Description |
|-------|-------------|
| `syslog_host` | Your Onum syslog listener hostname |
| `vendors.fortinet.port` | TCP port for FortiGate logs |
| `vendors.mimecast.port` | TCP port for Mimecast logs |
| `lab.domain` | Your lab domain (used in email addresses) |
| `lab.machines.*` | Lab machine IPs injected into log samples via `{{PLACEHOLDER}}` tokens |

The script auto-loads `config.json` from the same directory. Use `--config path/to/other.json` to specify a different file. Without a config file, generic placeholder IPs are used.

## Usage

```bash
# List vendors, sample counts, and verify config
python3 portable_sender.py --list-vendors

# Send all 92 unique samples (67 FortiGate + 25 Mimecast)
python3 portable_sender.py --vendor all --count 0

# Send 50 FortiGate logs (cycles through samples)
python3 portable_sender.py --vendor fortinet --count 50

# Send 20 Mimecast logs with 1s delay
python3 portable_sender.py --vendor mimecast --count 20 --delay 1.0

# Send from a CSV file of raw syslog lines
python3 portable_sender.py --vendor fortinet --csv /path/to/export.csv --count 0

# Override host/port via CLI (ignores config)
python3 portable_sender.py --host my-host.example.com --port 2518
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--vendor` | `fortinet` | `fortinet`, `mimecast`, or `all` |
| `--count` | `10` | Number of logs per vendor. `0` = all unique samples once |
| `--delay` | `0.5` | Seconds between each log |
| `--config` | `config.json` | Path to config file |
| `--host` | from config | Syslog host override |
| `--port` | from config | Port override (all vendors) |
| `--csv` | none | CSV file with raw syslog lines (single vendor only) |
| `--list-vendors` | — | Show vendors, sample counts, config values |

## How It Works

1. **Loads config** from `config.json` (host, ports, lab IPs)
2. **Selects samples** from built-in templates (or CSV file)
3. **Applies placeholders** — replaces `{{DETECT_IP}}`, `{{LAB_DOMAIN}}`, etc. with config values
4. **Rewrites timestamps** — every log gets current UTC time at send-time:
   - FortiGate: `date=`, `time=`, `eventtime=` (nanoseconds)
   - Mimecast: `"datetime":` (ISO 8601)
5. **Randomizes fields** — source ports, session IDs, byte counts vary ±30% each run
6. **Sends via TCP** — one connection per log (`nc -q 2` style) with 2 retries on timeout

## Sample Coverage

### FortiGate — 67 samples across 27 subtypes

| Category | Subtypes | Count |
|----------|----------|-------|
| **Traffic** | forward, local, multicast, sniffer | 15 |
| **Event** | system, router, vpn, user, ha, wireless, sdwan, connector, endpoint, security-rating, wad, rest-api, switch-controller, fortiextender | 27 |
| **UTM/Security** | virus, webfilter, dns, app-ctrl, ips, anomaly, dlp, ssh, ssl | 25 |

Parsed by NGSIEM parser `fortinet-fortigate` (v5.1.2+) into 80+ ECS fields.

### Mimecast — 25 samples (JSON format)

| Category | Count |
|----------|-------|
| Receipt (accept/reject, SPF/DKIM) | 4 |
| Process (attachments, held) | 4 |
| Delivery (success/fail) | 5 |
| AV / Sandbox | 4 |
| Spam | 1 |
| TTP URL Protect | 2 |
| TTP Impersonation | 2 |
| TTP Attachment / Internal | 3 |

Parsed by NGSIEM parser `mimecast-emailsecurity`.

## Built-in Attack Scenario

The samples include a **correlated phishing-to-compromise attack story** that spans both vendors. This is designed to demonstrate cross-vendor investigation in NGSIEM.

### Attack Timeline

```
T+0   [Mimecast]  Phishing email from hr-admin@securecorp-benefits.com
                   → emily.jones@{{LAB_DOMAIN}}
                   Attachment: Q4_Benefits_Update.xlsm (macro-enabled)
                   Status: Accepted + Delivered (bypassed filters)

T+1   [Mimecast]  Second phishing from noreply@it-helpdesk-portal.com
                   → admin@{{LAB_DOMAIN}}
                   Attachment: password_reset_form.html (credential harvester)
                   Status: Accepted + Delivered

T+2   [FortiGate] Detect machine ({{DETECT_IP}}) sends HTTP GET requests:
                   → /proc/self/environ
                   → /etc/passwd
                   → /etc/security/passwd
                   Target: c2-callback.example.com (185.220.101.45)

T+3   [FortiGate] C2 callback from {{DETECT_IP}} to 185.220.101.45:4443

T+4   [FortiGate] Data exfiltration: 5.2MB upload from {{DETECT_IP}}
                   to 185.220.101.45:443
```

### Additional Lab Traffic

The samples also include realistic background noise from lab machines:

- **Protect machine** → Google/O365 browsing
- **Ubuntu machine** → apt updates
- **Detect machine** → normal Office365 traffic (before compromise)
- **Unmanaged machine** → suspicious external SSH
- **Kali (attacker)** → port scan + SMB exploitation attempts against internal hosts

## NGSIEM Detection Rules to Activate

The following built-in CrowdStrike NGSIEM detection rules will trigger on the attack scenario logs. Enable them before sending logs.

### 1. Generic - Web - Suspicious HTTP GET Requests

**Triggered by:** FortiGate webfilter logs from `{{DETECT_IP}}` requesting `/proc/self/environ`, `/etc/passwd`, `/etc/security/passwd`.

- **Severity:** Medium
- **MITRE:** Discovery (File and Directory Discovery), Initial Access (Exploit Public-Facing Application)
- **Where to find:** NGSIEM → Detection Rules → search "Suspicious HTTP GET"
- **Key query logic:**
  ```
  http.request.method="GET"
  url.original=/(?:%2f|\/)proc(?:%2f|\/)self(?:%2f|\/)environ/i
  url.original=/(?:%2f|\/)etc(?:%2f|\/)passwd/i
  ```

### 2. Mimecast - Email Security - Suspicious Attachment Type Detected

**Triggered by:** Mimecast process + delivery logs with `.xlsm` and `.html` attachments accepted and delivered inbound.

- **Severity:** Medium
- **MITRE:** Initial Access (Spearphishing Attachment)
- **Where to find:** NGSIEM → Detection Rules → search "Suspicious Attachment Type"
- **Key query logic:**
  ```
  #Vendor="mimecast" #event.dataset="emailsecurity.process"
  event.action=/acc/i
  Vendor.attachments=/\.xlsm/i   (or .html, .exe, .bat, .ps1, .lnk, etc.)
  ```
- **Note:** This rule joins `emailsecurity.process` and `emailsecurity.delivery` events on `Vendor.processingId`. Both logs share `processingId: "proc-2024-atk-00891"`.

### 3. Recommended Additional Rules

These built-in rules may also trigger depending on your NGSIEM configuration:

| Rule | Triggered By |
|------|-------------|
| IPS/IDS Alert — Critical Severity | FortiGate IPS: SMB exploitation from Kali → Unmanaged |
| Port Scan Detected | FortiGate IPS: port scan from Kali → Detect |
| Anomalous Data Transfer | FortiGate: 5.2MB upload from Detect to external IP |
| Mimecast — Impersonation Detected | CEO name impersonation sample |
| Mimecast — Phishing URL Blocked | TTP URL protect: credential harvesting URL clicked |

## Investigation Workflow (Demo)

After sending logs with `--vendor all --count 0`, walk through this investigation:

1. **Start with Mimecast alert** — "Suspicious Attachment Type Detected"
   - Pivot on recipient: `emily.jones@{{LAB_DOMAIN}}`
   - Note the `.xlsm` attachment and external sender domain

2. **Search FortiGate logs for the victim's IP** — `{{DETECT_IP}}`
   - Timeline shows normal O365 traffic, then suspicious HTTP GETs
   - Pivot on destination IP `185.220.101.45`

3. **Find the full attack chain:**
   - Recon: GET `/proc/self/environ`, `/etc/passwd`
   - C2 callback on port 4443
   - Data exfiltration: 5.2MB upload

4. **Check lateral movement** — search for Kali `{{ATTACKER_IP}}`
   - Port scan against Detect
   - SMB exploitation attempt against Unmanaged

5. **Correlate timestamps** — all events cluster around the same time window

## Extending with New Vendors

The script uses a vendor registry pattern. To add a new vendor:

1. Add sample logs to a new `VENDOR_SAMPLES` list
2. Add a timestamp rewrite function
3. Add a randomization function
4. Register in `VENDOR_REGISTRY`, `REWRITE_FN`, and `RANDOMIZE_FN` dicts

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection timeout | Check firewall/VPN. The script uses one TCP connection per log. Ensure the Onum port is reachable. |
| Logs received but not parsed | Check the Onum pipeline parser assignment. FortiGate needs `fortinet-fortigate`, Mimecast needs `mimecast-emailsecurity`. |
| Mimecast JSON parse error | Ensure you have the latest version — older versions sent pipe-delimited format. |
| `config.json` not found | Place it in the same directory as the script, or use `--config /path/to/config.json`. |
| Stale timestamps rejected | The script rewrites timestamps at send-time. If logs still show old dates, verify the rewrite regex matches your log format. |
