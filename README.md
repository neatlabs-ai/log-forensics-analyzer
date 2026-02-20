# 🔒 NEATLABS™ Log Forensics Analyzer v3.1

**Enterprise-grade log forensics, threat hunting, and incident response — in a single Python file.**

5,350+ lines. 13 threat hunting modules. 32 Windows Event IDs. 132-entry known-good whitelist. Zero external dependencies. Runs entirely local — no data ever leaves your machine.

Built for SOC analysts, incident responders, CMMC assessors, and anyone who's ever had to make sense of 50,000 event logs on a Friday afternoon with nothing but a Python interpreter.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Lines](https://img.shields.io/badge/Lines-5%2C350+-green)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)

---

## What It Does

Point it at logs. Get answers.

The analyzer collects, parses, and threat-hunts across Windows Event Logs, Linux syslogs, AWS CloudTrail, JSON, CSV, and generic text logs. It maps every finding to MITRE ATT&CK, extracts IOCs, performs Geo-IP analysis, and generates professional forensics reports with risk scores and remediation guidance.

### The Problem It Solves

You're sitting at an endpoint. No SIEM. No Splunk. No EDR dashboard. Just raw `.evtx` files and a room full of people who need answers now. This tool turns that into a structured forensic analysis in under 60 seconds.

---

## Features

### 📥 Log Collection Engine
- **Windows Event Logs** — Native `wevtutil` / PowerShell export with automatic channel discovery. Finds all 245+ `.evtx` files, prioritizes security-relevant channels, and exports them without touching locked system files
- **Linux Logs** — `journalctl` integration, `/var/log` scanning, auth.log / syslog parsing
- **Network Shares** — UNC path scanning for centralized log repositories
- **Directory Browser** — Point at any folder and it auto-detects the format
- **Admin Detection** — Alerts if running without elevation, explains what you'll miss

### 🔍 Multi-Format Parser
| Format | Source | Detection |
|--------|--------|-----------|
| **EVTX XML** | Windows Event Logs via wevtutil | Namespace-aware XML parsing |
| **PowerShell Text** | Get-WinEvent output | Key-value pair extraction |
| **Auth Log** | Linux `/var/log/auth.log`, `secure` | Syslog pattern matching |
| **Syslog** | Standard RFC 3164/5424 | Timestamp + facility parsing |
| **CloudTrail** | AWS JSON exports | Record structure detection |
| **JSON / JSONL** | Generic structured logs | Auto-detect single vs. multi-line |
| **CSV** | Exported log data | Header-based field mapping |
| **Generic** | Anything else | Line-by-line with timestamp extraction |

Multi-source content (mixed formats from collection) is automatically split and each block is parsed with the correct engine.

### 🎯 13 Threat Hunting Modules

| Module | MITRE ATT&CK | What It Catches |
|--------|-------------|-----------------|
| **Brute Force Detection** | T1110 | Failed login bursts with attack-rate thresholds (filters out normal typos) |
| **Password Spraying** | T1110 | Many users, few attempts each, same source IP |
| **Privilege Escalation** | T1548 | Escalation chains: login → sudo → user creation → group modification |
| **Lateral Movement** | T1021 | Multi-host logins, RDP pivoting, SMB session tracking |
| **Impossible Travel** | T1078 | Same user logging in from geographically impossible locations |
| **Account Manipulation** | T1098 | Rapid user creation, group changes, password resets |
| **Log Tampering** | T1070 | Audit log clearing with context (SYSTEM routine vs. user-initiated) |
| **Suspicious Services** | T1569 | New service installs filtered against 132-entry known-good whitelist |
| **Unusual Hours** | T1078 | Logins during midnight–5AM with pattern analysis |
| **Known Bad IPs** | T1090 | Activity from documented malicious IP ranges |
| **Credential Abuse** | T1078 | Shared accounts, service account misuse, impossible concurrency |
| **Cloud Threats** | T1537 | CloudTrail: IAM changes, S3 exposure, security group modifications |
| **Recon Activity** | T1595 | Enumeration patterns, scanning behavior, information gathering |

### 🛡️ False Positive Reduction

This is what separates a useful tool from an alert cannon:

- **132-entry known-good software whitelist** — Malwarebytes, Bitdefender, CrowdStrike, SentinelOne, Defender, Sophos, ESET, Kaspersky, Trend Micro, Avast, Webroot, Cortex XDR, Norton, Carbon Black, and common system services. Your AV reloading kernel drivers 10 times during an update doesn't generate 30 findings.
- **17 known-good path patterns** — `C:\Windows\System32\drivers`, `C:\Program Files\Malwarebytes`, etc. Services running from trusted directories are silently skipped.
- **16 system account exclusions** — SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM, UMFD. Routine 4672 (Special Privileges) events from Windows service accounts don't trigger privilege escalation alerts.
- **Attack-rate thresholds** — 13 failed logins over two weeks at 0.0 attempts/minute is someone forgetting their password, not a brute force attack. Requires ≥0.5 attempts/min to trigger.
- **Service deduplication** — Repeated driver reloads from the same service are collapsed into a single finding.
- **Contextual log tampering** — SYSTEM clearing logs during maintenance is MEDIUM. A named user account wiping the audit trail at 2AM is CRITICAL.
- **Suspicious path escalation** — Services running from `\temp\`, `\downloads\`, `\public\`, or using script extensions (`.ps1`, `.vbs`, `.bat`) auto-escalate to HIGH.

### 📊 Analysis & Reporting

- **IOC Extraction** — IPs, domains, URLs, email addresses, file hashes, usernames, registry keys
- **Geo-IP Analysis** — Geographic mapping of source IPs with built-in RFC 1918 detection
- **MITRE ATT&CK Mapping** — Every finding tagged with technique ID and tactic category
- **Risk Scoring** — 0–100 risk score per finding with severity classification
- **Statistics Dashboard** — Total events, unique IPs, unique users, failed logins, event type distribution, timeline
- **Professional Reports** — Export to HTML (styled forensics report), CSV (raw data), or IOC list
- **32 Windows Event IDs** — Full mapping including 4624/4625 (logon), 4672 (privileges), 4688 (process creation), 4720 (user created), 7045 (service installed), 1102 (log cleared), and more
- **9 Logon Type Classifications** — Interactive, Network, Batch, Service, Unlock, RDP, CachedInteractive, and more

### 🖥️ Desktop GUI

Full tkinter interface with dark theme:

- **Log Collection Center** — Tabbed interface: Local System, Network Share, Browse Directory
- **Real-time Collection Status** — Progress bar, admin status indicator, source discovery
- **Analysis Dashboard** — Summary cards (events, findings, IPs, users, failed logins)
- **Tabbed Results** — Findings, Timeline, Events, IOCs, Geo-IP, MITRE ATT&CK, Raw Log
- **One-Click Export** — HTML report, CSV data, IOC list

---

## Quick Start

### Requirements

- Python 3.8+
- tkinter (included with most Python installations)
- No pip installs. No virtual environments. No package managers.

### Run It

```bash
# Launch GUI
python log_forensics_analyzer.py

# Windows: Run as Administrator for full Event Log access
# Right-click terminal → "Run as Administrator"
```

### Collect & Analyze

1. Click **Collect Logs**
2. Select sources (Event Logs, Security, System, PowerShell, etc.)
3. Click **Collecting...**
4. Results populate automatically across all tabs

### Load Existing Logs

```bash
# Load a log file directly
# Click "Load Log File" → select any supported format
```

---

## Architecture

```
log_forensics_analyzer.py (5,350+ lines, single file)
│
├── LogEvent            — Normalized event data class
├── LogParser           — Multi-format parser with auto-detection
│   ├── EVTX XML       — Namespace-aware Windows Event Log parser
│   ├── PowerShell      — Get-WinEvent text format parser  
│   ├── Auth Log        — Linux authentication log parser
│   ├── Syslog          — RFC 3164/5424 parser
│   ├── CloudTrail      — AWS JSON parser
│   ├── JSON/JSONL      — Generic structured log parser
│   ├── CSV             — Tabular data parser
│   ├── Generic         — Fallback line parser
│   └── Multi-Source    — Splits collected content, parses each block independently
│
├── LogCollector        — System log collection engine
│   ├── Windows         — wevtutil + PowerShell with 2-layer fallback
│   ├── Linux           — journalctl + /var/log scanning
│   ├── macOS           — system.log + unified logging
│   ├── Network         — UNC share scanning
│   └── EVTX Directory  — Channel discovery + prioritized export
│
├── ThreatHunter        — 13 automated threat hunting modules
│   ├── Known-Good DB   — 132 services, 17 paths, 16 system accounts
│   └── MITRE ATT&CK    — Technique mapping for all findings
│
├── IOCExtractor        — Indicator of Compromise extraction
├── GeoIPLookup         — Geographic IP analysis
├── LogStatistics       — Event statistics and timeline
├── ReportGenerator     — HTML/CSV/IOC export
│
├── LogCollectorDialog  — Collection GUI (Local/Network/Browse tabs)
└── LogForensicsGUI     — Main application GUI with analysis dashboard
```

---

## Windows Event Log Collection

The tool uses `wevtutil` (native Windows utility) to export event logs instead of reading locked `.evtx` files directly. This is the correct approach — the Event Log service holds exclusive locks on these files.

### How It Works

1. Scans `C:\Windows\System32\winevt\Logs` for `.evtx` files
2. Extracts channel names from filenames (e.g., `Microsoft-Windows-PowerShell%4Operational.evtx` → `Microsoft-Windows-PowerShell/Operational`)
3. Exports each channel via `wevtutil qe <channel> /f:xml`
4. Falls back to `PowerShell Get-WinEvent` if wevtutil fails
5. Silently skips hardware/driver/telemetry channels (Camera, Intel-GFX, Audio, etc.)
6. Deduplicates channels already selected individually

### Priority Channels

Security, System, Application, PowerShell Operational, Sysmon, Windows Defender, Terminal Services, Task Scheduler, Firewall, NTLM, WMI Activity, Group Policy, DNS Client, and Remote Desktop.

### Admin Requirement

Most channels require elevation. Without admin:
- Application log: ✅ accessible
- System log: ✅ accessible
- Security log: ❌ requires admin
- PowerShell Operational: ❌ requires admin

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| **Initial Access** | T1078 Valid Accounts |
| **Execution** | T1569 System Services, T1053 Scheduled Tasks |
| **Persistence** | T1098 Account Manipulation, T1053 Scheduled Tasks |
| **Privilege Escalation** | T1548 Abuse Elevation Control |
| **Defense Evasion** | T1070 Indicator Removal |
| **Credential Access** | T1110 Brute Force |
| **Discovery** | T1595 Active Scanning |
| **Lateral Movement** | T1021 Remote Services |
| **Exfiltration** | T1537 Transfer to Cloud Account |

---

## Example Output

```
🔒 NEATLABS™ Log Forensics Report
Events Analyzed: 47,686

[CRITICAL] T1070  | Risk: 95 | Log Tampering / Evidence Destruction by admin
  Event: Audit Log Cleared
  User: admin
  Time: 2026-02-20 02:14:30

[HIGH]     T1110  | Risk: 85 | Brute Force → COMPROMISED: admin@203.0.113.50
  47 failed attempts over 3m12s
  Attack rate: 14.7 attempts/min
  ⚠ SUCCESSFUL LOGIN DETECTED after failures
  Source: Moscow, Russia

[HIGH]     T1569  | Risk: 75 | Suspicious Service: SystemUpdate32
  Path: C:\Users\Public\Downloads\svchost.exe
  ⚠ Suspicious path: \public\

[MEDIUM]   T1548  | Risk: 50 | Privilege Escalation Activity: jsmith
  [14:11:18] Special Privileges Assigned
  [14:12:03] User Account Created: backdoor_admin
  [14:12:09] Member Added to Security Group: Domain Admins
```

---

## Author

**NEATLABS™** — Security 360 LLC  
eteran-Owned Small Business (SDVOSB)  
28+ Years Federal Cybersecurity & Technology

---

## License

Proprietary — All Rights Reserved  
©Security 360 LLC / DBA Neatlabs™
