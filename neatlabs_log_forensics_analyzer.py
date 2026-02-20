#!/usr/bin/env python3
"""
NEATLABS™ Log Forensics Analyzer v3.1
======================================
Enterprise-grade log forensics and automated threat hunting platform.
Supports: Syslog, Windows EVTX (XML), auth.log, CloudTrail JSON, CSV logs.

Features:
- Log Collection from local system, network shares, and UNC paths
- Auto-discovery of OS-specific log sources (Linux, Windows, macOS)
- Windows Event Log export via wevtutil/PowerShell
- Journalctl integration for systemd journal collection
- Network share and directory scanning with recursive search
- Automated threat hunting across all log formats
- Brute force timeline reconstruction
- Privilege escalation chain detection
- Lateral movement mapping
- Impossible travel detection
- MITRE ATT&CK mapping on every finding
- Interactive timeline visualization
- IOC extraction (IPs, domains, hashes, emails)
- Geo-IP analysis with distance calculations
- Risk scoring with weighted threat model
- Full export: HTML reports, CSV findings, JSON IOCs

Zero external dependencies. One file. Pure Python + tkinter.
Copyright © 2025 NEATLABS™ / Stealth Entry LLC. All rights reserved.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import re
import os
import io
import hashlib
import math
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter, OrderedDict
from ipaddress import ip_address, ip_network
import struct
import binascii
import threading
import time
import textwrap
import uuid
import html as html_module
import glob
import subprocess
import platform
import pathlib
import fnmatch
import shutil
import stat as stat_module

# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

MITRE_ATTACK_DB = {
    "T1110": {
        "id": "T1110", "name": "Brute Force",
        "tactic": "Credential Access", "severity": "HIGH",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or password hashes are obtained.",
        "subtechniques": {
            "T1110.001": "Password Guessing",
            "T1110.002": "Password Cracking",
            "T1110.003": "Password Spraying",
            "T1110.004": "Credential Stuffing"
        },
        "mitigations": ["Account Lockout Policies", "Multi-factor Authentication", "Password Policies"],
        "detection": "Monitor authentication logs for multiple failed login attempts"
    },
    "T1078": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "severity": "HIGH",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.",
        "subtechniques": {
            "T1078.001": "Default Accounts",
            "T1078.002": "Domain Accounts",
            "T1078.003": "Local Accounts",
            "T1078.004": "Cloud Accounts"
        },
        "mitigations": ["Privileged Account Management", "MFA", "Audit"],
        "detection": "Monitor for unusual account usage patterns"
    },
    "T1098": {
        "id": "T1098", "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation", "severity": "HIGH",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems.",
        "subtechniques": {
            "T1098.001": "Additional Cloud Credentials",
            "T1098.002": "Additional Email Delegate Permissions",
            "T1098.003": "Additional Cloud Roles"
        },
        "mitigations": ["MFA", "Privileged Account Management", "Network Segmentation"],
        "detection": "Monitor for changes to account objects and permissions"
    },
    "T1021": {
        "id": "T1021", "name": "Remote Services",
        "tactic": "Lateral Movement", "severity": "MEDIUM",
        "description": "Adversaries may use valid accounts to log into remote services to move laterally.",
        "subtechniques": {
            "T1021.001": "Remote Desktop Protocol",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1021.003": "Distributed Component Object Model",
            "T1021.004": "SSH",
            "T1021.006": "Windows Remote Management"
        },
        "mitigations": ["MFA", "Network Segmentation", "Disable Unused Services"],
        "detection": "Monitor logon sessions and remote access patterns"
    },
    "T1550": {
        "id": "T1550", "name": "Use Alternate Authentication Material",
        "tactic": "Defense Evasion, Lateral Movement", "severity": "HIGH",
        "description": "Adversaries may use alternate authentication material like hashes or tickets to move laterally.",
        "subtechniques": {
            "T1550.001": "Application Access Token",
            "T1550.002": "Pass the Hash",
            "T1550.003": "Pass the Ticket"
        },
        "mitigations": ["Privileged Account Management", "User Account Control"],
        "detection": "Monitor authentication logs for anomalous authentication patterns"
    },
    "T1053": {
        "id": "T1053", "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation", "severity": "MEDIUM",
        "description": "Adversaries may abuse task scheduling to execute malicious code at system startup or on a schedule.",
        "subtechniques": {
            "T1053.002": "At",
            "T1053.003": "Cron",
            "T1053.005": "Scheduled Task"
        },
        "mitigations": ["Audit", "Operating System Configuration", "Privileged Account Management"],
        "detection": "Monitor for newly created scheduled tasks or cron jobs"
    },
    "T1136": {
        "id": "T1136", "name": "Create Account",
        "tactic": "Persistence", "severity": "MEDIUM",
        "description": "Adversaries may create an account to maintain access to victim systems.",
        "subtechniques": {
            "T1136.001": "Local Account",
            "T1136.002": "Domain Account",
            "T1136.003": "Cloud Account"
        },
        "mitigations": ["MFA", "Network Segmentation", "Privileged Account Management"],
        "detection": "Monitor for new accounts created outside of normal procedures"
    },
    "T1070": {
        "id": "T1070", "name": "Indicator Removal",
        "tactic": "Defense Evasion", "severity": "HIGH",
        "description": "Adversaries may delete or modify artifacts on a host system to remove evidence of their presence.",
        "subtechniques": {
            "T1070.001": "Clear Windows Event Logs",
            "T1070.002": "Clear Linux/Mac System Logs",
            "T1070.003": "Clear Command History",
            "T1070.004": "File Deletion"
        },
        "mitigations": ["Encrypt Sensitive Information", "Remote Data Storage", "Restrict File Permissions"],
        "detection": "Monitor for unexpected log clearing or deletion events"
    },
    "T1059": {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "severity": "MEDIUM",
        "description": "Adversaries may abuse command and script interpreters to execute commands and scripts.",
        "subtechniques": {
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            "T1059.004": "Unix Shell"
        },
        "mitigations": ["Code Signing", "Execution Prevention", "Antivirus/Antimalware"],
        "detection": "Monitor command-line arguments and script execution"
    },
    "T1548": {
        "id": "T1548", "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation, Defense Evasion", "severity": "HIGH",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        "subtechniques": {
            "T1548.001": "Setuid and Setgid",
            "T1548.002": "Bypass User Account Control",
            "T1548.003": "Sudo and Sudo Caching"
        },
        "mitigations": ["Audit", "Operating System Configuration", "Privileged Account Management"],
        "detection": "Monitor for elevation of privilege events"
    },
    "T1562": {
        "id": "T1562", "name": "Impair Defenses",
        "tactic": "Defense Evasion", "severity": "CRITICAL",
        "description": "Adversaries may maliciously modify components of a victim environment to hinder defensive capabilities.",
        "subtechniques": {
            "T1562.001": "Disable or Modify Tools",
            "T1562.002": "Disable Windows Event Logging",
            "T1562.004": "Disable or Modify System Firewall",
            "T1562.008": "Disable Cloud Logs"
        },
        "mitigations": ["Restrict File/Directory Permissions", "User Account Management"],
        "detection": "Monitor for changes to security tools and logging configurations"
    },
    "T1087": {
        "id": "T1087", "name": "Account Discovery",
        "tactic": "Discovery", "severity": "LOW",
        "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment.",
        "subtechniques": {
            "T1087.001": "Local Account",
            "T1087.002": "Domain Account",
            "T1087.003": "Email Account",
            "T1087.004": "Cloud Account"
        },
        "mitigations": ["Operating System Configuration"],
        "detection": "Monitor for processes and command-line arguments associated with account enumeration"
    },
    "T1071": {
        "id": "T1071", "name": "Application Layer Protocol",
        "tactic": "Command and Control", "severity": "MEDIUM",
        "description": "Adversaries may communicate using application layer protocols to blend in with normal traffic.",
        "subtechniques": {
            "T1071.001": "Web Protocols",
            "T1071.004": "DNS"
        },
        "mitigations": ["Network Intrusion Prevention", "Filter Network Traffic"],
        "detection": "Analyze network data for uncommon data flows"
    },
    "T1486": {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "severity": "CRITICAL",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "subtechniques": {},
        "mitigations": ["Data Backup", "Behavior Prevention on Endpoint"],
        "detection": "Monitor for file modification events and unusual encryption activity"
    },
    "T1531": {
        "id": "T1531", "name": "Account Access Removal",
        "tactic": "Impact", "severity": "HIGH",
        "description": "Adversaries may interrupt availability by inhibiting access to accounts.",
        "subtechniques": {},
        "mitigations": ["Audit", "Privileged Account Management"],
        "detection": "Monitor for account lockouts and password changes"
    },
    "T1046": {
        "id": "T1046", "name": "Network Service Discovery",
        "tactic": "Discovery", "severity": "LOW",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "subtechniques": {},
        "mitigations": ["Network Segmentation", "Network Intrusion Prevention"],
        "detection": "Monitor for port scanning and service enumeration activity"
    },
    "T1569": {
        "id": "T1569", "name": "System Services",
        "tactic": "Execution", "severity": "MEDIUM",
        "description": "Adversaries may abuse system services or daemons to execute commands or programs.",
        "subtechniques": {
            "T1569.001": "Launchctl",
            "T1569.002": "Service Execution"
        },
        "mitigations": ["Privileged Account Management", "Restrict File/Directory Permissions"],
        "detection": "Monitor for changes to system services"
    },
    "T1558": {
        "id": "T1558", "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access", "severity": "HIGH",
        "description": "Adversaries may attempt to steal or forge Kerberos tickets for lateral movement.",
        "subtechniques": {
            "T1558.001": "Golden Ticket",
            "T1558.003": "Kerberoasting"
        },
        "mitigations": ["Active Directory Configuration", "Encrypt Sensitive Information", "Password Policies"],
        "detection": "Monitor for anomalous Kerberos ticket requests"
    },
    "T1090": {
        "id": "T1090", "name": "Proxy",
        "tactic": "Command and Control", "severity": "MEDIUM",
        "description": "Adversaries may use a proxy to direct network traffic between systems or act as an intermediary.",
        "subtechniques": {
            "T1090.001": "Internal Proxy",
            "T1090.002": "External Proxy",
            "T1090.003": "Multi-hop Proxy"
        },
        "mitigations": ["Filter Network Traffic", "Network Intrusion Prevention", "SSL Inspection"],
        "detection": "Monitor network data for uncommon proxy patterns"
    },
    "T1133": {
        "id": "T1133", "name": "External Remote Services",
        "tactic": "Persistence, Initial Access", "severity": "HIGH",
        "description": "Adversaries may leverage external-facing remote services to gain initial access or persistence.",
        "subtechniques": {},
        "mitigations": ["Disable/Remove Feature", "Limit Access to Resource", "MFA", "Network Segmentation"],
        "detection": "Monitor for external remote service connections from unusual sources"
    },
    "T1556": {
        "id": "T1556", "name": "Modify Authentication Process",
        "tactic": "Credential Access, Defense Evasion, Persistence", "severity": "CRITICAL",
        "description": "Adversaries may modify authentication mechanisms to access user credentials or enable unauthorized access.",
        "subtechniques": {
            "T1556.001": "Domain Controller Authentication",
            "T1556.003": "Pluggable Authentication Modules",
            "T1556.006": "Multi-Factor Authentication"
        },
        "mitigations": ["Audit", "MFA", "Privileged Account Management", "Privileged Process Integrity"],
        "detection": "Monitor for changes to authentication processes and configurations"
    },
    "T1537": {
        "id": "T1537", "name": "Transfer Data to Cloud Account",
        "tactic": "Exfiltration", "severity": "HIGH",
        "description": "Adversaries may exfiltrate data by transferring it to another cloud account they control.",
        "subtechniques": {},
        "mitigations": ["Filter Network Traffic", "Password Policies", "User Account Management"],
        "detection": "Monitor for unusual data transfer to external cloud accounts"
    },
    "T1535": {
        "id": "T1535", "name": "Unused/Unsupported Cloud Regions",
        "tactic": "Defense Evasion", "severity": "MEDIUM",
        "description": "Adversaries may create cloud instances in unused geographic service regions to evade detection.",
        "subtechniques": {},
        "mitigations": ["Software Configuration"],
        "detection": "Monitor for cloud activity in unusual or unused regions"
    },
    "T1528": {
        "id": "T1528", "name": "Steal Application Access Token",
        "tactic": "Credential Access", "severity": "HIGH",
        "description": "Adversaries can steal application access tokens to acquire credentials or access remote systems.",
        "subtechniques": {},
        "mitigations": ["Audit", "Encrypt Sensitive Information", "Restrict Web-Based Content"],
        "detection": "Monitor for unusual API token usage patterns"
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# GEO-IP DATABASE (Major IP ranges for impossible travel detection)
# ═══════════════════════════════════════════════════════════════════════════════

GEO_IP_RANGES = [
    # US ranges
    ("3.0.0.0/8", "US", "Virginia", 38.9072, -77.0369),
    ("4.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("8.8.0.0/16", "US", "California", 37.386, -122.0838),
    ("12.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("13.0.0.0/8", "US", "Virginia", 38.9072, -77.0369),
    ("15.0.0.0/8", "US", "Various", 41.8781, -87.6298),
    ("17.0.0.0/8", "US", "California", 37.3318, -122.0312),
    ("18.0.0.0/8", "US", "Massachusetts", 42.3601, -71.0589),
    ("20.0.0.0/8", "US", "Washington", 47.6062, -122.3321),
    ("23.0.0.0/8", "US", "Various", 33.749, -84.388),
    ("24.0.0.0/8", "US", "Various", 39.7392, -104.9903),
    ("32.0.0.0/8", "US", "Various", 29.7604, -95.3698),
    ("34.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("35.0.0.0/8", "US", "Various", 40.4406, -79.9959),
    ("40.0.0.0/8", "US", "Virginia", 38.9072, -77.0369),
    ("44.0.0.0/8", "US", "Various", 47.6062, -122.3321),
    ("50.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("52.0.0.0/8", "US", "Virginia", 38.9072, -77.0369),
    ("54.0.0.0/8", "US", "Virginia", 38.9072, -77.0369),
    ("63.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("64.0.0.0/8", "US", "Various", 34.0522, -118.2437),
    ("65.0.0.0/8", "US", "Various", 33.749, -84.388),
    ("66.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("67.0.0.0/8", "US", "Various", 41.8781, -87.6298),
    ("68.0.0.0/8", "US", "Various", 32.7767, -96.7970),
    ("69.0.0.0/8", "US", "Various", 25.7617, -80.1918),
    ("70.0.0.0/8", "US", "Various", 30.2672, -97.7431),
    ("71.0.0.0/8", "US", "Various", 36.1627, -86.7816),
    ("72.0.0.0/8", "US", "Various", 39.9612, -82.9988),
    ("73.0.0.0/8", "US", "Various", 35.2271, -80.8431),
    ("74.0.0.0/8", "US", "Various", 42.3314, -83.0458),
    ("75.0.0.0/8", "US", "Various", 44.9778, -93.2650),
    ("76.0.0.0/8", "US", "Various", 47.6062, -122.3321),
    ("96.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("97.0.0.0/8", "US", "Various", 33.4484, -112.0740),
    ("98.0.0.0/8", "US", "Various", 37.5407, -77.4360),
    ("99.0.0.0/8", "US", "Various", 36.1627, -86.7816),
    ("100.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("104.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("107.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("108.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("142.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("143.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("144.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("147.0.0.0/8", "US", "Various", 37.3861, -122.0839),
    ("148.0.0.0/8", "US", "Various", 33.749, -84.388),
    ("149.0.0.0/8", "US", "Various", 47.6062, -122.3321),
    ("155.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("156.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("157.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("158.0.0.0/8", "US", "Various", 41.8781, -87.6298),
    ("159.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("160.0.0.0/8", "US", "Various", 34.0522, -118.2437),
    ("161.0.0.0/8", "US", "Various", 42.3601, -71.0589),
    ("162.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("163.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("164.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("165.0.0.0/8", "US", "Various", 29.7604, -95.3698),
    ("166.0.0.0/8", "US", "Various", 32.7767, -96.7970),
    ("167.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("168.0.0.0/8", "US", "Various", 33.749, -84.388),
    ("169.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("170.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("172.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("173.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("174.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("184.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("192.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("198.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("199.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("204.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("205.0.0.0/8", "US", "Various", 34.0522, -118.2437),
    ("206.0.0.0/8", "US", "Various", 47.6062, -122.3321),
    ("207.0.0.0/8", "US", "Various", 40.7128, -74.0060),
    ("208.0.0.0/8", "US", "Various", 37.7749, -122.4194),
    ("209.0.0.0/8", "US", "Various", 38.9072, -77.0369),
    ("216.0.0.0/8", "US", "Various", 41.8781, -87.6298),
    # Europe
    ("2.0.0.0/8", "FR", "Paris", 48.8566, 2.3522),
    ("5.0.0.0/8", "DE", "Frankfurt", 50.1109, 8.6821),
    ("31.0.0.0/8", "NL", "Amsterdam", 52.3676, 4.9041),
    ("37.0.0.0/8", "IT", "Rome", 41.9028, 12.4964),
    ("46.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("51.0.0.0/8", "GB", "London", 51.5074, -0.1278),
    ("62.0.0.0/8", "DE", "Berlin", 52.5200, 13.4050),
    ("77.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("78.0.0.0/8", "GB", "London", 51.5074, -0.1278),
    ("79.0.0.0/8", "ES", "Madrid", 40.4168, -3.7038),
    ("80.0.0.0/8", "DE", "Frankfurt", 50.1109, 8.6821),
    ("81.0.0.0/8", "GB", "London", 51.5074, -0.1278),
    ("82.0.0.0/8", "FR", "Paris", 48.8566, 2.3522),
    ("83.0.0.0/8", "DE", "Berlin", 52.5200, 13.4050),
    ("84.0.0.0/8", "ES", "Madrid", 40.4168, -3.7038),
    ("85.0.0.0/8", "IT", "Milan", 45.4642, 9.1900),
    ("86.0.0.0/8", "FR", "Lyon", 45.7640, 4.8357),
    ("87.0.0.0/8", "GB", "Manchester", 53.4808, -2.2426),
    ("88.0.0.0/8", "DE", "Munich", 48.1351, 11.5820),
    ("89.0.0.0/8", "NL", "Amsterdam", 52.3676, 4.9041),
    ("90.0.0.0/8", "FR", "Paris", 48.8566, 2.3522),
    ("91.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("92.0.0.0/8", "SE", "Stockholm", 59.3293, 18.0686),
    ("93.0.0.0/8", "DE", "Hamburg", 53.5511, 9.9937),
    ("94.0.0.0/8", "RU", "St. Petersburg", 59.9343, 30.3351),
    ("95.0.0.0/8", "UA", "Kyiv", 50.4501, 30.5234),
    ("109.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("176.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("178.0.0.0/8", "RU", "Novosibirsk", 55.0084, 82.9357),
    ("185.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("188.0.0.0/8", "RU", "Moscow", 55.7558, 37.6173),
    ("193.0.0.0/8", "EU", "Various", 50.1109, 8.6821),
    ("194.0.0.0/8", "EU", "Various", 52.5200, 13.4050),
    ("195.0.0.0/8", "EU", "Various", 48.8566, 2.3522),
    ("212.0.0.0/8", "EU", "Various", 51.5074, -0.1278),
    ("213.0.0.0/8", "EU", "Various", 40.4168, -3.7038),
    ("217.0.0.0/8", "EU", "Various", 52.3676, 4.9041),
    # Asia
    ("1.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("14.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("27.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("36.0.0.0/8", "CN", "Shenzhen", 22.5431, 114.0579),
    ("39.0.0.0/8", "CN", "Guangzhou", 23.1291, 113.2644),
    ("42.0.0.0/8", "KR", "Seoul", 37.5665, 126.9780),
    ("43.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("45.0.0.0/8", "SG", "Singapore", 1.3521, 103.8198),
    ("49.0.0.0/8", "KR", "Seoul", 37.5665, 126.9780),
    ("58.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("59.0.0.0/8", "KR", "Busan", 35.1796, 129.0756),
    ("60.0.0.0/8", "JP", "Osaka", 34.6937, 135.5023),
    ("61.0.0.0/8", "AU", "Sydney", -33.8688, 151.2093),
    ("101.0.0.0/8", "IN", "Mumbai", 19.0760, 72.8777),
    ("103.0.0.0/8", "IN", "Delhi", 28.7041, 77.1025),
    ("106.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("110.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("111.0.0.0/8", "CN", "Hangzhou", 30.2741, 120.1551),
    ("112.0.0.0/8", "CN", "Shenzhen", 22.5431, 114.0579),
    ("113.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("114.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("115.0.0.0/8", "IN", "Bangalore", 12.9716, 77.5946),
    ("116.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("117.0.0.0/8", "CN", "Guangzhou", 23.1291, 113.2644),
    ("118.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("119.0.0.0/8", "CN", "Shenzhen", 22.5431, 114.0579),
    ("120.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("121.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("122.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("123.0.0.0/8", "CN", "Nanjing", 32.0603, 118.7969),
    ("124.0.0.0/8", "CN", "Wuhan", 30.5928, 114.3055),
    ("125.0.0.0/8", "KR", "Seoul", 37.5665, 126.9780),
    ("126.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("180.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("182.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("183.0.0.0/8", "CN", "Shenzhen", 22.5431, 114.0579),
    ("202.0.0.0/8", "AU", "Melbourne", -37.8136, 144.9631),
    ("203.0.0.0/8", "AU", "Sydney", -33.8688, 151.2093),
    ("210.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("211.0.0.0/8", "KR", "Seoul", 37.5665, 126.9780),
    ("218.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("219.0.0.0/8", "KR", "Seoul", 37.5665, 126.9780),
    ("220.0.0.0/8", "JP", "Tokyo", 35.6762, 139.6503),
    ("221.0.0.0/8", "CN", "Shanghai", 31.2304, 121.4737),
    ("222.0.0.0/8", "CN", "Beijing", 39.9042, 116.4074),
    ("223.0.0.0/8", "CN", "Shenzhen", 22.5431, 114.0579),
    # Middle East / Africa
    ("41.0.0.0/8", "ZA", "Johannesburg", -26.2041, 28.0473),
    ("102.0.0.0/8", "NG", "Lagos", 6.5244, 3.3792),
    ("105.0.0.0/8", "EG", "Cairo", 30.0444, 31.2357),
    ("154.0.0.0/8", "ZA", "Cape Town", -33.9249, 18.4241),
    ("196.0.0.0/8", "ZA", "Johannesburg", -26.2041, 28.0473),
    ("197.0.0.0/8", "NG", "Lagos", 6.5244, 3.3792),
    # South America
    ("177.0.0.0/8", "BR", "Sao Paulo", -23.5505, -46.6333),
    ("179.0.0.0/8", "BR", "Rio de Janeiro", -22.9068, -43.1729),
    ("181.0.0.0/8", "AR", "Buenos Aires", -34.6037, -58.3816),
    ("186.0.0.0/8", "BR", "Brasilia", -15.7975, -47.8919),
    ("187.0.0.0/8", "BR", "Sao Paulo", -23.5505, -46.6333),
    ("189.0.0.0/8", "MX", "Mexico City", 19.4326, -99.1332),
    ("190.0.0.0/8", "CO", "Bogota", 4.7110, -74.0721),
    ("191.0.0.0/8", "BR", "Sao Paulo", -23.5505, -46.6333),
    ("200.0.0.0/8", "BR", "Sao Paulo", -23.5505, -46.6333),
    ("201.0.0.0/8", "MX", "Mexico City", 19.4326, -99.1332),
    # Canada
    ("47.0.0.0/8", "CA", "Toronto", 43.6532, -79.3832),
    ("48.0.0.0/8", "CA", "Vancouver", 49.2827, -123.1207),
    ("129.0.0.0/8", "CA", "Montreal", 45.5017, -73.5673),
    ("132.0.0.0/8", "CA", "Ottawa", 45.4215, -75.6972),
    ("136.0.0.0/8", "CA", "Calgary", 51.0447, -114.0719),
    # Private/Reserved
    ("10.0.0.0/8", "PRIVATE", "Internal", 0, 0),
    ("127.0.0.0/8", "LOCAL", "Localhost", 0, 0),
    ("169.254.0.0/16", "LINK-LOCAL", "Link-Local", 0, 0),
    ("192.168.0.0/16", "PRIVATE", "Internal", 0, 0),
]

# ═══════════════════════════════════════════════════════════════════════════════
# KNOWN MALICIOUS IP RANGES / THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════════════

KNOWN_BAD_RANGES = [
    "185.220.100.0/24",  # Tor exit nodes
    "185.220.101.0/24",  # Tor exit nodes
    "185.220.102.0/24",  # Tor exit nodes
    "185.56.80.0/24",    # Known C2
    "91.219.236.0/24",   # Known C2
    "45.155.205.0/24",   # Known scanner
    "193.142.146.0/24",  # Known scanner
    "89.248.167.0/24",   # Known scanner
    "71.6.135.0/24",     # Known scanner
    "80.82.77.0/24",     # Known scanner
    "162.142.125.0/24",  # Mass scanner
    "167.94.138.0/24",   # Mass scanner
    "167.94.145.0/24",   # Mass scanner
    "167.94.146.0/24",   # Mass scanner
    "198.235.24.0/24",   # Known APT infra
    "5.188.86.0/24",     # Known brute forcer
    "5.188.87.0/24",     # Known brute forcer
    "194.26.29.0/24",    # Known brute forcer
]

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 5900, 5985, 5986, 1433, 3306, 6379, 27017, 11211, 9200}
SUSPICIOUS_USERAGENTS = ["nikto", "sqlmap", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "wpscan", "acunetix"]

# ═══════════════════════════════════════════════════════════════════════════════
# LOG PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

class LogEvent:
    """Universal log event structure."""
    __slots__ = ['timestamp', 'source_ip', 'dest_ip', 'username', 'action',
                 'status', 'service', 'message', 'raw', 'source_type',
                 'hostname', 'port', 'event_id', 'pid', 'severity',
                 'extra']

    def __init__(self, **kwargs):
        for s in self.__slots__:
            setattr(self, s, kwargs.get(s, ''))
        if not self.extra:
            self.extra = {}

    def to_dict(self):
        d = {}
        for s in self.__slots__:
            v = getattr(self, s, '')
            if v:
                d[s] = v
        return d


class LogParser:
    """Multi-format log parser with auto-detection."""

    # Syslog patterns
    SYSLOG_PAT = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+'
        r'(?P<message>.*)'
    )

    SYSLOG_ISO_PAT = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+'
        r'(?P<message>.*)'
    )

    # Auth log specifics
    AUTH_FAIL_PAT = re.compile(r'(?:Failed password|authentication failure|FAILED LOGIN|invalid user|Invalid user)', re.I)
    AUTH_SUCCESS_PAT = re.compile(r'(?:Accepted password|Accepted publickey|session opened|Successful login)', re.I)
    AUTH_USER_PAT = re.compile(r'(?:for|user[= ])(?:invalid user\s+)?(\S+)', re.I)
    AUTH_IP_PAT = re.compile(r'(?:from|rhost=)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    AUTH_PORT_PAT = re.compile(r'port\s+(\d+)')
    AUTH_SUDO_PAT = re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.*)', re.I)
    AUTH_SU_PAT = re.compile(r"su(?:\[\d+\])?\s*:\s+(?:(?:pam_unix\(su[^)]*\):\s+)?session opened|Successful su|'\+' )", re.I)
    AUTH_USERADD_PAT = re.compile(r'(?:useradd|adduser).*name=(\S+)', re.I)
    AUTH_USERDEL_PAT = re.compile(r'(?:userdel|deluser).*name=(\S+)', re.I)
    AUTH_GROUPADD_PAT = re.compile(r'(?:usermod|gpasswd).*(?:group|to group)\s+(\S+)', re.I)
    AUTH_PASSWD_PAT = re.compile(r'(?:passwd|password changed|chpasswd)', re.I)
    AUTH_KEY_PAT = re.compile(r'(?:Accepted publickey|key .* from)', re.I)
    AUTH_DISCONNECT_PAT = re.compile(r'(?:Disconnected from|Connection closed by|session closed)', re.I)

    # IP extraction
    IP_PAT = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    # Windows Event IDs of interest
    WINDOWS_EVENTS = {
        "4624": ("Successful Logon", "success"),
        "4625": ("Failed Logon", "failure"),
        "4634": ("Logoff", "info"),
        "4647": ("User Initiated Logoff", "info"),
        "4648": ("Logon with Explicit Credentials", "warning"),
        "4656": ("Object Handle Requested", "info"),
        "4663": ("Object Access Attempt", "info"),
        "4672": ("Special Privileges Assigned", "warning"),
        "4688": ("New Process Created", "info"),
        "4697": ("Service Installed", "warning"),
        "4698": ("Scheduled Task Created", "warning"),
        "4699": ("Scheduled Task Deleted", "info"),
        "4700": ("Scheduled Task Enabled", "warning"),
        "4720": ("User Account Created", "warning"),
        "4722": ("User Account Enabled", "info"),
        "4723": ("Password Change Attempt", "info"),
        "4724": ("Password Reset Attempt", "warning"),
        "4725": ("User Account Disabled", "info"),
        "4726": ("User Account Deleted", "warning"),
        "4728": ("Member Added to Security Group", "warning"),
        "4732": ("Member Added to Local Group", "warning"),
        "4733": ("Member Removed from Local Group", "info"),
        "4738": ("User Account Changed", "info"),
        "4740": ("Account Locked Out", "warning"),
        "4767": ("Account Unlocked", "info"),
        "4771": ("Kerberos Pre-Auth Failed", "failure"),
        "4776": ("NTLM Authentication", "info"),
        "4778": ("Session Reconnected", "info"),
        "4779": ("Session Disconnected", "info"),
        "1102": ("Audit Log Cleared", "critical"),
        "7045": ("Service Installed", "warning"),
        "4104": ("PowerShell Script Block", "warning"),
    }

    # Windows logon types
    LOGON_TYPES = {
        "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
        "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
        "10": "RemoteInteractive", "11": "CachedInteractive"
    }

    @staticmethod
    def detect_format(content):
        """Auto-detect log format from content."""
        lines = content[:5000].split('\n')
        first_lines = [l.strip() for l in lines[:20] if l.strip()]

        # Check JSON (CloudTrail / generic JSON logs)
        if content.lstrip().startswith('{') or content.lstrip().startswith('['):
            try:
                data = json.loads(content)
                if isinstance(data, dict) and 'Records' in data:
                    return 'cloudtrail'
                if isinstance(data, list) and len(data) > 0:
                    if 'eventSource' in str(data[0]):
                        return 'cloudtrail'
                    return 'json_log'
                if 'eventSource' in str(data):
                    return 'cloudtrail'
                return 'json_log'
            except json.JSONDecodeError:
                # Try JSONL (one JSON per line)
                try:
                    json.loads(first_lines[0])
                    return 'jsonl'
                except:
                    pass

        # Check EVTX XML
        if '<Event ' in content[:2000] or '<Events>' in content[:200] or '<?xml' in content[:200]:
            if 'EventID' in content[:5000] or '<System>' in content[:5000]:
                return 'evtx_xml'

        # Check PowerShell Get-WinEvent text format
        if 'TimeCreated' in content[:3000] and 'LevelDisplayName' in content[:3000]:
            return 'evtx_xml'
        # Check CSV
        if ',' in first_lines[0] and len(first_lines[0].split(',')) >= 3:
            # Heuristic: if header-like first line
            if any(k in first_lines[0].lower() for k in ['timestamp', 'date', 'time', 'event', 'source', 'ip', 'user']):
                return 'csv'

        # Check auth.log style
        for line in first_lines[:5]:
            if any(k in line.lower() for k in ['sshd', 'pam_unix', 'sudo', 'su:', 'auth', 'login', 'passwd']):
                return 'auth_log'

        # Check general syslog
        for line in first_lines[:5]:
            if LogParser.SYSLOG_PAT.match(line) or LogParser.SYSLOG_ISO_PAT.match(line):
                return 'syslog'

        # Try JSONL one more time
        for line in first_lines[:5]:
            try:
                json.loads(line)
                return 'jsonl'
            except:
                continue

        return 'generic'

    @staticmethod
    def parse(content, format_hint=None):
        """Parse log content into list of LogEvent objects.

        Handles multi-source content (from Log Collector) by splitting on
        ### SOURCE: markers and parsing each block independently.
        """

        # ── Multi-source handling ──
        # If content has ### SOURCE: markers (from Log Collector), split and parse each
        if '### SOURCE:' in content:
            return LogParser._parse_multi_source(content)

        # ── Single source parsing ──
        if format_hint is None:
            format_hint = LogParser.detect_format(content)

        parsers = {
            'cloudtrail': LogParser._parse_cloudtrail,
            'evtx_xml': LogParser._parse_evtx_xml,
            'auth_log': LogParser._parse_auth_log,
            'syslog': LogParser._parse_syslog,
            'json_log': LogParser._parse_json_generic,
            'jsonl': LogParser._parse_jsonl,
            'csv': LogParser._parse_csv,
            'generic': LogParser._parse_generic,
        }

        parser = parsers.get(format_hint, LogParser._parse_generic)
        events = parser(content)

        # Sort by timestamp if possible
        def sort_key(e):
            if isinstance(e.timestamp, datetime):
                return e.timestamp
            if isinstance(e.timestamp, str) and e.timestamp:
                try:
                    return datetime.fromisoformat(e.timestamp.replace('Z', '+00:00'))
                except:
                    pass
            return datetime.min
        events.sort(key=sort_key)
        return events, format_hint

    @staticmethod
    def _parse_multi_source(content):
        """Parse content with multiple ### SOURCE: blocks.

        Splits content on source markers, detects format for each block,
        parses independently, and merges results.
        """
        all_events = []
        format_counts = Counter()

        # Split on ### SOURCE: markers
        segments = re.split(r'\n*### SOURCE:.*###\n*', content)

        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue

            # Skip very short segments (likely just whitespace or headers)
            if len(segment) < 20:
                continue

            # Detect format for this segment
            try:
                fmt = LogParser.detect_format(segment)
                format_counts[fmt] += 1

                parsers = {
                    'cloudtrail': LogParser._parse_cloudtrail,
                    'evtx_xml': LogParser._parse_evtx_xml,
                    'auth_log': LogParser._parse_auth_log,
                    'syslog': LogParser._parse_syslog,
                    'json_log': LogParser._parse_json_generic,
                    'jsonl': LogParser._parse_jsonl,
                    'csv': LogParser._parse_csv,
                    'generic': LogParser._parse_generic,
                }

                parser = parsers.get(fmt, LogParser._parse_generic)
                events = parser(segment)
                all_events.extend(events)

            except Exception:
                # If one segment fails, continue with others
                continue

        # Determine predominant format for display
        if format_counts:
            primary_format = format_counts.most_common(1)[0][0]
            if len(format_counts) > 1:
                primary_format = f"multi({','.join(f'{k}:{v}' for k, v in format_counts.most_common(3))})"
        else:
            primary_format = 'unknown'

        # Sort all events by timestamp
        def sort_key(e):
            if isinstance(e.timestamp, datetime):
                return e.timestamp
            if isinstance(e.timestamp, str) and e.timestamp:
                try:
                    return datetime.fromisoformat(e.timestamp.replace('Z', '+00:00'))
                except:
                    pass
            return datetime.min
        all_events.sort(key=sort_key)

        return all_events, primary_format

    @staticmethod
    def _parse_timestamp_syslog(ts_str):
        """Parse syslog-style timestamp (e.g., 'Jan  5 14:32:01')."""
        current_year = datetime.now().year
        formats = [
            f"%b %d %H:%M:%S",
            f"%b  %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                return dt.replace(year=current_year)
            except ValueError:
                continue
        # ISO format
        try:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except:
            pass
        return ts_str

    @staticmethod
    def _parse_auth_log(content):
        """Parse Linux auth.log / secure log."""
        events = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

            event = LogEvent(raw=line, source_type='auth_log')

            # Try both syslog patterns
            m = LogParser.SYSLOG_PAT.match(line)
            if not m:
                m = LogParser.SYSLOG_ISO_PAT.match(line)
            if m:
                event.timestamp = LogParser._parse_timestamp_syslog(m.group('timestamp'))
                event.hostname = m.group('hostname')
                event.service = m.group('service')
                event.pid = m.group('pid') or ''
                event.message = m.group('message')
            else:
                event.message = line

            msg = event.message

            # Extract IPs
            ips = LogParser.IP_PAT.findall(msg)
            if ips:
                event.source_ip = ips[0]

            # Extract port
            port_m = LogParser.AUTH_PORT_PAT.search(msg)
            if port_m:
                event.port = port_m.group(1)

            # Determine action and status
            if LogParser.AUTH_FAIL_PAT.search(msg):
                event.action = 'login_failed'
                event.status = 'failure'
                event.severity = 'WARNING'
            elif LogParser.AUTH_SUCCESS_PAT.search(msg):
                event.action = 'login_success'
                event.status = 'success'
                event.severity = 'INFO'
            elif LogParser.AUTH_SUDO_PAT.search(msg):
                sudo_m = LogParser.AUTH_SUDO_PAT.search(msg)
                event.action = 'sudo_command'
                event.status = 'success'
                event.username = sudo_m.group(1)
                event.extra = {'command': sudo_m.group(2).strip()}
                event.severity = 'WARNING'
            elif LogParser.AUTH_SU_PAT.search(msg):
                event.action = 'su_session'
                event.status = 'success'
                event.severity = 'WARNING'
            elif LogParser.AUTH_USERADD_PAT.search(msg):
                ua_m = LogParser.AUTH_USERADD_PAT.search(msg)
                event.action = 'user_created'
                event.username = ua_m.group(1)
                event.status = 'success'
                event.severity = 'WARNING'
            elif LogParser.AUTH_USERDEL_PAT.search(msg):
                ud_m = LogParser.AUTH_USERDEL_PAT.search(msg)
                event.action = 'user_deleted'
                event.username = ud_m.group(1)
                event.status = 'success'
                event.severity = 'WARNING'
            elif LogParser.AUTH_GROUPADD_PAT.search(msg):
                event.action = 'group_modified'
                event.status = 'success'
                event.severity = 'WARNING'
            elif LogParser.AUTH_PASSWD_PAT.search(msg):
                event.action = 'password_change'
                event.status = 'success'
                event.severity = 'INFO'
            elif LogParser.AUTH_KEY_PAT.search(msg):
                event.action = 'key_auth'
                event.status = 'success'
                event.severity = 'INFO'
            elif LogParser.AUTH_DISCONNECT_PAT.search(msg):
                event.action = 'disconnect'
                event.status = 'info'
                event.severity = 'INFO'
            elif 'session opened' in msg.lower():
                event.action = 'session_opened'
                event.status = 'success'
                event.severity = 'INFO'
            elif 'session closed' in msg.lower():
                event.action = 'session_closed'
                event.status = 'info'
                event.severity = 'INFO'
            else:
                event.action = 'other'
                event.status = 'info'
                event.severity = 'INFO'

            # Extract username if not set
            if not event.username:
                user_m = LogParser.AUTH_USER_PAT.search(msg)
                if user_m:
                    event.username = user_m.group(1)

            events.append(event)
        return events

    @staticmethod
    def _parse_syslog(content):
        """Parse generic syslog messages."""
        events = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            event = LogEvent(raw=line, source_type='syslog')
            m = LogParser.SYSLOG_PAT.match(line)
            if not m:
                m = LogParser.SYSLOG_ISO_PAT.match(line)
            if m:
                event.timestamp = LogParser._parse_timestamp_syslog(m.group('timestamp'))
                event.hostname = m.group('hostname')
                event.service = m.group('service')
                event.pid = m.group('pid') or ''
                event.message = m.group('message')
            else:
                event.message = line

            ips = LogParser.IP_PAT.findall(event.message)
            if ips:
                event.source_ip = ips[0]
                if len(ips) > 1:
                    event.dest_ip = ips[1]

            # Classify by keywords
            msg_lower = event.message.lower()
            if any(k in msg_lower for k in ['error', 'fail', 'denied', 'reject', 'refused']):
                event.severity = 'WARNING'
                event.status = 'failure'
            elif any(k in msg_lower for k in ['critical', 'emergency', 'alert', 'panic']):
                event.severity = 'CRITICAL'
                event.status = 'failure'
            elif any(k in msg_lower for k in ['warning', 'warn']):
                event.severity = 'WARNING'
                event.status = 'warning'
            else:
                event.severity = 'INFO'
                event.status = 'info'

            event.action = event.service
            events.append(event)
        return events

    @staticmethod
    def _parse_evtx_xml(content):
        """Parse Windows Event Log XML export (wevtutil / PowerShell output)."""
        events = []

        # Skip non-XML content
        content = content.strip()
        if not content:
            return events

        # Find the XML portion if there's non-XML text mixed in
        # wevtutil output may have <Events> wrapper or bare <Event> elements
        xml_start = content.find('<Event')
        if xml_start == -1:
            xml_start = content.find('<Events')
        if xml_start == -1:
            # No XML events found — might be PowerShell text format
            return LogParser._parse_powershell_eventlog(content)

        content = content[xml_start:]

        # Strip XML namespaces — they break simple tag matching
        # Remove xmlns='...' and xmlns:X='...' attributes
        content = re.sub(r'\s+xmlns(?::\w+)?=["\'][^"\']*["\']', '', content)

        # Wrap bare events if needed
        if not content.strip().startswith('<Events'):
            content = f'<Events>{content}</Events>'

        # Clean up common XML issues
        content = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#)', '&amp;', content)

        # Try parsing as one document first
        parsed_root = None
        try:
            parsed_root = ET.fromstring(content)
        except ET.ParseError:
            # If full parse fails, try extracting individual Event elements
            pass

        if parsed_root is not None:
            # Successfully parsed as one XML document
            for evt_elem in parsed_root.iter():
                tag = evt_elem.tag.split('}')[-1] if '}' in evt_elem.tag else evt_elem.tag
                if tag == 'Event':
                    event = LogParser._extract_evtx_event(evt_elem)
                    if event:
                        events.append(event)
        else:
            # Fallback: extract individual <Event>...</Event> blocks with regex
            event_blocks = re.findall(
                r'<Event[^>]*>.*?</Event>',
                content,
                re.DOTALL
            )
            for block in event_blocks:
                # Clean namespace from individual block
                block = re.sub(r'\s+xmlns(?::\w+)?=["\'][^"\']*["\']', '', block)
                try:
                    evt_elem = ET.fromstring(block)
                    event = LogParser._extract_evtx_event(evt_elem)
                    if event:
                        events.append(event)
                except ET.ParseError:
                    continue

        return events

    @staticmethod
    def _extract_evtx_event(evt_elem):
        """Extract a LogEvent from an XML Event element."""
        event = LogEvent(source_type='evtx_xml')

        # Extract System data — handle both namespaced and non-namespaced tags
        for sys_elem in evt_elem.iter():
            tag = sys_elem.tag.split('}')[-1] if '}' in sys_elem.tag else sys_elem.tag

            if tag == 'EventID':
                event.event_id = (sys_elem.text or '').strip()
            elif tag == 'TimeCreated':
                ts = sys_elem.get('SystemTime', '')
                if ts:
                    try:
                        # Handle various timestamp formats from wevtutil
                        ts = ts.rstrip('Z').split('.')[0]  # Remove Z and fractional seconds
                        if 'T' in ts:
                            event.timestamp = datetime.fromisoformat(ts)
                        else:
                            event.timestamp = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            event.timestamp = datetime.fromisoformat(
                                sys_elem.get('SystemTime', '').replace('Z', '+00:00')
                            )
                        except:
                            event.timestamp = ts
            elif tag == 'Computer':
                event.hostname = (sys_elem.text or '').strip()
            elif tag == 'Channel':
                event.service = (sys_elem.text or '').strip()
            elif tag == 'Provider':
                if not event.service:
                    event.service = sys_elem.get('Name', '')
            elif tag == 'Level':
                level = (sys_elem.text or '').strip()
                if level in ('1', '2'):  # Critical, Error
                    event.severity = 'ERROR'
                elif level == '3':  # Warning
                    event.severity = 'WARNING'

        # Skip events with no EventID (not useful)
        if not event.event_id:
            return None

        # Extract EventData
        data_fields = {}
        for data_elem in evt_elem.iter():
            tag = data_elem.tag.split('}')[-1] if '}' in data_elem.tag else data_elem.tag
            if tag == 'Data':
                name = data_elem.get('Name', '')
                value = (data_elem.text or '').strip()
                if name:
                    data_fields[name] = value
                elif value and not name:
                    # Some events have unnamed Data elements
                    data_fields[f'Data_{len(data_fields)}'] = value

        event.extra = data_fields

        # Map Windows event fields
        event.username = data_fields.get('TargetUserName',
                        data_fields.get('SubjectUserName',
                        data_fields.get('UserName', '')))
        event.source_ip = data_fields.get('IpAddress',
                         data_fields.get('SourceAddress',
                         data_fields.get('ClientAddress', '')))
        if event.source_ip in ('-', '::1', '127.0.0.1', ''):
            event.source_ip = ''

        event.port = data_fields.get('IpPort',
                    data_fields.get('SourcePort', ''))

        # Map event ID to action/status
        if event.event_id in LogParser.WINDOWS_EVENTS:
            desc, sev = LogParser.WINDOWS_EVENTS[event.event_id]
            event.action = desc
            event.status = sev
            if sev == 'failure':
                event.severity = 'WARNING'
            elif sev == 'warning':
                event.severity = 'WARNING'
            elif sev == 'critical':
                event.severity = 'CRITICAL'
            elif event.severity not in ('ERROR', 'WARNING', 'CRITICAL'):
                event.severity = 'INFO'
        else:
            event.action = f'EventID_{event.event_id}'
            if event.severity not in ('ERROR', 'WARNING', 'CRITICAL'):
                event.severity = 'INFO'

        # Add logon type context
        logon_type = data_fields.get('LogonType', '')
        if logon_type in LogParser.LOGON_TYPES:
            event.extra['logon_type_name'] = LogParser.LOGON_TYPES[logon_type]

        event.message = f"[{event.event_id}] {event.action}"
        if event.username:
            event.message += f" - User: {event.username}"
        if event.source_ip:
            event.message += f" - IP: {event.source_ip}"

        try:
            event.raw = ET.tostring(evt_elem, encoding='unicode', method='xml')[:500]
        except:
            event.raw = str(data_fields)[:500]

        return event

    @staticmethod
    def _parse_powershell_eventlog(content):
        """Parse PowerShell Get-WinEvent text format output.

        Handles output from: Get-WinEvent | Format-List TimeCreated,Id,LevelDisplayName,Message
        """
        events = []
        current = {}

        for line in content.split('\n'):
            line = line.strip()
            if not line:
                if current:
                    # Build event from accumulated fields
                    event = LogEvent(source_type='evtx_xml')
                    if 'TimeCreated' in current:
                        try:
                            ts_str = current['TimeCreated'].strip()
                            # PowerShell format: "2/20/2026 3:45:12 PM" or ISO
                            for fmt in [
                                '%m/%d/%Y %I:%M:%S %p',
                                '%m/%d/%Y %H:%M:%S',
                                '%Y-%m-%d %H:%M:%S',
                                '%Y-%m-%dT%H:%M:%S',
                            ]:
                                try:
                                    event.timestamp = datetime.strptime(ts_str, fmt)
                                    break
                                except ValueError:
                                    continue
                        except:
                            event.timestamp = current.get('TimeCreated', '')

                    event.event_id = current.get('Id', '')
                    event.severity = current.get('LevelDisplayName', 'INFO')
                    if event.severity.lower() in ('error', 'critical'):
                        event.severity = 'ERROR'
                    elif event.severity.lower() == 'warning':
                        event.severity = 'WARNING'
                    else:
                        event.severity = 'INFO'

                    event.service = current.get('ProviderName', '')
                    event.message = current.get('Message', '')[:500]

                    if event.event_id in LogParser.WINDOWS_EVENTS:
                        desc, sev = LogParser.WINDOWS_EVENTS[event.event_id]
                        event.action = desc
                        event.status = sev
                    else:
                        event.action = f'EventID_{event.event_id}'

                    # Extract IPs from message
                    ips = LogParser.IP_PAT.findall(event.message)
                    if ips:
                        event.source_ip = ips[0]

                    if event.event_id:
                        events.append(event)

                    current = {}
                continue

            # Parse "Key : Value" lines
            if ' : ' in line:
                parts = line.split(' : ', 1)
                key = parts[0].strip()
                val = parts[1].strip() if len(parts) > 1 else ''
                current[key] = val
            elif current:
                # Continuation of previous field (multi-line message)
                last_key = list(current.keys())[-1] if current else None
                if last_key:
                    current[last_key] += '\n' + line

        # Don't forget the last entry
        if current and current.get('Id'):
            event = LogEvent(source_type='evtx_xml')
            event.event_id = current.get('Id', '')
            event.message = current.get('Message', '')[:500]
            event.service = current.get('ProviderName', '')
            if event.event_id in LogParser.WINDOWS_EVENTS:
                desc, sev = LogParser.WINDOWS_EVENTS[event.event_id]
                event.action = desc
                event.status = sev
            else:
                event.action = f'EventID_{event.event_id}'
            events.append(event)

        return events

    @staticmethod
    def _parse_cloudtrail(content):
        """Parse AWS CloudTrail JSON logs."""
        events = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return events

        records = data.get('Records', [data] if isinstance(data, dict) else data)
        if isinstance(records, dict):
            records = [records]

        for record in records:
            if not isinstance(record, dict):
                continue
            event = LogEvent(source_type='cloudtrail')

            # Timestamp
            ts = record.get('eventTime', '')
            if ts:
                try:
                    event.timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except:
                    event.timestamp = ts

            # Source
            event.source_ip = record.get('sourceIPAddress', '')
            event.service = record.get('eventSource', '')
            event.action = record.get('eventName', '')
            event.hostname = record.get('awsRegion', '')

            # User identity
            user_identity = record.get('userIdentity', {})
            event.username = (user_identity.get('userName', '') or
                            user_identity.get('arn', '').split('/')[-1] if user_identity.get('arn') else '')

            # Status
            error_code = record.get('errorCode', '')
            error_msg = record.get('errorMessage', '')
            if error_code:
                event.status = 'failure'
                event.severity = 'WARNING'
                event.extra = {'errorCode': error_code, 'errorMessage': error_msg}
            else:
                event.status = 'success'
                event.severity = 'INFO'

            # Request parameters for extra context
            req_params = record.get('requestParameters', {})
            resp_elems = record.get('responseElements', {})
            ua = record.get('userAgent', '')

            if req_params:
                event.extra['requestParameters'] = req_params
            if resp_elems:
                event.extra['responseElements'] = resp_elems
            if ua:
                event.extra['userAgent'] = ua

            # Classify severity by action type
            action_lower = event.action.lower()
            high_risk_actions = [
                'delete', 'terminate', 'stop', 'deactivate', 'remove',
                'detach', 'modify', 'update', 'put', 'create',
                'attach', 'associate', 'authorize', 'revoke',
                'disable', 'enable',
            ]
            critical_actions = [
                'deletetrail', 'stoplogging', 'deleteflowlogs',
                'deletebucket', 'putbucketpolicy', 'deletealarm',
                'disablekey', 'schedulekey', 'createuser', 'deleteuser',
                'attachrolepolicy', 'attachuserpolicy', 'createaccesskey',
                'updateaccesskey', 'createloginprofile', 'updateloginprofile',
                'deactivatemfadevice', 'deleteaccesskey',
                'putrolerpolicy', 'putuserpolicy',
            ]

            if action_lower in critical_actions:
                event.severity = 'CRITICAL'
            elif any(action_lower.startswith(a) for a in high_risk_actions):
                event.severity = 'WARNING'

            event.message = f"{event.service}: {event.action}"
            if event.username:
                event.message += f" by {event.username}"
            if error_code:
                event.message += f" [{error_code}]"

            event.raw = json.dumps(record)[:500]
            events.append(event)

        return events

    @staticmethod
    def _parse_json_generic(content):
        """Parse generic JSON log format."""
        events = []
        try:
            data = json.loads(content)
        except:
            return events

        if isinstance(data, dict):
            data = [data]

        for record in data:
            if not isinstance(record, dict):
                continue
            event = LogEvent(source_type='json_log')

            # Try common timestamp fields
            for k in ['timestamp', 'time', '@timestamp', 'datetime', 'date', 'eventTime', 'created_at']:
                if k in record:
                    ts = record[k]
                    if isinstance(ts, str):
                        try:
                            event.timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        except:
                            event.timestamp = ts
                    break

            # Common fields
            for k in ['source_ip', 'src_ip', 'srcip', 'client_ip', 'remote_addr', 'ip', 'sourceIPAddress']:
                if k in record:
                    event.source_ip = str(record[k])
                    break
            for k in ['dest_ip', 'dst_ip', 'dstip', 'destination_ip', 'server_ip']:
                if k in record:
                    event.dest_ip = str(record[k])
                    break
            for k in ['user', 'username', 'user_name', 'userName', 'account']:
                if k in record:
                    event.username = str(record[k])
                    break
            for k in ['action', 'event', 'eventName', 'event_type', 'type', 'method']:
                if k in record:
                    event.action = str(record[k])
                    break
            for k in ['status', 'result', 'outcome', 'response_code']:
                if k in record:
                    event.status = str(record[k])
                    break
            for k in ['message', 'msg', 'log', 'description']:
                if k in record:
                    event.message = str(record[k])
                    break
            for k in ['service', 'source', 'eventSource', 'program', 'facility']:
                if k in record:
                    event.service = str(record[k])
                    break
            for k in ['severity', 'level', 'priority', 'sev']:
                if k in record:
                    event.severity = str(record[k]).upper()
                    break

            if not event.message:
                event.message = json.dumps(record)[:200]

            event.raw = json.dumps(record)[:500]
            event.extra = record
            events.append(event)

        return events

    @staticmethod
    def _parse_jsonl(content):
        """Parse JSON Lines format (one JSON per line)."""
        all_records = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                all_records.append(record)
            except:
                continue
        if all_records:
            return LogParser._parse_json_generic(json.dumps(all_records))
        return []

    @staticmethod
    def _parse_csv(content):
        """Parse CSV log files."""
        events = []
        reader = csv.DictReader(io.StringIO(content))
        records = list(reader)
        if records:
            return LogParser._parse_json_generic(json.dumps(records))
        return events

    @staticmethod
    def _parse_generic(content):
        """Parse unrecognized log format line by line."""
        events = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            event = LogEvent(raw=line, source_type='generic', message=line)

            # Try to find timestamp
            ts_patterns = [
                r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
                r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            ]
            for pat in ts_patterns:
                m = re.search(pat, line)
                if m:
                    event.timestamp = LogParser._parse_timestamp_syslog(m.group(1))
                    break

            ips = LogParser.IP_PAT.findall(line)
            if ips:
                event.source_ip = ips[0]
                if len(ips) > 1:
                    event.dest_ip = ips[1]

            msg_lower = line.lower()
            if any(k in msg_lower for k in ['error', 'fail', 'denied', 'reject']):
                event.severity = 'WARNING'
                event.status = 'failure'
            elif any(k in msg_lower for k in ['critical', 'emergency', 'alert']):
                event.severity = 'CRITICAL'
            else:
                event.severity = 'INFO'
                event.status = 'info'

            events.append(event)
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# GEO-IP LOOKUP ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class GeoIPLookup:
    """Local geo-IP resolution using built-in ranges."""

    _cache = {}

    @classmethod
    def lookup(cls, ip_str):
        if ip_str in cls._cache:
            return cls._cache[ip_str]

        try:
            addr = ip_address(ip_str)
        except ValueError:
            return None

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            result = {"country": "PRIVATE", "city": "Internal", "lat": 0, "lon": 0}
            cls._cache[ip_str] = result
            return result

        for cidr, country, city, lat, lon in GEO_IP_RANGES:
            try:
                if addr in ip_network(cidr, strict=False):
                    result = {"country": country, "city": city, "lat": lat, "lon": lon}
                    cls._cache[ip_str] = result
                    return result
            except:
                continue

        # Default - use first octet heuristic
        first = int(ip_str.split('.')[0])
        if first < 50:
            result = {"country": "US", "city": "Unknown", "lat": 38.0, "lon": -97.0}
        elif first < 100:
            result = {"country": "EU", "city": "Unknown", "lat": 50.0, "lon": 10.0}
        elif first < 130:
            result = {"country": "APAC", "city": "Unknown", "lat": 35.0, "lon": 105.0}
        else:
            result = {"country": "UNKNOWN", "city": "Unknown", "lat": 0, "lon": 0}

        cls._cache[ip_str] = result
        return result

    @staticmethod
    def distance_km(lat1, lon1, lat2, lon2):
        """Haversine formula for distance in km."""
        if lat1 == 0 and lon1 == 0:
            return 0
        if lat2 == 0 and lon2 == 0:
            return 0
        R = 6371
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat/2)**2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon/2)**2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c

    @staticmethod
    def is_in_bad_range(ip_str):
        """Check if IP is in known malicious ranges."""
        try:
            addr = ip_address(ip_str)
        except ValueError:
            return False
        for cidr in KNOWN_BAD_RANGES:
            try:
                if addr in ip_network(cidr, strict=False):
                    return True
            except:
                continue
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatFinding:
    """Represents a single threat finding."""
    def __init__(self, title, description, severity, mitre_id, evidence=None,
                 source_ips=None, usernames=None, timestamps=None, recommendation=""):
        self.id = str(uuid.uuid4())[:8]
        self.title = title
        self.description = description
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.mitre_id = mitre_id
        self.mitre_info = MITRE_ATTACK_DB.get(mitre_id, {})
        self.evidence = evidence or []
        self.source_ips = source_ips or []
        self.usernames = usernames or []
        self.timestamps = timestamps or []
        self.recommendation = recommendation
        self.risk_score = self._calc_risk_score()

    def _calc_risk_score(self):
        base = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10}
        score = base.get(self.severity, 50)
        # Boost for multiple IPs involved
        if len(self.source_ips) > 3:
            score = min(100, score + 10)
        # Boost for multiple users
        if len(self.usernames) > 2:
            score = min(100, score + 5)
        # Boost for known bad IPs
        for ip in self.source_ips:
            if GeoIPLookup.is_in_bad_range(ip):
                score = min(100, score + 15)
                break
        return score


class ThreatHunter:
    """Automated threat hunting across parsed log events."""

    # ── Known-Good Software Whitelists ─────────────────────────────────────
    # Services/drivers from these vendors are legitimate and should not trigger alerts
    KNOWN_GOOD_SERVICES = {
        # Malwarebytes
        'mbamprotection', 'mbamwebprotection', 'mbamupdater', 'mbamchameleon',
        'mbamfarflt', 'mbamswissarmy', 'mbae', 'mwac', 'mbam', 'farflt',
        'malwarebytes anti-exploit', 'malwarebytes updater service',
        'malwarebytes service', 'mbamservice',
        # Bitdefender
        'bdredline', 'bdfndisf6', 'bdprivmon', 'trufos', 'avc3', 'avckf',
        'bdsandbox', 'bdagent', 'bdntwrk', 'bdelam', 'gzflt', 'avchv',
        'bdvedisk', 'bdpfndisf', 'bdfsfltr', 'bdsdkit', 'bdpluginloader',
        'bitdefender', 'bdservicehost',
        # Windows Defender / Microsoft
        'windefend', 'wdfilter', 'wdnisdrv', 'wdnissvc', 'wdboot',
        'msmpeng', 'mssense', 'sensecncproxy', 'sense',
        'microsoft defender', 'windows defender',
        # CrowdStrike
        'csagent', 'csfalconservice', 'csdevicecontrol', 'csfalconcontainer',
        'crowdstrike', 'falcon',
        # SentinelOne
        'sentinelone', 'sentinelagent', 'sentinelmonitor', 'sentinelstaticengine',
        # Carbon Black
        'cbdefense', 'cbstream', 'carbonblack', 'cb.exe',
        # Sophos
        'sophosav', 'sophosfim', 'sophosclean', 'sophosssp',
        'hmpalert', 'sophoshealth', 'sophosntpservice',
        # Norton / Symantec
        'symantec', 'norton', 'sepwscsvr', 'sepmasterservice', 'srtsp',
        'ccsvchst', 'nscsvc', 'symefasi',
        # ESET
        'ekrn', 'eset', 'ehdrv', 'eamonm', 'epfw', 'epfwlwf',
        # Kaspersky
        'avp', 'klnagent', 'kavfs', 'kaspersky',
        # Trend Micro
        'trendmicro', 'tmfilter', 'tmpreflt', 'tmlisten', 'ntrtscan',
        # Avast / AVG
        'avast', 'aswsp', 'aswbidsa', 'aswbids', 'avgntflt', 'avgsvc',
        # Webroot
        'wrsa', 'webroot',
        # Palo Alto / Cortex XDR
        'cyserver', 'cytray', 'traps', 'cortex',
        # Common system services
        'wuauserv', 'trustedinstaller', 'tiworker', 'windows update',
        'windows modules installer', 'bits', 'cryptsvc',
        'windows time', 'w32time', 'spooler', 'wmi performance adapter',
        'task scheduler', 'schedule', 'plug and play', 'umpnpmgr',
        'dhcp client', 'dns client', 'nlasvc',
        # Samsung / common OEM
        'quick share', 'quickshare', 'samsung',
        # Common legitimate tools
        'vmtools', 'vmware', 'vboxservice', 'virtualbox',
        'splashtop', 'teamviewer', 'anydesk', 'bomgar',
        'adobe', 'java', 'oracle',
    }

    # Paths from these directories are generally trustworthy
    KNOWN_GOOD_PATHS = {
        r'c:\windows\system32\drivers',
        r'c:\windows\system32',
        r'c:\program files\malwarebytes',
        r'c:\program files\bitdefender',
        r'c:\program files\windows defender',
        r'c:\program files (x86)\malwarebytes',
        r'c:\program files\common files\microsoft',
        r'c:\program files\microsoft',
        r'c:\programdata\malwarebytes',
        r'c:\programdata\microsoft',
        r'c:\program files\crowdstrike',
        r'c:\program files\sentinelone',
        r'c:\program files\eset',
        r'c:\program files\kaspersky',
        r'c:\program files (x86)\sophos',
        r'c:\program files\vmware',
        r'c:\windows\windowsapps',
    }

    # Windows system accounts that normally get 4672 (Special Privileges)
    SYSTEM_ACCOUNTS = {
        'system', 'local service', 'network service', 'local system',
        'nt authority\\system', 'nt authority\\local service',
        'nt authority\\network service', 'dwm-1', 'dwm-2', 'dwm-3',
        'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
        'font driver host', 'window manager',
    }

    # Minimum attack rate (attempts per minute) to consider brute force
    BRUTE_FORCE_MIN_RATE = 0.5  # At least 1 attempt every 2 minutes
    BRUTE_FORCE_MIN_ATTEMPTS = 5

    def __init__(self, events):
        self.events = events
        self.findings = []

    def hunt_all(self):
        """Run all threat hunting modules."""
        self.findings = []
        self._hunt_brute_force()
        self._hunt_password_spraying()
        self._hunt_priv_escalation()
        self._hunt_lateral_movement()
        self._hunt_impossible_travel()
        self._hunt_account_manipulation()
        self._hunt_log_tampering()
        self._hunt_suspicious_services()
        self._hunt_unusual_hours()
        self._hunt_known_bad_ips()
        self._hunt_credential_abuse()
        self._hunt_cloud_threats()
        self._hunt_recon_activity()

        # Sort by risk score
        self.findings.sort(key=lambda f: f.risk_score, reverse=True)
        return self.findings

    def _hunt_brute_force(self):
        """Detect brute force login attempts."""
        # Group failures by target user and source IP
        fail_by_ip_user = defaultdict(list)
        success_after_fail = defaultdict(list)

        for e in self.events:
            if e.action in ('login_failed', 'Failed Logon') or e.status == 'failure':
                key = (e.source_ip or 'unknown', e.username or 'unknown')
                fail_by_ip_user[key].append(e)
            elif e.action in ('login_success', 'Successful Logon') or (e.status == 'success' and 'login' in str(e.action).lower()):
                key = (e.source_ip or 'unknown', e.username or 'unknown')
                success_after_fail[key].append(e)

        for (ip, user), failures in fail_by_ip_user.items():
            if len(failures) >= self.BRUTE_FORCE_MIN_ATTEMPTS:
                # Check time window
                timestamps = []
                for f in failures:
                    if isinstance(f.timestamp, datetime):
                        timestamps.append(f.timestamp)

                window_desc = ""
                rate = 0.0
                if len(timestamps) >= 2:
                    span = (max(timestamps) - min(timestamps)).total_seconds()
                    window_desc = f" over {self._format_duration(span)}"
                    if span > 0:
                        rate = len(failures) / (span / 60)

                # Skip if rate is too low (normal typos, not an attack)
                # Exception: still flag if there's a success after failures (compromise)
                compromised = (ip, user) in success_after_fail
                if rate < self.BRUTE_FORCE_MIN_RATE and not compromised and len(timestamps) >= 2:
                    continue
                sev = "CRITICAL" if compromised else "HIGH"
                title = f"Brute Force {'→ COMPROMISED' if compromised else 'Attack'}: {user}@{ip}"

                evidence = [f"  {len(failures)} failed attempts{window_desc}"]
                if compromised:
                    evidence.append(f"  ⚠ SUCCESSFUL LOGIN DETECTED after failures")

                if rate > 0:
                    evidence.append(f"  Attack rate: {rate:.1f} attempts/min")

                geo = GeoIPLookup.lookup(ip)
                if geo and geo['country'] not in ('PRIVATE', 'LOCAL'):
                    evidence.append(f"  Source: {geo['city']}, {geo['country']}")

                if GeoIPLookup.is_in_bad_range(ip):
                    evidence.append(f"  ⚠ IP {ip} is in known malicious range!")

                desc = f"Detected {len(failures)} failed login attempts for user '{user}' from {ip}{window_desc}."
                if compromised:
                    desc += " A successful login followed the brute force attempts, indicating account compromise."

                rec = "Immediately reset credentials for affected account. " if compromised else ""
                rec += "Block source IP at firewall. Review account for unauthorized access. Implement account lockout policies and MFA."

                self.findings.append(ThreatFinding(
                    title=title, description=desc, severity=sev,
                    mitre_id="T1110",
                    evidence=evidence,
                    source_ips=[ip], usernames=[user],
                    timestamps=[str(f.timestamp) for f in failures[:10]],
                    recommendation=rec
                ))

    def _hunt_password_spraying(self):
        """Detect password spraying (many users, few attempts each, same source)."""
        fail_by_ip = defaultdict(lambda: defaultdict(list))

        for e in self.events:
            if e.action in ('login_failed', 'Failed Logon') or e.status == 'failure':
                if e.source_ip and e.username:
                    fail_by_ip[e.source_ip][e.username].append(e)

        for ip, user_fails in fail_by_ip.items():
            if len(user_fails) >= 4:
                # Multiple users, few attempts each = spraying
                max_per_user = max(len(v) for v in user_fails.values())
                if max_per_user <= 3:
                    users = list(user_fails.keys())
                    total = sum(len(v) for v in user_fails.values())

                    evidence = [
                        f"  {total} failed attempts across {len(users)} unique users",
                        f"  Max {max_per_user} attempts per user (spraying pattern)",
                        f"  Targeted users: {', '.join(users[:10])}"
                    ]

                    geo = GeoIPLookup.lookup(ip)
                    if geo and geo['country'] not in ('PRIVATE', 'LOCAL'):
                        evidence.append(f"  Source: {geo['city']}, {geo['country']}")

                    self.findings.append(ThreatFinding(
                        title=f"Password Spraying Detected from {ip}",
                        description=f"Detected password spraying pattern: {total} failures across {len(users)} users from single source {ip}.",
                        severity="HIGH",
                        mitre_id="T1110",
                        evidence=evidence,
                        source_ips=[ip], usernames=users[:20],
                        recommendation="Block source IP. Enforce account lockout. Deploy MFA. Check if any targeted accounts were subsequently compromised."
                    ))

    def _hunt_priv_escalation(self):
        """Detect privilege escalation chains."""
        # Track sudo usage, user creation, group changes
        priv_events = []
        for e in self.events:
            # Skip system accounts getting routine 4672 (Special Privileges Assigned)
            # This is normal Windows behavior for SYSTEM, LOCAL SERVICE, etc.
            if e.event_id == '4672':
                user_lower = (e.username or '').lower().strip()
                if user_lower in self.SYSTEM_ACCOUNTS or not user_lower:
                    continue

            if e.action in ('sudo_command', 'su_session', 'user_created', 'group_modified',
                          'Special Privileges Assigned', 'Member Added to Security Group',
                          'Member Added to Local Group', 'User Account Created',
                          'password_change', 'Password Reset Attempt'):
                priv_events.append(e)

            # Windows specific
            if e.event_id in ('4672', '4728', '4732', '4720', '4724'):
                priv_events.append(e)

            # CloudTrail IAM
            if e.source_type == 'cloudtrail' and e.action:
                action_lower = e.action.lower()
                if any(k in action_lower for k in ['attachpolicy', 'putpolicy', 'createrole',
                    'createuser', 'adduser', 'createaccesskey', 'createloginprofile',
                    'updaterole', 'putrolepolicy', 'attachuserpolicy', 'attachgrouppolicy']):
                    priv_events.append(e)

        if len(priv_events) >= 2:
            # Group by user
            by_user = defaultdict(list)
            for e in priv_events:
                u = e.username or 'unknown'
                by_user[u].append(e)

            for user, events in by_user.items():
                if len(events) >= 2:
                    evidence = []
                    for e in events[:15]:
                        ts = str(e.timestamp)[:19] if isinstance(e.timestamp, datetime) else str(e.timestamp)
                        evidence.append(f"  [{ts}] {e.action}: {e.message[:100]}")

                    # Check for escalation chain patterns
                    actions = [e.action for e in events]
                    chain_detected = False
                    chain_desc = ""

                    if 'login_success' in actions or 'Successful Logon' in actions:
                        if 'sudo_command' in actions or 'Special Privileges Assigned' in actions:
                            chain_detected = True
                            chain_desc = "Login → Privilege Escalation"
                    if 'user_created' in actions or 'User Account Created' in actions:
                        if 'group_modified' in actions or 'Member Added to Security Group' in actions:
                            chain_detected = True
                            chain_desc = "Account Creation → Group Addition"

                    sev = "HIGH" if chain_detected else "MEDIUM"
                    title = f"Privilege Escalation {'Chain' if chain_detected else 'Activity'}: {user}"
                    if chain_desc:
                        title += f" ({chain_desc})"

                    self.findings.append(ThreatFinding(
                        title=title,
                        description=f"Detected {len(events)} privilege-related events for user '{user}'.",
                        severity=sev,
                        mitre_id="T1548",
                        evidence=evidence,
                        usernames=[user],
                        recommendation="Audit all privilege changes for this user. Verify authorization for each escalation. Review sudo/admin logs."
                    ))

    def _hunt_lateral_movement(self):
        """Detect lateral movement patterns."""
        # Track successful logins from internal IPs to multiple hosts
        logins_by_user = defaultdict(list)

        for e in self.events:
            if e.action in ('login_success', 'Successful Logon', 'session_opened') or \
               (e.status == 'success' and e.event_id in ('4624', '4648')):
                if e.username:
                    logins_by_user[e.username].append(e)

        for user, logins in logins_by_user.items():
            # Check for multiple source IPs or hosts
            source_ips = set()
            dest_hosts = set()
            rdp_sessions = []
            smb_sessions = []

            for e in logins:
                if e.source_ip:
                    source_ips.add(e.source_ip)
                if e.hostname:
                    dest_hosts.add(e.hostname)

                # Check for RDP (logon type 10)
                lt = e.extra.get('LogonType', '') if isinstance(e.extra, dict) else ''
                if lt == '10' or 'RemoteInteractive' in str(e.extra):
                    rdp_sessions.append(e)
                elif lt == '3' or 'Network' in str(e.extra):
                    smb_sessions.append(e)

            # Multiple hosts accessed = lateral movement
            if len(dest_hosts) >= 3 or (len(source_ips) >= 2 and len(dest_hosts) >= 2):
                evidence = [
                    f"  User accessed {len(dest_hosts)} distinct hosts",
                    f"  From {len(source_ips)} source IPs",
                    f"  Hosts: {', '.join(list(dest_hosts)[:8])}",
                    f"  Sources: {', '.join(list(source_ips)[:8])}"
                ]
                if rdp_sessions:
                    evidence.append(f"  {len(rdp_sessions)} RDP sessions detected")
                if smb_sessions:
                    evidence.append(f"  {len(smb_sessions)} SMB/Network logon sessions")

                mitre = "T1021"
                if rdp_sessions:
                    evidence.append(f"  Sub-technique: T1021.001 (Remote Desktop Protocol)")
                elif smb_sessions:
                    evidence.append(f"  Sub-technique: T1021.002 (SMB/Windows Admin Shares)")

                self.findings.append(ThreatFinding(
                    title=f"Lateral Movement Detected: {user}",
                    description=f"User '{user}' accessed {len(dest_hosts)} hosts from {len(source_ips)} sources, indicating potential lateral movement.",
                    severity="HIGH",
                    mitre_id=mitre,
                    evidence=evidence,
                    source_ips=list(source_ips),
                    usernames=[user],
                    recommendation="Investigate all accessed hosts for compromise. Review what actions were performed. Check for data exfiltration."
                ))

    def _hunt_impossible_travel(self):
        """Detect impossible travel - logins from geographically distant locations in short time."""
        logins_by_user = defaultdict(list)

        for e in self.events:
            if (e.action in ('login_success', 'Successful Logon', 'key_auth') or
                (e.status == 'success' and 'login' in str(e.action).lower())):
                if e.source_ip and isinstance(e.timestamp, datetime):
                    geo = GeoIPLookup.lookup(e.source_ip)
                    if geo and geo['country'] not in ('PRIVATE', 'LOCAL', 'UNKNOWN'):
                        logins_by_user[e.username or 'unknown'].append((e, geo))

        for user, login_list in logins_by_user.items():
            # Sort by time
            login_list.sort(key=lambda x: x[0].timestamp)

            for i in range(1, len(login_list)):
                e1, geo1 = login_list[i-1]
                e2, geo2 = login_list[i]

                dist = GeoIPLookup.distance_km(geo1['lat'], geo1['lon'], geo2['lat'], geo2['lon'])
                time_diff = (e2.timestamp - e1.timestamp).total_seconds()

                if dist > 500 and time_diff > 0 and time_diff < 7200:  # >500km in <2hr
                    speed_kmh = (dist / time_diff) * 3600 if time_diff > 0 else float('inf')

                    if speed_kmh > 1000:  # Faster than commercial aviation
                        evidence = [
                            f"  Login 1: {geo1['city']}, {geo1['country']} ({e1.source_ip}) at {str(e1.timestamp)[:19]}",
                            f"  Login 2: {geo2['city']}, {geo2['country']} ({e2.source_ip}) at {str(e2.timestamp)[:19]}",
                            f"  Distance: {dist:.0f} km",
                            f"  Time gap: {self._format_duration(time_diff)}",
                            f"  Required speed: {speed_kmh:.0f} km/h (impossible by conventional travel)",
                        ]

                        self.findings.append(ThreatFinding(
                            title=f"Impossible Travel: {user}",
                            description=f"User '{user}' logged in from {geo1['city']}, {geo1['country']} and {geo2['city']}, {geo2['country']} ({dist:.0f}km apart) within {self._format_duration(time_diff)}.",
                            severity="CRITICAL",
                            mitre_id="T1078",
                            evidence=evidence,
                            source_ips=[e1.source_ip, e2.source_ip],
                            usernames=[user],
                            recommendation="One of these sessions is likely unauthorized. Investigate both. Reset credentials. Enable MFA. Check for VPN/proxy usage."
                        ))

    def _hunt_account_manipulation(self):
        """Detect suspicious account manipulation."""
        create_events = []
        for e in self.events:
            if e.action in ('user_created', 'User Account Created') or e.event_id == '4720':
                create_events.append(e)

        # Account creation outside business hours or from unusual sources
        for e in create_events:
            suspicious = False
            reasons = []

            if isinstance(e.timestamp, datetime):
                hour = e.timestamp.hour
                if hour < 6 or hour > 22:
                    suspicious = True
                    reasons.append(f"Created at {hour:02d}:{e.timestamp.minute:02d} (outside business hours)")

            if e.source_ip:
                geo = GeoIPLookup.lookup(e.source_ip)
                if geo and geo['country'] not in ('PRIVATE', 'LOCAL', 'US', 'UNKNOWN'):
                    suspicious = True
                    reasons.append(f"Created from foreign IP: {e.source_ip} ({geo['country']})")

                if GeoIPLookup.is_in_bad_range(e.source_ip):
                    suspicious = True
                    reasons.append(f"Created from known malicious IP: {e.source_ip}")

            if suspicious:
                evidence = [f"  {r}" for r in reasons]
                evidence.append(f"  Account: {e.username or 'unknown'}")

                self.findings.append(ThreatFinding(
                    title=f"Suspicious Account Creation: {e.username}",
                    description=f"Account '{e.username}' created under suspicious circumstances.",
                    severity="HIGH",
                    mitre_id="T1136",
                    evidence=evidence,
                    usernames=[e.username or 'unknown'],
                    recommendation="Verify this account creation was authorized. Check for additional persistence mechanisms."
                ))

    def _hunt_log_tampering(self):
        """Detect log clearing and tampering."""
        # Track 1102 events to deduplicate and add context
        tamper_events = []

        for e in self.events:
            tamper = False
            if e.event_id == '1102':
                tamper = True
            if e.action and any(k in str(e.action).lower() for k in
                              ['clear', 'wipe', 'delete log', 'stoplogging', 'deletetrail',
                               'deleteflowlogs', 'disablelogging']):
                tamper = True
            if e.message and any(k in e.message.lower() for k in
                               ['log cleared', 'audit log was cleared', 'event log cleared']):
                tamper = True

            if tamper:
                tamper_events.append(e)

        if not tamper_events:
            return

        # Group by user to deduplicate
        by_user = defaultdict(list)
        for e in tamper_events:
            u = (e.username or 'unknown').lower().strip()
            by_user[u].append(e)

        for user, events in by_user.items():
            # Determine if this is routine or suspicious
            is_system = user in self.SYSTEM_ACCOUNTS or user in ('unknown', '')

            # If SYSTEM cleared logs, it's likely routine Windows maintenance
            # Still report it but at lower severity
            if is_system:
                severity = "MEDIUM"
                title = "Log Clearing Detected (System/Routine)"
                desc = (
                    f"The audit log was cleared {len(events)} time(s) by SYSTEM or "
                    f"during routine maintenance. This is common after Windows Update, "
                    f"AV updates, or scheduled maintenance. Review if unexpected."
                )
                rec = (
                    "Likely routine if correlated with Windows Update or AV update cycles. "
                    "Verify no other suspicious activity occurred around these times. "
                    "Consider forwarding logs to a SIEM to preserve copies."
                )
            else:
                severity = "CRITICAL"
                title = f"Log Tampering / Evidence Destruction by {user}"
                desc = (
                    f"User '{user}' cleared the audit log {len(events)} time(s). "
                    f"Log clearing by a named user account is a strong indicator of "
                    f"post-compromise activity or insider threat."
                )
                rec = (
                    "Treat as confirmed incident. Preserve remaining logs. "
                    "Check backup/SIEM for original logs. "
                    "Investigate all activity from this user before and after the clearing event."
                )

            evidence = []
            for e in events[:5]:
                ts = str(e.timestamp)[:19] if isinstance(e.timestamp, datetime) else str(e.timestamp)
                evidence.append(f"  Event: {e.action or 'Audit Log Cleared'}")
                evidence.append(f"  User: {e.username or 'SYSTEM'}")
                evidence.append(f"  Time: {ts}")
                if e.source_ip:
                    evidence.append(f"  Source: {e.source_ip}")

            if len(events) > 5:
                evidence.append(f"  ... and {len(events) - 5} more clearing events")

            self.findings.append(ThreatFinding(
                title=title,
                description=desc,
                severity=severity,
                mitre_id="T1070",
                evidence=evidence,
                source_ips=[e.source_ip for e in events if e.source_ip],
                usernames=[user] if user != 'unknown' else [],
                recommendation=rec,
            ))

    def _hunt_suspicious_services(self):
        """Detect suspicious service installations and scheduled tasks.

        Uses known-good software whitelists to suppress false positives from
        legitimate AV/EDR products, Windows system services, and common software.
        Deduplicates repeated service reinstalls (e.g., Malwarebytes driver reloads).
        """
        seen_services = set()  # Deduplicate by service name

        for e in self.events:
            if e.event_id in ('7045', '4697', '4698', '4700'):
                svc_name = ''
                img_path = ''
                if isinstance(e.extra, dict):
                    svc_name = e.extra.get('ServiceName', e.extra.get('TaskName', ''))
                    img_path = e.extra.get('ImagePath', e.extra.get('ActionName', ''))

                # ── Whitelist Check ──
                svc_lower = svc_name.lower().strip()
                path_lower = img_path.lower().strip().strip('"')

                # Check service name against known-good list
                is_known_good = False
                for known in self.KNOWN_GOOD_SERVICES:
                    if known in svc_lower or svc_lower in known:
                        is_known_good = True
                        break

                # Check path against known-good directories
                if not is_known_good and path_lower:
                    for known_path in self.KNOWN_GOOD_PATHS:
                        if path_lower.startswith(known_path):
                            is_known_good = True
                            break

                # Skip known-good services entirely
                if is_known_good:
                    continue

                # ── Deduplication ──
                dedup_key = svc_lower or path_lower or str(e.timestamp)
                if dedup_key in seen_services:
                    continue
                seen_services.add(dedup_key)

                # ── Build finding ──
                evidence = [
                    f"  Event: {e.action}",
                    f"  User: {e.username or 'unknown'}",
                ]
                if svc_name:
                    evidence.append(f"  Service/Task: {svc_name}")
                if img_path:
                    evidence.append(f"  Path: {img_path}")

                # Flag extra suspicious indicators
                severity = "MEDIUM"
                suspicious_indicators = []

                if img_path:
                    # Suspicious path patterns
                    sus_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\public\\',
                                 '\\downloads\\', '\\users\\public\\', '\\\\\\\\']
                    for sp in sus_paths:
                        if sp in path_lower:
                            suspicious_indicators.append(f"Suspicious path: {sp}")
                            severity = "HIGH"
                            break

                    # No extension or unusual extension
                    if path_lower.endswith(('.ps1', '.vbs', '.bat', '.cmd', '.js', '.wsh')):
                        suspicious_indicators.append("Script-based service (unusual)")
                        severity = "HIGH"

                if suspicious_indicators:
                    evidence.extend([f"  ⚠ {s}" for s in suspicious_indicators])

                mitre = "T1053" if e.event_id in ('4698', '4700') else "T1569"

                self.findings.append(ThreatFinding(
                    title=f"Suspicious {'Scheduled Task' if e.event_id in ('4698', '4700') else 'Service'}: {svc_name or e.action}",
                    description=f"New service or scheduled task detected that is not in the known-good software whitelist.",
                    severity=severity,
                    mitre_id=mitre,
                    evidence=evidence,
                    usernames=[e.username] if e.username else [],
                    recommendation="Verify this service/task is legitimate. Check the binary path for known malware signatures."
                ))

    def _hunt_unusual_hours(self):
        """Detect login activity during unusual hours."""
        off_hours = defaultdict(list)

        for e in self.events:
            if e.action in ('login_success', 'Successful Logon', 'session_opened'):
                if isinstance(e.timestamp, datetime):
                    hour = e.timestamp.hour
                    if hour < 5 or hour > 23:
                        off_hours[e.username or 'unknown'].append(e)

        for user, events in off_hours.items():
            if len(events) >= 2:
                evidence = []
                for ev in events[:8]:
                    ts = str(ev.timestamp)[:19]
                    evidence.append(f"  [{ts}] from {ev.source_ip or 'local'}")

                self.findings.append(ThreatFinding(
                    title=f"Off-Hours Activity: {user}",
                    description=f"User '{user}' had {len(events)} successful logins during unusual hours (midnight-5AM).",
                    severity="LOW",
                    mitre_id="T1078",
                    evidence=evidence,
                    usernames=[user],
                    source_ips=list(set(e.source_ip for e in events if e.source_ip)),
                    recommendation="Verify if this user normally works these hours. Check for automation or compromised credentials."
                ))

    def _hunt_known_bad_ips(self):
        """Flag any activity from known malicious IP ranges."""
        bad_ip_events = defaultdict(list)

        for e in self.events:
            if e.source_ip and GeoIPLookup.is_in_bad_range(e.source_ip):
                bad_ip_events[e.source_ip].append(e)

        for ip, events in bad_ip_events.items():
            geo = GeoIPLookup.lookup(ip)
            evidence = [
                f"  IP: {ip} — Known malicious range",
                f"  Location: {geo['city']}, {geo['country']}" if geo else f"  IP: {ip}",
                f"  {len(events)} events from this source",
            ]
            actions = Counter(e.action for e in events if e.action)
            for action, count in actions.most_common(5):
                evidence.append(f"    {action}: {count}")

            self.findings.append(ThreatFinding(
                title=f"Known Malicious IP: {ip}",
                description=f"Activity detected from {ip}, which is in a known malicious IP range (threat intel match).",
                severity="HIGH",
                mitre_id="T1071",
                evidence=evidence,
                source_ips=[ip],
                recommendation="Block this IP immediately. Investigate all sessions. Check for data exfiltration. Update firewall rules."
            ))

    def _hunt_credential_abuse(self):
        """Detect credential abuse patterns."""
        # Kerberos ticket anomalies (Windows)
        for e in self.events:
            if e.event_id == '4771':
                self.findings.append(ThreatFinding(
                    title=f"Kerberos Pre-Auth Failure: {e.username}",
                    description=f"Kerberos pre-authentication failed for '{e.username}', may indicate ticket forgery attempt.",
                    severity="MEDIUM",
                    mitre_id="T1558",
                    evidence=[f"  User: {e.username}", f"  Source: {e.source_ip or 'unknown'}"],
                    usernames=[e.username] if e.username else [],
                    recommendation="Check for Kerberoasting or Golden Ticket attacks. Review DC logs."
                ))

        # Multiple explicit credential logons (T1550)
        explicit_creds = [e for e in self.events if e.event_id == '4648']
        if len(explicit_creds) >= 3:
            users = list(set(e.username for e in explicit_creds if e.username))
            self.findings.append(ThreatFinding(
                title=f"Explicit Credential Usage Spike",
                description=f"{len(explicit_creds)} logons using explicit credentials detected. May indicate pass-the-hash or credential relay.",
                severity="MEDIUM",
                mitre_id="T1550",
                evidence=[f"  {len(explicit_creds)} events", f"  Users: {', '.join(users[:10])}"],
                usernames=users,
                recommendation="Investigate explicit credential use. Look for NTLM relay or pass-the-hash activity."
            ))

    def _hunt_cloud_threats(self):
        """Detect cloud-specific threats (CloudTrail)."""
        ct_events = [e for e in self.events if e.source_type == 'cloudtrail']
        if not ct_events:
            return

        # Detect MFA tampering
        for e in ct_events:
            if e.action and 'deactivatemfa' in e.action.lower():
                self.findings.append(ThreatFinding(
                    title=f"MFA Deactivated: {e.username}",
                    description=f"MFA was deactivated by '{e.username}'. This could enable unauthorized access.",
                    severity="CRITICAL",
                    mitre_id="T1556",
                    evidence=[f"  Action: {e.action}", f"  User: {e.username}", f"  Source: {e.source_ip}"],
                    source_ips=[e.source_ip] if e.source_ip else [],
                    usernames=[e.username] if e.username else [],
                    recommendation="Investigate immediately. Re-enable MFA. Check for unauthorized access after deactivation."
                ))

        # Detect logging disabled
        for e in ct_events:
            if e.action and any(k in e.action.lower() for k in ['stoplogging', 'deletetrail', 'puteventsselectors']):
                self.findings.append(ThreatFinding(
                    title=f"Cloud Logging Modified: {e.action}",
                    description=f"CloudTrail logging was modified/disabled by '{e.username}'. Critical anti-forensics activity.",
                    severity="CRITICAL",
                    mitre_id="T1562",
                    evidence=[f"  Action: {e.action}", f"  User: {e.username}",
                             f"  Region: {e.hostname}", f"  Source: {e.source_ip}"],
                    source_ips=[e.source_ip] if e.source_ip else [],
                    usernames=[e.username] if e.username else [],
                    recommendation="Treat as confirmed incident. Restore logging. Investigate all prior activity from this identity."
                ))

        # Detect unusual region usage
        regions = Counter(e.hostname for e in ct_events if e.hostname)
        if len(regions) > 1:
            # Check for activity in unusual regions
            region_events = defaultdict(list)
            for e in ct_events:
                if e.hostname:
                    region_events[e.hostname].append(e)

            main_regions = [r for r, c in regions.most_common(2)]
            unusual = [r for r in regions if r not in main_regions and regions[r] < 5]
            for region in unusual:
                evts = region_events[region]
                evidence = [f"  Region: {region} ({len(evts)} events)",
                           f"  Primary regions: {', '.join(main_regions)}"]
                for ev in evts[:5]:
                    evidence.append(f"    {ev.action} by {ev.username}")

                self.findings.append(ThreatFinding(
                    title=f"Unusual Cloud Region Activity: {region}",
                    description=f"Activity detected in unusual region '{region}' while primary activity is in {', '.join(main_regions)}.",
                    severity="MEDIUM",
                    mitre_id="T1535",
                    evidence=evidence,
                    recommendation="Verify if this region is authorized for your organization. Check for shadow IT or adversary staging."
                ))

        # Detect IAM key creation
        for e in ct_events:
            if e.action and 'createaccesskey' in e.action.lower():
                self.findings.append(ThreatFinding(
                    title=f"New IAM Access Key Created",
                    description=f"New access key created by '{e.username}' for IAM operations.",
                    severity="MEDIUM",
                    mitre_id="T1098",
                    evidence=[f"  Action: {e.action}", f"  User: {e.username}",
                             f"  Source: {e.source_ip}", f"  Region: {e.hostname}"],
                    source_ips=[e.source_ip] if e.source_ip else [],
                    usernames=[e.username] if e.username else [],
                    recommendation="Verify key creation was authorized. Monitor key usage for anomalies."
                ))

    def _hunt_recon_activity(self):
        """Detect reconnaissance and discovery activity."""
        recon_events = []
        for e in self.events:
            if e.source_type == 'cloudtrail' and e.action:
                action_lower = e.action.lower()
                recon_actions = ['describe', 'list', 'get', 'lookup']
                if any(action_lower.startswith(a) for a in recon_actions):
                    recon_events.append(e)

        if not recon_events:
            return

        # Group by user
        by_user = defaultdict(list)
        for e in recon_events:
            by_user[e.username or 'unknown'].append(e)

        for user, events in by_user.items():
            # Many different describe/list calls = recon
            unique_actions = set(e.action for e in events)
            if len(unique_actions) >= 8:
                evidence = [
                    f"  {len(unique_actions)} unique discovery actions",
                    f"  Total events: {len(events)}",
                    f"  Sample actions:"
                ]
                for action in list(unique_actions)[:10]:
                    evidence.append(f"    - {action}")

                self.findings.append(ThreatFinding(
                    title=f"Cloud Reconnaissance: {user}",
                    description=f"User '{user}' performed {len(unique_actions)} unique discovery/enumeration actions, suggesting reconnaissance activity.",
                    severity="MEDIUM",
                    mitre_id="T1087",
                    evidence=evidence,
                    usernames=[user],
                    recommendation="Review if this user typically performs broad enumeration. May indicate compromised credentials being explored."
                ))

    @staticmethod
    def _format_duration(seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        elif seconds < 86400:
            return f"{seconds/3600:.1f}h"
        else:
            return f"{seconds/86400:.1f}d"


# ═══════════════════════════════════════════════════════════════════════════════
# IOC EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class IOCExtractor:
    """Extract Indicators of Compromise from log events."""

    IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    DOMAIN_RE = re.compile(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
    URL_RE = re.compile(r'https?://[^\s<>"\']+')
    AWS_KEY_RE = re.compile(r'AKIA[0-9A-Z]{16}')
    PRIV_KEY_RE = re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----')

    @classmethod
    def extract(cls, events):
        iocs = {
            'ips': Counter(),
            'domains': Counter(),
            'emails': Counter(),
            'hashes_md5': Counter(),
            'hashes_sha1': Counter(),
            'hashes_sha256': Counter(),
            'urls': Counter(),
            'aws_keys': Counter(),
            'private_keys': 0,
            'usernames': Counter(),
        }

        exclude_domains = {'localhost', 'localdomain', 'internal', 'local', 'example.com',
                          'amazonaws.com', 'cloudfront.net', 'signin.aws.amazon.com'}

        for e in events:
            text = e.raw or e.message or ''

            for ip in cls.IP_RE.findall(text):
                try:
                    addr = ip_address(ip)
                    if not addr.is_private and not addr.is_loopback:
                        iocs['ips'][ip] += 1
                except:
                    pass

            if e.source_ip:
                try:
                    addr = ip_address(e.source_ip)
                    if not addr.is_private and not addr.is_loopback:
                        iocs['ips'][e.source_ip] += 1
                except:
                    pass

            for m in cls.DOMAIN_RE.finditer(text):
                domain = m.group(0).lower().rstrip('.')
                if domain not in exclude_domains and '.' in domain:
                    iocs['domains'][domain] += 1

            for email in cls.EMAIL_RE.findall(text):
                iocs['emails'][email.lower()] += 1

            for h in cls.SHA256_RE.findall(text):
                iocs['hashes_sha256'][h.lower()] += 1
            for h in cls.SHA1_RE.findall(text):
                if h.lower() not in iocs['hashes_sha256']:
                    iocs['hashes_sha1'][h.lower()] += 1
            for h in cls.MD5_RE.findall(text):
                if h.lower() not in iocs['hashes_sha1'] and h.lower() not in iocs['hashes_sha256']:
                    iocs['hashes_md5'][h.lower()] += 1

            for url in cls.URL_RE.findall(text):
                iocs['urls'][url] += 1

            for key in cls.AWS_KEY_RE.findall(text):
                iocs['aws_keys'][key] += 1

            if cls.PRIV_KEY_RE.search(text):
                iocs['private_keys'] += 1

            if e.username and e.username not in ('-', 'N/A', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                iocs['usernames'][e.username] += 1

        return iocs


# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class LogStatistics:
    """Compute comprehensive statistics from log events."""

    @staticmethod
    def compute(events):
        stats = {
            'total_events': len(events),
            'time_range': LogStatistics._time_range(events),
            'source_types': Counter(e.source_type for e in events),
            'severity_dist': Counter(e.severity for e in events if e.severity),
            'status_dist': Counter(e.status for e in events if e.status),
            'action_dist': Counter(e.action for e in events if e.action),
            'top_source_ips': Counter(e.source_ip for e in events if e.source_ip).most_common(20),
            'top_usernames': Counter(e.username for e in events if e.username).most_common(20),
            'top_services': Counter(e.service for e in events if e.service).most_common(20),
            'top_hosts': Counter(e.hostname for e in events if e.hostname).most_common(20),
            'events_per_hour': LogStatistics._events_per_hour(events),
            'login_failures': sum(1 for e in events if e.status == 'failure'),
            'login_successes': sum(1 for e in events if e.status == 'success'),
            'unique_ips': len(set(e.source_ip for e in events if e.source_ip)),
            'unique_users': len(set(e.username for e in events if e.username)),
        }
        return stats

    @staticmethod
    def _time_range(events):
        timestamps = []
        for e in events:
            if isinstance(e.timestamp, datetime):
                timestamps.append(e.timestamp)
        if timestamps:
            return {'start': min(timestamps), 'end': max(timestamps),
                    'duration': (max(timestamps) - min(timestamps)).total_seconds()}
        return {'start': None, 'end': None, 'duration': 0}

    @staticmethod
    def _events_per_hour(events):
        hours = Counter()
        for e in events:
            if isinstance(e.timestamp, datetime):
                hours[e.timestamp.hour] += 1
        return dict(sorted(hours.items()))


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate HTML forensics reports."""

    @staticmethod
    def generate_html(stats, findings, iocs, events):
        """Generate comprehensive HTML report."""
        severity_colors = {
            'CRITICAL': '#ff1744', 'HIGH': '#ff6d00',
            'MEDIUM': '#ffab00', 'LOW': '#2979ff', 'INFO': '#00c853'
        }

        # Compute MITRE coverage
        mitre_tactics = Counter()
        for f in findings:
            if f.mitre_info:
                for tactic in f.mitre_info.get('tactic', '').split(', '):
                    if tactic:
                        mitre_tactics[tactic] += 1

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>NEATLABS™ Log Forensics Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e14; color: #c5cdd9; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
h1 {{ color: #00e5ff; font-size: 28px; margin-bottom: 5px; }}
h2 {{ color: #00e5ff; font-size: 22px; margin: 30px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #1a2332; }}
h3 {{ color: #4dd0e1; font-size: 16px; margin: 15px 0 10px; }}
.header {{ background: linear-gradient(135deg, #0d1117 0%, #1a2332 100%); padding: 30px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #00e5ff33; }}
.subtitle {{ color: #8899aa; font-size: 14px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }}
.stat-card {{ background: #111820; padding: 18px; border-radius: 10px; border: 1px solid #1a2332; }}
.stat-card .value {{ font-size: 28px; font-weight: bold; color: #00e5ff; }}
.stat-card .label {{ font-size: 12px; color: #8899aa; text-transform: uppercase; }}
.finding {{ background: #111820; padding: 20px; border-radius: 10px; margin: 12px 0; border-left: 4px solid; }}
.finding-critical {{ border-color: #ff1744; }}
.finding-high {{ border-color: #ff6d00; }}
.finding-medium {{ border-color: #ffab00; }}
.finding-low {{ border-color: #2979ff; }}
.finding-info {{ border-color: #00c853; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
.severity-badge {{ padding: 3px 12px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; }}
.mitre-badge {{ background: #1a237e; padding: 3px 10px; border-radius: 4px; font-size: 11px; color: #82b1ff; }}
.evidence {{ background: #0a0e14; padding: 12px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 12px; margin: 8px 0; white-space: pre-wrap; color: #aab; }}
.recommendation {{ background: #0d2818; padding: 12px; border-radius: 6px; margin-top: 8px; color: #69f0ae; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ background: #1a2332; color: #00e5ff; padding: 10px; text-align: left; font-size: 12px; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #1a2332; font-size: 13px; }}
tr:hover {{ background: #111820; }}
.risk-bar {{ height: 6px; border-radius: 3px; background: #1a2332; }}
.risk-fill {{ height: 100%; border-radius: 3px; }}
.section {{ margin: 20px 0; }}
.footer {{ text-align: center; padding: 20px; color: #556; font-size: 11px; margin-top: 30px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔒 NEATLABS™ Log Forensics Report</h1>
<p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Events Analyzed: {stats['total_events']:,}</p>
</div>

<div class="grid">
<div class="stat-card"><div class="value">{stats['total_events']:,}</div><div class="label">Total Events</div></div>
<div class="stat-card"><div class="value">{len(findings)}</div><div class="label">Threat Findings</div></div>
<div class="stat-card"><div class="value">{sum(1 for f in findings if f.severity == 'CRITICAL')}</div><div class="label">Critical Findings</div></div>
<div class="stat-card"><div class="value">{stats['unique_ips']}</div><div class="label">Unique IPs</div></div>
<div class="stat-card"><div class="value">{stats['unique_users']}</div><div class="label">Unique Users</div></div>
<div class="stat-card"><div class="value">{stats['login_failures']:,}</div><div class="label">Failed Logins</div></div>
</div>

<h2>Threat Findings ({len(findings)})</h2>"""

        for f in findings:
            sev_lower = f.severity.lower()
            sev_color = severity_colors.get(f.severity, '#888')
            html += f"""
<div class="finding finding-{sev_lower}">
<div class="finding-header">
<div>
<strong style="color: white; font-size: 15px;">{html_module.escape(f.title)}</strong>
<span class="mitre-badge">{f.mitre_id} — {html_module.escape(f.mitre_info.get('name', ''))}</span>
</div>
<div>
<span class="severity-badge" style="background:{sev_color}">{f.severity}</span>
<span style="color:#888; font-size:12px; margin-left:8px;">Risk: {f.risk_score}/100</span>
</div>
</div>
<p style="color:#aab; font-size:13px;">{html_module.escape(f.description)}</p>
<div class="evidence">{'&#10;'.join(html_module.escape(e) for e in f.evidence)}</div>
<div class="recommendation">💡 {html_module.escape(f.recommendation)}</div>
</div>"""

        # MITRE ATT&CK Coverage
        if mitre_tactics:
            html += "<h2>MITRE ATT&CK Coverage</h2><div class='grid'>"
            for tactic, count in mitre_tactics.most_common():
                html += f"<div class='stat-card'><div class='value'>{count}</div><div class='label'>{html_module.escape(tactic)}</div></div>"
            html += "</div>"

        # IOCs
        html += "<h2>Indicators of Compromise</h2>"
        if iocs['ips']:
            html += "<h3>IP Addresses</h3><table><tr><th>IP</th><th>Count</th><th>Location</th><th>Threat Intel</th></tr>"
            for ip, count in iocs['ips'].most_common(30):
                geo = GeoIPLookup.lookup(ip)
                loc = f"{geo['city']}, {geo['country']}" if geo else "Unknown"
                bad = "⚠ MALICIOUS" if GeoIPLookup.is_in_bad_range(ip) else "Clean"
                html += f"<tr><td>{html_module.escape(ip)}</td><td>{count}</td><td>{html_module.escape(loc)}</td><td>{bad}</td></tr>"
            html += "</table>"

        if iocs['usernames']:
            html += "<h3>User Accounts</h3><table><tr><th>Username</th><th>Events</th></tr>"
            for user, count in iocs['usernames'].most_common(20):
                html += f"<tr><td>{html_module.escape(user)}</td><td>{count}</td></tr>"
            html += "</table>"

        if iocs['urls']:
            html += "<h3>URLs</h3><table><tr><th>URL</th><th>Count</th></tr>"
            for url, count in iocs['urls'].most_common(20):
                html += f"<tr><td style='word-break:break-all'>{html_module.escape(url)}</td><td>{count}</td></tr>"
            html += "</table>"

        html += f"""
<div class="footer">
NEATLABS™ Log Forensics Analyzer v3.0 — Stealth Entry LLC / Security 360 LLC<br>
Report generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
</div>
</body>
</html>"""
        return html


# ═══════════════════════════════════════════════════════════════════════════════
# LOG COLLECTOR - LOCAL SYSTEM & NETWORK SHARE COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

class LogCollector:
    """Discovers and collects log files from local system and network shares."""

    # Common log file extensions
    LOG_EXTENSIONS = {
        '.log', '.txt', '.json', '.xml', '.evtx', '.csv', '.tsv',
        '.gz', '.bz2', '.xz', '.audit', '.journal', '.syslog'
    }

    # ── Linux/macOS log sources ────────────────────────────────────────────
    LINUX_LOG_SOURCES = [
        {'path': '/var/log/syslog', 'name': 'Syslog', 'category': 'System', 'priority': 1},
        {'path': '/var/log/syslog.1', 'name': 'Syslog (Previous)', 'category': 'System', 'priority': 2},
        {'path': '/var/log/messages', 'name': 'Messages', 'category': 'System', 'priority': 1},
        {'path': '/var/log/messages.1', 'name': 'Messages (Previous)', 'category': 'System', 'priority': 2},
        {'path': '/var/log/auth.log', 'name': 'Auth Log', 'category': 'Authentication', 'priority': 1},
        {'path': '/var/log/auth.log.1', 'name': 'Auth Log (Previous)', 'category': 'Authentication', 'priority': 2},
        {'path': '/var/log/secure', 'name': 'Secure (RHEL/CentOS)', 'category': 'Authentication', 'priority': 1},
        {'path': '/var/log/secure.1', 'name': 'Secure (Previous)', 'category': 'Authentication', 'priority': 2},
        {'path': '/var/log/kern.log', 'name': 'Kernel Log', 'category': 'System', 'priority': 2},
        {'path': '/var/log/daemon.log', 'name': 'Daemon Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/boot.log', 'name': 'Boot Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/cron', 'name': 'Cron Log', 'category': 'Scheduled Tasks', 'priority': 2},
        {'path': '/var/log/cron.log', 'name': 'Cron Log', 'category': 'Scheduled Tasks', 'priority': 2},
        {'path': '/var/log/faillog', 'name': 'Failed Login Log', 'category': 'Authentication', 'priority': 1},
        {'path': '/var/log/lastlog', 'name': 'Last Login Log', 'category': 'Authentication', 'priority': 2},
        {'path': '/var/log/wtmp', 'name': 'Login Records (wtmp)', 'category': 'Authentication', 'priority': 2},
        {'path': '/var/log/btmp', 'name': 'Bad Login Records (btmp)', 'category': 'Authentication', 'priority': 1},
        {'path': '/var/log/audit/audit.log', 'name': 'Audit Log', 'category': 'Audit', 'priority': 1},
        {'path': '/var/log/audit/audit.log.1', 'name': 'Audit Log (Previous)', 'category': 'Audit', 'priority': 2},
        {'path': '/var/log/ufw.log', 'name': 'UFW Firewall Log', 'category': 'Firewall', 'priority': 1},
        {'path': '/var/log/firewalld', 'name': 'Firewalld Log', 'category': 'Firewall', 'priority': 1},
        {'path': '/var/log/apache2/access.log', 'name': 'Apache Access Log', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/apache2/error.log', 'name': 'Apache Error Log', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/nginx/access.log', 'name': 'Nginx Access Log', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/nginx/error.log', 'name': 'Nginx Error Log', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/httpd/access_log', 'name': 'HTTPD Access Log (RHEL)', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/httpd/error_log', 'name': 'HTTPD Error Log (RHEL)', 'category': 'Web Server', 'priority': 2},
        {'path': '/var/log/mysql/error.log', 'name': 'MySQL Error Log', 'category': 'Database', 'priority': 3},
        {'path': '/var/log/postgresql/', 'name': 'PostgreSQL Logs', 'category': 'Database', 'priority': 3, 'is_dir': True},
        {'path': '/var/log/mail.log', 'name': 'Mail Log', 'category': 'Mail', 'priority': 3},
        {'path': '/var/log/mail.err', 'name': 'Mail Error Log', 'category': 'Mail', 'priority': 3},
        {'path': '/var/log/dpkg.log', 'name': 'Package Manager Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/yum.log', 'name': 'YUM Package Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/dnf.log', 'name': 'DNF Package Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/cups/', 'name': 'CUPS Print Logs', 'category': 'System', 'priority': 4, 'is_dir': True},
        {'path': '/var/log/samba/', 'name': 'Samba Logs', 'category': 'File Sharing', 'priority': 2, 'is_dir': True},
        {'path': '/var/log/sssd/', 'name': 'SSSD Logs', 'category': 'Authentication', 'priority': 2, 'is_dir': True},
    ]

    # ── macOS-specific log sources ─────────────────────────────────────────
    MACOS_LOG_SOURCES = [
        {'path': '/var/log/system.log', 'name': 'System Log', 'category': 'System', 'priority': 1},
        {'path': '/var/log/install.log', 'name': 'Install Log', 'category': 'System', 'priority': 3},
        {'path': '/var/log/wifi.log', 'name': 'WiFi Log', 'category': 'Network', 'priority': 3},
        {'path': '/private/var/log/asl/', 'name': 'Apple System Log', 'category': 'System', 'priority': 2, 'is_dir': True},
        {'path': '/Library/Logs/', 'name': 'Library Logs', 'category': 'Application', 'priority': 3, 'is_dir': True},
        {'path': os.path.expanduser('~/Library/Logs/'), 'name': 'User Library Logs', 'category': 'Application', 'priority': 3, 'is_dir': True},
    ]

    # ── Windows log sources ────────────────────────────────────────────────
    WINDOWS_LOG_SOURCES = [
        {'name': 'Security Event Log', 'channel': 'Security', 'category': 'Security', 'priority': 1},
        {'name': 'System Event Log', 'channel': 'System', 'category': 'System', 'priority': 1},
        {'name': 'Application Event Log', 'channel': 'Application', 'category': 'Application', 'priority': 2},
        {'name': 'PowerShell Operational', 'channel': 'Microsoft-Windows-PowerShell/Operational', 'category': 'Security', 'priority': 1},
        {'name': 'Windows Defender Operational', 'channel': 'Microsoft-Windows-Windows Defender/Operational', 'category': 'Security', 'priority': 1},
        {'name': 'Sysmon Operational', 'channel': 'Microsoft-Windows-Sysmon/Operational', 'category': 'Security', 'priority': 1},
        {'name': 'Task Scheduler Operational', 'channel': 'Microsoft-Windows-TaskScheduler/Operational', 'category': 'Scheduled Tasks', 'priority': 2},
        {'name': 'Windows Firewall', 'channel': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'category': 'Firewall', 'priority': 2},
        {'name': 'RDP Client', 'channel': 'Microsoft-Windows-TerminalServices-RDPClient/Operational', 'category': 'Remote Access', 'priority': 2},
        {'name': 'RDP Local Session', 'channel': 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'category': 'Remote Access', 'priority': 2},
        {'name': 'DNS Client Events', 'channel': 'Microsoft-Windows-DNS-Client/Operational', 'category': 'Network', 'priority': 3},
        {'name': 'NTLM Operational', 'channel': 'Microsoft-Windows-NTLM/Operational', 'category': 'Authentication', 'priority': 2},
        {'name': 'Bits Client', 'channel': 'Microsoft-Windows-Bits-Client/Operational', 'category': 'System', 'priority': 3},
        {'name': 'AppLocker', 'channel': 'Microsoft-Windows-AppLocker/EXE and DLL', 'category': 'Security', 'priority': 2},
        {'name': 'WMI Activity', 'channel': 'Microsoft-Windows-WMI-Activity/Operational', 'category': 'Security', 'priority': 2},
    ]

    # ── Windows file-based log locations ───────────────────────────────────
    WINDOWS_FILE_SOURCES = [
        {'path': r'C:\Windows\System32\winevt\Logs', 'name': 'Event Log Files (.evtx)', 'category': 'Event Logs', 'priority': 1, 'is_dir': True},
        {'path': r'C:\Windows\System32\LogFiles', 'name': 'System Log Files', 'category': 'System', 'priority': 2, 'is_dir': True},
        {'path': r'C:\inetpub\logs\LogFiles', 'name': 'IIS Log Files', 'category': 'Web Server', 'priority': 2, 'is_dir': True},
        {'path': r'C:\Windows\debug', 'name': 'Debug Logs', 'category': 'System', 'priority': 3, 'is_dir': True},
        {'path': r'C:\Windows\Panther', 'name': 'Setup Logs', 'category': 'System', 'priority': 4, 'is_dir': True},
        {'path': r'C:\ProgramData\Microsoft\Windows Defender\Support', 'name': 'Defender Logs', 'category': 'Security', 'priority': 2, 'is_dir': True},
    ]

    @classmethod
    def detect_os(cls):
        """Detect the operating system."""
        sys_platform = platform.system().lower()
        if sys_platform == 'windows':
            return 'windows'
        elif sys_platform == 'darwin':
            return 'macos'
        else:
            return 'linux'

    @classmethod
    def discover_local_sources(cls):
        """Discover available log sources on the local system."""
        os_type = cls.detect_os()
        discovered = []

        if os_type in ('linux', 'macos'):
            sources = list(cls.LINUX_LOG_SOURCES)
            if os_type == 'macos':
                sources.extend(cls.MACOS_LOG_SOURCES)

            for src in sources:
                path = src['path']
                is_dir = src.get('is_dir', False)
                entry = {
                    'name': src['name'],
                    'path': path,
                    'category': src['category'],
                    'priority': src['priority'],
                    'os_type': os_type,
                    'source_type': 'file',
                    'exists': False,
                    'readable': False,
                    'size': 0,
                    'modified': None,
                    'is_dir': is_dir,
                    'file_count': 0,
                }

                if is_dir:
                    if os.path.isdir(path):
                        entry['exists'] = True
                        try:
                            files = [f for f in os.listdir(path)
                                     if os.path.isfile(os.path.join(path, f))]
                            entry['file_count'] = len(files)
                            total_size = sum(
                                os.path.getsize(os.path.join(path, f))
                                for f in files
                            )
                            entry['size'] = total_size
                            entry['readable'] = True
                            if files:
                                newest = max(
                                    os.path.getmtime(os.path.join(path, f))
                                    for f in files
                                )
                                entry['modified'] = datetime.fromtimestamp(newest)
                        except PermissionError:
                            entry['readable'] = False
                else:
                    if os.path.isfile(path):
                        entry['exists'] = True
                        try:
                            st = os.stat(path)
                            entry['size'] = st.st_size
                            entry['modified'] = datetime.fromtimestamp(st.st_mtime)
                            entry['readable'] = os.access(path, os.R_OK)
                        except (PermissionError, OSError):
                            entry['readable'] = False

                if entry['exists']:
                    discovered.append(entry)

            # Also check for journalctl availability
            try:
                result = subprocess.run(['which', 'journalctl'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    discovered.append({
                        'name': 'Systemd Journal (journalctl)',
                        'path': 'journalctl',
                        'category': 'System',
                        'priority': 1,
                        'os_type': os_type,
                        'source_type': 'command',
                        'exists': True,
                        'readable': True,
                        'size': 0,
                        'modified': datetime.now(),
                        'is_dir': False,
                        'file_count': 0,
                        'command': 'journalctl --no-pager -n 5000 --output=short-iso',
                    })
            except Exception:
                pass

        elif os_type == 'windows':
            # Check Windows event log channels
            for src in cls.WINDOWS_LOG_SOURCES:
                entry = {
                    'name': src['name'],
                    'path': src['channel'],
                    'category': src['category'],
                    'priority': src['priority'],
                    'os_type': 'windows',
                    'source_type': 'wevtutil',
                    'exists': False,
                    'readable': False,
                    'size': 0,
                    'modified': None,
                    'is_dir': False,
                    'file_count': 0,
                    'channel': src['channel'],
                }
                try:
                    result = subprocess.run(
                        ['wevtutil', 'gli', src['channel']],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        entry['exists'] = True
                        entry['readable'] = True
                        for line in result.stdout.splitlines():
                            if 'numberOfLogRecords' in line.lower() or 'records' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 1:
                                    try:
                                        entry['file_count'] = int(parts[1].strip())
                                    except ValueError:
                                        pass
                            if 'filesize' in line.lower() or 'size' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 1:
                                    try:
                                        entry['size'] = int(parts[1].strip())
                                    except ValueError:
                                        pass
                        discovered.append(entry)
                except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                    pass

            # Check Windows file-based log locations
            for src in cls.WINDOWS_FILE_SOURCES:
                path = src['path']
                entry = {
                    'name': src['name'],
                    'path': path,
                    'category': src['category'],
                    'priority': src['priority'],
                    'os_type': 'windows',
                    'source_type': 'file',
                    'exists': False,
                    'readable': False,
                    'size': 0,
                    'modified': None,
                    'is_dir': True,
                    'file_count': 0,
                }
                if os.path.isdir(path):
                    entry['exists'] = True
                    try:
                        files = [f for f in os.listdir(path)
                                 if os.path.isfile(os.path.join(path, f))]
                        entry['file_count'] = len(files)
                        entry['readable'] = True
                        discovered.append(entry)
                    except PermissionError:
                        entry['readable'] = False
                        discovered.append(entry)

        # Sort by priority then name
        discovered.sort(key=lambda x: (x['priority'], x['name']))
        return discovered

    @classmethod
    def scan_directory(cls, dir_path, recursive=True, extensions=None, max_depth=5,
                       min_size=0, max_size=500*1024*1024, max_files=500):
        """Scan a directory (local or network share) for log files.

        Args:
            dir_path: Directory path (local path or UNC path like \\\\server\\share)
            recursive: Search subdirectories
            extensions: Set of file extensions to match (default: LOG_EXTENSIONS)
            max_depth: Maximum recursion depth
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes (default 500MB)
            max_files: Maximum number of files to return

        Returns:
            List of dicts with file metadata
        """
        if extensions is None:
            extensions = cls.LOG_EXTENSIONS

        found_files = []
        dir_path = os.path.normpath(dir_path)

        if not os.path.isdir(dir_path):
            return found_files

        def _scan(current_path, depth):
            if depth > max_depth or len(found_files) >= max_files:
                return
            try:
                entries = os.scandir(current_path)
            except (PermissionError, OSError):
                return

            for entry in entries:
                if len(found_files) >= max_files:
                    break
                try:
                    if entry.is_file(follow_symlinks=False):
                        ext = os.path.splitext(entry.name)[1].lower()
                        if ext in extensions or not extensions:
                            st = entry.stat()
                            if min_size <= st.st_size <= max_size:
                                found_files.append({
                                    'path': entry.path,
                                    'name': entry.name,
                                    'size': st.st_size,
                                    'modified': datetime.fromtimestamp(st.st_mtime),
                                    'ext': ext,
                                    'readable': os.access(entry.path, os.R_OK),
                                    'relative_path': os.path.relpath(entry.path, dir_path),
                                })
                    elif entry.is_dir(follow_symlinks=False) and recursive:
                        # Skip hidden directories and common non-log dirs
                        if not entry.name.startswith('.') and entry.name not in (
                            'node_modules', '__pycache__', '.git', 'venv', 'env'
                        ):
                            _scan(entry.path, depth + 1)
                except (PermissionError, OSError):
                    continue

        _scan(dir_path, 0)
        found_files.sort(key=lambda x: x['modified'] or datetime.min, reverse=True)
        return found_files

    @classmethod
    def collect_file(cls, file_path, max_bytes=100*1024*1024):
        """Read a log file and return its contents.

        Args:
            file_path: Path to the file
            max_bytes: Maximum bytes to read (default 100MB)

        Returns:
            Tuple of (content_string, bytes_read)
        """
        try:
            size = os.path.getsize(file_path)
            read_size = min(size, max_bytes)

            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(read_size)

            return content, read_size
        except Exception as e:
            raise IOError(f"Failed to read {file_path}: {e}")

    @classmethod
    def is_admin(cls):
        """Check if running with elevated/admin privileges."""
        os_type = cls.detect_os()
        if os_type == 'windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                pass
            # Fallback: try writing to a protected location
            try:
                test_path = r'C:\Windows\Temp\_admin_test_' + str(uuid.uuid4())
                with open(test_path, 'w') as f:
                    f.write('test')
                os.remove(test_path)
                return True
            except Exception:
                return False
        else:
            return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    @classmethod
    def evtx_filename_to_channel(cls, filename):
        """Convert an .evtx filename to an Event Log channel name.

        Examples:
            Security.evtx → Security
            System.evtx → System
            Microsoft-Windows-PowerShell%4Operational.evtx → Microsoft-Windows-PowerShell/Operational
            Microsoft-Windows-Sysmon%4Operational.evtx → Microsoft-Windows-Sysmon/Operational
        """
        name = os.path.splitext(filename)[0]  # Remove .evtx
        # %4 in filenames represents '/' in channel names
        name = name.replace('%4', '/')
        return name

    @classmethod
    def collect_windows_eventlog(cls, channel, max_events=10000, output_format='xml'):
        """Export Windows Event Log channel using wevtutil with PowerShell fallback.

        Args:
            channel: Event log channel name (e.g., 'Security')
            max_events: Maximum events to export
            output_format: Output format ('xml' or 'text')

        Returns:
            Tuple of (content_string, event_count)
        """
        errors_collected = []

        # ── Attempt 1: wevtutil (fastest, native) ──
        try:
            cmd = [
                'wevtutil', 'qe', channel,
                '/c:{}'.format(max_events),
                '/rd:true',
                '/f:xml',
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                content = result.stdout
                if content.strip().startswith('<Event'):
                    content = f'<Events>\n{content}\n</Events>'
                event_count = content.count('<Event ')
                if event_count > 0:
                    return content, event_count
            if result.stderr:
                errors_collected.append(f"wevtutil: {result.stderr.strip()[:200]}")
        except FileNotFoundError:
            errors_collected.append("wevtutil not found")
        except subprocess.TimeoutExpired:
            errors_collected.append("wevtutil timed out")
        except Exception as e:
            errors_collected.append(f"wevtutil error: {e}")

        # ── Attempt 2: PowerShell Get-WinEvent (more compatible) ──
        try:
            ps_cmd = (
                f'Get-WinEvent -LogName "{channel}" -MaxEvents {max_events} -ErrorAction Stop '
                f'| ForEach-Object {{ $_.ToXml() }}'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                content = result.stdout
                if '<Event' in content:
                    content = f'<Events>\n{content}\n</Events>'
                    event_count = content.count('<Event')
                    if event_count > 0:
                        return content, event_count

            # Fallback to text format
            ps_cmd2 = (
                f'Get-WinEvent -LogName "{channel}" -MaxEvents {max_events} -ErrorAction Stop '
                f'| Format-List TimeCreated,Id,LevelDisplayName,ProviderName,Message'
            )
            result2 = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd2],
                capture_output=True, text=True, timeout=120
            )
            if result2.returncode == 0 and result2.stdout.strip():
                content = result2.stdout
                event_count = content.count('TimeCreated')
                if event_count > 0:
                    return content, event_count

            if result.stderr:
                errors_collected.append(f"PowerShell: {result.stderr.strip()[:200]}")
        except FileNotFoundError:
            errors_collected.append("PowerShell not found")
        except subprocess.TimeoutExpired:
            errors_collected.append("PowerShell timed out")
        except Exception as e:
            errors_collected.append(f"PowerShell error: {e}")

        # ── Both methods failed ──
        error_detail = '; '.join(errors_collected)
        raise RuntimeError(
            f"Could not export '{channel}'. Try running as Administrator. Details: {error_detail}"
        )

    @classmethod
    def collect_evtx_directory(cls, dir_path, max_events_per_channel=5000,
                                max_channels=20, priority_channels=None,
                                skip_channels=None):
        """Collect logs from an .evtx directory by exporting channels via wevtutil.

        Instead of reading locked .evtx files directly, this extracts channel names
        from filenames and exports them using wevtutil/PowerShell.

        Only exports security-relevant channels. Hardware/driver/telemetry channels
        are silently skipped as they contain no security-relevant data.

        Args:
            dir_path: Path to directory containing .evtx files
            max_events_per_channel: Max events per channel
            max_channels: Maximum number of channels to export
            priority_channels: List of priority channel names to export first
            skip_channels: Set of channel names already being collected (to avoid duplicates)

        Returns:
            Tuple of (all_content_list, source_names, total_bytes, errors)
        """
        if skip_channels is None:
            skip_channels = set()
        if priority_channels is None:
            priority_channels = [
                'Security', 'System', 'Application',
                'Microsoft-Windows-PowerShell/Operational',
                'Microsoft-Windows-Sysmon/Operational',
                'Microsoft-Windows-Windows Defender/Operational',
                'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                'Microsoft-Windows-TerminalServices-RDPClient/Operational',
                'Microsoft-Windows-TaskScheduler/Operational',
                'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
                'Microsoft-Windows-NTLM/Operational',
                'Microsoft-Windows-WMI-Activity/Operational',
                'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
                'Microsoft-Windows-GroupPolicy/Operational',
                'Microsoft-Windows-Kernel-PnP/Configuration',
                'Microsoft-Windows-DNS-Client/Operational',
            ]

        # Channels to silently skip — hardware, drivers, telemetry, etc.
        # These never contain security-relevant data
        SKIP_PATTERNS = {
            'camera', 'intel-', 'nvidia', 'realtek', 'audio', 'bluetooth',
            'media', 'graphics', 'display', 'video', 'codec', 'directx',
            'print', 'usb', 'battery', 'power-efficiency', 'energy',
            'font', 'speech', 'handwriting', 'input', 'touch',
            'devicesetupmanager', 'dxgi', 'dwm', 'wpn', 'push',
            'appxpackaging', 'appxdeployment', 'storeagent',
            'settingsyncprovider', 'appmodel', 'cloudexperience',
            'appreadiness', 'backgroundtaskinfra', 'shellcore',
            'twinui', 'search', 'cortana', 'startmenuexperiencehost',
            'immersivecontrol', 'mrt', 'windowsupdateclient', 'wuahandler',
            'microsoftedge', 'webauth', 'crypto-dpapi', 'crypto-ncrypt',
            'codeintegrity', 'deviceguard', 'hello',
            'staterepository', 'windowsbackup', 'filehistory',
            'deduplication', 'vhdmp', 'partition', 'storport',
            'kernelstreaming', 'wlan', 'ndis', 'tcpip', 'wfp',
            'networkprofile', 'ncsi', 'winsock', 'nla',
            'homegrouplistener', 'homegroupprovider',
            'international', 'languagepacksetup', 'muicachemanager',
            'spp-', 'licensingcsp', 'client-licensing',
            'hardwareevents', 'setupapi', 'deviceinstall',
            'drivetools', 'defrag', 'disk',
            'winhttp', 'webio', 'bits-client', 'deliveryoptimization',
            'peerdistreplication', 'branchcache',
            'perfdiag', 'resourceexhaustion', 'systemresourceusage',
            'telemetry', 'application-experience', 'compatibilityassistant',
            'applocker',
        }

        all_content = []
        source_names = []
        total_bytes = 0
        errors = []

        # Discover .evtx files and map to channels
        try:
            evtx_files = [f for f in os.listdir(dir_path) if f.lower().endswith('.evtx')]
        except (PermissionError, OSError) as e:
            return all_content, source_names, total_bytes, [f"Cannot list {dir_path}: {e}"]

        # Build channel map: channel_name → filename
        channel_map = {}
        for fname in evtx_files:
            channel = cls.evtx_filename_to_channel(fname)
            channel_map[channel] = fname

        # Build ordered list: priority channels first, then other security-relevant ones
        priority_set = set(priority_channels)
        ordered_channels = []

        # Add priority channels that exist and aren't already being collected
        for ch in priority_channels:
            if ch in channel_map and ch not in skip_channels:
                ordered_channels.append(ch)

        # Add other channels that aren't in skip list and aren't already being collected
        for ch in sorted(channel_map.keys()):
            if ch in priority_set or ch in skip_channels:
                continue
            ch_lower = ch.lower()
            # Skip if matches any skip pattern
            if any(pattern in ch_lower for pattern in SKIP_PATTERNS):
                continue
            ordered_channels.append(ch)

        # Limit total channels
        ordered_channels = ordered_channels[:max_channels]

        skipped_silent = 0
        for channel in ordered_channels:
            is_priority = channel in priority_set
            try:
                content, count = cls.collect_windows_eventlog(
                    channel, max_events=max_events_per_channel
                )
                if content and count > 0:
                    all_content.append(f"\n### SOURCE: {channel} (Event Log) ###\n")
                    all_content.append(content)
                    source_names.append(channel)
                    total_bytes += len(content.encode('utf-8', errors='replace'))
            except Exception as e:
                if is_priority:
                    # Only report errors for priority/important channels
                    errors.append(f"{channel}: {e}")
                else:
                    # Silently skip non-essential channels that fail
                    skipped_silent += 1

        return all_content, source_names, total_bytes, errors

    @classmethod
    def collect_journalctl(cls, args=None, max_lines=10000):
        """Collect logs via journalctl on Linux systems.

        Args:
            args: Additional journalctl arguments
            max_lines: Maximum lines to retrieve

        Returns:
            Tuple of (content_string, line_count)
        """
        cmd = ['journalctl', '--no-pager', '-n', str(max_lines), '--output=short-iso']
        if args:
            cmd.extend(args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            content = result.stdout
            line_count = content.count('\n')
            return content, line_count
        except FileNotFoundError:
            raise RuntimeError("journalctl not available on this system")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timed out collecting journal entries")

    @classmethod
    def merge_log_contents(cls, file_list):
        """Read and merge multiple log files into a single content string.

        Args:
            file_list: List of file paths to merge

        Returns:
            Tuple of (merged_content, total_bytes, file_count, errors)
        """
        merged = []
        total_bytes = 0
        errors = []

        for fpath in file_list:
            try:
                content, nbytes = cls.collect_file(fpath)
                if content.strip():
                    # Add file separator header
                    merged.append(f"\n### SOURCE: {os.path.basename(fpath)} ###\n")
                    merged.append(content)
                    total_bytes += nbytes
            except Exception as e:
                errors.append(f"{fpath}: {e}")

        return '\n'.join(merged), total_bytes, len(file_list) - len(errors), errors

    @classmethod
    def format_size(cls, size_bytes):
        """Format bytes into human-readable string."""
        if size_bytes == 0:
            return "0 B"
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        i = 0
        size = float(size_bytes)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f"{size:.1f} {units[i]}"


# ═══════════════════════════════════════════════════════════════════════════════
# LOG COLLECTOR DIALOG
# ═══════════════════════════════════════════════════════════════════════════════

class LogCollectorDialog:
    """GUI dialog for collecting logs from local system and network shares."""

    BG = '#0a0e14'
    BG2 = '#111922'
    BG3 = '#1a2332'
    BG4 = '#0d1117'
    FG = '#c5d0dc'
    ACCENT = '#00e5ff'
    GREEN = '#00e676'
    RED = '#ff5252'
    YELLOW = '#ffd740'
    ORANGE = '#ff9100'

    def __init__(self, parent_app):
        self.parent = parent_app
        self.root = parent_app.root
        self.selected_files = []
        self.discovered_sources = []
        self.scanned_files = []
        self.scan_vars = {}
        self.result_content = None  # Will hold collected content
        self.result_source = None   # Will hold source description

        self._build_dialog()

    def _build_dialog(self):
        """Build the collection dialog window."""
        self.dialog = tk.Toplevel(self.root)
        self.dialog.title("🗂️ Log Collection — Local System & Network")
        self.dialog.geometry("1100x750")
        self.dialog.configure(bg=self.BG)
        self.dialog.transient(self.root)
        self.dialog.grab_set()

        # Make it modal
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_close)

        # ── Header ──
        header = tk.Frame(self.dialog, bg=self.BG)
        header.pack(fill='x', padx=15, pady=(10, 5))

        tk.Label(
            header, text="🗂️  Log Collection Center",
            bg=self.BG, fg=self.ACCENT, font=('Segoe UI', 18, 'bold')
        ).pack(side='left')

        os_type = LogCollector.detect_os()
        os_labels = {'windows': '🖥️ Windows', 'linux': '🐧 Linux', 'macos': '🍎 macOS'}
        is_admin = LogCollector.is_admin()
        admin_str = "  ✅ Admin" if is_admin else "  ⚠️ Not Admin"
        admin_color = self.GREEN if is_admin else self.YELLOW
        header_right = tk.Frame(header, bg=self.BG)
        header_right.pack(side='right')
        tk.Label(
            header_right, text=f"Detected: {os_labels.get(os_type, os_type)}  |  Host: {platform.node()}",
            bg=self.BG, fg='#8899aa', font=('Segoe UI', 10)
        ).pack(anchor='e')
        if os_type == 'windows':
            tk.Label(
                header_right, text=admin_str,
                bg=self.BG, fg=admin_color, font=('Segoe UI', 9, 'bold')
            ).pack(anchor='e')

        # ── Notebook with tabs ──
        self.nb = ttk.Notebook(self.dialog)
        self.nb.pack(fill='both', expand=True, padx=15, pady=5)

        self._build_local_tab()
        self._build_network_tab()
        self._build_directory_tab()

        # ── Bottom action bar ──
        action_bar = tk.Frame(self.dialog, bg=self.BG3, height=60)
        action_bar.pack(fill='x', side='bottom', padx=0, pady=0)
        action_bar.pack_propagate(False)

        inner = tk.Frame(action_bar, bg=self.BG3)
        inner.pack(expand=True, fill='both', padx=15, pady=10)

        self.status_lbl = tk.Label(
            inner, text="Select log sources to collect and analyze",
            bg=self.BG3, fg='#8899aa', font=('Segoe UI', 10), anchor='w'
        )
        self.status_lbl.pack(side='left', fill='x', expand=True)

        self.collect_btn = tk.Button(
            inner, text="⬇️  Collect & Analyze Selected",
            bg='#004d5e', fg=self.ACCENT, font=('Segoe UI', 11, 'bold'),
            relief='flat', padx=20, pady=5, cursor='hand2',
            command=self._collect_and_analyze
        )
        self.collect_btn.pack(side='right', padx=(10, 0))

        tk.Button(
            inner, text="Select All",
            bg=self.BG2, fg=self.FG, font=('Segoe UI', 9),
            relief='flat', padx=10, pady=5, cursor='hand2',
            command=self._select_all
        ).pack(side='right', padx=3)

        tk.Button(
            inner, text="Select None",
            bg=self.BG2, fg=self.FG, font=('Segoe UI', 9),
            relief='flat', padx=10, pady=5, cursor='hand2',
            command=self._select_none
        ).pack(side='right', padx=3)

        # Auto-discover on open
        self.dialog.after(100, self._discover_local)

    def _build_local_tab(self):
        """Build the Local System log sources tab."""
        frame = tk.Frame(self.nb, bg=self.BG)
        self.nb.add(frame, text="  🖥️  Local System  ")

        # Info bar
        info = tk.Frame(frame, bg=self.BG4)
        info.pack(fill='x', padx=5, pady=5)
        tk.Label(
            info, text="  ℹ️  Auto-detected log sources on this system. Check the sources you want to collect.",
            bg=self.BG4, fg='#8899aa', font=('Segoe UI', 9), anchor='w', pady=6
        ).pack(fill='x', padx=10)

        # Admin warning for Windows
        if LogCollector.detect_os() == 'windows' and not LogCollector.is_admin():
            warn_frame = tk.Frame(frame, bg='#3d2000')
            warn_frame.pack(fill='x', padx=5, pady=(0, 5))
            tk.Label(
                warn_frame,
                text="  ⚠️  Not running as Administrator. Event Log exports may fail. "
                     "Right-click → 'Run as Administrator' for full access.",
                bg='#3d2000', fg=self.YELLOW, font=('Segoe UI', 9), anchor='w', pady=6,
                wraplength=900
            ).pack(fill='x', padx=10)

        # Refresh button
        btn_bar = tk.Frame(frame, bg=self.BG)
        btn_bar.pack(fill='x', padx=5, pady=(5, 0))
        tk.Button(
            btn_bar, text="🔄 Refresh", bg=self.BG3, fg=self.FG,
            font=('Segoe UI', 9), relief='flat', padx=10, cursor='hand2',
            command=self._discover_local
        ).pack(side='left')

        self.local_count_lbl = tk.Label(
            btn_bar, text="", bg=self.BG, fg='#8899aa', font=('Segoe UI', 9)
        )
        self.local_count_lbl.pack(side='left', padx=10)

        # Scrollable source list
        canvas_frame = tk.Frame(frame, bg=self.BG)
        canvas_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.local_canvas = tk.Canvas(canvas_frame, bg=self.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient='vertical', command=self.local_canvas.yview)
        self.local_inner = tk.Frame(self.local_canvas, bg=self.BG)

        self.local_inner.bind(
            '<Configure>',
            lambda e: self.local_canvas.configure(scrollregion=self.local_canvas.bbox('all'))
        )

        self.local_canvas.create_window((0, 0), window=self.local_inner, anchor='nw')
        self.local_canvas.configure(yscrollcommand=scrollbar.set)

        self.local_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Mouse wheel scrolling
        self.local_canvas.bind('<Enter>', lambda e: self.local_canvas.bind_all('<MouseWheel>',
            lambda ev: self.local_canvas.yview_scroll(-1 * (ev.delta // 120), 'units')))
        self.local_canvas.bind('<Leave>', lambda e: self.local_canvas.unbind_all('<MouseWheel>'))

    def _build_network_tab(self):
        """Build the Network Share / UNC Path tab."""
        frame = tk.Frame(self.nb, bg=self.BG)
        self.nb.add(frame, text="  🌐  Network Share  ")

        info = tk.Frame(frame, bg=self.BG4)
        info.pack(fill='x', padx=5, pady=5)
        tk.Label(
            info, text="  ℹ️  Enter a UNC path (\\\\server\\share) or mounted network path to browse for log files.",
            bg=self.BG4, fg='#8899aa', font=('Segoe UI', 9), anchor='w', pady=6
        ).pack(fill='x', padx=10)

        # Path entry
        path_frame = tk.Frame(frame, bg=self.BG)
        path_frame.pack(fill='x', padx=5, pady=5)

        tk.Label(path_frame, text="Network Path:", bg=self.BG, fg=self.FG,
                 font=('Segoe UI', 10)).pack(side='left', padx=(5, 10))

        self.net_path_var = tk.StringVar()
        self.net_path_entry = tk.Entry(
            path_frame, textvariable=self.net_path_var,
            bg=self.BG2, fg=self.FG, insertbackground=self.FG,
            font=('Consolas', 11), relief='flat', width=50
        )
        self.net_path_entry.pack(side='left', fill='x', expand=True, padx=5, ipady=4)
        self.net_path_entry.bind('<Return>', lambda e: self._scan_network())

        tk.Button(
            path_frame, text="📁 Browse", bg=self.BG3, fg=self.FG,
            font=('Segoe UI', 9), relief='flat', padx=10, cursor='hand2',
            command=self._browse_network_path
        ).pack(side='left', padx=3)

        tk.Button(
            path_frame, text="🔍 Scan", bg='#004d5e', fg=self.ACCENT,
            font=('Segoe UI', 9, 'bold'), relief='flat', padx=15, cursor='hand2',
            command=self._scan_network
        ).pack(side='left', padx=3)

        # Options
        opts_frame = tk.Frame(frame, bg=self.BG)
        opts_frame.pack(fill='x', padx=5, pady=2)

        self.net_recursive_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opts_frame, text="Recursive search", variable=self.net_recursive_var,
            bg=self.BG, fg=self.FG, selectcolor=self.BG2,
            activebackground=self.BG, activeforeground=self.FG, font=('Segoe UI', 9)
        ).pack(side='left', padx=10)

        tk.Label(opts_frame, text="Max depth:", bg=self.BG, fg='#8899aa',
                 font=('Segoe UI', 9)).pack(side='left', padx=(20, 5))
        self.net_depth_var = tk.StringVar(value='5')
        tk.Entry(
            opts_frame, textvariable=self.net_depth_var, bg=self.BG2, fg=self.FG,
            insertbackground=self.FG, font=('Consolas', 10), relief='flat', width=4
        ).pack(side='left', ipady=2)

        tk.Label(opts_frame, text="Max files:", bg=self.BG, fg='#8899aa',
                 font=('Segoe UI', 9)).pack(side='left', padx=(20, 5))
        self.net_maxfiles_var = tk.StringVar(value='500')
        tk.Entry(
            opts_frame, textvariable=self.net_maxfiles_var, bg=self.BG2, fg=self.FG,
            insertbackground=self.FG, font=('Consolas', 10), relief='flat', width=6
        ).pack(side='left', ipady=2)

        # Network scan results treeview
        tree_frame = tk.Frame(frame, bg=self.BG)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)

        cols = ('check', 'name', 'path', 'size', 'modified', 'type')
        self.net_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', selectmode='extended')
        self.net_tree.heading('check', text='✓')
        self.net_tree.heading('name', text='File Name')
        self.net_tree.heading('path', text='Relative Path')
        self.net_tree.heading('size', text='Size')
        self.net_tree.heading('modified', text='Modified')
        self.net_tree.heading('type', text='Type')
        self.net_tree.column('check', width=30, anchor='center')
        self.net_tree.column('name', width=250)
        self.net_tree.column('path', width=300)
        self.net_tree.column('size', width=80, anchor='e')
        self.net_tree.column('modified', width=150, anchor='center')
        self.net_tree.column('type', width=60, anchor='center')

        net_scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=net_scroll.set)
        self.net_tree.pack(side='left', fill='both', expand=True)
        net_scroll.pack(side='right', fill='y')

        # Toggle selection on click
        self.net_tree.bind('<ButtonRelease-1>', self._toggle_net_selection)
        self.net_selected = set()

        self.net_status_lbl = tk.Label(
            frame, text="Enter a path and click Scan to discover log files",
            bg=self.BG, fg='#8899aa', font=('Segoe UI', 9)
        )
        self.net_status_lbl.pack(fill='x', padx=10, pady=(0, 5))

    def _build_directory_tab(self):
        """Build the Browse Directory tab for local folder scanning."""
        frame = tk.Frame(self.nb, bg=self.BG)
        self.nb.add(frame, text="  📁  Browse Directory  ")

        info = tk.Frame(frame, bg=self.BG4)
        info.pack(fill='x', padx=5, pady=5)
        tk.Label(
            info, text="  ℹ️  Browse any local directory to find log files. Great for custom log locations.",
            bg=self.BG4, fg='#8899aa', font=('Segoe UI', 9), anchor='w', pady=6
        ).pack(fill='x', padx=10)

        # Path entry
        path_frame = tk.Frame(frame, bg=self.BG)
        path_frame.pack(fill='x', padx=5, pady=5)

        tk.Label(path_frame, text="Directory:", bg=self.BG, fg=self.FG,
                 font=('Segoe UI', 10)).pack(side='left', padx=(5, 10))

        self.dir_path_var = tk.StringVar()
        self.dir_path_entry = tk.Entry(
            path_frame, textvariable=self.dir_path_var,
            bg=self.BG2, fg=self.FG, insertbackground=self.FG,
            font=('Consolas', 11), relief='flat', width=50
        )
        self.dir_path_entry.pack(side='left', fill='x', expand=True, padx=5, ipady=4)

        tk.Button(
            path_frame, text="📁 Browse", bg=self.BG3, fg=self.FG,
            font=('Segoe UI', 9), relief='flat', padx=10, cursor='hand2',
            command=self._browse_local_dir
        ).pack(side='left', padx=3)

        tk.Button(
            path_frame, text="🔍 Scan", bg='#004d5e', fg=self.ACCENT,
            font=('Segoe UI', 9, 'bold'), relief='flat', padx=15, cursor='hand2',
            command=self._scan_directory
        ).pack(side='left', padx=3)

        # Options
        opts_frame = tk.Frame(frame, bg=self.BG)
        opts_frame.pack(fill='x', padx=5, pady=2)

        self.dir_recursive_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opts_frame, text="Recursive search", variable=self.dir_recursive_var,
            bg=self.BG, fg=self.FG, selectcolor=self.BG2,
            activebackground=self.BG, activeforeground=self.FG, font=('Segoe UI', 9)
        ).pack(side='left', padx=10)

        self.dir_allfiles_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opts_frame, text="All files (not just log extensions)", variable=self.dir_allfiles_var,
            bg=self.BG, fg=self.FG, selectcolor=self.BG2,
            activebackground=self.BG, activeforeground=self.FG, font=('Segoe UI', 9)
        ).pack(side='left', padx=10)

        # Directory scan results treeview (reuse same layout as network)
        tree_frame = tk.Frame(frame, bg=self.BG)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)

        cols = ('check', 'name', 'path', 'size', 'modified', 'type')
        self.dir_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', selectmode='extended')
        self.dir_tree.heading('check', text='✓')
        self.dir_tree.heading('name', text='File Name')
        self.dir_tree.heading('path', text='Relative Path')
        self.dir_tree.heading('size', text='Size')
        self.dir_tree.heading('modified', text='Modified')
        self.dir_tree.heading('type', text='Type')
        self.dir_tree.column('check', width=30, anchor='center')
        self.dir_tree.column('name', width=250)
        self.dir_tree.column('path', width=300)
        self.dir_tree.column('size', width=80, anchor='e')
        self.dir_tree.column('modified', width=150, anchor='center')
        self.dir_tree.column('type', width=60, anchor='center')

        dir_scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.dir_tree.yview)
        self.dir_tree.configure(yscrollcommand=dir_scroll.set)
        self.dir_tree.pack(side='left', fill='both', expand=True)
        dir_scroll.pack(side='right', fill='y')

        self.dir_tree.bind('<ButtonRelease-1>', self._toggle_dir_selection)
        self.dir_selected = set()

        self.dir_status_lbl = tk.Label(
            frame, text="Select a directory and click Scan",
            bg=self.BG, fg='#8899aa', font=('Segoe UI', 9)
        )
        self.dir_status_lbl.pack(fill='x', padx=10, pady=(0, 5))

    # ── Discovery ──────────────────────────────────────────────────────────

    def _discover_local(self):
        """Discover local log sources in a background thread."""
        self.status_lbl.configure(text="🔍 Discovering local log sources...")

        def task():
            sources = LogCollector.discover_local_sources()
            self.discovered_sources = sources
            self.dialog.after(0, lambda: self._populate_local_sources(sources))

        threading.Thread(target=task, daemon=True).start()

    def _populate_local_sources(self, sources):
        """Populate the local sources list with checkboxes."""
        # Clear existing
        for widget in self.local_inner.winfo_children():
            widget.destroy()
        self.scan_vars.clear()

        if not sources:
            tk.Label(
                self.local_inner,
                text="No log sources discovered. You may need elevated privileges (sudo/Administrator).",
                bg=self.BG, fg=self.YELLOW, font=('Segoe UI', 10), wraplength=600
            ).pack(padx=20, pady=20)
            self.local_count_lbl.configure(text="0 sources found")
            self.status_lbl.configure(text="No log sources found. Try running with elevated privileges.")
            return

        # Group by category
        categories = OrderedDict()
        for src in sources:
            cat = src['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(src)

        cat_colors = {
            'Authentication': '#ff5252', 'Security': '#ff5252', 'Audit': '#ff9100',
            'System': '#00e5ff', 'Firewall': '#ffd740', 'Web Server': '#69f0ae',
            'Scheduled Tasks': '#b388ff', 'Remote Access': '#ff80ab',
            'Network': '#448aff', 'Database': '#80deea', 'Mail': '#ce93d8',
            'Application': '#90a4ae', 'File Sharing': '#a5d6a7', 'Event Logs': '#ff8a65',
        }

        row = 0
        for cat, items in categories.items():
            # Category header
            color = cat_colors.get(cat, '#8899aa')
            cat_frame = tk.Frame(self.local_inner, bg=self.BG3)
            cat_frame.pack(fill='x', padx=5, pady=(8, 2))
            tk.Label(
                cat_frame, text=f"  ▸ {cat} ({len(items)} sources)",
                bg=self.BG3, fg=color, font=('Segoe UI', 10, 'bold'), anchor='w', pady=4
            ).pack(fill='x', padx=5)

            for src in items:
                item_frame = tk.Frame(self.local_inner, bg=self.BG)
                item_frame.pack(fill='x', padx=15, pady=1)

                var = tk.BooleanVar(value=src.get('priority', 3) <= 1 and src.get('readable', False))
                self.scan_vars[src['path']] = {'var': var, 'source': src}

                cb = tk.Checkbutton(
                    item_frame, variable=var, bg=self.BG, fg=self.FG,
                    selectcolor=self.BG2, activebackground=self.BG, activeforeground=self.FG
                )
                cb.pack(side='left', padx=(0, 5))

                # Source name
                name_color = self.GREEN if src.get('readable') else self.RED
                tk.Label(
                    item_frame, text=src['name'], bg=self.BG, fg=name_color,
                    font=('Segoe UI', 10), width=30, anchor='w'
                ).pack(side='left')

                # Path
                tk.Label(
                    item_frame, text=src['path'], bg=self.BG, fg='#667788',
                    font=('Consolas', 9), anchor='w'
                ).pack(side='left', padx=(10, 0), fill='x', expand=True)

                # Size
                size_str = LogCollector.format_size(src.get('size', 0))
                if src.get('is_dir') and src.get('file_count'):
                    size_str = f"{src['file_count']} files ({size_str})"
                tk.Label(
                    item_frame, text=size_str, bg=self.BG, fg='#8899aa',
                    font=('Consolas', 9), width=18, anchor='e'
                ).pack(side='right', padx=5)

                # Modified date
                if src.get('modified'):
                    mod_str = src['modified'].strftime('%Y-%m-%d %H:%M')
                else:
                    mod_str = ''
                tk.Label(
                    item_frame, text=mod_str, bg=self.BG, fg='#667788',
                    font=('Consolas', 9), width=16, anchor='e'
                ).pack(side='right', padx=5)

                # Access indicator
                if not src.get('readable'):
                    tk.Label(
                        item_frame, text="🔒", bg=self.BG, font=('Segoe UI', 9)
                    ).pack(side='right', padx=2)
                    var.set(False)

                row += 1

        readable_count = sum(1 for s in sources if s.get('readable'))
        self.local_count_lbl.configure(
            text=f"{len(sources)} sources found ({readable_count} readable)"
        )
        self.status_lbl.configure(
            text=f"✅ Found {len(sources)} log sources ({readable_count} readable). Select and collect."
        )

    # ── Network Share Scanning ─────────────────────────────────────────────

    def _browse_network_path(self):
        """Browse for network share / directory."""
        path = filedialog.askdirectory(title="Select Network Share or Directory")
        if path:
            self.net_path_var.set(path)

    def _scan_network(self):
        """Scan the entered network path for log files."""
        path = self.net_path_var.get().strip()
        if not path:
            messagebox.showinfo("Network Scan", "Please enter a network path first.")
            return

        self.net_status_lbl.configure(text=f"🔍 Scanning {path}...")
        self.net_selected.clear()

        def task():
            try:
                max_depth = int(self.net_depth_var.get() or 5)
            except ValueError:
                max_depth = 5
            try:
                max_files = int(self.net_maxfiles_var.get() or 500)
            except ValueError:
                max_files = 500

            try:
                files = LogCollector.scan_directory(
                    path,
                    recursive=self.net_recursive_var.get(),
                    max_depth=max_depth,
                    max_files=max_files
                )
                self.dialog.after(0, lambda: self._populate_network_results(files, path))
            except Exception as e:
                self.dialog.after(0, lambda: self.net_status_lbl.configure(
                    text=f"❌ Error scanning: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    def _populate_network_results(self, files, base_path):
        """Populate network scan results treeview."""
        self.net_tree.delete(*self.net_tree.get_children())
        self.scanned_files = files
        self.net_selected.clear()

        total_size = 0
        for f in files:
            size_str = LogCollector.format_size(f['size'])
            mod_str = f['modified'].strftime('%Y-%m-%d %H:%M') if f.get('modified') else ''
            readable_mark = '✓' if f.get('readable') else '🔒'
            iid = self.net_tree.insert('', 'end', values=(
                readable_mark, f['name'], f['relative_path'],
                size_str, mod_str, f['ext']
            ))
            if f.get('readable'):
                self.net_selected.add(iid)
            total_size += f.get('size', 0)

        self.net_status_lbl.configure(
            text=f"Found {len(files)} files ({LogCollector.format_size(total_size)} total) in {base_path}"
        )
        self.status_lbl.configure(
            text=f"📂 Network scan: {len(files)} files found. Click rows to toggle selection."
        )

    def _toggle_net_selection(self, event):
        """Toggle selection state for network tree items."""
        item = self.net_tree.identify_row(event.y)
        if item:
            if item in self.net_selected:
                self.net_selected.discard(item)
                vals = list(self.net_tree.item(item, 'values'))
                vals[0] = '○'
                self.net_tree.item(item, values=vals)
            else:
                self.net_selected.add(item)
                vals = list(self.net_tree.item(item, 'values'))
                vals[0] = '✓'
                self.net_tree.item(item, values=vals)

    # ── Directory Scanning ─────────────────────────────────────────────────

    def _browse_local_dir(self):
        """Browse for a local directory."""
        path = filedialog.askdirectory(title="Select Directory to Scan")
        if path:
            self.dir_path_var.set(path)

    def _scan_directory(self):
        """Scan the selected local directory."""
        path = self.dir_path_var.get().strip()
        if not path:
            messagebox.showinfo("Directory Scan", "Please select a directory first.")
            return

        self.dir_status_lbl.configure(text=f"🔍 Scanning {path}...")
        self.dir_selected.clear()

        def task():
            extensions = set() if self.dir_allfiles_var.get() else LogCollector.LOG_EXTENSIONS
            try:
                files = LogCollector.scan_directory(
                    path, recursive=self.dir_recursive_var.get(),
                    extensions=extensions, max_files=500
                )
                self.dialog.after(0, lambda: self._populate_dir_results(files, path))
            except Exception as e:
                self.dialog.after(0, lambda: self.dir_status_lbl.configure(
                    text=f"❌ Error scanning: {e}"
                ))

        threading.Thread(target=task, daemon=True).start()

    def _populate_dir_results(self, files, base_path):
        """Populate directory scan results."""
        self.dir_tree.delete(*self.dir_tree.get_children())
        self.dir_scanned_files = files
        self.dir_selected.clear()

        total_size = 0
        for f in files:
            size_str = LogCollector.format_size(f['size'])
            mod_str = f['modified'].strftime('%Y-%m-%d %H:%M') if f.get('modified') else ''
            readable_mark = '✓' if f.get('readable') else '🔒'
            iid = self.dir_tree.insert('', 'end', values=(
                readable_mark, f['name'], f['relative_path'],
                size_str, mod_str, f['ext']
            ))
            if f.get('readable'):
                self.dir_selected.add(iid)
            total_size += f.get('size', 0)

        self.dir_status_lbl.configure(
            text=f"Found {len(files)} files ({LogCollector.format_size(total_size)} total) in {base_path}"
        )

    def _toggle_dir_selection(self, event):
        """Toggle selection state for directory tree items."""
        item = self.dir_tree.identify_row(event.y)
        if item:
            if item in self.dir_selected:
                self.dir_selected.discard(item)
                vals = list(self.dir_tree.item(item, 'values'))
                vals[0] = '○'
                self.dir_tree.item(item, values=vals)
            else:
                self.dir_selected.add(item)
                vals = list(self.dir_tree.item(item, 'values'))
                vals[0] = '✓'
                self.dir_tree.item(item, values=vals)

    # ── Selection Helpers ──────────────────────────────────────────────────

    def _select_all(self):
        """Select all available sources across all tabs."""
        for key, data in self.scan_vars.items():
            if data['source'].get('readable'):
                data['var'].set(True)
        for iid in self.net_tree.get_children():
            self.net_selected.add(iid)
            vals = list(self.net_tree.item(iid, 'values'))
            vals[0] = '✓'
            self.net_tree.item(iid, values=vals)
        if hasattr(self, 'dir_scanned_files'):
            for iid in self.dir_tree.get_children():
                self.dir_selected.add(iid)
                vals = list(self.dir_tree.item(iid, 'values'))
                vals[0] = '✓'
                self.dir_tree.item(iid, values=vals)

    def _select_none(self):
        """Deselect all sources."""
        for key, data in self.scan_vars.items():
            data['var'].set(False)
        self.net_selected.clear()
        for iid in self.net_tree.get_children():
            vals = list(self.net_tree.item(iid, 'values'))
            vals[0] = '○'
            self.net_tree.item(iid, values=vals)
        self.dir_selected.clear()
        for iid in self.dir_tree.get_children():
            vals = list(self.dir_tree.item(iid, 'values'))
            vals[0] = '○'
            self.dir_tree.item(iid, values=vals)

    # ── Collection & Analysis ──────────────────────────────────────────────

    def _collect_and_analyze(self):
        """Collect all selected sources and feed to the analyzer."""
        self.collect_btn.configure(state='disabled', text="⏳ Collecting...")
        self.status_lbl.configure(text="Collecting selected log sources...")

        def task():
            all_content = []
            source_names = []
            total_bytes = 0
            errors = []
            is_windows = LogCollector.detect_os() == 'windows'

            # Check admin status on Windows
            if is_windows and not LogCollector.is_admin():
                self._update_collect_status(
                    "⚠️ Not running as Administrator — some logs may be inaccessible. Collecting what's available..."
                )

            # ── Collect from Local System tab ──

            # First pass: identify channels being collected individually via wevtutil
            # so we can skip them in the evtx directory export (avoid duplicates)
            individually_selected_channels = set()
            for path, data in self.scan_vars.items():
                if not data['var'].get():
                    continue
                src = data['source']
                if src.get('source_type') == 'wevtutil' and src.get('channel'):
                    individually_selected_channels.add(src['channel'])

            for path, data in self.scan_vars.items():
                if not data['var'].get():
                    continue
                src = data['source']

                try:
                    if src.get('source_type') == 'command':
                        # journalctl
                        self._update_collect_status(f"Collecting {src['name']}...")
                        content, count = LogCollector.collect_journalctl()
                        all_content.append(f"\n### SOURCE: {src['name']} ###\n")
                        all_content.append(content)
                        source_names.append(src['name'])
                        total_bytes += len(content.encode('utf-8', errors='replace'))

                    elif src.get('source_type') == 'wevtutil':
                        # Windows Event Log channel via wevtutil
                        self._update_collect_status(f"Exporting {src['name']}...")
                        try:
                            content, count = LogCollector.collect_windows_eventlog(
                                src['channel'], max_events=10000
                            )
                            all_content.append(f"\n### SOURCE: {src['name']} ({src['channel']}) ###\n")
                            all_content.append(content)
                            source_names.append(src['name'])
                            total_bytes += len(content.encode('utf-8', errors='replace'))
                        except Exception as e:
                            errors.append(f"{src['name']}: {e}")

                    elif src.get('is_dir'):
                        # Directory of log files — special handling for .evtx directories
                        self._update_collect_status(f"Collecting {src['name']}...")

                        # Check if this is a Windows Event Log directory
                        is_evtx_dir = False
                        if is_windows:
                            try:
                                dir_files = os.listdir(src['path'])
                                evtx_count = sum(1 for f in dir_files if f.lower().endswith('.evtx'))
                                is_evtx_dir = evtx_count > len(dir_files) * 0.5  # >50% .evtx files
                            except (PermissionError, OSError):
                                is_evtx_dir = 'winevt' in src['path'].lower() or 'evtx' in src['name'].lower()

                        if is_evtx_dir:
                            # Use wevtutil to export channels instead of reading raw .evtx files
                            self._update_collect_status(
                                f"Exporting Event Log channels from {src['name']}..."
                            )
                            evtx_content, evtx_names, evtx_bytes, evtx_errors = \
                                LogCollector.collect_evtx_directory(
                                    src['path'],
                                    max_events_per_channel=5000,
                                    max_channels=15,
                                    skip_channels=individually_selected_channels,
                                )
                            all_content.extend(evtx_content)
                            source_names.extend(evtx_names)
                            total_bytes += evtx_bytes
                            errors.extend(evtx_errors)
                        else:
                            # Normal directory — read files directly
                            dir_files = LogCollector.scan_directory(
                                src['path'], recursive=False, max_files=50
                            )
                            collected_any = False
                            for df in dir_files:
                                if df.get('readable') and df['size'] > 0:
                                    # Skip .evtx files in any directory — they're binary/locked
                                    if df.get('ext', '').lower() == '.evtx':
                                        continue
                                    try:
                                        content, nbytes = LogCollector.collect_file(df['path'])
                                        if content.strip():
                                            all_content.append(f"\n### SOURCE: {df['name']} ###\n")
                                            all_content.append(content)
                                            total_bytes += nbytes
                                            collected_any = True
                                    except PermissionError:
                                        errors.append(f"{df['name']}: Permission denied")
                                    except Exception as e:
                                        errors.append(f"{df['name']}: {e}")
                            if collected_any:
                                source_names.append(src['name'])

                    else:
                        # Single file
                        # Skip .evtx files — they need wevtutil, not direct read
                        if src['path'].lower().endswith('.evtx'):
                            channel = LogCollector.evtx_filename_to_channel(
                                os.path.basename(src['path'])
                            )
                            self._update_collect_status(f"Exporting {channel} via wevtutil...")
                            try:
                                content, count = LogCollector.collect_windows_eventlog(
                                    channel, max_events=10000
                                )
                                all_content.append(f"\n### SOURCE: {channel} (Event Log) ###\n")
                                all_content.append(content)
                                source_names.append(channel)
                                total_bytes += len(content.encode('utf-8', errors='replace'))
                            except Exception as e:
                                errors.append(f"{src['name']}: {e}")
                        else:
                            self._update_collect_status(f"Reading {src['name']}...")
                            content, nbytes = LogCollector.collect_file(src['path'])
                            all_content.append(f"\n### SOURCE: {src['name']} ###\n")
                            all_content.append(content)
                            source_names.append(src['name'])
                            total_bytes += nbytes

                except Exception as e:
                    errors.append(f"{src['name']}: {e}")

            # ── Collect from Network Share tab ──
            if self.net_selected and self.scanned_files:
                net_indices = []
                for iid in self.net_selected:
                    try:
                        idx = self.net_tree.index(iid)
                        net_indices.append(idx)
                    except Exception:
                        pass

                for idx in net_indices:
                    if idx < len(self.scanned_files):
                        f = self.scanned_files[idx]
                        try:
                            # Handle .evtx in network shares
                            if f.get('ext', '').lower() == '.evtx':
                                channel = LogCollector.evtx_filename_to_channel(f['name'])
                                self._update_collect_status(f"Exporting {channel} from network...")
                                try:
                                    content, count = LogCollector.collect_windows_eventlog(
                                        channel, max_events=5000
                                    )
                                    all_content.append(f"\n### SOURCE: {channel} (Network Event Log) ###\n")
                                    all_content.append(content)
                                    source_names.append(f"NET:{channel}")
                                    total_bytes += len(content.encode('utf-8', errors='replace'))
                                except Exception as e:
                                    errors.append(f"NET:{f['name']}: {e}")
                            else:
                                self._update_collect_status(f"Reading {f['name']}...")
                                content, nbytes = LogCollector.collect_file(f['path'])
                                all_content.append(f"\n### SOURCE: {f['name']} (Network) ###\n")
                                all_content.append(content)
                                source_names.append(f"NET:{f['name']}")
                                total_bytes += nbytes
                        except Exception as e:
                            errors.append(f"{f['path']}: {e}")

            # ── Collect from Browse Directory tab ──
            if self.dir_selected and hasattr(self, 'dir_scanned_files'):
                dir_indices = []
                for iid in self.dir_selected:
                    try:
                        idx = self.dir_tree.index(iid)
                        dir_indices.append(idx)
                    except Exception:
                        pass

                for idx in dir_indices:
                    if idx < len(self.dir_scanned_files):
                        f = self.dir_scanned_files[idx]
                        try:
                            if f.get('ext', '').lower() == '.evtx':
                                channel = LogCollector.evtx_filename_to_channel(f['name'])
                                self._update_collect_status(f"Exporting {channel}...")
                                try:
                                    content, count = LogCollector.collect_windows_eventlog(
                                        channel, max_events=5000
                                    )
                                    all_content.append(f"\n### SOURCE: {channel} (Event Log) ###\n")
                                    all_content.append(content)
                                    source_names.append(f"DIR:{channel}")
                                    total_bytes += len(content.encode('utf-8', errors='replace'))
                                except Exception as e:
                                    errors.append(f"DIR:{f['name']}: {e}")
                            else:
                                self._update_collect_status(f"Reading {f['name']}...")
                                content, nbytes = LogCollector.collect_file(f['path'])
                                all_content.append(f"\n### SOURCE: {f['name']} (Directory) ###\n")
                                all_content.append(content)
                                source_names.append(f"DIR:{f['name']}")
                                total_bytes += nbytes
                        except Exception as e:
                            errors.append(f"{f['path']}: {e}")

            # ── Finalize ──
            if not all_content:
                no_data_msg = "No log data was collected. "
                if is_windows and not LogCollector.is_admin():
                    no_data_msg += (
                        "This is likely because the application is not running as Administrator.\n\n"
                        "To collect Windows Event Logs:\n"
                        "1. Right-click the application or command prompt\n"
                        "2. Select 'Run as Administrator'\n"
                        "3. Try collecting again\n\n"
                        "Alternatively, uncheck the 'Event Log Files (.evtx)' source and use "
                        "only the individual channel sources (Security, System, PowerShell, etc.) "
                        "which may work with limited privileges."
                    )
                else:
                    no_data_msg += "Check that selected sources are accessible and contain data."

                self.dialog.after(0, lambda: messagebox.showwarning("No Data", no_data_msg))
                self.dialog.after(0, lambda: self.collect_btn.configure(
                    state='normal', text="⬇️  Collect & Analyze Selected"
                ))
                return

            merged = '\n'.join(all_content)
            source_desc = (
                f"Collected {len(source_names)} sources "
                f"({LogCollector.format_size(total_bytes)})"
            )
            if errors:
                source_desc += f" | {len(errors)} errors"

            # Store results and close dialog
            self.result_content = merged
            self.result_source = source_desc
            self.result_errors = errors

            self.dialog.after(0, self._finish_collection)

        threading.Thread(target=task, daemon=True).start()

    def _update_collect_status(self, text):
        """Update status label from background thread."""
        self.dialog.after(0, lambda: self.status_lbl.configure(text=text))

    def _finish_collection(self):
        """Close dialog and feed collected data to the parent analyzer."""
        self.dialog.destroy()

        # Feed to parent's analysis engine FIRST — don't block with popups
        if self.result_content:
            self.parent.current_file = f"[Collected: {self.result_source}]"
            self.parent._analyze_content(self.result_content, self.result_source)
        else:
            # Only show errors when NOTHING was collected
            if self.result_errors:
                perm_denied = [e for e in self.result_errors if 'Permission denied' in str(e) or 'Errno 13' in str(e)]
                other_errors = [e for e in self.result_errors if e not in perm_denied]

                parts = ["No log data was collected.\n"]
                if perm_denied:
                    parts.append(
                        f"⚠️ {len(perm_denied)} sources had permission errors "
                        f"(run as Administrator for full access)"
                    )
                if other_errors:
                    parts.append(f"\n{len(other_errors)} errors:")
                    for e in other_errors[:5]:
                        msg = str(e)
                        if len(msg) > 120:
                            msg = msg[:120] + "..."
                        parts.append(f"  • {msg}")
                    if len(other_errors) > 5:
                        parts.append(f"  ... and {len(other_errors) - 5} more")

                messagebox.showerror("Collection Failed", '\n'.join(parts))
            else:
                messagebox.showinfo("No Data", "No log data was collected. Select at least one source.")

    def _on_close(self):
        """Handle dialog close."""
        self.dialog.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class LogForensicsApp:
    """Main GUI Application."""

    # Color scheme
    BG = '#0a0e14'
    BG2 = '#111820'
    BG3 = '#1a2332'
    FG = '#c5cdd9'
    ACCENT = '#00e5ff'
    ACCENT2 = '#4dd0e1'
    GREEN = '#00c853'
    RED = '#ff1744'
    ORANGE = '#ff6d00'
    YELLOW = '#ffab00'
    BLUE = '#2979ff'

    SEV_COLORS = {
        'CRITICAL': '#ff1744', 'HIGH': '#ff6d00',
        'MEDIUM': '#ffab00', 'LOW': '#2979ff', 'INFO': '#00c853'
    }

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NEATLABS™ Log Forensics Analyzer v3.1")
        self.root.geometry("1600x950")
        self.root.configure(bg=self.BG)
        self.root.minsize(1200, 700)

        # State
        self.events = []
        self.findings = []
        self.iocs = {}
        self.stats = {}
        self.log_format = ''
        self.current_file = ''

        self._setup_styles()
        self._build_gui()
        self._bind_keys()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=self.BG, foreground=self.FG, fieldbackground=self.BG2)
        style.configure('TFrame', background=self.BG)
        style.configure('TLabel', background=self.BG, foreground=self.FG, font=('Segoe UI', 10))
        style.configure('Header.TLabel', background=self.BG, foreground=self.ACCENT, font=('Segoe UI', 20, 'bold'))
        style.configure('Sub.TLabel', background=self.BG, foreground='#8899aa', font=('Segoe UI', 10))
        style.configure('Stat.TLabel', background=self.BG2, foreground=self.ACCENT, font=('Segoe UI', 24, 'bold'))
        style.configure('StatLabel.TLabel', background=self.BG2, foreground='#8899aa', font=('Segoe UI', 9))
        style.configure('TButton', background=self.BG3, foreground=self.FG, font=('Segoe UI', 10),
                        borderwidth=0, padding=(15, 8))
        style.map('TButton', background=[('active', self.BG2)])
        style.configure('Accent.TButton', background='#004d5e', foreground=self.ACCENT, font=('Segoe UI', 10, 'bold'))
        style.map('Accent.TButton', background=[('active', '#006070')])
        style.configure('TNotebook', background=self.BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=self.BG3, foreground=self.FG,
                        padding=(18, 8), font=('Segoe UI', 10))
        style.map('TNotebook.Tab', background=[('selected', self.BG2)],
                  foreground=[('selected', self.ACCENT)])
        style.configure("Treeview", background=self.BG2, foreground=self.FG,
                        fieldbackground=self.BG2, borderwidth=0, font=('Consolas', 10),
                        rowheight=26)
        style.configure("Treeview.Heading", background=self.BG3, foreground=self.ACCENT,
                        font=('Segoe UI', 10, 'bold'))
        style.map("Treeview", background=[('selected', '#1a3550')],
                  foreground=[('selected', '#ffffff')])
        style.configure("Horizontal.TProgressbar", troughcolor=self.BG3,
                        background=self.ACCENT, borderwidth=0)

    def _build_gui(self):
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill='x', padx=15, pady=(10, 5))

        title_frame = ttk.Frame(header)
        title_frame.pack(side='left')
        ttk.Label(title_frame, text="🔒 Log Forensics Analyzer", style='Header.TLabel').pack(anchor='w')
        self.status_label = ttk.Label(title_frame, text="Drop a log file or click Load to begin analysis", style='Sub.TLabel')
        self.status_label.pack(anchor='w')

        btn_frame = ttk.Frame(header)
        btn_frame.pack(side='right')

        ttk.Button(btn_frame, text="📂 Load Log File", style='Accent.TButton',
                  command=self._load_file).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="🗂️ Collect Logs", style='Accent.TButton',
                  command=self._open_collector).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="📋 Load Clipboard", style='TButton',
                  command=self._load_clipboard).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="🔄 Re-Analyze", style='TButton',
                  command=self._reanalyze).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="📊 Export HTML", style='TButton',
                  command=self._export_html).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="📁 Export CSV", style='TButton',
                  command=self._export_csv).pack(side='left', padx=3)
        ttk.Button(btn_frame, text="🔍 Export IOCs", style='TButton',
                  command=self._export_iocs).pack(side='left', padx=3)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode='determinate', style="Horizontal.TProgressbar")
        self.progress.pack(fill='x', padx=15, pady=(0, 5))

        # Stats bar
        self.stats_frame = ttk.Frame(self.root)
        self.stats_frame.pack(fill='x', padx=15, pady=(0, 5))
        self._build_stat_cards()

        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=15, pady=(0, 10))

        self._build_findings_tab()
        self._build_timeline_tab()
        self._build_events_tab()
        self._build_ioc_tab()
        self._build_geo_tab()
        self._build_mitre_tab()
        self._build_raw_tab()

    def _build_stat_cards(self):
        """Build the top statistics cards."""
        self.stat_widgets = {}
        card_defs = [
            ('total', 'TOTAL EVENTS', '0'),
            ('findings', 'FINDINGS', '0'),
            ('critical', 'CRITICAL', '0'),
            ('high', 'HIGH', '0'),
            ('ips', 'UNIQUE IPs', '0'),
            ('users', 'UNIQUE USERS', '0'),
            ('failures', 'FAILED LOGINS', '0'),
            ('format', 'LOG FORMAT', '—'),
        ]

        for i, (key, label, default) in enumerate(card_defs):
            card = tk.Frame(self.stats_frame, bg=self.BG2, padx=12, pady=8,
                           highlightthickness=1, highlightbackground=self.BG3)
            card.pack(side='left', fill='x', expand=True, padx=2)

            val = tk.Label(card, text=default, bg=self.BG2, fg=self.ACCENT,
                          font=('Segoe UI', 18, 'bold'))
            val.pack()
            tk.Label(card, text=label, bg=self.BG2, fg='#8899aa',
                    font=('Segoe UI', 8)).pack()
            self.stat_widgets[key] = val

    def _build_findings_tab(self):
        """Build the Findings tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 🎯 Findings ")

        # Filter bar
        filt = ttk.Frame(tab)
        filt.pack(fill='x', padx=5, pady=5)
        ttk.Label(filt, text="Filter:").pack(side='left', padx=5)

        self.finding_filter = tk.StringVar(value='ALL')
        for sev in ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            rb = tk.Radiobutton(filt, text=sev, variable=self.finding_filter, value=sev,
                               bg=self.BG, fg=self.FG, selectcolor=self.BG2,
                               activebackground=self.BG, activeforeground=self.ACCENT,
                               font=('Segoe UI', 9), command=self._filter_findings)
            rb.pack(side='left', padx=3)

        # Search
        ttk.Label(filt, text="Search:").pack(side='left', padx=(15, 5))
        self.finding_search = tk.Entry(filt, bg=self.BG2, fg=self.FG, insertbackground=self.FG,
                                       font=('Segoe UI', 10), width=25, relief='flat',
                                       highlightthickness=1, highlightbackground=self.BG3)
        self.finding_search.pack(side='left', padx=3)
        self.finding_search.bind('<KeyRelease>', lambda e: self._filter_findings())

        # Findings list
        self.findings_text = scrolledtext.ScrolledText(tab, bg=self.BG2, fg=self.FG,
            font=('Consolas', 10), insertbackground=self.FG, relief='flat',
            highlightthickness=1, highlightbackground=self.BG3, wrap='word', state='disabled')
        self.findings_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Configure tags
        self.findings_text.tag_configure('critical', foreground='#ff1744', font=('Consolas', 10, 'bold'))
        self.findings_text.tag_configure('high', foreground='#ff6d00', font=('Consolas', 10, 'bold'))
        self.findings_text.tag_configure('medium', foreground='#ffab00', font=('Consolas', 10, 'bold'))
        self.findings_text.tag_configure('low', foreground='#2979ff', font=('Consolas', 10, 'bold'))
        self.findings_text.tag_configure('info', foreground='#00c853', font=('Consolas', 10, 'bold'))
        self.findings_text.tag_configure('title', foreground='#ffffff', font=('Consolas', 11, 'bold'))
        self.findings_text.tag_configure('mitre', foreground='#82b1ff', font=('Consolas', 10))
        self.findings_text.tag_configure('evidence', foreground='#8899aa', font=('Consolas', 9))
        self.findings_text.tag_configure('rec', foreground='#69f0ae', font=('Consolas', 9))
        self.findings_text.tag_configure('divider', foreground='#333d4d')
        self.findings_text.tag_configure('risk', foreground='#ffab00')

    def _build_timeline_tab(self):
        """Build the Timeline tab with canvas visualization."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" ⏱ Timeline ")

        self.timeline_canvas = tk.Canvas(tab, bg=self.BG2, highlightthickness=0)
        self.timeline_canvas.pack(fill='both', expand=True, padx=5, pady=5)
        self.timeline_canvas.bind('<Configure>', lambda e: self._draw_timeline())

    def _build_events_tab(self):
        """Build the Events browser tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 📋 Events ")

        # Filter
        filt = ttk.Frame(tab)
        filt.pack(fill='x', padx=5, pady=5)
        ttk.Label(filt, text="Filter:").pack(side='left', padx=5)
        self.event_filter = tk.Entry(filt, bg=self.BG2, fg=self.FG, insertbackground=self.FG,
                                     font=('Segoe UI', 10), width=40, relief='flat',
                                     highlightthickness=1, highlightbackground=self.BG3)
        self.event_filter.pack(side='left', padx=3)
        self.event_filter.bind('<Return>', lambda e: self._filter_events())
        ttk.Button(filt, text="Apply", command=self._filter_events).pack(side='left', padx=3)
        ttk.Button(filt, text="Clear", command=self._clear_event_filter).pack(side='left', padx=3)

        self.event_count_label = ttk.Label(filt, text="0 events", style='Sub.TLabel')
        self.event_count_label.pack(side='right', padx=10)

        # Treeview
        cols = ('time', 'source_ip', 'username', 'action', 'status', 'severity', 'message')
        self.events_tree = ttk.Treeview(tab, columns=cols, show='headings', selectmode='browse')

        widths = {'time': 160, 'source_ip': 120, 'username': 100, 'action': 140,
                  'status': 80, 'severity': 80, 'message': 500}
        for col in cols:
            self.events_tree.heading(col, text=col.upper().replace('_', ' '),
                                    command=lambda c=col: self._sort_events(c))
            self.events_tree.column(col, width=widths.get(col, 100), minwidth=60)

        vsb = ttk.Scrollbar(tab, orient='vertical', command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=vsb.set)

        self.events_tree.pack(side='left', fill='both', expand=True, padx=(5, 0), pady=5)
        vsb.pack(side='right', fill='y', padx=(0, 5), pady=5)

        self.events_tree.bind('<<TreeviewSelect>>', self._on_event_select)

        # Detail pane at bottom
        self.event_detail = scrolledtext.ScrolledText(tab, bg=self.BG, fg=self.FG,
            font=('Consolas', 9), height=6, relief='flat', wrap='word', state='disabled',
            highlightthickness=1, highlightbackground=self.BG3)
        self.event_detail.pack(fill='x', padx=5, pady=(0, 5))

    def _build_ioc_tab(self):
        """Build the IOC extraction tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 🔗 IOCs ")

        self.ioc_text = scrolledtext.ScrolledText(tab, bg=self.BG2, fg=self.FG,
            font=('Consolas', 10), insertbackground=self.FG, relief='flat',
            highlightthickness=1, highlightbackground=self.BG3, wrap='word', state='disabled')
        self.ioc_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.ioc_text.tag_configure('header', foreground=self.ACCENT, font=('Consolas', 12, 'bold'))
        self.ioc_text.tag_configure('subheader', foreground=self.ACCENT2, font=('Consolas', 10, 'bold'))
        self.ioc_text.tag_configure('bad', foreground=self.RED)
        self.ioc_text.tag_configure('count', foreground=self.YELLOW)

    def _build_geo_tab(self):
        """Build the Geo-IP analysis tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 🌍 Geo-IP ")

        cols = ('ip', 'country', 'city', 'events', 'threat_intel', 'first_seen', 'last_seen')
        self.geo_tree = ttk.Treeview(tab, columns=cols, show='headings', selectmode='browse')

        widths = {'ip': 130, 'country': 80, 'city': 120, 'events': 70, 'threat_intel': 120,
                  'first_seen': 160, 'last_seen': 160}
        for col in cols:
            self.geo_tree.heading(col, text=col.upper().replace('_', ' '))
            self.geo_tree.column(col, width=widths.get(col, 100))

        vsb = ttk.Scrollbar(tab, orient='vertical', command=self.geo_tree.yview)
        self.geo_tree.configure(yscrollcommand=vsb.set)
        self.geo_tree.pack(side='left', fill='both', expand=True, padx=(5, 0), pady=5)
        vsb.pack(side='right', fill='y', padx=(0, 5), pady=5)

    def _build_mitre_tab(self):
        """Build the MITRE ATT&CK mapping tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" ⚔ MITRE ATT&CK ")

        self.mitre_text = scrolledtext.ScrolledText(tab, bg=self.BG2, fg=self.FG,
            font=('Consolas', 10), insertbackground=self.FG, relief='flat',
            highlightthickness=1, highlightbackground=self.BG3, wrap='word', state='disabled')
        self.mitre_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.mitre_text.tag_configure('header', foreground=self.ACCENT, font=('Consolas', 14, 'bold'))
        self.mitre_text.tag_configure('tactic', foreground='#bb86fc', font=('Consolas', 12, 'bold'))
        self.mitre_text.tag_configure('technique', foreground=self.ACCENT2, font=('Consolas', 10, 'bold'))
        self.mitre_text.tag_configure('desc', foreground='#aab')
        self.mitre_text.tag_configure('mitigation', foreground=self.GREEN)
        self.mitre_text.tag_configure('finding_ref', foreground=self.ORANGE)

    def _build_raw_tab(self):
        """Build the Raw Log viewer tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 📄 Raw Log ")

        self.raw_text = scrolledtext.ScrolledText(tab, bg=self.BG2, fg=self.FG,
            font=('Consolas', 9), insertbackground=self.FG, relief='flat',
            highlightthickness=1, highlightbackground=self.BG3, wrap='none', state='disabled')
        self.raw_text.pack(fill='both', expand=True, padx=5, pady=5)

    def _bind_keys(self):
        self.root.bind('<Control-o>', lambda e: self._load_file())
        self.root.bind('<Control-e>', lambda e: self._export_html())

        # Drop support via DnD-like behavior (paste file path)
        self.root.bind('<Control-v>', lambda e: self._load_clipboard())

    # ═══════════════════════════════════════════════════════════════════════════
    # FILE LOADING
    # ═══════════════════════════════════════════════════════════════════════════

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("All Log Files", "*.log *.txt *.json *.xml *.evtx *.csv *.tsv"),
                ("Log Files", "*.log"),
                ("Text Files", "*.txt"),
                ("JSON Files", "*.json"),
                ("XML Files", "*.xml"),
                ("CSV Files", "*.csv *.tsv"),
                ("All Files", "*.*"),
            ]
        )
        if path:
            self.current_file = path
            self._analyze_file(path)

    def _load_clipboard(self):
        try:
            content = self.root.clipboard_get()
            if content.strip():
                self._analyze_content(content, "clipboard")
        except:
            messagebox.showinfo("Clipboard", "No text content in clipboard.")

    def _open_collector(self):
        """Open the Log Collection dialog for local system and network share collection."""
        LogCollectorDialog(self)

    def _reanalyze(self):
        if self.events:
            self._run_analysis_on_events()

    def _analyze_file(self, path):
        def task():
            try:
                self._update_status(f"Loading {os.path.basename(path)}...")
                self.progress['value'] = 10

                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                self._analyze_content(content, os.path.basename(path))
            except Exception as ex:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load file:\n{ex}"))
                self.root.after(0, lambda: self._update_status("Error loading file"))

        threading.Thread(target=task, daemon=True).start()

    def _analyze_content(self, content, source_name):
        def task():
            try:
                self._update_status(f"Parsing {source_name}...")
                self._set_progress(20)

                events, fmt = LogParser.parse(content)
                self.events = events
                self.log_format = fmt

                self._set_progress(40)
                self._update_status(f"Parsed {len(events):,} events ({fmt}). Running threat analysis...")

                # Run threat hunting
                hunter = ThreatHunter(events)
                self.findings = hunter.hunt_all()

                self._set_progress(60)

                # Extract IOCs
                self.iocs = IOCExtractor.extract(events)

                self._set_progress(70)

                # Compute statistics
                self.stats = LogStatistics.compute(events)

                self._set_progress(85)

                # Update GUI
                self.root.after(0, lambda: self._populate_all(content))

                self._set_progress(100)
                self._update_status(
                    f"✅ Analysis complete: {len(events):,} events | {len(self.findings)} findings | "
                    f"Format: {fmt} | File: {source_name}"
                )
            except Exception as ex:
                import traceback
                tb = traceback.format_exc()
                self.root.after(0, lambda: messagebox.showerror("Analysis Error", f"{ex}\n\n{tb}"))
                self._update_status("Analysis failed")

        threading.Thread(target=task, daemon=True).start()

    def _run_analysis_on_events(self):
        hunter = ThreatHunter(self.events)
        self.findings = hunter.hunt_all()
        self.iocs = IOCExtractor.extract(self.events)
        self.stats = LogStatistics.compute(self.events)
        self._populate_findings()
        self._populate_iocs()
        self._populate_geo()
        self._populate_mitre()
        self._update_stats()

    def _update_status(self, text):
        self.root.after(0, lambda: self.status_label.configure(text=text))

    def _set_progress(self, val):
        self.root.after(0, lambda: self.progress.configure(value=val))

    # ═══════════════════════════════════════════════════════════════════════════
    # POPULATE GUI
    # ═══════════════════════════════════════════════════════════════════════════

    def _populate_all(self, raw_content=""):
        self._update_stats()
        self._populate_findings()
        self._populate_events()
        self._populate_iocs()
        self._populate_geo()
        self._populate_mitre()
        self._populate_raw(raw_content)
        self._draw_timeline()

    def _update_stats(self):
        s = self.stats
        self.stat_widgets['total'].config(text=f"{s.get('total_events', 0):,}")
        self.stat_widgets['findings'].config(text=str(len(self.findings)))
        crit = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity == 'HIGH')
        self.stat_widgets['critical'].config(text=str(crit), fg=self.RED if crit else self.ACCENT)
        self.stat_widgets['high'].config(text=str(high), fg=self.ORANGE if high else self.ACCENT)
        self.stat_widgets['ips'].config(text=str(s.get('unique_ips', 0)))
        self.stat_widgets['users'].config(text=str(s.get('unique_users', 0)))
        self.stat_widgets['failures'].config(text=f"{s.get('login_failures', 0):,}",
                                             fg=self.RED if s.get('login_failures', 0) > 10 else self.ACCENT)
        self.stat_widgets['format'].config(text=self.log_format.upper())

    def _populate_findings(self):
        self.findings_text.configure(state='normal')
        self.findings_text.delete('1.0', 'end')

        filtered = self._get_filtered_findings()

        if not filtered:
            self.findings_text.insert('end', "\n  No findings match the current filter.\n" if self.findings else
                                     "\n  No log data loaded. Use 'Load Log File' to begin analysis.\n")
            self.findings_text.configure(state='disabled')
            return

        for i, f in enumerate(filtered):
            sev_tag = f.severity.lower()
            self.findings_text.insert('end', f"\n {'━'*120}\n", 'divider')
            self.findings_text.insert('end', f"  [{f.severity}] ", sev_tag)
            self.findings_text.insert('end', f"{f.title}\n", 'title')
            self.findings_text.insert('end', f"  MITRE: {f.mitre_id} — {f.mitre_info.get('name', 'N/A')} | "
                                            f"Tactic: {f.mitre_info.get('tactic', 'N/A')}\n", 'mitre')
            self.findings_text.insert('end', f"  Risk Score: {f.risk_score}/100\n", 'risk')
            self.findings_text.insert('end', f"\n  {f.description}\n\n", '')
            self.findings_text.insert('end', "  Evidence:\n", '')
            for ev in f.evidence:
                self.findings_text.insert('end', f"  {ev}\n", 'evidence')

            if f.source_ips:
                self.findings_text.insert('end', f"\n  Source IPs: {', '.join(f.source_ips[:10])}\n", 'evidence')
            if f.usernames:
                self.findings_text.insert('end', f"  Usernames: {', '.join(f.usernames[:10])}\n", 'evidence')

            self.findings_text.insert('end', f"\n  ✅ Recommendation: {f.recommendation}\n", 'rec')

        self.findings_text.configure(state='disabled')

    def _get_filtered_findings(self):
        sev_filter = self.finding_filter.get()
        search_term = self.finding_search.get().lower().strip() if hasattr(self, 'finding_search') else ''

        filtered = self.findings
        if sev_filter != 'ALL':
            filtered = [f for f in filtered if f.severity == sev_filter]
        if search_term:
            filtered = [f for f in filtered if search_term in f.title.lower() or
                       search_term in f.description.lower() or
                       search_term in f.mitre_id.lower() or
                       any(search_term in ip for ip in f.source_ips) or
                       any(search_term in u.lower() for u in f.usernames)]
        return filtered

    def _filter_findings(self):
        self._populate_findings()

    def _populate_events(self):
        self.events_tree.delete(*self.events_tree.get_children())

        display_events = self.events[:10000]  # Cap display for performance

        for e in display_events:
            ts = str(e.timestamp)[:19] if isinstance(e.timestamp, datetime) else str(e.timestamp)[:19]
            msg = (e.message or '')[:200]
            values = (ts, e.source_ip, e.username, e.action, e.status, e.severity, msg)

            item = self.events_tree.insert('', 'end', values=values)

            # Color code by severity
            if e.severity == 'CRITICAL':
                self.events_tree.item(item, tags=('critical',))
            elif e.severity == 'WARNING':
                self.events_tree.item(item, tags=('warning',))

        self.events_tree.tag_configure('critical', foreground=self.RED)
        self.events_tree.tag_configure('warning', foreground=self.ORANGE)

        self.event_count_label.configure(text=f"{len(display_events):,} of {len(self.events):,} events")

    def _filter_events(self):
        term = self.event_filter.get().lower().strip()
        if not term:
            self._populate_events()
            return

        self.events_tree.delete(*self.events_tree.get_children())
        count = 0
        for e in self.events:
            searchable = f"{e.source_ip} {e.username} {e.action} {e.status} {e.severity} {e.message}".lower()
            if term in searchable:
                ts = str(e.timestamp)[:19] if isinstance(e.timestamp, datetime) else str(e.timestamp)[:19]
                values = (ts, e.source_ip, e.username, e.action, e.status, e.severity, (e.message or '')[:200])
                self.events_tree.insert('', 'end', values=values)
                count += 1
                if count >= 5000:
                    break

        self.event_count_label.configure(text=f"{count:,} matches")

    def _clear_event_filter(self):
        self.event_filter.delete(0, 'end')
        self._populate_events()

    def _sort_events(self, col):
        """Sort events treeview by column."""
        items = [(self.events_tree.set(k, col), k) for k in self.events_tree.get_children('')]
        items.sort()
        for idx, (val, k) in enumerate(items):
            self.events_tree.move(k, '', idx)

    def _on_event_select(self, event):
        sel = self.events_tree.selection()
        if not sel:
            return
        idx = self.events_tree.index(sel[0])
        if idx < len(self.events):
            e = self.events[idx]
            self.event_detail.configure(state='normal')
            self.event_detail.delete('1.0', 'end')
            detail = json.dumps(e.to_dict(), indent=2, default=str)
            self.event_detail.insert('end', detail)
            self.event_detail.configure(state='disabled')

    def _populate_iocs(self):
        self.ioc_text.configure(state='normal')
        self.ioc_text.delete('1.0', 'end')

        iocs = self.iocs
        if not iocs:
            self.ioc_text.insert('end', "\n  No IOCs extracted. Load a log file first.\n")
            self.ioc_text.configure(state='disabled')
            return

        self.ioc_text.insert('end', " Indicators of Compromise\n\n", 'header')

        total = (len(iocs.get('ips', {})) + len(iocs.get('domains', {})) +
                len(iocs.get('emails', {})) + len(iocs.get('hashes_md5', {})) +
                len(iocs.get('hashes_sha1', {})) + len(iocs.get('hashes_sha256', {})) +
                len(iocs.get('urls', {})))
        self.ioc_text.insert('end', f" Total unique IOCs: {total}\n\n")

        # IPs
        if iocs.get('ips'):
            self.ioc_text.insert('end', f" 🌐 IP Addresses ({len(iocs['ips'])})\n", 'subheader')
            for ip, count in iocs['ips'].most_common(50):
                geo = GeoIPLookup.lookup(ip)
                loc = f" [{geo['city']}, {geo['country']}]" if geo else ""
                bad = " ⚠ KNOWN MALICIOUS" if GeoIPLookup.is_in_bad_range(ip) else ""
                tag = 'bad' if bad else ''
                self.ioc_text.insert('end', f"   {ip:<18} ", tag)
                self.ioc_text.insert('end', f"({count:>5} hits)", 'count')
                self.ioc_text.insert('end', f"{loc}{bad}\n", 'bad' if bad else '')

        # Domains
        if iocs.get('domains'):
            self.ioc_text.insert('end', f"\n 🔗 Domains ({len(iocs['domains'])})\n", 'subheader')
            for domain, count in iocs['domains'].most_common(30):
                self.ioc_text.insert('end', f"   {domain:<40} ")
                self.ioc_text.insert('end', f"({count:>5} hits)\n", 'count')

        # Emails
        if iocs.get('emails'):
            self.ioc_text.insert('end', f"\n 📧 Email Addresses ({len(iocs['emails'])})\n", 'subheader')
            for email, count in iocs['emails'].most_common(20):
                self.ioc_text.insert('end', f"   {email:<40} ")
                self.ioc_text.insert('end', f"({count:>5} hits)\n", 'count')

        # Hashes
        for htype, key in [('MD5', 'hashes_md5'), ('SHA1', 'hashes_sha1'), ('SHA256', 'hashes_sha256')]:
            if iocs.get(key):
                self.ioc_text.insert('end', f"\n 🔑 {htype} Hashes ({len(iocs[key])})\n", 'subheader')
                for h, count in iocs[key].most_common(20):
                    self.ioc_text.insert('end', f"   {h}  ")
                    self.ioc_text.insert('end', f"({count})\n", 'count')

        # URLs
        if iocs.get('urls'):
            self.ioc_text.insert('end', f"\n 🔗 URLs ({len(iocs['urls'])})\n", 'subheader')
            for url, count in iocs['urls'].most_common(20):
                self.ioc_text.insert('end', f"   {url[:100]}  ")
                self.ioc_text.insert('end', f"({count})\n", 'count')

        # AWS Keys
        if iocs.get('aws_keys'):
            self.ioc_text.insert('end', f"\n ⚠️ AWS Access Keys ({len(iocs['aws_keys'])})\n", 'subheader')
            for key, count in iocs['aws_keys'].most_common(10):
                self.ioc_text.insert('end', f"   {key}  ", 'bad')
                self.ioc_text.insert('end', f"({count})\n", 'count')

        if iocs.get('private_keys', 0) > 0:
            self.ioc_text.insert('end', f"\n ⚠️ Private Keys Found: {iocs['private_keys']}\n", 'bad')

        # Usernames
        if iocs.get('usernames'):
            self.ioc_text.insert('end', f"\n 👤 User Accounts ({len(iocs['usernames'])})\n", 'subheader')
            for user, count in iocs['usernames'].most_common(30):
                self.ioc_text.insert('end', f"   {user:<30} ")
                self.ioc_text.insert('end', f"({count:>5} events)\n", 'count')

        self.ioc_text.configure(state='disabled')

    def _populate_geo(self):
        self.geo_tree.delete(*self.geo_tree.get_children())

        ip_data = defaultdict(lambda: {'events': 0, 'first': None, 'last': None})
        for e in self.events:
            if e.source_ip:
                d = ip_data[e.source_ip]
                d['events'] += 1
                if isinstance(e.timestamp, datetime):
                    if d['first'] is None or e.timestamp < d['first']:
                        d['first'] = e.timestamp
                    if d['last'] is None or e.timestamp > d['last']:
                        d['last'] = e.timestamp

        for ip, d in sorted(ip_data.items(), key=lambda x: x[1]['events'], reverse=True):
            try:
                addr = ip_address(ip)
                if addr.is_private or addr.is_loopback:
                    continue
            except:
                continue

            geo = GeoIPLookup.lookup(ip)
            country = geo['country'] if geo else 'Unknown'
            city = geo['city'] if geo else 'Unknown'
            threat = "⚠ MALICIOUS" if GeoIPLookup.is_in_bad_range(ip) else "Clean"
            first_seen = str(d['first'])[:19] if d['first'] else '-'
            last_seen = str(d['last'])[:19] if d['last'] else '-'

            item = self.geo_tree.insert('', 'end', values=(ip, country, city, d['events'], threat, first_seen, last_seen))
            if GeoIPLookup.is_in_bad_range(ip):
                self.geo_tree.item(item, tags=('bad',))

        self.geo_tree.tag_configure('bad', foreground=self.RED)

    def _populate_mitre(self):
        self.mitre_text.configure(state='normal')
        self.mitre_text.delete('1.0', 'end')

        if not self.findings:
            self.mitre_text.insert('end', "\n  No MITRE ATT&CK mappings. Load a log file first.\n")
            self.mitre_text.configure(state='disabled')
            return

        self.mitre_text.insert('end', " MITRE ATT&CK Coverage Map\n\n", 'header')

        # Group findings by tactic
        by_tactic = defaultdict(list)
        for f in self.findings:
            if f.mitre_info:
                for tactic in f.mitre_info.get('tactic', 'Unknown').split(', '):
                    by_tactic[tactic.strip()].append(f)

        tactic_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Command and Control', 'Exfiltration', 'Impact'
        ]

        for tactic in tactic_order:
            if tactic in by_tactic:
                findings = by_tactic[tactic]
                self.mitre_text.insert('end', f"\n ▸ {tactic.upper()} ({len(findings)} findings)\n", 'tactic')

                # Group by technique
                by_tech = defaultdict(list)
                for f in findings:
                    by_tech[f.mitre_id].append(f)

                for tech_id, tech_findings in by_tech.items():
                    info = MITRE_ATTACK_DB.get(tech_id, {})
                    tech_name = info.get('name', 'Unknown')
                    self.mitre_text.insert('end', f"\n   {tech_id}: {tech_name}\n", 'technique')
                    self.mitre_text.insert('end', f"   {info.get('description', '')[:200]}\n", 'desc')

                    for f in tech_findings:
                        sev_marker = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '🟢'}
                        marker = sev_marker.get(f.severity, '⚪')
                        self.mitre_text.insert('end', f"     {marker} {f.title} [Risk: {f.risk_score}]\n", 'finding_ref')

                    if info.get('mitigations'):
                        self.mitre_text.insert('end', f"   Mitigations: {', '.join(info['mitigations'])}\n", 'mitigation')

        # Also show any uncovered tactics
        remaining = [t for t in tactic_order if t not in by_tactic]
        if remaining:
            self.mitre_text.insert('end', f"\n\n No Findings for These Tactics:\n", 'header')
            for t in remaining:
                self.mitre_text.insert('end', f"   ○ {t}\n", 'desc')

        self.mitre_text.configure(state='disabled')

    def _populate_raw(self, content):
        self.raw_text.configure(state='normal')
        self.raw_text.delete('1.0', 'end')
        # Show first 100K characters
        display = content[:100000]
        if len(content) > 100000:
            display += f"\n\n... [Truncated: {len(content):,} total characters] ..."
        self.raw_text.insert('end', display)
        self.raw_text.configure(state='disabled')

    def _draw_timeline(self):
        """Draw activity timeline on canvas."""
        canvas = self.timeline_canvas
        canvas.delete('all')

        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 100 or h < 100:
            return

        if not self.events:
            canvas.create_text(w//2, h//2, text="Load a log file to see the activity timeline",
                             fill='#556', font=('Segoe UI', 14))
            return

        # Compute hourly bins
        hourly = defaultdict(lambda: {'total': 0, 'failures': 0, 'critical': 0})
        for e in self.events:
            if isinstance(e.timestamp, datetime):
                key = e.timestamp.replace(minute=0, second=0, microsecond=0)
                hourly[key]['total'] += 1
                if e.status == 'failure':
                    hourly[key]['failures'] += 1
                if e.severity in ('CRITICAL', 'WARNING'):
                    hourly[key]['critical'] += 1

        if not hourly:
            canvas.create_text(w//2, h//2, text="No timestamped events for timeline",
                             fill='#556', font=('Segoe UI', 14))
            return

        sorted_hours = sorted(hourly.keys())
        max_val = max(v['total'] for v in hourly.values()) or 1

        # Drawing params
        margin_l, margin_r, margin_t, margin_b = 70, 30, 40, 60
        plot_w = w - margin_l - margin_r
        plot_h = h - margin_t - margin_b

        # Title
        canvas.create_text(margin_l, 15, text="Activity Timeline", fill=self.ACCENT,
                         font=('Segoe UI', 12, 'bold'), anchor='w')

        # Axes
        canvas.create_line(margin_l, margin_t, margin_l, h - margin_b, fill='#333')
        canvas.create_line(margin_l, h - margin_b, w - margin_r, h - margin_b, fill='#333')

        # Y-axis labels
        for i in range(5):
            y = margin_t + (plot_h * i / 4)
            val = int(max_val * (4 - i) / 4)
            canvas.create_text(margin_l - 5, y, text=str(val), fill='#888',
                             font=('Consolas', 8), anchor='e')
            canvas.create_line(margin_l, y, w - margin_r, y, fill='#1a2332', dash=(2, 4))

        if len(sorted_hours) == 0:
            return

        bar_w = max(2, min(20, plot_w // len(sorted_hours) - 1))
        step = plot_w / len(sorted_hours) if len(sorted_hours) > 0 else plot_w

        for i, hour in enumerate(sorted_hours):
            x = margin_l + (i * step) + step / 2
            data = hourly[hour]

            # Total bar
            bar_h = (data['total'] / max_val) * plot_h
            y_top = h - margin_b - bar_h
            color = self.ACCENT
            if data['critical'] > data['total'] * 0.3:
                color = self.RED
            elif data['failures'] > data['total'] * 0.3:
                color = self.ORANGE

            canvas.create_rectangle(x - bar_w/2, y_top, x + bar_w/2, h - margin_b,
                                  fill=color, outline='', stipple='')

            # Failure overlay
            if data['failures'] > 0:
                fail_h = (data['failures'] / max_val) * plot_h
                canvas.create_rectangle(x - bar_w/2, h - margin_b - fail_h,
                                      x + bar_w/2, h - margin_b,
                                      fill=self.RED, outline='')

            # X-axis labels (every Nth)
            label_interval = max(1, len(sorted_hours) // 15)
            if i % label_interval == 0:
                label = hour.strftime('%m/%d\n%H:%M')
                canvas.create_text(x, h - margin_b + 10, text=label, fill='#888',
                                 font=('Consolas', 7), anchor='n')

        # Legend
        lx = w - margin_r - 200
        ly = margin_t + 5
        canvas.create_rectangle(lx, ly, lx + 10, ly + 10, fill=self.ACCENT, outline='')
        canvas.create_text(lx + 15, ly + 5, text="Total Events", fill='#888', font=('Segoe UI', 8), anchor='w')
        canvas.create_rectangle(lx, ly + 15, lx + 10, ly + 25, fill=self.RED, outline='')
        canvas.create_text(lx + 15, ly + 20, text="Failed Events", fill='#888', font=('Segoe UI', 8), anchor='w')

    # ═══════════════════════════════════════════════════════════════════════════
    # EXPORT
    # ═══════════════════════════════════════════════════════════════════════════

    def _export_html(self):
        if not self.events:
            messagebox.showinfo("Export", "No data to export. Load a log file first.")
            return

        path = filedialog.asksaveasfilename(
            title="Export HTML Report",
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")],
            initialfile=f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        if path:
            html = ReportGenerator.generate_html(self.stats, self.findings, self.iocs, self.events)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Export Complete", f"HTML report saved to:\n{path}")

    def _export_csv(self):
        if not self.findings:
            messagebox.showinfo("Export", "No findings to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Findings CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Severity', 'Risk Score', 'Title', 'Description',
                               'MITRE ID', 'MITRE Technique', 'MITRE Tactic',
                               'Source IPs', 'Usernames', 'Recommendation'])
                for finding in self.findings:
                    writer.writerow([
                        finding.id, finding.severity, finding.risk_score,
                        finding.title, finding.description,
                        finding.mitre_id, finding.mitre_info.get('name', ''),
                        finding.mitre_info.get('tactic', ''),
                        '; '.join(finding.source_ips[:10]),
                        '; '.join(finding.usernames[:10]),
                        finding.recommendation
                    ])
            messagebox.showinfo("Export Complete", f"Findings CSV saved to:\n{path}")

    def _export_iocs(self):
        if not self.iocs:
            messagebox.showinfo("Export", "No IOCs to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export IOCs JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if path:
            export = {}
            for key in ['ips', 'domains', 'emails', 'hashes_md5', 'hashes_sha1',
                        'hashes_sha256', 'urls', 'aws_keys', 'usernames']:
                if key in self.iocs and self.iocs[key]:
                    export[key] = dict(self.iocs[key].most_common(100))

            # Add geo-IP context for IPs
            if 'ips' in export:
                ip_details = {}
                for ip in export['ips']:
                    geo = GeoIPLookup.lookup(ip)
                    ip_details[ip] = {
                        'count': export['ips'][ip],
                        'geo': geo,
                        'malicious': GeoIPLookup.is_in_bad_range(ip)
                    }
                export['ip_details'] = ip_details

            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"IOCs JSON saved to:\n{path}")

    def run(self):
        self.root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app = LogForensicsApp()
    app.run()
