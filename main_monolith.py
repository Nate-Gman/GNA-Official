"""Global Network Archive - Single-File Monolith.
All submodules inlined. Runs Start PubLAN.bat upon launch.

Threading Model:
- Main thread: Blocks on infinite loop with 1-second sleeps
- Discovery thread (daemon): Runs every 5 seconds to update peer bookkeeping
- Flask thread (daemon): Runs HTTP server for web UI and peer communication
- Status thread (daemon): Runs every 5 seconds to print live status

Graceful Shutdown:
- KeyboardInterrupt (Ctrl+C) caught, prints warning
- Daemon threads are killed automatically when main exits
- User prompted to press Enter to close window
"""
from __future__ import annotations


import asyncio
import hashlib
import hmac as hmac_module
import json
import logging
import logging.handlers
import os
import platform
import random
import re
import shutil
import socket
import string
import struct
import base64
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Dict, Final, List, Optional, Protocol, Tuple

import argparse
import contextlib
import datetime
import ipaddress
import math
import queue
import sqlite3
import statistics
import urllib.request
from collections import Counter, defaultdict, deque
from logging.handlers import RotatingFileHandler

import io as _io
import requests
import socketio

import psutil

try:
    from scapy.all import (
        ARP, BOOTP, DHCP, DNS, IP, TCP, UDP,
        Ether, IPv6, Raw, sniff, srp,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

_IS_WINDOWS = os.name == 'nt'
if _IS_WINDOWS:
    try:
        import winreg
        import ctypes
        import ctypes.wintypes
    except ImportError:
        _IS_WINDOWS = False

try:
    import uvicorn
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    import manuf
    _PARSER = manuf.MacParser()
    _HAS_MANUF = True
except ImportError:
    _HAS_MANUF = False
    _PARSER = None

try:
    import geoip2.database as _geoip2_db
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

# Fix Windows console encoding — emoji/unicode chars crash cp1252
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

_mb_logger = logging.getLogger('medianbox')


# ========================== USER CONFIG ==========================
ALLOWED_APPS = {
    "zoom": False, "google": True, "cloudflare": False, "teams": False,
    "slack": False, "discord": False, "riot": True, "league": True,
}

MIMIC_KEYWORDS = {
    "zoom":       ["zoom", "zmeet", "zoomus", "zoom.us"],
    "google":     ["google", "gstatic", "googlevideo", "googleapis", "goog"],
    "cloudflare": ["cloudflare", "cf-", "warp", "one.one"],
    "teams":      ["teams", "microsoftonline", "microsoft365", "office365"],
    "slack":      ["slack", "slack-edge"],
    "discord":    ["discord", "discordapp", "dis.gd"],
    "riot":       ["riot", "riotgames", "leagueoflegends"],
    "league":     ["league", "lol", "lolesports"],
    "chrome":     ["chrome", "chromium"],
    "firefox":    ["firefox", "mozilla"],
    "edge":       ["msedge", "microsoftedge"],
}

EXPECTED_EXE_PATHS = {
    "chrome.exe":       [r"google\chrome\application"],
    "firefox.exe":      [r"mozilla firefox"],
    "msedge.exe":       [r"microsoft\edge\application"],
    "zoom.exe":         [r"zoom\bin", r"zoom"],
    "discord.exe":      [r"discord\app"],
    "teams.exe":        [r"microsoft teams", r"teams"],
    "slack.exe":        [r"slack\app"],
    "riotclientservices.exe": [r"riot games"],
    "leagueclient.exe": [r"riot games\league of legends"],
    "league of legends.exe": [r"riot games\league of legends"],
    "svchost.exe":      [r"windows\system32"],
    "csrss.exe":        [r"windows\system32"],
    "lsass.exe":        [r"windows\system32"],
    "services.exe":     [r"windows\system32"],
    "smss.exe":         [r"windows\system32"],
    "winlogon.exe":     [r"windows\system32"],
    "explorer.exe":     [r"windows"],
    "taskhostw.exe":    [r"windows\system32"],
    "conhost.exe":      [r"windows\system32"],
    "dllhost.exe":      [r"windows\system32"],
    "wininit.exe":      [r"windows\system32"],
    "spoolsv.exe":      [r"windows\system32"],
}

EXPECTED_PARENTS = {
    "svchost.exe":  ["services.exe"],
    "csrss.exe":    ["smss.exe"],
    "lsass.exe":    ["wininit.exe"],
    "services.exe": ["wininit.exe"],
    "smss.exe":     ["system"],
    "winlogon.exe": ["smss.exe"],
    "wininit.exe":  ["smss.exe"],
    "taskhostw.exe": ["svchost.exe"],
}

KNOWN_SERVICE_RANGES = {
    "riot":  ["104.160.128.0/17", "185.40.64.0/22", "162.249.72.0/21",
              "103.10.8.0/22", "45.7.36.0/22"],
    "google":["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
              "209.85.128.0/17", "74.125.0.0/16", "64.233.160.0/19",
              "173.194.0.0/16", "108.177.0.0/17", "35.190.0.0/17"],
    "cloudflare": ["104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22",
                   "1.1.1.0/24", "1.0.0.0/24"],
    "microsoft": ["13.64.0.0/11", "20.33.0.0/16", "20.40.0.0/13",
                  "40.64.0.0/10", "52.96.0.0/12", "52.112.0.0/14"],
    "discord": ["162.159.128.0/17", "66.22.196.0/22"],
    "zoom":  ["3.7.35.0/25", "3.21.137.128/25", "3.22.11.0/24",
              "8.5.128.0/23", "64.125.62.0/24", "64.211.144.0/24",
              "65.39.152.0/24", "69.174.57.0/24", "147.124.96.0/19",
              "170.114.0.0/16", "206.247.0.0/16", "209.9.211.0/24"],
}

HARDWARE_KEYWORDS = {
    'audio':  ['audiodg', 'audioservice', 'pulseaudio', 'pipewire', 'rtkaudioservice'],
    'camera': ['camerabrokersvc', 'frameworkservice', 'webcam', 'camerahelper'],
}

PERSISTENCE_KEYS = []
if _IS_WINDOWS:
    PERSISTENCE_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

SUSPICIOUS_DLL_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\downloads\\",
    "\\desktop\\", "\\public\\", "\\programdata\\", "\\users\\public",
]

# ========================== DEFAULT CONFIG ==========================
CONFIG = {
    'remote_ports': {22, 3389, 5900, 5938, 445, 139, 5985, 5986},
    'probe_alert_ports': {21, 23, 80, 443, 445, 22, 3389, 5900},
    'alert_cooldown': 75,
    'deduction_cooldown': 120,
    'db_file': 'medianbox_ultimate.db',
    'log_file': 'medianbox_ultimate.log',
    'actions_log': 'medianbox_full_actions.log',
    'deductions_log': 'medianbox_deductions.log',
    'process_scan_interval': 3,
    'scan_interval_min': 5,
    'scan_interval_max': 55,
    'baseline_min_samples': 50,
    'beacon_min_samples': 20,
    'risk_critical': 70,
    'risk_warning': 40,
    'entropy_suspicious_threshold': 7.2,
    'exfil_bytes_spike_factor': 10,
    'exfil_min_bytes': 1_000_000,
    'dns_tunnel_max_label_len': 50,
    'dns_tunnel_entropy_threshold': 3.5,
    'dns_tunnel_query_rate_threshold': 30,
    'geoip_cache_ttl': 3600,
    'geoip_enabled': True,
    'high_risk_countries': {'CN', 'RU', 'KP', 'IR'},
    'user_idle_threshold': 300,
    'registry_scan_interval': 60,
    'dll_scan_interval': 30,
    'escalation_window': 300,
    'escalation_multiplier': 1.5,
    'siem_output': None,
    'siem_host': '127.0.0.1',
    'siem_port': 514,
    'dashboard_enabled': True,
    'dashboard_port': 8470,
    'ml_baseline_window': 86400,
    'ml_zscore_threshold': 3.0,
    'config_file': 'medianbox_config.yaml',
    'pipeline_workers': 2,
    'pipeline_queue_size': 5000,
    'dashboard_password': '',
    'geoip_db_path': '',
}

EMOJI = {
    'new': '🆕', 'alert': '🚨', 'remote': '🔌', 'probe': '🔍', 'kill': '☠️',
    'ok': '✅', 'spoof': '🕵️', 'mimic': '🎭', 'foreign': '🌍', 'chess': '♟️',
    'beacon': '📡', 'phantom': '👻', 'impersonate': '🥸', 'inject': '💉',
    'anomaly': '📊', 'brain': '🧠', 'tunnel': '🕳️', 'exfil': '📤',
    'entropy': '🔐', 'dll': '🧩', 'persist': '📌', 'geo': '🗺️',
    'idle': '💤', 'ml': '🤖', 'escalate': '⬆️', 'dashboard': '📺',
}


class Colors:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    C = '\033[96m'
    M = '\033[95m'
    B = '\033[94m'
    W = '\033[97m'
    END = '\033[0m'


# ========================== CONFIG SCHEMA & VALIDATION ==========================
CONFIG_SCHEMA = {
    'remote_ports':               {'type': set,   'elem': int},
    'probe_alert_ports':          {'type': set,   'elem': int},
    'alert_cooldown':             {'type': (int, float), 'min': 0},
    'deduction_cooldown':         {'type': (int, float), 'min': 0},
    'db_file':                    {'type': str},
    'log_file':                   {'type': str},
    'actions_log':                {'type': str},
    'deductions_log':             {'type': str},
    'process_scan_interval':      {'type': (int, float), 'min': 0.5, 'max': 60},
    'scan_interval_min':          {'type': (int, float), 'min': 1},
    'scan_interval_max':          {'type': (int, float), 'min': 1},
    'baseline_min_samples':       {'type': int, 'min': 5},
    'beacon_min_samples':         {'type': int, 'min': 5},
    'risk_critical':              {'type': (int, float), 'min': 0, 'max': 1000},
    'risk_warning':               {'type': (int, float), 'min': 0, 'max': 1000},
    'entropy_suspicious_threshold': {'type': (int, float), 'min': 0, 'max': 8},
    'exfil_bytes_spike_factor':   {'type': (int, float), 'min': 1},
    'exfil_min_bytes':            {'type': int, 'min': 1000},
    'dns_tunnel_max_label_len':   {'type': int, 'min': 10},
    'dns_tunnel_entropy_threshold': {'type': (int, float), 'min': 0, 'max': 8},
    'dns_tunnel_query_rate_threshold': {'type': (int, float), 'min': 1},
    'geoip_cache_ttl':            {'type': (int, float), 'min': 0},
    'geoip_enabled':              {'type': bool},
    'high_risk_countries':        {'type': set, 'elem': str},
    'user_idle_threshold':        {'type': (int, float), 'min': 0},
    'registry_scan_interval':     {'type': (int, float), 'min': 5},
    'dll_scan_interval':          {'type': (int, float), 'min': 5},
    'escalation_window':          {'type': (int, float), 'min': 10},
    'escalation_multiplier':      {'type': (int, float), 'min': 1.0, 'max': 10.0},
    'siem_output':                {'type': (str, type(None)), 'choices': {None, 'json', 'cef', 'syslog'}},
    'siem_host':                  {'type': str},
    'siem_port':                  {'type': int, 'min': 1, 'max': 65535},
    'dashboard_enabled':          {'type': bool},
    'dashboard_port':             {'type': int, 'min': 1, 'max': 65535},
    'ml_baseline_window':         {'type': (int, float), 'min': 60},
    'ml_zscore_threshold':        {'type': (int, float), 'min': 1.0},
    'config_file':                {'type': str},
    'pipeline_workers':           {'type': int, 'min': 1, 'max': 16},
    'pipeline_queue_size':        {'type': int, 'min': 100},
}


def validate_config(cfg: dict) -> list:
    """Validate config dict against schema. Returns list of error strings (empty = valid)."""
    errors = []
    for key, rules in CONFIG_SCHEMA.items():
        if key not in cfg:
            continue
        val = cfg[key]
        expected_type = rules['type']
        if not isinstance(val, expected_type):
            errors.append(f"{key}: expected {expected_type}, got {type(val).__name__} ({val!r})")
            continue
        if 'elem' in rules and isinstance(val, set):
            for item in val:
                if not isinstance(item, rules['elem']):
                    errors.append(f"{key}: set element {item!r} is not {rules['elem'].__name__}")
                    break
        if 'min' in rules and isinstance(val, (int, float)) and val < rules['min']:
            errors.append(f"{key}: {val} < minimum {rules['min']}")
        if 'max' in rules and isinstance(val, (int, float)) and val > rules['max']:
            errors.append(f"{key}: {val} > maximum {rules['max']}")
        if 'choices' in rules and val not in rules['choices']:
            errors.append(f"{key}: {val!r} not in {rules['choices']}")
    return errors


def load_config(cfg_path: Optional[str] = None):
    """Load config from YAML file, validate, and merge into CONFIG."""
    try:
        import yaml
    except ImportError:
        _mb_logger.info("PyYAML not installed — using default config")
        return
    cfg_file = cfg_path or CONFIG.get('config_file', 'medianbox_config.yaml')
    if not os.path.exists(cfg_file):
        _mb_logger.debug("Config file %s not found — using defaults", cfg_file)
        return
    try:
        with open(cfg_file, encoding='utf-8') as f:
            user_cfg = yaml.safe_load(f) or {}
    except Exception as exc:
        _mb_logger.warning("Failed to load config from %s: %s", cfg_file, exc)
        return
    for k, v in user_cfg.items():
        if k in CONFIG and isinstance(CONFIG[k], set) and isinstance(v, list):
            user_cfg[k] = set(v)
    errors = validate_config(user_cfg)
    if errors:
        for err in errors:
            _mb_logger.warning("Config validation error: %s", err)
        _mb_logger.warning("Config file has %d error(s) — invalid keys were NOT applied", len(errors))
        error_keys = {e.split(':')[0] for e in errors}
        for k, v in user_cfg.items():
            if k in CONFIG and k not in error_keys:
                CONFIG[k] = v
    else:
        for k, v in user_cfg.items():
            if k in CONFIG:
                CONFIG[k] = v
    _mb_logger.info("Loaded config from %s", cfg_file)


# ========================== MODELS ==========================
@dataclass
class ProcessProfile:
    pid: int
    name: str
    exe_path: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    start_time: float = 0.0
    destinations: set[str] = field(default_factory=set)
    dns_domains: set[str] = field(default_factory=set)
    sni_domains: set[str] = field(default_factory=set)
    connection_count: int = 0
    seen_conn_keys: set[tuple] = field(default_factory=set)
    cpu_samples: "deque[float]" = field(default_factory=lambda: deque(maxlen=60))
    packet_timestamps: "deque[float]" = field(default_factory=lambda: deque(maxlen=500))
    bytes_sent: int = 0
    bytes_recv: int = 0
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)
    last_network_ts: float = 0.0
    checked_legitimacy: bool = False
    checked_dlls: bool = False
    io_baseline_sent: int = 0
    io_baseline_recv: int = 0
    io_snapshot_time: float = 0.0
    geo_countries: set[str] = field(default_factory=set)
    loaded_dlls: list[str] = field(default_factory=list)
    escalation_hits: int = 0
    ml_anomaly_score: float = 0.0


@dataclass
class Deduction:
    timestamp: float
    severity: str
    category: str
    process_name: str
    pid: int
    message: str
    evidence: list
    score: float


# ========================== OUI LOOKUP ==========================
_FALLBACK_OUI = {
    '001A2B': 'Apple', 'ACBC32': 'Samsung', '000C29': 'VMware', '001C42': 'D-Link',
    'AC8995': 'TP-Link', '001E65': 'Netgear', 'B827EB': 'Raspberry Pi', 'F81A67': 'TP-Link',
    '001122': 'Generic', '0024E4': 'Withings', '00156D': 'Ubiquiti', '001B11': 'ARRIS',
    '00E04C': 'Realtek', '0017C4': 'Nokia', '0019E0': 'TP-Link', '0024A5': 'Freebox',
    '001D92': 'AVM', '0026B9': 'Dell', '001310': 'HP', '001E0B': 'Hewlett-Packard',
    'F0B429': 'Google Nest', '00163E': 'ASUSTek', '0024D2': 'Askey', '001B21': 'Intel',
    '0014D1': 'OvisLink', '0019FB': 'Philips', '0023DF': 'Sony', '000E8F': 'ADT',
    'F4F5D8': 'Google', '0017B0': 'Samsung', '0018F8': 'Linksys', '0023BE': 'Belkin',
    '001D0F': 'TP-Link', '0024D7': 'Xiaomi', '0019E3': 'Aruba', '0026BB': 'ARRIS',
}


def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    if _HAS_MANUF:
        try:
            result = _PARSER.get_manuf(mac)
            if result:
                return result
        except Exception as exc:
            _mb_logger.debug("manuf lookup failed for %s: %s", mac, exc)
    prefix = mac.upper().replace(':', '').replace('-', '')[:6]
    return _FALLBACK_OUI.get(prefix, "Unknown Vendor")


# ========================== DNS CACHE & TUNNEL DETECTOR ==========================
class DNSCache:
    """Thread-safe DNS resolution cache built from sniffed DNS responses."""
    def __init__(self):
        self.ip_to_domains: dict[str, set[str]] = defaultdict(set)
        self.domain_to_ips: dict[str, set[str]] = defaultdict(set)
        self.query_log: deque = deque(maxlen=5000)
        self.lock = threading.Lock()

    def process_packet(self, pkt):
        if not pkt.haslayer(DNS):
            return
        dns_layer = pkt[DNS]
        if dns_layer.qr == 1 and dns_layer.ancount > 0:
            try:
                qname = dns_layer.qd.qname.decode(errors='ignore').rstrip('.')
                rr = dns_layer.an
                for _ in range(min(dns_layer.ancount, 30)):
                    if rr is None:
                        break
                    if hasattr(rr, 'rdata'):
                        ip_str = str(rr.rdata)
                        try:
                            ipaddress.ip_address(ip_str)
                            with self.lock:
                                self.ip_to_domains[ip_str].add(qname)
                                self.domain_to_ips[qname].add(ip_str)
                        except ValueError:
                            pass
                    rr = rr.payload if hasattr(rr, 'payload') and rr.payload else None
            except Exception as exc:
                _mb_logger.debug("DNS response parse error: %s", exc)
        elif dns_layer.qr == 0:
            try:
                qname = dns_layer.qd.qname.decode(errors='ignore').rstrip('.')
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                with self.lock:
                    self.query_log.append((time.time(), src, qname))
            except Exception as exc:
                _mb_logger.debug("DNS query parse error: %s", exc)

    def get_domains(self, ip: str) -> set[str]:
        with self.lock:
            return set(self.ip_to_domains.get(ip, set()))

    def get_ips(self, domain: str) -> set[str]:
        with self.lock:
            return set(self.domain_to_ips.get(domain, set()))

    def recent_queries(self, keyword: str, window: float = 120) -> list[tuple]:
        cutoff = time.time() - window
        with self.lock:
            return [(t, s, d) for t, s, d in self.query_log
                    if t > cutoff and keyword in d.lower()]

    # --- Windows DNS client cache polling ---
    def poll_system_dns_cache(self):
        """Harvest IP→domain mappings from the Windows DNS client cache.
        Uses ipconfig /displaydns with CNAME chain tracking, then
        PowerShell Get-DnsClientCache for richer data."""
        added = 0
        added += self._poll_ipconfig_displaydns()
        added += self._poll_powershell_dns_cache()
        if added:
            _mb_logger.debug("DNS cache poll: added %d new IP→domain mappings total", added)

    def _add_domain_ip(self, ip_str: str, domain: str) -> bool:
        """Add a single IP→domain mapping. Returns True if new."""
        domain = domain.rstrip('.').lower()
        if not domain or not ip_str:
            return False
        with self.lock:
            if domain not in self.ip_to_domains.get(ip_str, set()):
                self.ip_to_domains[ip_str].add(domain)
                self.domain_to_ips[domain].add(ip_str)
                return True
        return False

    def _poll_ipconfig_displaydns(self) -> int:
        """Parse 'ipconfig /displaydns' with CNAME chain resolution."""
        try:
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            if result.returncode != 0:
                return 0
            # Pass 1: collect all record names → A/AAAA IPs and CNAME targets
            current_name = None
            a_records = {}      # record_name → set of IPs
            cname_map = {}      # cname_target → set of original names that point to it
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith('Record Name'):
                    parts = stripped.split(':', 1)
                    if len(parts) == 2:
                        current_name = parts[1].strip().rstrip('.').lower()
                elif current_name:
                    if 'A (Host) Record' in stripped or 'AAAA' in stripped:
                        parts = stripped.split(':', 1)
                        if len(parts) == 2:
                            ip_str = parts[1].strip()
                            try:
                                ipaddress.ip_address(ip_str)
                                a_records.setdefault(current_name, set()).add(ip_str)
                            except ValueError:
                                pass
                    elif 'CNAME Record' in stripped:
                        parts = stripped.split(':', 1)
                        if len(parts) == 2:
                            target = parts[1].strip().rstrip('.').lower()
                            cname_map.setdefault(target, set()).add(current_name)
            # Pass 2: for each A record, follow CNAME chains back to original names
            added = 0
            for record_name, ips in a_records.items():
                # Collect all names that resolve to these IPs (including CNAME sources)
                all_names = {record_name}
                queue = [record_name]
                visited = set()
                while queue:
                    name = queue.pop()
                    if name in visited:
                        continue
                    visited.add(name)
                    # Find names that CNAME to this name
                    for source in cname_map.get(name, set()):
                        all_names.add(source)
                        queue.append(source)
                for ip_str in ips:
                    for name in all_names:
                        if self._add_domain_ip(ip_str, name):
                            added += 1
            return added
        except Exception as exc:
            _mb_logger.debug("ipconfig /displaydns parse error: %s", exc)
            return 0

    def _poll_powershell_dns_cache(self) -> int:
        """Use PowerShell Get-DnsClientCache for richer DNS data with original query names."""
        try:
            cmd = (
                'Get-DnsClientCache -Status Success -ErrorAction SilentlyContinue '
                '| Where-Object { $_.Type -in 1,28 } '
                '| Select-Object -Property Entry,Data '
                '| Format-Table -HideTableHeaders -AutoSize'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            if result.returncode != 0:
                return 0
            added = 0
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    entry = parts[0].strip().rstrip('.').lower()
                    ip_str = parts[-1].strip()
                    try:
                        ipaddress.ip_address(ip_str)
                        if self._add_domain_ip(ip_str, entry):
                            added += 1
                    except ValueError:
                        pass
            return added
        except Exception as exc:
            _mb_logger.debug("PowerShell DNS cache error: %s", exc)
            return 0

    # --- Persistent domain history ---
    _HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dns_domain_history.json')

    def save_history(self):
        """Persist all IP→domain mappings to disk so they survive restarts."""
        try:
            with self.lock:
                data = {ip: sorted(doms) for ip, doms in self.ip_to_domains.items() if doms}
            with open(self._HISTORY_FILE, 'w') as f:
                json.dump(data, f)
        except Exception as exc:
            _mb_logger.debug("DNS history save error: %s", exc)

    def load_history(self):
        """Load persisted IP→domain mappings from a previous session."""
        try:
            if not os.path.exists(self._HISTORY_FILE):
                return
            with open(self._HISTORY_FILE, 'r') as f:
                data = json.load(f)
            added = 0
            with self.lock:
                for ip, doms in data.items():
                    for d in doms:
                        if d not in self.ip_to_domains.get(ip, set()):
                            self.ip_to_domains[ip].add(d)
                            self.domain_to_ips[d].add(ip)
                            added += 1
            if added:
                _mb_logger.debug("DNS history: loaded %d IP→domain mappings from disk", added)
        except Exception as exc:
            _mb_logger.debug("DNS history load error: %s", exc)


class DNSTunnelingDetector:
    """Detects data exfiltration via DNS queries (long subdomains, high entropy, high rate)."""
    def __init__(self):
        self.domain_query_counts: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.lock = threading.Lock()

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def analyze_query(self, qname: str) -> tuple[bool, float, list[str]]:
        evidence = []
        score = 0.0
        parts = qname.split('.')
        if len(parts) < 2:
            return False, 0, []
        base_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        max_label = max((len(p) for p in parts[:-2]), default=0)
        if max_label > CONFIG['dns_tunnel_max_label_len']:
            evidence.append(f"Very long subdomain label: {max_label} chars")
            score += 25
        if subdomain:
            ent = self.shannon_entropy(subdomain.replace('.', ''))
            if ent > CONFIG['dns_tunnel_entropy_threshold']:
                evidence.append(f"High subdomain entropy: {ent:.2f} bits")
                score += 25
        now = time.time()
        with self.lock:
            self.domain_query_counts[base_domain].append(now)
            recent = sum(1 for t in self.domain_query_counts[base_domain] if now - t < 60)
        if recent > CONFIG['dns_tunnel_query_rate_threshold']:
            evidence.append(f"High query rate: {recent}/min to {base_domain}")
            score += 25
        if len(evidence) >= 2:
            score += 15
            evidence.append("Multiple indicators — high confidence DNS tunneling")
        return score >= 25, score, evidence


# ========================== NETWORK DETECTORS ==========================
class BeaconDetector:
    """Catches C2 beaconing via inter-packet timing regularity analysis."""
    @staticmethod
    def analyze(timestamps) -> tuple[bool, float, str]:
        if len(timestamps) < CONFIG['beacon_min_samples']:
            return False, 0.0, ""
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        if not intervals:
            return False, 0.0, ""
        mean_iv = statistics.mean(intervals)
        if mean_iv < 0.5:
            return False, 0.0, ""
        try:
            stdev_iv = statistics.stdev(intervals)
            cv = stdev_iv / mean_iv if mean_iv > 0 else float('inf')
        except statistics.StatisticsError:
            return False, 0.0, ""
        if cv < 0.12 and mean_iv > 2:
            conf = min(1.0, (0.12 - cv) / 0.12 + 0.5)
            return True, conf, f"Fixed beacon: {mean_iv:.1f}s +/-{stdev_iv:.2f}s jitter={cv:.3f}"
        if cv < 0.25 and mean_iv > 5 and len(intervals) > 40:
            conf = min(0.85, (0.25 - cv) / 0.25 + 0.3)
            return True, conf, f"Periodic callback: ~{mean_iv:.1f}s jitter={cv:.3f}"
        if len(intervals) > 30:
            median_iv = statistics.median(intervals)
            if median_iv > 3:
                within = sum(1 for i in intervals if abs(i - median_iv) < median_iv * 0.15)
                ratio = within / len(intervals)
                if ratio > 0.65:
                    return True, ratio * 0.75, f"Clustered: ~{median_iv:.1f}s {ratio:.0%} consistent"
        return False, 0.0, ""


class SNIExtractor:
    """Extracts Server Name Indication from TLS ClientHello."""
    @staticmethod
    def extract(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 6 or data[0] != 0x16:
                return None
            hs_data = data[5:]
            if len(hs_data) < 4 or hs_data[0] != 0x01:
                return None
            ch_len = int.from_bytes(hs_data[1:4], 'big')
            ch = hs_data[4:4+ch_len]
            if len(ch) < 38:
                return None
            offset = 34
            sess_id_len = ch[offset]
            offset += 1 + sess_id_len
            if offset + 2 > len(ch):
                return None
            cipher_len = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2 + cipher_len
            if offset >= len(ch):
                return None
            comp_len = ch[offset]
            offset += 1 + comp_len
            if offset + 2 > len(ch):
                return None
            ext_total = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2
            end = min(offset + ext_total, len(ch))
            while offset + 4 < end:
                ext_type = int.from_bytes(ch[offset:offset+2], 'big')
                ext_len = int.from_bytes(ch[offset+2:offset+4], 'big')
                offset += 4
                if ext_type == 0x0000:
                    sni_data = ch[offset:offset+ext_len]
                    if len(sni_data) >= 5:
                        name_len = int.from_bytes(sni_data[3:5], 'big')
                        if len(sni_data) >= 5 + name_len:
                            return sni_data[5:5+name_len].decode('ascii', errors='ignore')
                offset += ext_len
        except Exception as exc:
            _mb_logger.debug("SNI extraction error: %s", exc)
        return None


class EntropyAnalyzer:
    """Shannon entropy analysis on packet payloads to detect encrypted C2."""
    @staticmethod
    def payload_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def is_suspicious(pkt, entropy_val: float) -> tuple[bool, str]:
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        tls_ports = {443, 8443, 993, 995, 465, 636}
        if dport in tls_ports or sport in tls_ports:
            return False, ""
        if entropy_val > CONFIG['entropy_suspicious_threshold']:
            return True, (f"High entropy {entropy_val:.2f} on non-TLS port "
                          f"(sport={sport} dport={dport}) — possible encrypted C2")
        return False, ""


# ========================== PROCESS DETECTORS ==========================
class ProcessLegitimacyChecker:
    """Detects impersonation by verifying exe path and parent chain."""
    @staticmethod
    def check_path(name: str, exe_path: str) -> tuple[bool, str]:
        name_l = name.lower()
        exe_l = (exe_path or "").lower()
        if name_l in EXPECTED_EXE_PATHS and exe_l and not any(f in exe_l for f in EXPECTED_EXE_PATHS[name_l]):
            return True, f"'{name}' at unexpected path: {exe_path}"
        return False, ""

    @staticmethod
    def check_parent(name: str, parent_name: str) -> tuple[bool, str]:
        name_l = name.lower()
        parent_l = (parent_name or "").lower()
        if name_l in EXPECTED_PARENTS:
            expected = EXPECTED_PARENTS[name_l]
            if parent_l and parent_l not in expected:
                return True, f"'{name}' has unexpected parent '{parent_name}' (expected: {expected})"
        return False, ""

    @staticmethod
    def check_all(proc) -> list[str]:
        reasons = []
        try:
            name = proc.name()
            exe = proc.exe() or ""
            sus, msg = ProcessLegitimacyChecker.check_path(name, exe)
            if sus:
                reasons.append(msg)
            try:
                parent = psutil.Process(proc.ppid())
                sus2, msg2 = ProcessLegitimacyChecker.check_parent(name, parent.name())
                if sus2:
                    reasons.append(msg2)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if name.lower() in ("svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
                                "smss.exe", "winlogon.exe", "wininit.exe"):
                if exe and "system32" not in exe.lower() and "syswow64" not in exe.lower():
                    reasons.append(f"SYSTEM IMPERSONATION: '{name}' at '{exe}' — NOT in System32")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return reasons


class DLLInspector:
    """Checks loaded modules per process for suspicious DLL paths."""
    @staticmethod
    def inspect(proc) -> list[str]:
        suspicious = []
        if not _IS_WINDOWS:
            return suspicious
        try:
            for mmap in proc.memory_maps(grouped=False):
                path_lower = (mmap.path or "").lower()
                if any(frag in path_lower for frag in SUSPICIOUS_DLL_PATHS):
                    suspicious.append(mmap.path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as exc:
            _mb_logger.debug("DLL inspection error for %s: %s", proc, exc)
        return suspicious


# ========================== SYSTEM DETECTORS ==========================
class RegistryMonitor:
    """Monitors Windows Run keys and scheduled tasks for persistence changes."""
    def __init__(self):
        self.baseline: dict[str, str] = {}
        self.lock = threading.Lock()

    def scan(self) -> list[tuple[str, str, str]]:
        if not _IS_WINDOWS:
            return []
        changes = []
        current = {}
        for hive, key_path in PERSISTENCE_KEYS:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            full_key = f"{key_path}\\{name}"
                            current[full_key] = str(value)
                            i += 1
                        except OSError:
                            break
            except OSError as exc:
                _mb_logger.debug("Registry scan error for %s: %s", key_path, exc)
        with self.lock:
            if self.baseline:
                for k, v in current.items():
                    if k not in self.baseline:
                        changes.append(("ADDED", k, v))
                    elif self.baseline[k] != v:
                        changes.append(("MODIFIED", k, v))
                for k in self.baseline:
                    if k not in current:
                        changes.append(("REMOVED", k, self.baseline[k]))
            self.baseline = current
        return changes


class UserIdleMonitor:
    """Tracks user idle time via Windows GetLastInputInfo."""
    @staticmethod
    def get_idle_seconds() -> float:
        if not _IS_WINDOWS:
            return 0.0
        try:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
                return millis / 1000.0
        except Exception as exc:
            _mb_logger.debug("GetLastInputInfo failed: %s", exc)
        return 0.0


# ========================== STATISTICAL BASELINE ==========================
class StatisticalBaseline:
    """Z-score anomaly detection per process name on key behavioral metrics."""
    def __init__(self):
        self.models: dict[str, dict] = defaultdict(lambda: {
            'conn_rate': deque(maxlen=500),
            'dst_count': deque(maxlen=500),
            'bytes_rate': deque(maxlen=500),
            'cpu_mean': deque(maxlen=500),
        })
        self.lock = threading.Lock()

    def record(self, proc_name: str, conn_rate: float, dst_count: int,
               bytes_rate: float, cpu_mean: float):
        with self.lock:
            m = self.models[proc_name]
            m['conn_rate'].append(conn_rate)
            m['dst_count'].append(dst_count)
            m['bytes_rate'].append(bytes_rate)
            m['cpu_mean'].append(cpu_mean)

    def score(self, proc_name: str, conn_rate: float, dst_count: int,
              bytes_rate: float, cpu_mean: float) -> tuple[float, list[str]]:
        anomalies = []
        total_z = 0.0
        with self.lock:
            m = self.models.get(proc_name)
            if not m or len(m['conn_rate']) < 30:
                return 0.0, []
            for metric_name, current_val in [('conn_rate', conn_rate), ('dst_count', dst_count),
                                              ('bytes_rate', bytes_rate), ('cpu_mean', cpu_mean)]:
                samples = list(m[metric_name])
                if len(samples) < 10:
                    continue
                mean = statistics.mean(samples)
                try:
                    std = statistics.stdev(samples)
                except statistics.StatisticsError:
                    continue
                if std < 0.001:
                    continue
                z = abs(current_val - mean) / std
                if z > CONFIG['ml_zscore_threshold']:
                    anomalies.append(f"{metric_name}: z={z:.1f} (val={current_val:.1f} mean={mean:.1f} std={std:.1f})")
                    total_z += z
        score = min(100, total_z * 10)
        return score, anomalies


# ========================== JA4+ FINGERPRINTING ==========================
class JA4Plus:
    """Extended JA4 — JA4S (ServerHello), JA4H (HTTP), JA4X (X.509 cert)."""
    @staticmethod
    def ja4(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 9 or data[0] != 0x16:
                return None
            handshake = data[5:]
            if len(handshake) < 4 or handshake[0] != 0x01:
                return None
            ch = handshake[4:]
            if len(ch) < 38:
                return None
            tls_ver = f"t{ch[0]:02x}{ch[1]:02x}"
            sess_id_len = ch[34]
            offset = 35 + sess_id_len
            cipher_len = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2 + cipher_len
            comp_len = ch[offset]
            offset += 1 + comp_len
            ext_len = int.from_bytes(ch[offset:offset+2], 'big')
            alpn = "h2" if b'\x00\x10' in data else "http1"
            return f"{tls_ver}d{cipher_len//2:02d}{ext_len//4:02d}_{alpn}"
        except Exception as exc:
            _mb_logger.debug("JA4 fingerprint error: %s", exc)
            return None

    @staticmethod
    def ja4s(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 6 or data[0] != 0x16:
                return None
            hs = data[5:]
            if len(hs) < 4 or hs[0] != 0x02:
                return None
            sh = hs[4:]
            if len(sh) < 38:
                return None
            ver = f"s{sh[0]:02x}{sh[1]:02x}"
            cipher = int.from_bytes(sh[35:37], 'big')
            return f"{ver}c{cipher:04x}"
        except Exception as exc:
            _mb_logger.debug("JA4S parse error: %s", exc)
            return None

    @staticmethod
    def ja4h(pkt) -> Optional[str]:
        if not pkt.haslayer(Raw):
            return None
        try:
            data = bytes(pkt[Raw])
            text = data.decode('ascii', errors='ignore')
            if not any(text.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ']):
                return None
            lines = text.split('\r\n')
            method = lines[0].split(' ')[0]
            headers = []
            for line in lines[1:]:
                if ':' in line:
                    headers.append(line.split(':')[0].strip().lower())
                elif line == '':
                    break
            h_hash = hashlib.sha256(','.join(headers).encode()).hexdigest()[:12]
            return f"h_{method}_{len(headers):02d}_{h_hash}"
        except Exception as exc:
            _mb_logger.debug("JA4H parse error: %s", exc)
            return None

    @staticmethod
    def ja4x(cert_data: bytes) -> Optional[str]:
        try:
            h = hashlib.sha256(cert_data).hexdigest()[:16]
            return f"x_{h}"
        except Exception as exc:
            _mb_logger.debug("JA4X hash error: %s", exc)
            return None


# ========================== VIRUSTOTAL INTEGRATION ==========================
class VirusTotalChecker:
    """Check executable hashes against VirusTotal API (free tier: 4 req/min)."""
    _VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get('VT_API_KEY', '')
        self.cache: dict[str, dict] = {}  # sha256 -> result
        self.lock = threading.Lock()
        self._rate_bucket = TokenBucket(rate=4.0, capacity=4.0)
        self._checked_pids: set[int] = set()

    def _hash_file(self, filepath: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def check_exe(self, pid: int, exe_path: str) -> Optional[dict]:
        if not self.api_key or not exe_path or pid in self._checked_pids:
            return None
        self._checked_pids.add(pid)
        sha256 = self._hash_file(exe_path)
        if not sha256:
            return None
        with self.lock:
            if sha256 in self.cache:
                return self.cache[sha256]
        if not self._rate_bucket.consume():
            return None
        try:
            req = urllib.request.Request(
                self._VT_URL.format(hash=sha256),
                headers={'x-apikey': self.api_key, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            result = {
                'sha256': sha256, 'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'name': data.get('data', {}).get('attributes', {}).get('meaningful_name', ''),
            }
            with self.lock:
                self.cache[sha256] = result
            return result
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result = {'sha256': sha256, 'malicious': 0, 'suspicious': 0,
                          'undetected': 0, 'harmless': 0, 'name': 'NOT IN VT DB'}
                with self.lock:
                    self.cache[sha256] = result
                return result
            return None
        except Exception:
            return None

    def get_all_results(self) -> dict:
        with self.lock:
            return dict(self.cache)


# ========================== FILE SYSTEM WATCHDOG ==========================
class FileSystemWatchdog:
    """Monitor sensitive directories for suspicious file changes (ransomware, staging)."""
    RANSOMWARE_EXTS = {'.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.pay',
                       '.ransom', '.locky', '.cerber', '.zepto', '.odin', '.thor',
                       '.aesir', '.zzzzz', '.micro', '.mp3', '.xxx'}

    def __init__(self):
        self.lock = threading.Lock()
        self._baseline: dict[str, dict] = {}  # path -> {mtime, size}
        self._events: deque = deque(maxlen=5000)
        self._dirs_to_watch: list[str] = []
        home = os.path.expanduser("~")
        for d in ['Desktop', 'Documents', 'Downloads', 'AppData\\Local\\Temp']:
            p = os.path.join(home, d)
            if os.path.isdir(p):
                self._dirs_to_watch.append(p)
        self._baseline_set = False
        self._rename_counter: dict[str, int] = defaultdict(int)  # dir -> rename count in window
        self._rename_window_start: float = time.time()

    def scan(self) -> list[dict]:
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Reset rename window every 60s
        if now - self._rename_window_start > 60:
            self._rename_counter.clear()
            self._rename_window_start = now
        for watch_dir in self._dirs_to_watch:
            try:
                for entry in os.scandir(watch_dir):
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        st = entry.stat()
                        current[entry.path] = {'mtime': st.st_mtime, 'size': st.st_size}
                    except Exception:
                        continue
                    _, ext = os.path.splitext(entry.name)
                    if ext.lower() in self.RANSOMWARE_EXTS:
                        events.append({
                            'type': 'RANSOMWARE_EXT', 'path': entry.path,
                            'time': now, 'severity': 'CRITICAL',
                            'detail': f"Suspicious extension: {ext}"})
            except Exception:
                continue
        if self._baseline_set:
            for path, info in current.items():
                if path not in self._baseline:
                    events.append({'type': 'FILE_CREATED', 'path': path,
                                   'time': now, 'severity': 'INFO',
                                   'detail': f"New file: {os.path.basename(path)} ({info['size']} bytes)"})
                    d = os.path.dirname(path)
                    self._rename_counter[d] = self._rename_counter.get(d, 0) + 1
                elif self._baseline[path]['mtime'] != info['mtime']:
                    events.append({'type': 'FILE_MODIFIED', 'path': path,
                                   'time': now, 'severity': 'INFO',
                                   'detail': f"Modified: {os.path.basename(path)}"})
            for path in self._baseline:
                if path not in current:
                    events.append({'type': 'FILE_DELETED', 'path': path,
                                   'time': now, 'severity': 'WARNING',
                                   'detail': f"Deleted: {os.path.basename(path)}"})
                    d = os.path.dirname(path)
                    self._rename_counter[d] = self._rename_counter.get(d, 0) + 1
            # Mass rename detection (ransomware pattern)
            for d, count in self._rename_counter.items():
                if count > 20:
                    events.append({'type': 'MASS_RENAME', 'path': d,
                                   'time': now, 'severity': 'CRITICAL',
                                   'detail': f"Mass file changes in {d}: {count} files in 60s"})
        with self.lock:
            self._baseline = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== CLIPBOARD MONITOR ==========================
class ClipboardMonitor:
    """Watch for clipboard hijacking (crypto address swaps, data theft)."""
    _CRYPTO_PATTERNS = {
        'BTC': re.compile(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$'),
        'ETH': re.compile(r'^0x[0-9a-fA-F]{40}$'),
        'XMR': re.compile(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'),
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._last_content: str = ""
        self._events: deque = deque(maxlen=1000)
        self._change_count: int = 0
        self._window_start: float = time.time()

    def check(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        now = time.time()
        if now - self._window_start > 60:
            if self._change_count > 50:
                events.append({'type': 'RAPID_CLIPBOARD', 'time': now,
                               'severity': 'WARNING',
                               'detail': f"Clipboard changed {self._change_count} times in 60s"})
            self._change_count = 0
            self._window_start = now
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', 'Get-Clipboard'],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000)  # CREATE_NO_WINDOW
            if result.returncode == 0:
                text = result.stdout.strip()[:2000]
                if text and text != self._last_content:
                    self._change_count += 1
                    for coin, pat in self._CRYPTO_PATTERNS.items():
                        if pat.match(text.strip()):
                            events.append({
                                'type': 'CRYPTO_ADDRESS', 'time': now,
                                'severity': 'CRITICAL',
                                'detail': f"Clipboard contains {coin} address: {text[:40]}..."})
                    self._last_content = text
        except Exception:
            pass
        with self.lock:
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== USB DEVICE MONITOR ==========================
class USBMonitor:
    """Detect new USB devices being plugged in."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_devices: set[str] = set()
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current = set()
        try:
            key_path = r"SYSTEM\CurrentControlSet\Enum\USB"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                            j = 0
                            while True:
                                try:
                                    instance = winreg.EnumKey(subkey, j)
                                    dev_id = f"{subkey_name}\\{instance}"
                                    current.add(dev_id)
                                    try:
                                        with winreg.OpenKey(subkey, instance, 0, winreg.KEY_READ) as inst_key:
                                            desc, _ = winreg.QueryValueEx(inst_key, 'DeviceDesc')
                                    except Exception:
                                        desc = dev_id
                                    if self._baseline_set and dev_id not in self._known_devices:
                                        events.append({
                                            'type': 'USB_NEW', 'device_id': dev_id,
                                            'time': time.time(), 'severity': 'WARNING',
                                            'detail': f"New USB device: {desc}"})
                                    j += 1
                                except OSError:
                                    break
                        i += 1
                    except OSError:
                        break
        except Exception as exc:
            _mb_logger.debug("USB scan error: %s", exc)
        with self.lock:
            self._known_devices = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== SCHEDULED TASK MONITOR ==========================
class ScheduledTaskMonitor:
    """Monitor Windows scheduled tasks for new/modified entries."""
    def __init__(self):
        self.lock = threading.Lock()
        self._baseline: dict[str, str] = {}  # task_name -> hash
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, str] = {}
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/nh'],
                capture_output=True, text=True, timeout=15,
                creationflags=0x08000000)
            for line in result.stdout.strip().split('\n'):
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    task_name = parts[0].strip('"')
                    task_hash = hashlib.md5(line.encode()).hexdigest()
                    current[task_name] = task_hash
        except Exception as exc:
            _mb_logger.debug("Scheduled task scan error: %s", exc)
            return []
        if self._baseline_set:
            for name, h in current.items():
                if name not in self._baseline:
                    events.append({'type': 'TASK_ADDED', 'task': name,
                                   'time': time.time(), 'severity': 'WARNING',
                                   'detail': f"New scheduled task: {name}"})
                elif self._baseline[name] != h:
                    events.append({'type': 'TASK_MODIFIED', 'task': name,
                                   'time': time.time(), 'severity': 'WARNING',
                                   'detail': f"Modified scheduled task: {name}"})
            for name in self._baseline:
                if name not in current:
                    events.append({'type': 'TASK_REMOVED', 'task': name,
                                   'time': time.time(), 'severity': 'INFO',
                                   'detail': f"Removed scheduled task: {name}"})
        with self.lock:
            self._baseline = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== NAMED PIPE / IPC MONITOR ==========================
class NamedPipeMonitor:
    """Detect inter-process communication via named pipes (used by RATs, Cobalt Strike)."""
    SUSPICIOUS_PIPES = {'msagent_', 'postex_', 'status_', 'msse-', 'MSSE-',
                        'mssecsvc', 'mypipe', 'win_svc', 'ntsvcs', 'scerpc',
                        'isapi', 'sdclient', 'chromepipe', 'gecko', '\\psexec',
                        'csexec', 'paexec', 'remcom'}

    def __init__(self):
        self.lock = threading.Lock()
        self._known_pipes: set[str] = set()
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current = set()
        try:
            pipe_dir = r'\\.\pipe'
            import win32file
            pipes = win32file.FindFilesW(pipe_dir + r'\*')
            for p in pipes:
                current.add(p[8])  # cFileName
        except ImportError:
            try:
                result = subprocess.run(
                    ['cmd', '/c', 'dir', r'\\.\pipe\\', '/b'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000)
                for line in result.stdout.strip().split('\n'):
                    name = line.strip()
                    if name:
                        current.add(name)
            except Exception:
                pass
        except Exception as exc:
            _mb_logger.debug("Named pipe scan error: %s", exc)
        if self._baseline_set:
            new_pipes = current - self._known_pipes
            for pipe_name in new_pipes:
                is_suspicious = any(s.lower() in pipe_name.lower() for s in self.SUSPICIOUS_PIPES)
                if is_suspicious:
                    events.append({'type': 'SUSPICIOUS_PIPE', 'pipe': pipe_name,
                                   'time': time.time(), 'severity': 'CRITICAL',
                                   'detail': f"Suspicious named pipe: {pipe_name}"})
                elif len(new_pipes) <= 20:  # only log if not too noisy
                    events.append({'type': 'NEW_PIPE', 'pipe': pipe_name,
                                   'time': time.time(), 'severity': 'INFO',
                                   'detail': f"New named pipe: {pipe_name}"})
        with self.lock:
            self._known_pipes = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== WHOIS LOOKUP ==========================
class WhoisLookup:
    """Look up IP ownership via RDAP/whois for unknown IPs."""
    _RDAP_URL = "https://rdap.org/ip/{ip}"

    def __init__(self):
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._rate = TokenBucket(rate=10.0, capacity=10.0)

    def lookup(self, ip: str) -> Optional[dict]:
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        if not self._rate.consume():
            return None
        try:
            req = urllib.request.Request(self._RDAP_URL.format(ip=ip),
                                        headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            result = {
                'name': data.get('name', '?'),
                'handle': data.get('handle', '?'),
                'type': data.get('type', '?'),
                'country': data.get('country', '?'),
                'start_address': data.get('startAddress', '?'),
                'end_address': data.get('endAddress', '?'),
                'entities': [],
            }
            for ent in data.get('entities', [])[:3]:
                vcard = ent.get('vcardArray', [None, []])[1] if 'vcardArray' in ent else []
                org_name = ''
                for v in vcard:
                    if v[0] == 'org':
                        org_name = v[3] if len(v) > 3 else ''
                    elif v[0] == 'fn':
                        org_name = org_name or (v[3] if len(v) > 3 else '')
                result['entities'].append({'name': org_name, 'roles': ent.get('roles', [])})
            with self.lock:
                self.cache[ip] = result
            return result
        except Exception:
            with self.lock:
                self.cache[ip] = {'name': '?', 'error': True}
            return None


# ========================== INBOUND SCAN DETECTOR ==========================
class InboundScanDetector:
    """Detect external IPs port-scanning this machine (inbound SYN probes)."""
    def __init__(self):
        self.lock = threading.Lock()
        self._inbound_syns: dict[str, list[int]] = defaultdict(list)  # src_ip -> [ports]
        self._alerts: deque = deque(maxlen=500)
        self._alerted: set[str] = set()
        self._window_start: float = time.time()

    def record_inbound_syn(self, src_ip: str, dst_port: int):
        now = time.time()
        with self.lock:
            if now - self._window_start > 120:
                self._inbound_syns.clear()
                self._window_start = now
            self._inbound_syns[src_ip].append(dst_port)

    def check(self) -> list[dict]:
        events = []
        with self.lock:
            for ip, ports in self._inbound_syns.items():
                unique_ports = set(ports)
                if len(unique_ports) >= 5 and ip not in self._alerted:
                    self._alerted.add(ip)
                    events.append({
                        'type': 'INBOUND_SCAN', 'source_ip': ip,
                        'time': time.time(), 'severity': 'CRITICAL',
                        'ports_probed': sorted(unique_ports)[:20],
                        'detail': f"Port scan from {ip}: {len(unique_ports)} ports probed"})
            for ev in events:
                self._alerts.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._alerts)


# ========================== DoH DETECTION ==========================
class DoHDetector:
    """Detect DNS over HTTPS usage (bypasses local DNS monitoring)."""
    DOH_SERVERS = {
        '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare',
        '8.8.8.8': 'Google', '8.8.4.4': 'Google',
        '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9',
        '208.67.222.222': 'OpenDNS', '208.67.220.220': 'OpenDNS',
        '94.140.14.14': 'AdGuard', '94.140.15.15': 'AdGuard',
        '185.228.168.9': 'CleanBrowsing', '185.228.169.9': 'CleanBrowsing',
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._detections: dict[int, dict] = {}  # pid -> info
        self._events: deque = deque(maxlen=500)

    def check_connection(self, pid: int, proc_name: str, dst_ip: str, dst_port: int) -> Optional[dict]:
        if dst_port != 443 or dst_ip not in self.DOH_SERVERS:
            return None
        provider = self.DOH_SERVERS[dst_ip]
        key = (pid, dst_ip)
        with self.lock:
            if key in self._detections:
                return None
            ev = {'type': 'DOH_DETECTED', 'pid': pid, 'process': proc_name,
                  'dst_ip': dst_ip, 'provider': provider,
                  'time': time.time(), 'severity': 'WARNING',
                  'detail': f"{proc_name} (PID {pid}) using DNS-over-HTTPS via {provider} ({dst_ip})"}
            self._detections[key] = ev
            self._events.append(ev)
            return ev

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== TLS CERT / MITM DETECTOR ==========================
class TLSCertDetector:
    """Detect possible MITM by checking TLS ServerHello certificate fingerprints."""
    KNOWN_ISSUERS = {
        'google': ['GTS', 'Google Trust Services'],
        'microsoft': ['Microsoft', 'DigiCert'],
        'cloudflare': ['Cloudflare', 'DigiCert', "Let's Encrypt"],
        'amazon': ['Amazon', 'DigiCert', 'Starfield'],
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._cert_cache: dict[str, str] = {}  # ip -> cert_hash
        self._events: deque = deque(maxlen=500)
        self._cert_change_count: dict[str, int] = defaultdict(int)

    def record_cert(self, dst_ip: str, cert_data: bytes) -> Optional[dict]:
        if not cert_data:
            return None
        cert_hash = hashlib.sha256(cert_data).hexdigest()[:16]
        with self.lock:
            prev = self._cert_cache.get(dst_ip)
            self._cert_cache[dst_ip] = cert_hash
            if prev and prev != cert_hash:
                self._cert_change_count[dst_ip] += 1
                if self._cert_change_count[dst_ip] >= 3:
                    ev = {'type': 'CERT_CHANGE', 'ip': dst_ip,
                          'time': time.time(), 'severity': 'CRITICAL',
                          'old_hash': prev, 'new_hash': cert_hash,
                          'detail': f"TLS cert changed {self._cert_change_count[dst_ip]}x for {dst_ip} — possible MITM"}
                    self._events.append(ev)
                    return ev
        return None

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== CONNECTION HISTORY ==========================
class ConnectionHistory:
    """Track all connections seen during session, including closed ones, with timestamps."""
    def __init__(self):
        self.lock = threading.Lock()
        self._active: dict[tuple, dict] = {}  # (rip, rport, lip, lport, pid) -> info
        self._history: deque = deque(maxlen=20000)
        self._bandwidth: dict[str, dict] = defaultdict(lambda: {  # ip -> bandwidth
            'bytes_sent': 0, 'bytes_recv': 0, 'last_update': 0})

    def update(self, connections: list):
        """Called each cycle with current psutil connections."""
        now = time.time()
        current_keys = set()
        with self.lock:
            for conn in connections:
                if not conn.raddr:
                    continue
                key = (conn.raddr[0], conn.raddr[1],
                       conn.laddr[0] if conn.laddr else '',
                       conn.laddr[1] if conn.laddr else 0,
                       conn.pid or 0)
                current_keys.add(key)
                if key not in self._active:
                    self._active[key] = {
                        'remote_ip': conn.raddr[0], 'remote_port': conn.raddr[1],
                        'local_ip': conn.laddr[0] if conn.laddr else '',
                        'local_port': conn.laddr[1] if conn.laddr else 0,
                        'pid': conn.pid or 0, 'status': conn.status,
                        'start_time': now, 'end_time': None,
                        'duration': 0, 'active': True,
                    }
                else:
                    self._active[key]['status'] = conn.status
                    self._active[key]['duration'] = now - self._active[key]['start_time']
            # Close connections that disappeared
            closed_keys = set(self._active.keys()) - current_keys
            for key in closed_keys:
                entry = self._active.pop(key)
                entry['end_time'] = now
                entry['duration'] = now - entry['start_time']
                entry['active'] = False
                self._history.append(entry)

    def update_bandwidth(self, ip: str, sent: int, recv: int):
        with self.lock:
            bw = self._bandwidth[ip]
            bw['bytes_sent'] += sent
            bw['bytes_recv'] += recv
            bw['last_update'] = time.time()

    def get_active(self) -> list[dict]:
        with self.lock:
            return [dict(v) for v in self._active.values()]

    def get_history(self) -> list[dict]:
        with self.lock:
            active = [dict(v) for v in self._active.values()]
            closed = list(self._history)
            return active + closed

    def get_bandwidth(self) -> dict:
        with self.lock:
            return dict(self._bandwidth)

    def get_timeline(self) -> list[dict]:
        """Return all connections sorted by start_time for timeline display."""
        with self.lock:
            all_conns = list(self._history) + [dict(v) for v in self._active.values()]
        all_conns.sort(key=lambda c: c.get('start_time', 0))
        return all_conns


# ========================== BLUETOOTH SCANNER ==========================
class BluetoothScanner:
    """Enumerate Bluetooth devices via Windows registry and WMI."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_devices: dict[str, dict] = {}
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Method 1: Registry enumeration of paired BT devices
        try:
            bt_key = r"SYSTEM\CurrentControlSet\Enum\BTHENUM"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bt_key, 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        try:
                            with winreg.OpenKey(key, subkey_name) as sub:
                                j = 0
                                while True:
                                    try:
                                        instance = winreg.EnumKey(sub, j)
                                        j += 1
                                        dev_id = f"{subkey_name}\\{instance}"
                                        try:
                                            with winreg.OpenKey(sub, instance) as inst_key:
                                                friendly = ""
                                                try:
                                                    friendly, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                                except FileNotFoundError:
                                                    pass
                                                current[dev_id] = {
                                                    'device_id': dev_id,
                                                    'name': friendly or subkey_name[:40],
                                                    'time': now,
                                                    'type': 'bluetooth',
                                                }
                                        except Exception:
                                            pass
                                    except OSError:
                                        break
                        except Exception:
                            pass
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Method 2: Bluetooth radios via registry
        try:
            radio_key = r"SYSTEM\CurrentControlSet\Enum\USB"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, radio_key, 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        if 'BTHUSB' in subkey_name.upper() or 'BLUETOOTH' in subkey_name.upper():
                            current[f"radio_{subkey_name}"] = {
                                'device_id': subkey_name,
                                'name': f"BT Radio: {subkey_name[:30]}",
                                'time': now, 'type': 'bt_radio',
                            }
                    except OSError:
                        break
        except Exception:
            pass
        # Detect new devices
        if self._baseline_set:
            for dev_id, info in current.items():
                if dev_id not in self._known_devices:
                    events.append({
                        'severity': 'WARNING',
                        'detail': f"New Bluetooth device: {info['name']} ({dev_id[:50]})",
                        'device': info,
                    })
        with self.lock:
            self._known_devices = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_devices(self) -> list[dict]:
        with self.lock:
            return list(self._known_devices.values())

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== SERIAL PORT SCANNER ==========================
class SerialPortScanner:
    """Enumerate active COM/Serial ports and detect new ones."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_ports: dict[str, dict] = {}
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Registry: SERIALCOMM
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DEVICEMAP\SERIALCOMM", 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        i += 1
                        current[val] = {
                            'port': val, 'device': name,
                            'time': now, 'type': 'serial',
                        }
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Detect new ports
        if self._baseline_set:
            for port_name, info in current.items():
                if port_name not in self._known_ports:
                    events.append({
                        'severity': 'WARNING',
                        'detail': f"New serial port: {port_name} ({info['device']})",
                        'port_info': info,
                    })
        with self.lock:
            self._known_ports = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_ports(self) -> list[dict]:
        with self.lock:
            return list(self._known_ports.values())

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== GEOIP WITH RATE LIMITER ==========================
class TokenBucket:
    """Thread-safe token bucket rate limiter. ip-api.com free tier: 45 req/min."""
    def __init__(self, rate: float = 40.0, capacity: float = 45.0):
        self.rate = rate / 60.0
        self.capacity = capacity
        self.tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self._last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class GeoIPCache:
    """Thread-safe GeoIP lookup with caching, rate limiting, optional local DB, and HTTPS fallback."""
    _PRIVACY_WARNED = False
    _EMPTY: dict[str, object] = {'country': '??', 'countryCode': '??', 'city': '??',
                                 'org': 'Unknown', 'isp': 'Unknown', 'lat': 0, 'lon': 0}

    def __init__(self, maxmind_db_path: Optional[str] = None):
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._api_url = ("http://ip-api.com/json/{ip}?fields="
                        "status,country,countryCode,org,as,isp,lat,lon,city,regionName,timezone")
        self._rate_limiter = TokenBucket(rate=40.0, capacity=45.0)
        self._rate_limited_count = 0
        self._rate_lock = threading.Lock()
        self._local_reader = None
        db_path = maxmind_db_path or CONFIG.get('geoip_db_path')
        if db_path and HAS_GEOIP2:
            try:
                self._local_reader = _geoip2_db.Reader(db_path)
                _mb_logger.info("GeoIP: using local MaxMind DB at %s", db_path)
            except Exception as exc:
                _mb_logger.warning("GeoIP: failed to open MaxMind DB '%s': %s — falling back to API", db_path, exc)

    def _lookup_local(self, ip: str) -> Optional[dict]:
        if not self._local_reader:
            return None
        try:
            resp = self._local_reader.city(ip)
            return {
                'status': 'success',
                'country': resp.country.name or '??',
                'countryCode': resp.country.iso_code or '??',
                'city': resp.city.name or '??',
                'regionName': (resp.subdivisions.most_specific.name
                               if resp.subdivisions else ''),
                'org': (resp.traits.organization or
                        resp.traits.autonomous_system_organization or 'Unknown'),
                'isp': resp.traits.isp if hasattr(resp.traits, 'isp') else 'Unknown',
                'as': (f"AS{resp.traits.autonomous_system_number}"
                       if resp.traits.autonomous_system_number else ''),
                'lat': resp.location.latitude or 0.0,
                'lon': resp.location.longitude or 0.0,
                'timezone': resp.location.time_zone or '',
                '_ts': time.time(),
                '_source': 'local',
            }
        except Exception as exc:
            _mb_logger.debug("Local GeoIP lookup failed for %s: %s", ip, exc)
            return None

    def _lookup_api(self, ip: str) -> Optional[dict]:
        if not self._rate_limiter.consume():
            with self._rate_lock:
                self._rate_limited_count += 1
                count = self._rate_limited_count
            if count % 50 == 1:
                _mb_logger.warning("GeoIP rate limited — %d lookups throttled. "
                                "Consider using a local MaxMind DB (geoip_db_path config).",
                                self._rate_limited_count)
            return None
        try:
            url = self._api_url.format(ip=ip)
            req = urllib.request.Request(url, headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                data['_ts'] = time.time()
                data['_source'] = 'api'
                return data
        except Exception as exc:
            _mb_logger.debug("GeoIP API lookup failed for %s: %s", ip, exc)
        return None

    def lookup(self, ip: str) -> Optional[dict]:
        if not CONFIG.get('geoip_enabled', True):
            return None
        if not GeoIPCache._PRIVACY_WARNED and not self._local_reader:
            _mb_logger.warning(
                "GeoIP enabled: destination IPs will be sent to ip-api.com over HTTP. "
                "Set geoip_enabled=False or configure geoip_db_path for local lookups."
            )
            GeoIPCache._PRIVACY_WARNED = True
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached
        data = self._lookup_local(ip) or self._lookup_api(ip)
        if data:
            with self.lock:
                self.cache[ip] = data
            return data
        return None

    def get_country(self, ip: str) -> str:
        info = self.lookup(ip)
        return info.get('countryCode', '??') if info else '??'

    def get_org(self, ip: str) -> str:
        info = self.lookup(ip)
        return info.get('org', 'Unknown') if info else 'Unknown'

    def get_coords(self, ip: str) -> tuple:
        info = self.lookup(ip)
        if info:
            return info.get('lat', 0.0), info.get('lon', 0.0)
        return 0.0, 0.0

    def get_full(self, ip: str) -> dict:
        info = self.lookup(ip)
        if not info:
            return dict(self._EMPTY)
        return info


# ========================== LOCATION VERIFIER ==========================
# Known IATA airport codes and city abbreviations found in reverse-DNS hostnames
_RDNS_CITY_CODES: dict[str, tuple[str, str]] = {
    'lax': ('Los Angeles', 'US'), 'sfo': ('San Francisco', 'US'),
    'sjc': ('San Jose', 'US'), 'sea': ('Seattle', 'US'),
    'ord': ('Chicago', 'US'), 'iad': ('Washington DC', 'US'),
    'dfw': ('Dallas', 'US'), 'atl': ('Atlanta', 'US'),
    'mia': ('Miami', 'US'), 'bos': ('Boston', 'US'),
    'den': ('Denver', 'US'), 'phx': ('Phoenix', 'US'),
    'jfk': ('New York', 'US'), 'ewr': ('Newark', 'US'),
    'nyc': ('New York', 'US'), 'chi': ('Chicago', 'US'),
    'dal': ('Dallas', 'US'), 'hou': ('Houston', 'US'),
    'lhr': ('London', 'GB'), 'fra': ('Frankfurt', 'DE'),
    'ams': ('Amsterdam', 'NL'), 'cdg': ('Paris', 'FR'),
    'nrt': ('Tokyo', 'JP'), 'hnd': ('Tokyo', 'JP'),
    'icn': ('Seoul', 'KR'), 'sin': ('Singapore', 'SG'),
    'hkg': ('Hong Kong', 'HK'), 'syd': ('Sydney', 'AU'),
    'gru': ('Sao Paulo', 'BR'), 'bom': ('Mumbai', 'IN'),
    'del': ('Delhi', 'IN'), 'dub': ('Dublin', 'IE'),
    'arn': ('Stockholm', 'SE'), 'waw': ('Warsaw', 'PL'),
    'mad': ('Madrid', 'ES'), 'mxp': ('Milan', 'IT'),
    'zrh': ('Zurich', 'CH'), 'yyz': ('Toronto', 'CA'),
    'yvr': ('Vancouver', 'CA'), 'yul': ('Montreal', 'CA'),
    'muc': ('Munich', 'DE'), 'vie': ('Vienna', 'AT'),
    'cpt': ('Cape Town', 'ZA'), 'jnb': ('Johannesburg', 'ZA'),
    'tpe': ('Taipei', 'TW'), 'bkk': ('Bangkok', 'TH'),
    'kul': ('Kuala Lumpur', 'MY'), 'mel': ('Melbourne', 'AU'),
    'osl': ('Oslo', 'NO'), 'hel': ('Helsinki', 'FI'),
    'cph': ('Copenhagen', 'DK'), 'lis': ('Lisbon', 'PT'),
    'bcn': ('Barcelona', 'ES'), 'ist': ('Istanbul', 'TR'),
}

_RDNS_CODE_RE = re.compile(
    r'(?:^|[.\-])(' + '|'.join(_RDNS_CITY_CODES.keys()) + r')(?:[.\-\d]|$)', re.IGNORECASE)


class LocationVerifier:
    """Cross-references GeoIP results using multiple independent methods to produce
    a confidence score (0-100%) and a list of proof strings for each IP location.

    Methods:
      1. Reverse DNS hostname — parse for IATA/city codes, compare with claimed location
      2. RDAP/WHOIS — query the IP's registration country from regional registries
      3. RTT ping — estimate max physical distance from round-trip time
      4. Second GeoIP source — cross-reference with ipwho.is (free, no key)
    """

    def __init__(self, service_resolver: 'ServiceResolver' = None):
        self._resolver = service_resolver
        self._cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()
        self._rate = TokenBucket(rate=20.0, capacity=25.0)  # shared rate limit for verification APIs

    def verify(self, ip: str, geo: dict) -> dict:
        """Return {'confidence': 0-100, 'proof': [str, ...], 'grade': str}."""
        with self._cache_lock:
            cached = self._cache.get(ip)
            if cached:
                return cached

        claimed_country = (geo.get('countryCode') or '??').upper()
        claimed_city = (geo.get('city') or '??').lower()
        proofs: list[str] = []
        score = 0
        total_methods = 0

        # Method 1: Reverse DNS city code matching (fast, no network call if cached)
        rdns_result = self._check_rdns(ip, claimed_country, claimed_city)
        if rdns_result is not None:
            total_methods += 1
            if rdns_result[0]:
                score += 1
                proofs.append(f"✅ rDNS: {rdns_result[1]}")
            else:
                proofs.append(f"❌ rDNS: {rdns_result[1]}")

        # Method 2: RDAP/WHOIS country verification
        rdap_result = self._check_rdap(ip, claimed_country)
        if rdap_result is not None:
            total_methods += 1
            if rdap_result[0]:
                score += 1
                proofs.append(f"✅ RDAP: {rdap_result[1]}")
            else:
                proofs.append(f"❌ RDAP: {rdap_result[1]}")

        # Method 3: RTT-based distance estimation
        rtt_result = self._check_rtt(ip, geo)
        if rtt_result is not None:
            total_methods += 1
            if rtt_result[0]:
                score += 1
                proofs.append(f"✅ RTT: {rtt_result[1]}")
            else:
                proofs.append(f"⚠️ RTT: {rtt_result[1]}")

        # Method 4: Second GeoIP source cross-reference
        alt_result = self._check_alt_geoip(ip, claimed_country, claimed_city)
        if alt_result is not None:
            total_methods += 1
            if alt_result[0]:
                score += 1
                proofs.append(f"✅ AltGeo: {alt_result[1]}")
            else:
                proofs.append(f"❌ AltGeo: {alt_result[1]}")

        # Calculate confidence percentage
        if total_methods == 0:
            confidence = 0
            grade = "UNVERIFIED"
        else:
            confidence = int((score / total_methods) * 100)
            if confidence >= 75:
                grade = "HIGH"
            elif confidence >= 50:
                grade = "MEDIUM"
            elif confidence >= 25:
                grade = "LOW"
            else:
                grade = "SUSPECT"

        if not proofs:
            proofs.append("No verification methods succeeded")

        result = {'confidence': confidence, 'proof': proofs, 'grade': grade,
                  'methods_passed': score, 'methods_total': total_methods}

        with self._cache_lock:
            if len(self._cache) < 5000:
                self._cache[ip] = result
        return result

    def _check_rdns(self, ip: str, claimed_cc: str, claimed_city: str):
        """Parse reverse DNS for IATA airport codes or city abbreviations."""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
        except (socket.herror, socket.gaierror, OSError):
            return None  # No rDNS available — skip this method

        match = _RDNS_CODE_RE.search(hostname)
        if match:
            code = match.group(1).lower()
            city_name, country_code = _RDNS_CITY_CODES[code]
            if country_code == claimed_cc:
                return (True, f"hostname '{hostname}' contains '{code}' "
                        f"({city_name}, {country_code}) — matches claimed {claimed_cc}")
            else:
                return (False, f"hostname '{hostname}' contains '{code}' "
                        f"({city_name}, {country_code}) — claimed {claimed_cc}")

        # Check if hostname contains the claimed city name directly
        if claimed_city != '??' and len(claimed_city) > 3 and claimed_city in hostname:
            return (True, f"hostname '{hostname}' contains city name '{claimed_city}'")

        # Check for country TLD matching
        parts = hostname.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            # Map common ccTLDs to country codes
            tld_map = {
                'uk': 'GB', 'de': 'DE', 'fr': 'FR', 'jp': 'JP', 'au': 'AU',
                'ca': 'CA', 'br': 'BR', 'in': 'IN', 'nl': 'NL', 'se': 'SE',
                'no': 'NO', 'fi': 'FI', 'dk': 'DK', 'pl': 'PL', 'it': 'IT',
                'es': 'ES', 'pt': 'PT', 'ch': 'CH', 'at': 'AT', 'ie': 'IE',
                'sg': 'SG', 'kr': 'KR', 'tw': 'TW', 'hk': 'HK', 'nz': 'NZ',
                'za': 'ZA', 'mx': 'MX', 'ar': 'AR', 'cl': 'CL', 'co': 'CO',
                'ru': 'RU', 'cn': 'CN', 'th': 'TH', 'my': 'MY', 'id': 'ID',
                'tr': 'TR', 'il': 'IL', 'ae': 'AE', 'ro': 'RO', 'cz': 'CZ',
                'hu': 'HU', 'bg': 'BG', 'hr': 'HR', 'ua': 'UA', 'be': 'BE',
            }
            tld_cc = tld_map.get(tld, tld.upper() if len(tld) == 2 else None)
            if tld_cc and tld_cc == claimed_cc:
                return (True, f"hostname TLD '.{tld}' matches claimed country {claimed_cc}")
            elif tld_cc and tld_cc != claimed_cc and tld not in ('com', 'net', 'org', 'io', 'dev'):
                return (False, f"hostname TLD '.{tld}' ({tld_cc}) contradicts claimed {claimed_cc}")

        return None  # No conclusive data from rDNS

    def _check_rdap(self, ip: str, claimed_cc: str):
        """Query RDAP for the IP's registered country code."""
        if not self._rate.consume():
            return None
        try:
            url = f"https://rdap.org/ip/{ip}"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'MedianBoxMonitor/3.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            # RDAP response: look for country in the registration
            rdap_cc = None
            if 'country' in data:
                rdap_cc = data['country'].upper()
            elif 'entities' in data:
                for entity in data.get('entities', []):
                    if 'vcardArray' in entity:
                        for item in entity['vcardArray']:
                            if isinstance(item, list):
                                for field in item:
                                    if isinstance(field, list) and len(field) >= 4:
                                        if field[0] == 'adr' and isinstance(field[3], dict):
                                            cc = field[3].get('cc', '')
                                            if cc:
                                                rdap_cc = cc.upper()
                                                break
            if rdap_cc:
                if rdap_cc == claimed_cc:
                    return (True, f"RDAP registry country '{rdap_cc}' matches claimed {claimed_cc}")
                else:
                    return (False, f"RDAP registry country '{rdap_cc}' differs from claimed {claimed_cc}")
        except Exception:
            pass
        return None

    def _check_rtt(self, ip: str, geo: dict):
        """Ping the IP and estimate max distance from RTT.
        Speed of light in fiber ≈ 200,000 km/s → ~100km per 1ms RTT (round trip)."""
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', '2', '-w', '2000', ip]
            else:
                cmd = ['ping', '-c', '2', '-W', '2', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            output = result.stdout
            # Extract average RTT
            # Windows: "Average = 42ms" or "Minimum = 20ms, Maximum = 25ms, Average = 22ms"
            m = re.search(r'Average\s*=\s*(\d+)\s*ms', output)
            if not m:
                # Linux: "rtt min/avg/max/mdev = 10.123/12.456/14.789/2.345 ms"
                m = re.search(r'=\s*[\d.]+/([\d.]+)/', output)
            if m:
                avg_rtt_ms = float(m.group(1))
                # Max distance: speed of light in fiber, accounting for round-trip
                # ~100 km per ms of RTT (conservative)
                max_distance_km = avg_rtt_ms * 100
                # Calculate actual distance from our approximate location to claimed location
                claimed_lat = geo.get('lat', 0)
                claimed_lon = geo.get('lon', 0)
                if claimed_lat == 0 and claimed_lon == 0:
                    return None
                # Use haversine approximation (rough)
                # For this purpose, just report whether RTT is consistent
                if avg_rtt_ms < 5:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — very close (<500km), consistent with nearby location")
                elif avg_rtt_ms < 50:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — domestic range (<5000km), max possible {max_distance_km:.0f}km")
                elif avg_rtt_ms < 150:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — continental range, max possible {max_distance_km:.0f}km")
                elif avg_rtt_ms < 300:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — intercontinental, max possible {max_distance_km:.0f}km")
                else:
                    return (None, f"RTT {avg_rtt_ms:.0f}ms — very high latency, possible proxy/VPN")
            # Ping succeeded but couldn't parse RTT
            if 'Reply from' in output or 'bytes from' in output:
                return None  # Host replied but format unexpected
            return None  # Ping blocked/filtered
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _check_alt_geoip(self, ip: str, claimed_cc: str, claimed_city: str):
        """Cross-reference with ipwho.is (free, no API key, 10k/month)."""
        if not self._rate.consume():
            return None
        try:
            url = f"https://ipwho.is/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            if not data.get('success', True):
                return None
            alt_cc = (data.get('country_code') or '').upper()
            alt_city = (data.get('city') or '').lower()
            if alt_cc:
                cc_match = alt_cc == claimed_cc
                city_match = (alt_city and claimed_city != '??' and
                              (alt_city in claimed_city or claimed_city in alt_city))
                if cc_match and city_match:
                    return (True, f"ipwho.is confirms {alt_cc}/{alt_city} — exact match")
                elif cc_match:
                    return (True, f"ipwho.is confirms country {alt_cc} "
                            f"(city: '{alt_city}' vs claimed '{claimed_city}')")
                else:
                    return (False, f"ipwho.is says {alt_cc}/{alt_city} — "
                            f"claimed {claimed_cc}/{claimed_city}")
        except Exception:
            pass
        return None


# ========================== PROXY DETECTOR ==========================
# Known CDN / Reverse Proxy IP prefixes (first 2-3 octets for quick matching)
_CLOUDFLARE_RANGES = [
    '103.21.244', '103.22.200', '103.31.4', '104.16', '104.17', '104.18',
    '104.19', '104.20', '104.21', '104.22', '104.23', '104.24', '104.25',
    '104.26', '104.27', '108.162', '131.0.72', '141.101', '162.158',
    '172.64', '172.65', '172.66', '172.67', '173.245', '188.114',
    '190.93', '197.234', '198.41',
]
_AKAMAI_RANGES = [
    '23.0', '23.1', '23.2', '23.3', '23.4', '23.5', '23.6', '23.7',
    '23.32', '23.33', '23.34', '23.35', '23.36', '23.37', '23.38', '23.39',
    '23.40', '23.41', '23.42', '23.43', '23.44', '23.45', '23.46', '23.47',
    '23.48', '23.49', '23.50', '23.51', '23.52', '23.53', '23.54', '23.55',
    '23.56', '23.57', '23.58', '23.59', '23.60', '23.61', '23.62', '23.63',
    '23.64', '23.65', '23.66', '23.67', '23.72', '23.73', '23.74', '23.75',
    '23.76', '23.77', '23.78', '23.79', '23.192', '23.193', '23.194',
    '23.195', '23.196', '23.197', '23.198', '23.199',
    '2.16', '2.17', '2.18', '2.19', '2.20', '2.21', '2.22', '2.23',
    '95.100', '95.101', '184.24', '184.25', '184.26', '184.27',
    '184.28', '184.29', '184.30', '184.31', '184.50', '184.51',
]
_FASTLY_RANGES = [
    '151.101', '199.232', '23.235',
]
_CLOUDFRONT_RANGES = [
    '13.32', '13.33', '13.35', '13.224', '13.225', '13.226', '13.227',
    '13.228', '13.249', '18.64', '18.65', '18.154', '18.155', '18.160',
    '18.161', '18.164', '18.172', '18.238', '18.244', '52.46',
    '52.84', '52.85', '52.222', '54.182', '54.192', '54.230', '54.239',
    '54.240', '64.252', '65.9', '70.132', '71.152', '99.84', '99.86',
    '108.138', '108.156', '116.129', '130.176', '143.204', '144.220',
    '204.246', '205.251',
]
_INCAPSULA_RANGES = ['45.64.64', '107.154', '199.83']

# Known residential proxy service domains and keywords
_RESIDENTIAL_PROXY_DOMAINS = [
    'luminati', 'brightdata', 'bright.data', 'zyte.com', 'smartproxy',
    'oxylabs', 'netnut', 'geosurf', 'soax.com', 'iproyal', 'proxy-seller',
    'storm-proxies', 'microleaves', 'shifter.io', 'packetstream',
    'peer2profit', 'honeygain', 'pawns.app', 'earnapp', 'traffmonetizer',
    'ipburger', 'proxy-cheap', 'webshare', 'private-proxy', 'infatica',
]

# Known forward proxy software process names
_PROXY_PROCESS_NAMES = [
    'squid', 'privoxy', 'polipo', 'tinyproxy', 'charles', 'fiddler',
    'mitmproxy', 'burpsuite', 'proxifier', 'proxycap', 'redsocks',
    'shadowsocks', 'ss-local', 'v2ray', 'xray', 'clash', 'trojan',
    'tor', 'obfs4proxy', 'meek-client', 'snowflake-client',
    'wireproxy', 'gost', 'brook', 'naiveproxy', 'hysteria',
    'sing-box', 'tuic', 'juicity',
]

# Common proxy ports
_PROXY_PORTS = {
    1080, 3128, 8080, 8118, 8888, 9050, 9150,  # SOCKS, Squid, Privoxy, Tor
    8443, 8880, 9090, 1081, 1082, 7890, 7891, 7892, 7893,  # Clash
    10808, 10809, 20170, 20171,  # V2Ray / Xray defaults
}


class ProxyDetector:
    """Detects forward, reverse, and residential proxy usage on connections.

    - Forward Proxy: checks system proxy settings (env vars, Windows registry),
      running proxy processes, and connections to common proxy ports.
    - Reverse Proxy: checks if destination IPs belong to known CDN/reverse-proxy
      infrastructure (Cloudflare, Akamai, Fastly, CloudFront, Incapsula).
    - Residential Proxy: checks if DNS queries or connection domains match known
      residential proxy services, and flags ISP-type ASNs with proxy behavior.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._system_proxy: dict = {}
        self._proxy_processes: list[str] = []
        self._proxy_events: deque = deque(maxlen=500)
        self._last_system_scan = 0.0
        self._flagged_ips: set[str] = set()

    def scan_system(self) -> list[dict]:
        """Detect forward proxy configuration at the system level.
        Returns list of proxy detection events."""
        now = time.time()
        if now - self._last_system_scan < 30:
            return []
        self._last_system_scan = now
        events: list[dict] = []

        # 1. Check environment variables
        for var in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy',
                    'ALL_PROXY', 'all_proxy', 'SOCKS_PROXY', 'socks_proxy',
                    'NO_PROXY', 'no_proxy'):
            val = os.environ.get(var, '')
            if val and var.upper() != 'NO_PROXY':
                ev = {'type': 'FORWARD_PROXY', 'subtype': 'ENV_VAR',
                      'severity': 'WARNING',
                      'detail': f"Proxy env var set: {var}={val[:120]}"}
                events.append(ev)

        # 2. Check Windows registry proxy settings
        if _IS_WINDOWS:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    try:
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    except FileNotFoundError:
                        proxy_server = "unknown"
                    ev = {'type': 'FORWARD_PROXY', 'subtype': 'REGISTRY',
                          'severity': 'WARNING',
                          'detail': f"Windows system proxy enabled: {proxy_server}"}
                    events.append(ev)
                try:
                    pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    if pac_url:
                        ev = {'type': 'FORWARD_PROXY', 'subtype': 'PAC',
                              'severity': 'WARNING',
                              'detail': f"PAC auto-config URL: {pac_url[:150]}"}
                        events.append(ev)
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except Exception:
                pass

        # 3. Check for running proxy processes
        proxy_procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = proc.name().lower().replace('.exe', '')
                for proxy_name in _PROXY_PROCESS_NAMES:
                    if proxy_name in pname:
                        proxy_procs.append(f"{proc.name()} (PID {proc.pid})")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if proxy_procs:
            with self._lock:
                self._proxy_processes = proxy_procs
            ev = {'type': 'FORWARD_PROXY', 'subtype': 'PROCESS',
                  'severity': 'WARNING',
                  'detail': f"Proxy software running: {', '.join(proxy_procs[:5])}"}
            events.append(ev)
        else:
            with self._lock:
                self._proxy_processes = []

        with self._lock:
            for ev in events:
                self._proxy_events.append(ev)
        return events

    def classify_connection(self, remote_ip: str, remote_port: int,
                            domain: str, org: str, isp: str,
                            asn: str = '') -> dict:
        """Classify a single connection for proxy indicators.
        Returns {'proxy_type': str, 'proxy_detail': str} or empty if none."""
        results: list[str] = []
        detail_parts: list[str] = []

        # --- Forward Proxy: check if connecting TO a proxy port ---
        if remote_port in _PROXY_PORTS:
            results.append('FORWARD')
            detail_parts.append(f"port {remote_port} is a known proxy port")

        # --- Reverse Proxy: check if dest IP is in CDN ranges ---
        for prefix in _CLOUDFLARE_RANGES:
            if remote_ip.startswith(prefix):
                results.append('REVERSE')
                detail_parts.append(f"IP in Cloudflare range ({prefix}.*)")
                break
        else:
            for prefix in _AKAMAI_RANGES:
                if remote_ip.startswith(prefix):
                    results.append('REVERSE')
                    detail_parts.append(f"IP in Akamai range ({prefix}.*)")
                    break
            else:
                for prefix in _FASTLY_RANGES:
                    if remote_ip.startswith(prefix):
                        results.append('REVERSE')
                        detail_parts.append(f"IP in Fastly range ({prefix}.*)")
                        break
                else:
                    for prefix in _CLOUDFRONT_RANGES:
                        if remote_ip.startswith(prefix):
                            results.append('REVERSE')
                            detail_parts.append(f"IP in CloudFront range ({prefix}.*)")
                            break
                    else:
                        for prefix in _INCAPSULA_RANGES:
                            if remote_ip.startswith(prefix):
                                results.append('REVERSE')
                                detail_parts.append(f"IP in Incapsula/Imperva range ({prefix}.*)")
                                break

        # --- Residential Proxy: check domain/org for known proxy services ---
        check_str = f"{domain} {org} {isp}".lower()
        for rp_kw in _RESIDENTIAL_PROXY_DOMAINS:
            if rp_kw in check_str:
                results.append('RESIDENTIAL')
                detail_parts.append(f"matches residential proxy service '{rp_kw}'")
                break

        if not results:
            return {}

        proxy_type = '/'.join(sorted(set(results)))
        return {
            'proxy_type': proxy_type,
            'proxy_detail': '; '.join(detail_parts),
        }

    def get_events(self) -> list[dict]:
        with self._lock:
            return list(self._proxy_events)

    def get_proxy_processes(self) -> list[str]:
        with self._lock:
            return list(self._proxy_processes)

    def get_system_proxy(self) -> dict:
        with self._lock:
            return dict(self._system_proxy)


# ========================== LOGGING SETUP ==========================
def setup_structured_logging():
    """Configure Python logging with rotation for main, actions, and deductions logs."""
    logger = logging.getLogger('medianbox')
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh = RotatingFileHandler('medianbox_structured.log', maxBytes=50_000_000, backupCount=5,
                                 encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    actions_mb_logger = logging.getLogger('medianbox.actions')
    if not actions_mb_logger.handlers:
        actions_mb_logger.setLevel(logging.DEBUG)
        actions_mb_logger.propagate = False
        afmt = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        afh = RotatingFileHandler(CONFIG['actions_log'], maxBytes=50_000_000, backupCount=3,
                                  encoding='utf-8')
        afh.setLevel(logging.DEBUG)
        afh.setFormatter(afmt)
        actions_mb_logger.addHandler(afh)

    ded_mb_logger = logging.getLogger('medianbox.deductions')
    if not ded_mb_logger.handlers:
        ded_mb_logger.setLevel(logging.DEBUG)
        ded_mb_logger.propagate = False
        dfmt = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        dfh = RotatingFileHandler(CONFIG['deductions_log'], maxBytes=50_000_000, backupCount=3,
                                  encoding='utf-8')
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(dfmt)
        ded_mb_logger.addHandler(dfh)

    return logger


# ========================== SIEM OUTPUT ==========================
class SIEMOutput:
    """Formats and sends deductions as CEF, JSON, or Syslog."""
    def __init__(self):
        self.sock = None
        self._json_mb_logger = None
        self._cef_mb_logger = None
        if CONFIG['siem_output'] == 'json':
            self._json_mb_logger = self._make_file_mb_logger('medianbox.siem_json', 'medianbox_siem.json')
        elif CONFIG['siem_output'] == 'cef':
            self._cef_mb_logger = self._make_file_mb_logger('medianbox.siem_cef', 'medianbox_siem.cef')
        elif CONFIG['siem_output'] == 'syslog':
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception as exc:
                _mb_logger.warning("Failed to create syslog socket: %s", exc)

    @staticmethod
    def _make_file_mb_logger(name: str, filename: str):
        lg = logging.getLogger(name)
        if not lg.handlers:
            lg.setLevel(logging.DEBUG)
            lg.propagate = False
            fh = RotatingFileHandler(filename, maxBytes=50_000_000, backupCount=3, encoding='utf-8')
            fh.setFormatter(logging.Formatter('%(message)s'))
            lg.addHandler(fh)
        return lg

    def emit(self, d: Deduction):
        fmt = CONFIG.get('siem_output')
        if not fmt:
            return
        if fmt == 'json':
            self._emit_json(d)
        elif fmt == 'cef':
            self._emit_cef(d)
        elif fmt == 'syslog':
            self._emit_syslog(d)

    def _emit_json(self, d: Deduction):
        record = {
            'timestamp': datetime.datetime.fromtimestamp(d.timestamp).isoformat(),
            'severity': d.severity, 'category': d.category,
            'process': d.process_name, 'pid': d.pid,
            'message': d.message, 'evidence': d.evidence, 'score': d.score,
        }
        if self._json_mb_logger:
            self._json_mb_logger.info(json.dumps(record))

    def _emit_cef(self, d: Deduction):
        sev_map = {'INFO': 3, 'WARNING': 6, 'CRITICAL': 9}
        sev = sev_map.get(d.severity, 5)
        cef = (f"CEF:0|MedianBox|ChessEngine|3.0|{d.category}|{d.message[:128]}|{sev}|"
               f"src={d.process_name} pid={d.pid} score={d.score:.1f}")
        if self._cef_mb_logger:
            self._cef_mb_logger.info(cef)

    def _emit_syslog(self, d: Deduction):
        if not self.sock:
            return
        pri = 134
        if d.severity == 'CRITICAL':
            pri = 130
        elif d.severity == 'WARNING':
            pri = 132
        msg = f"<{pri}>MedianBox: [{d.category}] {d.message} pid={d.pid} score={d.score:.1f}"
        try:
            self.sock.sendto(msg.encode()[:1024],
                             (CONFIG['siem_host'], CONFIG['siem_port']))
        except Exception as exc:
            _mb_logger.debug("SIEM syslog send failed: %s", exc)


# ========================== ALERT ESCALATION ==========================
class AlertEscalation:
    """Compounds risk when same process triggers multiple deductions in a window."""
    def __init__(self):
        self.history: dict[int, deque] = defaultdict(lambda: deque(maxlen=50))
        self.lock = threading.Lock()

    def record(self, pid: int, score: float):
        with self.lock:
            self.history[pid].append((time.time(), score))

    def get_multiplier(self, pid: int) -> float:
        cutoff = time.time() - CONFIG['escalation_window']
        with self.lock:
            recent = [(t, s) for t, s in self.history.get(pid, []) if t > cutoff]
        if len(recent) <= 1:
            return 1.0
        return min(5.0, CONFIG['escalation_multiplier'] ** (len(recent) - 1))


# ========================== DATABASE ==========================
class DatabaseManager:
    """Thread-safe SQLite with connection-per-operation and WAL journal mode."""
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or CONFIG['db_file']
        self._init_db()

    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        try:
            conn = self._get_db()
            conn.execute("""CREATE TABLE IF NOT EXISTS deductions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, severity TEXT, category TEXT,
                process TEXT, pid INTEGER, message TEXT,
                evidence TEXT, score REAL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS devices (
                key TEXT PRIMARY KEY, mac TEXT, ip TEXT, vendor TEXT,
                hostname TEXT, os_guess TEXT, first_seen TEXT,
                last_seen TEXT, confidence REAL)""")
            conn.commit()
            conn.close()
        except Exception as exc:
            _mb_logger.warning("Database init failed: %s", exc)

    def save_deduction(self, d: Deduction):
        conn = None
        try:
            conn = self._get_db()
            conn.execute(
                "INSERT INTO deductions (timestamp, severity, category, process, pid, message, evidence, score) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.datetime.fromtimestamp(d.timestamp).isoformat(),
                 d.severity, d.category, d.process_name, d.pid,
                 d.message, json.dumps(d.evidence), d.score))
            conn.commit()
        except Exception as exc:
            _mb_logger.debug("DB deduction save failed: %s", exc)
        finally:
            if conn:
                conn.close()

    def save_device(self, key: str, dev: dict):
        conn = None
        try:
            conn = self._get_db()
            conn.execute(
                "INSERT OR REPLACE INTO devices (key, mac, ip, vendor, hostname, os_guess, "
                "first_seen, last_seen, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (key, dev.get('mac'), dev.get('ip'), dev.get('vendor'),
                 dev.get('hostname'), dev.get('os_guess'),
                 datetime.datetime.fromtimestamp(dev.get('first_seen', 0)).isoformat(),
                 datetime.datetime.fromtimestamp(dev.get('last_seen', 0)).isoformat(),
                 dev.get('confidence', 0)))
            conn.commit()
        except Exception as exc:
            _mb_logger.debug("DB device save failed: %s", exc)
        finally:
            if conn:
                conn.close()


# ========================== PACKET PIPELINE ==========================
class PacketPipeline:
    """Multi-worker queue that decouples packet capture from analysis."""
    def __init__(self, handler: Callable, stop_event: threading.Event,
                 num_workers: Optional[int] = None, max_queue: Optional[int] = None):
        self._handler = handler
        self._stop = stop_event
        self._num_workers = num_workers or CONFIG.get('pipeline_workers', 2)
        self._queue: queue.Queue = queue.Queue(
            maxsize=max_queue or CONFIG.get('pipeline_queue_size', 5000))
        self._workers: list = []
        self._dropped = 0
        self._processed = 0
        self._lock = threading.Lock()

    def enqueue(self, pkt):
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            if self._dropped % 500 == 1:
                _mb_logger.warning("Packet pipeline full — dropped %d packets so far", self._dropped)

    def _worker(self, worker_id: int):
        _mb_logger.debug("Pipeline worker %d started", worker_id)
        while not self._stop.is_set():
            try:
                pkt = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._handler(pkt)
                with self._lock:
                    self._processed += 1
            except Exception as exc:
                _mb_logger.debug("Pipeline worker %d error: %s", worker_id, exc)
            finally:
                self._queue.task_done()
        _mb_logger.debug("Pipeline worker %d stopped", worker_id)

    def start(self):
        for i in range(self._num_workers):
            t = threading.Thread(target=self._worker, args=(i,),
                                 daemon=True, name=f"Pipeline-Worker-{i}")
            t.start()
            self._workers.append(t)
        _mb_logger.info("Packet pipeline started with %d workers (queue=%d)",
                     self._num_workers, self._queue.maxsize)

    def stats(self) -> dict:
        with self._lock:
            return {
                'queue_size': self._queue.qsize(),
                'processed': self._processed,
                'dropped': self._dropped,
                'workers': len(self._workers),
            }

    def drain(self, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.1)


# ========================== SERVICE RESOLVER ==========================
SERVICE_PATTERNS = [
    (r'youtube|googlevideo|ytimg|yt\d|ggpht', 'YouTube', 'Streaming', '🎬'),
    (r'netflix|nflxvideo|nflximg|nflxso|nflxext', 'Netflix', 'Streaming', '🎬'),
    (r'disneyplus|disney-plus|bamgrid|dssott', 'Disney+', 'Streaming', '🎬'),
    (r'hulu|hulustream', 'Hulu', 'Streaming', '🎬'),
    (r'primevideo|atv-ps|aiv-cdn|amazonvideo', 'Prime Video', 'Streaming', '🎬'),
    (r'twitch\.tv|twitchcdn|jtvnw', 'Twitch', 'Streaming', '🎬'),
    (r'crunchyroll|vrv\.co', 'Crunchyroll', 'Streaming', '🎬'),
    (r'spotify|scdn\.co|audio-ak', 'Spotify', 'Streaming', '🎵'),
    (r'tidal\.com|tidalhifi', 'Tidal', 'Streaming', '🎵'),
    (r'facebook|fbcdn|fb\.com|fbsbx|instagram|cdninstagram', 'Meta (FB/IG)', 'Social', '📱'),
    (r'twitter\.com|twimg|x\.com|abs\.twimg', 'X (Twitter)', 'Social', '📱'),
    (r'reddit\.com|redd\.it|redditstatic|redditmedia', 'Reddit', 'Social', '📱'),
    (r'tiktok|tiktokcdn|musical\.ly|byteoversea|byteimg', 'TikTok', 'Social', '📱'),
    (r'snapchat|sc-cdn|snap-storage', 'Snapchat', 'Social', '📱'),
    (r'linkedin\.com|licdn\.com', 'LinkedIn', 'Social', '📱'),
    (r'pinterest\.com|pinimg\.com', 'Pinterest', 'Social', '📱'),
    (r'discord|discordapp|dis\.gd', 'Discord', 'Communication', '💬'),
    (r'slack\.com|slack-edge|slack-msgs', 'Slack', 'Communication', '💬'),
    (r'teams\.microsoft|teams\.live|teams\.cdn', 'Microsoft Teams', 'Communication', '💬'),
    (r'zoom\.us|zoom\.com|zoomgov', 'Zoom', 'Communication', '💬'),
    (r'whatsapp|wa\.me', 'WhatsApp', 'Communication', '💬'),
    (r'signal\.org|signal-cdn', 'Signal', 'Communication', '💬'),
    (r'telegram\.org|t\.me|telegram-cdn', 'Telegram', 'Communication', '💬'),
    (r'google\.com|googleapis|gstatic|goog\b|google-analytics|googleusercontent|1e100\.net', 'Google', 'Tech', '🔍'),
    (r'bing\.com|bingapis|msn\.com', 'Microsoft Bing', 'Tech', '🔍'),
    (r'duckduckgo', 'DuckDuckGo', 'Tech', '🔍'),
    (r'cloudflare|cf-|one\.one\.one', 'Cloudflare', 'CDN/Cloud', '☁️'),
    (r'akamai|akam|akamaized|edgekey|edgesuite', 'Akamai CDN', 'CDN/Cloud', '☁️'),
    (r'fastly|fastlylb', 'Fastly CDN', 'CDN/Cloud', '☁️'),
    (r'amazonaws\.com|aws\.amazon|cloudfront\.net|s3\.', 'Amazon AWS', 'CDN/Cloud', '☁️'),
    (r'azure\.com|azure\.net|msedge\.net|windows\.net', 'Microsoft Azure', 'CDN/Cloud', '☁️'),
    (r'cloud\.google\.com|googleapis|gcp', 'Google Cloud', 'CDN/Cloud', '☁️'),
    (r'amazon\.com|amazon\.co|media-amazon|images-amazon', 'Amazon', 'Shopping', '🛒'),
    (r'ebay\.com|ebaystatic|ebayimg', 'eBay', 'Shopping', '🛒'),
    (r'walmart\.com|walmartimages', 'Walmart', 'Shopping', '🛒'),
    (r'shopify\.com|cdn\.shopify', 'Shopify', 'Shopping', '🛒'),
    (r'riotgames|leagueoflegends|riotcdn', 'Riot Games', 'Gaming', '🎮'),
    (r'steampowered|steamcommunity|steamcdn|valve\.net', 'Steam', 'Gaming', '🎮'),
    (r'epicgames|fortnite|unrealengine', 'Epic Games', 'Gaming', '🎮'),
    (r'battle\.net|blizzard|bnet', 'Blizzard', 'Gaming', '🎮'),
    (r'xbox\.com|xboxlive', 'Xbox Live', 'Gaming', '🎮'),
    (r'playstation|psn|sie\.com', 'PlayStation', 'Gaming', '🎮'),
    (r'ea\.com|origin\.com|eaplay', 'EA Games', 'Gaming', '🎮'),
    (r'microsoft\.com|microsoftonline|office365|office\.com|live\.com|outlook\.com|windows\.com|windowsupdate|msauth|login\.live', 'Microsoft', 'Tech', '🪟'),
    (r'apple\.com|icloud|apple-dns|mzstatic|itunes', 'Apple', 'Tech', '🍎'),
    (r'openai\.com|chatgpt|oaiusercontent', 'OpenAI', 'AI', '🤖'),
    (r'anthropic\.com|claude\.ai', 'Anthropic', 'AI', '🤖'),
    (r'gemini\.google|bard\.google|generativelanguage', 'Google Gemini', 'AI', '🤖'),
    (r'grok|x\.ai', 'xAI Grok', 'AI', '🤖'),
    (r'cnn\.com', 'CNN', 'News', '📰'),
    (r'bbc\.co|bbc\.com', 'BBC', 'News', '📰'),
    (r'nytimes\.com', 'NY Times', 'News', '📰'),
    (r'foxnews\.com', 'Fox News', 'News', '📰'),
    (r'gmail\.com|mail\.google', 'Gmail', 'Email', '📧'),
    (r'outlook\.live|hotmail', 'Outlook', 'Email', '📧'),
    (r'yahoo\.com|yimg\.com|yahoodns', 'Yahoo', 'Email/Web', '📧'),
    (r'1\.1\.1\.1|one\.one', 'Cloudflare DNS', 'DNS', '🌐'),
    (r'8\.8\.8\.8|8\.8\.4\.4|dns\.google', 'Google DNS', 'DNS', '🌐'),
    (r'9\.9\.9\.9|dns\.quad9', 'Quad9 DNS', 'DNS', '🌐'),
    (r'nordvpn|nord-vpn', 'NordVPN', 'VPN', '🔒'),
    (r'expressvpn|xvpn', 'ExpressVPN', 'VPN', '🔒'),
    (r'protonvpn|proton\.me', 'ProtonVPN', 'VPN', '🔒'),
    (r'coinbase\.com', 'Coinbase', 'Crypto', '💰'),
    (r'binance\.com', 'Binance', 'Crypto', '💰'),
    (r'chase\.com', 'Chase Bank', 'Banking', '🏦'),
    (r'bankofamerica|bofa\.com', 'Bank of America', 'Banking', '🏦'),
    (r'paypal\.com|paypalobjects', 'PayPal', 'Finance', '💳'),
    (r'venmo\.com', 'Venmo', 'Finance', '💳'),
    (r'stripe\.com', 'Stripe', 'Finance', '💳'),
    (r'github\.com|github\.io|githubusercontent', 'GitHub', 'Dev', '💻'),
    (r'stackoverflow\.com|stackexchange', 'StackOverflow', 'Dev', '💻'),
]

_COMPILED_PATTERNS = [(re.compile(pat, re.IGNORECASE), name, cat, icon)
                      for pat, name, cat, icon in SERVICE_PATTERNS]

# Services that are broad infrastructure providers — more specific matches should override these
_GENERIC_SERVICES = frozenset({
    'Google', 'Microsoft', 'Apple', 'Amazon AWS', 'Google Cloud',
    'Microsoft Azure', 'Cloudflare', 'Akamai CDN', 'Fastly CDN',
})


class ServiceResolver:
    """Resolves IPs and domains to human-readable service names with caching."""
    def __init__(self):
        self._rdns_cache: dict[str, str] = {}
        self._service_cache: dict[str, dict] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _is_unresolved(service: str) -> bool:
        """True if service is just an IP, 'Unknown', or empty — needs re-resolution."""
        if not service or service == 'Unknown':
            return True
        try:
            ipaddress.ip_address(service)
            return True
        except ValueError:
            return False

    @staticmethod
    def _pick_best_website_domain(candidates: list[str]) -> str:
        """From a list of raw website domains, pick the most readable one."""
        if not candidates:
            return ''
        # Prefer shortest non-www, non-cdn domain; fall back to shortest overall
        clean = []
        for d in candidates:
            low = d.lower()
            if not low.startswith(('www.', 'cdn.', 'static.', 'assets.', 'img.', 'images.',
                                   'api.', 'edge.', 'media.', 'dl.', 'download.')):
                clean.append(d)
        pool = clean or candidates
        return min(pool, key=len)

    def resolve_domain(self, domain: str) -> dict:
        if not domain:
            return {'service': 'Unknown', 'category': 'Unknown', 'icon': '❓'}
        domain_lower = domain.lower()
        for pattern, name, category, icon in _COMPILED_PATTERNS:
            if pattern.search(domain_lower):
                return {'service': name, 'category': category, 'icon': icon}
        return {'service': domain_lower, 'category': 'Other', 'icon': '🌐'}

    def reverse_dns(self, ip: str) -> Optional[str]:
        with self.lock:
            if ip in self._rdns_cache:
                return self._rdns_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            with self.lock:
                self._rdns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            with self.lock:
                self._rdns_cache[ip] = ""
            return ""

    def identify(self, ip: str, domains: Optional[set] = None) -> dict:
        with self.lock:
            cached = self._service_cache.get(ip)
            if cached:
                svc = cached.get('service', '')
                # Return immediately only for specific known services (non-generic, non-placeholder)
                if svc and svc not in _GENERIC_SERVICES and not self._is_unresolved(svc):
                    # CDN hostnames should always allow re-evaluation
                    svc_lower = svc.lower()
                    is_cdn_svc = any(cdn in svc_lower for cdn in (
                        'cloudfront', 'akamai', 'fastly', 'cloudflare', 'amazonaws',
                        'azureedge', 'edgecast', 'hwcdn', 'edgesuite', 'akamaiedge',
                        'server-', 'deploy.static', 'compute-1.', '.elb.',
                        '1e100.net', 'fbcdn', 'googleusercontent',
                    ))
                    if is_cdn_svc:
                        if not domains:
                            return cached
                        # Fall through to re-evaluate with new domains
                    elif domains:
                        # Check if we already have a website domain or a pattern-matched service
                        resolved = self.resolve_domain(cached.get('domain', ''))
                        if resolved.get('service') != cached.get('domain', '').lower():
                            # It's a pattern-matched service like YouTube — keep it
                            return cached
                        # It's a website domain (pornhub.com) — check if a better specific match exists
                    else:
                        return cached
                if not domains:
                    return cached
        if domains:
            specific_match = None      # YouTube, Netflix, Discord, etc.
            specific_domain = None
            generic_match = None       # Google, Cloudflare, Akamai, etc.
            generic_domain = None
            website_domains = []       # pornhub.com, yahoo.com — actual sites

            for d in domains:
                result = self.resolve_domain(d)
                is_pattern_match = (result['service'] != d.lower())
                if is_pattern_match:
                    if result['service'] not in _GENERIC_SERVICES:
                        # Specific known service — best possible match
                        if specific_match is None:
                            specific_match = result
                            specific_domain = d
                    else:
                        if generic_match is None:
                            generic_match = result
                            generic_domain = d
                else:
                    # No pattern matched — this IS the actual website domain
                    website_domains.append(d)

            # Priority: specific service > website domain > generic CDN
            if specific_match:
                specific_match['domain'] = specific_domain
                if generic_match:
                    specific_match['via'] = generic_match['service']
                with self.lock:
                    self._service_cache[ip] = specific_match
                return specific_match

            if website_domains:
                best_domain = self._pick_best_website_domain(website_domains)
                result = {'service': best_domain, 'category': 'Website', 'icon': '🌐',
                          'domain': best_domain, 'via': ''}
                if generic_match:
                    result['via'] = generic_match['service']
                with self.lock:
                    self._service_cache[ip] = result
                return result

            if generic_match:
                generic_match['domain'] = generic_domain
                with self.lock:
                    self._service_cache[ip] = generic_match
                return generic_match

            # All domains were unrecognized duplicates of themselves — use first
            first_domain = next(iter(domains))
            result = {'service': first_domain, 'category': 'Other', 'icon': '🌐',
                      'domain': first_domain, 'via': ''}
            with self.lock:
                self._service_cache[ip] = result
            return result

        rdns = self.reverse_dns(ip)
        if rdns:
            result = self.resolve_domain(rdns)
            result['domain'] = rdns
            with self.lock:
                self._service_cache[ip] = result
            return result
        if ip in ('1.1.1.1', '1.0.0.1'):
            result = {'service': 'Cloudflare DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip.startswith('8.8.'):
            result = {'service': 'Google DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip == '9.9.9.9':
            result = {'service': 'Quad9 DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        else:
            result = {'service': ip, 'category': 'Unknown', 'icon': '❓', 'domain': ip}
        with self.lock:
            self._service_cache[ip] = result
        return result


# ========================== CONNECTION INVENTORY ==========================
class ConnectionEntry:
    """Single tracked connection with full metadata."""
    __slots__ = (
        'all_domains', 'category', 'city', 'cmdline', 'country', 'country_code',
        'domain', 'exe_path', 'first_seen', 'icon', 'isp', 'last_seen', 'lat',
        'local_port', 'loc_confidence', 'loc_grade', 'loc_proof', 'lon', 'org',
        'parent_name', 'pid', 'process_name', 'protocol', 'proxy_detail',
        'proxy_type', 'region', 'remote_ip', 'remote_port', 'service', 'status',
        'via', 'website_tag',
    )

    def __init__(self):
        self.pid = 0
        self.process_name = ''
        self.exe_path = ''
        self.parent_name = ''
        self.cmdline = ''
        self.website_tag = ''
        self.remote_ip = ''
        self.remote_port = 0
        self.local_port = 0
        self.protocol = 'TCP'
        self.status = ''
        self.service = 'Unknown'
        self.category = 'Unknown'
        self.icon = '❓'
        self.domain = ''
        self.all_domains: list = []
        self.via = ''
        self.country = '??'
        self.country_code = '??'
        self.city = '??'
        self.region = ''
        self.org = 'Unknown'
        self.isp = 'Unknown'
        self.lat = 0.0
        self.lon = 0.0
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.loc_confidence = 0
        self.loc_grade = 'UNVERIFIED'
        self.loc_proof: list = []
        self.proxy_type = ''
        self.proxy_detail = ''

    def to_dict(self) -> dict:
        return {
            'pid': self.pid, 'process': self.process_name,
            'exe_path': self.exe_path, 'parent_name': self.parent_name,
            'cmdline': self.cmdline, 'website_tag': self.website_tag,
            'remote_ip': self.remote_ip, 'remote_port': self.remote_port,
            'local_port': self.local_port, 'protocol': self.protocol,
            'status': self.status, 'service': self.service,
            'category': self.category, 'icon': self.icon, 'domain': self.domain,
            'all_domains': list(self.all_domains), 'via': self.via,
            'country': self.country, 'country_code': self.country_code,
            'city': self.city, 'region': self.region,
            'org': self.org, 'isp': self.isp,
            'lat': self.lat, 'lon': self.lon,
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'loc_confidence': self.loc_confidence, 'loc_grade': self.loc_grade,
            'loc_proof': list(self.loc_proof),
            'proxy_type': self.proxy_type, 'proxy_detail': self.proxy_detail,
        }


class ConnectionInventory:
    """Maintains a live inventory of ALL network connections with service + geo data."""
    def __init__(self, dns_cache: DNSCache, geoip: GeoIPCache,
                 service_resolver: ServiceResolver, stop_event: threading.Event,
                 conn_provider=None):
        self.dns_cache = dns_cache
        self.geoip = geoip
        self.resolver = service_resolver
        self.stop = stop_event
        self._conn_provider = conn_provider
        self.loc_verifier = LocationVerifier(service_resolver)
        self.proxy_detector = ProxyDetector()
        self.lock = threading.Lock()
        self.connections: dict[tuple, ConnectionEntry] = {}
        self.services_seen: dict[str, dict] = {}
        self.total_unique_ips: set[str] = set()
        self.scan_count = 0

    def _is_public(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    def _get_connections(self) -> list:
        if self._conn_provider:
            return self._conn_provider()
        try:
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            _mb_logger.debug("Connection inventory: access denied for net_connections")
            return []
        except Exception as exc:
            _mb_logger.debug("Connection inventory scan error: %s", exc)
            return []

    _CDN_HOSTNAME_PATTERNS = (
        'cloudfront', 'akamai', 'fastly', 'cloudflare', 'amazonaws',
        'azureedge', 'edgecast', 'cdn.', 'deploy.static', 'compute-1.',
        'elb.', 'server-', '.r.cloudfront', 'hwcdn', 'edgesuite',
        'akadns', 'akamaiedge', 'azurefd', 'trafficmanager', 'msedge.net',
        'footprint.net', 'fpbns.net', 'nsatc.net', 'nflxvideo',
        'llnwd.net', 'lldns.net', 'edgekey', 'akamaihd', 'akamaitechnologies',
        'cloudapp.net', 'azure.com', 'googleusercontent', '1e100.net',
        'gstatic', 'ggpht', 'fbcdn', 'facebook.net', 'xx.fbcdn',
    )

    @staticmethod
    def _is_cdn_hostname(domain: str) -> bool:
        dl = domain.lower()
        return any(cdn in dl for cdn in ConnectionInventory._CDN_HOSTNAME_PATTERNS)

    @staticmethod
    def _compute_website_tag(entry) -> str:
        """Best-effort human-readable label for WHAT WEBSITE this connection is for."""
        svc = entry.service
        dom = entry.domain
        via = entry.via
        all_doms = entry.all_domains
        # If service is a known specific service (YouTube, Netflix, etc.) use it
        if svc and svc not in _GENERIC_SERVICES and not ServiceResolver._is_unresolved(svc):
            tag = svc
            if via:
                tag += f" (via {via})"
            return tag
        # If we have real website domains, pick the best one
        if all_doms:
            real_sites = [d for d in all_doms
                          if not ConnectionInventory._is_cdn_hostname(d)]
            if real_sites:
                # Prefer shortest non-www domain as it's usually the apex
                def _score(d):
                    d_lower = d.lower()
                    # Prefer shorter domains (apex like amazon.com over sub.amazon.com)
                    parts = d_lower.split('.')
                    return (len(parts), len(d_lower))
                best = min(real_sites, key=_score)
                tag = best
                if via:
                    tag += f" (via {via})"
                elif svc in _GENERIC_SERVICES:
                    tag += f" (via {svc})"
                return tag
        # Fall back: use domain if it's not just an IP
        if dom and not ServiceResolver._is_unresolved(dom) and dom != entry.remote_ip:
            # Even CDN hostname is better than nothing — show with org
            org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
            if ConnectionInventory._is_cdn_hostname(dom) and org:
                return f"[{org}] {dom}"
            return dom
        # Use service + org for context
        if svc and not ServiceResolver._is_unresolved(svc):
            org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
            if org and org.lower() not in svc.lower():
                return f"{svc} ({org})"
            return svc
        # Absolute fallback: IP + org
        org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
        if org:
            return f"{entry.remote_ip} ({org})"
        return entry.remote_ip

    @staticmethod
    def _get_process_detail(pid: int) -> dict:
        """Gather full process detail for a PID: name, exe path, parent, cmdline."""
        info = {'name': f'PID:{pid}', 'exe_path': '', 'parent_name': '', 'cmdline': ''}
        try:
            proc = psutil.Process(pid)
            info['name'] = proc.name()
            try:
                info['exe_path'] = proc.exe() or ''
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                parent = proc.parent()
                if parent:
                    info['parent_name'] = parent.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                cmdline = proc.cmdline()
                if cmdline:
                    info['cmdline'] = ' '.join(cmdline)[:300]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return info

    def scan(self):
        now = time.time()
        active_keys = set()
        pid_names = {}
        for proc in psutil.process_iter(['pid', 'name']):
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                pid_names[proc.pid] = proc.name()
        conns = self._get_connections()
        for conn in conns:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr[0]
            remote_port = conn.raddr[1]
            pid = conn.pid or 0
            key = (remote_ip, remote_port, pid)
            active_keys.add(key)
            with self.lock:
                if key in self.connections:
                    entry = self.connections[key]
                    entry.last_seen = now
                    entry.status = conn.status
                    # Always refresh all_domains from DNS cache
                    fresh_domains = self.dns_cache.get_domains(remote_ip)
                    if fresh_domains:
                        entry.all_domains = sorted(fresh_domains)
                    # Re-resolve service if under-resolved (generic CDN, IP, Unknown, empty domain, CDN hostname)
                    cur_svc = entry.service
                    needs_recheck = (
                        cur_svc in _GENERIC_SERVICES
                        or ServiceResolver._is_unresolved(cur_svc)
                        or not entry.domain
                        or entry.domain == remote_ip
                        or self._is_cdn_hostname(cur_svc)
                        or self._is_cdn_hostname(entry.domain)
                    )
                    if needs_recheck and fresh_domains:
                        svc_info = self.resolver.identify(remote_ip, fresh_domains)
                        new_svc = svc_info.get('service', cur_svc)
                        if new_svc != cur_svc:
                            entry.service = new_svc
                            entry.category = svc_info.get('category', entry.category)
                            entry.icon = svc_info.get('icon', entry.icon)
                            entry.domain = svc_info.get('domain', entry.domain)
                            entry.via = svc_info.get('via', entry.via)
                    # Recompute website tag every cycle
                    entry.website_tag = self._compute_website_tag(entry)
                    continue
            # --- New connection: gather full process detail ---
            pdetail = self._get_process_detail(pid)
            entry = ConnectionEntry()
            entry.pid = pid
            entry.process_name = pdetail['name']
            entry.exe_path = pdetail['exe_path']
            entry.parent_name = pdetail['parent_name']
            entry.cmdline = pdetail['cmdline']
            entry.remote_ip = remote_ip
            entry.remote_port = remote_port
            entry.local_port = conn.laddr[1] if conn.laddr else 0
            entry.protocol = 'TCP' if conn.type == 1 else 'UDP'
            entry.status = conn.status
            entry.first_seen = now
            entry.last_seen = now
            domains = self.dns_cache.get_domains(remote_ip)
            svc_info = self.resolver.identify(remote_ip, domains)
            entry.service = svc_info.get('service', 'Unknown')
            entry.category = svc_info.get('category', 'Unknown')
            entry.icon = svc_info.get('icon', '❓')
            entry.domain = svc_info.get('domain', '')
            entry.via = svc_info.get('via', '')
            entry.all_domains = sorted(domains) if domains else []
            if self._is_public(remote_ip):
                geo = self.geoip.get_full(remote_ip)
                entry.country = geo.get('country', '??')
                entry.country_code = geo.get('countryCode', '??')
                entry.city = geo.get('city', '??')
                entry.region = geo.get('regionName', '')
                entry.org = geo.get('org', 'Unknown')
                entry.isp = geo.get('isp', 'Unknown')
                entry.lat = geo.get('lat', 0.0)
                entry.lon = geo.get('lon', 0.0)
                # Run location verification in background to avoid blocking
                try:
                    vr = self.loc_verifier.verify(remote_ip, geo)
                    entry.loc_confidence = vr.get('confidence', 0)
                    entry.loc_grade = vr.get('grade', 'UNVERIFIED')
                    entry.loc_proof = vr.get('proof', [])
                except Exception:
                    pass
            # Proxy detection per-connection
            try:
                proxy_info = self.proxy_detector.classify_connection(
                    remote_ip, remote_port, entry.domain, entry.org, entry.isp)
                if proxy_info:
                    entry.proxy_type = proxy_info.get('proxy_type', '')
                    entry.proxy_detail = proxy_info.get('proxy_detail', '')
            except Exception:
                pass
            entry.website_tag = self._compute_website_tag(entry)
            with self.lock:
                if self._is_public(remote_ip):
                    self.total_unique_ips.add(remote_ip)
                self.connections[key] = entry
                self.services_seen[entry.service] = {
                    'category': entry.category, 'icon': entry.icon,
                    'country': entry.country, 'city': entry.city,
                    'org': entry.org, 'lat': entry.lat, 'lon': entry.lon,
                    'last_seen': now,
                }
        with self.lock:
            stale = [k for k, v in self.connections.items() if k not in active_keys
                     and now - v.last_seen > 60]
            for k in stale:
                del self.connections[k]
        with self.lock:
            self.scan_count += 1

    def get_all(self) -> list[dict]:
        with self.lock:
            return [e.to_dict() for e in self.connections.values()]

    def get_map_points(self) -> list[dict]:
        seen_ips = {}
        with self.lock:
            for entry in self.connections.values():
                if (entry.lat != 0 or entry.lon != 0) and entry.remote_ip not in seen_ips:
                    seen_ips[entry.remote_ip] = {
                        'ip': entry.remote_ip, 'lat': entry.lat, 'lon': entry.lon,
                        'service': entry.service, 'icon': entry.icon,
                        'domain': entry.domain,
                        'all_domains': list(entry.all_domains),
                        'via': entry.via, 'website_tag': entry.website_tag,
                        'city': entry.city, 'country': entry.country,
                        'org': entry.org, 'process': entry.process_name,
                        'loc_confidence': entry.loc_confidence,
                        'loc_grade': entry.loc_grade,
                        'loc_proof': list(entry.loc_proof),
                        'proxy_type': entry.proxy_type,
                        'proxy_detail': entry.proxy_detail,
                    }
        return list(seen_ips.values())

    def get_services_summary(self) -> list[dict]:
        with self.lock:
            return [{'service': name, **info} for name, info in self.services_seen.items()]

    def get_stats(self) -> dict:
        with self.lock:
            n_conns = len(self.connections)
            n_services = len(self.services_seen)
        return {
            'total_connections': n_conns,
            'unique_services': n_services,
            'unique_ips': len(self.total_unique_ips),
            'scans': self.scan_count,
        }

    def format_terminal_line(self, entry: ConnectionEntry) -> str:
        geo = f"{entry.city}, {entry.country_code}" if entry.city != '??' else entry.country_code
        coords = f"({entry.lat:.2f}, {entry.lon:.2f})" if entry.lat or entry.lon else ""
        return (f"  {entry.icon} {entry.service:20s} | {entry.process_name:20s} | "
                f"{entry.remote_ip:15s}:{entry.remote_port:<5d} | "
                f"{geo:20s} {coords} | {entry.org}")

    def run_thread(self):
        _mb_logger.info("Connection inventory thread started")
        first_scan = True
        while not self.stop.is_set():
            self.scan()
            if first_scan or self.scan_count % 12 == 0:
                self._log_summary()
                first_scan = False
            time.sleep(5)

    def _log_summary(self):
        entries = self.get_all()
        if not entries:
            return
        stats = self.get_stats()
        print(f"\n{Colors.G}{'='*100}")
        print(f"{EMOJI['chess']} CONNECTION MAP — {stats['total_connections']} active | "
              f"{stats['unique_services']} services | {stats['unique_ips']} unique IPs")
        print(f"{'='*100}{Colors.END}")
        by_cat = defaultdict(list)
        for e in entries:
            by_cat[e['category']].append(e)
        for cat in sorted(by_cat.keys()):
            conns = by_cat[cat]
            print(f"{Colors.C}  [{cat}]{Colors.END}")
            for c in conns[:15]:
                geo = f"{c['city']}, {c['country_code']}" if c['city'] != '??' else c['country_code']
                coords = f"({c['lat']:.2f}, {c['lon']:.2f})" if c['lat'] or c['lon'] else ""
                print(f"    {c['icon']} {c['service']:20s} | {c['process']:18s} | "
                      f"{c['remote_ip']:15s}:{c['remote_port']:<5d} | "
                      f"{geo:20s} {coords}")
            if len(conns) > 15:
                print(f"    ... and {len(conns)-15} more")
        print(f"{Colors.G}{'='*100}{Colors.END}\n")


# ========================== DASHBOARD ==========================
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedianBoxMonitor Dashboard</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#c0c0c0;font-family:'Consolas','Fira Code',monospace;font-size:13px}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:12px 24px;border-bottom:2px solid #0f3460;display:flex;justify-content:space-between;align-items:center}
.header h1{color:#e94560;font-size:18px;text-shadow:0 0 20px rgba(233,69,96,0.5)}
.header .stats{display:flex;gap:16px}
.stat{text-align:center}.stat .val{font-size:20px;font-weight:bold;color:#00d4ff}.stat .lbl{font-size:9px;color:#666}
.tabs{display:flex;background:#12121a;border-bottom:2px solid #1a1a2e}
.tab{padding:10px 20px;cursor:pointer;color:#666;font-size:12px;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:#c0c0c0}.tab.active{color:#e94560;border-bottom-color:#e94560}
.tab-content{display:none;height:calc(100vh - 115px);overflow:hidden}
.tab-content.active{display:block}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:10px;height:100%;overflow:hidden}
.grid-3{display:grid;grid-template-columns:1fr;gap:10px;padding:10px;height:100%}
.panel{background:#12121a;border:1px solid #1a1a2e;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.panel-title{background:#1a1a2e;padding:6px 14px;font-size:11px;font-weight:bold;color:#e94560;text-transform:uppercase;letter-spacing:1px}
.panel-body{overflow-y:auto;padding:6px;flex:1}
#map-container{height:50vh;border-radius:8px;overflow:hidden;border:1px solid #1a1a2e}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:#1a1a2e;color:#0f3460;font-size:10px;text-align:left;padding:3px 6px;text-transform:uppercase}
td{padding:2px 6px;border-bottom:1px solid #1a1a2e;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px}
tr:hover{background:#1a1a2e}
.risk-critical{color:#e94560;font-weight:bold}.risk-warning{color:#f5a623}.risk-low{color:#4caf50}
.sev-CRITICAL{background:#e9456022;color:#e94560;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:10px}
.sev-WARNING{background:#f5a62322;color:#f5a623;padding:2px 6px;border-radius:3px;font-size:10px}
.sev-INFO{background:#4caf5022;color:#4caf50;padding:2px 6px;border-radius:3px;font-size:10px}
.conn-row{display:flex;align-items:center;padding:4px 8px;border-bottom:1px solid #1a1a2e;gap:8px;font-size:11px}
.conn-row:hover{background:#1a1a2e}
.conn-icon{font-size:16px;min-width:22px;text-align:center}
.conn-svc{color:#00d4ff;font-weight:bold;min-width:130px}
.conn-proc{color:#f5a623;min-width:120px}
.conn-ip{color:#888;min-width:150px;font-family:monospace}
.conn-geo{color:#4caf50;min-width:160px}
.conn-coords{color:#666;font-size:10px;min-width:120px}
.conn-org{color:#888;flex:1;overflow:hidden;text-overflow:ellipsis}
.cat-header{padding:6px 12px;background:#0f3460;color:#00d4ff;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.device{padding:3px 0;border-bottom:1px solid #1a1a2e;display:flex;justify-content:space-between;font-size:11px}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#0a0a0f}::-webkit-scrollbar-thumb{background:#1a1a2e;border-radius:3px}
.leaflet-popup-content{font-family:'Consolas',monospace;font-size:12px;color:#222}
.leaflet-popup-content b{color:#e94560}
</style></head><body>
<div class="header">
  <h1>&#9823; MedianBoxMonitor 3.0</h1>
  <div class="stats">
    <div class="stat"><div class="val" id="s-conn">-</div><div class="lbl">CONNECTIONS</div></div>
    <div class="stat"><div class="val" id="s-svc">-</div><div class="lbl">SERVICES</div></div>
    <div class="stat"><div class="val" id="s-ips">-</div><div class="lbl">UNIQUE IPs</div></div>
    <div class="stat"><div class="val" id="s-proc">-</div><div class="lbl">PROCESSES</div></div>
    <div class="stat"><div class="val" id="s-ded">-</div><div class="lbl">DEDUCTIONS</div></div>
    <div class="stat"><div class="val" id="s-dev">-</div><div class="lbl">DEVICES</div></div>
    <div class="stat"><div class="val" id="s-idle">-</div><div class="lbl">IDLE (s)</div></div>
  </div>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('map')">&#127758; Connection Map</div>
  <div class="tab" onclick="switchTab('list')">&#128196; All Connections</div>
  <div class="tab" onclick="switchTab('deductions')">&#128680; Deductions</div>
  <div class="tab" onclick="switchTab('processes')">&#128202; Processes</div>
  <div class="tab" onclick="switchTab('devices')">&#127381; Devices</div>
</div>
<!-- TAB 1: Connection Map -->
<div id="tab-map" class="tab-content active">
  <div class="grid" style="grid-template-columns:1fr;grid-template-rows:55% 45%">
    <div id="map-container"></div>
    <div class="panel"><div class="panel-title">&#128225; Active Services</div>
      <div class="panel-body" id="svc-body"></div>
    </div>
  </div>
</div>
<!-- TAB 2: All Connections -->
<div id="tab-list" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128279; All Active Connections (auto-discovered)</div>
    <div class="panel-body" id="conn-body"></div>
  </div></div>
</div>
<!-- TAB 3: Deductions -->
<div id="tab-deductions" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128680; Live Deductions</div><div class="panel-body">
    <table><thead><tr><th>Time</th><th>Sev</th><th>Cat</th><th>Process</th><th>Message</th><th>Score</th></tr></thead><tbody id="ded-table"></tbody></table>
  </div></div></div>
</div>
<!-- TAB 4: Processes -->
<div id="tab-processes" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128202; Process Risk Scores</div><div class="panel-body">
    <table><thead><tr><th>PID</th><th>Name</th><th>Risk</th><th>Conn</th><th>Dst</th><th>ML</th><th>Countries</th></tr></thead><tbody id="proc-table"></tbody></table>
  </div></div></div>
</div>
<!-- TAB 5: Devices -->
<div id="tab-devices" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#127381; Network Devices</div>
    <div class="panel-body" id="dev-body"></div>
  </div></div>
</div>
<script>
// === Map Setup ===
const map=L.map('map-container',{zoomControl:true}).setView([30,0],2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
  attribution:'&copy; OSM &copy; CARTO',maxZoom:18,subdomains:'abcd'
}).addTo(map);
const markers={};
function updateMap(points){
  const seen=new Set();
  (points||[]).forEach(p=>{
    if(!p.lat&&!p.lon)return;
    const k=p.ip;seen.add(k);
    if(markers[k]){markers[k].setPopupContent(popupHtml(p));return}
    const m=L.circleMarker([p.lat,p.lon],{radius:6,color:'#e94560',fillColor:'#00d4ff',fillOpacity:0.8,weight:1}).addTo(map);
    m.bindPopup(popupHtml(p));markers[k]=m;
  });
  Object.keys(markers).forEach(k=>{if(!seen.has(k)){map.removeLayer(markers[k]);delete markers[k]}});
}
function popupHtml(p){
  const d=document.createElement('div');
  d.innerHTML='';
  if(p.website_tag){const wt=document.createElement('b');wt.style.color='#00ff88';wt.textContent='\ud83c\udff7\ufe0f '+p.website_tag;d.appendChild(wt);d.appendChild(document.createElement('br'))}
  const b1=document.createElement('b');b1.textContent=p.service+' '+p.icon;d.appendChild(b1);
  d.appendChild(document.createElement('br'));
  let domLine=p.domain||'';
  if(p.via)domLine+=' (via '+p.via+')';
  if(domLine){const dt=document.createTextNode(domLine);d.appendChild(dt);d.appendChild(document.createElement('br'))}
  const t1=document.createTextNode(p.ip+' ('+p.process+')');d.appendChild(t1);
  d.appendChild(document.createElement('br'));
  const t2=document.createTextNode(p.city+', '+p.country);d.appendChild(t2);
  d.appendChild(document.createElement('br'));
  const sm=document.createElement('small');sm.textContent=p.org+' | '+p.lat.toFixed(4)+', '+p.lon.toFixed(4);d.appendChild(sm);
  if(p.all_domains&&p.all_domains.length>1){d.appendChild(document.createElement('br'));const ad=document.createElement('small');ad.style.color='#888';ad.textContent='Domains: '+p.all_domains.slice(0,6).join(', ')+(p.all_domains.length>6?' (+'+String(p.all_domains.length-6)+')':'');d.appendChild(ad)}
  return d.innerHTML;
}
// === Tab Switching ===
function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelectorAll('.tab').forEach(t=>{if(t.textContent.toLowerCase().includes(name.slice(0,4)))t.classList.add('active')});
  if(name==='map')setTimeout(()=>map.invalidateSize(),100);
}
// === DOM Helpers ===
function mkTd(text){const td=document.createElement('td');td.textContent=text;return td}
function mkRow(cells){const tr=document.createElement('tr');cells.forEach(c=>{if(typeof c==='object')tr.appendChild(c);else tr.appendChild(mkTd(c))});return tr}
function riskClass(r){return r>=70?'risk-critical':r>=40?'risk-warning':'risk-low'}
function sevClass(s){return{'CRITICAL':'sev-CRITICAL','WARNING':'sev-WARNING','INFO':'sev-INFO'}[s]||'sev-INFO'}
// === Connection List ===
function updateConnections(conns){
  const body=document.getElementById('conn-body');body.replaceChildren();
  if(!conns||!conns.length){body.textContent='Scanning connections...';return}
  const byCat={};
  conns.forEach(c=>{if(!byCat[c.category])byCat[c.category]=[];byCat[c.category].push(c)});
  Object.keys(byCat).sort().forEach(cat=>{
    const hdr=document.createElement('div');hdr.className='cat-header';hdr.textContent=cat+' ('+byCat[cat].length+')';body.appendChild(hdr);
    byCat[cat].forEach(c=>{
      const row=document.createElement('div');row.className='conn-row';
      const icon=document.createElement('span');icon.className='conn-icon';icon.textContent=c.icon;
      const svc=document.createElement('span');svc.className='conn-svc';svc.textContent=c.service+(c.via?' (via '+c.via+')':'');
      const dom=document.createElement('span');dom.className='conn-proc';dom.style.color='#888';dom.textContent=c.domain||'';
      const proc=document.createElement('span');proc.className='conn-proc';proc.textContent=c.process;
      const ip=document.createElement('span');ip.className='conn-ip';ip.textContent=c.remote_ip+':'+c.remote_port;
      const geo=document.createElement('span');geo.className='conn-geo';
      geo.textContent=(c.city&&c.city!=='??')?c.city+', '+c.country_code:c.country_code;
      const coords=document.createElement('span');coords.className='conn-coords';
      coords.textContent=(c.lat||c.lon)?'('+c.lat.toFixed(2)+', '+c.lon.toFixed(2)+')':'';
      const org=document.createElement('span');org.className='conn-org';org.textContent=c.org||'';
      row.appendChild(icon);row.appendChild(svc);row.appendChild(dom);row.appendChild(proc);row.appendChild(ip);
      row.appendChild(geo);row.appendChild(coords);row.appendChild(org);body.appendChild(row);
    });
  });
}
// === Services Summary ===
function updateServices(svcs){
  const body=document.getElementById('svc-body');body.replaceChildren();
  if(!svcs||!svcs.length)return;
  svcs.sort((a,b)=>(a.category||'').localeCompare(b.category||''));
  svcs.forEach(s=>{
    const row=document.createElement('div');row.className='conn-row';
    const icon=document.createElement('span');icon.className='conn-icon';icon.textContent=s.icon;
    const svc=document.createElement('span');svc.className='conn-svc';svc.textContent=s.service;
    const geo=document.createElement('span');geo.className='conn-geo';
    geo.textContent=(s.city&&s.city!=='??')?s.city+', '+s.country:'';
    const org=document.createElement('span');org.className='conn-org';org.textContent=s.org||'';
    const coords=document.createElement('span');coords.className='conn-coords';
    coords.textContent=(s.lat||s.lon)?'('+s.lat.toFixed(2)+', '+s.lon.toFixed(2)+')':'';
    row.appendChild(icon);row.appendChild(svc);row.appendChild(geo);row.appendChild(coords);row.appendChild(org);
    body.appendChild(row);
  });
}
// === Main Update ===
function update(data){
  document.getElementById('s-conn').textContent=data.conn_stats?data.conn_stats.total_connections:'-';
  document.getElementById('s-svc').textContent=data.conn_stats?data.conn_stats.unique_services:'-';
  document.getElementById('s-ips').textContent=data.conn_stats?data.conn_stats.unique_ips:'-';
  document.getElementById('s-proc').textContent=data.processes?data.processes.length:'-';
  document.getElementById('s-ded').textContent=data.deductions?data.deductions.length:'-';
  document.getElementById('s-dev').textContent=data.devices?data.devices.length:'-';
  document.getElementById('s-idle').textContent=data.idle_seconds||'-';
  updateMap(data.map_points);
  updateConnections(data.connections);
  updateServices(data.services);
  let dt=document.getElementById('ded-table');dt.replaceChildren();
  (data.deductions||[]).slice(0,50).forEach(d=>{
    const sevTd=document.createElement('td');
    const sevSpan=document.createElement('span');sevSpan.className=sevClass(d.severity);sevSpan.textContent=d.severity;
    sevTd.appendChild(sevSpan);
    const msgTd=document.createElement('td');msgTd.textContent=(d.message||'').slice(0,80);msgTd.title=d.message||'';
    dt.appendChild(mkRow([d.time,sevTd,d.category,d.process+':'+d.pid,msgTd,String(d.score)]));
  });
  let pt=document.getElementById('proc-table');pt.replaceChildren();
  (data.processes||[]).filter(p=>p.risk>0.1||p.connections>0).slice(0,60).forEach(p=>{
    const riskTd=document.createElement('td');riskTd.textContent=p.risk;riskTd.className=riskClass(p.risk);
    pt.appendChild(mkRow([String(p.pid),p.name,riskTd,String(p.connections),String(p.destinations),String(p.ml_score),(p.countries||[]).join(',')]));
  });
  let db=document.getElementById('dev-body');db.replaceChildren();
  (data.devices||[]).forEach(d=>{
    const div=document.createElement('div');div.className='device';
    const s1=document.createElement('span');s1.textContent=(d.ip||'?')+' \\u2014 '+(d.vendor||'?')+' \\u2014 '+(d.hostname||'?');
    const s2=document.createElement('span');s2.textContent=(d.os_guess||'?')+' | conf='+(d.confidence||0).toFixed(2);
    div.appendChild(s1);div.appendChild(s2);db.appendChild(div);
  });
}
const urlParams=new URLSearchParams(window.location.search);
const authToken=urlParams.get('token')||'';
const wsUrl='ws://'+location.host+'/ws'+(authToken?'?token='+encodeURIComponent(authToken):'');
const apiUrl='/api/state'+(authToken?'?token='+encodeURIComponent(authToken):'');
let ws=new WebSocket(wsUrl);
ws.onmessage=e=>update(JSON.parse(e.data));
ws.onclose=()=>setTimeout(()=>location.reload(),5000);
setInterval(()=>{if(ws.readyState!==1)fetch(apiUrl).then(r=>r.json()).then(update).catch(()=>{})},5000);
</script></body></html>"""


# ========================== GNA TRACER GUI ==========================
# Simplified world coastline points (lat, lon) for equirectangular map projection
_WORLD_COASTLINE = [
    # North America
    (49, -125), (48, -123), (45, -124), (42, -124), (38, -123), (34, -120),
    (32, -117), (28, -115), (23, -110), (20, -105), (18, -103), (16, -96),
    (15, -92), (18, -88), (21, -87), (25, -90), (29, -89), (30, -84),
    (27, -80), (25, -80), (30, -81), (32, -80), (35, -75), (37, -76),
    (39, -74), (41, -72), (42, -70), (43, -70), (44, -67), (45, -67),
    (47, -68), (47, -65), (45, -61), (47, -60), (49, -64), (47, -56),
    (52, -56), (55, -60), (58, -64), (60, -65), (63, -68), (66, -62),
    (60, -46), (70, -52), (72, -56), (75, -60), (78, -73), (76, -89),
    (70, -100), (68, -110), (70, -128), (68, -136), (60, -140), (59, -150),
    (55, -160), (57, -157), (58, -153), (60, -147), (60, -141), (55, -132),
    (54, -130), (49, -125),
    None,  # break
    # South America
    (12, -72), (10, -76), (8, -77), (2, -78), (-2, -80), (-5, -81), (-6, -77),
    (-15, -75), (-18, -71), (-23, -70), (-27, -71), (-33, -72), (-41, -74),
    (-46, -76), (-53, -71), (-55, -68), (-52, -68), (-48, -66), (-42, -64),
    (-37, -57), (-35, -53), (-23, -42), (-13, -39), (-8, -35), (-2, -44),
    (2, -50), (5, -52), (7, -58), (8, -60), (10, -62), (11, -68), (12, -72),
    None,  # break
    # Europe
    (36, -6), (37, -2), (38, 0), (40, 0), (43, 3), (43, 7), (44, 9),
    (40, 14), (38, 16), (38, 21), (40, 24), (41, 29), (43, 28), (44, 34),
    (46, 37), (47, 40), (50, 40), (55, 38), (58, 30), (60, 29), (62, 30),
    (65, 26), (68, 20), (70, 20), (71, 26), (70, 30), (68, 44), (64, 40),
    (60, 32), (58, 28), (56, 21), (55, 12), (54, 9), (53, 7), (52, 5),
    (51, 4), (49, 0), (48, -5), (44, -8), (43, -9), (37, -9), (36, -6),
    None,  # break
    # Africa
    (36, -6), (35, -1), (37, 10), (33, 12), (32, 24), (31, 32), (22, 37),
    (12, 44), (2, 42), (-10, 40), (-15, 41), (-26, 33), (-34, 18),
    (-34, 18), (-33, 17), (-30, 17), (-22, 14), (-17, 12), (-12, 14),
    (-5, 12), (4, 2), (6, 1), (4, -7), (5, -4), (7, -5), (10, -15),
    (15, -17), (21, -17), (27, -13), (31, -10), (36, -6),
    None,  # break
    # Asia
    (42, 30), (41, 40), (37, 44), (30, 48), (25, 56), (22, 60), (25, 62),
    (25, 66), (24, 68), (20, 73), (15, 74), (8, 77), (6, 80), (10, 80),
    (16, 81), (22, 88), (22, 97), (10, 99), (1, 104), (-7, 106), (-8, 115),
    (-6, 120), (0, 118), (5, 119), (12, 109), (18, 106), (22, 108), (22, 114),
    (30, 122), (35, 129), (38, 127), (39, 126), (43, 132), (46, 143),
    (50, 143), (52, 141), (56, 136), (59, 143), (62, 150), (60, 163),
    (64, 177), (66, 175), (68, 180), (72, 140), (75, 97), (73, 70),
    (68, 55), (55, 55), (50, 53), (44, 50), (42, 44), (42, 30),
    None,  # break
    # Australia
    (-12, 130), (-12, 136), (-15, 141), (-17, 146), (-24, 152), (-28, 154),
    (-33, 152), (-38, 145), (-39, 146), (-37, 150), (-34, 151), (-29, 153),
    (-38, 148), (-39, 147), (-43, 147), (-44, 146), (-38, 140),
    (-35, 137), (-35, 135), (-32, 133), (-32, 127), (-22, 114),
    (-14, 127), (-12, 130),
]

# Country label positions (lat, lon, name) — shown at zoom >= 1.5
_COUNTRY_LABELS = [
    (39, -98, "USA"), (56, -96, "CANADA"), (23, -102, "MEXICO"), (-14, -51, "BRAZIL"),
    (-35, -65, "ARGENTINA"), (4, -72, "COLOMBIA"), (-10, -76, "PERU"), (46, 2, "FRANCE"),
    (51, 10, "GERMANY"), (42, 12, "ITALY"), (40, -4, "SPAIN"), (55, -3, "UK"),
    (52, 20, "POLAND"), (50, 14, "CZECH"), (47, 8, "SWISS"), (60, 25, "FINLAND"),
    (62, 15, "SWEDEN"), (62, 10, "NORWAY"), (56, 10, "DENMARK"), (52, 5, "NL"),
    (50, 4, "BELGIUM"), (47, 19, "HUNGARY"), (44, 21, "SERBIA"), (42, 24, "BULGARIA"),
    (39, 22, "GREECE"), (38, 35, "TURKEY"), (32, 54, "IRAN"), (33, 44, "IRAQ"),
    (24, 45, "SAUDI"), (25, 55, "UAE"), (30, 70, "PAKISTAN"), (22, 79, "INDIA"),
    (35, 105, "CHINA"), (37, 128, "S.KOREA"), (36, 138, "JAPAN"), (15, 101, "THAILAND"),
    (2, 112, "MALAYSIA"), (-2, 118, "INDONESIA"), (-25, 135, "AUSTRALIA"), (-42, 174, "NZ"),
    (61, 100, "RUSSIA"), (48, 68, "KAZAKH"), (41, 65, "UZBEK"), (32, 35, "ISRAEL"),
    (30, 31, "EGYPT"), (7, -2, "GHANA"), (10, 8, "NIGERIA"), (-1, 37, "KENYA"),
    (-14, 34, "MALAWI"), (-26, 28, "S.AFRICA"), (34, 9, "TUNISIA"), (34, -2, "MOROCCO"),
    (14, 108, "VIETNAM"), (13, 105, "CAMBODIA"), (16, 96, "MYANMAR"), (1, 104, "SINGAPORE"),
    (14, 121, "PHILIPPINES"), (24, 121, "TAIWAN"), (47, 29, "MOLDOVA"), (46, 25, "ROMANIA"),
]

# Major cities (lat, lon, name, population_tier) — tier 1 shown at zoom >=3, tier 2 at >=6
_MAJOR_CITIES = [
    # Tier 1 — world capitals / mega cities (zoom >= 3)
    (40.71, -74.01, "New York", 1), (34.05, -118.24, "Los Angeles", 1),
    (41.88, -87.63, "Chicago", 1), (51.51, -0.13, "London", 1),
    (48.86, 2.35, "Paris", 1), (52.52, 13.41, "Berlin", 1),
    (55.76, 37.62, "Moscow", 1), (35.68, 139.69, "Tokyo", 1),
    (39.91, 116.39, "Beijing", 1), (31.23, 121.47, "Shanghai", 1),
    (22.32, 114.17, "Hong Kong", 1), (1.35, 103.82, "Singapore", 1),
    (28.61, 77.21, "New Delhi", 1), (19.08, 72.88, "Mumbai", 1),
    (-23.55, -46.63, "Sao Paulo", 1), (19.43, -99.13, "Mexico City", 1),
    (-33.87, 151.21, "Sydney", 1), (25.20, 55.27, "Dubai", 1),
    (30.04, 31.24, "Cairo", 1), (-1.29, 36.82, "Nairobi", 1),
    (37.57, 127.00, "Seoul", 1), (13.76, 100.50, "Bangkok", 1),
    (45.46, 9.19, "Milan", 1), (59.33, 18.07, "Stockholm", 1),
    (38.72, -9.14, "Lisbon", 1), (41.01, 29.00, "Istanbul", 1),
    # Tier 2 — secondary cities (zoom >= 6)
    (47.61, -122.33, "Seattle", 2), (37.77, -122.42, "San Francisco", 2),
    (29.76, -95.37, "Houston", 2), (33.75, -84.39, "Atlanta", 2),
    (25.76, -80.19, "Miami", 2), (42.36, -71.06, "Boston", 2),
    (39.95, -75.17, "Philadelphia", 2), (38.91, -77.04, "Washington DC", 2),
    (43.65, -79.38, "Toronto", 2), (45.50, -73.57, "Montreal", 2),
    (49.28, -123.12, "Vancouver", 2), (53.55, 9.99, "Hamburg", 2),
    (48.14, 11.58, "Munich", 2), (50.94, 6.96, "Cologne", 2),
    (43.30, -1.98, "Bilbao", 2), (41.39, 2.17, "Barcelona", 2),
    (40.42, -3.70, "Madrid", 2), (53.35, -6.26, "Dublin", 2),
    (47.50, 19.04, "Budapest", 2), (50.08, 14.44, "Prague", 2),
    (48.21, 16.37, "Vienna", 2), (46.95, 7.45, "Bern", 2),
    (60.17, 24.94, "Helsinki", 2), (59.91, 10.75, "Oslo", 2),
    (55.68, 12.57, "Copenhagen", 2), (52.37, 4.90, "Amsterdam", 2),
    (50.85, 4.35, "Brussels", 2), (44.43, 26.10, "Bucharest", 2),
    (42.70, 23.32, "Sofia", 2), (37.97, 23.73, "Athens", 2),
    (39.92, 32.85, "Ankara", 2), (35.69, 51.39, "Tehran", 2),
    (24.69, 46.72, "Riyadh", 2), (31.95, 35.93, "Amman", 2),
    (33.89, 35.50, "Beirut", 2), (33.31, 44.37, "Baghdad", 2),
    (34.53, 69.17, "Kabul", 2), (23.81, 90.41, "Dhaka", 2),
    (27.72, 85.32, "Kathmandu", 2), (6.93, 79.84, "Colombo", 2),
    (22.57, 88.36, "Kolkata", 2), (12.97, 77.59, "Bangalore", 2),
    (23.13, 113.26, "Guangzhou", 2), (22.54, 114.06, "Shenzhen", 2),
    (30.57, 104.07, "Chengdu", 2), (34.26, 108.94, "Xi'an", 2),
    (14.60, 120.98, "Manila", 2), (21.03, 105.85, "Hanoi", 2),
    (10.82, 106.63, "Ho Chi Minh", 2), (3.14, 101.69, "Kuala Lumpur", 2),
    (-6.21, 106.85, "Jakarta", 2), (-37.81, 144.96, "Melbourne", 2),
    (-36.85, 174.76, "Auckland", 2), (-33.45, -70.67, "Santiago", 2),
    (-34.61, -58.38, "Buenos Aires", 2), (-12.05, -77.04, "Lima", 2),
    (4.71, -74.07, "Bogota", 2), (-22.91, -43.17, "Rio de Janeiro", 2),
    (-15.79, -47.88, "Brasilia", 2), (6.52, 3.38, "Lagos", 2),
    (9.06, 7.49, "Abuja", 2), (-33.93, 18.42, "Cape Town", 2),
    (36.75, 3.06, "Algiers", 2), (33.97, -6.85, "Rabat", 2),
]


class GNATracerGUI:
    """Full-detail popup window for GNA Tracer — shows 100% of all data."""

    def __init__(self, get_state_fn, get_full_data_fn, stop_event: threading.Event):
        self._get_state = get_state_fn
        self._get_full_data = get_full_data_fn
        self._stop = stop_event
        self._root = None
        self._map_canvas = None
        self._map_dots = {}  # ip -> canvas item id
        self._map_w = 900
        self._map_h = 460
        self._tooltip = None
        self._tooltip_id = None
        self._selected_ip = None
        # Zoom / pan state for atlas map
        self._map_zoom = 1.0
        self._map_center_lat = 20.0   # initial center latitude
        self._map_center_lon = 0.0    # initial center longitude
        self._map_drag_start = None   # (x, y) when drag starts
        self._map_min_zoom = 1.0
        self._map_max_zoom = 20.0
        self._ip_actions_text = None
        self._update_job = None
        # Connection blocking — dict: ip -> {service, domain, process, pid, time_blocked, ...}
        self._blocked_ips: dict = {}
        self._conn_paused = False
        self._conn_buttons: list = []  # track embedded button widgets
        self._fw_rule_prefix = 'GNA_Tracer_Block_'
        # Auto-save series
        self._session_start = time.time()
        self._save_counter = 0
        self._autosave_job = None
        self._autosave_interval_ms = 10 * 60 * 1000  # 10 minutes

    def _toggle_conn_pause(self):
        self._conn_paused = not self._conn_paused
        if hasattr(self, '_pause_btn'):
            self._pause_btn.config(
                text='▶ Resume Updates' if self._conn_paused else '⏸ Pause Updates',
                bg='#4caf50' if self._conn_paused else '#333344')

    def _toggle_block_ip(self, ip, conn_info=None):
        if ip in self._blocked_ips:
            self._unblock_ip(ip)
        else:
            self._block_ip(ip, conn_info)

    @staticmethod
    def _is_admin():
        """Check if the current process has admin/elevated privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_firewall_cmd(self, args):
        """Run a netsh firewall command and return (success, stderr_text).
        If already admin, runs directly. Otherwise runs normally (may fail)."""
        try:
            result = subprocess.run(
                args, capture_output=True, timeout=10,
                creationflags=0x08000000, text=True)
            if result.returncode == 0:
                return True, ''
            return False, result.stderr.strip() or result.stdout.strip()
        except Exception as exc:
            return False, str(exc)

    def _run_elevated_batch(self, commands):
        """Write commands to a temp .bat, run it elevated via UAC prompt, wait for it.
        Returns True if UAC was accepted and commands executed."""
        import ctypes
        import ctypes.wintypes
        import tempfile

        # Write batch file
        bat_path = os.path.join(tempfile.gettempdir(), 'gna_tracer_fw.bat')
        with open(bat_path, 'w') as f:
            f.write('@echo off\n')
            for cmd in commands:
                f.write(cmd + '\n')

        # SHELLEXECUTEINFOW structure for ShellExecuteExW
        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", ctypes.wintypes.HANDLE),
                ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p),
                ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p),
                ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p),
                ("hkeyClass", ctypes.wintypes.HKEY),
                ("dwHotKey", ctypes.wintypes.DWORD),
                ("hIcon", ctypes.wintypes.HANDLE),
                ("hProcess", ctypes.wintypes.HANDLE),
            ]

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SW_HIDE = 0

        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = bat_path
        sei.lpParameters = ""
        sei.lpDirectory = None
        sei.nShow = SW_HIDE
        sei.hProcess = None

        try:
            if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
                return False  # user cancelled UAC or error
            if sei.hProcess:
                # Wait up to 30 seconds for the batch to finish
                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 30000)
                # Get exit code
                exit_code = ctypes.wintypes.DWORD()
                ctypes.windll.kernel32.GetExitCodeProcess(
                    sei.hProcess, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
            return True  # UAC accepted, commands ran
        except Exception as exc:
            _mb_logger.warning("Elevated execution failed: %s", exc)
            return False
        finally:
            try:
                os.remove(bat_path)
            except Exception:
                pass

    def _verify_rule_exists(self, rule_name):
        """Check if a firewall rule exists by name."""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                 f'name={rule_name}'],
                capture_output=True, timeout=10,
                creationflags=0x08000000, text=True)
            return result.returncode == 0 and 'Rule Name' in result.stdout
        except Exception:
            return False

    def _block_ip(self, ip, conn_info=None):
        if not ip or ip in self._blocked_ips:
            return
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_")}'
        if self._is_admin():
            # Already admin — run directly
            ok_out, _ = self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=out', f'remoteip={ip}',
                 'action=block', 'protocol=any'])
            ok_in, _ = self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}_in', 'dir=in', f'remoteip={ip}',
                 'action=block', 'protocol=any'])
            success = ok_out and ok_in
        else:
            # Not admin — elevate via UAC prompt
            commands = [
                f'netsh advfirewall firewall add rule name="{rule_name}" dir=out remoteip={ip} action=block protocol=any',
                f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in remoteip={ip} action=block protocol=any',
            ]
            uac_ok = self._run_elevated_batch(commands)
            if not uac_ok:
                messagebox.showwarning(
                    "Block Cancelled",
                    f"UAC prompt was cancelled or failed for {ip}.\n"
                    "You must click Yes on the Windows permission dialog.")
                return
            # Verify the rules were actually created
            success = self._verify_rule_exists(rule_name)

        if success:
            meta = {
                'ip': ip,
                'time_blocked': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'service': (conn_info or {}).get('service', '?'),
                'domain': (conn_info or {}).get('domain', '?'),
                'process': (conn_info or {}).get('process', '?'),
                'pid': (conn_info or {}).get('pid', '?'),
                'country': (conn_info or {}).get('country', '?'),
                'city': (conn_info or {}).get('city', '?'),
                'org': (conn_info or {}).get('org', '?'),
                'isp': (conn_info or {}).get('isp', '?'),
                'remote_port': (conn_info or {}).get('remote_port', '?'),
                'category': (conn_info or {}).get('category', '?'),
            }
            self._blocked_ips[ip] = meta
            _mb_logger.info('GNA Tracer: Blocked IP %s (both directions)', ip)
        else:
            messagebox.showerror(
                "Block Failed",
                f"Failed to create firewall rules for {ip}.\n\n"
                "The rules could not be verified after execution.")
            _mb_logger.warning('GNA Tracer: Failed to block %s', ip)
        self._update_blocked_label()

    def _unblock_ip(self, ip):
        if not ip or ip not in self._blocked_ips:
            return
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_")}'
        if self._is_admin():
            self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}'])
            self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}_in'])
        else:
            commands = [
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                f'netsh advfirewall firewall delete rule name="{rule_name}_in"',
            ]
            self._run_elevated_batch(commands)
        self._blocked_ips.pop(ip, None)
        _mb_logger.info('GNA Tracer: Unblocked IP %s', ip)
        self._update_blocked_label()

    def _unblock_all(self):
        for ip in list(self._blocked_ips):
            self._unblock_ip(ip)

    def _update_blocked_label(self):
        if hasattr(self, '_blocked_lbl'):
            n = len(self._blocked_ips)
            if n:
                ip_list = ', '.join(sorted(self._blocked_ips.keys()))
                self._blocked_lbl.config(
                    text=f'🚫 Blocked ({n}): {ip_list}',
                    fg='#e94560')
            else:
                self._blocked_lbl.config(
                    text='No IPs blocked',
                    fg='#666666')

    # ─── Scroll-aware refresh helpers ───
    def _is_at_bottom(self, widget):
        """Return True if the scrollbar is near the bottom (auto-scroll zone)."""
        return widget.yview()[1] >= 0.95

    def _begin_refresh(self, widget):
        """Save scroll state before a full rewrite. Returns (was_at_bottom, scroll_frac)."""
        at_bottom = self._is_at_bottom(widget)
        frac = widget.yview()[0]
        return at_bottom, frac

    def _end_refresh(self, widget, at_bottom, frac):
        """Restore scroll: auto-scroll to end if was at bottom, else restore position."""
        if at_bottom:
            widget.see("end")
        else:
            widget.yview_moveto(frac)

    # ─── Search infrastructure ───
    def _make_search_bar(self, parent, search_var):
        """Create a search toolbar frame with entry + clear button. Returns the frame."""
        bar = tk.Frame(parent, bg="#1a1a2e", height=28)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        tk.Label(bar, text="🔍", bg="#1a1a2e", fg="#666666",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 2))
        entry = tk.Entry(bar, textvariable=search_var, bg="#222233", fg="#00d4ff",
                         insertbackground="#00d4ff", font=("Consolas", 9),
                         bd=0, highlightthickness=1, highlightcolor="#333366")
        entry.pack(side="left", fill="x", expand=True, padx=4, pady=3)
        clear_btn = tk.Button(bar, text="✕", bg="#1a1a2e", fg="#666666",
                              font=("Consolas", 9), bd=0, padx=4,
                              command=lambda: search_var.set(""))
        clear_btn.pack(side="right", padx=4)
        return bar

    def _highlight_search(self, widget, query):
        """Highlight all matches of query in a text widget.
        Prefix with 'r:' or '/' for regex search (e.g., 'r:\\d+\\.\\d+' or '/\\d+\\.\\d+')."""
        widget.tag_remove("search_match", "1.0", "end")
        if not query or len(query) < 2:
            return 0
        # Check for regex mode
        is_regex = False
        regex_query = query
        if query.startswith('r:') and len(query) > 2:
            is_regex = True
            regex_query = query[2:]
        elif query.startswith('/') and len(query) > 1:
            is_regex = True
            regex_query = query[1:]
        count = 0
        if is_regex:
            try:
                pattern = re.compile(regex_query, re.IGNORECASE)
                content = widget.get("1.0", "end")
                for match in pattern.finditer(content):
                    start_idx = f"1.0+{match.start()}c"
                    end_idx = f"1.0+{match.end()}c"
                    widget.tag_add("search_match", start_idx, end_idx)
                    count += 1
                    if count > 5000:
                        break
            except re.error:
                pass  # Invalid regex — silently ignore
        else:
            start = "1.0"
            query_lower = query.lower()
            while True:
                pos = widget.search(query_lower, start, stopindex="end", nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(query)}c"
                widget.tag_add("search_match", pos, end)
                start = end
                count += 1
        return count

    def _latlon_to_xy(self, lat, lon):
        """Convert lat/lon to canvas x/y using current zoom and center."""
        z = self._map_zoom
        cx, cy = self._map_center_lon, self._map_center_lat
        w, h = self._map_w, self._map_h
        x = w / 2 + (lon - cx) * (w / 360) * z
        y = h / 2 - (lat - cy) * (h / 180) * z
        return x, y

    def _xy_to_latlon(self, x, y):
        """Convert canvas x/y back to lat/lon."""
        z = self._map_zoom
        cx, cy = self._map_center_lon, self._map_center_lat
        w, h = self._map_w, self._map_h
        lon = cx + (x - w / 2) / (w / 360 * z)
        lat = cy - (y - h / 2) / (h / 180 * z)
        return lat, lon

    def _draw_map_full(self):
        """Redraw the entire map: grid, coastlines, labels."""
        if not self._map_canvas:
            return
        self._map_canvas.delete("grid", "coastline", "label", "city")
        self._draw_grid()
        self._draw_coastline()
        self._draw_labels()
        self._zoom_lbl.config(text=f"Zoom: {self._map_zoom:.1f}x")

    def _draw_grid(self):
        """Draw lat/lon grid lines that adapt to zoom level."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Choose grid spacing based on zoom
        if z >= 10:
            spacing = 5
        elif z >= 5:
            spacing = 10
        elif z >= 2:
            spacing = 15
        else:
            spacing = 30
        # Latitude lines
        for lat in range(-90, 91, spacing):
            _, y = self._latlon_to_xy(lat, 0)
            if 0 <= y <= h:
                self._map_canvas.create_line(0, y, w, y, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1.5:
                    self._map_canvas.create_text(
                        4, y - 2, text=f"{lat}°", fill="#334444",
                        font=("Consolas", 7), anchor="sw", tags="grid")
        # Longitude lines
        for lon in range(-180, 181, spacing):
            x, _ = self._latlon_to_xy(0, lon)
            if 0 <= x <= w:
                self._map_canvas.create_line(x, 0, x, h, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1.5:
                    self._map_canvas.create_text(
                        x + 2, h - 2, text=f"{lon}°", fill="#334444",
                        font=("Consolas", 7), anchor="se", tags="grid")
        # Equator + prime meridian highlighted
        _, eq_y = self._latlon_to_xy(0, 0)
        pm_x, _ = self._latlon_to_xy(0, 0)
        if 0 <= eq_y <= h:
            self._map_canvas.create_line(0, eq_y, w, eq_y, fill="#2a3a3a",
                                         width=1, tags="grid")
        if 0 <= pm_x <= w:
            self._map_canvas.create_line(pm_x, 0, pm_x, h, fill="#2a3a3a",
                                         width=1, tags="grid")

    def _draw_coastline(self):
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        line_width = max(1, min(3, z * 0.8))
        fill_color = "#2a5a3a" if z >= 2 else "#2a4a3a"
        segment = []
        for pt in _WORLD_COASTLINE:
            if pt is None:
                if len(segment) >= 2:
                    self._map_canvas.create_line(
                        *[c for xy in segment for c in xy],
                        fill=fill_color, width=line_width,
                        tags="coastline", smooth=True)
                segment = []
            else:
                px, py = self._latlon_to_xy(pt[0], pt[1])
                # Skip points far outside viewport for performance
                if -200 <= px <= w + 200 and -200 <= py <= h + 200:
                    segment.append((px, py))
                else:
                    if len(segment) >= 2:
                        self._map_canvas.create_line(
                            *[c for xy in segment for c in xy],
                            fill=fill_color, width=line_width,
                            tags="coastline", smooth=True)
                    segment = []
        if len(segment) >= 2:
            self._map_canvas.create_line(
                *[c for xy in segment for c in xy],
                fill=fill_color, width=line_width,
                tags="coastline", smooth=True)

    def _draw_labels(self):
        """Draw country and city labels based on zoom level."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Country labels at zoom >= 1.5
        if z >= 1.5:
            font_size = max(7, min(11, int(7 + z)))
            for lat, lon, name in _COUNTRY_LABELS:
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_text(
                        x, y, text=name, fill="#3a5a5a",
                        font=("Consolas", font_size, "bold"),
                        tags="label")
        # Tier 1 cities at zoom >= 3
        if z >= 3:
            for lat, lon, name, tier in _MAJOR_CITIES:
                if tier > 1 and z < 6:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    r = 2
                    self._map_canvas.create_oval(
                        x - r, y - r, x + r, y + r,
                        fill="#556666", outline="#778888", tags="city")
                    self._map_canvas.create_text(
                        x + 5, y, text=name, fill="#667777",
                        font=("Consolas", max(7, min(9, int(6 + z * 0.5)))),
                        anchor="w", tags="city")

    # --- Map interaction handlers ---
    def _map_zoom_by(self, factor, event=None):
        """Zoom the map by a factor, optionally centered on mouse position."""
        old_zoom = self._map_zoom
        self._map_zoom = max(self._map_min_zoom,
                             min(self._map_max_zoom, self._map_zoom * factor))
        if event and old_zoom != self._map_zoom:
            # Zoom toward the mouse cursor position
            lat, lon = self._xy_to_latlon(event.x, event.y)
            # Shift center partially toward the cursor
            t = 0.3
            self._map_center_lat += (lat - self._map_center_lat) * t
            self._map_center_lon += (lon - self._map_center_lon) * t
        self._draw_map_full()
        self._redraw_dots_only()

    def _map_reset_view(self):
        """Reset map to default view."""
        self._map_zoom = 1.0
        self._map_center_lat = 20.0
        self._map_center_lon = 0.0
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_scroll(self, event):
        """Mouse wheel zoom."""
        if event.delta > 0:
            self._map_zoom_by(1.3, event)
        else:
            self._map_zoom_by(1 / 1.3, event)

    def _on_map_drag_start(self, event):
        self._map_drag_start = (event.x, event.y)

    def _on_map_drag(self, event):
        if not self._map_drag_start:
            return
        dx = event.x - self._map_drag_start[0]
        dy = event.y - self._map_drag_start[1]
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        self._map_center_lon -= dx / (w / 360 * z)
        self._map_center_lat += dy / (h / 180 * z)
        # Clamp
        self._map_center_lat = max(-85, min(85, self._map_center_lat))
        self._map_center_lon = max(-180, min(180, self._map_center_lon))
        self._map_drag_start = (event.x, event.y)
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_drag_end(self, event):
        self._map_drag_start = None

    def _on_map_mouse_move(self, event):
        """Show lat/lon coordinates under cursor."""
        lat, lon = self._xy_to_latlon(event.x, event.y)
        if hasattr(self, '_coords_lbl'):
            self._coords_lbl.config(text=f"Lat: {lat:.2f}° Lon: {lon:.2f}°")

    def _redraw_dots_only(self):
        """Quick redraw of just the connection dots without full data refresh."""
        if not self._map_canvas:
            return
        self._map_canvas.delete("dot", "line_to_dot")
        if hasattr(self, '_last_map_data') and self._last_map_data:
            self._plot_map_dots(self._last_map_data)

    def _show_tooltip(self, event, text):
        self._hide_tooltip()
        x, y = event.x_root + 15, event.y_root + 10
        self._tooltip = tk.Toplevel(self._root)
        self._tooltip.wm_overrideredirect(True)
        self._tooltip.wm_geometry(f"+{x}+{y}")
        self._tooltip.attributes("-topmost", True)
        frame = tk.Frame(self._tooltip, bg="#1a1a2e", bd=1, relief="solid")
        frame.pack()
        lbl = tk.Label(frame, text=text, bg="#1a1a2e", fg="#00d4ff",
                       font=("Consolas", 9), justify="left", padx=6, pady=4)
        lbl.pack()

    def _hide_tooltip(self):
        if self._tooltip:
            self._tooltip.destroy()
            self._tooltip = None

    def _on_map_dot_enter(self, event, ip, info):
        loc_conf = info.get('loc_confidence', 0)
        loc_grade = info.get('loc_grade', '')
        loc_line = f"\n📍 Location: {loc_conf}% {loc_grade}" if loc_grade else ""
        proof_lines = ""
        for p in info.get('loc_proof', [])[:3]:
            proof_lines += f"\n  {p}"
        proxy_line = ""
        pt = info.get('proxy_type', '')
        if pt:
            proxy_line = f"\n🔀 Proxy: {pt}"
            pd = info.get('proxy_detail', '')
            if pd:
                proxy_line += f"\n  {pd}"
        domain_str = info.get('domain', '?')
        via = info.get('via', '')
        domain_line = f"Domain: {domain_str}"
        if via:
            domain_line += f" (via {via})"
        all_doms = info.get('all_domains', [])
        all_doms_line = ""
        if all_doms and len(all_doms) > 1:
            all_doms_line = f"\nAll Domains: {', '.join(all_doms[:6])}"
            if len(all_doms) > 6:
                all_doms_line += f" (+{len(all_doms)-6})"
        wtag = info.get('website_tag', '')
        wtag_line = f"🏷️ {wtag}\n" if wtag else ""
        text = (f"{wtag_line}"
                f"IP: {ip}\n"
                f"Service: {info.get('service', '?')}\n"
                f"{domain_line}\n"
                f"Process: {info.get('process', '?')}\n"
                f"City: {info.get('city', '?')}, {info.get('country', '?')}\n"
                f"Org: {info.get('org', '?')}\n"
                f"Lat: {info.get('lat', 0):.4f}, Lon: {info.get('lon', 0):.4f}"
                f"{all_doms_line}{loc_line}{proof_lines}{proxy_line}\n"
                f"[Click for full action log]")
        self._show_tooltip(event, text)

    def _on_map_dot_leave(self, event):
        self._hide_tooltip()

    def _on_map_dot_click(self, ip):
        self._selected_ip = ip
        if self._ip_actions_text:
            self._ip_actions_text.config(state="normal")
            self._ip_actions_text.delete("1.0", "end")
            data = self._get_full_data()
            lines = [f"=== FULL ACTION LOG FOR IP: {ip} ===\n"]
            # Find all connections for this IP
            for conn in data.get('connections', []):
                if conn.get('remote_ip') == ip:
                    wtag = conn.get('website_tag', '')
                    if wtag:
                        lines.append(f"🏷️ WEBSITE: {wtag}")
                    lines.append(f"Connection: {conn.get('process', '?')} (PID {conn.get('pid', '?')})")
                    exe_p = conn.get('exe_path', '')
                    if exe_p:
                        lines.append(f"  Exe Path: {exe_p}")
                    parent_n = conn.get('parent_name', '')
                    if parent_n:
                        lines.append(f"  Parent: {parent_n}")
                    lines.append(f"  Remote: {ip}:{conn.get('remote_port', '?')}")
                    lines.append(f"  Local Port: {conn.get('local_port', '?')}")
                    lines.append(f"  Protocol: {conn.get('protocol', '?')}")
                    lines.append(f"  Status: {conn.get('status', '?')}")
                    lines.append(f"  Service: {conn.get('service', '?')} ({conn.get('category', '?')})")
                    via = conn.get('via', '')
                    domain_info = conn.get('domain', '?')
                    if via:
                        domain_info += f" (via {via})"
                    lines.append(f"  Domain: {domain_info}")
                    all_doms = conn.get('all_domains', [])
                    if all_doms:
                        lines.append(f"  All Domains: {', '.join(all_doms[:10])}")
                        if len(all_doms) > 10:
                            lines.append(f"    (+{len(all_doms)-10} more)")
                    lines.append(f"  Country: {conn.get('country', '?')} ({conn.get('country_code', '?')})")
                    lines.append(f"  City: {conn.get('city', '?')}, Region: {conn.get('region', '?')}")
                    lines.append(f"  Org: {conn.get('org', '?')}, ISP: {conn.get('isp', '?')}")
                    lines.append(f"  Coords: ({conn.get('lat', 0):.4f}, {conn.get('lon', 0):.4f})")
                    lines.append(f"  First Seen: {_fmt_ts(conn.get('first_seen', 0))}")
                    lines.append(f"  Last Seen: {_fmt_ts(conn.get('last_seen', 0))}")
                    lines.append("")
            # Find all deductions mentioning this IP
            lines.append(f"\n=== DEDUCTIONS INVOLVING {ip} ===")
            for d in data.get('deductions', []):
                if ip in (d.get('message', '') + ' '.join(d.get('evidence', []))):
                    lines.append(f"[{d.get('time', '?')}] [{d.get('severity', '?')}] {d.get('category', '?')}")
                    lines.append(f"  Process: {d.get('process', '?')} (PID {d.get('pid', '?')})")
                    lines.append(f"  Message: {d.get('message', '?')}")
                    for ev in d.get('evidence', []):
                        lines.append(f"    -> {ev}")
                    lines.append(f"  Score: {d.get('score', 0)}")
                    lines.append("")
            # Find all process actions involving this IP
            lines.append(f"\n=== PROCESS ACTIONS INVOLVING {ip} ===")
            for act in data.get('all_actions', []):
                if ip in str(act):
                    lines.append(f"  {act}")
            if len(lines) <= 4:
                lines.append("  (No detailed actions recorded yet for this IP)")
            self._ip_actions_text.insert("1.0", "\n".join(lines))
            self._ip_actions_text.config(state="disabled")

    def run(self):
        try:
            self._run_gui()
        except Exception as exc:
            import traceback
            print(f"GUI RUN CRASH: {exc}", flush=True)
            traceback.print_exc()

    def _run_gui(self):
        self._root = tk.Tk()
        self._root.title("GNA Tracer — Full Network Intelligence")
        self._root.geometry("1280x820")
        self._root.configure(bg="#0a0a0f")
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0a0a0f", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1a1a2e", foreground="#c0c0c0",
                        padding=[12, 6], font=("Consolas", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", "#e94560")],
                  foreground=[("selected", "#ffffff")])
        style.configure("TFrame", background="#0a0a0f")
        style.configure("Treeview", background="#12121a", foreground="#c0c0c0",
                        fieldbackground="#12121a", font=("Consolas", 9),
                        rowheight=20)
        style.configure("Treeview.Heading", background="#1a1a2e", foreground="#e94560",
                        font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", "#0f3460")])

        # Header
        hdr = tk.Frame(self._root, bg="#1a1a2e", height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="♟ GNA TRACER — FULL NETWORK INTELLIGENCE",
                 bg="#1a1a2e", fg="#e94560", font=("Consolas", 14, "bold")).pack(side="left", padx=16)
        self._status_lbl = tk.Label(hdr, text="Initializing...", bg="#1a1a2e", fg="#00d4ff",
                                    font=("Consolas", 10))
        self._status_lbl.pack(side="right", padx=16)

        # Notebook
        nb = ttk.Notebook(self._root)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        # Search variables (one per tab)
        self._search_overview = tk.StringVar()
        self._search_conn = tk.StringVar()
        self._search_ded = tk.StringVar()
        self._search_proc = tk.StringVar()
        self._search_dev = tk.StringVar()
        self._search_actions = tk.StringVar()
        self._search_terminal = tk.StringVar()
        self._search_suspicious = tk.StringVar()
        self._search_live = tk.StringVar()

        # === TAB 1: Overview ===
        self._overview_frame = ttk.Frame(nb)
        nb.add(self._overview_frame, text=" 📊 Overview ")
        self._make_search_bar(self._overview_frame, self._search_overview)
        self._overview_text = scrolledtext.ScrolledText(
            self._overview_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 10), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._overview_text.pack(fill="both", expand=True)

        # === TAB 2: Live Connections (only active/established) ===
        self._live_frame = ttk.Frame(nb)
        nb.add(self._live_frame, text=" 🟢 Live Connections ")
        self._make_search_bar(self._live_frame, self._search_live)
        self._live_text = scrolledtext.ScrolledText(
            self._live_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._live_text.pack(fill="both", expand=True)
        self._live_buttons: list = []
        self._live_expanded: dict[str, bool] = {}  # conn_key → expanded?

        # === TAB 3: All Connections (each individually) ===
        self._conn_frame = ttk.Frame(nb)
        nb.add(self._conn_frame, text=" 🔗 All Connections ")
        # Toolbar
        conn_toolbar = tk.Frame(self._conn_frame, bg="#1a1a2e", height=32)
        conn_toolbar.pack(fill="x", side="top")
        conn_toolbar.pack_propagate(False)
        self._pause_btn = tk.Button(
            conn_toolbar, text="⏸ Pause Updates", bg="#333344", fg="#00d4ff",
            font=("Consolas", 9, "bold"), bd=0, padx=12, pady=2,
            activebackground="#444466", activeforeground="#00d4ff",
            command=self._toggle_conn_pause)
        self._pause_btn.pack(side="left", padx=8, pady=4)
        self._blocked_lbl = tk.Label(
            conn_toolbar, text="No IPs blocked", bg="#1a1a2e", fg="#666666",
            font=("Consolas", 9))
        self._blocked_lbl.pack(side="left", padx=12)
        unblock_all_btn = tk.Button(
            conn_toolbar, text="🔓 Unblock All", bg="#333344", fg="#f5a623",
            font=("Consolas", 9), bd=0, padx=8, pady=2,
            activebackground="#444466", activeforeground="#f5a623",
            command=self._unblock_all)
        unblock_all_btn.pack(side="right", padx=8, pady=4)
        tk.Label(conn_toolbar, text="Click [Block] next to any connection to add a firewall rule",
                 bg="#1a1a2e", fg="#555555", font=("Consolas", 8)).pack(side="right", padx=8)
        # Connection search + list
        self._make_search_bar(self._conn_frame, self._search_conn)
        self._conn_text = scrolledtext.ScrolledText(
            self._conn_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._conn_text.pack(fill="both", expand=True)

        # === TAB 3: Deductions (full evidence) ===
        self._ded_frame = ttk.Frame(nb)
        nb.add(self._ded_frame, text=" 🚨 Deductions ")
        self._make_search_bar(self._ded_frame, self._search_ded)
        self._ded_text = scrolledtext.ScrolledText(
            self._ded_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ded_text.pack(fill="both", expand=True)

        # === TAB 4: Processes ===
        self._proc_frame = ttk.Frame(nb)
        nb.add(self._proc_frame, text=" 📈 Processes ")
        self._make_search_bar(self._proc_frame, self._search_proc)
        self._proc_text = scrolledtext.ScrolledText(
            self._proc_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._proc_text.pack(fill="both", expand=True)

        # === TAB 5: Devices ===
        self._dev_frame = ttk.Frame(nb)
        nb.add(self._dev_frame, text=" 📱 Devices ")
        self._make_search_bar(self._dev_frame, self._search_dev)
        self._dev_text = scrolledtext.ScrolledText(
            self._dev_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._dev_text.pack(fill="both", expand=True)

        # === TAB 6: IP Map (Atlas with zoom/pan) ===
        self._map_frame = ttk.Frame(nb)
        nb.add(self._map_frame, text=" 🗺️ IP Map ")
        # Controls bar
        map_ctrl = tk.Frame(self._map_frame, bg="#1a1a2e", height=32)
        map_ctrl.pack(fill="x")
        map_ctrl.pack_propagate(False)
        tk.Button(map_ctrl, text="➕ Zoom In", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=lambda: self._map_zoom_by(1.5)).pack(side="left", padx=4, pady=2)
        tk.Button(map_ctrl, text="➖ Zoom Out", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=lambda: self._map_zoom_by(1/1.5)).pack(side="left", padx=4, pady=2)
        tk.Button(map_ctrl, text="🏠 Reset", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=self._map_reset_view).pack(side="left", padx=4, pady=2)
        self._zoom_lbl = tk.Label(map_ctrl, text="Zoom: 1.0x", bg="#1a1a2e",
                                  fg="#00d4ff", font=("Consolas", 9))
        self._zoom_lbl.pack(side="left", padx=12)
        self._coords_lbl = tk.Label(map_ctrl, text="", bg="#1a1a2e",
                                    fg="#888888", font=("Consolas", 9))
        self._coords_lbl.pack(side="right", padx=12)
        # Legend
        legend_f = tk.Frame(map_ctrl, bg="#1a1a2e")
        legend_f.pack(side="right", padx=8)
        for color, label in [("#44cc44", "Low"), ("#ffcc00", "Med"),
                              ("#ff8800", "High"), ("#ff0000", "Crit")]:
            tk.Canvas(legend_f, bg=color, width=10, height=10,
                      highlightthickness=0).pack(side="left", padx=1)
            tk.Label(legend_f, text=label, bg="#1a1a2e", fg="#888888",
                     font=("Consolas", 7)).pack(side="left", padx=(0, 6))
        # Map canvas
        map_top = tk.Frame(self._map_frame, bg="#0a0a0f")
        map_top.pack(fill="both", expand=True)
        self._map_canvas = tk.Canvas(map_top, bg="#0d1117", width=self._map_w,
                                     height=self._map_h, highlightthickness=0)
        self._map_canvas.pack(fill="both", expand=True, padx=4, pady=4)
        # Bind zoom (mouse wheel) and pan (click-drag)
        self._map_canvas.bind("<MouseWheel>", self._on_map_scroll)
        self._map_canvas.bind("<Button-4>", lambda e: self._map_zoom_by(1.3, e))
        self._map_canvas.bind("<Button-5>", lambda e: self._map_zoom_by(1/1.3, e))
        self._map_canvas.bind("<ButtonPress-3>", self._on_map_drag_start)
        self._map_canvas.bind("<B3-Motion>", self._on_map_drag)
        self._map_canvas.bind("<ButtonRelease-3>", self._on_map_drag_end)
        self._map_canvas.bind("<Motion>", self._on_map_mouse_move)
        self._draw_map_full()
        # Action log below map
        map_bottom = tk.Frame(self._map_frame, bg="#0a0a0f", height=220)
        map_bottom.pack(fill="both", expand=True)
        map_bottom.pack_propagate(False)
        tk.Label(map_bottom, text="IP ACTION LOG (click a dot · scroll to zoom · right-drag to pan)",
                 bg="#1a1a2e", fg="#e94560", font=("Consolas", 10, "bold")).pack(fill="x")
        self._ip_actions_text = scrolledtext.ScrolledText(
            map_bottom, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ip_actions_text.pack(fill="both", expand=True)

        # === TAB 7: Raw Actions Log ===
        self._actions_frame = ttk.Frame(nb)
        nb.add(self._actions_frame, text=" 📝 Actions Log ")
        self._make_search_bar(self._actions_frame, self._search_actions)
        self._actions_text = scrolledtext.ScrolledText(
            self._actions_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._actions_text.pack(fill="both", expand=True)

        # === TAB 8: Terminal (100% of all processed output) ===
        self._terminal_frame = ttk.Frame(nb)
        nb.add(self._terminal_frame, text=" 🖥️ Terminal ")
        self._make_search_bar(self._terminal_frame, self._search_terminal)
        self._terminal_text = scrolledtext.ScrolledText(
            self._terminal_frame, bg="#0a0a0f", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._terminal_text.pack(fill="both", expand=True)
        self._terminal_last_count = 0  # track how many lines we've rendered

        # === TAB 9: Suspicious Activity (ONLY out-of-norm behavior) ===
        self._suspicious_frame = ttk.Frame(nb)
        nb.add(self._suspicious_frame, text=" 🔴 Suspicious Activity ")
        self._make_search_bar(self._suspicious_frame, self._search_suspicious)
        self._suspicious_text = scrolledtext.ScrolledText(
            self._suspicious_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._suspicious_text.pack(fill="both", expand=True)

        # === TAB 10: Blocked IPs ===
        self._blocked_frame = ttk.Frame(nb)
        nb.add(self._blocked_frame, text=" 🛑 Blocked IPs ")
        self._blocked_text = scrolledtext.ScrolledText(
            self._blocked_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._blocked_text.pack(fill="both", expand=True)

        # === TAB 11: Process Tree ===
        self._ptree_frame = ttk.Frame(nb)
        nb.add(self._ptree_frame, text=" 🌳 Process Tree ")
        self._ptree_text = scrolledtext.ScrolledText(
            self._ptree_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._ptree_text.pack(fill="both", expand=True)

        # === TAB 12: Network Stats ===
        self._netstats_frame = ttk.Frame(nb)
        nb.add(self._netstats_frame, text=" 📊 Net Stats ")
        self._netstats_text = scrolledtext.ScrolledText(
            self._netstats_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._netstats_text.pack(fill="both", expand=True)

        # === TAB 13: Connection Timeline ===
        self._timeline_frame = ttk.Frame(nb)
        nb.add(self._timeline_frame, text=" ⏱️ Timeline ")
        self._timeline_text = scrolledtext.ScrolledText(
            self._timeline_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._timeline_text.pack(fill="both", expand=True)

        # === TAB 14: Config Editor ===
        self._config_frame = ttk.Frame(nb)
        nb.add(self._config_frame, text=" ⚙️ Config ")
        self._config_text = scrolledtext.ScrolledText(
            self._config_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._config_text.pack(fill="both", expand=True)

        # Alert flash tracking
        self._alert_flash_tabs: dict[str, int] = {}
        self._last_suspicious_count = 0

        # Watchlist sets (synced from monitor)
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()

        # Window geometry persistence
        self._geometry_file = os.path.join(os.path.expanduser("~"), ".gna_tracer_geometry.json")
        self._load_geometry()

        # Configure text tags for coloring
        for widget in [self._overview_text, self._live_text, self._conn_text,
                       self._ded_text, self._proc_text, self._dev_text,
                       self._actions_text, self._terminal_text,
                       self._suspicious_text, self._blocked_text,
                       self._ptree_text, self._netstats_text,
                       self._timeline_text, self._config_text]:
            widget.tag_configure("critical", foreground="#e94560", font=("Consolas", 10, "bold"))
            widget.tag_configure("warning", foreground="#f5a623")
            widget.tag_configure("info", foreground="#4caf50")
            widget.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
            widget.tag_configure("subheader", foreground="#e94560", font=("Consolas", 10, "bold"))
            widget.tag_configure("dim", foreground="#666666")
            widget.tag_configure("highlight", foreground="#ffffff")
            widget.tag_configure("default", foreground="#c0c0c0")
            widget.tag_configure("cyan", foreground="#00d4ff")
            widget.tag_configure("search_match", background="#f5a623", foreground="#000000",
                                 font=("Consolas", 10, "bold"))

        self._schedule_update()
        self._schedule_autosave()
        self._root.mainloop()

    def _schedule_autosave(self):
        """Periodic auto-save: writes a complete numbered log file every interval."""
        if self._stop.is_set():
            return
        try:
            self._save_tracer_data()
        except Exception as exc:
            _mb_logger.warning("Auto-save failed: %s", exc)
        self._autosave_job = self._root.after(self._autosave_interval_ms, self._schedule_autosave)

    def _schedule_update(self):
        if self._stop.is_set():
            return
        try:
            self._refresh_all()
        except Exception as exc:
            _mb_logger.debug("GUI refresh error: %s", exc)
        self._update_job = self._root.after(3000, self._schedule_update)

    def _refresh_all(self):
        data = self._get_full_data()
        self._refresh_status(data)
        self._refresh_overview(data)
        self._refresh_live(data)
        self._refresh_connections(data)
        self._refresh_deductions(data)
        self._refresh_processes(data)
        self._refresh_devices(data)
        self._refresh_map(data)
        self._refresh_actions(data)
        self._refresh_terminal(data)
        self._refresh_suspicious(data)
        self._refresh_blocked()
        self._refresh_process_tree(data)
        self._refresh_netstats(data)
        self._refresh_timeline(data)
        self._refresh_config()
        self._check_alert_flash(data)

    def _refresh_status(self, data):
        stats = data.get('conn_stats', {})
        self._status_lbl.config(
            text=f"Connections: {stats.get('total_connections', 0)} | "
                 f"Services: {stats.get('unique_services', 0)} | "
                 f"IPs: {stats.get('unique_ips', 0)} | "
                 f"Processes: {len(data.get('processes', []))} | "
                 f"Deductions: {len(data.get('deductions', []))} | "
                 f"Pipeline: {data.get('pipeline_processed', 0)}/{data.get('pipeline_dropped', 0)}")

    def _set_text(self, widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content)
        widget.config(state="disabled")

    def _refresh_overview(self, data):
        w = self._overview_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        stats = data.get('conn_stats', {})
        w.insert("end", "═" * 90 + "\n", "dim")
        w.insert("end", "  GNA TRACER — SYSTEM OVERVIEW\n", "header")
        w.insert("end", "═" * 90 + "\n\n", "dim")
        w.insert("end", f"  Active Connections:   {stats.get('total_connections', 0)}\n", "highlight")
        w.insert("end", f"  Unique Services:      {stats.get('unique_services', 0)}\n", "highlight")
        w.insert("end", f"  Unique Public IPs:    {stats.get('unique_ips', 0)}\n", "highlight")
        w.insert("end", f"  Tracked Processes:    {len(data.get('processes', []))}\n", "highlight")
        w.insert("end", f"  Total Deductions:     {len(data.get('deductions', []))}\n", "highlight")
        w.insert("end", f"  Network Devices:      {len(data.get('devices', []))}\n", "highlight")
        w.insert("end", f"  DNS Cache Entries:    {data.get('dns_count', 0)}\n", "highlight")
        w.insert("end", f"  GeoIP Cache Entries:  {data.get('geoip_count', 0)}\n", "highlight")
        w.insert("end", f"  User Idle:            {data.get('idle_seconds', 0):.0f}s\n", "highlight")
        w.insert("end", f"  Pipeline Processed:   {data.get('pipeline_processed', 0)}\n", "highlight")
        w.insert("end", f"  Pipeline Dropped:     {data.get('pipeline_dropped', 0)}\n", "highlight")
        # Tier 5 stats
        w.insert("end", "\n" + "─" * 60 + "\n", "dim")
        w.insert("end", "  EXTENDED MONITORS\n", "subheader")
        w.insert("end", "─" * 60 + "\n", "dim")
        fs_ct = len(data.get('fs_events', []))
        vt_ct = len(data.get('vt_results', {}))
        usb_ct = len(data.get('usb_events', []))
        clip_ct = len(data.get('clipboard_events', []))
        task_ct = len(data.get('sched_task_events', []))
        pipe_ct = len(data.get('named_pipe_events', []))
        scan_ct = len(data.get('inbound_scan_events', []))
        doh_ct = len(data.get('doh_events', []))
        cert_ct = len(data.get('cert_events', []))
        tl_ct = len(data.get('conn_timeline', []))
        w.insert("end", f"  File System Events:   {fs_ct}\n",
                 "warning" if fs_ct > 50 else "highlight")
        w.insert("end", f"  VirusTotal Scans:     {vt_ct}\n", "highlight")
        w.insert("end", f"  USB Device Events:    {usb_ct}\n",
                 "warning" if usb_ct > 0 else "highlight")
        w.insert("end", f"  Clipboard Events:     {clip_ct}\n",
                 "critical" if clip_ct > 0 else "highlight")
        w.insert("end", f"  Sched Task Changes:   {task_ct}\n",
                 "warning" if task_ct > 0 else "highlight")
        w.insert("end", f"  Named Pipe Events:    {pipe_ct}\n",
                 "warning" if pipe_ct > 5 else "highlight")
        w.insert("end", f"  Inbound Scans:        {scan_ct}\n",
                 "critical" if scan_ct > 0 else "highlight")
        w.insert("end", f"  DoH Detections:       {doh_ct}\n",
                 "warning" if doh_ct > 0 else "highlight")
        w.insert("end", f"  Cert/MITM Events:     {cert_ct}\n",
                 "critical" if cert_ct > 0 else "highlight")
        w.insert("end", f"  Connection Timeline:  {tl_ct}\n", "highlight")
        bt_ct = len(data.get('bt_devices', []))
        bt_ev = len(data.get('bt_events', []))
        serial_ct = len(data.get('serial_ports', []))
        serial_ev = len(data.get('serial_events', []))
        w.insert("end", f"  Bluetooth Devices:    {bt_ct} ({bt_ev} events)\n",
                 "warning" if bt_ev > 0 else "highlight")
        w.insert("end", f"  Serial/COM Ports:     {serial_ct} ({serial_ev} events)\n",
                 "warning" if serial_ev > 0 else "highlight")
        proxy_ev = len(data.get('proxy_events', []))
        proxy_procs = data.get('proxy_processes', [])
        # Count connections with proxy flags
        proxy_conns = sum(1 for c in data.get('connections', []) if c.get('proxy_type'))
        fwd_ct = sum(1 for c in data.get('connections', []) if 'FORWARD' in c.get('proxy_type', ''))
        rev_ct = sum(1 for c in data.get('connections', []) if 'REVERSE' in c.get('proxy_type', ''))
        res_ct = sum(1 for c in data.get('connections', []) if 'RESIDENTIAL' in c.get('proxy_type', ''))
        w.insert("end", f"  Proxy Detections:     {proxy_conns} connections",
                 "critical" if res_ct > 0 else ("warning" if proxy_conns > 0 else "highlight"))
        if proxy_conns > 0:
            parts = []
            if fwd_ct:
                parts.append(f"{fwd_ct} fwd")
            if rev_ct:
                parts.append(f"{rev_ct} rev")
            if res_ct:
                parts.append(f"{res_ct} residential")
            w.insert("end", f" ({', '.join(parts)})\n",
                     "critical" if res_ct > 0 else "warning")
        else:
            w.insert("end", "\n")
        if proxy_procs:
            w.insert("end", f"  Proxy Processes:      {', '.join(proxy_procs[:3])}\n", "critical")
        if proxy_ev > 0:
            w.insert("end", f"  System Proxy Events:  {proxy_ev}\n", "warning")
        # High-risk processes
        high_risk = [p for p in data.get('processes', []) if p.get('risk', 0) >= 40]
        if high_risk:
            w.insert("end", "\n" + "═" * 90 + "\n", "dim")
            w.insert("end", "  ⚠ HIGH-RISK PROCESSES\n", "critical")
            w.insert("end", "═" * 90 + "\n", "dim")
            for p in sorted(high_risk, key=lambda x: -x.get('risk', 0)):
                w.insert("end", f"\n  PID {p['pid']}: {p['name']}\n", "warning")
                w.insert("end", f"    Risk Score: {p['risk']}\n", "critical")
                w.insert("end", f"    Exe: {p.get('exe', '?')}\n")
                w.insert("end", f"    Connections: {p.get('connections', 0)}\n")
                w.insert("end", f"    Destinations: {p.get('destinations', 0)}\n")
                w.insert("end", f"    ML Anomaly: {p.get('ml_score', 0)}\n")
                w.insert("end", f"    Countries: {', '.join(p.get('countries', []))}\n")
        # Service summary
        svcs = data.get('services', [])
        if svcs:
            w.insert("end", "\n" + "═" * 90 + "\n", "dim")
            w.insert("end", "  📡 ACTIVE SERVICES\n", "header")
            w.insert("end", "═" * 90 + "\n", "dim")
            for s in svcs:
                w.insert("end", f"  {s.get('icon', '?')} {s.get('service', '?'):25s} "
                                f"| {s.get('category', '?'):15s} | "
                                f"{s.get('city', '?')}, {s.get('country', '?'):15s} | "
                                f"{s.get('org', '?')}\n")
        self._highlight_search(w, self._search_overview.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _conn_matches_search(self, c, query):
        """Check if a connection matches the search query."""
        if not query or len(query) < 2:
            return True
        q = query.lower()
        fields = [
            str(c.get('remote_ip', '')), str(c.get('domain', '')),
            str(c.get('service', '')), str(c.get('process', '')),
            str(c.get('category', '')), str(c.get('country', '')),
            str(c.get('org', '')), str(c.get('isp', '')),
            str(c.get('city', '')), str(c.get('pid', '')),
            str(c.get('via', '')), str(c.get('website_tag', '')),
            str(c.get('exe_path', '')), str(c.get('parent_name', '')),
            ' '.join(str(d) for d in c.get('all_domains', [])),
        ]
        return any(q in f.lower() for f in fields)

    def _live_toggle_conn(self, conn_key: str):
        """Toggle expand/collapse for a single connection in the live tab."""
        self._live_expanded[conn_key] = not self._live_expanded.get(conn_key, False)
        # Force immediate re-render by calling the last cached data
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    def _live_set_all_expanded(self, expanded: bool):
        """Set all connections to expanded or collapsed."""
        if expanded:
            # Expand everything currently visible
            if hasattr(self, '_last_live_data') and self._last_live_data is not None:
                for c in self._last_live_data.get('connections', []):
                    self._live_expanded[self._live_conn_key(c)] = True
        else:
            self._live_expanded.clear()
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    def _live_toggle_category(self, cat_key: str, conn_keys: list):
        """Toggle all connections in a category."""
        # If any are expanded, collapse all; otherwise expand all
        any_open = any(self._live_expanded.get(k, False) for k in conn_keys)
        for k in conn_keys:
            self._live_expanded[k] = not any_open
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    @staticmethod
    def _live_conn_key(c: dict) -> str:
        """Stable key for a connection dict to track expand state."""
        return f"{c.get('remote_ip', '')}:{c.get('remote_port', '')}:{c.get('pid', '')}"

    def _live_render_detail(self, w, c, risk, risk_tag):
        """Render the expanded detail lines for a connection."""
        rip = c.get('remote_ip', '')
        # === WEBSITE TAG ===
        wtag = c.get('website_tag', '')
        if wtag:
            w.insert("end", f"  │  🏷️ WEBSITE:    ", "")
            w.insert("end", f"{wtag}\n", "highlight")
        # === Process detail ===
        w.insert("end", f"  │     Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
        exe_path = c.get('exe_path', '')
        if exe_path:
            w.insert("end", f"  │     Exe Path:    {exe_path}\n", "dim")
        parent = c.get('parent_name', '')
        if parent:
            w.insert("end", f"  │     Parent:      {parent}\n", "dim")
        # === Network detail ===
        w.insert("end", f"  │     Remote:      {rip}:{c.get('remote_port', '?')}\n")
        w.insert("end", f"  │     Local Port:  {c.get('local_port', '?')}\n")
        w.insert("end", f"  │     Protocol:    {c.get('protocol', '?')} — Status: ", "")
        w.insert("end", f"{c.get('status', '?')}\n", risk_tag)
        # === Domain detail ===
        domain_str = c.get('domain', 'unresolved')
        via = c.get('via', '')
        if via:
            w.insert("end", f"  │     Domain:      {domain_str}", "highlight")
            w.insert("end", f" (via {via})\n", "dim")
        else:
            w.insert("end", f"  │     Domain:      {domain_str}\n")
        all_doms = c.get('all_domains', [])
        if all_doms and len(all_doms) > 1:
            w.insert("end", f"  │     All Domains: {', '.join(all_doms[:8])}", "dim")
            if len(all_doms) > 8:
                w.insert("end", f" (+{len(all_doms)-8} more)", "dim")
            w.insert("end", "\n")
        elif all_doms and len(all_doms) == 1:
            w.insert("end", f"  │     All Domains: {all_doms[0]}\n", "dim")
        # === Geo detail ===
        w.insert("end", f"  │     Country:     {c.get('country', '?')} ({c.get('country_code', '?')})\n")
        w.insert("end", f"  │     City:        {c.get('city', '?')}\n")
        w.insert("end", f"  │     Org:         {c.get('org', '?')}\n")
        if risk > 0:
            w.insert("end", f"  │     Risk:        {risk:.1f}\n", risk_tag)
        # Location verification proof
        loc_conf = c.get('loc_confidence', 0)
        loc_grade = c.get('loc_grade', 'UNVERIFIED')
        loc_proof = c.get('loc_proof', [])
        if loc_proof:
            grade_tag = "info" if loc_grade == "HIGH" else (
                "warning" if loc_grade in ("MEDIUM", "LOW") else "critical")
            w.insert("end", f"  │     📍 Location: ", "")
            w.insert("end", f"{loc_conf}% {loc_grade}\n", grade_tag)
            for proof in loc_proof:
                w.insert("end", f"  │       {proof}\n", "dim")
        # Proxy detection
        proxy_type = c.get('proxy_type', '')
        if proxy_type:
            proxy_detail = c.get('proxy_detail', '')
            w.insert("end", f"  │     🔀 Proxy:    ", "")
            w.insert("end", f"{proxy_type}\n", "warning")
            if proxy_detail:
                w.insert("end", f"  │       {proxy_detail}\n", "dim")

    def _refresh_live(self, data):
        """Show ONLY live (active/established) connections with collapsible rows."""
        self._last_live_data = data
        w = self._live_text
        at_bottom, frac = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._live_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._live_buttons.clear()
        w.config(state="normal")
        w.delete("1.0", "end")
        conns = data.get('connections', [])
        live_statuses = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'LISTEN', 'LAST_ACK', 'FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'TIME_WAIT'}
        live = [c for c in conns if c.get('status', '').upper() in live_statuses]
        # Apply search filter
        search_q = self._search_live.get()
        if search_q and len(search_q) >= 2:
            live = [c for c in live if self._conn_matches_search(c, search_q)]
        # Header with Expand All / Collapse All buttons
        w.insert("end", f"{'═' * 140}\n", "dim")
        w.insert("end", f"  🟢 LIVE CONNECTIONS — {len(live)} active  ", "header")
        # Expand All button
        btn_expand = tk.Button(
            w, text="▼ Expand All", bg="#333355", fg="#00d4ff",
            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
            activebackground="#555577", activeforeground="#ffffff",
            command=lambda: self._live_set_all_expanded(True))
        w.window_create("end", window=btn_expand)
        self._live_buttons.append(btn_expand)
        w.insert("end", "  ")
        # Collapse All button
        btn_collapse = tk.Button(
            w, text="▶ Collapse All", bg="#333355", fg="#aaaaaa",
            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
            activebackground="#555577", activeforeground="#ffffff",
            command=lambda: self._live_set_all_expanded(False))
        w.window_create("end", window=btn_collapse)
        self._live_buttons.append(btn_collapse)
        if search_q and len(search_q) >= 2:
            w.insert("end", f"  (filter: \"{search_q}\")", "dim")
        w.insert("end", "\n")
        w.insert("end", f"{'═' * 140}\n", "dim")
        if not live:
            w.insert("end", "\n  No live connections" +
                     (f" matching \"{search_q}\"" if search_q else "") + ".\n", "dim")
        else:
            by_cat = defaultdict(list)
            for c in live:
                by_cat[c.get('category', 'Unknown')].append(c)
            for cat in sorted(by_cat.keys()):
                cat_conns = by_cat[cat]
                cat_keys = [self._live_conn_key(c) for c in cat_conns]
                # Category header with toggle button
                w.insert("end", "\n  ")
                cat_any_open = any(self._live_expanded.get(k, False) for k in cat_keys)
                cat_arrow = "▼" if cat_any_open else "▶"
                cat_btn = tk.Button(
                    w, text=f"{cat_arrow} {cat} ({len(cat_conns)})",
                    bg="#1a1a2e", fg="#00d4ff",
                    font=("Consolas", 9, "bold"), bd=0, padx=4, pady=1,
                    activebackground="#333355", activeforeground="#ffffff",
                    anchor="w",
                    command=lambda ck=cat_keys: self._live_toggle_category(cat, ck))
                w.window_create("end", window=cat_btn)
                self._live_buttons.append(cat_btn)
                w.insert("end", " " + "─" * 80 + "\n", "dim")
                for idx, c in enumerate(cat_conns, 1):
                    rip = c.get('remote_ip', '')
                    conn_key = self._live_conn_key(c)
                    is_expanded = self._live_expanded.get(conn_key, False)
                    is_blocked = rip in self._blocked_ips
                    risk = 0
                    for p in data.get('processes', []):
                        if p['pid'] == c.get('pid'):
                            risk = p.get('risk', 0)
                            break
                    if risk >= 50:
                        risk_tag = "critical"
                    elif risk >= 25:
                        risk_tag = "warning"
                    else:
                        risk_tag = "info"
                    # --- Compact summary row with toggle arrow ---
                    arrow = "▼" if is_expanded else "▶"
                    wtag = c.get('website_tag', '')
                    svc_label = wtag if wtag else c.get('service', 'Unknown')
                    summary = f"{c.get('icon', '?')} {svc_label}  —  {rip}:{c.get('remote_port', '?')}  [{c.get('process', '?')}]"
                    if is_blocked:
                        summary += "  🚫BLOCKED"
                    w.insert("end", f"  ")
                    # Toggle button
                    toggle_btn = tk.Button(
                        w, text=arrow, bg="#12121a", fg="#00d4ff",
                        font=("Consolas", 10, "bold"), bd=0, padx=2, pady=0,
                        activebackground="#333355", activeforeground="#ffffff",
                        command=lambda ck=conn_key: self._live_toggle_conn(ck))
                    w.window_create("end", window=toggle_btn)
                    self._live_buttons.append(toggle_btn)
                    w.insert("end", f" ", "")
                    w.insert("end", f"{summary}\n", "highlight" if is_expanded else "")
                    # --- Expanded detail ---
                    if is_expanded:
                        # Block button inside expanded view
                        if rip:
                            btn_text = f"🔓 Unblock {rip}" if is_blocked else f"🚫 Block {rip}"
                            btn_bg = "#4caf50" if is_blocked else "#8b0000"
                            btn = tk.Button(
                                w, text=btn_text, bg=btn_bg, fg="#ffffff",
                                font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
                                activebackground="#555555", activeforeground="#ffffff",
                                command=lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                            w.insert("end", "       ")
                            w.window_create("end", window=btn)
                            self._live_buttons.append(btn)
                            w.insert("end", "\n")
                        self._live_render_detail(w, c, risk, risk_tag)
                        w.insert("end", f"  └{'─' * 90}\n", "dim")
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_connections(self, data):
        if self._conn_paused:
            return  # user is browsing — don't reset scroll
        w = self._conn_text
        at_bottom, frac = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._conn_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._conn_buttons.clear()
        w.config(state="normal")
        w.delete("1.0", "end")
        conns = data.get('connections', [])
        search_q = self._search_conn.get()
        # Filter connections by search
        if search_q and len(search_q) >= 2:
            filtered = [c for c in conns if self._conn_matches_search(c, search_q)]
        else:
            filtered = conns
        w.insert("end", f"{'═' * 140}\n", "dim")
        if search_q and len(search_q) >= 2:
            w.insert("end", f"  ALL ACTIVE CONNECTIONS — {len(filtered)}/{len(conns)} matching \"{search_q}\"\n", "header")
        else:
            w.insert("end", f"  ALL ACTIVE CONNECTIONS — {len(conns)} total (each listed individually)\n", "header")
        w.insert("end", f"{'═' * 140}\n\n", "dim")
        if not filtered:
            w.insert("end", "  No connections match the search.\n" if search_q else "  Scanning... no connections yet.\n", "dim")
        else:
            by_cat = defaultdict(list)
            for c in filtered:
                by_cat[c.get('category', 'Unknown')].append(c)
            for cat in sorted(by_cat.keys()):
                cat_conns = by_cat[cat]
                w.insert("end", f"\n  ┌─ {cat} ({len(cat_conns)} connections) ", "subheader")
                w.insert("end", "─" * 80 + "\n", "dim")
                for idx, c in enumerate(cat_conns, 1):
                    rip = c.get('remote_ip', '')
                    is_blocked = rip in self._blocked_ips
                    w.insert("end", f"  │\n")
                    w.insert("end", f"  ├── [{idx}] ", "highlight")
                    w.insert("end", f"{c.get('icon', '?')} {c.get('service', 'Unknown')}  ", "highlight")
                    # Embed Block/Unblock button
                    if rip:
                        btn_text = f"🔓 Unblock {rip}" if is_blocked else f"🚫 Block {rip}"
                        btn_bg = "#4caf50" if is_blocked else "#8b0000"
                        btn_fg = "#ffffff"
                        btn = tk.Button(
                            w, text=btn_text, bg=btn_bg, fg=btn_fg,
                            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
                            activebackground="#555555", activeforeground="#ffffff",
                            command=lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                        w.window_create("end", window=btn)
                        self._conn_buttons.append(btn)
                    if is_blocked:
                        w.insert("end", "  ← BLOCKED", "critical")
                    w.insert("end", "\n")
                    # === WEBSITE TAG ===
                    wtag = c.get('website_tag', '')
                    if wtag:
                        w.insert("end", f"  │  🏷️ WEBSITE:    ", "")
                        w.insert("end", f"{wtag}\n", "highlight")
                    # === Process detail ===
                    w.insert("end", f"  │     Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
                    exe_path = c.get('exe_path', '')
                    if exe_path:
                        w.insert("end", f"  │     Exe Path:    {exe_path}\n", "dim")
                    parent = c.get('parent_name', '')
                    if parent:
                        w.insert("end", f"  │     Parent:      {parent}\n", "dim")
                    # === Network detail ===
                    w.insert("end", f"  │     Remote:      {rip}:{c.get('remote_port', '?')}\n")
                    w.insert("end", f"  │     Local Port:  {c.get('local_port', '?')}\n")
                    w.insert("end", f"  │     Protocol:    {c.get('protocol', '?')} — Status: {c.get('status', '?')}\n")
                    # === Domain detail ===
                    domain_str = c.get('domain', 'unresolved')
                    via = c.get('via', '')
                    if via:
                        w.insert("end", f"  │     Domain:      {domain_str}", "highlight")
                        w.insert("end", f" (via {via})\n", "dim")
                    else:
                        w.insert("end", f"  │     Domain:      {domain_str}\n")
                    all_doms = c.get('all_domains', [])
                    if all_doms and len(all_doms) > 1:
                        w.insert("end", f"  │     All Domains: {', '.join(all_doms[:8])}", "dim")
                        if len(all_doms) > 8:
                            w.insert("end", f" (+{len(all_doms)-8} more)", "dim")
                        w.insert("end", "\n")
                    elif all_doms and len(all_doms) == 1:
                        w.insert("end", f"  │     All Domains: {all_doms[0]}\n", "dim")
                    # === Geo detail ===
                    w.insert("end", f"  │     Country:     {c.get('country', '?')} ({c.get('country_code', '?')})\n")
                    w.insert("end", f"  │     City:        {c.get('city', '?')}, Region: {c.get('region', '?')}\n")
                    w.insert("end", f"  │     Org:         {c.get('org', '?')}\n")
                    w.insert("end", f"  │     ISP:         {c.get('isp', '?')}\n")
                    w.insert("end", f"  │     Coordinates: ({c.get('lat', 0):.4f}, {c.get('lon', 0):.4f})\n")
                    # Location verification proof
                    loc_conf = c.get('loc_confidence', 0)
                    loc_grade = c.get('loc_grade', 'UNVERIFIED')
                    loc_proof = c.get('loc_proof', [])
                    if loc_proof:
                        grade_tag = "info" if loc_grade == "HIGH" else (
                            "warning" if loc_grade in ("MEDIUM", "LOW") else "critical")
                        w.insert("end", f"  │     📍 Location: ", "")
                        w.insert("end", f"{loc_conf}% {loc_grade}\n", grade_tag)
                        for proof in loc_proof:
                            w.insert("end", f"  │       {proof}\n", "dim")
                    # Proxy detection
                    proxy_type = c.get('proxy_type', '')
                    if proxy_type:
                        proxy_detail = c.get('proxy_detail', '')
                        w.insert("end", f"  │     🔀 Proxy:    ", "")
                        w.insert("end", f"{proxy_type}\n", "warning")
                        if proxy_detail:
                            w.insert("end", f"  │       {proxy_detail}\n", "dim")
                    w.insert("end", f"  │     First Seen:  {_fmt_ts(c.get('first_seen', 0))}\n")
                    w.insert("end", f"  │     Last Seen:   {_fmt_ts(c.get('last_seen', 0))}\n")
                w.insert("end", f"  └{'─' * 100}\n", "dim")
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_deductions(self, data):
        w = self._ded_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        deds = data.get('deductions', [])
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  ALL DEDUCTIONS — {len(deds)} total (full evidence)\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        for idx, d in enumerate(reversed(deds), 1):
            sev = d.get('severity', 'INFO')
            tag = "critical" if sev == "CRITICAL" else ("warning" if sev == "WARNING" else "info")
            w.insert("end", f"  ┌─ Deduction #{idx} ", tag)
            w.insert("end", f"{'─' * 70}\n", "dim")
            w.insert("end", f"  │ Time:     {d.get('time', '?')}\n")
            w.insert("end", f"  │ Severity: ", "")
            w.insert("end", f"{sev}\n", tag)
            w.insert("end", f"  │ Category: {d.get('category', '?')}\n")
            w.insert("end", f"  │ Process:  {d.get('process', '?')} (PID {d.get('pid', '?')})\n")
            w.insert("end", f"  │ Score:    {d.get('score', 0)}\n", tag)
            w.insert("end", f"  │ Message:  {d.get('message', '?')}\n", "highlight")
            evidence = d.get('evidence', [])
            if evidence:
                w.insert("end", f"  │ Evidence:\n")
                for ev in evidence:
                    w.insert("end", f"  │   → {ev}\n")
            w.insert("end", f"  └{'─' * 80}\n\n", "dim")
        self._highlight_search(w, self._search_ded.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_processes(self, data):
        w = self._proc_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        procs = data.get('processes', [])
        active = [p for p in procs if p.get('connections', 0) > 0 or p.get('risk', 0) > 0]
        active.sort(key=lambda x: -x.get('risk', 0))
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", f"  ALL TRACKED PROCESSES — {len(active)} with network activity or risk\n", "header")
        w.insert("end", f"{'═' * 120}\n\n", "dim")
        w.insert("end", f"  {'PID':<8} {'Name':<28} {'Risk':>6} {'Conn':>6} {'Dst':>5} "
                        f"{'ML':>6} {'Exe':<50} {'Countries'}\n", "subheader")
        w.insert("end", f"  {'─'*8} {'─'*28} {'─'*6} {'─'*6} {'─'*5} {'─'*6} {'─'*50} {'─'*20}\n", "dim")
        for p in active:
            risk = p.get('risk', 0)
            tag = "critical" if risk >= 70 else ("warning" if risk >= 40 else "")
            line = (f"  {p['pid']:<8} {p['name']:<28} {risk:>6.1f} {p.get('connections', 0):>6} "
                    f"{p.get('destinations', 0):>5} {p.get('ml_score', 0):>6.1f} "
                    f"{p.get('exe', '?')[:50]:<50} {', '.join(p.get('countries', []))}\n")
            w.insert("end", line, tag)
        # Also show detailed per-process connection breakdown
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", f"  DETAILED PER-PROCESS CONNECTION BREAKDOWN\n", "header")
        w.insert("end", f"{'═' * 120}\n", "dim")
        for p in active[:50]:
            if p.get('connections', 0) > 0:
                w.insert("end", f"\n  ▶ {p['name']} (PID {p['pid']}) — "
                                f"Risk: {p.get('risk', 0):.1f} — "
                                f"{p.get('connections', 0)} connections\n", "subheader")
                # Pull individual connections for this PID
                for c in data.get('connections', []):
                    if c.get('pid') == p['pid']:
                        w.insert("end", f"    ├─ {c.get('remote_ip', '?')}:{c.get('remote_port', '?')} | "
                                        f"{c.get('service', '?')} | {c.get('domain', '?')} | "
                                        f"{c.get('country_code', '?')} | {c.get('org', '?')} | "
                                        f"{c.get('status', '?')}\n")
        self._highlight_search(w, self._search_proc.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_devices(self, data):
        w = self._dev_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        devs = data.get('devices', [])
        w.insert("end", f"{'═' * 110}\n", "dim")
        w.insert("end", f"  NETWORK DEVICES — {len(devs)} discovered\n", "header")
        w.insert("end", f"{'═' * 110}\n\n", "dim")
        w.insert("end", f"  {'IP':<18} {'MAC':<20} {'Vendor':<18} {'Hostname':<25} "
                        f"{'OS Guess':<20} {'Conf':>6}\n", "subheader")
        w.insert("end", f"  {'─'*18} {'─'*20} {'─'*18} {'─'*25} {'─'*20} {'─'*6}\n", "dim")
        for d in devs:
            w.insert("end", f"  {d.get('ip', '?'):<18} {d.get('mac', '?'):<20} "
                            f"{d.get('vendor', '?'):<18} {d.get('hostname', '?'):<25} "
                            f"{d.get('os_guess', '?'):<20} {d.get('confidence', 0):>6.2f}\n")
            if d.get('ja4'):
                w.insert("end", f"    JA4: {d['ja4']}\n", "dim")
            if d.get('ja4s'):
                w.insert("end", f"    JA4S: {d['ja4s']}\n", "dim")
            if d.get('ja4h'):
                w.insert("end", f"    JA4H: {d['ja4h']}\n", "dim")
        # Bluetooth devices
        bt_devs = data.get('bt_devices', [])
        if bt_devs:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  BLUETOOTH DEVICES — {len(bt_devs)} detected\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            w.insert("end", f"  {'Name':<35} {'Type':<15} {'Device ID':<60}\n", "subheader")
            w.insert("end", f"  {'─'*35} {'─'*15} {'─'*60}\n", "dim")
            for bt in bt_devs:
                w.insert("end", f"  {bt.get('name', '?'):<35} {bt.get('type', '?'):<15} "
                                f"{bt.get('device_id', '?')[:60]:<60}\n")
        # Serial ports
        serial_ports = data.get('serial_ports', [])
        if serial_ports:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  SERIAL / COM PORTS — {len(serial_ports)} active\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            w.insert("end", f"  {'Port':<12} {'Device':<60}\n", "subheader")
            w.insert("end", f"  {'─'*12} {'─'*60}\n", "dim")
            for sp in serial_ports:
                w.insert("end", f"  {sp.get('port', '?'):<12} {sp.get('device', '?'):<60}\n")
        self._highlight_search(w, self._search_dev.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_map(self, data):
        if not self._map_canvas:
            return
        # Resize canvas to current size
        self._map_w = max(600, self._map_canvas.winfo_width())
        self._map_h = max(300, self._map_canvas.winfo_height())
        # Prepare map data for dot plotting (also used by _redraw_dots_only)
        all_points = list(data.get('map_points', []))
        conn_list = data.get('connections', [])
        seen = {p['ip'] for p in all_points}
        for c in conn_list:
            if c.get('lat') or c.get('lon'):
                if c.get('remote_ip') not in seen:
                    all_points.append({
                        'ip': c['remote_ip'], 'lat': c['lat'], 'lon': c['lon'],
                        'service': c.get('service', '?'), 'icon': c.get('icon', '?'),
                        'city': c.get('city', '?'), 'country': c.get('country', '?'),
                        'org': c.get('org', '?'), 'process': c.get('process', '?'),
                    })
                    seen.add(c['remote_ip'])
        ip_risk: dict[str, float] = {}
        for c in conn_list:
            rip = c.get('remote_ip', '')
            for p in data.get('processes', []):
                if p['pid'] == c.get('pid'):
                    ip_risk[rip] = max(ip_risk.get(rip, 0), p.get('risk', 0))
                    break
        ip_conn_count: dict[str, int] = defaultdict(int)
        for c in conn_list:
            ip_conn_count[c.get('remote_ip', '')] += 1
        # Cache for zoom/pan redraws
        self._last_map_data = {
            'all_points': all_points,
            'ip_risk': ip_risk,
            'ip_conn_count': ip_conn_count,
        }
        # Full redraw: grid + coastline + labels + dots
        self._draw_map_full()
        self._map_canvas.delete("dot", "line_to_dot")
        self._plot_map_dots(self._last_map_data)

    def _plot_map_dots(self, map_data):
        """Plot IP dots on the map using precomputed map_data."""
        if not self._map_canvas or not map_data:
            return
        all_points = map_data.get('all_points', [])
        ip_risk = map_data.get('ip_risk', {})
        ip_conn_count = map_data.get('ip_conn_count', {})
        w, h = self._map_w, self._map_h
        z = self._map_zoom
        # Draw connection lines from local to remote at higher zoom
        if z >= 2 and all_points:
            local_x, local_y = w / 2, h / 2  # approximate local position
            for pt in all_points:
                lat, lon = pt.get('lat', 0), pt.get('lon', 0)
                if lat == 0 and lon == 0:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_line(
                        local_x, local_y, x, y,
                        fill="#1a2a3a", width=1, dash=(3, 6),
                        tags="line_to_dot")
        for pt in all_points:
            lat, lon = pt.get('lat', 0), pt.get('lon', 0)
            if lat == 0 and lon == 0:
                continue
            x, y = self._latlon_to_xy(lat, lon)
            # Skip dots outside viewport
            if x < -20 or x > w + 20 or y < -20 or y > h + 20:
                continue
            ip = pt.get('ip', '?')
            risk = ip_risk.get(ip, 0)
            if risk >= 50:
                fill_color, outline_color = "#ff0000", "#ff4444"
            elif risk >= 25:
                fill_color, outline_color = "#ff8800", "#ffaa44"
            elif risk >= 10:
                fill_color, outline_color = "#ffcc00", "#ffdd44"
            else:
                fill_color, outline_color = "#44cc44", "#66ff66"
            if ip in getattr(self, '_watchlist_ips', set()):
                outline_color = "#00ffff"
            radius = min(8, max(3, 3 + ip_conn_count.get(ip, 1)))
            dot = self._map_canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill=fill_color, outline=outline_color, width=1, tags="dot")
            info = pt
            self._map_canvas.tag_bind(dot, "<Enter>",
                lambda e, i=ip, inf=info: self._on_map_dot_enter(e, i, inf))
            self._map_canvas.tag_bind(dot, "<Leave>", self._on_map_dot_leave)
            self._map_canvas.tag_bind(dot, "<Button-1>",
                lambda e, i=ip: self._on_map_dot_click(i))
            # Show IP label when zoomed in enough
            if z >= 4:
                self._map_canvas.create_text(
                    x + radius + 3, y, text=ip, fill="#88aaaa",
                    font=("Consolas", max(7, min(9, int(6 + z * 0.3)))),
                    anchor="w", tags="dot")

    def _refresh_actions(self, data):
        w = self._actions_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        actions = data.get('all_actions', [])
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  RAW ACTIONS LOG — {len(actions)} entries\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        for act in actions[-500:]:
            line = str(act) + "\n"
            if 'CRITICAL' in line or 'DEDUCTION' in line:
                w.insert("end", line, "critical")
            elif 'WARNING' in line:
                w.insert("end", line, "warning")
            else:
                w.insert("end", line)
        self._highlight_search(w, self._search_actions.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_suspicious(self, data):
        """Show ONLY out-of-norm / anomalous events — virus behavior, data access, hardware, remote power, etc."""
        w = self._suspicious_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        events = data.get('suspicious_events', [])
        w.insert("end", "═" * 110 + "\n", "dim")
        w.insert("end", f"  🔴 SUSPICIOUS ACTIVITY — {len(events)} anomalous events detected\n", "header")
        w.insert("end", "═" * 110 + "\n", "dim")
        w.insert("end", "  Only shows operations that are OUT OF THE NORM: virus behavior, data exfil,\n", "dim")
        w.insert("end", "  cookie tracking, mic/camera access, remote power/access, code injection,\n", "dim")
        w.insert("end", "  suspicious paths, credential access, script execution, high-risk geo, etc.\n", "dim")
        w.insert("end", "═" * 110 + "\n\n", "dim")
        if not events:
            w.insert("end", "  ✅ No suspicious activity detected yet.\n\n", "info")
            w.insert("end", "  The monitor is watching for:\n", "dim")
            w.insert("end", "    • Virus-like behavior (injection, hooking, RWX memory)\n", "dim")
            w.insert("end", "    • Data exfiltration / unusual uploads\n", "dim")
            w.insert("end", "    • Cookie & tracker sending (even from Google)\n", "dim")
            w.insert("end", "    • Mic / camera / hardware access\n", "dim")
            w.insert("end", "    • Remote power (shutdown, restart, wake-on-LAN)\n", "dim")
            w.insert("end", "    • Remote access (RDP, SSH, VNC, TeamViewer)\n", "dim")
            w.insert("end", "    • Processes from temp/downloads/AppData paths\n", "dim")
            w.insert("end", "    • Credential / password / token access\n", "dim")
            w.insert("end", "    • Script execution (PowerShell, cmd, wscript)\n", "dim")
            w.insert("end", "    • Connections to high-risk countries\n", "dim")
            w.insert("end", "    • All deductions from the chess engine\n", "dim")
            w.config(state="disabled")
            self._end_refresh(w, at_bottom, frac)
            return
        # Group by category
        by_cat = {}
        for ev in events:
            cat = ev.get('category', 'UNKNOWN')
            by_cat.setdefault(cat, []).append(ev)
        # Category icons
        cat_icons = {
            'HARDWARE_ACCESS': '🎤', 'REMOTE_ACCESS': '🔌', 'REMOTE_POWER': '⚡',
            'COOKIE_TRACKING': '🍪', 'DATA_UPLOAD': '📤', 'DATA_EXFIL': '📤',
            'CREDENTIAL_ACCESS': '🔑', 'TOKEN_ACCESS': '🔑', 'CLIPBOARD_ACCESS': '📋',
            'KEYLOGGER': '⌨️', 'SCREEN_CAPTURE': '📸', 'CODE_INJECTION': '💉',
            'API_HOOK': '🪝', 'ENCRYPTION': '🔐', 'SCRIPT_EXEC': '📜',
            'DLL_REGISTER': '🧩', 'SCHEDULED_TASK': '📅', 'SUSPICIOUS_PATH': '📁',
            'TEMP_EXECUTION': '📁', 'HIGH_RISK_GEO': '🌍',
            'MIMIC': '🎭', 'BEACON': '📡', 'PHANTOM': '👻',
            'IMPERSONATION': '🥸', 'FOREIGN': '🌍', 'ANOMALY': '📊',
            'INJECTION': '💉', 'TUNNEL': '🕳️', 'EXFIL': '📤',
            'ENTROPY': '🔐', 'DLL': '🧩', 'PERSISTENCE': '📌',
            'IDLE_ANOMALY': '💤', 'ML_ANOMALY': '🤖',
        }
        # Summary bar
        crit_count = sum(1 for e in events if e.get('severity') == 'CRITICAL')
        warn_count = sum(1 for e in events if e.get('severity') == 'WARNING')
        info_count = len(events) - crit_count - warn_count
        w.insert("end", f"  CRITICAL: {crit_count}  |  WARNING: {warn_count}  |  INFO: {info_count}  |  "
                        f"Categories: {len(by_cat)}\n\n", "subheader")
        # Render each category
        for cat in sorted(by_cat.keys()):
            cat_events = by_cat[cat]
            icon = cat_icons.get(cat, '❓')
            w.insert("end", f"{'─' * 100}\n", "dim")
            w.insert("end", f"  {icon} {cat} — {len(cat_events)} event(s)\n", "header")
            w.insert("end", f"{'─' * 100}\n", "dim")
            for ev in cat_events[-50:]:  # cap per category for performance
                sev = ev.get('severity', 'INFO')
                tag = 'critical' if sev == 'CRITICAL' else ('warning' if sev == 'WARNING' else 'info')
                w.insert("end", f"\n  [{sev}] ", tag)
                w.insert("end", f"{ev.get('time', '?')} — ", "dim")
                w.insert("end", f"{ev.get('description', '?')}\n", tag)
                w.insert("end", f"    Process: {ev.get('process', '?')} (PID {ev.get('pid', '?')})\n", "highlight")
                for detail in ev.get('details', []):
                    w.insert("end", f"      → {detail}\n", "dim")
        w.insert("end", f"\n{'═' * 110}\n", "dim")
        w.insert("end", f"  END OF SUSPICIOUS ACTIVITY LOG — {len(events)} total events\n", "dim")
        self._highlight_search(w, self._search_suspicious.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_blocked(self):
        """Show all currently blocked IPs with full metadata and unblock buttons."""
        w = self._blocked_text
        at_bottom, frac = self._begin_refresh(w)
        # Destroy old embedded buttons
        if not hasattr(self, '_blocked_tab_buttons'):
            self._blocked_tab_buttons = []
        for btn in self._blocked_tab_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._blocked_tab_buttons.clear()
        w.config(state="normal")
        w.delete("1.0", "end")
        blocked = self._blocked_ips
        n = len(blocked)
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", f"  🛑 BLOCKED IPs — {n} currently blocked by Windows Firewall\n", "header")
        w.insert("end", f"{'═' * 120}\n", "dim")
        if not self._is_admin():
            w.insert("end", "\n  ℹ Running without admin — a UAC prompt will appear when you block/unblock.\n", "warning")
            w.insert("end", "  Click Yes on the Windows permission dialog to allow the firewall change.\n\n", "dim")
        if n == 0:
            w.insert("end", "\n  No IPs are currently blocked.\n\n", "dim")
            w.insert("end", "  To block an IP, go to the All Connections tab and click the\n", "dim")
            w.insert("end", "  🚫 Block button next to any connection.\n", "dim")
        else:
            w.insert("end", "\n")
            for idx, (ip, meta) in enumerate(sorted(blocked.items()), 1):
                w.insert("end", f"  ┌─ Blocked IP #{idx} ", "critical")
                w.insert("end", "─" * 80 + "\n", "dim")
                w.insert("end", f"  │\n")
                w.insert("end", f"  │  IP:           {ip}\n", "highlight")
                # Embed unblock button
                w.insert("end", f"  │  Action:       ")
                btn = tk.Button(
                    w, text=f"🔓 Unblock {ip}", bg="#4caf50", fg="#ffffff",
                    font=("Consolas", 9, "bold"), bd=0, padx=8, pady=2,
                    activebackground="#66bb6a", activeforeground="#ffffff",
                    command=lambda i=ip: self._unblock_ip(i))
                w.window_create("end", window=btn)
                self._blocked_tab_buttons.append(btn)
                w.insert("end", "\n")
                w.insert("end", f"  │  Time Blocked: {meta.get('time_blocked', '?')}\n", "warning")
                w.insert("end", f"  │  Service:      {meta.get('service', '?')}\n")
                w.insert("end", f"  │  Domain:       {meta.get('domain', '?')}\n")
                w.insert("end", f"  │  Process:      {meta.get('process', '?')} (PID {meta.get('pid', '?')})\n")
                w.insert("end", f"  │  Country:      {meta.get('country', '?')}\n")
                w.insert("end", f"  │  City:         {meta.get('city', '?')}\n")
                w.insert("end", f"  │  Org:          {meta.get('org', '?')}\n")
                w.insert("end", f"  │  ISP:          {meta.get('isp', '?')}\n")
                w.insert("end", f"  │  Port:         {meta.get('remote_port', '?')}\n")
                w.insert("end", f"  │  Category:     {meta.get('category', '?')}\n")
                w.insert("end", f"  └{'─' * 90}\n\n", "dim")
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", f"  Firewall rules are automatically cleaned up when the program is closed.\n", "dim")
        w.insert("end", f"  Rules use prefix: {self._fw_rule_prefix}*\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    # ====================== GEOMETRY PERSISTENCE (Multi-monitor) ======================
    def _load_geometry(self):
        try:
            if os.path.exists(self._geometry_file):
                with open(self._geometry_file, 'r') as f:
                    geo = json.load(f)
                self._root.geometry(geo.get('geometry', ''))
        except Exception:
            pass

    def _save_geometry(self):
        try:
            with open(self._geometry_file, 'w') as f:
                json.dump({'geometry': self._root.geometry()}, f)
        except Exception:
            pass

    # ====================== ALERT FLASH SYSTEM ======================
    def _check_alert_flash(self, data):
        sus_count = len(data.get('suspicious_events', []))
        if sus_count > self._last_suspicious_count:
            new_alerts = sus_count - self._last_suspicious_count
            self._last_suspicious_count = sus_count
            # Flash the Suspicious Activity tab
            try:
                nb = self._root.nametowidget(self._suspicious_frame.winfo_parent())
                tab_id = nb.index(self._suspicious_frame)
                self._flash_tab(nb, tab_id, " 🔴 Suspicious Activity ", 6)
            except Exception:
                pass

    def _flash_tab(self, notebook, tab_index, original_text, flashes_remaining):
        if flashes_remaining <= 0:
            try:
                notebook.tab(tab_index, text=original_text)
            except Exception:
                pass
            return
        try:
            current = notebook.tab(tab_index, 'text')
            if '⚡' in current:
                notebook.tab(tab_index, text=original_text)
            else:
                notebook.tab(tab_index, text=" ⚡ ALERT ⚡ ")
        except Exception:
            return
        self._root.after(400, lambda: self._flash_tab(notebook, tab_index,
                                                        original_text, flashes_remaining - 1))

    # ====================== RIGHT-CLICK CONTEXT MENUS ======================
    def _show_conn_context_menu(self, event, ip, conn_info=None):
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#e94560", activeforeground="white")
        menu.add_command(label=f"Block {ip}", command=lambda: self._toggle_block_ip(ip, conn_info))
        menu.add_command(label=f"Copy IP: {ip}", command=lambda: self._copy_to_clipboard(ip))
        menu.add_command(label=f"Add to Watchlist", command=lambda: self._add_to_watchlist_ip(ip))
        menu.add_command(label=f"Remove from Watchlist", command=lambda: self._watchlist_ips.discard(ip))
        menu.add_separator()
        menu.add_command(label=f"Whois Lookup", command=lambda: self._whois_popup(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_proc_context_menu(self, event, pid, name):
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#e94560", activeforeground="white")
        menu.add_command(label=f"Add '{name}' to Watchlist",
                         command=lambda: self._watchlist_procs.add(name.lower()))
        menu.add_command(label=f"Remove '{name}' from Watchlist",
                         command=lambda: self._watchlist_procs.discard(name.lower()))
        menu.add_command(label=f"Copy PID: {pid}", command=lambda: self._copy_to_clipboard(str(pid)))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_to_clipboard(self, text):
        self._root.clipboard_clear()
        self._root.clipboard_append(text)

    def _add_to_watchlist_ip(self, ip):
        self._watchlist_ips.add(ip)

    def _whois_popup(self, ip):
        """Open a popup with whois info for an IP."""
        def _do_lookup():
            try:
                req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                            headers={'Accept': 'application/json'})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read())
                info = f"Name: {data.get('name', '?')}\nHandle: {data.get('handle', '?')}\n"
                info += f"Country: {data.get('country', '?')}\nRange: {data.get('startAddress', '?')} - {data.get('endAddress', '?')}\n"
                for ent in data.get('entities', [])[:3]:
                    roles = ', '.join(ent.get('roles', []))
                    info += f"Entity ({roles}): "
                    vcard = ent.get('vcardArray', [None, []])[1] if 'vcardArray' in ent else []
                    for v in vcard:
                        if v[0] in ('fn', 'org') and len(v) > 3:
                            info += f"{v[3]} "
                    info += "\n"
            except Exception as exc:
                info = f"Whois lookup failed: {exc}"
            self._root.after(0, lambda: _show_result(info))

        def _show_result(info):
            win = tk.Toplevel(self._root)
            win.title(f"Whois: {ip}")
            win.configure(bg="#12121a")
            win.geometry("500x300")
            txt = scrolledtext.ScrolledText(win, bg="#12121a", fg="#c0c0c0",
                                            font=("Consolas", 10), wrap="word")
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", info)
            txt.config(state="disabled")

        threading.Thread(target=_do_lookup, daemon=True).start()

    # ====================== EXPORT HTML REPORT ======================
    def _export_html_report(self):
        data = self._get_full_data()
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filepath = os.path.join(desktop, f"GNA_Report_{ts}.html")
        html = ['<!DOCTYPE html><html><head><meta charset="utf-8">',
                '<title>GNA Tracer Report</title>',
                '<style>body{background:#0a0a0f;color:#c0c0c0;font-family:Consolas,monospace;padding:20px}',
                'h1{color:#00d4ff}h2{color:#e94560}h3{color:#f5a623}',
                'table{border-collapse:collapse;width:100%;margin:10px 0}',
                'th,td{border:1px solid #333;padding:6px;text-align:left}',
                'th{background:#1a1a2e;color:#00d4ff}',
                'tr:nth-child(even){background:#12121a}',
                '.critical{color:#e94560;font-weight:bold}.warning{color:#f5a623}',
                '.info{color:#4caf50}.badge{display:inline-block;padding:2px 8px;border-radius:4px;',
                'font-size:11px;font-weight:bold}.badge-red{background:#e94560;color:white}',
                '.badge-yellow{background:#f5a623;color:black}',
                '</style></head><body>',
                f'<h1>GNA Tracer Security Report</h1>',
                f'<p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>']
        # Summary
        stats = data.get('conn_stats', {})
        html.append('<h2>Summary</h2><table>')
        html.append(f'<tr><th>Connections</th><td>{stats.get("total_connections", 0)}</td></tr>')
        html.append(f'<tr><th>Processes</th><td>{len(data.get("processes", []))}</td></tr>')
        html.append(f'<tr><th>Deductions</th><td>{len(data.get("deductions", []))}</td></tr>')
        html.append(f'<tr><th>Suspicious Events</th><td>{len(data.get("suspicious_events", []))}</td></tr>')
        html.append(f'<tr><th>Devices</th><td>{len(data.get("devices", []))}</td></tr>')
        html.append('</table>')
        # Deductions
        deds = data.get('deductions', [])
        if deds:
            html.append('<h2>Deductions</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Process</th><th>Message</th><th>Score</th></tr>')
            for d in deds[-200:]:
                sev_cls = 'critical' if d['severity'] == 'CRITICAL' else 'warning'
                html.append(f'<tr><td>{d["time"]}</td><td class="{sev_cls}">{d["severity"]}</td>'
                            f'<td>{d["category"]}</td><td>{d["process"]}</td>'
                            f'<td>{d["message"]}</td><td>{d["score"]}</td></tr>')
            html.append('</table>')
        # Suspicious Events
        sus = data.get('suspicious_events', [])
        if sus:
            html.append('<h2>Suspicious Events</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Process</th><th>Description</th></tr>')
            for ev in sus[-200:]:
                sev_cls = 'critical' if ev.get('severity') == 'CRITICAL' else 'warning'
                html.append(f'<tr><td>{ev.get("time","?")}</td><td class="{sev_cls}">{ev.get("severity","?")}</td>'
                            f'<td>{ev.get("category","?")}</td><td>{ev.get("process","?")}</td>'
                            f'<td>{ev.get("description","?")}</td></tr>')
            html.append('</table>')
        # Connections
        conns = data.get('connections', [])
        if conns:
            html.append('<h2>Active Connections</h2><table><tr><th>Process</th><th>Remote IP</th><th>Port</th><th>Service</th><th>Country</th><th>Org</th></tr>')
            for c in conns[:300]:
                html.append(f'<tr><td>{c.get("process","?")}</td><td>{c.get("remote_ip","?")}</td>'
                            f'<td>{c.get("remote_port","?")}</td><td>{c.get("service","?")}</td>'
                            f'<td>{c.get("country","?")}</td><td>{c.get("org","?")}</td></tr>')
            html.append('</table>')
        # Processes
        procs = data.get('processes', [])
        if procs:
            html.append('<h2>Processes</h2><table><tr><th>PID</th><th>Name</th><th>Risk</th><th>Connections</th><th>Countries</th></tr>')
            for p in sorted(procs, key=lambda x: x.get('risk', 0), reverse=True)[:100]:
                risk_cls = 'critical' if p.get('risk', 0) > 50 else ('warning' if p.get('risk', 0) > 20 else '')
                html.append(f'<tr><td>{p["pid"]}</td><td>{p["name"]}</td>'
                            f'<td class="{risk_cls}">{p["risk"]}</td><td>{p["connections"]}</td>'
                            f'<td>{", ".join(p.get("countries", []))}</td></tr>')
            html.append('</table>')
        # VT Results
        vt = data.get('vt_results', {})
        if vt:
            html.append('<h2>VirusTotal Results</h2><table><tr><th>SHA256</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>')
            for sha, r in vt.items():
                m_cls = 'critical' if r.get('malicious', 0) > 0 else ''
                html.append(f'<tr><td>{sha[:16]}...</td><td class="{m_cls}">{r.get("malicious",0)}</td>'
                            f'<td>{r.get("suspicious",0)}</td><td>{r.get("harmless",0)}</td></tr>')
            html.append('</table>')
        html.append('</body></html>')
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            _mb_logger.info("HTML report exported to %s", filepath)
            from tkinter import messagebox
            messagebox.showinfo("Report Exported", f"Report saved to:\n{filepath}")
        except Exception as exc:
            _mb_logger.warning("HTML export failed: %s", exc)

    # ====================== PROCESS TREE TAB ======================
    def _refresh_process_tree(self, data):
        w = self._ptree_text
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  🌳 PROCESS TREE — Parent → Child Relationships\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        procs = data.get('processes', [])
        if not procs:
            w.insert("end", "  No processes tracked yet.\n", "dim")
            w.config(state="disabled")
            return
        # Build tree: parent_pid -> [children]
        by_pid = {p['pid']: p for p in procs}
        children_map = defaultdict(list)
        roots = []
        for p in procs:
            parent = p.get('parent', '')
            parent_pid = None
            for op in procs:
                if op['name'] == parent and op['pid'] != p['pid']:
                    parent_pid = op['pid']
                    break
            if parent_pid and parent_pid in by_pid:
                children_map[parent_pid].append(p)
            else:
                roots.append(p)
        # Sort roots by risk
        roots.sort(key=lambda x: x.get('risk', 0), reverse=True)

        def _draw_tree(proc, prefix="", is_last=True):
            connector = "└── " if is_last else "├── "
            risk = proc.get('risk', 0)
            tag = 'critical' if risk > 50 else ('warning' if risk > 20 else 'default')
            star = " ★" if proc['name'].lower() in self._watchlist_procs else ""
            conns = proc.get('connections', 0)
            countries = ', '.join(proc.get('countries', [])) or '-'
            line = (f"{prefix}{connector}{proc['name']} (PID {proc['pid']}) "
                    f"risk={risk:.0f} conns={conns} geo=[{countries}]{star}\n")
            w.insert("end", line, tag)
            kids = children_map.get(proc['pid'], [])
            kids.sort(key=lambda x: x.get('risk', 0), reverse=True)
            new_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(kids):
                _draw_tree(child, new_prefix, i == len(kids) - 1)

        for i, root in enumerate(roots[:50]):
            _draw_tree(root, "  ", i == len(roots) - 1)
        w.insert("end", f"\n  Total: {len(procs)} processes tracked\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    # ====================== NETWORK STATS TAB ======================
    def _refresh_netstats(self, data):
        w = self._netstats_text
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  📊 NETWORK INTERFACE STATS — Real-time Bandwidth\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        iface_data = data.get('iface_stats', {})
        if not iface_data:
            w.insert("end", "  Collecting data... stats will appear after a few seconds.\n", "dim")
            w.config(state="disabled")
            return
        for iface, samples in sorted(iface_data.items()):
            if not samples:
                continue
            latest = samples[-1] if samples else {}
            sent_rate = latest.get('sent_rate', 0)
            recv_rate = latest.get('recv_rate', 0)
            total_sent = latest.get('total_sent', 0)
            total_recv = latest.get('total_recv', 0)
            errin = latest.get('errin', 0)
            errout = latest.get('errout', 0)
            dropin = latest.get('dropin', 0)
            dropout = latest.get('dropout', 0)
            w.insert("end", f"  ┌─ {iface} ", "subheader")
            w.insert("end", "─" * max(1, 90 - len(iface)) + "\n", "dim")
            w.insert("end", f"  │  ↑ Upload:   {self._fmt_bytes_rate(sent_rate)}  "
                            f"(Total: {self._fmt_bytes(total_sent)})\n", "info")
            w.insert("end", f"  │  ↓ Download: {self._fmt_bytes_rate(recv_rate)}  "
                            f"(Total: {self._fmt_bytes(total_recv)})\n", "cyan")
            w.insert("end", f"  │  Packets:    ↑{latest.get('packets_sent',0):,}  ↓{latest.get('packets_recv',0):,}\n")
            if errin or errout or dropin or dropout:
                w.insert("end", f"  │  Errors:     in={errin} out={errout}  "
                                f"Drops: in={dropin} out={dropout}\n", "warning")
            # Sparkline (last 30 samples)
            recent = samples[-30:] if len(samples) > 30 else samples
            if len(recent) >= 2:
                max_rate = max(max(s.get('sent_rate', 0), s.get('recv_rate', 0)) for s in recent) or 1
                spark_chars = "▁▂▃▄▅▆▇█"
                send_spark = ""
                recv_spark = ""
                for s in recent:
                    si = min(7, int(s.get('sent_rate', 0) / max_rate * 7))
                    ri = min(7, int(s.get('recv_rate', 0) / max_rate * 7))
                    send_spark += spark_chars[si]
                    recv_spark += spark_chars[ri]
                w.insert("end", f"  │  ↑ Trend:   {send_spark}\n", "info")
                w.insert("end", f"  │  ↓ Trend:   {recv_spark}\n", "cyan")
            w.insert("end", f"  └{'─' * 95}\n\n", "dim")
        # Per-IP bandwidth
        bw = data.get('conn_bandwidth', {})
        if bw:
            w.insert("end", "\n  TOP IPs BY BANDWIDTH\n", "subheader")
            w.insert("end", "  " + "─" * 95 + "\n", "dim")
            sorted_bw = sorted(bw.items(), key=lambda x: x[1].get('bytes_sent', 0) + x[1].get('bytes_recv', 0), reverse=True)
            for ip, info in sorted_bw[:20]:
                total = info.get('bytes_sent', 0) + info.get('bytes_recv', 0)
                star = " ★" if ip in self._watchlist_ips else ""
                w.insert("end", f"  {ip:>20}  ↑{self._fmt_bytes(info.get('bytes_sent',0)):>10}  "
                                f"↓{self._fmt_bytes(info.get('bytes_recv',0)):>10}  "
                                f"Total: {self._fmt_bytes(total):>10}{star}\n")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    @staticmethod
    def _fmt_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    @staticmethod
    def _fmt_bytes_rate(b):
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB/s"

    # ====================== CONNECTION TIMELINE TAB ======================
    def _refresh_timeline(self, data):
        w = self._timeline_text
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  ⏱️ CONNECTION TIMELINE — All Connections (Active + Closed)\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        timeline = data.get('conn_timeline', [])
        if not timeline:
            w.insert("end", "  No connection history yet.\n", "dim")
            w.config(state="disabled")
            return
        # Show most recent first
        for entry in reversed(timeline[-500:]):
            rip = entry.get('remote_ip', '?')
            rport = entry.get('remote_port', '?')
            pid = entry.get('pid', 0)
            status = entry.get('status', '?')
            active = entry.get('active', False)
            duration = entry.get('duration', 0)
            start = entry.get('start_time', 0)
            start_str = datetime.datetime.fromtimestamp(start).strftime("%H:%M:%S") if start else '?'
            dur_str = f"{int(duration)}s" if duration < 3600 else f"{duration/3600:.1f}h"
            star = " ★" if rip in self._watchlist_ips else ""
            if active:
                tag = 'info'
                state_icon = "🟢"
            else:
                tag = 'dim'
                state_icon = "⚪"
            w.insert("end", f"  {state_icon} {start_str}  {rip:>20}:{rport:<6}  "
                            f"PID {pid:<8} {status:<14} dur={dur_str:<8}{star}\n", tag)
        w.insert("end", f"\n  Total tracked: {len(timeline)} connections\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    # ====================== CONFIG EDITOR TAB ======================
    def _refresh_config(self):
        w = self._config_text
        # Only refresh once (static content) unless user hasn't seen it
        if hasattr(self, '_config_rendered') and self._config_rendered:
            return
        self._config_rendered = True
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  ⚙️ CURRENT CONFIGURATION\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        w.insert("end", "  To change values, edit medianbox_config.yaml and restart.\n", "dim")
        w.insert("end", "  Or set VT_API_KEY environment variable for VirusTotal.\n\n", "dim")
        # Export button
        export_btn = tk.Button(w, text=" 📄 Export HTML Report ", bg="#1a6b3f", fg="white",
                               font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
                               command=self._export_html_report)
        w.window_create("end", window=export_btn)
        w.insert("end", "\n\n")
        for key in sorted(CONFIG.keys()):
            val = CONFIG[key]
            if isinstance(val, set):
                val_str = str(sorted(val))
            else:
                val_str = str(val)
            w.insert("end", f"  {key:<40} = ", "cyan")
            w.insert("end", f"{val_str}\n")
        w.insert("end", "\n\n  WATCHLIST IPs: ", "subheader")
        w.insert("end", f"{', '.join(sorted(self._watchlist_ips)) or '(none)'}\n")
        w.insert("end", "  WATCHLIST Processes: ", "subheader")
        w.insert("end", f"{', '.join(sorted(self._watchlist_procs)) or '(none)'}\n")
        w.config(state="disabled")

    def _refresh_terminal(self, data):
        """Show 100% of all terminal output — appends only new lines for performance."""
        w = self._terminal_text
        lines = data.get('terminal_lines', [])
        new_count = len(lines)
        if new_count == self._terminal_last_count:
            # Still apply search highlighting even if no new lines
            search_q = self._search_terminal.get()
            if search_q and len(search_q) >= 2:
                w.config(state="normal")
                self._highlight_search(w, search_q)
                w.config(state="disabled")
            return
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        if self._terminal_last_count == 0:
            # First render — write header + all lines
            w.delete("1.0", "end")
            w.insert("end", "═" * 110 + "\n", "dim")
            w.insert("end", "  TERMINAL — 100% OF ALL PROCESSED OUTPUT\n", "header")
            w.insert("end", "═" * 110 + "\n\n", "dim")
        # Append only new lines since last refresh
        new_lines = lines[self._terminal_last_count:]
        for _ts, tag, text in new_lines:
            w.insert("end", text + "\n", tag)
        self._terminal_last_count = new_count
        self._highlight_search(w, self._search_terminal.get())
        w.config(state="disabled")
        # Only auto-scroll if user was at the bottom
        if at_bottom:
            w.see("end")
        else:
            w.yview_moveto(frac)

    def _on_close(self):
        # Save window geometry for multi-monitor persistence
        try:
            self._save_geometry()
        except Exception:
            pass
        # Final save
        try:
            self._save_tracer_data()
        except Exception as exc:
            _mb_logger.warning("Failed to save GNA tracer data: %s", exc)
        # Remove all firewall rules created by this session
        try:
            self._unblock_all()
        except Exception:
            pass
        self._stop.set()
        if self._update_job:
            self._root.after_cancel(self._update_job)
        if self._autosave_job:
            self._root.after_cancel(self._autosave_job)
        self._root.destroy()

    def _save_tracer_data(self):
        self._save_counter += 1
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filepath = os.path.join(desktop, f"GNA tracer data {self._save_counter}.txt")
        data = self._get_full_data()
        ts_now = datetime.datetime.now()
        ts = ts_now.strftime("%Y-%m-%d %H:%M:%S")
        start_ts = datetime.datetime.fromtimestamp(self._session_start).strftime("%Y-%m-%d %H:%M:%S")
        elapsed = time.time() - self._session_start
        hrs, rem = divmod(int(elapsed), 3600)
        mins, secs = divmod(rem, 60)
        runtime_str = f"{hrs}h {mins}m {secs}s"
        lines = []
        lines.append("=" * 120)
        lines.append(f"  GNA TRACER — COMPLETE OPERATIONS LOG #{self._save_counter}")
        lines.append(f"  Exported:      {ts}")
        lines.append(f"  Session Start: {start_ts}")
        lines.append(f"  Runtime:       {runtime_str} ({int(elapsed)}s total)")
        lines.append(f"  Save #:        {self._save_counter} (auto-saved every 10 min + on close)")
        lines.append("=" * 120)
        lines.append("")
        # Overview
        stats = data.get('conn_stats', {})
        lines.append("=" * 100)
        lines.append("── OVERVIEW ──")
        lines.append("=" * 100)
        lines.append(f"  Active Connections:  {stats.get('total_connections', 0)}")
        lines.append(f"  Unique Services:     {stats.get('unique_services', 0)}")
        lines.append(f"  Unique Public IPs:   {stats.get('unique_ips', 0)}")
        lines.append(f"  Tracked Processes:   {len(data.get('processes', []))}")
        lines.append(f"  Total Deductions:    {len(data.get('deductions', []))}")
        lines.append(f"  Network Devices:     {len(data.get('devices', []))}")
        lines.append(f"  Suspicious Events:   {len(data.get('suspicious_events', []))}")
        lines.append(f"  Terminal Lines:      {len(data.get('terminal_lines', []))}")
        lines.append(f"  DNS Cache:           {data.get('dns_count', 0)}")
        lines.append(f"  GeoIP Cache:         {data.get('geoip_count', 0)}")
        lines.append(f"  Pipeline:            {data.get('pipeline_processed', 0)} processed / {data.get('pipeline_dropped', 0)} dropped")
        proxy_conns = [c for c in data.get('connections', []) if c.get('proxy_type')]
        lines.append(f"  Proxy Connections:   {len(proxy_conns)}")
        proxy_procs = data.get('proxy_processes', [])
        if proxy_procs:
            lines.append(f"  Proxy Processes:     {', '.join(proxy_procs)}")
        lines.append("")
        # All connections individually
        lines.append("=" * 100)
        lines.append("── ALL CONNECTIONS (each individually) ──")
        lines.append("=" * 100)
        for idx, c in enumerate(data.get('connections', []), 1):
            lines.append(f"\n  [{idx}] {c.get('icon', '?')} {c.get('service', 'Unknown')}")
            lines.append(f"      Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})")
            lines.append(f"      Remote:      {c.get('remote_ip', '?')}:{c.get('remote_port', '?')}")
            lines.append(f"      Local Port:  {c.get('local_port', '?')}")
            lines.append(f"      Protocol:    {c.get('protocol', '?')} — Status: {c.get('status', '?')}")
            lines.append(f"      Domain:      {c.get('domain', 'unresolved')}")
            lines.append(f"      Country:     {c.get('country', '?')} ({c.get('country_code', '?')})")
            lines.append(f"      City:        {c.get('city', '?')}, Region: {c.get('region', '?')}")
            lines.append(f"      Org:         {c.get('org', '?')}")
            lines.append(f"      ISP:         {c.get('isp', '?')}")
            lines.append(f"      Coordinates: ({c.get('lat', 0):.4f}, {c.get('lon', 0):.4f})")
            loc_conf = c.get('loc_confidence', 0)
            loc_grade = c.get('loc_grade', 'UNVERIFIED')
            loc_proof = c.get('loc_proof', [])
            lines.append(f"      Location Verified: {loc_conf}% {loc_grade}")
            for proof in loc_proof:
                lines.append(f"        {proof}")
            proxy_type = c.get('proxy_type', '')
            if proxy_type:
                lines.append(f"      Proxy:       {proxy_type} — {c.get('proxy_detail', '')}")
            lines.append(f"      First Seen:  {_fmt_ts(c.get('first_seen', 0))}")
            lines.append(f"      Last Seen:   {_fmt_ts(c.get('last_seen', 0))}")
        # All deductions with full evidence
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL DEDUCTIONS (full evidence) ──")
        lines.append("=" * 100)
        for idx, d in enumerate(data.get('deductions', []), 1):
            lines.append(f"\n  Deduction #{idx}")
            lines.append(f"    Time:     {d.get('time', '?')}")
            lines.append(f"    Severity: {d.get('severity', '?')}")
            lines.append(f"    Category: {d.get('category', '?')}")
            lines.append(f"    Process:  {d.get('process', '?')} (PID {d.get('pid', '?')})")
            lines.append(f"    Score:    {d.get('score', 0)}")
            lines.append(f"    Message:  {d.get('message', '?')}")
            for ev in d.get('evidence', []):
                lines.append(f"      -> {ev}")
        # All processes
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL PROCESSES ──")
        lines.append("=" * 100)
        for p in data.get('processes', []):
            lines.append(f"\n  PID {p['pid']}: {p['name']}")
            lines.append(f"    Exe:          {p.get('exe', '?')}")
            lines.append(f"    Parent:       {p.get('parent', '?')}")
            lines.append(f"    Risk Score:   {p.get('risk', 0)}")
            lines.append(f"    Connections:  {p.get('connections', 0)}")
            lines.append(f"    Destinations: {p.get('destinations', 0)}")
            lines.append(f"    ML Anomaly:   {p.get('ml_score', 0)}")
            lines.append(f"    Countries:    {', '.join(p.get('countries', []))}")
        # All devices
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL DEVICES ──")
        lines.append("=" * 100)
        for d in data.get('devices', []):
            lines.append(f"\n  {d.get('ip', '?')} — {d.get('mac', '?')}")
            lines.append(f"    Vendor:     {d.get('vendor', '?')}")
            lines.append(f"    Hostname:   {d.get('hostname', '?')}")
            lines.append(f"    OS Guess:   {d.get('os_guess', '?')}")
            lines.append(f"    Confidence: {d.get('confidence', 0):.2f}")
        # ALL raw actions — no caps (complete log)
        lines.append("")
        lines.append("=" * 100)
        lines.append("── COMPLETE RAW ACTIONS LOG (ALL, NO CAPS) ──")
        lines.append("=" * 100)
        for act in data.get('all_actions', []):
            lines.append(f"  {act}")
        # Map data
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL IPs WITH GEOLOCATION ──")
        lines.append("=" * 100)
        for pt in data.get('map_points', []):
            lines.append(f"  {pt.get('ip', '?')} — {pt.get('service', '?')} | "
                         f"{pt.get('city', '?')}, {pt.get('country', '?')} | "
                         f"({pt.get('lat', 0):.4f}, {pt.get('lon', 0):.4f}) | "
                         f"{pt.get('org', '?')} | Process: {pt.get('process', '?')}")
        # Suspicious activity events
        lines.append("")
        lines.append("=" * 100)
        lines.append("── SUSPICIOUS ACTIVITY (OUT-OF-NORM ONLY) ──")
        lines.append("=" * 100)
        susp_events = data.get('suspicious_events', [])
        if not susp_events:
            lines.append("  No suspicious activity detected.")
        for ev in susp_events:
            lines.append(f"\n  [{ev.get('severity', '?')}] [{ev.get('category', '?')}] {ev.get('time', '?')}")
            lines.append(f"    Description: {ev.get('description', '?')}")
            lines.append(f"    Process:     {ev.get('process', '?')} (PID {ev.get('pid', '?')})")
            for detail in ev.get('details', []):
                lines.append(f"      → {detail}")
        # ── TIER 5 DATA ──
        # VirusTotal results
        vt_results = data.get('vt_results', {})
        if vt_results:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── VIRUSTOTAL SCAN RESULTS ──")
            lines.append("=" * 100)
            for sha, r in vt_results.items():
                mal = r.get('malicious', 0)
                tag = " *** MALICIOUS ***" if mal > 0 else ""
                lines.append(f"  SHA256: {sha}{tag}")
                lines.append(f"    Malicious: {mal}  Suspicious: {r.get('suspicious', 0)}  "
                             f"Harmless: {r.get('harmless', 0)}  Undetected: {r.get('undetected', 0)}")
                if r.get('name'):
                    lines.append(f"    Name: {r['name']}")
        # File system events
        fs_events = data.get('fs_events', [])
        if fs_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── FILE SYSTEM WATCHDOG EVENTS ──")
            lines.append("=" * 100)
            for ev in fs_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
                if ev.get('path'):
                    lines.append(f"    Path: {ev['path']}")
        # Clipboard events
        clip_events = data.get('clipboard_events', [])
        if clip_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── CLIPBOARD MONITOR EVENTS ──")
            lines.append("=" * 100)
            for ev in clip_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
        # USB events
        usb_events = data.get('usb_events', [])
        if usb_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── USB DEVICE EVENTS ──")
            lines.append("=" * 100)
            for ev in usb_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Scheduled task events
        task_events = data.get('sched_task_events', [])
        if task_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── SCHEDULED TASK CHANGES ──")
            lines.append("=" * 100)
            for ev in task_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
        # Named pipe events
        pipe_events = data.get('named_pipe_events', [])
        if pipe_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── NAMED PIPE / IPC EVENTS ──")
            lines.append("=" * 100)
            for ev in pipe_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Inbound scan events
        scan_events = data.get('inbound_scan_events', [])
        if scan_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── INBOUND PORT SCAN DETECTIONS ──")
            lines.append("=" * 100)
            for ev in scan_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
                lines.append(f"    Ports probed: {ev.get('ports_probed', [])}")
        # DoH detections
        doh_events = data.get('doh_events', [])
        if doh_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── DNS-OVER-HTTPS (DoH) DETECTIONS ──")
            lines.append("=" * 100)
            for ev in doh_events:
                lines.append(f"  {ev.get('detail', '?')}")
        # TLS cert / MITM events
        cert_events = data.get('cert_events', [])
        if cert_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── TLS CERTIFICATE / MITM EVENTS ──")
            lines.append("=" * 100)
            for ev in cert_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Connection timeline with durations
        timeline = data.get('conn_timeline', [])
        if timeline:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── CONNECTION TIMELINE (Active + Closed, with Duration) ──")
            lines.append("=" * 100)
            for entry in timeline[-1000:]:
                rip = entry.get('remote_ip', '?')
                rport = entry.get('remote_port', '?')
                pid = entry.get('pid', 0)
                active = entry.get('active', False)
                duration = entry.get('duration', 0)
                start = entry.get('start_time', 0)
                start_str = _fmt_ts(start)
                dur_str = f"{int(duration)}s" if duration < 3600 else f"{duration/3600:.1f}h"
                state = "ACTIVE" if active else "CLOSED"
                lines.append(f"  [{state:6}] {start_str}  {rip}:{rport}  PID {pid}  dur={dur_str}")
        # Network interface bandwidth
        iface_data = data.get('iface_stats', {})
        if iface_data:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── NETWORK INTERFACE BANDWIDTH ──")
            lines.append("=" * 100)
            for iface, samples in sorted(iface_data.items()):
                if samples:
                    latest = samples[-1]
                    lines.append(f"  {iface}: ↑{latest.get('total_sent',0)/1024/1024:.1f} MB sent  "
                                 f"↓{latest.get('total_recv',0)/1024/1024:.1f} MB recv  "
                                 f"pkts: ↑{latest.get('packets_sent',0)}  ↓{latest.get('packets_recv',0)}  "
                                 f"errs: {latest.get('errin',0)}/{latest.get('errout',0)}")
        # Bluetooth devices
        bt_devs = data.get('bt_devices', [])
        if bt_devs:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── BLUETOOTH DEVICES ──")
            lines.append("=" * 100)
            for bt in bt_devs:
                lines.append(f"  {bt.get('name', '?')}  Type: {bt.get('type', '?')}  ID: {bt.get('device_id', '?')}")
        bt_events = data.get('bt_events', [])
        if bt_events:
            lines.append("")
            lines.append("── BLUETOOTH EVENTS ──")
            for ev in bt_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Serial / COM ports
        serial_ports = data.get('serial_ports', [])
        if serial_ports:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── SERIAL / COM PORTS ──")
            lines.append("=" * 100)
            for sp in serial_ports:
                lines.append(f"  {sp.get('port', '?')}  Device: {sp.get('device', '?')}")
        serial_events = data.get('serial_events', [])
        if serial_events:
            lines.append("")
            lines.append("── SERIAL PORT EVENTS ──")
            for ev in serial_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Full terminal output (100%)
        lines.append("")
        lines.append("=" * 100)
        lines.append("── FULL TERMINAL OUTPUT (100%) ──")
        lines.append("=" * 100)
        for _ts, _tag, text in data.get('terminal_lines', []):
            lines.append(f"  {text}")
        # Footer
        lines.append("")
        lines.append("=" * 120)
        lines.append(f"  END OF LOG #{self._save_counter} — Runtime: {runtime_str} — {ts}")
        lines.append("=" * 120)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        _mb_logger.info("GNA tracer data saved to %s (save #%d, runtime %s)", filepath, self._save_counter, runtime_str)


def _fmt_ts(ts):
    if not ts or ts == 0:
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _check_token(request, token: str) -> bool:
    """Validate bearer token from query param or Authorization header."""
    if request.query_params.get('token') == token:
        return True
    auth = request.headers.get('authorization', '')
    return bool(auth.startswith('Bearer ') and auth[7:] == token)


def start_dashboard(get_state_fn, stop_event):
    """Run the FastAPI dashboard (blocking — call from a daemon thread)."""
    if not HAS_FASTAPI:
        _mb_logger.info("FastAPI not installed — dashboard disabled")
        return
    if not CONFIG.get('dashboard_enabled'):
        return

    from fastapi.responses import PlainTextResponse
    from starlette.requests import Request

    app = FastAPI(title="MedianBoxMonitor Dashboard")
    auth_token = CONFIG.get('dashboard_password', '')

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        if auth_token and not _check_token(request, auth_token):
            return PlainTextResponse("401 Unauthorized — append ?token=YOUR_PASSWORD", status_code=401)
        return DASHBOARD_HTML

    @app.get("/api/state")
    async def api_state(request: Request):
        if auth_token and not _check_token(request, auth_token):
            return PlainTextResponse("401 Unauthorized", status_code=401)
        return JSONResponse(get_state_fn())

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        import asyncio
        if auth_token:
            ws_token = websocket.query_params.get('token', '')
            if ws_token != auth_token:
                await websocket.close(code=4001, reason="Unauthorized")
                return
        await websocket.accept()
        try:
            while not stop_event.is_set():
                state = get_state_fn()
                await websocket.send_json(state)
                await asyncio.sleep(3)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            _mb_logger.debug("WebSocket error: %s", exc)

    if auth_token:
        _mb_logger.info("Dashboard authentication enabled (token required)")

    try:
        uvicorn.run(app, host="127.0.0.1", port=CONFIG['dashboard_port'],
                    log_level="warning")
    except Exception as e:
        _mb_logger.warning("Dashboard failed: %s", e)


# ========================== MAIN MONITOR CLASS ==========================
class MedianBoxMonitor:
    def __init__(self, args):
        self.args = args
        self.lock = threading.RLock()
        self.local_ip, self.subnet, self.network = self._detect_subnet()

        # Terminal output buffer — captures 100% of all _log output
        self.terminal_buffer: deque = deque(maxlen=10000)

        # Database
        self.db = DatabaseManager()

        # Original LAN tracking
        self.devices = {}
        self.seen_composites = set()
        self.remote_sessions = {}
        self.probe_attempts = defaultdict(int)
        self.flow_stats = defaultdict(lambda: deque(maxlen=400))
        self.mac_to_ip_history = defaultdict(set)
        self.last_alert = defaultdict(float)

        # Connection cache — populated by dedicated mapper thread
        self.conn_by_pid: dict[int, list] = defaultdict(list)
        self.conn_by_raddr: dict[str, tuple] = {}
        self.conn_cache_lock = threading.Lock()

        # Deductive Chess Engine v2
        self.dns_cache = DNSCache()
        self.dns_cache.load_history()
        self.beacon_detector = BeaconDetector()
        self.process_profiles: dict[int, ProcessProfile] = {}
        self.process_actions = defaultdict(list)
        self.deductions: deque = deque(maxlen=2000)
        self.deduction_cooldowns: dict[str, float] = {}

        # Suspicious activity buffer — ONLY out-of-norm / anomalous events
        self.suspicious_events: deque = deque(maxlen=5000)

        # Behavioral baselines keyed by process NAME
        self.name_baselines: dict[str, dict] = defaultdict(lambda: {
            'typical_dsts': set(),
            'dst_count_samples': deque(maxlen=200),
            'pkt_rate_samples': deque(maxlen=200),
            'samples': 0,
        })

        # Hardware / user-activity correlation
        self.audio_active_pids: set[int] = set()
        self.camera_active_pids: set[int] = set()
        self.user_activity_ts: float = 0.0

        # Pre-parsed known IP ranges
        self.known_ranges: dict[str, list] = {}
        for svc, cidrs in KNOWN_SERVICE_RANGES.items():
            self.known_ranges[svc] = [ipaddress.ip_network(c, strict=False) for c in cidrs]

        # Tier 1
        self.sni_extractor = SNIExtractor()
        self.dns_tunnel_detector = DNSTunnelingDetector()
        self.entropy_analyzer = EntropyAnalyzer()

        # Tier 2
        self.geoip = GeoIPCache()
        self.registry_monitor = RegistryMonitor()
        self.user_idle = UserIdleMonitor()
        self.registry_baseline_set = False

        # Tier 3
        self.escalation = AlertEscalation()
        self.siem = SIEMOutput()
        self.slog = setup_structured_logging()

        # Tier 4
        self.ml_baseline = StatisticalBaseline()
        self.ja4plus = JA4Plus()

        # Tier 5 — New detectors
        self.vt_checker = VirusTotalChecker()
        self.fs_watchdog = FileSystemWatchdog()
        self.clipboard_monitor = ClipboardMonitor()
        self.usb_monitor = USBMonitor()
        self.sched_task_monitor = ScheduledTaskMonitor()
        self.named_pipe_monitor = NamedPipeMonitor()
        self.whois_lookup = WhoisLookup()
        self.inbound_scan_detector = InboundScanDetector()
        self.doh_detector = DoHDetector()
        self.tls_cert_detector = TLSCertDetector()
        self.conn_history = ConnectionHistory()
        self.bt_scanner = BluetoothScanner()
        self.serial_scanner = SerialPortScanner()
        self.proxy_detector = ProxyDetector()

        # Watchlist / Favorites
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()

        # Network interface bandwidth tracking
        self._iface_stats_prev: dict[str, tuple] = {}
        self._iface_stats_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=120))

        # Admin check
        self._admin_mode = True
        try:
            psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self._admin_mode = False

        self.stop = threading.Event()

        # Packet pipeline (queue-based async processing)
        self.pipeline = PacketPipeline(
            handler=self._packet_callback,
            stop_event=self.stop,
        )

        # Shared connection snapshot (written by _connection_mapper, read by inventory + process watcher)
        self._conn_snapshot = []
        self._conn_snapshot_lock = threading.Lock()

        # Service resolver + Connection inventory (reads from shared snapshot)
        self.service_resolver = ServiceResolver()
        self.conn_inventory = ConnectionInventory(
            dns_cache=self.dns_cache,
            geoip=self.geoip,
            service_resolver=self.service_resolver,
            stop_event=self.stop,
            conn_provider=self._get_conn_snapshot,
        )

        self._print_banner()

    # ====================== BANNER ======================
    def _print_banner(self):
        self._log(f"{Colors.G}{EMOJI['brain']} MedianBoxMonitor 3.0 — MODULAR DEDUCTIVE CHESS ENGINE{Colors.END}")
        self._log(f"Monitoring: {self.local_ip} -> {self.subnet}")
        cap = [
            'DNS-chess', 'SNI-extract', 'Beacon-detect', 'Legitimacy-check',
            'Phantom-hunt', 'DNS-tunnel-detect', 'Entropy-analysis', 'Exfil-detect',
        ]
        if _IS_WINDOWS:
            cap.extend(['DLL-inspect', 'Registry-monitor', 'User-idle', 'Memory-forensics'])
        cap.extend(['GeoIP-enrich', 'Statistical-baseline', 'JA4+', 'Alert-escalation',
                     'Queue-pipeline'])
        if CONFIG['siem_output']:
            cap.append(f"SIEM-{CONFIG['siem_output']}")
        if HAS_FASTAPI and CONFIG['dashboard_enabled']:
            cap.append(f"Dashboard:{CONFIG['dashboard_port']}")
        if not self._admin_mode:
            self._log(f"{Colors.Y}Running without admin — reduced capability{Colors.END}")
        self._log(f"{Colors.M}Capabilities: {' | '.join(cap)}{Colors.END}")

    # ====================== LOGGING ======================
    _ANSI_RE = re.compile(r'\033\[[0-9;]*m')

    def _log(self, msg, color=Colors.Y):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {color}{msg}{Colors.END}"
        print(line)
        # Capture to terminal buffer with color tag for GUI
        clean = self._ANSI_RE.sub('', line)
        tag = 'critical' if color == Colors.R else ('warning' if color == Colors.Y else (
            'info' if color == Colors.G else 'default'))
        with self.lock:
            self.terminal_buffer.append((ts, tag, clean))

    def _safe_alert(self, msg, color=Colors.R):
        key = msg.split('\u2192')[0].strip() if '\u2192' in msg else msg[:60]
        now = time.time()
        with self.lock:
            if now - self.last_alert.get(key, 0) > CONFIG['alert_cooldown']:
                self.last_alert[key] = now
                self._log(msg, color=color)

    # Keywords that mark a _write_action as suspicious (auto-flagged)
    _SUSPICIOUS_ACTION_KW = {
        'NETWORK_FLOW': 'DATA_ACCESS',
        'DEDUCTION_': 'DEDUCTION',
    }
    _SUSPICIOUS_EXTRA_KW = [
        ('cookie', 'COOKIE_TRACKING', 'Process is sending/receiving tracking cookies'),
        ('upload', 'DATA_UPLOAD', 'Process is uploading data'),
        ('exfil', 'DATA_EXFIL', 'Potential data exfiltration detected'),
        ('credential', 'CREDENTIAL_ACCESS', 'Process accessing credentials'),
        ('password', 'CREDENTIAL_ACCESS', 'Process accessing password data'),
        ('token', 'TOKEN_ACCESS', 'Process accessing authentication tokens'),
        ('clipboard', 'CLIPBOARD_ACCESS', 'Process accessing clipboard data'),
        ('keylog', 'KEYLOGGER', 'Possible keylogger behavior detected'),
        ('screenshot', 'SCREEN_CAPTURE', 'Process performing screen capture'),
        ('inject', 'CODE_INJECTION', 'Process injection activity detected'),
        ('hook', 'API_HOOK', 'Process hooking system APIs'),
        ('encrypt', 'ENCRYPTION', 'Process performing encryption (possible ransomware)'),
        ('decrypt', 'ENCRYPTION', 'Process performing decryption'),
        ('powershell', 'SCRIPT_EXEC', 'PowerShell execution detected'),
        ('cmd.exe', 'SCRIPT_EXEC', 'Command shell execution detected'),
        ('wscript', 'SCRIPT_EXEC', 'Windows Script Host execution'),
        ('cscript', 'SCRIPT_EXEC', 'Console Script Host execution'),
        ('regsvr', 'DLL_REGISTER', 'DLL registration activity'),
        ('schtask', 'SCHEDULED_TASK', 'Scheduled task manipulation'),
        ('rdp', 'REMOTE_ACCESS', 'Remote Desktop Protocol activity'),
        ('vnc', 'REMOTE_ACCESS', 'VNC remote access activity'),
        ('ssh', 'REMOTE_ACCESS', 'SSH remote access activity'),
        ('telnet', 'REMOTE_ACCESS', 'Telnet remote access activity'),
        ('wake-on-lan', 'REMOTE_POWER', 'Wake-on-LAN (remote power on)'),
        ('shutdown', 'REMOTE_POWER', 'Remote shutdown command detected'),
        ('restart', 'REMOTE_POWER', 'Remote restart command detected'),
        ('microphone', 'HARDWARE_ACCESS', 'Microphone access detected'),
        ('camera', 'HARDWARE_ACCESS', 'Camera access detected'),
        ('webcam', 'HARDWARE_ACCESS', 'Webcam access detected'),
        ('audiodg', 'HARDWARE_ACCESS', 'Audio device graph isolation active'),
        ('temp\\\\', 'TEMP_EXECUTION', 'Process running from temp directory'),
        ('appdata', 'SUSPICIOUS_PATH', 'Process running from AppData'),
        ('downloads\\\\', 'SUSPICIOUS_PATH', 'Process running from Downloads'),
    ]

    def _flag_suspicious(self, category: str, severity: str, process: str,
                         pid: int, description: str, details: list):
        """Record a suspicious/anomalous event — ONLY out-of-norm behavior."""
        ts = time.time()
        event = {
            'timestamp': ts,
            'time': datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            'category': category,
            'severity': severity,
            'process': process,
            'pid': pid,
            'description': description,
            'details': details,
        }
        with self.lock:
            self.suspicious_events.append(event)

    def _auto_flag_action(self, pid, name, action, extra):
        """Check if an action matches suspicious patterns and auto-flag it."""
        combined = f"{action} {extra}".lower()
        for keyword, cat, desc in self._SUSPICIOUS_EXTRA_KW:
            if keyword in combined or keyword in name.lower():
                self._flag_suspicious(cat, "WARNING", name, pid, desc,
                    [f"Action: {action}", f"Detail: {extra}",
                     f"Process: {name} (PID {pid})",
                     f"Matched keyword: '{keyword}'"])
                return

    def _write_action(self, pid, name, action, extra=""):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{ts} | {name} (PID {pid}) | {action} {extra}"
        logging.getLogger('medianbox.actions').info(entry)
        with self.lock:
            self.process_actions[pid].append((time.time(), name, action, extra))
        # Auto-detect suspicious actions
        self._auto_flag_action(pid, name, action, extra)

    def _write_deduction_log(self, d: Deduction):
        ts = datetime.datetime.fromtimestamp(d.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        entry = (f"{ts} | [{d.severity}] [{d.category}] {d.process_name} (PID {d.pid}) | "
                 f"{d.message} | score={d.score:.1f} | evidence={d.evidence}")
        logging.getLogger('medianbox.deductions').info(entry)

    # ====================== SUBNET DETECTION ======================
    def _detect_subnet(self):
        for _iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith('127') and a.netmask:
                    try:
                        net = ipaddress.IPv4Interface(f"{a.address}/{a.netmask}").network
                        return a.address, str(net), net
                    except Exception:
                        continue
        return "192.168.1.100", "192.168.1.0/24", ipaddress.IPv4Network("192.168.1.0/24")

    # ====================== HELPERS ======================
    def _is_public_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    def _composite_key(self, mac, ip):
        return hashlib.sha256(f"{mac or 'nomac'}:{ip or 'noip'}".encode()).hexdigest()[:16]

    def _extract_hostname(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                return pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
            except Exception as exc:
                _mb_logger.debug("Hostname extract error: %s", exc)
        if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    return opt[1].decode(errors='ignore')
        return None

    def _passive_os(self, pkt):
        if not pkt.haslayer(TCP) or not (pkt[TCP].flags & 0x02):
            return "Unknown"
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else (pkt[IPv6].hlim if pkt.haslayer(IPv6) else 64)
        win = pkt[TCP].window
        if 50 <= ttl <= 70 and win >= 5000:
            return "Linux 5.x/6.x"
        if 110 <= ttl <= 130 and win <= 12000:
            return "Windows 10/11"
        if ttl >= 200:
            return "macOS/BSD"
        return "Unknown/other"

    # ====================== DEDUCTIVE CHESS ENGINE v2 ======================
    def _add_deduction(self, severity, category, proc_name, pid, message, evidence, score):
        cooldown_key = f"{category}:{pid}:{hash(message[:80])}"
        now = time.time()
        with self.lock:
            if now - self.deduction_cooldowns.get(cooldown_key, 0) < CONFIG['deduction_cooldown']:
                return
            self.deduction_cooldowns[cooldown_key] = now

        multiplier = self.escalation.get_multiplier(pid)
        escalated_score = score * multiplier
        self.escalation.record(pid, escalated_score)
        if multiplier > 1.0:
            evidence.append(f"{EMOJI['escalate']} ESCALATED x{multiplier:.1f} ({score:.0f} -> {escalated_score:.0f})")
            if severity == "WARNING" and escalated_score >= 50:
                severity = "CRITICAL"

        d = Deduction(now, severity, category, proc_name, pid, message, evidence, escalated_score)
        with self.lock:
            self.deductions.append(d)
            if pid in self.process_profiles:
                self.process_profiles[pid].risk_score += escalated_score
                self.process_profiles[pid].risk_reasons.append(f"[{category}] {message}")
                self.process_profiles[pid].escalation_hits += 1

        emoji_map = {
            "MIMIC": EMOJI['mimic'], "BEACON": EMOJI['beacon'],
            "PHANTOM": EMOJI['phantom'], "IMPERSONATION": EMOJI['impersonate'],
            "FOREIGN": EMOJI['foreign'], "ANOMALY": EMOJI['anomaly'],
            "INJECTION": EMOJI['inject'], "TUNNEL": EMOJI['tunnel'],
            "EXFIL": EMOJI['exfil'], "ENTROPY": EMOJI['entropy'],
            "DLL": EMOJI['dll'], "PERSISTENCE": EMOJI['persist'],
            "IDLE_ANOMALY": EMOJI['idle'], "ML_ANOMALY": EMOJI['ml'],
        }
        icon = emoji_map.get(category, EMOJI['chess'])
        color = Colors.R if severity == "CRITICAL" else Colors.Y

        self._log(f"{icon} [{severity}] {message}", color=color)
        for e in evidence:
            self._log(f"    -> {e}", color=Colors.C)

        log_level = logging.CRITICAL if severity == "CRITICAL" else (
            logging.WARNING if severity == "WARNING" else logging.INFO)
        self.slog.log(log_level, f"[{category}] {message} | pid={pid} score={escalated_score:.1f}")

        self._write_action(pid, proc_name, f"DEDUCTION_{category}", message)
        self._write_deduction_log(d)
        self.db.save_deduction(d)
        self.siem.emit(d)
        # Every deduction is a suspicious event
        self._flag_suspicious(category, severity, proc_name, pid, message, list(evidence))

    # ---------- DEDUCTION 1: Mimic Traffic ----------
    def _check_mimic(self, profile, dst_ip, domains):
        all_idents = {d.lower() for d in domains}
        all_idents.add(dst_ip)
        for service, keywords in MIMIC_KEYWORDS.items():
            if any(kw in ident for kw in keywords for ident in all_idents):
                app_running = any(
                    service in p.name.lower()
                    for p in self.process_profiles.values()
                    if p.pid != profile.pid)
                if ALLOWED_APPS.get(service) and not app_running:
                    continue
                if not app_running:
                    suspicion = 30.0
                    evidence = [
                        f"Traffic matches '{service}' (keywords: {keywords})",
                        f"But NO '{service}' process is running",
                        f"Destinations: {', '.join(list(profile.destinations)[:5])}",
                        f"Process: {profile.name} (PID {profile.pid}, exe={profile.exe_path})",
                    ]
                    self._add_deduction("WARNING", "MIMIC", profile.name, profile.pid,
                        f"MIMIC: '{profile.name}' imitates '{service}' traffic "
                        f"(suspicion={suspicion:.0f})", evidence, suspicion)

    # ---------- DEDUCTION 2: Foreign Influence ----------
    def _check_foreign(self, profile, dst_ip, domains):
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if not ip_obj.is_global:
                return
        except Exception:
            return
        proc_lower = profile.name.lower()
        for service, ranges in self.known_ranges.items():
            if service not in proc_lower:
                continue
            in_range = any(ip_obj in net for net in ranges)
            if not in_range:
                domain_str = ', '.join(domains) if domains else 'no resolved domain'
                recent_cpu = any(c > 2 for c in list(profile.cpu_samples)[-10:])
                evidence = [
                    f"'{profile.name}' claims to be '{service}' service",
                    f"Destination {dst_ip} ({domain_str}) NOT in known {service} IP ranges",
                    f"User CPU activity: {'yes' if recent_cpu else 'NONE'}",
                    f"Process exe: {profile.exe_path}",
                ]
                score = 25.0 if not recent_cpu else 15.0
                self._add_deduction("WARNING", "FOREIGN", profile.name, profile.pid,
                    f"FOREIGN: '{profile.name}' -> {dst_ip} ({domain_str}) "
                    f"outside known {service} infrastructure", evidence, score)
            break

    # ---------- DEDUCTION 3: Behavioral Anomaly ----------
    def _check_behavioral_anomaly(self, profile, dst_ip):
        name_lower = profile.name.lower()
        bl = self.name_baselines[name_lower]
        if bl['samples'] >= CONFIG['baseline_min_samples']:
            new_dsts = profile.destinations - bl['typical_dsts']
            if len(new_dsts) > 3:
                evidence = [
                    f"Baseline: {len(bl['typical_dsts'])} typical dests over {bl['samples']} samples",
                    f"{len(new_dsts)} NEW destinations: {', '.join(list(new_dsts)[:8])}",
                    f"Domains: {', '.join(profile.dns_domains)}",
                ]
                self._add_deduction("WARNING", "ANOMALY", profile.name, profile.pid,
                    f"BEHAVIORAL SHIFT: '{profile.name}' suddenly has "
                    f"{len(new_dsts)} new destinations", evidence, 20.0)
        bl['typical_dsts'].update(profile.destinations)
        bl['dst_count_samples'].append(len(profile.destinations))
        bl['samples'] += 1

    # ---------- DEDUCTION 4: Beacon Detection ----------
    def _check_beacon(self, profile):
        if len(profile.packet_timestamps) < CONFIG['beacon_min_samples']:
            return
        is_beacon, confidence, desc = self.beacon_detector.analyze(profile.packet_timestamps)
        if is_beacon and confidence > 0.4:
            evidence = [desc, f"Destinations: {', '.join(list(profile.destinations)[:6])}",
                        f"Exe: {profile.exe_path}", f"Connections: {profile.connection_count}"]
            sev = "CRITICAL" if confidence > 0.7 else "WARNING"
            self._add_deduction(sev, "BEACON", profile.name, profile.pid,
                f"C2 BEACON: '{profile.name}' automated callback (confidence={confidence:.0%})",
                evidence, confidence * 55)

    # ---------- DEDUCTION 5: Process Impersonation ----------
    def _check_impersonation(self, profile, proc):
        if profile.checked_legitimacy:
            return
        profile.checked_legitimacy = True
        reasons = ProcessLegitimacyChecker.check_all(proc)
        for reason in reasons:
            self._add_deduction("CRITICAL", "IMPERSONATION", profile.name, profile.pid,
                f"IMPERSONATION: {reason}",
                [reason, f"Exe: {profile.exe_path}",
                 f"Parent: {profile.parent_name} (PID {profile.parent_pid})"], 45.0)

    # ---------- DEDUCTION 6: Phantom Connections ----------
    def _check_phantoms(self, active_pids):
        try:
            with self._conn_snapshot_lock:
                snapshot = list(self._conn_snapshot)
            for conn in snapshot:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.pid is None or conn.pid == 0 or conn.pid not in active_pids:
                        dst_ip = conn.raddr[0]
                        domains = self.dns_cache.get_domains(dst_ip)
                        evidence = [
                            f"Connection: {conn.laddr} -> {conn.raddr}",
                            f"PID: {conn.pid or 'NONE'} — not in active process list",
                            f"Domains: {', '.join(domains) if domains else 'unknown'}",
                        ]
                        self._add_deduction("CRITICAL", "PHANTOM", "UNKNOWN", conn.pid or 0,
                            f"PHANTOM: {conn.laddr} -> {conn.raddr} — "
                            f"{'no owning process' if not conn.pid else f'PID {conn.pid} missing'}",
                            evidence, 50.0)
        except psutil.AccessDenied:
            pass
        except Exception as exc:
            _mb_logger.debug("Phantom check error: %s", exc)

    # ---------- DEDUCTION 7: Injection Chain ----------
    def _check_injection_chain(self, profile):
        if not profile.parent_name:
            return
        parent_lower = profile.parent_name.lower()
        name_lower = profile.name.lower()
        known_apps = {"chrome.exe", "firefox.exe", "msedge.exe", "explorer.exe",
                      "zoom.exe", "teams.exe", "discord.exe", "slack.exe"}
        if parent_lower in known_apps and name_lower not in known_apps and profile.connection_count > 2:
            evidence = [
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Child: {profile.name} (PID {profile.pid})",
                f"Child has {profile.connection_count} INDIVIDUAL network connections:",
            ]
            with self.conn_cache_lock:
                pid_conns = list(self.conn_by_pid.get(profile.pid, []))
            for idx, conn in enumerate(pid_conns, 1):
                if conn.raddr:
                    dst_ip = conn.raddr[0]
                    dst_port = conn.raddr[1]
                    local_port = conn.laddr[1] if conn.laddr else 0
                    domains = self.dns_cache.get_domains(dst_ip)
                    svc_info = self.service_resolver.identify(dst_ip, domains)
                    svc_name = svc_info.get('service', 'Unknown')
                    domain_str = ', '.join(domains) if domains else 'unresolved'
                    geo_country = self.geoip.get_country(dst_ip) if self._is_public_ip(dst_ip) else 'LAN'
                    geo_org = self.geoip.get_org(dst_ip) if self._is_public_ip(dst_ip) else 'Local'
                    evidence.append(
                        f"  [{idx}] {dst_ip}:{dst_port} (local:{local_port}) | "
                        f"service={svc_name} | domain={domain_str} | "
                        f"country={geo_country} | org={geo_org} | status={conn.status}"
                    )
            if not pid_conns:
                for dst_ip in list(profile.destinations):
                    domains = self.dns_cache.get_domains(dst_ip)
                    domain_str = ', '.join(domains) if domains else 'unresolved'
                    evidence.append(f"  -> {dst_ip} | domain={domain_str}")
            self._add_deduction("WARNING", "INJECTION", profile.name, profile.pid,
                f"INJECTION CHAIN: '{profile.parent_name}' spawned '{profile.name}' "
                f"which has {profile.connection_count} connections (each listed below)",
                evidence, 30.0)

    # ---------- DEDUCTION 8: DNS Tunneling ----------
    def _check_dns_tunnel(self, qname, src_ip):
        is_tunnel, score, evidence = self.dns_tunnel_detector.analyze_query(qname)
        if is_tunnel:
            self._add_deduction("CRITICAL", "TUNNEL", "DNS", 0,
                f"DNS TUNNELING: suspicious query '{qname[:80]}...' from {src_ip}",
                evidence, score)

    # ---------- DEDUCTION 9: Data Exfiltration ----------
    def _check_exfil(self, profile, proc):
        try:
            io_counters = proc.io_counters()
            now = time.time()
            if profile.io_snapshot_time > 0:
                dt = now - profile.io_snapshot_time
                if dt > 0:
                    sent_rate = (io_counters.write_bytes - profile.io_baseline_sent) / dt
                    self.ml_baseline.record(profile.name.lower(), profile.connection_count,
                        len(profile.destinations), sent_rate,
                        statistics.mean(profile.cpu_samples) if profile.cpu_samples else 0)
                    if (sent_rate > CONFIG['exfil_min_bytes'] / 60 and
                            io_counters.write_bytes - profile.io_baseline_sent > CONFIG['exfil_min_bytes']):
                        evidence = [
                            f"Send rate: {sent_rate/1024:.0f} KB/s",
                            f"Total sent: {(io_counters.write_bytes - profile.io_baseline_sent)/1024/1024:.1f} MB",
                            f"Destinations: {', '.join(list(profile.destinations)[:5])}",
                        ]
                        idle_sec = self.user_idle.get_idle_seconds()
                        if idle_sec > CONFIG['user_idle_threshold']:
                            evidence.append(f"User idle for {idle_sec:.0f}s")
                        self._add_deduction("CRITICAL", "EXFIL", profile.name, profile.pid,
                            f"DATA EXFILTRATION: '{profile.name}' uploading {sent_rate/1024:.0f} KB/s",
                            evidence, 40.0)
            with self.lock:
                profile.io_baseline_sent = io_counters.write_bytes
                profile.io_baseline_recv = io_counters.read_bytes
                profile.io_snapshot_time = now
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # ---------- DEDUCTION 10: DLL Injection ----------
    def _check_dlls(self, profile, proc):
        if profile.checked_dlls or not _IS_WINDOWS:
            return
        profile.checked_dlls = True
        suspicious = DLLInspector.inspect(proc)
        if suspicious:
            profile.loaded_dlls = suspicious
            evidence = [f"Suspicious DLL: {dll}" for dll in suspicious[:10]]
            self._add_deduction("CRITICAL", "DLL", profile.name, profile.pid,
                f"DLL INJECTION: '{profile.name}' has {len(suspicious)} suspicious modules",
                evidence, 40.0)

    # ---------- DEDUCTION 11: Persistence Changes ----------
    def _check_persistence(self):
        changes = self.registry_monitor.scan()
        for action, key_path, value in changes:
            if not self.registry_baseline_set:
                continue
            evidence = [f"Action: {action}", f"Key: {key_path}", f"Value: {value[:200]}"]
            sev = "CRITICAL" if action == "ADDED" else "WARNING"
            self._add_deduction(sev, "PERSISTENCE", "Registry", 0,
                f"PERSISTENCE {action}: {key_path}", evidence,
                35.0 if action == "ADDED" else 15.0)
        if not self.registry_baseline_set and changes is not None:
            self.registry_baseline_set = True

    # ---------- DEDUCTION 12: User Idle Anomaly ----------
    def _check_idle_anomaly(self, profile):
        idle_sec = self.user_idle.get_idle_seconds()
        if idle_sec < CONFIG['user_idle_threshold']:
            return
        if profile.connection_count > 5 and profile.last_network_ts > time.time() - 30:
            recent_cpu = any(c > 3 for c in list(profile.cpu_samples)[-10:])
            if not recent_cpu:
                evidence = [
                    f"User idle: {idle_sec:.0f}s",
                    f"'{profile.name}' has {profile.connection_count} active connections",
                    "No recent CPU activity from this process",
                ]
                self._add_deduction("WARNING", "IDLE_ANOMALY", profile.name, profile.pid,
                    f"IDLE ANOMALY: '{profile.name}' active while user idle {idle_sec:.0f}s",
                    evidence, 15.0)

    # ---------- DEDUCTION 13: Statistical Anomaly ----------
    def _check_ml_anomaly(self, profile):
        if len(profile.cpu_samples) < 5:
            return
        cpu_mean = statistics.mean(profile.cpu_samples) if profile.cpu_samples else 0
        ml_score, anomalies = self.ml_baseline.score(
            profile.name.lower(), profile.connection_count,
            len(profile.destinations), profile.bytes_sent, cpu_mean)
        profile.ml_anomaly_score = ml_score
        if ml_score > 30 and anomalies:
            evidence = [*anomalies, f"Overall anomaly score: {ml_score:.1f}", f"Process: {profile.name} (PID {profile.pid})"]
            sev = "CRITICAL" if ml_score > 60 else "WARNING"
            self._add_deduction(sev, "ML_ANOMALY", profile.name, profile.pid,
                f"STATISTICAL ANOMALY: '{profile.name}' deviates from baseline (score={ml_score:.0f})",
                evidence, ml_score * 0.5)

    # ---------- DEDUCTION 14: GeoIP Enrichment ----------
    def _check_geoip(self, profile, dst_ip, domains):
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if not ip_obj.is_global:
                return
        except Exception:
            return
        geo = self.geoip.lookup(dst_ip)
        if geo:
            country = geo.get('countryCode', '??')
            org = geo.get('org', 'Unknown')
            with self.lock:
                profile.geo_countries.add(country)
            if country in CONFIG.get('high_risk_countries', set()):
                idle_sec = self.user_idle.get_idle_seconds()
                recent_cpu = any(c > 2 for c in list(profile.cpu_samples)[-10:])
                if not recent_cpu and idle_sec > CONFIG['user_idle_threshold']:
                    evidence = [
                        f"Destination: {dst_ip} -> {country} ({org})",
                        f"Domains: {', '.join(domains) if domains else 'none'}",
                        f"User idle: {idle_sec:.0f}s" if idle_sec > 60 else "User recently active",
                        f"Process: {profile.name} exe={profile.exe_path}",
                    ]
                    self._add_deduction("WARNING", "FOREIGN", profile.name, profile.pid,
                        f"GEO ALERT: '{profile.name}' -> {dst_ip} ({country}, {org})",
                        evidence, 20.0)

    # ---------- Risk Score Management ----------
    def _update_risk(self, profile):
        profile.risk_score = max(0, profile.risk_score * 0.997)
        if profile.risk_score > CONFIG['risk_critical']:
            self._safe_alert(
                f"{EMOJI['alert']} HIGH RISK: '{profile.name}' (PID {profile.pid}) "
                f"score={profile.risk_score:.0f}", Colors.R)

    # ====================== CONNECTION MAPPER ======================
    def _get_conn_snapshot(self) -> list:
        """Return the latest connection snapshot (used by ConnectionInventory)."""
        with self._conn_snapshot_lock:
            return list(self._conn_snapshot)

    def _connection_mapper(self):
        while not self.stop.is_set():
            try:
                raw_conns = psutil.net_connections(kind='all')
                # Store raw snapshot for ConnectionInventory (single psutil call)
                with self._conn_snapshot_lock:
                    self._conn_snapshot = raw_conns
                # Build indexed views for process watcher
                by_pid = defaultdict(list)
                by_raddr = {}
                for conn in raw_conns:
                    if conn.pid:
                        by_pid[conn.pid].append(conn)
                    if conn.raddr:
                        by_raddr[conn.raddr[0]] = (conn.pid, conn)
                with self.conn_cache_lock:
                    self.conn_by_pid = by_pid
                    self.conn_by_raddr = by_raddr
            except psutil.AccessDenied:
                pass
            except Exception as exc:
                _mb_logger.debug("Connection mapper error: %s", exc)
            time.sleep(2)

    # ====================== PROCESS WATCHER ======================
    def _process_watcher(self):
        last_pids: set[int] = set()
        while not self.stop.is_set():
            current_pids: set[int] = set()
            audio_pids = set()
            camera_pids = set()
            with self.conn_cache_lock:
                conn_by_pid = dict(self.conn_by_pid)

            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cpu_percent']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    current_pids.add(pid)
                    # Hardware detection (merged — avoids double process_iter)
                    name_lower_hw = name.lower()
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['audio']):
                        if pid not in audio_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'WARNING', name, pid,
                                f'Audio device accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 f'Matched audio keyword in process name',
                                 f'Audio hardware is being used — potential eavesdropping if unexpected'])
                        audio_pids.add(pid)
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['camera']):
                        if pid not in camera_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'CRITICAL', name, pid,
                                f'Camera/webcam accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 f'Matched camera keyword in process name',
                                 f'Camera hardware is being used — potential surveillance if unexpected'])
                        camera_pids.add(pid)
                    with self.lock:
                        if pid not in self.process_profiles:
                            profile = ProcessProfile(
                                pid=pid, name=name, exe_path=proc.exe() or "",
                                parent_pid=proc.ppid() or 0,
                                start_time=proc.create_time(),
                            )
                            try:
                                profile.parent_name = psutil.Process(profile.parent_pid).name()
                            except Exception:
                                profile.parent_name = ""
                            self.process_profiles[pid] = profile
                            self._write_action(pid, name, "STARTED",
                                f"exe={profile.exe_path} parent={profile.parent_name}")
                            # Flag processes from suspicious paths
                            exe_lower = profile.exe_path.lower()
                            for susp_path in SUSPICIOUS_DLL_PATHS:
                                if susp_path in exe_lower:
                                    self._flag_suspicious('SUSPICIOUS_PATH', 'WARNING', name, pid,
                                        f'Process started from suspicious location: {profile.exe_path}',
                                        [f'Process: {name} (PID {pid})',
                                         f'Exe: {profile.exe_path}',
                                         f'Parent: {profile.parent_name} (PID {profile.parent_pid})',
                                         f'Matched suspicious path: {susp_path}'])
                                    break
                        profile = self.process_profiles[pid]

                    cpu = proc.cpu_percent(interval=None)
                    with self.lock:
                        profile.cpu_samples.append(cpu)
                        if cpu > 5:
                            self.user_activity_ts = time.time()

                    self._check_impersonation(profile, proc)
                    for conn in conn_by_pid.get(pid, []):
                        if conn.raddr:
                            dst_ip = conn.raddr[0]
                            conn_key = (dst_ip, conn.raddr[1], conn.laddr[0] if conn.laddr else '', conn.laddr[1] if conn.laddr else 0)
                            with self.lock:
                                is_new = conn_key not in profile.seen_conn_keys
                                profile.destinations.add(dst_ip)
                                if is_new:
                                    profile.seen_conn_keys.add(conn_key)
                                    profile.connection_count += 1
                                profile.packet_timestamps.append(time.time())
                                profile.last_network_ts = time.time()
                            domains = self.dns_cache.get_domains(dst_ip)
                            with self.lock:
                                profile.dns_domains.update(domains)
                            self._write_action(pid, name, "NETWORK_FLOW",
                                f"-> {dst_ip}:{conn.raddr[1]} domains={domains or 'unresolved'}")
                            # Flag remote access ports
                            dst_port = conn.raddr[1]
                            if is_new and dst_port in CONFIG['remote_ports']:
                                port_names = {22: 'SSH', 3389: 'RDP', 5900: 'VNC', 5938: 'TeamViewer',
                                              445: 'SMB', 139: 'NetBIOS', 5985: 'WinRM', 5986: 'WinRM-S'}
                                self._flag_suspicious('REMOTE_ACCESS', 'WARNING', name, pid,
                                    f'{name} connected to remote access port {dst_port} ({port_names.get(dst_port, "Unknown")})',
                                    [f'Process: {name} (PID {pid})',
                                     f'Destination: {dst_ip}:{dst_port}',
                                     f'Protocol: {port_names.get(dst_port, "Unknown")}',
                                     f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                     f'This could indicate remote control or lateral movement'])
                            # Flag connections to high-risk countries
                            if is_new and self._is_public_ip(dst_ip):
                                cc = self.geoip.get_country(dst_ip)
                                if cc in CONFIG['high_risk_countries']:
                                    self._flag_suspicious('HIGH_RISK_GEO', 'CRITICAL', name, pid,
                                        f'{name} connected to high-risk country: {cc} ({dst_ip})',
                                        [f'Process: {name} (PID {pid})',
                                         f'Destination: {dst_ip}:{dst_port}',
                                         f'Country: {cc}',
                                         f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                         f'High-risk countries: {CONFIG["high_risk_countries"]}'])
                            self._check_mimic(profile, dst_ip, domains)
                            self._check_foreign(profile, dst_ip, domains)
                            self._check_behavioral_anomaly(profile, dst_ip)
                            self._check_geoip(profile, dst_ip, domains)
                            # DoH detection
                            doh_ev = self.doh_detector.check_connection(pid, name, dst_ip, dst_port)
                            if doh_ev:
                                self._flag_suspicious('DOH', 'WARNING', name, pid,
                                    doh_ev['detail'], [doh_ev['detail']])
                                self._log(f"{EMOJI['tunnel']} DOH: {doh_ev['detail']}", color=Colors.Y)

                    self._check_beacon(profile)
                    if profile.connection_count > 0:
                        self._check_injection_chain(profile)
                    self._check_exfil(profile, proc)
                    self._check_dlls(profile, proc)
                    self._check_idle_anomaly(profile)
                    self._check_ml_anomaly(profile)
                    self._update_risk(profile)
                    # VirusTotal check (once per PID, rate-limited)
                    vt_result = self.vt_checker.check_exe(pid, profile.exe_path)
                    if vt_result and vt_result.get('malicious', 0) > 0:
                        self._flag_suspicious('VIRUSTOTAL', 'CRITICAL', name, pid,
                            f"VirusTotal: {name} flagged by {vt_result['malicious']} engines",
                            [f"SHA256: {vt_result.get('sha256', '?')}",
                             f"Malicious: {vt_result['malicious']}, Suspicious: {vt_result.get('suspicious', 0)}",
                             f"Exe: {profile.exe_path}"])
                        self._add_deduction("CRITICAL", "VIRUSTOTAL", name, pid,
                            f"VIRUSTOTAL: '{name}' flagged as malicious by {vt_result['malicious']} AV engines",
                            [f"SHA256: {vt_result.get('sha256', '?')}",
                             f"Malicious: {vt_result['malicious']}", f"Exe: {profile.exe_path}"],
                            min(80.0, vt_result['malicious'] * 5.0))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as exc:
                    _mb_logger.debug("Process watcher error for PID %s: %s", pid, exc)

            for pid in last_pids - current_pids:
                with self.lock:
                    if pid in self.process_profiles:
                        prof = self.process_profiles[pid]
                        self._write_action(pid, prof.name, "STOPPED")
                        del self.process_profiles[pid]

            # Update hardware activity from this scan pass
            with self.lock:
                self.audio_active_pids = audio_pids
                self.camera_active_pids = camera_pids

            self._check_phantoms(current_pids)
            if _IS_WINDOWS:
                self._check_persistence()
            last_pids = current_pids
            time.sleep(CONFIG['process_scan_interval'])

    # ====================== PACKET CALLBACK (via pipeline) ======================
    def _packet_callback(self, pkt):
        """Called by pipeline workers — not directly by sniff thread."""
        if pkt.haslayer(DNS):
            self.dns_cache.process_packet(pkt)
            if pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
                    src_q = pkt[IP].src if pkt.haslayer(IP) else '?'
                    self._check_dns_tunnel(qname, src_q)
                except Exception as exc:
                    _mb_logger.debug("DNS tunnel check error: %s", exc)

        sni = self.sni_extractor.extract(pkt)
        if sni:
            dst_for_sni = pkt[IP].dst if pkt.haslayer(IP) else None
            if dst_for_sni:
                with self.dns_cache.lock:
                    self.dns_cache.ip_to_domains[dst_for_sni].add(sni)
                    self.dns_cache.domain_to_ips[sni].add(dst_for_sni)

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if len(payload) >= 32:
                ent = self.entropy_analyzer.payload_entropy(payload)
                is_sus, desc = self.entropy_analyzer.is_suspicious(pkt, ent)
                if is_sus:
                    src_e = pkt[IP].src if pkt.haslayer(IP) else '?'
                    dst_e = pkt[IP].dst if pkt.haslayer(IP) else '?'
                    self._add_deduction("WARNING", "ENTROPY", "packet", 0,
                        f"HIGH ENTROPY PAYLOAD: {src_e} -> {dst_e}: {desc}",
                        [desc, f"Payload size: {len(payload)} bytes"], 15.0)

        ja4s = self.ja4plus.ja4s(pkt)
        ja4h = self.ja4plus.ja4h(pkt)

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else None
        try:
            if self.network and ipaddress.ip_address(src) not in self.network:
                if not (src.startswith('fe80') or src.startswith('fd')):
                    return
        except Exception:
            return

        comp_key = self._composite_key(mac, src)
        now = time.time()

        with self.lock:
            if comp_key not in self.seen_composites:
                vendor = get_vendor(mac)
                hostname = self._extract_hostname(pkt) or "Hidden"
                dev = {
                    'mac': mac, 'ip': src, 'vendor': vendor, 'hostname': hostname,
                    'os_guess': self._passive_os(pkt), 'first_seen': now, 'last_seen': now,
                    'confidence': 0.4, 'anomaly_count': 0,
                    'ja4': self.ja4plus.ja4(pkt),
                }
                self.devices[comp_key] = dev
                self.seen_composites.add(comp_key)
                self._log(f"{EMOJI['new']} NEW DEVICE -> {src:18} {vendor:14} {hostname}", color=Colors.Y)
                self.db.save_device(comp_key, dev)
            else:
                dev = self.devices[comp_key]
                if now - dev.get('last_seen', now) > 1800:
                    dev['confidence'] = max(0.05, dev['confidence'] * 0.93)
                dev['last_seen'] = now
                dev['ip'] = src
                dev['confidence'] = min(1.0, dev['confidence'] + 0.07)
            if ja4s:
                dev['ja4s'] = ja4s
            if ja4h:
                dev['ja4h'] = ja4h

        proto = pkt[IP].proto if pkt.haslayer(IP) else 0
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        flow_key = (src, dst, proto, sport, dport)

        # Inbound SYN detection — detect port scans targeting us
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and dst == self.local_ip and src != self.local_ip:
            self.inbound_scan_detector.record_inbound_syn(src, pkt[TCP].dport)

        # TLS certificate tracking (ServerHello with cert)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw])
            if len(raw_data) > 10 and raw_data[0] == 0x16:
                hs = raw_data[5:]
                if len(hs) > 4 and hs[0] == 0x0b:  # Certificate message
                    self.tls_cert_detector.record_cert(src, raw_data[:256])

        with self.lock:
            self.flow_stats[flow_key].append(now)
            probe_count = 0
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and pkt[TCP].dport in CONFIG['probe_alert_ports']:
                self.probe_attempts[src] += 1
                probe_count = self.probe_attempts[src]

            new_remote = False
            s_port = d_port = 0
            if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x10):
                s_port, d_port = pkt[TCP].sport, pkt[TCP].dport
                if d_port in CONFIG['remote_ports'] or s_port in CONFIG['remote_ports']:
                    session_key = (src, dst, s_port, d_port)
                    if session_key not in self.remote_sessions:
                        self.remote_sessions[session_key] = now
                        new_remote = True

            arp_spoof_mac = None
            if mac and pkt.haslayer(ARP) and pkt[ARP].op == 2:
                claimed = pkt[ARP].psrc
                if claimed not in self.mac_to_ip_history[mac]:
                    for other_mac, ips in self.mac_to_ip_history.items():
                        if other_mac != mac and claimed in ips:
                            arp_spoof_mac = (mac, claimed)
                            break
                self.mac_to_ip_history[mac].add(claimed)

        if probe_count > 7:
            self._safe_alert(f"{EMOJI['probe']} Active probe -> {src} ({probe_count} SYN attempts)", Colors.R)
        if new_remote:
            self._safe_alert(f"{EMOJI['remote']} REMOTE SESSION -> {src}:{s_port} -> {dst}:{d_port}", Colors.R)
        if arp_spoof_mac:
            self._safe_alert(f"{EMOJI['spoof']} ARP SPOOF -> {arp_spoof_mac[0]} claims {arp_spoof_mac[1]}", Colors.R)

    # ====================== THREADS ======================
    def _arp_thread(self):
        while not self.stop.is_set():
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.network)),
                             timeout=3, verbose=0)
                for _, rcv in ans:
                    fake = Ether(src=rcv.hwsrc)/IP(src=rcv.psrc)
                    self.pipeline.enqueue(fake)
            except Exception as exc:
                _mb_logger.debug("ARP scan error: %s", exc)
            time.sleep(random.uniform(CONFIG['scan_interval_min'], CONFIG['scan_interval_max']))

    def _dns_cache_poll_thread(self):
        """Periodically poll Windows DNS client cache and save domain history."""
        # Initial aggressive poll on startup
        self.dns_cache.poll_system_dns_cache()
        save_counter = 0
        while not self.stop.is_set():
            time.sleep(15)
            try:
                self.dns_cache.poll_system_dns_cache()
            except Exception as exc:
                _mb_logger.debug("DNS poll thread error: %s", exc)
            save_counter += 1
            if save_counter >= 4:  # Save every ~60 seconds
                try:
                    self.dns_cache.save_history()
                except Exception as exc:
                    _mb_logger.debug("DNS history save error: %s", exc)
                save_counter = 0

    def _sniff_thread(self):
        filt = "ip or ip6 or arp"
        while not self.stop.is_set():
            try:
                sniff(prn=self.pipeline.enqueue, filter=filt, store=False,
                      promisc=True, timeout=60,
                      stop_filter=lambda _: self.stop.is_set())
            except Exception as e:
                _mb_logger.warning("Sniff error: %s — retrying in 5s", e)
                time.sleep(5)

    def _status_thread(self):
        while not self.stop.is_set():
            with self.lock:
                n_procs = len(self.process_profiles)
                n_deductions = len(self.deductions)
                high_risk = sum(1 for p in self.process_profiles.values() if p.risk_score > CONFIG['risk_critical'])
                n_dns = len(self.dns_cache.ip_to_domains)
                n_geo = len(self.geoip.cache)
            idle_sec = self.user_idle.get_idle_seconds()
            ml_active = sum(1 for m in self.ml_baseline.models.values()
                            if len(m['conn_rate']) >= 30)
            pipe = self.pipeline.stats()
            self._log(
                f"{EMOJI['chess']} Status: {len(self.devices)} devices | "
                f"{n_procs} processes | {n_deductions} deductions | "
                f"{high_risk} high-risk | {n_dns} DNS | {n_geo} GeoIP | "
                f"{ml_active} baselines | idle={idle_sec:.0f}s | "
                f"pipe={pipe['processed']}/{pipe['dropped']}",
                color=Colors.G)
            # Periodic cleanup of stale deduction cooldowns
            now = time.time()
            cooldown_ttl = CONFIG['deduction_cooldown'] * 2
            with self.lock:
                stale_keys = [k for k, t in self.deduction_cooldowns.items()
                              if now - t > cooldown_ttl]
                for k in stale_keys:
                    del self.deduction_cooldowns[k]
            time.sleep(15)

    def _memory_forensics_thread(self):
        if not _IS_WINDOWS:
            return
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40
        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.wintypes.DWORD), ("Protect", ctypes.wintypes.DWORD),
                    ("Type", ctypes.wintypes.DWORD),
                ]
        except Exception:
            return

        while not self.stop.is_set():
            with self.lock:
                pids_to_check = [(pid, p.name) for pid, p in self.process_profiles.items()
                                 if p.risk_score > 10 and p.connection_count > 0]
            for pid, pname in pids_to_check[:20]:
                if self.stop.is_set():
                    break
                try:
                    handle = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
                    if not handle:
                        continue
                    mbi = MEMORY_BASIC_INFORMATION()
                    addr = 0
                    rwx_regions = 0
                    while ctypes.windll.kernel32.VirtualQueryEx(
                            handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.RegionSize > 4096:
                            rwx_regions += 1
                        addr += mbi.RegionSize
                        if addr > 0x7FFFFFFFFFFF:
                            break
                    ctypes.windll.kernel32.CloseHandle(handle)
                    if rwx_regions > 2:
                        evidence = [f"Process: {pname} (PID {pid})", f"RWX memory regions: {rwx_regions}",
                                    "RWX pages indicate possible shellcode or reflective DLL injection"]
                        self._add_deduction("CRITICAL", "DLL", pname, pid,
                            f"MEMORY FORENSICS: '{pname}' has {rwx_regions} RWX memory regions",
                            evidence, 45.0)
                except Exception as exc:
                    _mb_logger.debug("Memory forensics error for PID %s: %s", pid, exc)
            time.sleep(30)

    # ====================== EXTENDED MONITORS (Tier 5) ======================
    def _extended_monitor_thread(self):
        """Runs all Tier 5 detectors periodically in a single thread."""
        cycle = 0
        # Brief delay to let main thread proceed
        time.sleep(2)
        while not self.stop.is_set():
            try:
                cycle += 1
                # File system watchdog — every 10s
                if cycle % 2 == 0:
                    fs_events = self.fs_watchdog.scan()
                    for ev in fs_events:
                        if ev.get('severity') in ('CRITICAL', 'WARNING'):
                            self._flag_suspicious(ev['type'], ev['severity'],
                                'FileSystem', 0, ev['detail'],
                                [f"Path: {ev.get('path', '?')}", f"Type: {ev['type']}"])
                            self._log(f"{EMOJI['alert']} FS: {ev['detail']}",
                                      color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # Clipboard — every 5s
                clip_events = self.clipboard_monitor.check()
                for ev in clip_events:
                    self._flag_suspicious(ev['type'], ev['severity'],
                        'Clipboard', 0, ev['detail'], [ev['detail']])
                    self._log(f"{EMOJI['alert']} CLIPBOARD: {ev['detail']}", color=Colors.R)
                # USB devices — every 30s
                if cycle % 6 == 0:
                    usb_events = self.usb_monitor.scan()
                    for ev in usb_events:
                        self._flag_suspicious('USB', ev['severity'],
                            'USB', 0, ev['detail'], [ev.get('device_id', '?')])
                        self._log(f"{EMOJI['alert']} USB: {ev['detail']}", color=Colors.Y)
                # Scheduled tasks — every 60s
                if cycle % 12 == 0:
                    task_events = self.sched_task_monitor.scan()
                    for ev in task_events:
                        self._flag_suspicious('SCHEDULED_TASK', ev['severity'],
                            'TaskScheduler', 0, ev['detail'], [ev.get('task', '?')])
                        self._log(f"{EMOJI['persist']} TASK: {ev['detail']}", color=Colors.Y)
                # Named pipes — every 30s
                if cycle % 6 == 0:
                    pipe_events = self.named_pipe_monitor.scan()
                    for ev in pipe_events:
                        if ev['severity'] == 'CRITICAL':
                            self._flag_suspicious('NAMED_PIPE', 'CRITICAL',
                                'NamedPipe', 0, ev['detail'], [ev.get('pipe', '?')])
                            self._log(f"{EMOJI['inject']} PIPE: {ev['detail']}", color=Colors.R)
                # Inbound scan detection — every 5s
                scan_events = self.inbound_scan_detector.check()
                for ev in scan_events:
                    self._flag_suspicious('INBOUND_SCAN', 'CRITICAL',
                        'Network', 0, ev['detail'],
                        [f"Source: {ev.get('source_ip', '?')}",
                         f"Ports: {ev.get('ports_probed', [])}"])
                    self._log(f"{EMOJI['probe']} SCAN: {ev['detail']}", color=Colors.R)
                # Bluetooth scan — every 30s
                if cycle % 6 == 0:
                    bt_events = self.bt_scanner.scan()
                    for ev in bt_events:
                        self._flag_suspicious('BLUETOOTH', ev['severity'],
                            'Bluetooth', 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} BT: {ev['detail']}", color=Colors.Y)
                # Serial port scan — every 30s
                if cycle % 6 == 0:
                    serial_events = self.serial_scanner.scan()
                    for ev in serial_events:
                        self._flag_suspicious('SERIAL_PORT', ev['severity'],
                            'Serial', 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} SERIAL: {ev['detail']}", color=Colors.Y)
                # Proxy detection — every 30s
                if cycle % 6 == 0:
                    proxy_events = self.proxy_detector.scan_system()
                    for ev in proxy_events:
                        self._flag_suspicious(ev['type'], ev['severity'],
                            ev.get('subtype', 'Proxy'), 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} PROXY: {ev['detail']}", color=Colors.Y)
                # Connection history update
                with self._conn_snapshot_lock:
                    snapshot = list(self._conn_snapshot)
                self.conn_history.update(snapshot)
            except Exception as exc:
                _mb_logger.debug("Extended monitor error: %s", exc)
            time.sleep(5)

    def _iface_stats_thread(self):
        """Track network interface bandwidth over time."""
        while not self.stop.is_set():
            try:
                counters = psutil.net_io_counters(pernic=True)
                now = time.time()
                for iface, stats in counters.items():
                    prev = self._iface_stats_prev.get(iface)
                    if prev:
                        dt = now - prev[2]
                        if dt > 0:
                            sent_rate = (stats.bytes_sent - prev[0]) / dt
                            recv_rate = (stats.bytes_recv - prev[1]) / dt
                            self._iface_stats_history[iface].append({
                                'time': now, 'sent_rate': sent_rate,
                                'recv_rate': recv_rate,
                                'total_sent': stats.bytes_sent,
                                'total_recv': stats.bytes_recv,
                                'packets_sent': stats.packets_sent,
                                'packets_recv': stats.packets_recv,
                                'errin': stats.errin, 'errout': stats.errout,
                                'dropin': stats.dropin, 'dropout': stats.dropout,
                            })
                    self._iface_stats_prev[iface] = (stats.bytes_sent, stats.bytes_recv, now)
            except Exception as exc:
                _mb_logger.debug("Interface stats error: %s", exc)
            time.sleep(3)

    # ====================== DASHBOARD STATE ======================
    def _get_dashboard_state(self) -> dict:
        with self.lock:
            processes = []
            for _pid, p in list(self.process_profiles.items())[:200]:
                processes.append({
                    'pid': p.pid, 'name': p.name, 'exe': p.exe_path,
                    'parent': p.parent_name, 'risk': round(p.risk_score, 1),
                    'connections': p.connection_count,
                    'destinations': len(p.destinations),
                    'ml_score': round(p.ml_anomaly_score, 1),
                    'countries': sorted(p.geo_countries),
                })
            deductions_list = []
            for d in list(self.deductions)[-100:]:
                deductions_list.append({
                    'time': datetime.datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S"),
                    'severity': d.severity, 'category': d.category,
                    'process': d.process_name, 'pid': d.pid,
                    'message': d.message, 'score': round(d.score, 1),
                    'evidence': list(d.evidence),
                })
            devices_list = list(self.devices.values())
        pipe = self.pipeline.stats()
        return {
            'processes': processes, 'deductions': deductions_list,
            'devices': devices_list, 'dns_count': len(self.dns_cache.ip_to_domains),
            'geoip_count': len(self.geoip.cache),
            'idle_seconds': round(self.user_idle.get_idle_seconds(), 0),
            'pipeline_processed': pipe['processed'],
            'pipeline_dropped': pipe['dropped'],
            # Connection inventory data
            'connections': self.conn_inventory.get_all(),
            'map_points': self.conn_inventory.get_map_points(),
            'services': self.conn_inventory.get_services_summary(),
            'conn_stats': self.conn_inventory.get_stats(),
        }

    # ====================== FULL DATA (for GUI) ======================
    def _get_full_data(self) -> dict:
        """Returns ALL data for the GNA Tracer GUI — 100% detail."""
        base = self._get_dashboard_state()
        # Add raw actions log
        with self.lock:
            all_actions = []
            for pid, actions in list(self.process_actions.items()):
                for ts, name, action, extra in actions:
                    all_actions.append(
                        f"{datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')} | "
                        f"{name} (PID {pid}) | {action} {extra}"
                    )
        all_actions.sort()
        base['all_actions'] = all_actions
        # Add full deductions with evidence (all, not just last 100)
        with self.lock:
            full_deds = []
            for d in list(self.deductions):
                full_deds.append({
                    'time': datetime.datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S"),
                    'severity': d.severity, 'category': d.category,
                    'process': d.process_name, 'pid': d.pid,
                    'message': d.message, 'score': round(d.score, 1),
                    'evidence': list(d.evidence),
                })
        base['deductions'] = full_deds
        # Add 100% terminal output buffer
        with self.lock:
            base['terminal_lines'] = list(self.terminal_buffer)
        # Add suspicious activity events
        with self.lock:
            base['suspicious_events'] = list(self.suspicious_events)
        # Tier 5 data
        base['fs_events'] = self.fs_watchdog.get_events()
        base['clipboard_events'] = self.clipboard_monitor.get_events()
        base['usb_events'] = self.usb_monitor.get_events()
        base['sched_task_events'] = self.sched_task_monitor.get_events()
        base['named_pipe_events'] = self.named_pipe_monitor.get_events()
        base['inbound_scan_events'] = self.inbound_scan_detector.get_events()
        base['doh_events'] = self.doh_detector.get_events()
        base['cert_events'] = self.tls_cert_detector.get_events()
        base['vt_results'] = self.vt_checker.get_all_results()
        base['conn_timeline'] = self.conn_history.get_timeline()
        base['conn_bandwidth'] = self.conn_history.get_bandwidth()
        base['iface_stats'] = {k: list(v) for k, v in self._iface_stats_history.items()}
        base['watchlist_ips'] = list(self._watchlist_ips)
        base['watchlist_procs'] = list(self._watchlist_procs)
        base['bt_devices'] = self.bt_scanner.get_devices()
        base['bt_events'] = self.bt_scanner.get_events()
        base['serial_ports'] = self.serial_scanner.get_ports()
        base['serial_events'] = self.serial_scanner.get_events()
        base['proxy_events'] = self.proxy_detector.get_events()
        base['proxy_processes'] = self.proxy_detector.get_proxy_processes()
        return base

    # ====================== RUN ======================
    def run(self):
        # Start packet pipeline workers
        self.pipeline.start()

        threads = [
            threading.Thread(target=self._connection_mapper, daemon=True, name="Connection-Mapper"),
            threading.Thread(target=self._process_watcher, daemon=True, name="Process-Watcher"),
            threading.Thread(target=self._status_thread, daemon=True, name="Status-Reporter"),
            threading.Thread(target=self.conn_inventory.run_thread, daemon=True, name="Connection-Inventory"),
        ]
        if self._admin_mode:
            threads.append(threading.Thread(target=self._arp_thread, daemon=True, name="ARP-Scanner"))
            threads.append(threading.Thread(target=self._sniff_thread, daemon=True, name="Packet-Sniffer"))
        else:
            self._log(f"{Colors.Y}Skipping packet capture (no admin). Process monitoring only.{Colors.END}")

        threads.append(threading.Thread(target=self._dns_cache_poll_thread,
                                        daemon=True, name="DNS-Cache-Poll"))
        if _IS_WINDOWS:
            threads.append(threading.Thread(target=self._memory_forensics_thread,
                                            daemon=True, name="Memory-Forensics"))
        # Tier 5 extended monitors
        threads.append(threading.Thread(target=self._extended_monitor_thread,
                                        daemon=True, name="Extended-Monitor"))
        threads.append(threading.Thread(target=self._iface_stats_thread,
                                        daemon=True, name="Interface-Stats"))
        if HAS_FASTAPI and CONFIG.get('dashboard_enabled'):
            threads.append(threading.Thread(
                target=start_dashboard,
                args=(self._get_dashboard_state, self.stop),
                daemon=True, name="Dashboard"))

        for t in threads:
            t.start()
            self._log(f"  Started thread: {t.name}", color=Colors.C)

        if HAS_FASTAPI and CONFIG.get('dashboard_enabled'):
            self._log(f"{EMOJI['dashboard']} Dashboard: http://127.0.0.1:{CONFIG['dashboard_port']}", color=Colors.G)

        # Launch GNA Tracer GUI unless --no-gui
        gui = None
        use_gui = not getattr(self.args, 'no_gui', False)
        if use_gui:
            self._log(f"{EMOJI['brain']} Launching GNA Tracer GUI...", color=Colors.G)
            try:
                gui = GNATracerGUI(
                    get_state_fn=self._get_dashboard_state,
                    get_full_data_fn=self._get_full_data,
                    stop_event=self.stop,
                )
            except Exception as exc:
                import traceback
                print(f"GUI INIT CRASH: {exc}", flush=True)
                traceback.print_exc()
                gui = None
        try:
            if gui:
                gui.run()  # blocks until GUI window is closed
            else:
                while not self.stop.is_set():
                    time.sleep(1)
        except KeyboardInterrupt:
            self._log(f"{EMOJI['ok']} Shutting down...", color=Colors.C)
        except Exception as exc:
            import traceback
            self._log(f"GUI CRASH: {exc}", color=Colors.R)
            traceback.print_exc()
            if gui:
                _mb_logger.warning("GUI error: %s — falling back to terminal mode", exc)
            try:
                while not self.stop.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self._log(f"{EMOJI['ok']} Shutting down...", color=Colors.C)
        finally:
            self.stop.set()
            self.pipeline.drain(timeout=3)
            for t in threads:
                t.join(timeout=5)
            # Save GNA tracer data on any exit
            try:
                desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
                filepath = os.path.join(desktop, 'GNA tracer data.txt')
                if not os.path.exists(filepath):
                    saver = GNATracerGUI(
                        get_state_fn=self._get_dashboard_state,
                        get_full_data_fn=self._get_full_data,
                        stop_event=self.stop,
                    )
                    saver._save_tracer_data()
            except Exception:
                pass
            self._log(f"{EMOJI['ok']} Stopped. Logs: {CONFIG['actions_log']}, {CONFIG['deductions_log']}")



# ========================== ENTRY POINT ==========================
def medianbox_main():
    parser = argparse.ArgumentParser(
        description="MedianBoxMonitor 3.0 — Modular Deductive Chess Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--config', '-c', default=None,
                        help='Path to YAML config file (default: medianbox_config.yaml)')
    parser.add_argument('--no-dashboard', action='store_true',
                        help='Disable web dashboard')
    parser.add_argument('--no-geoip', action='store_true',
                        help='Disable GeoIP lookups (privacy)')
    parser.add_argument('--siem', choices=['json', 'cef', 'syslog'],
                        help='Enable SIEM output format')
    parser.add_argument('--port', type=int, default=None,
                        help='Dashboard port (default: 8470)')
    parser.add_argument('--workers', type=int, default=None,
                        help='Number of pipeline worker threads (default: 2)')
    parser.add_argument('--dashboard-password', default=None,
                        help='Require this password/token to access the dashboard')
    parser.add_argument('--geoip-db', default=None,
                        help='Path to MaxMind GeoLite2-City.mmdb for local offline GeoIP')
    parser.add_argument('--no-gui', action='store_true',
                        help='Disable the GNA Tracer GUI popup window (terminal only)')

    args = parser.parse_args()

    # Load YAML config first
    load_config(args.config)

    # CLI overrides
    if args.no_dashboard:
        CONFIG['dashboard_enabled'] = False
    if args.no_geoip:
        CONFIG['geoip_enabled'] = False
    if args.siem:
        CONFIG['siem_output'] = args.siem
    if args.port:
        CONFIG['dashboard_port'] = args.port
    if args.workers:
        CONFIG['pipeline_workers'] = args.workers
    if args.dashboard_password:
        CONFIG['dashboard_password'] = args.dashboard_password
    if args.geoip_db:
        CONFIG['geoip_db_path'] = args.geoip_db

    monitor = MedianBoxMonitor(args)
    monitor.run()



def _find_project_dir() -> Path:
    """Locate the real project directory containing Start PubLAN.bat.

    Search order:
      1. Directory containing this script
      2. 'GNA Official1' subfolder next to this script
      3. Any subfolder next to this script that has Start PubLAN.bat
    Returns the first match, or falls back to the script's own directory.
    """
    script_dir = Path(__file__).parent.resolve()
    # 1. Script lives inside the project folder already
    if (script_dir / 'Start PubLAN.bat').exists():
        return script_dir
    # 2. Well-known subfolder name
    candidate = script_dir / 'GNA Official1'
    if candidate.is_dir() and (candidate / 'Start PubLAN.bat').exists():
        return candidate
    # 3. Scan immediate subdirectories
    try:
        for child in script_dir.iterdir():
            if child.is_dir() and (child / 'Start PubLAN.bat').exists():
                return child
    except OSError:
        pass
    # Fallback — use script dir (original behaviour)
    return script_dir

PROJECT_DIR: Path = _find_project_dir()
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, Response, request as flask_request, jsonify, abort, redirect, send_from_directory
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo, IPVersion

logger = logging.getLogger(__name__)

# ===========================================================================
# config
# ===========================================================================
VERSION: Final[str] = "1.17"
APP_NAME: Final[str] = "Global Network Archive"
SERVICE_TYPE: Final[str] = "_databank._tcp.local."
DATA_DIR: Final[Path] = Path(os.getenv('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))) / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)
SHARED_PATHS_FILE: Final[Path] = DATA_DIR / "shared_paths.json"
PEERS_FILE: Final[Path] = DATA_DIR / "known_peers.json"
MY_JOIN_TIME_FILE: Final[Path] = DATA_DIR / "my_join_time.txt"
SHARED_DIR: Final[Path] = Path.home()
PORT: Final[int] = 5000
PEER_TIMEOUT_SECONDS: Final[int] = 40
DISCOVERY_INTERVAL_SECONDS: Final[int] = 5
STATUS_PRINT_INTERVAL_SECONDS: Final[int] = 5
SHARED_COUNT_TIMEOUT_SECONDS: Final[float] = 3.0
SHARED_LIST_TIMEOUT_SECONDS: Final[float] = 5.0
PEER_INFO_TIMEOUT_SECONDS: Final[float] = 6.0
SEARCH_TIMEOUT_SECONDS: Final[float] = 4.0
MAX_PREVIEW_ITEMS: Final[int] = 8
MAX_FAILOVER_CHAIN_SIZE: Final[int] = 11
PUBLIC_IP_API_URL: Final[str] = "https://api.ipify.org?format=text"
PUBLIC_IP_TIMEOUT_SECONDS: Final[int] = 5
DNS_PROBE_ADDRESS: Final[str] = "8.8.8.8"
DNS_PROBE_PORT: Final[int] = 80
ABOUT_FILE: Final[Path] = Path("about.txt")

DEFAULT_ABOUT_TEXT: Final[str] = """
<h2>Global Network Archive v1.17</h2>
<p><strong>A decentralized, peer-to-peer file sharing and communication network.</strong></p>
"""

def migrate_legacy_files() -> None:
    install_dir = PROJECT_DIR.parent.absolute()
    migrations = [("shared_paths.json", SHARED_PATHS_FILE), ("known_peers.json", PEERS_FILE), ("my_join_time.txt", MY_JOIN_TIME_FILE)]
    for old_name, new_path in migrations:
        old_path = install_dir / old_name
        if old_path.exists() and not new_path.exists():
            try:
                shutil.copy2(old_path, new_path)
            except Exception:
                pass

def load_about_text() -> str:
    if ABOUT_FILE.exists():
        return ABOUT_FILE.read_text(encoding="utf-8")
    return DEFAULT_ABOUT_TEXT

# ===========================================================================
# domain/exceptions
# ===========================================================================
class GNAException(Exception):
    pass
class PathValidationError(GNAException):
    pass
class PeerDiscoveryError(GNAException):
    pass
class NetworkError(GNAException):
    pass
class StateCorruptionError(GNAException):
    pass
class PersistenceError(GNAException):
    pass

# ===========================================================================
# domain/types
# ===========================================================================
@dataclass(frozen=True)
class PeerId:
    value: str
    def __str__(self) -> str:
        return self.value

@dataclass(frozen=True)
class PeerInfo:
    ip: str
    port: int
    join_time: float
    last_seen: float
    def is_alive(self, current_time: float, timeout_seconds: int) -> bool:
        return self.last_seen > current_time - timeout_seconds

@dataclass(frozen=True)
class SharedItem:
    path: str
    name: str
    size_str: str
    is_folder: bool
    @property
    def download_url_path(self) -> Optional[str]:
        if self.is_folder: return None
        return f"/preview/{self.path.lstrip('/')}?download=1"

@dataclass(frozen=True)
class FailoverNode:
    peer_id: PeerId
    role: str
    ip: str
    port: int

@dataclass(frozen=True)
class SearchResult:
    bank_id: str
    name: str
    size: str
    is_folder: bool
    link: str

@dataclass(frozen=True)
class ExplorerEntry:
    name: str
    path: str
    size: str
    is_dir: bool
    shared: bool
    tags: str = ""

SharedPaths = Dict[str, str]
PeerRegistry = Dict[str, PeerInfo]

class PeerStateProtocol(Protocol):
    def add_discovered_peer(self, peer_id: str, info: PeerInfo) -> None: ...

# ===========================================================================
# domain/peer_logic
# ===========================================================================
def get_live_peers(my_id, my_info, known_peers, discovered_peers, current_time, timeout_seconds):
    live = {my_id.value: my_info}
    for pid, data in list(known_peers.items()) + list(discovered_peers.items()):
        if data.is_alive(current_time, timeout_seconds):
            live[pid] = data
    return sorted(live.items(), key=lambda x: (x[1].join_time, x[0]))

def get_failover_chain(sorted_live, max_size):
    chain = []
    for i, (pid, data) in enumerate(sorted_live[:max_size]):
        role = "Primary" if i == 0 else f"Backup {i}"
        chain.append(FailoverNode(peer_id=PeerId(pid), role=role, ip=data.ip, port=data.port))
    return chain

def get_my_role(my_id, sorted_live):
    if not sorted_live: return "Primary"
    if sorted_live[0][0] == my_id.value: return "Primary"
    for i, (pid, _) in enumerate(sorted_live):
        if pid == my_id.value: return f"Backup {i}"
    return "Unknown"

def is_path_shared(path, shared_paths):
    if path in shared_paths: return True
    for shared_path in shared_paths:
        if shared_path.endswith('/'):
            shared_prefix = shared_path.rstrip('/')
            if path == shared_prefix or path.startswith(shared_prefix + '/'):
                return True
    return False

def filter_visible_paths(all_paths, shared_paths):
    return [p for p in all_paths if is_path_shared(p, shared_paths)]

# ===========================================================================
# infrastructure/crypto
# ===========================================================================
NONCE_SIZE = 12
KEY_SIZE = 32
PUB_KEY_SIZE = 32
SALT_SIZE = 32
FILE_CHUNK_SIZE = 65536
HKDF_INFO = b"PubLAN-v1-secure-channel"
FILE_HKDF_INFO = b"PubLAN-v1-file-encryption"

def generate_file_key():
    return os.urandom(KEY_SIZE)

def derive_key(shared_secret, salt, info=HKDF_INFO):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, info=info, backend=default_backend())
    return hkdf.derive(shared_secret)

def encrypt_data(key, plaintext):
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_data(key, encrypted):
    if len(encrypted) < NONCE_SIZE + 16: raise ValueError("Encrypted data too short")
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_file_data(key, data):
    salt = os.urandom(SALT_SIZE)
    derived = derive_key(key, salt, FILE_HKDF_INFO)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(derived)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_file_data(key, encrypted):
    if len(encrypted) < SALT_SIZE + NONCE_SIZE + 16: raise ValueError("Encrypted file data too short")
    salt = encrypted[:SALT_SIZE]
    nonce = encrypted[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted[SALT_SIZE + NONCE_SIZE:]
    derived = derive_key(key, salt, FILE_HKDF_INFO)
    aesgcm = AESGCM(derived)
    return aesgcm.decrypt(nonce, ciphertext, None)

class CryptoIdentity:
    def __init__(self, private_key_bytes=None):
        if private_key_bytes:
            self._private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
    @property
    def public_key_bytes(self):
        return self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    @property
    def private_key_bytes(self):
        return self._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    def encrypt_for_peer(self, peer_public_key_bytes, plaintext):
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_pub_bytes = ephemeral_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_public = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = ephemeral_private.exchange(peer_public)
        salt = os.urandom(SALT_SIZE)
        encryption_key = derive_key(shared_secret, salt)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return ephemeral_pub_bytes + salt + nonce + ciphertext
    def decrypt_from_peer(self, encrypted):
        min_size = PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE + 16
        if len(encrypted) < min_size: raise ValueError(f"Encrypted data too short: {len(encrypted)} < {min_size}")
        ephemeral_pub_bytes = encrypted[:PUB_KEY_SIZE]
        salt = encrypted[PUB_KEY_SIZE:PUB_KEY_SIZE + SALT_SIZE]
        nonce = encrypted[PUB_KEY_SIZE + SALT_SIZE:PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE]
        ciphertext = encrypted[PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE:]
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = self._private_key.exchange(ephemeral_public)
        encryption_key = derive_key(shared_secret, salt)
        aesgcm = AESGCM(encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    def derive_shared_key(self, peer_public_key_bytes):
        peer_public = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self._private_key.exchange(peer_public)
        salt = hashlib.sha256(self.public_key_bytes + peer_public_key_bytes).digest()
        return derive_key(shared_secret, salt)

def password_to_key(password, salt=None):
    if salt is None: salt = os.urandom(SALT_SIZE)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, iterations=600_000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def secure_random_token(length=32):
    return os.urandom(length).hex()

# ===========================================================================
# infrastructure/password_policy
# ===========================================================================
@dataclass
class PasswordValidationResult:
    valid: bool
    errors: List[str]
    strength_label: str
    strength_css_class: str

def _count_char_classes(password):
    upper = lower = digit = other = 0
    for ch in password:
        if ch.isupper(): upper += 1
        elif ch.islower(): lower += 1
        elif ch.isdigit(): digit += 1
        else: other += 1
    return upper, lower, digit, other

def get_strength_label(length):
    if length < 40: return "Frail password", "text-danger"
    elif length <= 50: return "Weak password", "text-warning"
    elif length < 75: return "Okay password", "text-info"
    elif length <= 93: return "Reasonable password", "text-primary"
    else: return "Strong password", "text-success"

def validate_vault_password(password):
    errors = []
    length = len(password)
    if length < 15: errors.append(f"Minimum 15 characters required (currently {length})")
    upper, lower, digit, other = _count_char_classes(password)
    if upper < 3: errors.append(f"Minimum 3 uppercase letters required (currently {upper})")
    if lower < 3: errors.append(f"Minimum 3 lowercase letters required (currently {lower})")
    if digit < 3: errors.append(f"Minimum 3 digits required (currently {digit})")
    if other < 1: errors.append(f"Minimum 1 special/other character required (currently {other})")
    strength_label, css_class = get_strength_label(length)
    return PasswordValidationResult(valid=len(errors) == 0, errors=errors, strength_label=strength_label, strength_css_class=css_class)

def format_password_requirements_html():
    return '''<div class="small text-muted mt-2">
        <strong>Password requirements:</strong>
        <ul class="mb-1">
            <li>Minimum 15 characters (no maximum)</li>
            <li>At least 3 uppercase letters</li>
            <li>At least 3 lowercase letters</li>
            <li>At least 3 digits</li>
            <li>At least 1 special character, symbol, Unicode, or emoji</li>
        </ul>
    </div>'''

def password_strength_js():
    return r'''<script>
function checkPasswordStrength(inputId, feedbackId) {
    const input = document.getElementById(inputId);
    const feedback = document.getElementById(feedbackId);
    if (!input || !feedback) return;
    input.addEventListener('input', function() {
        const pw = this.value;
        const len = [...pw].length;
        let upper=0, lower=0, digit=0, other=0;
        for (const ch of pw) {
            if (/\p{Lu}/u.test(ch)) upper++;
            else if (/\p{Ll}/u.test(ch)) lower++;
            else if (/\p{Nd}/u.test(ch)) digit++;
            else other++;
        }
        let errors = [];
        if (len < 15) errors.push('Need ' + (15-len) + ' more chars');
        if (upper < 3) errors.push((3-upper) + ' more uppercase');
        if (lower < 3) errors.push((3-lower) + ' more lowercase');
        if (digit < 3) errors.push((3-digit) + ' more digits');
        if (other < 1) errors.push('1 special/symbol/emoji');
        let strength, cls;
        if (len < 40) { strength='Frail password'; cls='text-danger'; }
        else if (len <= 50) { strength='Weak password'; cls='text-warning'; }
        else if (len < 75) { strength='Okay password'; cls='text-info'; }
        else if (len <= 93) { strength='Reasonable password'; cls='text-primary'; }
        else { strength='Strong password'; cls='text-success'; }
        let html = '<span class="'+cls+' fw-bold">['+strength+']</span>';
        html += ' <span class="text-muted">('+len+' chars)</span>';
        if (errors.length > 0) {
            html += '<br><small class="text-danger">Missing: '+errors.join(' &middot; ')+'</small>';
        } else {
            html += '<br><small class="text-success">All requirements met</small>';
        }
        feedback.innerHTML = html;
    });
}
</script>'''

# ===========================================================================
# infrastructure/vault
# ===========================================================================
VAULT_META_FILE = ".vault_meta"
VAULT_INDEX_FILE = ".vault_index.enc"
VAULT_DOWNLOADS_DIR = "Downloads"
VAULT_VERSION_NUM = 1
ENCRYPTED_EXT = ".vaultenc"

@dataclass
class VaultFileEntry:
    name: str
    encrypted_name: str
    size: int
    added_time: float
    file_hash: str
    is_download: bool = False
    def to_dict(self):
        return {'name': self.name, 'encrypted_name': self.encrypted_name, 'size': self.size, 'added_time': self.added_time, 'file_hash': self.file_hash, 'is_download': self.is_download}
    @staticmethod
    def from_dict(d):
        return VaultFileEntry(name=d['name'], encrypted_name=d['encrypted_name'], size=d['size'], added_time=d['added_time'], file_hash=d['file_hash'], is_download=d.get('is_download', False))

def compute_secret_file_fingerprint(data):
    hmac_key = hashlib.sha3_256(data).digest()
    return {'md5': hashlib.md5(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest(), 'sha256': hashlib.sha256(data).hexdigest(), 'sha3_512': hashlib.sha3_512(data).hexdigest(), 'blake2b_512': hashlib.blake2b(data, digest_size=64).hexdigest(), 'hmac_sha256': hmac_module.new(hmac_key, data, hashlib.sha256).hexdigest(), 'size': len(data)}

def verify_secret_file_fingerprint(data, stored):
    current = compute_secret_file_fingerprint(data)
    for key in ('md5', 'sha1', 'sha256', 'sha3_512', 'blake2b_512', 'hmac_sha256', 'size'):
        if current.get(key) != stored.get(key): return False
    return True

class SecureVault:
    def __init__(self, vault_path, password=None, secret_file_data=None):
        self.vault_path = Path(vault_path)
        self.downloads_path = self.vault_path / VAULT_DOWNLOADS_DIR
        self._master_key = None
        self._password_salt = None
        self._password_key = None
        self._index = {}
        self._unlocked = False
        self._requires_secret_file = False
        self._last_validation_errors = []
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.downloads_path.mkdir(parents=True, exist_ok=True)
        meta_path = self.vault_path / VAULT_META_FILE
        if meta_path.exists():
            if password: self._unlock(password, secret_file_data)
        else:
            if password: self._initialize(password, secret_file_data)
    @property
    def last_validation_errors(self): return self._last_validation_errors
    @property
    def requires_secret_file(self): return self._requires_secret_file
    def _initialize(self, password, secret_file_data=None):
        validation = validate_vault_password(password)
        if not validation.valid:
            self._last_validation_errors = validation.errors
            return
        self._last_validation_errors = []
        self._master_key = generate_file_key()
        self._password_key, self._password_salt = password_to_key(password)
        encrypted_master = encrypt_data(self._password_key, self._master_key)
        meta = {'version': VAULT_VERSION_NUM, 'salt': self._password_salt.hex(), 'encrypted_master_key': encrypted_master.hex(), 'created': time.time(), 'requires_secret_file': secret_file_data is not None}
        if secret_file_data is not None:
            meta['secret_file_fingerprint'] = compute_secret_file_fingerprint(secret_file_data)
            self._requires_secret_file = True
        meta_path = self.vault_path / VAULT_META_FILE
        with open(meta_path, 'w') as f: json.dump(meta, f)
        if platform.system() == 'Windows':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(meta_path), 2)
            except Exception: pass
        self._index = {}
        self._save_index()
        self._unlocked = True
    def _unlock(self, password, secret_file_data=None):
        meta_path = self.vault_path / VAULT_META_FILE
        try:
            with open(meta_path, 'r') as f: meta = json.load(f)
            self._requires_secret_file = meta.get('requires_secret_file', False)
            if self._requires_secret_file:
                stored_fp = meta.get('secret_file_fingerprint')
                if not stored_fp:
                    self._last_validation_errors = ['Vault metadata corrupted']
                    return False
                if secret_file_data is None:
                    self._last_validation_errors = ['This vault requires a secret file to unlock']
                    return False
                if not verify_secret_file_fingerprint(secret_file_data, stored_fp):
                    self._last_validation_errors = ['Secret file does not match']
                    return False
            self._password_salt = bytes.fromhex(meta['salt'])
            encrypted_master = bytes.fromhex(meta['encrypted_master_key'])
            self._password_key, _ = password_to_key(password, self._password_salt)
            self._master_key = decrypt_data(self._password_key, encrypted_master)
            self._load_index()
            self._unlocked = True
            self._last_validation_errors = []
            return True
        except Exception as e:
            self._last_validation_errors = [str(e)]
            self._unlocked = False
            return False
    @property
    def is_unlocked(self): return self._unlocked
    def _save_index(self):
        if not self._master_key: return
        index_data = json.dumps({k: v.to_dict() for k, v in self._index.items()}).encode('utf-8')
        encrypted_index = encrypt_data(self._master_key, index_data)
        with open(self.vault_path / VAULT_INDEX_FILE, 'wb') as f: f.write(encrypted_index)
    def _load_index(self):
        index_path = self.vault_path / VAULT_INDEX_FILE
        if not index_path.exists():
            self._index = {}
            return
        try:
            with open(index_path, 'rb') as f: encrypted_index = f.read()
            index_data = decrypt_data(self._master_key, encrypted_index)
            raw = json.loads(index_data.decode('utf-8'))
            self._index = {k: VaultFileEntry.from_dict(v) for k, v in raw.items()}
        except Exception: self._index = {}
    def add_file(self, name, data, is_download=False):
        if not self._unlocked: return False
        try:
            enc_name = os.urandom(16).hex() + ENCRYPTED_EXT
            store_path = (self.downloads_path if is_download else self.vault_path) / enc_name
            encrypted = encrypt_file_data(self._master_key, data)
            with open(store_path, 'wb') as f: f.write(encrypted)
            self._index[name] = VaultFileEntry(name=name, encrypted_name=enc_name, size=len(data), added_time=time.time(), file_hash=hashlib.sha256(data).hexdigest(), is_download=is_download)
            self._save_index()
            return True
        except Exception: return False
    def read_file(self, name):
        if not self._unlocked: return None
        entry = self._index.get(name)
        if not entry: return None
        try:
            store_path = (self.downloads_path if entry.is_download else self.vault_path) / entry.encrypted_name
            with open(store_path, 'rb') as f: encrypted = f.read()
            return decrypt_file_data(self._master_key, encrypted)
        except Exception: return None
    def open_file(self, name):
        data = self.read_file(name)
        if data is None: return False
        try:
            temp_dir = tempfile.mkdtemp(prefix='publan_vault_')
            temp_path = Path(temp_dir) / name
            with open(temp_path, 'wb') as f: f.write(data)
            if platform.system() == 'Windows': os.startfile(str(temp_path))
            elif platform.system() == 'Darwin': subprocess.Popen(['open', str(temp_path)])
            else: subprocess.Popen(['xdg-open', str(temp_path)])
            def cleanup():
                time.sleep(60)
                shutil.rmtree(temp_dir, ignore_errors=True)
            threading.Thread(target=cleanup, daemon=True).start()
            return True
        except Exception: return False
    def remove_file(self, name):
        if not self._unlocked: return False
        entry = self._index.get(name)
        if not entry: return False
        try:
            store_path = (self.downloads_path if entry.is_download else self.vault_path) / entry.encrypted_name
            if store_path.exists():
                size = store_path.stat().st_size
                with open(store_path, 'wb') as f: f.write(os.urandom(size))
                store_path.unlink()
            del self._index[name]
            self._save_index()
            return True
        except Exception: return False
    def list_files(self):
        if not self._unlocked: return []
        return [{'name': e.name, 'size': e.size, 'added': e.added_time, 'is_download': e.is_download, 'hash': e.file_hash} for e in self._index.values()]

def get_default_vault_path():
    return DATA_DIR / "Vault"

# ===========================================================================
# infrastructure/integrity
# ===========================================================================
MANIFEST_FILE = ".integrity_manifest.json"
VERIFY_EXTENSIONS = {'.py', '.js', '.json', '.bat', '.html', '.css', '.md'}
SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.mypy_cache', '.pytest_cache', 'venv', 'env'}
SKIP_FILES_SET = {MANIFEST_FILE, '.integrity_manifest.json'}

def _hash_file(filepath):
    h = hashlib.sha3_256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    except Exception: return ""

def _collect_source_files(project_root):
    files = []
    for root, dirs, filenames in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if fname in SKIP_FILES_SET: continue
            fpath = Path(root) / fname
            if fpath.suffix.lower() in VERIFY_EXTENSIONS: files.append(fpath)
    return files

def generate_manifest(project_root):
    files = _collect_source_files(project_root)
    manifest = {}
    for fpath in files:
        rel = fpath.relative_to(project_root).as_posix()
        file_hash = _hash_file(fpath)
        if file_hash: manifest[rel] = file_hash
    manifest_path = project_root / MANIFEST_FILE
    try:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({'version': 1, 'algorithm': 'sha3-256', 'files': manifest}, f, indent=2)
    except Exception: pass
    return manifest

def verify_integrity(project_root):
    manifest_path = project_root / MANIFEST_FILE
    if not manifest_path.exists():
        generate_manifest(project_root)
        return True, ["Integrity manifest created (first run)"]
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f: data = json.load(f)
        stored = data.get('files', {})
    except Exception as e: return False, [f"Could not read manifest: {e}"]
    issues = []
    current_files = _collect_source_files(project_root)
    current_map = {}
    for fpath in current_files:
        rel = fpath.relative_to(project_root).as_posix()
        current_map[rel] = _hash_file(fpath)
    for rel, expected_hash in stored.items():
        actual = current_map.get(rel)
        if actual is None: issues.append(f"Missing: {rel}")
        elif actual != expected_hash: issues.append(f"Modified: {rel}")
    for rel in current_map:
        if rel not in stored: issues.append(f"New file: {rel}")
    return len(issues) == 0, issues

def run_startup_integrity_check(project_root):
    passed, issues = verify_integrity(project_root)
    if passed:
        if issues and issues[0].startswith("Integrity manifest created"):
            print("[OK] Integrity manifest created for future verification")
        else:
            print("[OK] Software integrity verified")
        return True
    else:
        print()
        print("=" * 60)
        print("  [Unverified modified program]")
        print("=" * 60)
        print(f"  {len(issues)} file(s) differ from the integrity manifest:")
        for issue in issues[:10]: print(f"    - {issue}")
        if len(issues) > 10: print(f"    ... and {len(issues) - 10} more")
        print()
        print("  Execution will continue, but this software may have")
        print("  been modified from its original verified state.")
        print("=" * 60)
        print()
        return False

# ===========================================================================
# infrastructure/filesystem
# ===========================================================================
def normalize_path(path):
    return os.path.normpath(path).replace('\\', '/').lstrip('/')

def is_path_safe(requested_path, base_dir):
    try:
        full_path = (base_dir / requested_path).resolve()
        base_resolved = base_dir.resolve()
        return str(full_path).startswith(str(base_resolved))
    except Exception: return False

def get_file_size_kb(file_path):
    try: return file_path.stat().st_size // 1024
    except OSError: return 0

def list_directory_entries(dir_path, relative_to, shared_paths):
    if not dir_path.is_dir(): return []
    entries = []
    try:
        for name in sorted(os.listdir(dir_path)):
            item_path = dir_path / name
            try: rel_path = item_path.relative_to(relative_to); rel_str = str(rel_path).replace('\\', '/')
            except ValueError: continue
            is_dir = item_path.is_dir()
            if is_dir:
                display_name = name + '/'
                path_key = rel_str + '/'
                size_str = 'Folder'
            else:
                display_name = name
                path_key = rel_str
                size_kb = get_file_size_kb(item_path)
                size_str = f'{size_kb:,} KB'
            shared = is_path_shared(path_key, shared_paths)
            tags = shared_paths.get(path_key, "") if shared else ""
            entries.append(ExplorerEntry(name=display_name, path=path_key, size=size_str, is_dir=is_dir, shared=shared, tags=tags))
    except Exception: pass
    return entries

def get_visible_paths_in_directory(dir_path):
    if not dir_path.is_dir(): return []
    paths = []
    try:
        for name in os.listdir(dir_path):
            item_path = dir_path / name
            rel = normalize_path(name)
            paths.append(rel)
            if item_path.is_dir(): paths.append(rel + '/')
    except Exception: pass
    return paths

# ===========================================================================
# infrastructure/network
# ===========================================================================
def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((DNS_PROBE_ADDRESS, DNS_PROBE_PORT))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception: return "127.0.0.1"

def get_public_ip():
    try:
        response = requests.get(PUBLIC_IP_API_URL, timeout=PUBLIC_IP_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.text.strip()
    except Exception: return "unknown"

def fetch_peer_shared_count(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/shared_count", timeout=SHARED_COUNT_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json().get('count')
    except Exception: return None

def fetch_peer_shared_list(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/shared_list", timeout=SHARED_LIST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json().get('items', [])
    except Exception: return None

def fetch_peer_info(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/api/info", timeout=PEER_INFO_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except Exception: return None

# ===========================================================================
# infrastructure/id_generator
# ===========================================================================
_used_call_numbers = set()

def generate_random_peer_id():
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return PeerId(f"bank-{suffix}")

def generate_call_number():
    while True:
        part1 = random.randint(100, 999)
        part2 = random.randint(100, 999)
        part3 = random.randint(1000, 9999)
        call_number = f"{part1}-{part2}-{part3}"
        if call_number not in _used_call_numbers:
            _used_call_numbers.add(call_number)
            return call_number

def generate_peer_id_from_ip(ip):
    return PeerId(f"unknown-{ip.replace('.', '-')}")

# ===========================================================================
# infrastructure/discovery
# ===========================================================================
class PeerDiscoveryListener(ServiceListener):
    def __init__(self, state, my_id):
        self.state = state
        self.my_id = my_id
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if not info: return
        properties = dict(info.properties or {})
        peer_id_bytes = properties.get(b'id', b'')
        peer_id_str = peer_id_bytes.decode() if peer_id_bytes else ''
        if not peer_id_str or peer_id_str == self.my_id.value: return
        for addr in info.parsed_addresses(IPVersion.V4Only):
            peer_info = PeerInfo(ip=addr, port=info.port, join_time=time.time(), last_seen=time.time())
            self.state.add_discovered_peer(peer_id_str, peer_info)
    def remove_service(self, zc, type_, name): pass
    def update_service(self, zc, type_, name): pass

def register_service(zc, my_id, local_ip):
    service_name = f"{my_id.value}.{SERVICE_TYPE}"
    info = ServiceInfo(SERVICE_TYPE, service_name, addresses=[socket.inet_aton(local_ip)], port=PORT, properties={b'id': my_id.value.encode()})
    zc.register_service(info)
    return info

def start_discovery(zc, state, my_id):
    listener = PeerDiscoveryListener(state, my_id)
    return ServiceBrowser(zc, SERVICE_TYPE, listener)

# ===========================================================================
# infrastructure/global_discovery
# ===========================================================================
GLOBAL_CONFIG_FILE = PROJECT_DIR / "global_config.json"
DEFAULT_GLOBAL_CONFIG = {"enabled": True, "relay_url": "http://localhost:3000", "network_code": "publan-global-v1", "auto_connect": True}

def load_global_config():
    if GLOBAL_CONFIG_FILE.exists():
        try: return json.loads(GLOBAL_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception: pass
    return DEFAULT_GLOBAL_CONFIG.copy()

def save_global_config(config):
    try: GLOBAL_CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except Exception: pass

class GlobalDiscoveryService:
    def __init__(self, my_peer_id, my_call_number, local_ip, local_port, on_peers_updated=None):
        self.my_peer_id = my_peer_id
        self.my_call_number = my_call_number
        self.local_ip = local_ip
        self.local_port = local_port
        self.on_peers_updated = on_peers_updated
        self.config = load_global_config()
        self.sio = None
        self.global_peers = []
        self.running = False
        self._thread = None
        self._loop = None
    @property
    def enabled(self): return bool(self.config.get("enabled") and self.config.get("network_code") and self.config.get("relay_url"))
    @property
    def network_code(self): return self.config.get("network_code", "")
    @property
    def relay_url(self): return self.config.get("relay_url", "http://localhost:3000")
    def start(self):
        if not self.enabled: return
        self.running = True
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="GlobalDiscoveryThread")
        self._thread.start()
    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._connect_and_run())
    async def _connect_and_run(self):
        self.sio = socketio.AsyncClient(reconnection=True, reconnection_attempts=0, reconnection_delay=5, reconnection_delay_max=30)
        @self.sio.event
        async def connect():
            await self._register()
        @self.sio.event
        async def disconnect(): pass
        @self.sio.on("global-peer-list")
        async def on_peer_list(data):
            self.global_peers = [p for p in (data or []) if p.get("peerId") != self.my_peer_id]
            if self.on_peers_updated:
                try: self.on_peers_updated(self.global_peers)
                except Exception: pass
        while self.running:
            try:
                await self.sio.connect(self.relay_url, wait_timeout=10)
                break
            except Exception: await asyncio.sleep(5)
        while self.running:
            for _ in range(10):
                if not self.running: break
                await asyncio.sleep(0.5)
            if not self.running: break
            if self.sio and self.sio.connected:
                try:
                    await self._register()
                    await self.sio.emit("request-global-peers", {"networkCode": self.network_code})
                except Exception: pass
    async def _register(self):
        if not self.sio or not self.sio.connected: return
        await self.sio.emit("register-global-peer", {"networkCode": self.network_code, "peerId": self.my_peer_id, "friendlyName": platform.node(), "ip": self.local_ip, "port": self.local_port, "callNumber": self.my_call_number})
    def stop(self):
        self.running = False
        if self.sio and self._loop and self._loop.is_running():
            try:
                future = asyncio.run_coroutine_threadsafe(self.sio.disconnect(), self._loop)
                future.result(timeout=5)
            except Exception: pass
        if self._thread and self._thread.is_alive(): self._thread.join(timeout=10)
    def get_status(self):
        if not self.enabled: return "DISABLED"
        if self.sio and self.sio.connected: return f"CONNECTED ({len(self.global_peers)} peers)"
        return "CONNECTING..."

# ===========================================================================
# infrastructure/persistence
# ===========================================================================
def load_shared_paths():
    if not SHARED_PATHS_FILE.exists(): return {}
    try:
        with open(SHARED_PATHS_FILE, encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict): return data
            return {}
    except Exception: return {}

def save_shared_paths(paths):
    try:
        SHARED_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SHARED_PATHS_FILE, 'w', encoding='utf-8') as f: json.dump(paths, f, indent=2, ensure_ascii=False)
    except Exception: pass

def load_known_peers():
    if not PEERS_FILE.exists(): return {}
    try:
        with open(PEERS_FILE, encoding='utf-8') as f:
            raw_data = json.load(f)
            peers = {}
            for pid, data in raw_data.items():
                try: peers[pid] = PeerInfo(ip=data['ip'], port=data['port'], join_time=data.get('join_time', 0.0), last_seen=data.get('last_seen', 0.0))
                except (KeyError, TypeError): pass
            return peers
    except Exception: return {}

def save_known_peers(peers):
    try:
        PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        raw_data = {pid: {'ip': info.ip, 'port': info.port, 'join_time': info.join_time, 'last_seen': info.last_seen} for pid, info in peers.items()}
        with open(PEERS_FILE, 'w', encoding='utf-8') as f: json.dump(raw_data, f, indent=2)
    except Exception: pass

def load_join_time():
    if MY_JOIN_TIME_FILE.exists():
        try: return float(MY_JOIN_TIME_FILE.read_text().strip())
        except (ValueError, IOError): pass
    join_time = time.time()
    try:
        MY_JOIN_TIME_FILE.parent.mkdir(parents=True, exist_ok=True)
        MY_JOIN_TIME_FILE.write_text(str(join_time))
    except Exception: pass
    return join_time

# ===========================================================================
# application/state
# ===========================================================================
@dataclass
class ApplicationState:
    my_id: PeerId
    my_join_time: float
    local_ip: str
    public_ip: str
    call_number: str = ""
    shared_paths: SharedPaths = field(default_factory=dict)
    known_peers: PeerRegistry = field(default_factory=dict)
    discovered_peers: PeerRegistry = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    def get_my_info(self):
        with self._lock:
            ip = self.public_ip if self.public_ip != "unknown" else self.local_ip
            return PeerInfo(ip=ip, port=PORT, join_time=self.my_join_time, last_seen=time.time())
    def update_shared_paths(self, new_paths):
        with self._lock: self.shared_paths = new_paths
    def get_shared_paths(self):
        with self._lock: return dict(self.shared_paths)
    def add_known_peer(self, peer_id, info):
        with self._lock: self.known_peers[peer_id] = info
    def get_known_peers(self):
        with self._lock: return dict(self.known_peers)
    def add_discovered_peer(self, peer_id, info):
        with self._lock: self.discovered_peers[peer_id] = info
    def get_discovered_peers(self):
        with self._lock: return dict(self.discovered_peers)

# ===========================================================================
# upload transfer system
# ===========================================================================
_pending_uploads = {}
_pending_uploads_lock = threading.Lock()
_upload_counter = 0

def _generate_upload_id():
    global _upload_counter
    _upload_counter += 1
    return f"upload-{int(time.time())}-{_upload_counter}"

def add_pending_upload(sender_id, sender_ip, filename, dest_path, file_data):
    with _pending_uploads_lock:
        upload_id = _generate_upload_id()
        _pending_uploads[upload_id] = {
            'id': upload_id,
            'sender_id': sender_id,
            'sender_ip': sender_ip,
            'filename': filename,
            'dest_path': dest_path,
            'file_data': file_data,
            'file_size': len(file_data),
            'timestamp': time.time(),
            'status': 'pending'
        }
        return upload_id

def get_pending_uploads():
    with _pending_uploads_lock:
        return [
            {k: v for k, v in u.items() if k != 'file_data'}
            for u in _pending_uploads.values()
            if u['status'] == 'pending'
        ]

def accept_upload(upload_id):
    with _pending_uploads_lock:
        upload = _pending_uploads.get(upload_id)
        if not upload or upload['status'] != 'pending':
            return None
        upload['status'] = 'accepted'
        return dict(upload)

def reject_upload(upload_id):
    with _pending_uploads_lock:
        upload = _pending_uploads.get(upload_id)
        if not upload or upload['status'] != 'pending':
            return False
        upload['status'] = 'rejected'
        upload['file_data'] = b''
        return True

def cleanup_old_uploads(max_age=300):
    with _pending_uploads_lock:
        now = time.time()
        expired = [uid for uid, u in _pending_uploads.items()
                   if now - u['timestamp'] > max_age and u['status'] != 'pending']
        for uid in expired:
            _pending_uploads.pop(uid, None)

# ===========================================================================
# folder sync system
# ===========================================================================
_active_syncs = {}
_active_syncs_lock = threading.Lock()
_sync_counter = 0

def _generate_sync_id():
    global _sync_counter
    _sync_counter += 1
    return f"sync-{int(time.time())}-{_sync_counter}"

def add_active_sync(peer_id, local_path, remote_path, peer_ip, peer_port):
    with _active_syncs_lock:
        sync_id = _generate_sync_id()
        _active_syncs[sync_id] = {
            'id': sync_id,
            'peer_id': peer_id,
            'peer_ip': peer_ip,
            'peer_port': peer_port,
            'local_path': local_path,
            'remote_path': remote_path,
            'active': True,
            'last_sync': time.time(),
            'files_synced': 0,
            'stop': False,
        }
        return sync_id

def get_active_syncs():
    with _active_syncs_lock:
        return [
            {k: v for k, v in s.items() if k != 'stop'}
            for s in _active_syncs.values()
            if not s.get('stop', False)
        ]

def stop_sync(sync_id):
    with _active_syncs_lock:
        s = _active_syncs.get(sync_id)
        if s:
            s['stop'] = True
            s['active'] = False
            return True
        return False

def run_sync_job(sync_id, state):
    """Background worker: periodically pull files from peer into local folder."""
    while True:
        with _active_syncs_lock:
            s = _active_syncs.get(sync_id)
            if not s or s.get('stop', False):
                return
            peer_ip = s['peer_ip']
            peer_port = s['peer_port']
            remote_path = s['remote_path']
            local_path = s['local_path']
            s['active'] = True
        try:
            # Fetch remote file list
            url = f"http://{peer_ip}:{peer_port}/shared_list"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            items = data.get('items', [])
            home = Path.home()
            target_dir = home / local_path.rstrip('/')
            target_dir.mkdir(parents=True, exist_ok=True)
            count = 0
            for item in items:
                if item.get('is_folder', False):
                    continue
                item_path = item.get('path', '')
                if remote_path and not item_path.startswith(remote_path):
                    continue
                # Download the file
                try:
                    dl_url = f"http://{peer_ip}:{peer_port}/preview/{item_path}?download=1"
                    dl_resp = requests.get(dl_url, timeout=30)
                    if dl_resp.status_code == 200:
                        file_name = Path(item_path).name
                        dest_file = target_dir / file_name
                        # Only write if different size or missing
                        if not dest_file.exists() or dest_file.stat().st_size != len(dl_resp.content):
                            with open(dest_file, 'wb') as f:
                                f.write(dl_resp.content)
                            count += 1
                except Exception:
                    pass
            with _active_syncs_lock:
                s2 = _active_syncs.get(sync_id)
                if s2:
                    s2['files_synced'] = count
                    s2['last_sync'] = time.time()
                    s2['active'] = False
        except Exception as e:
            with _active_syncs_lock:
                s3 = _active_syncs.get(sync_id)
                if s3:
                    s3['active'] = False
            print(f"[SYNC] Error syncing {sync_id}: {e}")
        # Wait 30 seconds before next sync cycle
        for _ in range(30):
            time.sleep(1)
            with _active_syncs_lock:
                s4 = _active_syncs.get(sync_id)
                if not s4 or s4.get('stop', False):
                    return

# ===========================================================================
# remote permission popup prompt (asks host user to approve each action)
# ===========================================================================
_PERM_ACTION_LABELS = {
    'remote_exec': 'Remote Terminal Access',
    'clipboard_write': 'Write to Clipboard',
    'clipboard_read': 'Read Clipboard',
    'power_control': 'Power Control (shutdown/restart/sleep)',
    'screenshot': 'Capture Screenshot',
    'notify': 'Send Notification',
    'process_manager': 'View/Kill Processes',
    'screen_record': 'Record Screen',
    'remote_audio': 'Listen to Microphone',
    'system_audio': 'Listen to System Audio',
    'input_monitor': 'Monitor Keyboard/Mouse Input',
}

def prompt_remote_permission(action_key, requester_info='a remote peer'):
    """Show a blocking Windows MessageBox asking the host to approve an action.
    Returns True if approved, False if denied."""
    label = _PERM_ACTION_LABELS.get(action_key, action_key)
    try:
        ps_script = (
            'Add-Type -AssemblyName System.Windows.Forms;'
            f'$result = [System.Windows.Forms.MessageBox]::Show('
            f'"A remote peer ({requester_info}) is requesting permission to:\\n\\n'
            f'{label}\\n\\nAllow this action?", '
            f'"GNA Permission Request", "YesNo", "Warning");'
            '$result'
        )
        result = subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip().lower() == 'yes'
    except Exception:
        return False

# Input monitor state
_input_monitor_lock = threading.Lock()
_input_monitor_active = False
_input_monitor_events = []
_input_monitor_thread = None

# Mic audio streaming state
_audio_stream_lock = threading.Lock()
_audio_stream_active = False
_audio_stream_chunks = []  # list of base64 WAV chunks
_audio_stream_thread = None

# System audio streaming state
_sys_audio_active = False
_sys_audio_chunks = []
_sys_audio_thread = None

def is_local_request():
    addr = flask_request.remote_addr or ''
    return addr in ('127.0.0.1', '::1', 'localhost')

# ===========================================================================
# application/use_cases
# ===========================================================================
def get_sorted_live_peers(state):
    return get_live_peers(my_id=state.my_id, my_info=state.get_my_info(), known_peers=state.get_known_peers(), discovered_peers=state.get_discovered_peers(), current_time=time.time(), timeout_seconds=PEER_TIMEOUT_SECONDS)

def get_current_failover_chain(state):
    return get_failover_chain(get_sorted_live_peers(state), MAX_FAILOVER_CHAIN_SIZE)

def get_current_role(state):
    return get_my_role(state.my_id, get_sorted_live_peers(state))

def get_shared_items_list(state):
    items = []
    for path in state.shared_paths:
        full_item_path = SHARED_DIR / path.rstrip('/')
        is_folder = path.endswith('/')
        if is_folder: size_str = "Folder"
        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
        else: size_str = "N/A"
        name = os.path.basename(path.rstrip('/'))
        if is_folder: name += '/'
        items.append(SharedItem(path=path, name=name, size_str=size_str, is_folder=is_folder))
    return items

def get_preview_items(state, max_items=None):
    items = []
    sorted_paths = sorted(state.shared_paths.keys())
    if max_items is not None: sorted_paths = sorted_paths[:max_items]
    for path in sorted_paths:
        full_item_path = SHARED_DIR / path.rstrip('/')
        is_folder = path.endswith('/')
        if is_folder: size_str = "Folder"
        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
        else: size_str = "N/A"
        name = os.path.basename(path.rstrip('/'))
        if is_folder: name += '/'
        item = {'name': name, 'size': size_str, 'is_folder': is_folder, 'path': path.lstrip('/')}
        if is_folder: item['download_url'] = f"/preview/{item['path'].rstrip('/')}?download=1"
        elif full_item_path.exists(): item['download_url'] = f"/preview/{item['path']}?download=1"
        else: item['download_url'] = None
        items.append(item)
    return items

def list_explorer_directory(state, requested_path):
    full_path = SHARED_DIR / requested_path if requested_path else SHARED_DIR
    return list_directory_entries(full_path, SHARED_DIR, state.shared_paths)

def update_selection(state, current_path, selected_paths, tags_map=None):
    if tags_map is None: tags_map = {}
    if not isinstance(state.shared_paths, dict): state.shared_paths = {}
    current_norm = normalize_path(current_path) if current_path else ''
    current_prefix = current_norm + '/' if current_norm else ''
    full_path = SHARED_DIR / current_path if current_path else SHARED_DIR
    visible_paths = set(get_visible_paths_in_directory(full_path))
    to_remove = set()
    for p in list(state.shared_paths):
        if p in visible_paths and p not in selected_paths: to_remove.add(p)
        elif current_prefix and p.startswith(current_prefix) and p not in selected_paths: to_remove.add(p)
    for p in to_remove: del state.shared_paths[p]
    for rel_path in selected_paths:
        if not rel_path: continue
        clean_path = normalize_path(rel_path)
        if rel_path.endswith('/') and clean_path and not clean_path.endswith('/'): clean_path += '/'
        if clean_path:
            if rel_path in tags_map: tag_val = tags_map[rel_path]
            elif clean_path in tags_map: tag_val = tags_map[clean_path]
            elif clean_path in state.shared_paths: tag_val = state.shared_paths[clean_path]
            else: tag_val = ""
            state.shared_paths[clean_path] = tag_val
    save_shared_paths(state.shared_paths)

def _matches_query(name, tags, query_terms):
    name_lower = name.lower()
    tags_lower = tags.lower() if tags else ""
    tag_list = [t.strip() for t in tags_lower.split(',') if t.strip()] if tags_lower else []
    for term in query_terms:
        if term in name_lower: continue
        if any(term in t for t in tag_list): continue
        return False
    return True

def search_network(state, query):
    q_raw = query.strip()
    if not q_raw: return []
    query_terms = [t.strip().lower() for t in q_raw.split(',') if t.strip()]
    if not query_terms: return []
    all_results = []
    sorted_live = get_sorted_live_peers(state)
    for pid, data in sorted_live:
        ip, port = data.ip, data.port
        try:
            if pid == state.my_id.value:
                for path, tags in list(state.shared_paths.items()):
                    name = os.path.basename(path.rstrip('/'))
                    if _matches_query(name, tags, query_terms):
                        is_folder = path.endswith('/')
                        full_item_path = SHARED_DIR / path.rstrip('/')
                        if is_folder: size_str = "Folder"
                        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
                        else: size_str = "N/A"
                        tag_display = f" [{tags}]" if tags else ""
                        all_results.append(SearchResult(bank_id=pid, name=name + ('/' if is_folder else '') + tag_display, size=size_str, is_folder=is_folder, link=f"/preview/{path.lstrip('/')}"))
            else:
                remote_items = fetch_peer_shared_list(ip, port)
                if remote_items:
                    for item in remote_items:
                        item_tags = item.get('tags', '')
                        if _matches_query(item['name'], item_tags, query_terms):
                            tag_display = f" [{item_tags}]" if item_tags else ""
                            all_results.append(SearchResult(bank_id=pid, name=item['name'] + tag_display, size=item['size'], is_folder=item['is_folder'], link=f"/peer_download/{pid}/{item['path'].lstrip('/')}"))
        except Exception as e:
            print(f"Search failed for peer {pid}: {e}")
    return all_results

def add_manual_peer(state, ip, port):
    peer_id = generate_peer_id_from_ip(ip)
    peer_info_data = fetch_peer_info(ip, port)
    if peer_info_data and 'id' in peer_info_data: peer_id = PeerId(peer_info_data['id'])
    info = PeerInfo(ip=ip, port=port, join_time=time.time(), last_seen=time.time())
    state.add_known_peer(peer_id.value, info)
    save_known_peers(state.known_peers)
    return peer_id

def update_peer_bookkeeping(state):
    now = time.time()
    state.known_peers[state.my_id.value] = PeerInfo(ip=state.public_ip if state.public_ip != "unknown" else state.local_ip, port=PORT, join_time=state.my_join_time, last_seen=now)
    save_known_peers(state.known_peers)

# ===========================================================================
# presentation/templates
# ===========================================================================
def render_homepage(random_id, failover_chain, peers_list, live_count, about_text, call_number=""):
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Global Network Archive</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ background: #0d1117; color: #e6edf3; font-family: 'Inter', system-ui, sans-serif; margin-bottom: 60px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; }}
        .card-header {{ background: #21262d; border-bottom: 1px solid #30363d; color: #58a6ff; }}
        a {{ color: #58a6ff; }}
        a:hover {{ color: #79c0ff; }}
        .btn-primary {{ background: #238636; border-color: #238636; }}
        .btn-primary:hover {{ background: #2ea043; }}
        .btn-outline-light {{ --bs-btn-color: #e6edf3; --bs-btn-border-color: #444d56; }}
        .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }}
        .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }}
        .warning {{ background: #21262d; border-left: 4px solid #f0883e; color: #f2c46d; }}
        small {{ color: #8b949e; }}
        .preview-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1050; display: none; align-items: center; justify-content: center; }}
        .preview-modal .modal-dialog {{ max-width: 90vw; max-height: 90vh; width: 80vw !important; height: 80vh !important; margin: auto; }}
        .preview-modal .modal-content {{ display: flex !important; flex-direction: column !important; resize: both !important; overflow: hidden !important; height: 100% !important; width: 100% !important; background: #161b22 !important; border: 1px solid #30363d !important; border-radius: 8px !important; padding: 1rem !important; }}
        .preview-modal .preview-body {{ flex: 1; display: flex; flex-direction: column; border: 1px solid #30363d; border-radius: 4px; overflow: hidden; }}
        .preview-modal .preview-search {{ padding: 0.5rem; border-bottom: 1px solid #30363d; }}
        .preview-modal .preview-list {{ flex: 1; overflow-y: auto; padding: 0.5rem; }}
        .preview-modal .list-group {{ margin: 0; }}
        .form-control-lg {{ background: #161b22 !important; border-color: #444d56; color: white; }}
        .version-footer {{ position: fixed; bottom: 10px; left: 20px; font-size: 0.75rem; color: #6c757d; opacity: 0.7; z-index: 1000; }}
        .web-search-bar {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .web-search-bar input {{ background: #0d1117 !important; border-color: #444d56; color: #e6edf3; }}
        .web-search-bar input:focus {{ border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.15); }}
        .search-engine-btns .btn {{ font-size: 0.8rem; padding: 4px 12px; margin: 2px; }}
        .search-engine-btns .btn.active {{ background: #238636; border-color: #238636; }}
        .web-result {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; transition: border-color 0.2s; }}
        .web-result:hover {{ border-color: #58a6ff; }}
        .web-result-title {{ color: #58a6ff; font-size: 1.05rem; font-weight: 600; text-decoration: none; display: block; margin-bottom: 4px; }}
        .web-result-title:hover {{ color: #79c0ff; text-decoration: underline; }}
        .web-result-url {{ color: #3fb950; font-size: 0.8rem; margin-bottom: 4px; word-break: break-all; }}
        .web-result-snippet {{ color: #8b949e; font-size: 0.9rem; line-height: 1.4; }}
        .web-search-meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 15px; }}
        .remote-access-alert {{ background: linear-gradient(135deg, #da3633 0%, #b62324 100%); border: 2px solid #f85149; color: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; display: none; align-items: center; justify-content: space-between; animation: pulse-border 2s infinite; }}
        @keyframes pulse-border {{ 0%, 100% {{ border-color: #f85149; box-shadow: 0 0 8px rgba(248,81,73,0.3); }} 50% {{ border-color: #ff7b72; box-shadow: 0 0 16px rgba(248,81,73,0.6); }} }}
        .remote-access-alert .remote-info {{ display: flex; align-items: center; gap: 12px; }}
        .remote-access-alert .remote-icon {{ font-size: 1.5rem; }}
        .upload-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060; display: none; align-items: center; justify-content: center; }}
        .upload-modal .upload-dialog {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 500px; max-width: 90vw; }}
        .incoming-upload-banner {{ background: linear-gradient(135deg, #1f6feb 0%, #1a4fa0 100%); border: 2px solid #58a6ff; color: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 15px; display: none; align-items: center; justify-content: space-between; animation: pulse-blue 2s infinite; }}
        @keyframes pulse-blue {{ 0%, 100% {{ border-color: #58a6ff; box-shadow: 0 0 8px rgba(88,166,255,0.3); }} 50% {{ border-color: #79c0ff; box-shadow: 0 0 16px rgba(88,166,255,0.6); }} }}
        .gna-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060; display: none; align-items: center; justify-content: center; }}
        .gna-modal .gna-dialog {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 600px; max-width: 92vw; max-height: 85vh; overflow-y: auto; }}
        .ping-result {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 0.9rem; }}
        .ping-ok {{ color: #3fb950; }} .ping-warn {{ color: #d29922; }} .ping-fail {{ color: #f85149; }}
        .file-tree-item {{ padding: 6px 12px; border-bottom: 1px solid #21262d; cursor: pointer; transition: background 0.15s; display: flex; align-items: center; justify-content: space-between; }}
        .file-tree-item:hover {{ background: #21262d; }}
        .sync-status {{ font-size: 0.8rem; padding: 3px 8px; border-radius: 4px; }}
        .sync-active {{ background: #238636; color: white; }} .sync-idle {{ background: #30363d; color: #8b949e; }}
        .term-output {{ background: #000; color: #0f0; font-family: 'Consolas', 'Courier New', monospace; font-size: 0.85rem; padding: 12px; border-radius: 6px; max-height: 350px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #30363d; }}
        .term-input {{ background: #0d1117; color: #0f0; font-family: 'Consolas', monospace; border: 1px solid #30363d; }}
        .term-input:focus {{ border-color: #f85149; box-shadow: 0 0 0 3px rgba(248,81,73,0.2); color: #0f0; background: #0d1117; }}
        .power-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .power-grid .btn {{ padding: 16px; font-size: 0.95rem; }}
        .bw-bar {{ background: #21262d; border-radius: 6px; overflow: hidden; height: 24px; }}
        .bw-fill {{ height: 100%; background: linear-gradient(90deg, #238636, #3fb950); transition: width 0.3s; border-radius: 6px; }}
        .screenshot-img {{ max-width: 100%; border-radius: 6px; border: 1px solid #30363d; cursor: pointer; }}
        .sysinfo-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; font-size: 0.88rem; }}
        .sysinfo-grid .si-label {{ color: #8b949e; text-align: right; }} .sysinfo-grid .si-val {{ color: #e6edf3; word-break: break-word; }}
        .proc-table {{ font-size: 0.82rem; }} .proc-table th {{ position: sticky; top: 0; background: #161b22; z-index: 1; }}
        .proc-list-wrap {{ max-height: 400px; overflow-y: auto; border: 1px solid #30363d; border-radius: 6px; }}
        .screenrec-frame {{ max-width: 100%; border-radius: 6px; border: 1px solid #30363d; }}
        .rec-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #f85149; animation: recPulse 1s infinite; margin-right: 6px; }}
        @keyframes recPulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}
        .audio-visualizer {{ height: 60px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; display: flex; align-items: flex-end; gap: 2px; padding: 4px 8px; }}
        .audio-bar {{ flex: 1; background: #3fb950; border-radius: 2px 2px 0 0; transition: height 0.15s; min-height: 2px; }}
        .keylog-feed {{ background: #0d1117; color: #e6edf3; font-family: 'Consolas', monospace; font-size: 0.82rem; padding: 12px; border: 1px solid #30363d; border-radius: 6px; max-height: 350px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; min-height: 100px; }}
        .keylog-key {{ color: #58a6ff; }} .keylog-special {{ color: #d29922; }} .keylog-mouse {{ color: #f85149; }} .keylog-time {{ color: #8b949e; font-size: 0.75rem; }}
    </style>
</head>
<body class="p-5">
<div class="container">
    <div id="remote-access-banner" class="remote-access-alert">
        <div class="remote-info">
            <span class="remote-icon">WARNING</span>
            <div>
                <strong>REMOTE ACCESS ACTIVE</strong><br>
                <span id="remote-access-detail">Someone is currently controlling your system.</span>
            </div>
        </div>
        <button class="btn btn-light btn-sm fw-bold" onclick="revokeRemoteAccess()" id="revoke-remote-btn">Revoke Access</button>
    </div>
    <div id="incoming-uploads-container"></div>
    <div class="warning p-3 mb-5 rounded">
        <strong>SELECTIVE SHARING ACTIVE</strong><br>
        Only explicitly selected content is visible to others.
    </div>
    <h1 class="text-center mb-5">Global Network Archive</h1>
    <div class="mb-5 text-center">
        <form action="/search" method="get" class="d-inline-flex w-75">
            <input type="text" name="q" class="form-control form-control-lg me-3 bg-dark text-white border-secondary" placeholder="Search across all live instances..." required autofocus>
            <button type="submit" class="btn btn-primary btn-lg px-5">Search</button>
        </form>
    </div>
    <ul class="nav nav-tabs mb-5 justify-content-center border-bottom-0">
        <li class="nav-item"><a class="nav-link active text-white" data-bs-toggle="tab" href="#dashboard">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link text-white" href="/explorer">My Explorer</a></li>
        <li class="nav-item"><a class="nav-link text-white" href="/vault">Vault</a></li>
        <li class="nav-item"><a class="nav-link text-white" data-bs-toggle="tab" href="#websearch">Web Search</a></li>
        <li class="nav-item"><a class="nav-link text-white" data-bs-toggle="tab" href="#about">About</a></li>
    </ul>
    <div class="tab-content">
        <div class="tab-pane fade show active" id="dashboard">
            <div class="row g-4">
                <div class="col-lg-8">
                    <div class="card mb-4">
                        <div class="card-header">Your Instance</div>
                        <div class="card-body">
                            <p><strong>ID:</strong> {random_id} <small class="text-secondary">(session-based)</small></p>
                            <p><strong>Call Number:</strong> <span class="text-warning">{call_number}</span></p>
                            <p><strong>Role:</strong> Primary</p>
                            <a href="/explorer" class="btn btn-primary btn-lg w-100 mt-3">Manage Shared Content</a>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4">
                    <div class="card mb-4">
                        <div class="card-header">Failover Chain</div>
                        <div class="card-body p-0">
                            <table class="table table-sm mb-0">
                                <thead><tr><th>Role</th><th>ID</th></tr></thead>
                                <tbody>{"".join(f"<tr><td>{c['role']}</td><td>{c['id']}</td></tr>" for c in failover_chain)}</tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card mb-4">
                <div class="card-header">Connect to Remote Instance</div>
                <div class="card-body">
                    <form method="post" action="/add_peer">
                        <input type="text" name="ip_port" class="form-control mb-3 bg-dark text-white border-secondary" placeholder="e.g., 192.168.1.100:5000" required>
                        <button type="submit" class="btn btn-outline-light w-100">Connect</button>
                    </form>
                </div>
            </div>
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span>Active Instances — {live_count}</span>
                    <button class="btn btn-sm btn-outline-success" id="reconnect-relay-btn" onclick="reconnectRelay()">Reconnect Relay</button>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead><tr><th>ID</th><th>Shared Items</th><th>Actions</th></tr></thead>
                        <tbody>
                        {''.join(
                            f'<tr>'
                            f'<td>{p["id"]}<br><small class="text-muted">Call#: {p.get("call_number", "N/A")}</small></td>'
                            f'<td><span class="shared-count text-secondary" data-peer-id="{p["id"]}">Loading...</span></td>'
                            f'<td>'
                            f' <button class="btn btn-sm btn-outline-info me-1 preview-btn" data-peer-id="{p["id"]}">Preview</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 connect-btn" data-peer-id="{p["id"]}">Connect</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 view-screen-btn" data-peer-id="{p["id"]}">View Screen</button>'
                            f' <button class="btn btn-sm btn-outline-warning call-btn" data-peer-id="{p["id"]}">Call this PC</button>'
                            f' <button class="btn btn-sm btn-outline-primary me-1 upload-btn" data-peer-id="{p["id"]}">Upload</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 ping-btn" data-peer-id="{p["id"]}">Ping</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 request-file-btn" data-peer-id="{p["id"]}">Request File</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 sync-folder-btn" data-peer-id="{p["id"]}">Sync Folder</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 remote-term-btn" data-peer-id="{p["id"]}">Terminal</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 clipboard-btn" data-peer-id="{p["id"]}">Clipboard</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 power-btn" data-peer-id="{p["id"]}">Power</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 bw-test-btn" data-peer-id="{p["id"]}">Speed Test</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 screenshot-btn" data-peer-id="{p["id"]}">Screenshot</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 sysinfo-btn" data-peer-id="{p["id"]}">Sys Info</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 notify-btn" data-peer-id="{p["id"]}">Notify</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 procmgr-btn" data-peer-id="{p["id"]}">Processes</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 screenrec-btn" data-peer-id="{p["id"]}">Record</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 remote-audio-btn" data-peer-id="{p["id"]}">Mic Audio</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 sys-audio-btn" data-peer-id="{p["id"]}">Sys Audio</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 input-monitor-btn" data-peer-id="{p["id"]}">Keylog</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 wol-btn" data-peer-id="{p["id"]}">Wake-on-LAN</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 app-launch-btn" data-peer-id="{p["id"]}">App Launch</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 file-exec-btn" data-peer-id="{p["id"]}">File Exec</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 disk-info-btn" data-peer-id="{p["id"]}">Disk Info</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 event-log-btn" data-peer-id="{p["id"]}">Event Log</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 health-btn" data-peer-id="{p["id"]}">Health</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 printers-btn" data-peer-id="{p["id"]}">Printers</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 shared-term-btn" data-peer-id="{p["id"]}">Shared Term</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 wallpaper-btn" data-peer-id="{p["id"]}">Wallpaper</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 software-btn" data-peer-id="{p["id"]}">Software</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 registry-btn" data-peer-id="{p["id"]}">Registry</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 net-conns-btn" data-peer-id="{p["id"]}">Net Conns</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 env-vars-btn" data-peer-id="{p["id"]}">Env Vars</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 hosts-file-btn" data-peer-id="{p["id"]}">Hosts File</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 url-open-btn" data-peer-id="{p["id"]}">URL Open</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 drivers-btn" data-peer-id="{p["id"]}">Drivers</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 net-adapters-btn" data-peer-id="{p["id"]}">Net Adapters</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 firewall-btn" data-peer-id="{p["id"]}">Firewall</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 battery-btn" data-peer-id="{p["id"]}">Battery</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 webcam-snap-btn" data-peer-id="{p["id"]}">Webcam Snap</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 webcam-stream-btn" data-peer-id="{p["id"]}">Webcam Stream</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 location-btn" data-peer-id="{p["id"]}">Location</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 recent-files-btn" data-peer-id="{p["id"]}">Recent Files</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 bios-info-btn" data-peer-id="{p["id"]}">BIOS Info</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 perf-monitor-btn" data-peer-id="{p["id"]}">Perf Monitor</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 voice-note-btn" data-peer-id="{p["id"]}">Voice Note</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 tts-btn" data-peer-id="{p["id"]}">TTS</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 play-sound-btn" data-peer-id="{p["id"]}">Play Sound</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 mouse-jiggler-btn" data-peer-id="{p["id"]}">Mouse Jiggler</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 cursor-prank-btn" data-peer-id="{p["id"]}">Cursor Prank</button>'
                            f'</td></tr>'
                            for p in peers_list
                        )}
                        </tbody>
                    </table>
                </div>
            </div>
                    </div>
        <div class="tab-pane fade" id="websearch">
            <div class="web-search-bar">
                <h5 class="mb-3" style="color:#58a6ff;">Web Search</h5>
                <div class="d-flex">
                    <input type="text" id="webSearchInput" class="form-control form-control-lg me-3" placeholder="Search the web..." autocomplete="off">
                    <button class="btn btn-primary btn-lg px-4" onclick="doWebSearch()">Search</button>
                </div>
                <div class="mt-3 search-engine-btns">
                    <span class="text-secondary me-2" style="font-size:0.85rem;">Also try:</span>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('google')">Google</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('bing')">Bing</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('yahoo')">Yahoo</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('duckduckgo')">DuckDuckGo</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('brave')">Brave</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('wikipedia')">Wikipedia</button>
                </div>
            </div>
            <div id="webSearchMeta" class="web-search-meta" style="display:none;"></div>
            <div id="webSearchResults"></div>
            <div id="webSearchLoading" style="display:none;" class="text-center py-5">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-3 text-secondary">Searching the web...</p>
            </div>
        </div>
        <div class="tab-pane fade" id="about">
            <div class="card">
                <div class="card-body">
                    {about_text}
                </div>
            </div>
        </div>
    </div>
</div>
<div class="version-footer">v{VERSION}</div>
<div id="previewModal" class="preview-modal">
    <div class="modal-dialog modal-lg">
        <div id="previewContent" class="modal-content"></div>
    </div>
</div>
<div id="uploadModal" class="upload-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="upload-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Upload File to Peer</h5>
        <p class="text-secondary small mb-3">Select a file and choose where to place it on the remote PC.</p>
        <form id="uploadForm" enctype="multipart/form-data">
            <input type="hidden" id="uploadTargetPeerId" value="">
            <div class="mb-3">
                <label class="form-label small">Target Peer:</label>
                <div id="uploadTargetDisplay" class="text-warning fw-bold"></div>
            </div>
            <div class="mb-3">
                <label class="form-label small">File to send:</label>
                <input type="file" id="uploadFile" name="file" class="form-control bg-dark text-white border-secondary" required>
            </div>
            <div class="mb-3">
                <label class="form-label small">Destination path on remote PC:</label>
                <input type="text" id="uploadDestPath" name="dest_path" class="form-control bg-dark text-white border-secondary" placeholder="e.g. Desktop/received_files/" value="Desktop/">
                <small class="text-muted">Relative to the remote user's home directory</small>
            </div>
            <div id="uploadStatus" class="mb-3" style="display:none;"></div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary flex-fill" id="uploadPlaceBtn">Place</button>
                <button type="button" class="btn btn-outline-light flex-fill" onclick="document.getElementById('uploadModal').style.display='none'">Cancel</button>
            </div>
        </form>
    </div>
</div>
<div id="requestFileModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Request File from Peer</h5>
        <p class="text-secondary small mb-2">Browse the peer's shared files and download what you need.</p>
        <input type="hidden" id="rfTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="rfTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-2">
            <input type="text" id="rfSearchInput" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter files..." oninput="filterRequestFiles()">
        </div>
        <div id="rfLoading" class="text-center py-3" style="display:none;"><div class="spinner-border spinner-border-sm text-primary"></div> Loading shared files...</div>
        <div id="rfFileList" style="max-height:350px;overflow-y:auto;border:1px solid #30363d;border-radius:6px;"></div>
        <div id="rfStatus" class="mt-2" style="display:none;"></div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('requestFileModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="syncFolderModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Sync Folder with Peer</h5>
        <p class="text-secondary small mb-3">Keep a local folder in sync with a peer's shared folder. New or updated files are copied automatically.</p>
        <input type="hidden" id="sfTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="sfTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Local folder to sync into:</label>
            <input type="text" id="sfLocalPath" class="form-control bg-dark text-white border-secondary" placeholder="e.g. Desktop/synced/" value="Desktop/synced/">
            <small class="text-muted">Relative to your home directory</small>
        </div>
        <div class="mb-3">
            <label class="form-label small">Remote folder to sync from (leave empty for all shared):</label>
            <input type="text" id="sfRemotePath" class="form-control bg-dark text-white border-secondary" placeholder="/ (root of shared content)" value="">
        </div>
        <div id="sfStatus" class="mb-3" style="display:none;"></div>
        <div id="sfActiveSyncs"></div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-success flex-fill" id="sfStartBtn" onclick="startSync()">Start Sync</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('syncFolderModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="remoteTermModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#f85149;">Remote Terminal</h5>
        <p class="text-secondary small mb-2">Execute commands on the remote peer. <strong class="text-danger">Use responsibly.</strong></p>
        <input type="hidden" id="rtTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="rtTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="rtOutput" class="term-output mb-2">Ready. Type a command below.\n</div>
        <div class="d-flex gap-2">
            <input type="text" id="rtCmdInput" class="form-control term-input flex-fill" placeholder="Enter command..." autocomplete="off">
            <button class="btn btn-danger" id="rtSendBtn" onclick="sendTermCmd()">Run</button>
        </div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-outline-secondary flex-fill" onclick="document.getElementById('rtOutput').textContent='Ready.\\n'">Clear</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('remoteTermModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="clipboardModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#58a6ff;">Clipboard Sync</h5>
        <p class="text-secondary small mb-2">Send your clipboard to the peer, or grab theirs.</p>
        <input type="hidden" id="cbTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="cbTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Text to send (or paste here):</label>
            <textarea id="cbTextArea" class="form-control bg-dark text-white border-secondary" rows="4" placeholder="Paste or type text to send..."></textarea>
        </div>
        <div id="cbStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-primary flex-fill" onclick="sendClipboard()">Send to Peer</button>
            <button class="btn btn-outline-info flex-fill" onclick="grabClipboard()">Grab from Peer</button>
        </div>
        <div class="d-flex gap-2 mt-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('clipboardModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="powerModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#d29922;">Power Control</h5>
        <p class="text-secondary small mb-3">Send power commands to the remote peer.</p>
        <input type="hidden" id="pwTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="pwTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="pwStatus" class="mb-3" style="display:none;"></div>
        <div class="power-grid mb-3">
            <button class="btn btn-outline-success" onclick="sendPowerCmd('wake')">Wake (WOL)</button>
            <button class="btn btn-outline-warning" onclick="sendPowerCmd('sleep')">Sleep</button>
            <button class="btn btn-outline-info" onclick="sendPowerCmd('restart')">Restart</button>
            <button class="btn btn-outline-danger" onclick="sendPowerCmd('shutdown')">Shutdown</button>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('powerModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="bwTestModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#3fb950;">Bandwidth / Speed Test</h5>
        <p class="text-secondary small mb-3">Measure transfer speed between you and a peer.</p>
        <input type="hidden" id="bwTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="bwTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="bwResults" class="mb-3" style="display:none;">
            <div class="mb-2"><small class="text-secondary">Download from peer:</small>
                <div class="bw-bar"><div id="bwDlBar" class="bw-fill" style="width:0%"></div></div>
                <span id="bwDlSpeed" class="text-white small">—</span>
            </div>
            <div class="mb-2"><small class="text-secondary">Upload to peer:</small>
                <div class="bw-bar"><div id="bwUlBar" class="bw-fill" style="width:0%;background:linear-gradient(90deg,#1f6feb,#58a6ff);"></div></div>
                <span id="bwUlSpeed" class="text-white small">—</span>
            </div>
            <div><small class="text-secondary">Latency:</small> <span id="bwLatency" class="text-white small">—</span></div>
        </div>
        <div id="bwStatus" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="bwStartBtn" onclick="runBwTest()">Start Speed Test</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('bwTestModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="screenshotModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#e6edf3;">Screenshot Capture</h5>
        <input type="hidden" id="ssTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="ssTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="ssStatus" class="mb-2" style="display:none;"></div>
        <div id="ssImageContainer" class="text-center mb-3" style="display:none;">
            <img id="ssImage" class="screenshot-img" src="" alt="Screenshot" onclick="window.open(this.src, '_blank')">
            <small class="d-block text-secondary mt-1">Click image to open full size</small>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" id="ssCaptureBtn" onclick="captureScreenshot()">Capture Screenshot</button>
            <button class="btn btn-success flex-fill" id="ssSaveBtn" onclick="saveScreenshot()" style="display:none;">Save Screenshot</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('screenshotModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="sysinfoModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#58a6ff;">System Information</h5>
        <input type="hidden" id="siTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="siTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="siStatus" class="mb-2" style="display:none;"></div>
        <div id="siContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-info flex-fill" id="siRefreshBtn" onclick="fetchSysInfo()">Refresh</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('sysinfoModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="notifyModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#d29922;">Send Notification</h5>
        <p class="text-secondary small mb-2">Send a pop-up alert to the remote peer's desktop.</p>
        <input type="hidden" id="ntTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="ntTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Title:</label>
            <input type="text" id="ntTitle" class="form-control bg-dark text-white border-secondary" placeholder="Notification title" value="Message from GNA">
        </div>
        <div class="mb-3">
            <label class="form-label small">Message:</label>
            <textarea id="ntMessage" class="form-control bg-dark text-white border-secondary" rows="3" placeholder="Your message..."></textarea>
        </div>
        <div id="ntStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-warning flex-fill" onclick="sendNotify()">Send Notification</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('notifyModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="procMgrModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:800px;">
        <h5 class="mb-2" style="color:#f85149;">Process Manager</h5>
        <input type="hidden" id="pmTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="pmTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-2 d-flex gap-2">
            <input type="text" id="pmFilter" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter processes..." oninput="filterProcs()">
            <button class="btn btn-sm btn-outline-info" id="pmRefreshBtn" onclick="fetchProcesses()">Refresh</button>
        </div>
        <div id="pmStatus" class="mb-2" style="display:none;"></div>
        <div class="proc-list-wrap mb-3">
            <table class="table table-dark table-sm proc-table mb-0">
                <thead><tr><th>PID</th><th>Name</th><th>CPU %</th><th>Memory</th><th></th></tr></thead>
                <tbody id="pmProcList"></tbody>
            </table>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('procMgrModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="screenRecModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#3fb950;">Screen Record</h5>
        <input type="hidden" id="srTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="srTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="srRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot"></span><span class="text-danger small fw-bold">Recording</span> <span id="srFrameCount" class="text-secondary small ms-2"></span></div>
        <div id="srStatus" class="mb-2" style="display:none;"></div>
        <div id="srFrameContainer" class="text-center mb-3" style="display:none;">
            <img id="srFrame" class="screenrec-frame" src="" alt="Screen frame">
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="srStartBtn" onclick="startScreenRec()">Start Recording</button>
            <button class="btn btn-danger flex-fill" id="srStopBtn" onclick="stopScreenRec()" style="display:none;">Stop Recording</button>
            <button class="btn btn-info flex-fill" id="srSaveBtn" onclick="saveRecording()" style="display:none;">Save Recording</button>
            <button class="btn btn-outline-light flex-fill" onclick="stopScreenRec(); document.getElementById('screenRecModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="remoteAudioModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:600px;">
        <h5 class="mb-2" style="color:#3fb950;">Mic Audio</h5>
        <p class="text-secondary small mb-2">Listen to the remote peer's microphone — continuous tap.</p>
        <input type="hidden" id="raTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="raTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="raListenIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#3fb950;"></span><span class="text-success small fw-bold">Listening — continuous mic tap</span></div>
        <div id="raStatus" class="mb-2" style="display:none;"></div>
        <div class="audio-visualizer mb-3" id="raVisualizer" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="raStartBtn" onclick="startRemoteAudio()">Start Listening</button>
            <button class="btn btn-danger flex-fill" id="raStopBtn" onclick="stopRemoteAudio()" style="display:none;">Stop Listening</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('remoteAudioModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="sysAudioModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:600px;">
        <h5 class="mb-2" style="color:#58a6ff;">System Audio</h5>
        <p class="text-secondary small mb-2">Listen to what's playing on the remote peer's desktop (YouTube, Spotify, games, etc.).</p>
        <input type="hidden" id="saTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="saTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="saListenIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#58a6ff;"></span><span class="text-info small fw-bold">Listening — system audio</span></div>
        <div id="saStatus" class="mb-2" style="display:none;"></div>
        <div class="audio-visualizer mb-3" id="saVisualizer" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-primary flex-fill" id="saStartBtn" onclick="startSysAudio()">Start Listening</button>
            <button class="btn btn-danger flex-fill" id="saStopBtn" onclick="stopSysAudio()" style="display:none;">Stop Listening</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('sysAudioModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="inputMonitorModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#d29922;">Input Monitor</h5>
        <p class="text-secondary small mb-2">Monitor keystrokes and mouse activity on the remote peer.</p>
        <input type="hidden" id="imTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="imTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="imRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot"></span><span class="text-danger small fw-bold">Monitoring</span> <span id="imEventCount" class="text-secondary small ms-2"></span></div>
        <div id="imStatus" class="mb-2" style="display:none;"></div>
        <div class="keylog-feed mb-3" id="imFeed" style="display:none;"><span class="text-secondary">Waiting for input events...</span></div>
        <div class="d-flex gap-2">
            <button class="btn btn-warning flex-fill" id="imStartBtn" onclick="startInputMonitor()">Start Monitoring</button>
            <button class="btn btn-danger flex-fill" id="imStopBtn" onclick="stopInputMonitor()" style="display:none;">Stop Monitoring</button>
            <button class="btn btn-outline-secondary flex-fill" id="imClearBtn" onclick="document.getElementById('imFeed').innerHTML=''" style="display:none;">Clear</button>
            <button class="btn btn-outline-light flex-fill" onclick="stopInputMonitor(); document.getElementById('inputMonitorModal').style.display='none'">Close</button>
        </div>
    </div>
</div>

<div id="appLaunchModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#58a6ff;">App Launch</h5>
        <p class="text-secondary small mb-2">Select an application to launch on the remote peer.</p>
        <input type="hidden" id="alTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="alTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-2"><input type="text" id="alFilterInput" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter installed apps..." oninput="filterAppList()"></div>
        <div id="alLoading" class="text-center py-3" style="display:none;"><div class="spinner-border spinner-border-sm text-primary"></div> Loading installed apps...</div>
        <div id="alAppList" style="max-height:300px;overflow-y:auto;border:1px solid #30363d;border-radius:6px;margin-bottom:12px;"></div>
        <div class="mb-3"><label class="form-label small">Or enter path manually:</label><input type="text" id="alAppPath" class="form-control bg-dark text-white border-secondary" placeholder="e.g. notepad, calc, C:\\Program Files\\app.exe"></div>
        <div class="mb-3"><label class="form-label small">Arguments (optional):</label><input type="text" id="alAppArgs" class="form-control bg-dark text-white border-secondary" placeholder="e.g. --flag value"></div>
        <div id="alStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-info flex-fill" onclick="sendAppLaunch()">Launch</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('appLaunchModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="fileExecModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#f85149;">File Exec</h5>
        <p class="text-secondary small mb-2">Select a program to execute on the remote peer. <strong class="text-danger">Use responsibly.</strong></p>
        <input type="hidden" id="feTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="feTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-2"><input type="text" id="feFilterInput" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter installed apps..." oninput="filterFileExecList()"></div>
        <div id="feLoading" class="text-center py-3" style="display:none;"><div class="spinner-border spinner-border-sm text-primary"></div> Loading installed apps...</div>
        <div id="feAppList" style="max-height:300px;overflow-y:auto;border:1px solid #30363d;border-radius:6px;margin-bottom:12px;"></div>
        <div class="mb-3"><label class="form-label small">Or enter path manually:</label><input type="text" id="feFilePath" class="form-control bg-dark text-white border-secondary" placeholder="e.g. C:\\Users\\user\\script.bat"></div>
        <div id="feStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-danger flex-fill" onclick="sendFileExec()">Execute</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('fileExecModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="diskInfoModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#8b949e;">Disk Info</h5>
        <input type="hidden" id="diTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="diTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="diStatus" class="mb-2" style="display:none;"></div>
        <div id="diContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="diRefreshBtn" onclick="fetchDiskInfo()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('diskInfoModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="eventLogModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#58a6ff;">Event Log</h5>
        <input type="hidden" id="elTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="elTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="elStatus" class="mb-2" style="display:none;"></div>
        <div id="elContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-info flex-fill" id="elRefreshBtn" onclick="fetchEventLog()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('eventLogModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="healthModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#3fb950;">Health</h5>
        <input type="hidden" id="hlTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="hlTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="hlStatus" class="mb-2" style="display:none;"></div>
        <div id="hlContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-success flex-fill" id="hlRefreshBtn" onclick="fetchHealth()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('healthModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="printersModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#e6edf3;">Printers</h5>
        <input type="hidden" id="prTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="prTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="prStatus" class="mb-2" style="display:none;"></div>
        <div id="prContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-light flex-fill" id="prRefreshBtn" onclick="fetchPrinters()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('printersModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="sharedTermModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#8b949e;">Shared Terminal</h5>
        <p class="text-secondary small mb-2">A shared terminal session viewable by both peers.</p>
        <input type="hidden" id="stTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="stTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="stOutput" class="term-output mb-2">Ready. Type a command below.\n</div>
        <div class="d-flex gap-2"><input type="text" id="stCmdInput" class="form-control term-input flex-fill" placeholder="Enter command..." autocomplete="off"><button class="btn btn-secondary" id="stSendBtn" onclick="sendSharedTermCmd()">Run</button></div>
        <div class="d-flex gap-2 mt-3"><button class="btn btn-outline-secondary flex-fill" onclick="document.getElementById('stOutput').textContent='Ready.\\n'">Clear</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('sharedTermModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="wallpaperModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#f85149;">Wallpaper</h5>
        <p class="text-secondary small mb-2">Change the wallpaper on the remote peer's desktop.</p>
        <input type="hidden" id="wpTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="wpTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-3"><label class="form-label small">Image URL:</label><input type="text" id="wpUrl" class="form-control bg-dark text-white border-secondary" placeholder="https://example.com/image.jpg"></div>
        <div id="wpStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-danger flex-fill" onclick="sendWallpaper()">Set Wallpaper</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('wallpaperModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="softwareModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#8b949e;">Installed Software</h5>
        <input type="hidden" id="swTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="swTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-2"><input type="text" id="swFilter" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter software..." oninput="filterSoftwareList()"></div>
        <div id="swStatus" class="mb-2" style="display:none;"></div>
        <div id="swContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="swRefreshBtn" onclick="fetchSoftware()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('softwareModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="registryModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#58a6ff;">Registry</h5>
        <p class="text-secondary small mb-2">Query a registry key on the remote peer.</p>
        <input type="hidden" id="rgTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="rgTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-3"><label class="form-label small">Registry path:</label><input type="text" id="rgPath" class="form-control bg-dark text-white border-secondary" placeholder="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"></div>
        <div id="rgStatus" class="mb-2" style="display:none;"></div>
        <div id="rgContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-info flex-fill" onclick="fetchRegistry()">Query</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('registryModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="netConnsModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:800px;">
        <h5 class="mb-2" style="color:#58a6ff;">Network Connections</h5>
        <input type="hidden" id="ncTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="ncTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="ncStatus" class="mb-2" style="display:none;"></div>
        <div id="ncContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-info flex-fill" id="ncRefreshBtn" onclick="fetchNetConns()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('netConnsModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="envVarsModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#8b949e;">Environment Variables</h5>
        <input type="hidden" id="evTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="evTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="evStatus" class="mb-2" style="display:none;"></div>
        <div id="evContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="evRefreshBtn" onclick="fetchEnvVars()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('envVarsModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="hostsFileModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#d29922;">Hosts File</h5>
        <input type="hidden" id="hfTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="hfTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="hfStatus" class="mb-2" style="display:none;"></div>
        <div id="hfContent" class="mb-3" style="display:none;"><textarea id="hfTextArea" class="form-control bg-dark text-white border-secondary" rows="12" style="font-family:monospace;font-size:0.8rem;" readonly></textarea></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-warning flex-fill" id="hfRefreshBtn" onclick="fetchHostsFile()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('hostsFileModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="urlOpenModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#f85149;">URL Open</h5>
        <p class="text-secondary small mb-2">Open a URL in the remote peer's default browser.</p>
        <input type="hidden" id="uoTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="uoTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-3"><label class="form-label small">URL to open:</label><input type="text" id="uoUrl" class="form-control bg-dark text-white border-secondary" placeholder="https://example.com"></div>
        <div id="uoStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-danger flex-fill" onclick="sendUrlOpen()">Open URL</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('urlOpenModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="driversModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#8b949e;">Drivers</h5>
        <input type="hidden" id="drTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="drTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="drStatus" class="mb-2" style="display:none;"></div>
        <div id="drContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="drRefreshBtn" onclick="fetchDrivers()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('driversModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="netAdaptersModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#8b949e;">Network Adapters</h5>
        <input type="hidden" id="naTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="naTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="naStatus" class="mb-2" style="display:none;"></div>
        <div id="naContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="naRefreshBtn" onclick="fetchNetAdapters()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('netAdaptersModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="firewallModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:800px;">
        <h5 class="mb-2" style="color:#58a6ff;">Firewall Rules</h5>
        <input type="hidden" id="fwTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="fwTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="fwStatus" class="mb-2" style="display:none;"></div>
        <div id="fwContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-info flex-fill" id="fwRefreshBtn" onclick="fetchFirewall()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('firewallModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="batteryModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#8b949e;">Battery Status</h5>
        <input type="hidden" id="btTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="btTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="btStatus" class="mb-2" style="display:none;"></div>
        <div id="btContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="btRefreshBtn" onclick="fetchBattery()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('batteryModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="webcamSnapModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#3fb950;">Webcam Snap</h5>
        <input type="hidden" id="wsTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="wsTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="wsStatus" class="mb-2" style="display:none;"></div>
        <div id="wsImageContainer" class="text-center mb-3" style="display:none;"><img id="wsImage" class="screenshot-img" src="" alt="Webcam" onclick="window.open(this.src,'_blank')"><small class="d-block text-secondary mt-1">Click image to open full size</small></div>
        <div class="d-flex gap-2"><button class="btn btn-success flex-fill" id="wsCaptureBtn" onclick="captureWebcam()">Capture</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('webcamSnapModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="webcamStreamModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#8b949e;">Webcam Stream</h5>
        <input type="hidden" id="wcTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="wcTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="wcRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#3fb950;"></span><span class="text-success small fw-bold">Streaming</span> <span id="wcFrameCount" class="text-secondary small ms-2"></span></div>
        <div id="wcStatus" class="mb-2" style="display:none;"></div>
        <div id="wcFrameContainer" class="text-center mb-3" style="display:none;"><img id="wcFrame" class="screenrec-frame" src="" alt="Webcam frame"></div>
        <div class="d-flex gap-2"><button class="btn btn-success flex-fill" id="wcStartBtn" onclick="startWebcamStream()">Start Stream</button><button class="btn btn-danger flex-fill" id="wcStopBtn" onclick="stopWebcamStream()" style="display:none;">Stop</button><button class="btn btn-outline-light flex-fill" onclick="stopWebcamStream(); document.getElementById('webcamStreamModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="locationModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#d29922;">Location</h5>
        <input type="hidden" id="loTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="loTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="loStatus" class="mb-2" style="display:none;"></div>
        <div id="loContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-warning flex-fill" id="loRefreshBtn" onclick="fetchLocation()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('locationModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="recentFilesModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#8b949e;">Recent Files</h5>
        <input type="hidden" id="rfcTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="rfcTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="rfcStatus" class="mb-2" style="display:none;"></div>
        <div id="rfcContent" class="mb-3" style="max-height:400px;overflow-y:auto;display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-secondary flex-fill" id="rfcRefreshBtn" onclick="fetchRecentFiles()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('recentFilesModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="biosInfoModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#e6edf3;">BIOS Info</h5>
        <input type="hidden" id="biTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="biTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="biStatus" class="mb-2" style="display:none;"></div>
        <div id="biContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-outline-light flex-fill" id="biRefreshBtn" onclick="fetchBiosInfo()">Refresh</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('biosInfoModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="perfMonitorModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#f85149;">Performance Monitor</h5>
        <input type="hidden" id="pfTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="pfTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="pfRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#f85149;"></span><span class="text-danger small fw-bold">Live Monitoring</span></div>
        <div id="pfStatus" class="mb-2" style="display:none;"></div>
        <div id="pfContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-danger flex-fill" id="pfStartBtn" onclick="startPerfMonitor()">Start</button><button class="btn btn-outline-secondary flex-fill" id="pfStopBtn" onclick="stopPerfMonitor()" style="display:none;">Stop</button><button class="btn btn-outline-light flex-fill" onclick="stopPerfMonitor(); document.getElementById('perfMonitorModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="voiceNoteModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#58a6ff;">Voice Note</h5>
        <p class="text-secondary small mb-2">Record a short voice note and send it to the remote peer for playback.</p>
        <input type="hidden" id="vnTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="vnTargetDisplay" class="text-warning fw-bold"></span></div>
        <div id="vnRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot"></span><span class="text-danger small fw-bold">Recording...</span></div>
        <div id="vnStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-info flex-fill" id="vnRecordBtn" onclick="toggleVoiceNote()">Record</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('voiceNoteModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="ttsModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#f85149;">Text-to-Speech</h5>
        <p class="text-secondary small mb-2">Speak text aloud on the remote peer's speakers.</p>
        <input type="hidden" id="ttTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="ttTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-3"><label class="form-label small">Text to speak:</label><textarea id="ttText" class="form-control bg-dark text-white border-secondary" rows="3" placeholder="Enter text to speak..."></textarea></div>
        <div id="ttStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-danger flex-fill" onclick="sendTTS()">Speak</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('ttsModal').style.display='none'">Close</button></div>
    </div>
</div>
<div id="playSoundModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#8b949e;">Play Sound</h5>
        <p class="text-secondary small mb-2">Play a system sound or URL on the remote peer.</p>
        <input type="hidden" id="psTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2"><span class="text-secondary small">Peer:</span><span id="psTargetDisplay" class="text-warning fw-bold"></span></div>
        <div class="mb-3"><label class="form-label small">Sound name or URL:</label><input type="text" id="psSoundUrl" class="form-control bg-dark text-white border-secondary" placeholder="e.g. SystemAsterisk, or https://example.com/sound.wav"></div>
        <div id="psStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2"><button class="btn btn-secondary flex-fill" onclick="sendPlaySound()">Play</button><button class="btn btn-outline-light flex-fill" onclick="document.getElementById('playSoundModal').style.display='none'">Close</button></div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<script>
let _liveSocket = null;
try {{
    _liveSocket = io('http://localhost:3000', {{ transports: ['websocket', 'polling'] }});
    _liveSocket.on('connect', function() {{ _liveSocket.emit('dashboard-join', {{ peerId: '{random_id}' }}); }});
    _liveSocket.on('share-updated', function(data) {{ refreshSharedCounts(); setTimeout(function() {{ window.location.reload(); }}, 2000); }});
}} catch(e) {{ console.warn('Socket.IO live session unavailable:', e); }}
function refreshSharedCounts() {{
    document.querySelectorAll('.shared-count').forEach(function(span) {{
        const peerId = span.getAttribute('data-peer-id');
        fetch('/peer_shared_count/' + peerId).then(function(r) {{ return r.json(); }}).then(function(data) {{ span.textContent = data.count + ' items'; span.classList.remove('text-secondary'); span.classList.add('text-white'); }}).catch(function() {{ span.textContent = 'N/A'; }});
    }});
}}
refreshSharedCounts();
setInterval(function() {{ fetch('/api/peers').then(function(r) {{ return r.json(); }}).then(function(peers) {{ refreshSharedCounts(); }}).catch(function() {{}}); }}, 5000);
let _activeRemoteSessions = [];
function checkRemoteAccessStatus() {{ fetch('http://localhost:3000/api/remote-access-status').then(r => r.json()).then(data => {{ _activeRemoteSessions = data.sessions || []; updateRemoteBanner(); }}).catch(() => {{}}); }}
function updateRemoteBanner() {{
    const banner = document.getElementById('remote-access-banner');
    const detail = document.getElementById('remote-access-detail');
    const myId = '{random_id}';
    const mySessions = _activeRemoteSessions.filter(s => s.sessionId === myId);
    if (mySessions.length > 0) {{ const s = mySessions[0]; const name = s.remoteName || s.remotePeerId || 'Unknown'; detail.textContent = name + ' is currently controlling your system.'; banner.style.display = 'flex'; banner.setAttribute('data-session-id', s.sessionId); }} else {{ banner.style.display = 'none'; }}
}}
function revokeRemoteAccess() {{
    const banner = document.getElementById('remote-access-banner');
    const sessionId = banner.getAttribute('data-session-id');
    if (!sessionId) return;
    const btn = document.getElementById('revoke-remote-btn');
    btn.textContent = 'Revoking...'; btn.disabled = true;
    fetch('http://localhost:3000/api/remote-access-revoke', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ sessionId: sessionId }}) }}).then(r => r.json()).then(data => {{ banner.style.display = 'none'; btn.textContent = 'Revoke Access'; btn.disabled = false; }}).catch(() => {{ btn.textContent = 'Revoke Access'; btn.disabled = false; }});
}}
if (_liveSocket) {{
    _liveSocket.on('remote-access-status', function(data) {{
        if (data.active) {{ const idx = _activeRemoteSessions.findIndex(s => s.sessionId === data.sessionId); if (idx >= 0) {{ _activeRemoteSessions[idx] = data; }} else {{ _activeRemoteSessions.push(data); }} }} else {{ _activeRemoteSessions = _activeRemoteSessions.filter(s => s.sessionId !== data.sessionId); }}
        updateRemoteBanner();
    }});
}}
checkRemoteAccessStatus();
setInterval(checkRemoteAccessStatus, 10000);
function reconnectRelay() {{
    const btn = document.getElementById('reconnect-relay-btn');
    btn.textContent = 'Reconnecting...'; btn.disabled = true;
    fetch('/api/global-reconnect', {{ method: 'POST' }}).then(r => r.json()).then(data => {{ btn.textContent = data.status === 'ok' ? 'Relay Connected' : 'Reconnect Relay'; btn.disabled = false; setTimeout(() => {{ btn.textContent = 'Reconnect Relay'; }}, 3000); }}).catch(() => {{ btn.textContent = 'Reconnect Relay'; btn.disabled = false; }});
}}
document.querySelectorAll('.preview-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const modal = document.getElementById('previewModal');
        const content = document.getElementById('previewContent');
        content.innerHTML = '<div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Loading preview...</p></div>';
        modal.style.display = 'flex';
        fetch('/peer_preview/' + peerId).then(r => {{ if (!r.ok) throw new Error(r.status + ' ' + r.statusText); return r.text(); }}).then(html => {{ content.innerHTML = html; }}).catch(err => {{ content.innerHTML = '<div class="alert alert-warning m-4">Could not load preview<br><small>' + (err.message || err) + '</small><br><br><small>(Remote peers need port 5000 open & forwarded.)</small></div>'; }});
    }});
}});
document.querySelectorAll('.connect-btn').forEach(btn => {{ btn.addEventListener('click', function() {{ window.location.href = '/peer_connect/' + this.getAttribute('data-peer-id'); }}); }});
document.querySelectorAll('.view-screen-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        fetch('/launch_screen_viewer/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{ if (data.success) {{ alert('Screen viewer launched for ' + peerId); }} else {{ alert('Failed to launch viewer: ' + (data.error || 'Unknown error')); }} }}).catch(err => {{ alert('Error launching viewer: ' + err.message); }});
    }});
}});
document.querySelectorAll('.call-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        fetch('/launch_call/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{ if (data.success) {{ self.textContent = 'Calling...'; self.disabled = true; setTimeout(() => {{ self.textContent = 'Call this PC'; self.disabled = false; }}, 10000); }} else {{ alert('Failed to start call: ' + (data.error || 'Unknown error')); }} }}).catch(err => {{ alert('Error starting call: ' + err.message); }});
    }});
}});
document.getElementById('previewModal').addEventListener('click', function(e) {{ if (e.target === this) {{ this.style.display = 'none'; }} }});
document.querySelectorAll('.upload-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('uploadTargetPeerId').value = peerId;
        document.getElementById('uploadTargetDisplay').textContent = peerId;
        document.getElementById('uploadFile').value = '';
        document.getElementById('uploadDestPath').value = 'Desktop/';
        document.getElementById('uploadStatus').style.display = 'none';
        document.getElementById('uploadPlaceBtn').disabled = false;
        document.getElementById('uploadPlaceBtn').textContent = 'Place';
        document.getElementById('uploadModal').style.display = 'flex';
    }});
}});
document.getElementById('uploadForm').addEventListener('submit', function(e) {{
    e.preventDefault();
    const peerId = document.getElementById('uploadTargetPeerId').value;
    const fileInput = document.getElementById('uploadFile');
    const destPath = document.getElementById('uploadDestPath').value.trim();
    const statusDiv = document.getElementById('uploadStatus');
    const placeBtn = document.getElementById('uploadPlaceBtn');
    if (!fileInput.files.length) {{ statusDiv.innerHTML = '<div class="alert alert-warning py-2">Please select a file.</div>'; statusDiv.style.display = 'block'; return; }}
    if (!destPath) {{ statusDiv.innerHTML = '<div class="alert alert-warning py-2">Please enter a destination path.</div>'; statusDiv.style.display = 'block'; return; }}
    placeBtn.disabled = true; placeBtn.textContent = 'Sending...';
    statusDiv.innerHTML = '<div class="text-info small">Uploading file to peer...</div>'; statusDiv.style.display = 'block';
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('dest_path', destPath);
    fetch('/upload_to_peer/' + peerId, {{ method: 'POST', body: formData }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            statusDiv.innerHTML = '<div class="alert alert-success py-2">File sent! Waiting for ' + peerId + ' to accept.</div>';
            placeBtn.textContent = 'Sent';
            setTimeout(() => {{ document.getElementById('uploadModal').style.display = 'none'; }}, 3000);
        }} else {{
            statusDiv.innerHTML = '<div class="alert alert-danger py-2">Failed: ' + (data.error || 'Unknown error') + '</div>';
            placeBtn.disabled = false; placeBtn.textContent = 'Place';
        }}
    }}).catch(err => {{
        statusDiv.innerHTML = '<div class="alert alert-danger py-2">Error: ' + err.message + '</div>';
        placeBtn.disabled = false; placeBtn.textContent = 'Place';
    }});
}});
function checkIncomingUploads() {{
    fetch('/api/pending-uploads').then(r => r.json()).then(data => {{
        const container = document.getElementById('incoming-uploads-container');
        const uploads = data.uploads || [];
        if (uploads.length === 0) {{ container.innerHTML = ''; return; }}
        let html = '';
        uploads.forEach(function(u) {{
            const sizeStr = u.file_size > 1048576 ? (u.file_size / 1048576).toFixed(1) + ' MB' : u.file_size > 1024 ? (u.file_size / 1024).toFixed(1) + ' KB' : u.file_size + ' bytes';
            html += '<div class="incoming-upload-banner" style="display:flex;" id="upload-banner-' + u.id + '">'
                + '<div style="flex:1;">'
                + '<strong>INCOMING FILE</strong><br>'
                + '<span>' + escapeHtml(u.sender_id) + ' wants to send you <strong>' + escapeHtml(u.filename) + '</strong> (' + sizeStr + ')</span><br>'
                + '<small class="opacity-75">Destination: ~/' + escapeHtml(u.dest_path) + '</small>'
                + '</div>'
                + '<div class="d-flex gap-2 ms-3">'
                + '<button class="btn btn-success btn-sm fw-bold accept-upload-btn" data-upload-id="' + u.id + '">Yes, Accept</button>'
                + '<button class="btn btn-outline-light btn-sm fw-bold reject-upload-btn" data-upload-id="' + u.id + '">No, Reject</button>'
                + '</div></div>';
        }});
        container.innerHTML = html;
    }}).catch(() => {{}});
}}
function respondUpload(uploadId, accept) {{
    const banner = document.getElementById('upload-banner-' + uploadId);
    if (banner) {{
        const btns = banner.querySelectorAll('button');
        btns.forEach(b => {{ b.disabled = true; }});
    }}
    const endpoint = accept ? '/api/accept-upload/' : '/api/reject-upload/';
    fetch(endpoint + uploadId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (banner) {{
            if (accept && data.success) {{
                banner.style.background = 'linear-gradient(135deg, #238636 0%, #196c2e 100%)';
                banner.style.borderColor = '#3fb950';
                banner.querySelector('div').innerHTML = '<strong>FILE ACCEPTED</strong><br><span>Saved to ~/' + escapeHtml(data.saved_to || '') + '</span>';
            }} else if (!accept) {{
                banner.style.background = 'linear-gradient(135deg, #6e4000 0%, #4d2d00 100%)';
                banner.style.borderColor = '#d29922';
                banner.querySelector('div').innerHTML = '<strong>FILE REJECTED</strong>';
            }} else {{
                banner.querySelector('div').innerHTML = '<strong>Error:</strong> ' + (data.error || 'Unknown error');
            }}
            setTimeout(() => {{ banner.style.display = 'none'; }}, 4000);
        }}
    }}).catch(err => {{ if (banner) banner.querySelector('div').innerHTML = '<strong>Error:</strong> ' + err.message; }});
}}
checkIncomingUploads();
setInterval(checkIncomingUploads, 3000);
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('accept-upload-btn')) {{
        respondUpload(e.target.getAttribute('data-upload-id'), true);
    }}
    if (e.target.classList.contains('reject-upload-btn')) {{
        respondUpload(e.target.getAttribute('data-upload-id'), false);
    }}
}});
document.querySelectorAll('.ping-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        self.textContent = 'Pinging...'; self.disabled = true;
        fetch('/api/ping/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            self.disabled = false;
            if (data.success) {{
                const ms = data.latency_ms;
                const cls = ms < 100 ? 'ping-ok' : ms < 500 ? 'ping-warn' : 'ping-fail';
                const label = ms < 100 ? 'Excellent' : ms < 300 ? 'Good' : ms < 500 ? 'Fair' : 'Poor';
                self.innerHTML = '<span class="' + cls + '">' + ms + 'ms</span>';
                setTimeout(() => {{ self.textContent = 'Ping'; }}, 5000);
            }} else {{
                self.innerHTML = '<span class="ping-fail">Failed</span>';
                setTimeout(() => {{ self.textContent = 'Ping'; }}, 3000);
            }}
        }}).catch(() => {{ self.innerHTML = '<span class="ping-fail">Error</span>'; self.disabled = false; setTimeout(() => {{ self.textContent = 'Ping'; }}, 3000); }});
    }});
}});
let _rfAllItems = [];
document.querySelectorAll('.request-file-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('rfTargetPeerId').value = peerId;
        document.getElementById('rfTargetDisplay').textContent = peerId;
        document.getElementById('rfFileList').innerHTML = '';
        document.getElementById('rfSearchInput').value = '';
        document.getElementById('rfStatus').style.display = 'none';
        document.getElementById('rfLoading').style.display = 'block';
        _rfAllItems = [];
        document.getElementById('requestFileModal').style.display = 'flex';
        fetch('/api/request-file-list/' + peerId).then(r => r.json()).then(data => {{
            document.getElementById('rfLoading').style.display = 'none';
            if (data.error) {{ document.getElementById('rfFileList').innerHTML = '<div class="p-3 text-danger">' + data.error + '</div>'; return; }}
            _rfAllItems = data.items || [];
            renderRequestFiles(_rfAllItems);
        }}).catch(err => {{
            document.getElementById('rfLoading').style.display = 'none';
            document.getElementById('rfFileList').innerHTML = '<div class="p-3 text-danger">Could not load files: ' + err.message + '</div>';
        }});
    }});
}});
function renderRequestFiles(items) {{
    const list = document.getElementById('rfFileList');
    if (items.length === 0) {{ list.innerHTML = '<div class="p-3 text-secondary">No shared files found.</div>'; return; }}
    const peerId = document.getElementById('rfTargetPeerId').value;
    let html = '';
    items.forEach(function(item) {{
        const icon = item.is_folder ? 'Folder ' : 'File ';
        const sizeStr = item.is_folder ? '' : ' (' + item.size + ')';
        const cleanPath = item.is_folder ? item.path.replace(/\\/+$/g, '') : item.path;
        const dlBtn = '<button class="btn btn-sm btn-outline-success request-dl-btn" data-peer-id="' + peerId + '" data-path="' + cleanPath + '" data-is-folder="' + (item.is_folder ? '1' : '0') + '">Download</button>';
        html += '<div class="file-tree-item"><span>' + icon + escapeHtml(item.name) + sizeStr + '</span>' + dlBtn + '</div>';
    }});
    list.innerHTML = html;
}}
function filterRequestFiles() {{
    const q = (document.getElementById('rfSearchInput').value || '').toLowerCase();
    const filtered = q ? _rfAllItems.filter(function(i) {{ return i.name.toLowerCase().indexOf(q) >= 0; }}) : _rfAllItems;
    renderRequestFiles(filtered);
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('request-dl-btn')) {{
        const peerId = e.target.getAttribute('data-peer-id');
        const path = e.target.getAttribute('data-path');
        const btn = e.target;
        btn.textContent = 'Downloading...'; btn.disabled = true;
        fetch('/api/request-file-download/' + peerId + '/' + path, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            if (data.success) {{
                btn.textContent = 'Saved';
                btn.classList.remove('btn-outline-success'); btn.classList.add('btn-success');
                const st = document.getElementById('rfStatus');
                st.innerHTML = '<div class="alert alert-success py-2 small">Saved to ~/' + escapeHtml(data.saved_to || '') + '</div>';
                st.style.display = 'block';
            }} else {{
                btn.textContent = 'Failed';
                const st = document.getElementById('rfStatus');
                st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Download failed') + '</div>';
                st.style.display = 'block';
            }}
            setTimeout(() => {{ btn.textContent = 'Download'; btn.disabled = false; btn.classList.remove('btn-success'); btn.classList.add('btn-outline-success'); }}, 4000);
        }}).catch(err => {{ btn.textContent = 'Error'; btn.disabled = false; }});
    }}
}});
document.querySelectorAll('.sync-folder-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('sfTargetPeerId').value = peerId;
        document.getElementById('sfTargetDisplay').textContent = peerId;
        document.getElementById('sfLocalPath').value = 'Desktop/synced/';
        document.getElementById('sfRemotePath').value = '';
        document.getElementById('sfStatus').style.display = 'none';
        document.getElementById('sfStartBtn').disabled = false;
        document.getElementById('sfStartBtn').textContent = 'Start Sync';
        document.getElementById('syncFolderModal').style.display = 'flex';
        refreshActiveSyncs();
    }});
}});
function startSync() {{
    const peerId = document.getElementById('sfTargetPeerId').value;
    const localPath = document.getElementById('sfLocalPath').value.trim();
    const remotePath = document.getElementById('sfRemotePath').value.trim();
    const btn = document.getElementById('sfStartBtn');
    const st = document.getElementById('sfStatus');
    if (!localPath) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a local folder path.</div>'; st.style.display = 'block'; return; }}
    btn.disabled = true; btn.textContent = 'Starting...';
    st.innerHTML = '<div class="text-info small">Initiating sync...</div>'; st.style.display = 'block';
    fetch('/api/sync-folder', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ peer_id: peerId, local_path: localPath, remote_path: remotePath }}) }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            st.innerHTML = '<div class="alert alert-success py-2 small">Sync started! ' + (data.files_synced || 0) + ' files synced. Next auto-sync in 30s.</div>';
            btn.textContent = 'Sync Running';
            refreshActiveSyncs();
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Sync failed') + '</div>';
            btn.disabled = false; btn.textContent = 'Start Sync';
        }}
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; btn.disabled = false; btn.textContent = 'Start Sync'; }});
}}
function refreshActiveSyncs() {{
    fetch('/api/active-syncs').then(r => r.json()).then(data => {{
        const container = document.getElementById('sfActiveSyncs');
        const syncs = data.syncs || [];
        if (syncs.length === 0) {{ container.innerHTML = '<p class="text-secondary small">No active syncs.</p>'; return; }}
        let html = '<h6 class="small text-secondary mt-3 mb-2">Active Syncs:</h6>';
        syncs.forEach(function(s) {{
            html += '<div class="d-flex justify-content-between align-items-center mb-2 p-2" style="background:#0d1117;border-radius:6px;border:1px solid #30363d;">'
                + '<div><small class="text-white">' + escapeHtml(s.peer_id) + '</small><br><small class="text-muted">~/' + escapeHtml(s.local_path) + '</small></div>'
                + '<div class="d-flex align-items-center gap-2"><span class="sync-status ' + (s.active ? 'sync-active' : 'sync-idle') + '">' + (s.active ? 'Syncing' : 'Idle') + '</span>'
                + '<button class="btn btn-sm btn-outline-danger stop-sync-btn" data-sync-id="' + s.id + '">Stop</button></div></div>';
        }});
        container.innerHTML = html;
    }}).catch(() => {{}});
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('stop-sync-btn')) {{
        const syncId = e.target.getAttribute('data-sync-id');
        e.target.disabled = true; e.target.textContent = '...';
        fetch('/api/stop-sync/' + syncId, {{ method: 'POST' }}).then(r => r.json()).then(() => {{ refreshActiveSyncs(); }}).catch(() => {{ e.target.disabled = false; e.target.textContent = 'Stop'; }});
    }}
}});
document.querySelectorAll('.remote-term-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('rtTargetPeerId').value = peerId;
        document.getElementById('rtTargetDisplay').textContent = peerId;
        document.getElementById('rtOutput').textContent = 'Connected to ' + peerId + '. Type a command below.\\n';
        document.getElementById('rtCmdInput').value = '';
        document.getElementById('remoteTermModal').style.display = 'flex';
        document.getElementById('rtCmdInput').focus();
    }});
}});
document.getElementById('rtCmdInput').addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') sendTermCmd();
}});
function sendTermCmd() {{
    const peerId = document.getElementById('rtTargetPeerId').value;
    const cmd = document.getElementById('rtCmdInput').value.trim();
    if (!cmd) return;
    const out = document.getElementById('rtOutput');
    out.textContent += '> ' + cmd + '\\n';
    document.getElementById('rtCmdInput').value = '';
    document.getElementById('rtSendBtn').disabled = true;
    document.getElementById('rtSendBtn').textContent = '...';
    fetch('/api/remote-exec/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ command: cmd }}) }}).then(r => r.json()).then(data => {{
        if (data.output) out.textContent += data.output + '\\n';
        if (data.error) out.textContent += 'ERROR: ' + data.error + '\\n';
        out.scrollTop = out.scrollHeight;
        document.getElementById('rtSendBtn').disabled = false;
        document.getElementById('rtSendBtn').textContent = 'Run';
    }}).catch(err => {{
        out.textContent += 'NETWORK ERROR: ' + err.message + '\\n';
        document.getElementById('rtSendBtn').disabled = false;
        document.getElementById('rtSendBtn').textContent = 'Run';
    }});
}}
document.querySelectorAll('.clipboard-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('cbTargetPeerId').value = peerId;
        document.getElementById('cbTargetDisplay').textContent = peerId;
        document.getElementById('cbTextArea').value = '';
        document.getElementById('cbStatus').style.display = 'none';
        document.getElementById('clipboardModal').style.display = 'flex';
    }});
}});
function sendClipboard() {{
    const peerId = document.getElementById('cbTargetPeerId').value;
    const text = document.getElementById('cbTextArea').value;
    const st = document.getElementById('cbStatus');
    if (!text) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Nothing to send.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Sending...</div>'; st.style.display = 'block';
    fetch('/api/clipboard-send/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ text: text }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Clipboard sent to peer!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
function grabClipboard() {{
    const peerId = document.getElementById('cbTargetPeerId').value;
    const st = document.getElementById('cbStatus');
    st.innerHTML = '<div class="text-info small">Fetching clipboard...</div>'; st.style.display = 'block';
    fetch('/api/clipboard-grab/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            document.getElementById('cbTextArea').value = data.text || '';
            st.innerHTML = '<div class="alert alert-success py-2 small">Clipboard grabbed! Text is in the box above.</div>';
        }} else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
document.querySelectorAll('.power-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('pwTargetPeerId').value = peerId;
        document.getElementById('pwTargetDisplay').textContent = peerId;
        document.getElementById('pwStatus').style.display = 'none';
        document.getElementById('powerModal').style.display = 'flex';
    }});
}});
function sendPowerCmd(action) {{
    const peerId = document.getElementById('pwTargetPeerId').value;
    const st = document.getElementById('pwStatus');
    const warnings = {{ shutdown: 'SHUTDOWN the remote machine', restart: 'RESTART the remote machine', sleep: 'put the remote machine to SLEEP', wake: 'send a Wake-on-LAN packet' }};
    if (!confirm('Are you sure you want to ' + (warnings[action] || action) + ' (' + peerId + ')?')) return;
    st.innerHTML = '<div class="text-info small">Sending ' + action + ' command...</div>'; st.style.display = 'block';
    fetch('/api/power/' + peerId + '/' + action, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">' + (data.message || action + ' command sent!') + '</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
document.querySelectorAll('.bw-test-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('bwTargetPeerId').value = peerId;
        document.getElementById('bwTargetDisplay').textContent = peerId;
        document.getElementById('bwResults').style.display = 'none';
        document.getElementById('bwStatus').style.display = 'none';
        document.getElementById('bwStartBtn').disabled = false;
        document.getElementById('bwStartBtn').textContent = 'Start Speed Test';
        document.getElementById('bwTestModal').style.display = 'flex';
    }});
}});
function runBwTest() {{
    const peerId = document.getElementById('bwTargetPeerId').value;
    const btn = document.getElementById('bwStartBtn');
    const st = document.getElementById('bwStatus');
    const res = document.getElementById('bwResults');
    btn.disabled = true; btn.textContent = 'Testing...';
    st.innerHTML = '<div class="text-info small">Running speed test...</div>'; st.style.display = 'block';
    res.style.display = 'none';
    document.getElementById('bwDlBar').style.width = '0%';
    document.getElementById('bwUlBar').style.width = '0%';
    document.getElementById('bwDlSpeed').textContent = '—';
    document.getElementById('bwUlSpeed').textContent = '—';
    document.getElementById('bwLatency').textContent = '—';
    fetch('/api/bandwidth-test/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Start Speed Test';
        if (data.success) {{
            res.style.display = 'block';
            st.style.display = 'none';
            const dlMbps = data.download_mbps || 0;
            const ulMbps = data.upload_mbps || 0;
            const maxMbps = 1000;
            document.getElementById('bwDlBar').style.width = Math.min(dlMbps / maxMbps * 100, 100) + '%';
            document.getElementById('bwUlBar').style.width = Math.min(ulMbps / maxMbps * 100, 100) + '%';
            document.getElementById('bwDlSpeed').textContent = dlMbps.toFixed(2) + ' Mbps (' + (dlMbps / 8).toFixed(2) + ' MB/s)';
            document.getElementById('bwUlSpeed').textContent = ulMbps.toFixed(2) + ' Mbps (' + (ulMbps / 8).toFixed(2) + ' MB/s)';
            document.getElementById('bwLatency').textContent = (data.latency_ms || 0) + ' ms';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Test failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Start Speed Test';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.screenshot-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('ssTargetPeerId').value = peerId;
        document.getElementById('ssTargetDisplay').textContent = peerId;
        document.getElementById('ssStatus').style.display = 'none';
        document.getElementById('ssImageContainer').style.display = 'none';
        document.getElementById('ssCaptureBtn').disabled = false;
        document.getElementById('ssCaptureBtn').textContent = 'Capture Screenshot';
        document.getElementById('screenshotModal').style.display = 'flex';
    }});
}});
function captureScreenshot() {{
    const peerId = document.getElementById('ssTargetPeerId').value;
    const btn = document.getElementById('ssCaptureBtn');
    const st = document.getElementById('ssStatus');
    const imgC = document.getElementById('ssImageContainer');
    btn.disabled = true; btn.textContent = 'Capturing...';
    st.innerHTML = '<div class="text-info small">Requesting screenshot...</div>'; st.style.display = 'block';
    imgC.style.display = 'none';
    fetch('/api/screenshot/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Capture Again';
        if (data.success) {{
            st.style.display = 'none';
            document.getElementById('ssImage').src = 'data:image/png;base64,' + data.image;
            imgC.style.display = 'block';
            document.getElementById('ssSaveBtn').style.display = '';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Capture Screenshot';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.sysinfo-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('siTargetPeerId').value = peerId;
        document.getElementById('siTargetDisplay').textContent = peerId;
        document.getElementById('siStatus').style.display = 'none';
        document.getElementById('siContent').style.display = 'none';
        document.getElementById('sysinfoModal').style.display = 'flex';
        fetchSysInfo();
    }});
}});
function fetchSysInfo() {{
    const peerId = document.getElementById('siTargetPeerId').value;
    const st = document.getElementById('siStatus');
    const content = document.getElementById('siContent');
    const btn = document.getElementById('siRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...';
    st.innerHTML = '<div class="text-info small">Fetching system info...</div>'; st.style.display = 'block';
    content.style.display = 'none';
    fetch('/api/sysinfo/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{
            st.style.display = 'none';
            const info = data.info;
            let html = '<div class="sysinfo-grid">';
            const fields = [
                ['OS', info.os], ['Hostname', info.hostname], ['CPU', info.cpu],
                ['CPU Cores', info.cpu_cores], ['RAM Total', info.ram_total],
                ['RAM Used', info.ram_used], ['RAM %', info.ram_percent + '%'],
                ['Disk Total', info.disk_total], ['Disk Used', info.disk_used],
                ['Disk Free', info.disk_free], ['Disk %', info.disk_percent + '%'],
                ['Uptime', info.uptime], ['GPU', info.gpu],
                ['Python', info.python_version],
                ['Architecture', info.architecture], ['IP Addresses', (info.ip_addresses || []).join(', ')]
            ];
            fields.forEach(function(f) {{
                html += '<div class="si-label">' + f[0] + ':</div><div class="si-val">' + (f[1] || 'N/A') + '</div>';
            }});
            html += '</div>';
            content.innerHTML = html;
            content.style.display = 'block';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.notify-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('ntTargetPeerId').value = peerId;
        document.getElementById('ntTargetDisplay').textContent = peerId;
        document.getElementById('ntMessage').value = '';
        document.getElementById('ntStatus').style.display = 'none';
        document.getElementById('notifyModal').style.display = 'flex';
    }});
}});
function sendNotify() {{
    const peerId = document.getElementById('ntTargetPeerId').value;
    const title = document.getElementById('ntTitle').value.trim();
    const msg = document.getElementById('ntMessage').value.trim();
    const st = document.getElementById('ntStatus');
    if (!msg) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a message.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Sending notification...</div>'; st.style.display = 'block';
    fetch('/api/notify/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ title: title, message: msg }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Notification sent!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
let _pmAllProcs = [];
document.querySelectorAll('.procmgr-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('pmTargetPeerId').value = peerId;
        document.getElementById('pmTargetDisplay').textContent = peerId;
        document.getElementById('pmStatus').style.display = 'none';
        document.getElementById('pmProcList').innerHTML = '';
        document.getElementById('pmFilter').value = '';
        _pmAllProcs = [];
        document.getElementById('procMgrModal').style.display = 'flex';
        fetchProcesses();
    }});
}});
function fetchProcesses() {{
    const peerId = document.getElementById('pmTargetPeerId').value;
    const st = document.getElementById('pmStatus');
    const btn = document.getElementById('pmRefreshBtn');
    btn.disabled = true; btn.textContent = '...';
    st.innerHTML = '<div class="text-info small">Loading processes...</div>'; st.style.display = 'block';
    fetch('/api/processes/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{
            st.style.display = 'none';
            _pmAllProcs = data.processes || [];
            renderProcs(_pmAllProcs);
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
function renderProcs(procs) {{
    const list = document.getElementById('pmProcList');
    if (procs.length === 0) {{ list.innerHTML = '<tr><td colspan="5" class="text-secondary text-center">No processes.</td></tr>'; return; }}
    const peerId = document.getElementById('pmTargetPeerId').value;
    list.innerHTML = procs.map(function(p) {{
        return '<tr><td>' + p.pid + '</td><td>' + p.name + '</td><td>' + (p.cpu || '0') + '</td><td>' + (p.memory || '—') + '</td>'
            + '<td><button class="btn btn-sm btn-outline-danger py-0 px-1 kill-proc-btn" data-pid="' + p.pid + '" data-name="' + p.name + '">Kill</button></td></tr>';
    }}).join('');
}}
function filterProcs() {{
    const f = (document.getElementById('pmFilter').value || '').toLowerCase();
    if (!f) {{ renderProcs(_pmAllProcs); return; }}
    renderProcs(_pmAllProcs.filter(function(p) {{ return (p.name || '').toLowerCase().includes(f) || String(p.pid).includes(f); }}));
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('kill-proc-btn')) {{
        const pid = e.target.getAttribute('data-pid');
        const name = e.target.getAttribute('data-name');
        if (!confirm('Kill process "' + name + '" (PID ' + pid + ')?')) return;
        const peerId = document.getElementById('pmTargetPeerId').value;
        e.target.disabled = true; e.target.textContent = '...';
        fetch('/api/kill-process/' + peerId + '/' + pid, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            if (data.success) {{ fetchProcesses(); }}
            else {{ alert('Failed to kill: ' + (data.error || 'Unknown error')); e.target.disabled = false; e.target.textContent = 'Kill'; }}
        }}).catch(err => {{ alert('Error: ' + err.message); e.target.disabled = false; e.target.textContent = 'Kill'; }});
    }}
}});
let _srInterval = null;
let _srFrameNum = 0;
let _srFrames = [];
document.querySelectorAll('.screenrec-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('srTargetPeerId').value = peerId;
        document.getElementById('srTargetDisplay').textContent = peerId;
        document.getElementById('srStatus').style.display = 'none';
        document.getElementById('srFrameContainer').style.display = 'none';
        document.getElementById('srRecIndicator').style.display = 'none';
        document.getElementById('srStartBtn').style.display = '';
        document.getElementById('srStopBtn').style.display = 'none';
        document.getElementById('srSaveBtn').style.display = 'none';
        _srFrameNum = 0;
        _srFrames = [];
        document.getElementById('screenRecModal').style.display = 'flex';
    }});
}});
function startScreenRec() {{
    const peerId = document.getElementById('srTargetPeerId').value;
    document.getElementById('srStartBtn').style.display = 'none';
    document.getElementById('srStopBtn').style.display = '';
    document.getElementById('srRecIndicator').style.display = 'block';
    document.getElementById('srFrameContainer').style.display = 'block';
    document.getElementById('srStatus').style.display = 'none';
    _srFrameNum = 0;
    _srFrames = [];
    document.getElementById('srFrameCount').textContent = 'Frame: 0';
    fetchScreenFrame();
    _srInterval = setInterval(fetchScreenFrame, 2000);
}}
function stopScreenRec() {{
    if (_srInterval) {{ clearInterval(_srInterval); _srInterval = null; }}
    document.getElementById('srStartBtn').style.display = '';
    document.getElementById('srStopBtn').style.display = 'none';
    document.getElementById('srRecIndicator').style.display = 'none';
    if (_srFrames.length > 0) document.getElementById('srSaveBtn').style.display = '';
}}
function saveScreenshot() {{
    const img = document.getElementById('ssImage');
    if (!img.src || !img.src.startsWith('data:')) return;
    const a = document.createElement('a');
    a.href = img.src;
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.download = 'screenshot_' + ts + '.png';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}}
function saveRecording() {{
    if (_srFrames.length === 0) return;
    // Save all frames as individual PNG files in a zip-like download, or save the last frame
    // For simplicity: save each frame as separate download, or create a single animated approach
    // Best approach: download all frames as numbered PNGs
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    if (_srFrames.length === 1) {{
        const a = document.createElement('a');
        a.href = 'data:image/png;base64,' + _srFrames[0];
        a.download = 'recording_' + ts + '_001.png';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        return;
    }}
    // Multiple frames: trigger downloads sequentially
    const st = document.getElementById('srStatus');
    st.innerHTML = '<div class="text-info small">Saving ' + _srFrames.length + ' frames...</div>'; st.style.display = 'block';
    let idx = 0;
    function dlNext() {{
        if (idx >= _srFrames.length) {{
            st.innerHTML = '<div class="alert alert-success py-2 small">Saved ' + _srFrames.length + ' frames!</div>';
            return;
        }}
        const a = document.createElement('a');
        a.href = 'data:image/png;base64,' + _srFrames[idx];
        a.download = 'recording_' + ts + '_' + String(idx + 1).padStart(3, '0') + '.png';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        idx++;
        setTimeout(dlNext, 300);
    }}
    dlNext();
}}
function fetchScreenFrame() {{
    const peerId = document.getElementById('srTargetPeerId').value;
    fetch('/api/screenshot/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success && data.image) {{
            _srFrameNum++;
            _srFrames.push(data.image);
            document.getElementById('srFrame').src = 'data:image/png;base64,' + data.image;
            document.getElementById('srFrameCount').textContent = 'Frame: ' + _srFrameNum;
            document.getElementById('srFrameContainer').style.display = 'block';
        }} else if (data.error) {{
            const st = document.getElementById('srStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopScreenRec();
        }}
    }}).catch(function(err) {{
        const st = document.getElementById('srStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">Frame error: ' + err.message + '</div>';
        st.style.display = 'block';
        stopScreenRec();
    }});
}}
let _raInterval = null;
let _raAudioCtx = null;
let _raPlaying = false;
document.querySelectorAll('.remote-audio-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('raTargetPeerId').value = peerId;
        document.getElementById('raTargetDisplay').textContent = peerId;
        document.getElementById('raStatus').style.display = 'none';
        if (_raPlaying) {{
            document.getElementById('raListenIndicator').style.display = 'block';
            document.getElementById('raVisualizer').style.display = 'flex';
            document.getElementById('raStartBtn').style.display = 'none';
            document.getElementById('raStopBtn').style.display = '';
        }} else {{
            document.getElementById('raListenIndicator').style.display = 'none';
            document.getElementById('raVisualizer').style.display = 'none';
            document.getElementById('raStartBtn').style.display = '';
            document.getElementById('raStopBtn').style.display = 'none';
        }}
        document.getElementById('remoteAudioModal').style.display = 'flex';
    }});
}});
function startRemoteAudio() {{
    const peerId = document.getElementById('raTargetPeerId').value;
    document.getElementById('raStartBtn').style.display = 'none';
    document.getElementById('raStopBtn').style.display = '';
    document.getElementById('raStatus').style.display = 'none';
    document.getElementById('raListenIndicator').style.display = 'block';
    const vis = document.getElementById('raVisualizer');
    vis.innerHTML = '';
    for (let i = 0; i < 32; i++) {{
        const bar = document.createElement('div');
        bar.className = 'audio-bar';
        bar.style.height = '2px';
        vis.appendChild(bar);
    }}
    vis.style.display = 'flex';
    if (!_raAudioCtx) _raAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    _raPlaying = true;
    // Tell remote to start streaming
    fetch('/api/audio-stream/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('raStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed to start') + '</div>';
            st.style.display = 'block';
            stopRemoteAudio();
            return;
        }}
        // Start polling for chunks
        _raInterval = setInterval(fetchAudioChunk, 1500);
    }}).catch(function(err) {{
        const st = document.getElementById('raStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopRemoteAudio();
    }});
}}
function stopRemoteAudio() {{
    _raPlaying = false;
    if (_raInterval) {{ clearInterval(_raInterval); _raInterval = null; }}
    const peerId = document.getElementById('raTargetPeerId').value;
    fetch('/api/audio-stream/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('raStartBtn').style.display = '';
    document.getElementById('raStopBtn').style.display = 'none';
    document.getElementById('raListenIndicator').style.display = 'none';
}}
function fetchAudioChunk() {{
    if (!_raPlaying) return;
    const peerId = document.getElementById('raTargetPeerId').value;
    fetch('/api/audio-stream/' + peerId + '/chunk').then(r => r.json()).then(data => {{
        if (data.success && data.audio) {{
            const raw = atob(data.audio);
            const buf = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
            _raAudioCtx.decodeAudioData(buf.buffer.slice(0), function(audioBuffer) {{
                const src = _raAudioCtx.createBufferSource();
                src.buffer = audioBuffer;
                src.connect(_raAudioCtx.destination);
                src.start(0);
                const bars = document.querySelectorAll('#raVisualizer .audio-bar');
                const cd = audioBuffer.getChannelData(0);
                const step = Math.floor(cd.length / bars.length);
                bars.forEach(function(bar, i) {{
                    let sum = 0;
                    for (let j = i * step; j < (i + 1) * step && j < cd.length; j++) sum += Math.abs(cd[j]);
                    const avg = sum / step;
                    bar.style.height = Math.max(2, avg * 200) + 'px';
                }});
            }}, function() {{ }});
        }} else if (data.error) {{
            const st = document.getElementById('raStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopRemoteAudio();
        }}
    }}).catch(function() {{}});
}}
let _saInterval = null;
let _saAudioCtx = null;
let _saPlaying = false;
document.querySelectorAll('.sys-audio-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('saTargetPeerId').value = peerId;
        document.getElementById('saTargetDisplay').textContent = peerId;
        document.getElementById('saStatus').style.display = 'none';
        if (_saPlaying) {{
            document.getElementById('saListenIndicator').style.display = 'block';
            document.getElementById('saVisualizer').style.display = 'flex';
            document.getElementById('saStartBtn').style.display = 'none';
            document.getElementById('saStopBtn').style.display = '';
        }} else {{
            document.getElementById('saListenIndicator').style.display = 'none';
            document.getElementById('saVisualizer').style.display = 'none';
            document.getElementById('saStartBtn').style.display = '';
            document.getElementById('saStopBtn').style.display = 'none';
        }}
        document.getElementById('sysAudioModal').style.display = 'flex';
    }});
}});
function startSysAudio() {{
    const peerId = document.getElementById('saTargetPeerId').value;
    document.getElementById('saStartBtn').style.display = 'none';
    document.getElementById('saStopBtn').style.display = '';
    document.getElementById('saStatus').style.display = 'none';
    document.getElementById('saListenIndicator').style.display = 'block';
    const vis = document.getElementById('saVisualizer');
    vis.innerHTML = '';
    for (let i = 0; i < 32; i++) {{
        const bar = document.createElement('div');
        bar.className = 'audio-bar';
        bar.style.height = '2px';
        bar.style.background = '#58a6ff';
        vis.appendChild(bar);
    }}
    vis.style.display = 'flex';
    if (!_saAudioCtx) _saAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    _saPlaying = true;
    fetch('/api/sys-audio-stream/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('saStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed to start') + '</div>';
            st.style.display = 'block';
            stopSysAudio();
            return;
        }}
        _saInterval = setInterval(fetchSysAudioChunk, 1500);
    }}).catch(function(err) {{
        const st = document.getElementById('saStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopSysAudio();
    }});
}}
function stopSysAudio() {{
    _saPlaying = false;
    if (_saInterval) {{ clearInterval(_saInterval); _saInterval = null; }}
    const peerId = document.getElementById('saTargetPeerId').value;
    fetch('/api/sys-audio-stream/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('saStartBtn').style.display = '';
    document.getElementById('saStopBtn').style.display = 'none';
    document.getElementById('saListenIndicator').style.display = 'none';
}}
function fetchSysAudioChunk() {{
    if (!_saPlaying) return;
    const peerId = document.getElementById('saTargetPeerId').value;
    fetch('/api/sys-audio-stream/' + peerId + '/chunk').then(r => r.json()).then(data => {{
        if (data.success && data.audio) {{
            const raw = atob(data.audio);
            const buf = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
            _saAudioCtx.decodeAudioData(buf.buffer.slice(0), function(audioBuffer) {{
                const src = _saAudioCtx.createBufferSource();
                src.buffer = audioBuffer;
                src.connect(_saAudioCtx.destination);
                src.start(0);
                const bars = document.querySelectorAll('#saVisualizer .audio-bar');
                const cd = audioBuffer.getChannelData(0);
                const step = Math.floor(cd.length / bars.length);
                bars.forEach(function(bar, i) {{
                    let sum = 0;
                    for (let j = i * step; j < (i + 1) * step && j < cd.length; j++) sum += Math.abs(cd[j]);
                    const avg = sum / step;
                    bar.style.height = Math.max(2, avg * 200) + 'px';
                }});
            }}, function() {{ }});
        }} else if (data.error) {{
            const st = document.getElementById('saStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopSysAudio();
        }}
    }}).catch(function() {{}});
}}
let _imInterval = null;
let _imEventTotal = 0;
document.querySelectorAll('.input-monitor-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('imTargetPeerId').value = peerId;
        document.getElementById('imTargetDisplay').textContent = peerId;
        document.getElementById('imStatus').style.display = 'none';
        document.getElementById('imFeed').style.display = 'none';
        document.getElementById('imRecIndicator').style.display = 'none';
        document.getElementById('imStartBtn').style.display = '';
        document.getElementById('imStopBtn').style.display = 'none';
        document.getElementById('imClearBtn').style.display = 'none';
        _imEventTotal = 0;
        document.getElementById('inputMonitorModal').style.display = 'flex';
    }});
}});
function startInputMonitor() {{
    const peerId = document.getElementById('imTargetPeerId').value;
    document.getElementById('imStartBtn').style.display = 'none';
    document.getElementById('imStopBtn').style.display = '';
    document.getElementById('imClearBtn').style.display = '';
    document.getElementById('imRecIndicator').style.display = 'block';
    document.getElementById('imFeed').style.display = 'block';
    document.getElementById('imFeed').innerHTML = '<span class="text-secondary">Waiting for input events...</span>';
    document.getElementById('imStatus').style.display = 'none';
    _imEventTotal = 0;
    // Start monitoring on remote
    fetch('/api/input-monitor/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('imStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
            stopInputMonitor();
            return;
        }}
        _imInterval = setInterval(pollInputEvents, 1000);
    }}).catch(function(err) {{
        const st = document.getElementById('imStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopInputMonitor();
    }});
}}
function stopInputMonitor() {{
    if (_imInterval) {{ clearInterval(_imInterval); _imInterval = null; }}
    const peerId = document.getElementById('imTargetPeerId').value;
    fetch('/api/input-monitor/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('imStartBtn').style.display = '';
    document.getElementById('imStopBtn').style.display = 'none';
    document.getElementById('imRecIndicator').style.display = 'none';
}}
function pollInputEvents() {{
    const peerId = document.getElementById('imTargetPeerId').value;
    fetch('/api/input-monitor/' + peerId + '/events').then(r => r.json()).then(data => {{
        if (data.success && data.events && data.events.length > 0) {{
            const feed = document.getElementById('imFeed');
            if (_imEventTotal === 0) feed.innerHTML = '';
            data.events.forEach(function(ev) {{
                _imEventTotal++;
                let html = '<span class="keylog-time">[' + (ev.time || '') + '] </span>';
                if (ev.type === 'key') {{
                    if (ev.key && ev.key.length === 1) html += '<span class="keylog-key">' + ev.key + '</span>';
                    else html += '<span class="keylog-special">[' + (ev.key || '?') + ']</span>';
                }} else if (ev.type === 'mouse') {{
                    html += '<span class="keylog-mouse">[Click ' + (ev.button || '') + ' @ ' + (ev.x || 0) + ',' + (ev.y || 0) + ']</span>';
                }}
                feed.innerHTML += html;
            }});
            document.getElementById('imEventCount').textContent = 'Events: ' + _imEventTotal;
            feed.scrollTop = feed.scrollHeight;
        }} else if (data.error) {{
            const st = document.getElementById('imStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopInputMonitor();
        }}
    }}).catch(function() {{}});
}}
function filterPreview() {{
    const filter = (document.getElementById('previewSearch')?.value || '').toLowerCase();
    document.querySelectorAll('#previewList li').forEach(li => {{ if (!filter) {{ li.style.display = ''; }} else {{ const text = li.textContent.toLowerCase(); li.style.display = text.includes(filter) ? '' : 'none'; }} }});
}}
let _lastWebQuery = '';
document.getElementById('webSearchInput').addEventListener('keydown', function(e) {{ if (e.key === 'Enter') doWebSearch(); }});
function doWebSearch() {{
    const q = document.getElementById('webSearchInput').value.trim();
    if (!q) return;
    _lastWebQuery = q;
    const results = document.getElementById('webSearchResults');
    const loading = document.getElementById('webSearchLoading');
    const meta = document.getElementById('webSearchMeta');
    results.innerHTML = ''; meta.style.display = 'none'; loading.style.display = 'block';
    fetch('/api/web-search?q=' + encodeURIComponent(q)).then(r => r.json()).then(data => {{
        loading.style.display = 'none';
        if (data.error) {{ results.innerHTML = '<div class="alert alert-warning">' + data.error + '</div>'; return; }}
        const items = data.results || [];
        meta.style.display = 'block';
        meta.textContent = 'Found ' + items.length + ' results for "' + q + '" via ' + (data.engine || 'web search');
        if (items.length === 0) {{ results.innerHTML = '<div class="text-center py-4 text-secondary">No results found. Try a different query or use the engine buttons above.</div>'; return; }}
        let html = '';
        items.forEach(function(item) {{ const title = item.title || 'Untitled'; const url = item.url || '#'; const snippet = item.snippet || ''; const displayUrl = url.length > 80 ? url.substring(0, 80) + '...' : url; html += '<div class="web-result"><a href="' + url + '" target="_blank" rel="noopener" class="web-result-title">' + escapeHtml(title) + '</a><div class="web-result-url">' + escapeHtml(displayUrl) + '</div><div class="web-result-snippet">' + escapeHtml(snippet) + '</div></div>'; }});
        results.innerHTML = html;
    }}).catch(err => {{ loading.style.display = 'none'; results.innerHTML = '<div class="alert alert-danger">Search failed: ' + err.message + '</div>'; }});
}}
function escapeHtml(text) {{ const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }}
function openEngine(engine) {{
    const q = document.getElementById('webSearchInput').value.trim() || _lastWebQuery;
    if (!q) {{ alert('Enter a search query first.'); return; }}
    const urls = {{ google: 'https://www.google.com/search?q=', bing: 'https://www.bing.com/search?q=', yahoo: 'https://search.yahoo.com/search?p=', duckduckgo: 'https://duckduckgo.com/?q=', brave: 'https://search.brave.com/search?q=', wikipedia: 'https://en.wikipedia.org/w/index.php?search=' }};
    const base = urls[engine];
    if (base) window.open(base + encodeURIComponent(q), '_blank');
}}

// ===== Wake-on-LAN (direct send, no modal) =====
document.querySelectorAll('.wol-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        self.textContent = 'Sending...'; self.disabled = true;
        fetch('/api/wol/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            self.disabled = false;
            if (data.success) {{ self.textContent = 'Sent!'; setTimeout(() => {{ self.textContent = 'Wake-on-LAN'; }}, 3000); }}
            else {{ self.textContent = 'Failed'; setTimeout(() => {{ self.textContent = 'Wake-on-LAN'; }}, 3000); }}
        }}).catch(() => {{ self.textContent = 'Error'; self.disabled = false; setTimeout(() => {{ self.textContent = 'Wake-on-LAN'; }}, 3000); }});
    }});
}});
// ===== App Launch =====
let _alApps = [];
function renderAppList(apps, containerId, onSelect) {{
    const c = document.getElementById(containerId);
    if (!apps.length) {{ c.innerHTML = '<div class="text-secondary small p-3 text-center">No apps found.</div>'; return; }}
    c.innerHTML = apps.map(function(a, i) {{
        return '<div class="file-tree-item" data-idx="' + i + '" style="cursor:pointer;">' +
            '<span class="small text-white">' + a.name + '</span>' +
            '<small class="text-secondary" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + a.path + '</small>' +
            '</div>';
    }}).join('');
    c.querySelectorAll('.file-tree-item').forEach(function(el) {{
        el.addEventListener('click', function() {{
            const idx = parseInt(this.getAttribute('data-idx'));
            onSelect(apps[idx]);
            c.querySelectorAll('.file-tree-item').forEach(function(e) {{ e.style.background = ''; }});
            this.style.background = '#238636';
        }});
    }});
}}
function loadInstalledApps(peerId, containerId, loadingId, onSelect, cacheRef) {{
    const loading = document.getElementById(loadingId);
    const container = document.getElementById(containerId);
    loading.style.display = 'block';
    container.innerHTML = '';
    fetch('/api/installed-apps/' + peerId).then(r => r.json()).then(data => {{
        loading.style.display = 'none';
        if (data.success && data.apps) {{
            if (cacheRef === 'al') _alApps = data.apps;
            else _feApps = data.apps;
            renderAppList(data.apps, containerId, onSelect);
        }} else {{
            container.innerHTML = '<div class="text-danger small p-3">Failed to load apps: ' + (data.error || 'Unknown error') + '</div>';
        }}
    }}).catch(function(err) {{
        loading.style.display = 'none';
        container.innerHTML = '<div class="text-danger small p-3">Error: ' + err.message + '</div>';
    }});
}}
function filterAppList() {{
    const q = document.getElementById('alFilterInput').value.toLowerCase();
    const filtered = _alApps.filter(function(a) {{ return a.name.toLowerCase().indexOf(q) >= 0 || a.path.toLowerCase().indexOf(q) >= 0; }});
    renderAppList(filtered, 'alAppList', function(app) {{
        document.getElementById('alAppPath').value = app.path;
        document.getElementById('alAppArgs').value = app.args || '';
    }});
}}
document.querySelectorAll('.app-launch-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('alTargetPeerId').value = peerId;
        document.getElementById('alTargetDisplay').textContent = peerId;
        document.getElementById('alAppPath').value = '';
        document.getElementById('alAppArgs').value = '';
        document.getElementById('alFilterInput').value = '';
        document.getElementById('alStatus').style.display = 'none';
        document.getElementById('appLaunchModal').style.display = 'flex';
        loadInstalledApps(peerId, 'alAppList', 'alLoading', function(app) {{
            document.getElementById('alAppPath').value = app.path;
            document.getElementById('alAppArgs').value = app.args || '';
        }}, 'al');
    }});
}});
function sendAppLaunch() {{
    const peerId = document.getElementById('alTargetPeerId').value;
    const app = document.getElementById('alAppPath').value.trim();
    const args = document.getElementById('alAppArgs').value.trim();
    const st = document.getElementById('alStatus');
    if (!app) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Select an app or enter a path.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Launching...</div>'; st.style.display = 'block';
    fetch('/api/app-launch/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ app: app, args: args }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">App launched!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== File Exec =====
let _feApps = [];
function filterFileExecList() {{
    const q = document.getElementById('feFilterInput').value.toLowerCase();
    const filtered = _feApps.filter(function(a) {{ return a.name.toLowerCase().indexOf(q) >= 0 || a.path.toLowerCase().indexOf(q) >= 0; }});
    renderAppList(filtered, 'feAppList', function(app) {{
        document.getElementById('feFilePath').value = app.path;
    }});
}}
document.querySelectorAll('.file-exec-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('feTargetPeerId').value = peerId;
        document.getElementById('feTargetDisplay').textContent = peerId;
        document.getElementById('feFilePath').value = '';
        document.getElementById('feFilterInput').value = '';
        document.getElementById('feStatus').style.display = 'none';
        document.getElementById('fileExecModal').style.display = 'flex';
        loadInstalledApps(peerId, 'feAppList', 'feLoading', function(app) {{
            document.getElementById('feFilePath').value = app.path;
        }}, 'fe');
    }});
}});
function sendFileExec() {{
    const peerId = document.getElementById('feTargetPeerId').value;
    const fp = document.getElementById('feFilePath').value.trim();
    const st = document.getElementById('feStatus');
    if (!fp) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Select an app or enter a file path.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Executing...</div>'; st.style.display = 'block';
    fetch('/api/file-exec/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ path: fp }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">File executed!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Generic fetch-and-display helper =====
function gnaFetchDisplay(btnClass, modalId, targetPeerIdEl, targetDisplayEl, statusEl, contentEl, refreshBtnEl, fetchFn) {{
    document.querySelectorAll(btnClass).forEach(btn => {{
        btn.addEventListener('click', function() {{
            const peerId = this.getAttribute('data-peer-id');
            document.getElementById(targetPeerIdEl).value = peerId;
            document.getElementById(targetDisplayEl).textContent = peerId;
            document.getElementById(statusEl).style.display = 'none';
            document.getElementById(contentEl).style.display = 'none';
            document.getElementById(modalId).style.display = 'flex';
            fetchFn();
        }});
    }});
}}
// ===== Disk Info =====
gnaFetchDisplay('.disk-info-btn','diskInfoModal','diTargetPeerId','diTargetDisplay','diStatus','diContent','diRefreshBtn',fetchDiskInfo);
function fetchDiskInfo() {{
    const peerId = document.getElementById('diTargetPeerId').value;
    const st = document.getElementById('diStatus'); const c = document.getElementById('diContent'); const btn = document.getElementById('diRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching disk info...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/disk-info/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Event Log =====
gnaFetchDisplay('.event-log-btn','eventLogModal','elTargetPeerId','elTargetDisplay','elStatus','elContent','elRefreshBtn',fetchEventLog);
function fetchEventLog() {{
    const peerId = document.getElementById('elTargetPeerId').value;
    const st = document.getElementById('elStatus'); const c = document.getElementById('elContent'); const btn = document.getElementById('elRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching event log...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/event-log/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Health =====
gnaFetchDisplay('.health-btn','healthModal','hlTargetPeerId','hlTargetDisplay','hlStatus','hlContent','hlRefreshBtn',fetchHealth);
function fetchHealth() {{
    const peerId = document.getElementById('hlTargetPeerId').value;
    const st = document.getElementById('hlStatus'); const c = document.getElementById('hlContent'); const btn = document.getElementById('hlRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching health...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/health/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Printers =====
gnaFetchDisplay('.printers-btn','printersModal','prTargetPeerId','prTargetDisplay','prStatus','prContent','prRefreshBtn',fetchPrinters);
function fetchPrinters() {{
    const peerId = document.getElementById('prTargetPeerId').value;
    const st = document.getElementById('prStatus'); const c = document.getElementById('prContent'); const btn = document.getElementById('prRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching printers...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/printers/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Shared Term =====
document.querySelectorAll('.shared-term-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('stTargetPeerId').value = peerId;
        document.getElementById('stTargetDisplay').textContent = peerId;
        document.getElementById('stOutput').textContent = 'Connected to ' + peerId + '. Type a command below.\\n';
        document.getElementById('stCmdInput').value = '';
        document.getElementById('sharedTermModal').style.display = 'flex';
        document.getElementById('stCmdInput').focus();
    }});
}});
document.getElementById('stCmdInput').addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') sendSharedTermCmd();
}});
function sendSharedTermCmd() {{
    const peerId = document.getElementById('stTargetPeerId').value;
    const cmd = document.getElementById('stCmdInput').value.trim();
    if (!cmd) return;
    const out = document.getElementById('stOutput');
    out.textContent += '> ' + cmd + '\\n';
    document.getElementById('stCmdInput').value = '';
    document.getElementById('stSendBtn').disabled = true; document.getElementById('stSendBtn').textContent = '...';
    fetch('/api/remote-exec/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ command: cmd }}) }}).then(r => r.json()).then(data => {{
        if (data.output) out.textContent += data.output + '\\n';
        if (data.error) out.textContent += 'ERROR: ' + data.error + '\\n';
        out.scrollTop = out.scrollHeight;
        document.getElementById('stSendBtn').disabled = false; document.getElementById('stSendBtn').textContent = 'Run';
    }}).catch(err => {{
        out.textContent += 'NETWORK ERROR: ' + err.message + '\\n';
        document.getElementById('stSendBtn').disabled = false; document.getElementById('stSendBtn').textContent = 'Run';
    }});
}}
// ===== Wallpaper =====
document.querySelectorAll('.wallpaper-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('wpTargetPeerId').value = peerId;
        document.getElementById('wpTargetDisplay').textContent = peerId;
        document.getElementById('wpUrl').value = '';
        document.getElementById('wpStatus').style.display = 'none';
        document.getElementById('wallpaperModal').style.display = 'flex';
    }});
}});
function sendWallpaper() {{
    const peerId = document.getElementById('wpTargetPeerId').value;
    const url = document.getElementById('wpUrl').value.trim();
    const st = document.getElementById('wpStatus');
    if (!url) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter an image URL.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Setting wallpaper...</div>'; st.style.display = 'block';
    fetch('/api/wallpaper/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ url: url }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Wallpaper set!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Software =====
let _swAllItems = [];
gnaFetchDisplay('.software-btn','softwareModal','swTargetPeerId','swTargetDisplay','swStatus','swContent','swRefreshBtn',fetchSoftware);
function fetchSoftware() {{
    const peerId = document.getElementById('swTargetPeerId').value;
    const st = document.getElementById('swStatus'); const c = document.getElementById('swContent'); const btn = document.getElementById('swRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching software list...</div>'; st.style.display = 'block'; c.style.display = 'none'; _swAllItems = [];
    fetch('/api/software/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; _swAllItems = data.items || []; renderSoftwareList(_swAllItems); c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
function renderSoftwareList(items) {{
    const c = document.getElementById('swContent');
    if (items.length === 0) {{ c.innerHTML = '<p class="text-secondary small">No software found.</p>'; return; }}
    let html = '<table class="table table-dark table-sm mb-0"><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>';
    items.forEach(function(i) {{ html += '<tr><td>' + escapeHtml(i.name || '') + '</td><td>' + escapeHtml(i.version || '') + '</td></tr>'; }});
    html += '</tbody></table>';
    c.innerHTML = html;
}}
function filterSoftwareList() {{
    const q = (document.getElementById('swFilter').value || '').toLowerCase();
    const filtered = q ? _swAllItems.filter(function(i) {{ return (i.name || '').toLowerCase().includes(q); }}) : _swAllItems;
    renderSoftwareList(filtered);
}}
// ===== Registry =====
document.querySelectorAll('.registry-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('rgTargetPeerId').value = peerId;
        document.getElementById('rgTargetDisplay').textContent = peerId;
        document.getElementById('rgPath').value = 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion';
        document.getElementById('rgStatus').style.display = 'none';
        document.getElementById('rgContent').style.display = 'none';
        document.getElementById('registryModal').style.display = 'flex';
    }});
}});
function fetchRegistry() {{
    const peerId = document.getElementById('rgTargetPeerId').value;
    const path = document.getElementById('rgPath').value.trim();
    const st = document.getElementById('rgStatus'); const c = document.getElementById('rgContent');
    if (!path) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a registry path.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Querying registry...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/registry/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ path: path }}) }}).then(r => r.json()).then(data => {{
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Net Conns =====
gnaFetchDisplay('.net-conns-btn','netConnsModal','ncTargetPeerId','ncTargetDisplay','ncStatus','ncContent','ncRefreshBtn',fetchNetConns);
function fetchNetConns() {{
    const peerId = document.getElementById('ncTargetPeerId').value;
    const st = document.getElementById('ncStatus'); const c = document.getElementById('ncContent'); const btn = document.getElementById('ncRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching connections...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/net-conns/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Env Vars =====
gnaFetchDisplay('.env-vars-btn','envVarsModal','evTargetPeerId','evTargetDisplay','evStatus','evContent','evRefreshBtn',fetchEnvVars);
function fetchEnvVars() {{
    const peerId = document.getElementById('evTargetPeerId').value;
    const st = document.getElementById('evStatus'); const c = document.getElementById('evContent'); const btn = document.getElementById('evRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching env vars...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/env-vars/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Hosts File =====
document.querySelectorAll('.hosts-file-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('hfTargetPeerId').value = peerId;
        document.getElementById('hfTargetDisplay').textContent = peerId;
        document.getElementById('hfStatus').style.display = 'none';
        document.getElementById('hfContent').style.display = 'none';
        document.getElementById('hostsFileModal').style.display = 'flex';
        fetchHostsFile();
    }});
}});
function fetchHostsFile() {{
    const peerId = document.getElementById('hfTargetPeerId').value;
    const st = document.getElementById('hfStatus'); const c = document.getElementById('hfContent'); const btn = document.getElementById('hfRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching hosts file...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/hosts-file/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; document.getElementById('hfTextArea').value = data.content || ''; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== URL Open =====
document.querySelectorAll('.url-open-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('uoTargetPeerId').value = peerId;
        document.getElementById('uoTargetDisplay').textContent = peerId;
        document.getElementById('uoUrl').value = '';
        document.getElementById('uoStatus').style.display = 'none';
        document.getElementById('urlOpenModal').style.display = 'flex';
    }});
}});
function sendUrlOpen() {{
    const peerId = document.getElementById('uoTargetPeerId').value;
    const url = document.getElementById('uoUrl').value.trim();
    const st = document.getElementById('uoStatus');
    if (!url) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a URL.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Opening URL...</div>'; st.style.display = 'block';
    fetch('/api/url-open/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ url: url }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">URL opened!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Drivers =====
gnaFetchDisplay('.drivers-btn','driversModal','drTargetPeerId','drTargetDisplay','drStatus','drContent','drRefreshBtn',fetchDrivers);
function fetchDrivers() {{
    const peerId = document.getElementById('drTargetPeerId').value;
    const st = document.getElementById('drStatus'); const c = document.getElementById('drContent'); const btn = document.getElementById('drRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching drivers...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/drivers/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Net Adapters =====
gnaFetchDisplay('.net-adapters-btn','netAdaptersModal','naTargetPeerId','naTargetDisplay','naStatus','naContent','naRefreshBtn',fetchNetAdapters);
function fetchNetAdapters() {{
    const peerId = document.getElementById('naTargetPeerId').value;
    const st = document.getElementById('naStatus'); const c = document.getElementById('naContent'); const btn = document.getElementById('naRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching adapters...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/net-adapters/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Firewall =====
gnaFetchDisplay('.firewall-btn','firewallModal','fwTargetPeerId','fwTargetDisplay','fwStatus','fwContent','fwRefreshBtn',fetchFirewall);
function fetchFirewall() {{
    const peerId = document.getElementById('fwTargetPeerId').value;
    const st = document.getElementById('fwStatus'); const c = document.getElementById('fwContent'); const btn = document.getElementById('fwRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching firewall rules...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/firewall/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Battery =====
gnaFetchDisplay('.battery-btn','batteryModal','btTargetPeerId','btTargetDisplay','btStatus','btContent','btRefreshBtn',fetchBattery);
function fetchBattery() {{
    const peerId = document.getElementById('btTargetPeerId').value;
    const st = document.getElementById('btStatus'); const c = document.getElementById('btContent'); const btn = document.getElementById('btRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching battery...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/battery/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Webcam Snap =====
document.querySelectorAll('.webcam-snap-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('wsTargetPeerId').value = peerId;
        document.getElementById('wsTargetDisplay').textContent = peerId;
        document.getElementById('wsStatus').style.display = 'none';
        document.getElementById('wsImageContainer').style.display = 'none';
        document.getElementById('wsCaptureBtn').disabled = false; document.getElementById('wsCaptureBtn').textContent = 'Capture';
        document.getElementById('webcamSnapModal').style.display = 'flex';
    }});
}});
function captureWebcam() {{
    const peerId = document.getElementById('wsTargetPeerId').value;
    const btn = document.getElementById('wsCaptureBtn'); const st = document.getElementById('wsStatus'); const imgC = document.getElementById('wsImageContainer');
    btn.disabled = true; btn.textContent = 'Capturing...'; st.innerHTML = '<div class="text-info small">Requesting webcam snap...</div>'; st.style.display = 'block'; imgC.style.display = 'none';
    fetch('/api/webcam-snap/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Capture Again';
        if (data.success) {{ st.style.display = 'none'; document.getElementById('wsImage').src = 'data:image/png;base64,' + data.image; imgC.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Capture'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Webcam Stream =====
let _wcInterval = null; let _wcFrameNum = 0;
document.querySelectorAll('.webcam-stream-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('wcTargetPeerId').value = peerId;
        document.getElementById('wcTargetDisplay').textContent = peerId;
        document.getElementById('wcStatus').style.display = 'none'; document.getElementById('wcFrameContainer').style.display = 'none';
        document.getElementById('wcRecIndicator').style.display = 'none'; document.getElementById('wcStartBtn').style.display = '';
        document.getElementById('wcStopBtn').style.display = 'none'; _wcFrameNum = 0;
        document.getElementById('webcamStreamModal').style.display = 'flex';
    }});
}});
function startWebcamStream() {{
    document.getElementById('wcStartBtn').style.display = 'none'; document.getElementById('wcStopBtn').style.display = '';
    document.getElementById('wcRecIndicator').style.display = 'block'; document.getElementById('wcFrameContainer').style.display = 'block';
    _wcFrameNum = 0; fetchWebcamFrame(); _wcInterval = setInterval(fetchWebcamFrame, 2000);
}}
function stopWebcamStream() {{
    if (_wcInterval) {{ clearInterval(_wcInterval); _wcInterval = null; }}
    document.getElementById('wcStartBtn').style.display = ''; document.getElementById('wcStopBtn').style.display = 'none';
    document.getElementById('wcRecIndicator').style.display = 'none';
}}
function fetchWebcamFrame() {{
    const peerId = document.getElementById('wcTargetPeerId').value;
    fetch('/api/webcam-snap/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success && data.image) {{ _wcFrameNum++; document.getElementById('wcFrame').src = 'data:image/png;base64,' + data.image; document.getElementById('wcFrameCount').textContent = 'Frame: ' + _wcFrameNum; }}
        else if (data.error) {{ document.getElementById('wcStatus').innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>'; document.getElementById('wcStatus').style.display = 'block'; stopWebcamStream(); }}
    }}).catch(function(err) {{ document.getElementById('wcStatus').innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>'; document.getElementById('wcStatus').style.display = 'block'; stopWebcamStream(); }});
}}
// ===== Location =====
gnaFetchDisplay('.location-btn','locationModal','loTargetPeerId','loTargetDisplay','loStatus','loContent','loRefreshBtn',fetchLocation);
function fetchLocation() {{
    const peerId = document.getElementById('loTargetPeerId').value;
    const st = document.getElementById('loStatus'); const c = document.getElementById('loContent'); const btn = document.getElementById('loRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching location...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/location/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Recent Files =====
gnaFetchDisplay('.recent-files-btn','recentFilesModal','rfcTargetPeerId','rfcTargetDisplay','rfcStatus','rfcContent','rfcRefreshBtn',fetchRecentFiles);
function fetchRecentFiles() {{
    const peerId = document.getElementById('rfcTargetPeerId').value;
    const st = document.getElementById('rfcStatus'); const c = document.getElementById('rfcContent'); const btn = document.getElementById('rfcRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching recent files...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/recent-files/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== BIOS Info =====
gnaFetchDisplay('.bios-info-btn','biosInfoModal','biTargetPeerId','biTargetDisplay','biStatus','biContent','biRefreshBtn',fetchBiosInfo);
function fetchBiosInfo() {{
    const peerId = document.getElementById('biTargetPeerId').value;
    const st = document.getElementById('biStatus'); const c = document.getElementById('biContent'); const btn = document.getElementById('biRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...'; st.innerHTML = '<div class="text-info small">Fetching BIOS info...</div>'; st.style.display = 'block'; c.style.display = 'none';
    fetch('/api/bios-info/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; }}
    }}).catch(err => {{ btn.disabled = false; btn.textContent = 'Refresh'; st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Perf Monitor =====
let _pfInterval = null;
document.querySelectorAll('.perf-monitor-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('pfTargetPeerId').value = peerId;
        document.getElementById('pfTargetDisplay').textContent = peerId;
        document.getElementById('pfStatus').style.display = 'none'; document.getElementById('pfContent').style.display = 'none';
        document.getElementById('pfRecIndicator').style.display = 'none'; document.getElementById('pfStartBtn').style.display = '';
        document.getElementById('pfStopBtn').style.display = 'none';
        document.getElementById('perfMonitorModal').style.display = 'flex';
    }});
}});
function startPerfMonitor() {{
    document.getElementById('pfStartBtn').style.display = 'none'; document.getElementById('pfStopBtn').style.display = '';
    document.getElementById('pfRecIndicator').style.display = 'block';
    fetchPerfData(); _pfInterval = setInterval(fetchPerfData, 3000);
}}
function stopPerfMonitor() {{ if (_pfInterval) {{ clearInterval(_pfInterval); _pfInterval = null; }} document.getElementById('pfStartBtn').style.display = ''; document.getElementById('pfStopBtn').style.display = 'none'; document.getElementById('pfRecIndicator').style.display = 'none'; }}
function fetchPerfData() {{
    const peerId = document.getElementById('pfTargetPeerId').value;
    const st = document.getElementById('pfStatus'); const c = document.getElementById('pfContent');
    fetch('/api/perf-monitor/' + peerId).then(r => r.json()).then(data => {{
        if (data.success) {{ st.style.display = 'none'; c.innerHTML = '<pre class="text-white small mb-0" style="white-space:pre-wrap;">' + escapeHtml(data.info || 'No data') + '</pre>'; c.style.display = 'block'; }}
        else {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>'; st.style.display = 'block'; stopPerfMonitor(); }}
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; stopPerfMonitor(); }});
}}
// ===== Voice Note =====
let _vnMediaRecorder = null; let _vnChunks = [];
document.querySelectorAll('.voice-note-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('vnTargetPeerId').value = peerId;
        document.getElementById('vnTargetDisplay').textContent = peerId;
        document.getElementById('vnStatus').style.display = 'none'; document.getElementById('vnRecIndicator').style.display = 'none';
        document.getElementById('vnRecordBtn').textContent = 'Record'; _vnMediaRecorder = null; _vnChunks = [];
        document.getElementById('voiceNoteModal').style.display = 'flex';
    }});
}});
function toggleVoiceNote() {{
    if (_vnMediaRecorder && _vnMediaRecorder.state === 'recording') {{
        _vnMediaRecorder.stop(); document.getElementById('vnRecordBtn').textContent = 'Record'; document.getElementById('vnRecIndicator').style.display = 'none';
    }} else {{
        navigator.mediaDevices.getUserMedia({{ audio: true }}).then(stream => {{
            _vnChunks = []; _vnMediaRecorder = new MediaRecorder(stream);
            _vnMediaRecorder.ondataavailable = e => {{ if (e.data.size > 0) _vnChunks.push(e.data); }};
            _vnMediaRecorder.onstop = () => {{
                stream.getTracks().forEach(t => t.stop());
                const blob = new Blob(_vnChunks, {{ type: 'audio/webm' }});
                const reader = new FileReader();
                reader.onloadend = () => {{
                    const b64 = reader.result.split(',')[1];
                    const peerId = document.getElementById('vnTargetPeerId').value;
                    const st = document.getElementById('vnStatus');
                    st.innerHTML = '<div class="text-info small">Sending voice note...</div>'; st.style.display = 'block';
                    fetch('/api/voice-note/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ audio: b64 }}) }}).then(r => r.json()).then(data => {{
                        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Voice note sent!</div>';
                        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
                        st.style.display = 'block';
                    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>'; st.style.display = 'block'; }});
                }};
                reader.readAsDataURL(blob);
            }};
            _vnMediaRecorder.start(); document.getElementById('vnRecordBtn').textContent = 'Stop & Send'; document.getElementById('vnRecIndicator').style.display = 'block';
        }}).catch(err => {{
            const st = document.getElementById('vnStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">Mic access denied: ' + err.message + '</div>'; st.style.display = 'block';
        }});
    }}
}}
// ===== TTS =====
document.querySelectorAll('.tts-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('ttTargetPeerId').value = peerId;
        document.getElementById('ttTargetDisplay').textContent = peerId;
        document.getElementById('ttText').value = '';
        document.getElementById('ttStatus').style.display = 'none';
        document.getElementById('ttsModal').style.display = 'flex';
    }});
}});
function sendTTS() {{
    const peerId = document.getElementById('ttTargetPeerId').value;
    const text = document.getElementById('ttText').value.trim();
    const st = document.getElementById('ttStatus');
    if (!text) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter text to speak.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Sending TTS...</div>'; st.style.display = 'block';
    fetch('/api/tts/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ text: text }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">TTS played on peer!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Play Sound =====
document.querySelectorAll('.play-sound-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('psTargetPeerId').value = peerId;
        document.getElementById('psTargetDisplay').textContent = peerId;
        document.getElementById('psSoundUrl').value = '';
        document.getElementById('psStatus').style.display = 'none';
        document.getElementById('playSoundModal').style.display = 'flex';
    }});
}});
function sendPlaySound() {{
    const peerId = document.getElementById('psTargetPeerId').value;
    const sound = document.getElementById('psSoundUrl').value.trim();
    const st = document.getElementById('psStatus');
    if (!sound) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a sound name or URL.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Playing sound...</div>'; st.style.display = 'block';
    fetch('/api/play-sound/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ sound: sound }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Sound played!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
// ===== Mouse Jiggler (toggle, no modal) =====
document.querySelectorAll('.mouse-jiggler-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        const isActive = self.textContent.includes('Stop');
        self.textContent = isActive ? 'Stopping...' : 'Starting...'; self.disabled = true;
        fetch('/api/mouse-jiggler/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ action: isActive ? 'stop' : 'start' }}) }}).then(r => r.json()).then(data => {{
            self.disabled = false;
            if (data.success) {{ self.textContent = data.active ? 'Stop Jiggler' : 'Mouse Jiggler'; if (data.active) {{ self.classList.remove('btn-outline-secondary'); self.classList.add('btn-warning'); }} else {{ self.classList.remove('btn-warning'); self.classList.add('btn-outline-secondary'); }} }}
            else {{ self.textContent = 'Mouse Jiggler'; }}
        }}).catch(() => {{ self.textContent = 'Mouse Jiggler'; self.disabled = false; }});
    }});
}});
// ===== Cursor Prank (direct send, no modal) =====
document.querySelectorAll('.cursor-prank-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        self.textContent = 'Pranking...'; self.disabled = true;
        fetch('/api/cursor-prank/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            self.disabled = false;
            if (data.success) {{ self.textContent = 'Pranked!'; setTimeout(() => {{ self.textContent = 'Cursor Prank'; }}, 3000); }}
            else {{ self.textContent = 'Failed'; setTimeout(() => {{ self.textContent = 'Cursor Prank'; }}, 3000); }}
        }}).catch(() => {{ self.textContent = 'Error'; self.disabled = false; setTimeout(() => {{ self.textContent = 'Cursor Prank'; }}, 3000); }});
    }});
}});

</script>
</body>
</html>"""


def render_search_results(results, query):
    rows = []
    for r in results:
        actions = f'<a href="{r["link"]}" class="btn btn-sm btn-outline-light">Open</a>'
        dl_link = f'{r["link"]}?download=1' if '?' not in r["link"] else f'{r["link"]}&download=1'
        actions += f' <a href="{dl_link}" class="btn btn-sm btn-light ms-2">Download</a>'
        actions += f' <a href="/peer_connect/{r["bank_id"]}" class="btn btn-sm btn-outline-light ms-2">Connect</a>'
        rows.append(f'<tr><td><small class="text-secondary">{r["bank_id"]}</small><br><strong>{r["name"]}</strong></td><td>{r["size"]}</td><td>{actions}</td></tr>')
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Search Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ font-family: 'Inter', system-ui, sans-serif; background: #0d1117; color: #e6edf3; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }} .btn-outline-light {{ --bs-btn-color: #e6edf3; --bs-btn-border-color: #444d56; }} .btn-outline-light:hover {{ background: #30363d; color: white; }} .btn-light {{ --bs-btn-bg: #e6edf3; --bs-btn-color: #0d1117; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} small {{ color: #8b949e; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4 text-center">Network Search Results</h1>
        <p class="text-center mb-5 text-secondary">Found {len(results)} matching items across live instances</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <div class="table-responsive">
            <table class="table table-hover">
                <thead><tr><th>Instance / Name</th><th>Size/Type</th><th>Actions</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def render_explorer(entries, req_path):
    def _entry_row(e, idx):
        checked = 'checked' if e['shared'] else ''
        tag_display = 'block' if e['shared'] else 'none'
        tag_val = e.get('tags', '') or ''
        tag_val_safe = tag_val.replace('"', '&quot;')
        icon = 'Folder ' if e['is_dir'] else 'File '
        return (f'<tr><td><input type="checkbox" name="path" value="{e["path"]}" {checked} class="form-check-input" id="cb_{idx}" onchange="toggleTag({idx})"></td><td>{icon}<a href="/explorer/{e["path"]}" class="text-decoration-none">{e["name"]}</a></td><td>{e["size"]}</td><td><input type="text" name="tags_{e["path"]}" id="tag_{idx}" value="{tag_val_safe}" placeholder="Tags (comma separated)" class="form-control form-control-sm bg-dark text-white border-secondary tag-input" style="display:{tag_display};width:200px;font-size:0.8rem;"></td></tr>')
    rows = "".join(_entry_row(e, i) for i, e in enumerate(entries))
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Content Selection</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} .form-check-input:checked {{ background-color: #238636; border-color: #238636; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }} .tag-input::placeholder {{ color: #6e7681; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4">Content Selection</h1>
        <p class="text-secondary mb-4">Current location: /{req_path or 'Root'}</p>
        <p class="text-secondary small">Check a file to share it. Add comma-separated tags to make it searchable by genre/category.</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <form method="post" action="/save_selection">
            <input type="hidden" name="current_path" value="{req_path}">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th width="50">Select</th><th>Name</th><th>Size/Type</th><th>Tags</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <button type="submit" class="btn btn-success btn-lg w-100 mt-4">Save Selection</button>
        </form>
    </div>
<script>
function toggleTag(idx) {{ var cb = document.getElementById('cb_' + idx); var tag = document.getElementById('tag_' + idx); if (cb.checked) {{ tag.style.display = 'block'; }} else {{ tag.style.display = 'none'; tag.value = ''; }} }}
</script>
</body>
</html>"""


def render_preview(entries, req_path):
    def _preview_row(e):
        entry_type = "Folder " if e["is_dir"] else "File "
        download_btn = f'<a href="/preview/{e["path"].rstrip("/")}?download=1" class="btn btn-sm btn-outline-light">Download</a>'
        return f'<tr><td>{entry_type} <a href="/preview/{e["path"]}" class="text-decoration-none">{e["name"]}</a></td><td>{e["size"]}</td><td>{download_btn}</td></tr>'
    rows = "".join(_preview_row(e) for e in entries)
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Shared Content Preview</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4">Shared Content Preview</h1>
        <p class="text-secondary mb-4">Current location: /{req_path or 'Root'}</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <div class="table-responsive">
            <table class="table table-hover">
                <thead><tr><th>Name</th><th>Size</th><th>Action</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
</body>
</html>"""


# ===========================================================================
# presentation/routes
# ===========================================================================
def create_routes(app, state):
    @app.route('/shared_count')
    def shared_count():
        return jsonify({'count': len(state.shared_paths)})

    @app.route('/shared_list')
    def shared_list():
        items = get_shared_items_list(state)
        return jsonify({'items': [{'path': item.path, 'name': item.name, 'size': item.size_str, 'is_folder': item.is_folder, 'tags': state.shared_paths.get(item.path, '')} for item in items]})

    @app.route('/my_preview')
    def my_preview():
        count = len(state.shared_paths)
        items = get_preview_items(state)
        html = f"""
        <div class="modal-content bg-dark text-light p-4 rounded">
            <h5 class="mb-3">Peer Preview — Your Instance ({state.my_id})</h5>
            <p class="text-muted small">Click off display to close or use the button below</p>
            <p><strong>Shared items:</strong> {count}</p>
            <hr class="bg-secondary">
            <h6>Top shared content:</h6>
            <div class="preview-body">
                <ul id="previewList" class="list-group list-group-flush small preview-list">
                    {''.join(
                        '<li class="list-group-item bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center">'
                        + ("F " if i["is_folder"] else "f ") + i["name"]
                        + '<div class="d-flex align-items-center">'
                        + f'<small class="text-muted me-3">{i["size"]}</small>'
                        + (f'<a href="{i["download_url"]}" class="btn btn-sm btn-outline-light">Download</a>' if i["download_url"] else '')
                        + '</div></li>'
                        for i in items
                    ) or '<li class="list-group-item bg-dark text-muted border-secondary">No items shared yet</li>'}
                </ul>
            </div>
            <div class="mt-4 text-end">
                <button type="button" class="btn btn-sm btn-outline-light me-2" onclick="document.getElementById('previewModal').style.display='none'">Close</button>
                <a href="/" class="btn btn-sm btn-primary">Open Full Dashboard</a>
            </div>
        </div>
        """
        return html

    @app.route('/peer_shared_count/<peer_id>')
    def peer_shared_count_route(peer_id):
        if peer_id == str(state.my_id):
            return jsonify({'count': len(state.shared_paths)})
        peer_info = state.known_peers.get(peer_id)
        if not peer_info:
            return jsonify({'count': 0})
        count = fetch_peer_shared_count(peer_info.ip, peer_info.port)
        return jsonify({'count': count if count is not None else 0})

    @app.route('/peer_preview/<peer_id>')
    def peer_preview(peer_id):
        try:
            if peer_id == str(state.my_id):
                return my_preview()
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return '<div class="alert alert-warning m-4"><strong>Peer not found</strong></div>'
            count = "N/A"
            items = []
            count_val = fetch_peer_shared_count(peer_info.ip, peer_info.port)
            if count_val is not None: count = count_val
            remote_items = fetch_peer_shared_list(peer_info.ip, peer_info.port)
            if remote_items:
                count = len(remote_items)
                for item in remote_items:
                    path_clean = item.get('path', '').lstrip('/')
                    if path_clean:
                        download_url = f"/peer_download/{peer_id}/{path_clean.rstrip('/')}"
                    else:
                        download_url = None
                    items.append({'name': item.get('name', '—'), 'size': item.get('size', '—'), 'is_folder': item.get('is_folder', False), 'download_url': download_url})
            html = f"""
            <div class="modal-content bg-dark text-light p-4 rounded">
                <h5 class="mb-3">Peer Preview — {peer_id}</h5>
                <p class="text-muted small">Click off display to close or use the button below</p>
                <p><strong>Shared items:</strong> {count}</p>
                <hr class="bg-secondary">
                <div class="preview-body">
                    <div class="preview-search">
                        <input id="previewSearch" type="text" class="form-control" placeholder="Filter items..." oninput="filterPreview()">
                    </div>
                    <ul id="previewList" class="list-group list-group-flush small">
                        {''.join(
                            '<li class="list-group-item bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center">'
                            + ("F " if i["is_folder"] else "f ") + i["name"]
                            + '<div class="d-flex align-items-center">'
                            + f'<small class="text-muted me-3">{i["size"]}</small>'
                            + (f'<a href="{i["download_url"]}" class="btn btn-sm btn-outline-light">Download</a>' if i.get("download_url") else '')
                            + '</div></li>'
                            for i in items
                        ) or '<li class="list-group-item bg-dark text-muted border-secondary">No items visible or reachable</li>'}
                    </ul>
                </div>
                <div class="mt-4 text-end">
                    <button type="button" class="btn btn-sm btn-outline-light me-2" onclick="document.getElementById('previewModal').style.display='none'">Close</button>
                </div>
            </div>
            """
            return html
        except requests.exceptions.ConnectionError:
            return '<div class="alert alert-warning m-4"><strong>Connection refused</strong><br>The peer is not reachable.</div>'
        except requests.exceptions.Timeout:
            return '<div class="alert alert-warning m-4"><strong>Request timed out</strong></div>'
        except Exception as e:
            return f'<div class="alert alert-danger m-4">Could not load preview<br><small>{str(e)}</small></div>'

    @app.route('/peer_connect/<peer_id>')
    def peer_connect(peer_id):
        if peer_id == str(state.my_id): return redirect('/')
        peer_info = state.known_peers.get(peer_id)
        if not peer_info: abort(404)
        return redirect(f"http://{peer_info.ip}:{peer_info.port}")

    @app.route('/peer_download/<peer_id>/<path:file_path>')
    def peer_download(peer_id, file_path):
        if peer_id == str(state.my_id): return redirect(f"/preview/{file_path}?download=1")
        peer_info = state.known_peers.get(peer_id)
        if not peer_info: abort(404)
        return redirect(f"http://{peer_info.ip}:{peer_info.port}/preview/{file_path}?download=1")

    @app.route('/search', methods=['GET'])
    def search():
        q = flask_request.args.get('q', '').strip()
        if not q: return redirect('/')
        results = search_network(state, q)
        results_dicts = [{'bank_id': r.bank_id, 'name': r.name, 'size': r.size, 'is_folder': r.is_folder, 'link': r.link} for r in results]
        return render_search_results(results_dicts, q)

    @app.route('/api/peers', methods=['GET'])
    def api_peers():
        sorted_live = get_sorted_live_peers(state)
        peers = [{'id': pid, 'shared_count': 0} for pid, data in sorted_live]
        return jsonify({'peers': peers, 'count': len(peers)})

    @app.route('/add_peer', methods=['POST'])
    def add_peer_route():
        ip_port = flask_request.form.get('ip_port', '').strip()
        if ip_port:
            if ':' in ip_port:
                parts = ip_port.rsplit(':', 1)
                ip = parts[0]
                try: port = int(parts[1])
                except ValueError: port = PORT
            else:
                ip = ip_port
                port = PORT
            add_manual_peer(state, ip, port)
        return redirect('/')

    @app.route('/api/global-config', methods=['GET'])
    def get_global_config_route():
        return jsonify(load_global_config())

    @app.route('/api/global-config', methods=['POST'])
    def set_global_config_route():
        data = flask_request.get_json(force=True)
        cfg = load_global_config()
        cfg.update({'enabled': bool(data.get('enabled', cfg.get('enabled'))), 'relay_url': data.get('relay_url', cfg.get('relay_url', '')).strip(), 'network_code': data.get('network_code', cfg.get('network_code', '')).strip(), 'auto_connect': bool(data.get('auto_connect', cfg.get('auto_connect', True)))})
        save_global_config(cfg)
        old_svc = getattr(state, '_global_discovery', None)
        if old_svc: old_svc.stop()
        new_svc = GlobalDiscoveryService(my_peer_id=str(state.my_id), my_call_number=state.call_number, local_ip=state.local_ip, local_port=PORT, on_peers_updated=getattr(old_svc, 'on_peers_updated', None) if old_svc else None)
        state._global_discovery = new_svc
        new_svc.start()
        return jsonify({'status': 'ok', 'enabled': new_svc.enabled})

    @app.route('/api/global-reconnect', methods=['POST'])
    def global_reconnect():
        old_svc = getattr(state, '_global_discovery', None)
        if not old_svc: return jsonify({'status': 'error', 'message': 'No global discovery service'})
        old_svc.stop()
        new_svc = GlobalDiscoveryService(my_peer_id=str(state.my_id), my_call_number=state.call_number, local_ip=state.local_ip, local_port=PORT, on_peers_updated=getattr(old_svc, 'on_peers_updated', None))
        state._global_discovery = new_svc
        new_svc.start()
        return jsonify({'status': 'ok', 'enabled': new_svc.enabled})

    @app.route('/api/global-status')
    def get_global_status():
        svc = getattr(state, '_global_discovery', None)
        if not svc: return jsonify({'status': 'N/A', 'peers': []})
        return jsonify({'status': svc.get_status(), 'peers': svc.global_peers, 'enabled': svc.enabled, 'network_code': svc.network_code, 'relay_url': svc.relay_url})

    @app.route('/')
    def homepage():
        failover_chain = get_current_failover_chain(state)
        sorted_live = get_sorted_live_peers(state)
        live_count = len(sorted_live)
        failover_dicts = [{'role': node.role, 'id': str(node.peer_id)} for node in failover_chain]
        global_cn = getattr(state, '_global_call_numbers', {})
        peers_list = [{'id': pid, 'call_number': state.call_number if pid == str(state.my_id) else global_cn.get(pid, 'N/A')} for pid, data in sorted_live]
        about_text = load_about_text()
        return render_homepage(random_id=str(state.my_id), failover_chain=failover_dicts, peers_list=peers_list, live_count=live_count, about_text=about_text, call_number=state.call_number)

    @app.route('/explorer', defaults={'req_path': ''}, strict_slashes=False)
    @app.route('/explorer/<path:req_path>', strict_slashes=False)
    def explorer(req_path):
        full_path = SHARED_DIR / req_path if req_path else SHARED_DIR
        if not is_path_safe(req_path, SHARED_DIR): abort(403)
        if full_path.is_file():
            if flask_request.args.get('download') == '1': return send_from_directory(SHARED_DIR, req_path, as_attachment=True)
            return send_from_directory(SHARED_DIR, req_path)
        if full_path.is_dir() and flask_request.args.get('download') == '1':
            import zipfile
            from flask import send_file
            zip_buf = _io.BytesIO()
            folder_name = full_path.name or 'shared'
            with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for fp in full_path.rglob('*'):
                    if fp.is_file():
                        zf.write(fp, str(fp.relative_to(full_path)))
            zip_buf.seek(0)
            return send_file(zip_buf, mimetype='application/zip', as_attachment=True, download_name=f'{folder_name}.zip')
        if not full_path.is_dir(): abort(404)
        entries = list_explorer_directory(state, req_path)
        entries_dicts = [{'name': e.name, 'path': e.path, 'size': e.size, 'is_dir': e.is_dir, 'shared': e.shared, 'tags': e.tags} for e in entries]
        return render_explorer(entries_dicts, req_path)

    @app.route('/save_selection', methods=['POST'])
    def save_selection():
        current_path = flask_request.form.get('current_path', '').strip()
        selected = flask_request.form.getlist('path') or []
        tags_map = {}
        for p in selected:
            tag_val = flask_request.form.get(f'tags_{p}', '').strip()
            tags_map[p] = tag_val
        try:
            update_selection(state, current_path, selected, tags_map=tags_map)
            try:
                requests.post('http://localhost:3000/api/share-update', json={'peerId': str(state.my_id)}, timeout=1)
            except Exception: pass
            redirect_to = f'/explorer/{current_path}' if current_path else '/explorer'
            return redirect(redirect_to)
        except Exception as e:
            print("\n" + "="*80)
            print("ERROR in save_selection:")
            traceback.print_exc()
            print("="*80 + "\n")
            redirect_to = f'/explorer/{current_path}' if current_path else '/explorer'
            return redirect(redirect_to)

    @app.route('/preview', defaults={'req_path': ''}, strict_slashes=False)
    @app.route('/preview/<path:req_path>', strict_slashes=False)
    def preview(req_path):
        full_path = SHARED_DIR / req_path if req_path else SHARED_DIR
        if not is_path_safe(req_path, SHARED_DIR): abort(403)
        if full_path.is_file():
            if flask_request.args.get('download') == '1': return send_from_directory(SHARED_DIR, req_path, as_attachment=True)
            return send_from_directory(SHARED_DIR, req_path)
        if full_path.is_dir() and flask_request.args.get('download') == '1':
            import zipfile
            from flask import send_file
            zip_buf = _io.BytesIO()
            folder_name = full_path.name or 'shared'
            with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for fp in full_path.rglob('*'):
                    if fp.is_file():
                        zf.write(fp, str(fp.relative_to(full_path)))
            zip_buf.seek(0)
            return send_file(zip_buf, mimetype='application/zip', as_attachment=True, download_name=f'{folder_name}.zip')
        if not full_path.is_dir(): abort(404)
        all_entries = list_directory_entries(full_path, SHARED_DIR, state.shared_paths)
        visible_entries = [e for e in all_entries if is_path_shared(e.path, state.shared_paths)]
        entries_dicts = [{'name': e.name, 'path': e.path, 'size': e.size, 'is_dir': e.is_dir} for e in visible_entries]
        return render_preview(entries_dicts, req_path)

    # ========== VAULT ROUTES ==========
    _vault_instance = [None]
    _vault_errors = [[]]

    def _get_vault(password=None, secret_file_data=None):
        if _vault_instance[0] and _vault_instance[0].is_unlocked: return _vault_instance[0]
        if password:
            vault_path = get_default_vault_path()
            v = SecureVault(str(vault_path), password=password, secret_file_data=secret_file_data)
            _vault_instance[0] = v
            if not v.is_unlocked and v.last_validation_errors: _vault_errors[0] = v.last_validation_errors
            else: _vault_errors[0] = []
            return v
        return None

    def _vault_needs_secret_file():
        meta_path = get_default_vault_path() / VAULT_META_FILE
        if meta_path.exists():
            try:
                with open(meta_path, 'r') as f: meta = json.load(f)
                return meta.get('requires_secret_file', False)
            except Exception: pass
        return False

    @app.route('/vault', methods=['GET'])
    def vault_page():
        vault = _get_vault()
        unlocked = vault is not None and vault.is_unlocked
        files = vault.list_files() if unlocked else []
        needs_secret = _vault_needs_secret_file()
        errors = _vault_errors[0]
        files_html = ""
        for f in files:
            size_str = f"{f['size']:,} bytes"
            if f['size'] > 1048576: size_str = f"{f['size']/1048576:.1f} MB"
            elif f['size'] > 1024: size_str = f"{f['size']/1024:.1f} KB"
            loc = "Downloads" if f['is_download'] else "Vault"
            files_html += (f'<tr><td>{f["name"]}</td><td>{size_str}</td><td>{loc}</td><td><form method="post" action="/vault/open" style="display:inline"><input type="hidden" name="filename" value="{f["name"]}"><button class="btn btn-sm btn-outline-light me-1" type="submit">Open</button></form><form method="post" action="/vault/remove" style="display:inline"><input type="hidden" name="filename" value="{f["name"]}"><button class="btn btn-sm btn-outline-danger" type="submit">Remove</button></form></td></tr>')
        error_html = ""
        if errors:
            items = "".join(f"<li>{e}</li>" for e in errors)
            error_html = f'<div class="alert alert-danger"><strong>Error:</strong><ul class="mb-0">{items}</ul></div>'
        secret_file_field = ""
        if needs_secret:
            secret_file_field = '<label class="form-label small text-warning mt-2">Secret file required:</label><input type="file" name="secret_file" class="form-control bg-dark text-white border-secondary mb-3" required>'
        if not unlocked:
            req_html = format_password_requirements_html()
            strength_js = password_strength_js()
            body = f'''
            <div class="card">
                <div class="card-header">Unlock Vault</div>
                <div class="card-body">
                    {error_html}
                    <form method="post" action="/vault/unlock" enctype="multipart/form-data">
                        <input type="password" id="vaultPw" name="password" class="form-control mb-1 bg-dark text-white border-secondary" placeholder="Vault password" required>
                        <div id="pwStrength" class="mb-3 small"></div>
                        {secret_file_field}
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" name="setup_secret_file" id="setupSecretFile" value="1">
                            <label class="form-check-label small text-muted" for="setupSecretFile">Set up a secret file (optional, in addition to password)</label>
                        </div>
                        <div id="newSecretFileDiv" style="display:none" class="mb-3">
                            <label class="form-label small">Choose your secret file:</label>
                            <input type="file" name="new_secret_file" class="form-control bg-dark text-white border-secondary">
                            <small class="text-muted">This exact file will be required every time you unlock the vault.</small>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Unlock / Create Vault</button>
                    </form>
                    {req_html}
                    <p class="text-muted small mt-2">The vault is optional. It is never the default save location.</p>
                </div>
            </div>
            {strength_js}
            <script>
            checkPasswordStrength('vaultPw', 'pwStrength');
            document.getElementById('setupSecretFile').addEventListener('change', function() {{
                document.getElementById('newSecretFileDiv').style.display = this.checked ? 'block' : 'none';
            }});
            </script>'''
        else:
            body = f'''
            <div class="card mb-4">
                <div class="card-header">Vault — Encrypted Storage (Optional)</div>
                <div class="card-body">
                    <p class="text-success">Vault is unlocked</p>
                    <form method="post" action="/vault/add" enctype="multipart/form-data" class="mb-3">
                        <div class="input-group">
                            <input type="file" name="file" class="form-control bg-dark text-white border-secondary" required>
                            <select name="location" class="form-select bg-dark text-white border-secondary" style="max-width:150px">
                                <option value="vault">Vault</option>
                                <option value="downloads">Downloads</option>
                            </select>
                            <button type="submit" class="btn btn-primary">Add File</button>
                        </div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>Name</th><th>Size</th><th>Location</th><th>Actions</th></tr></thead>
                            <tbody>{files_html or '<tr><td colspan="4" class="text-muted">No files in vault</td></tr>'}</tbody>
                        </table>
                    </div>
                    <form method="post" action="/vault/lock" class="mt-3">
                        <button type="submit" class="btn btn-outline-warning w-100">Lock Vault</button>
                    </form>
                </div>
            </div>'''
        return f'''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Vault — Global Network Archive</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .card {{ background: #161b22; border: 1px solid #30363d; }} .card-header {{ background: #21262d; border-bottom: 1px solid #30363d; color: #58a6ff; }} a {{ color: #58a6ff; }}</style>
</head>
<body class="p-5">
<div class="container">
    <h1 class="mb-4">Encrypted Vault</h1>
    <a href="/" class="btn btn-outline-light mb-4">&larr; Dashboard</a>
    {body}
</div>
</body></html>'''

    @app.route('/vault/unlock', methods=['POST'])
    def vault_unlock():
        password = flask_request.form.get('password', '')
        if not password: return redirect('/vault')
        secret_data = None
        sf = flask_request.files.get('secret_file')
        if sf and sf.filename: secret_data = sf.read()
        nsf = flask_request.files.get('new_secret_file')
        if nsf and nsf.filename and flask_request.form.get('setup_secret_file') == '1': secret_data = nsf.read()
        _get_vault(password, secret_data)
        return redirect('/vault')

    @app.route('/vault/lock', methods=['POST'])
    def vault_lock():
        _vault_instance[0] = None
        _vault_errors[0] = []
        return redirect('/vault')

    @app.route('/vault/add', methods=['POST'])
    def vault_add():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        file = flask_request.files.get('file')
        if not file: return redirect('/vault')
        location = flask_request.form.get('location', 'vault')
        is_download = location == 'downloads'
        data = file.read()
        vault.add_file(file.filename, data, is_download=is_download)
        return redirect('/vault')

    @app.route('/vault/open', methods=['POST'])
    def vault_open():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        filename = flask_request.form.get('filename', '')
        if filename: vault.open_file(filename)
        return redirect('/vault')

    @app.route('/vault/remove', methods=['POST'])
    def vault_remove():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        filename = flask_request.form.get('filename', '')
        if filename: vault.remove_file(filename)
        return redirect('/vault')

    @app.route('/api/web-search')
    def web_search():
        query = flask_request.args.get('q', '').strip()
        if not query: return jsonify({'error': 'No query provided', 'results': []})
        if len(query) > 500: return jsonify({'error': 'Query too long', 'results': []})
        results = []
        engine = 'DuckDuckGo'
        try:
            from bs4 import BeautifulSoup
            resp = requests.post('https://lite.duckduckgo.com/lite/', data={'q': query}, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link_tag in soup.find_all('a', class_='result-link'):
                title = link_tag.get_text(strip=True)
                url = link_tag.get('href', '')
                snippet_tag = link_tag.find_parent('tr')
                snippet = ''
                if snippet_tag:
                    next_tr = snippet_tag.find_next_sibling('tr')
                    if next_tr:
                        snippet_td = next_tr.find('td', class_='result-snippet')
                        if snippet_td: snippet = snippet_td.get_text(strip=True)
                if url and title: results.append({'title': title, 'url': url, 'snippet': snippet})
                if len(results) >= 20: break
        except ImportError:
            try:
                resp = requests.post('https://lite.duckduckgo.com/lite/', data={'q': query}, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10)
                resp.raise_for_status()
                html = resp.text
                link_pattern = re.compile(r'<a[^>]+class="result-link"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', re.IGNORECASE)
                snippet_pattern = re.compile(r'<td[^>]+class="result-snippet"[^>]*>(.*?)</td>', re.IGNORECASE | re.DOTALL)
                links = link_pattern.findall(html)
                snippets = snippet_pattern.findall(html)
                for i, (url, title) in enumerate(links):
                    snippet = ''
                    if i < len(snippets): snippet = re.sub(r'<[^>]+>', '', snippets[i]).strip()
                    results.append({'title': title.strip(), 'url': url.strip(), 'snippet': snippet})
                    if len(results) >= 20: break
            except Exception: pass
        except Exception as e:
            return jsonify({'error': f'Search failed: {str(e)}', 'results': []})
        return jsonify({'results': results, 'engine': engine, 'query': query})

    @app.route('/launch_call/<peer_id>', methods=['POST'])
    def launch_call(peer_id):
        try:
            base_path = PROJECT_DIR
            caller_path = base_path / 'caller.py'
            if not caller_path.exists(): return jsonify({'success': False, 'error': 'caller.py not found'})
            my_id = str(state.my_id)
            my_call_num = state.call_number
            subprocess.Popen([sys.executable, str(caller_path), my_id, my_call_num, peer_id], creationflags=0)
            return jsonify({'success': True, 'peer_id': peer_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/launch_screen_viewer/<peer_id>', methods=['POST'])
    def launch_screen_viewer(peer_id):
        try:
            base_path = PROJECT_DIR
            receiver_path = base_path / 'receiver.py'
            sender_path = base_path / 'sender.py'
            if not receiver_path.exists(): return jsonify({'success': False, 'error': 'receiver.py not found'})
            my_id = str(state.my_id)
            if peer_id == my_id:
                if not sender_path.exists(): return jsonify({'success': False, 'error': 'sender.py not found'})
                session_id_file = base_path / 'sender_session_id.txt'
                with open(session_id_file, 'w') as f: f.write(my_id)
                subprocess.Popen([sys.executable, str(sender_path)], creationflags=0)
                time.sleep(2)
            subprocess.Popen([sys.executable, str(receiver_path), peer_id], creationflags=0)
            return jsonify({'success': True, 'peer_id': peer_id, 'sender_started': peer_id == my_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/upload_to_peer/<peer_id>', methods=['POST'])
    def upload_to_peer(peer_id):
        try:
            file = flask_request.files.get('file')
            if not file or not file.filename:
                return jsonify({'success': False, 'error': 'No file selected'})
            dest_path = flask_request.form.get('dest_path', 'Desktop/').strip()
            file_data = file.read()
            if len(file_data) > 100 * 1024 * 1024:
                return jsonify({'success': False, 'error': 'File too large (max 100 MB)'})
            # If uploading to self, add directly to pending
            if peer_id == str(state.my_id):
                upload_id = add_pending_upload(
                    sender_id=str(state.my_id),
                    sender_ip=state.local_ip,
                    filename=file.filename,
                    dest_path=dest_path,
                    file_data=file_data
                )
                return jsonify({'success': True, 'upload_id': upload_id, 'message': 'Upload queued locally'})
            # Find peer and forward
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            try:
                resp = requests.post(
                    f"http://{peer_info.ip}:{peer_info.port}/api/incoming-upload",
                    files={'file': (file.filename, _io.BytesIO(file_data), 'application/octet-stream')},
                    data={'sender_id': str(state.my_id), 'sender_ip': state.local_ip, 'dest_path': dest_path},
                    timeout=30
                )
                resp.raise_for_status()
                result = resp.json()
                return jsonify({'success': result.get('success', False), 'upload_id': result.get('upload_id', ''),
                                'message': result.get('message', 'Sent to peer')})
            except requests.exceptions.ConnectionError:
                return jsonify({'success': False, 'error': f'Could not connect to {peer_id} — peer unreachable'})
            except requests.exceptions.Timeout:
                return jsonify({'success': False, 'error': 'Upload timed out'})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Transfer failed: {str(e)}'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/incoming-upload', methods=['POST'])
    def incoming_upload():
        try:
            file = flask_request.files.get('file')
            if not file or not file.filename:
                return jsonify({'success': False, 'error': 'No file in request'})
            sender_id = flask_request.form.get('sender_id', 'unknown')
            sender_ip = flask_request.form.get('sender_ip', flask_request.remote_addr or 'unknown')
            dest_path = flask_request.form.get('dest_path', 'Desktop/')
            file_data = file.read()
            upload_id = add_pending_upload(
                sender_id=sender_id,
                sender_ip=sender_ip,
                filename=file.filename,
                dest_path=dest_path,
                file_data=file_data
            )
            print(f"[UPLOAD] Incoming file '{file.filename}' from {sender_id} — awaiting approval (id: {upload_id})")
            return jsonify({'success': True, 'upload_id': upload_id, 'message': 'Upload pending approval'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/pending-uploads', methods=['GET'])
    def pending_uploads_route():
        cleanup_old_uploads()
        return jsonify({'uploads': get_pending_uploads()})

    @app.route('/api/accept-upload/<upload_id>', methods=['POST'])
    def accept_upload_route(upload_id):
        try:
            upload = accept_upload(upload_id)
            if not upload:
                return jsonify({'success': False, 'error': 'Upload not found or already handled'})
            dest_path = upload.get('dest_path', 'Desktop/')
            filename = upload.get('filename', 'unnamed_file')
            file_data = upload.get('file_data', b'')
            # Resolve destination: relative to user's home directory
            home = Path.home()
            target_dir = home / dest_path.rstrip('/')
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / filename
            # Avoid overwriting — add suffix if file exists
            if target_file.exists():
                stem = target_file.stem
                suffix = target_file.suffix
                counter = 1
                while target_file.exists():
                    target_file = target_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
            with open(target_file, 'wb') as f:
                f.write(file_data)
            saved_to = str(target_file.relative_to(home))
            print(f"[UPLOAD] Accepted '{filename}' from {upload.get('sender_id')} — saved to ~/{saved_to}")
            return jsonify({'success': True, 'saved_to': saved_to, 'filename': filename})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/reject-upload/<upload_id>', methods=['POST'])
    def reject_upload_route(upload_id):
        try:
            result = reject_upload(upload_id)
            if result:
                print(f"[UPLOAD] Rejected upload {upload_id}")
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Upload not found or already handled'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/ping/<peer_id>', methods=['POST'])
    def ping_peer(peer_id):
        try:
            if peer_id == str(state.my_id):
                return jsonify({'success': True, 'latency_ms': 0, 'status': 'self'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            start = time.time()
            try:
                resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/info", timeout=5)
                latency = round((time.time() - start) * 1000)
                if resp.status_code == 200:
                    return jsonify({'success': True, 'latency_ms': latency, 'status': 'reachable',
                                    'peer_version': resp.json().get('version', '?')})
                return jsonify({'success': True, 'latency_ms': latency, 'status': f'http_{resp.status_code}'})
            except requests.exceptions.ConnectionError:
                return jsonify({'success': False, 'error': 'Unreachable', 'latency_ms': -1})
            except requests.exceptions.Timeout:
                return jsonify({'success': False, 'error': 'Timeout (>5s)', 'latency_ms': -1})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/request-file-list/<peer_id>')
    def request_file_list(peer_id):
        try:
            if peer_id == str(state.my_id):
                items = get_shared_items_list(state)
                return jsonify({'items': [{'path': i.path, 'name': i.name, 'size': i.size_str,
                                           'is_folder': i.is_folder} for i in items]})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'error': f'Peer {peer_id} not found', 'items': []})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/shared_list", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return jsonify({'items': data.get('items', [])})
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Peer unreachable', 'items': []})
        except Exception as e:
            return jsonify({'error': str(e), 'items': []})

    @app.route('/api/request-file-download/<peer_id>/<path:file_path>', methods=['POST'])
    def request_file_download(peer_id, file_path):
        try:
            home = Path.home()
            downloads_dir = home / 'Desktop' / 'GNA_Downloads'
            downloads_dir.mkdir(parents=True, exist_ok=True)
            if peer_id == str(state.my_id):
                # Local file or folder — copy from shared dir
                source = SHARED_DIR / file_path
                if not source.exists():
                    return jsonify({'success': False, 'error': 'Path not found locally'})
                if source.is_dir():
                    import zipfile
                    folder_name = source.name or 'folder'
                    dest = downloads_dir / f"{folder_name}.zip"
                    if dest.exists():
                        c = 1
                        while dest.exists():
                            dest = downloads_dir / f"{folder_name}_{c}.zip"
                            c += 1
                    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for fp in source.rglob('*'):
                            if fp.is_file():
                                zf.write(fp, str(fp.relative_to(source)))
                    return jsonify({'success': True, 'saved_to': str(dest.relative_to(home))})
                dest = downloads_dir / source.name
                if dest.exists():
                    stem, suffix = dest.stem, dest.suffix
                    c = 1
                    while dest.exists():
                        dest = downloads_dir / f"{stem}_{c}{suffix}"
                        c += 1
                shutil.copy2(str(source), str(dest))
                return jsonify({'success': True, 'saved_to': str(dest.relative_to(home))})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            dl_url = f"http://{peer_info.ip}:{peer_info.port}/preview/{file_path}?download=1"
            resp = requests.get(dl_url, timeout=60, stream=True)
            if resp.status_code != 200:
                return jsonify({'success': False, 'error': f'Remote returned {resp.status_code}'})
            content = resp.content
            file_name = Path(file_path).name
            # Detect zip response (folder download)
            ct = resp.headers.get('Content-Type', '')
            if 'zip' in ct and not file_name.endswith('.zip'):
                file_name = file_name + '.zip'
            dest = downloads_dir / file_name
            if dest.exists():
                stem, suffix = dest.stem, dest.suffix
                c = 1
                while dest.exists():
                    dest = downloads_dir / f"{stem}_{c}{suffix}"
                    c += 1
            with open(dest, 'wb') as f:
                f.write(resp.content)
            saved_to = str(dest.relative_to(home))
            print(f"[REQUEST] Downloaded '{file_name}' from {peer_id} — saved to ~/{saved_to}")
            return jsonify({'success': True, 'saved_to': saved_to, 'filename': file_name})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sync-folder', methods=['POST'])
    def sync_folder_route():
        try:
            data = flask_request.get_json(force=True)
            peer_id = data.get('peer_id', '')
            local_path = data.get('local_path', 'Desktop/synced/').strip()
            remote_path = data.get('remote_path', '').strip()
            if not peer_id:
                return jsonify({'success': False, 'error': 'No peer specified'})
            if not local_path:
                return jsonify({'success': False, 'error': 'No local path specified'})
            # Find peer info
            if peer_id == str(state.my_id):
                peer_ip = '127.0.0.1'
                peer_port = PORT
            else:
                peer_info = state.known_peers.get(peer_id)
                if not peer_info:
                    return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
                peer_ip = peer_info.ip
                peer_port = peer_info.port
            # Do an initial sync right now
            sync_id = add_active_sync(peer_id, local_path, remote_path, peer_ip, peer_port)
            # Run initial sync inline
            try:
                resp = requests.get(f"http://{peer_ip}:{peer_port}/shared_list", timeout=10)
                resp.raise_for_status()
                items = resp.json().get('items', [])
                home = Path.home()
                target_dir = home / local_path.rstrip('/')
                target_dir.mkdir(parents=True, exist_ok=True)
                count = 0
                for item in items:
                    if item.get('is_folder', False):
                        continue
                    item_path = item.get('path', '')
                    if remote_path and not item_path.startswith(remote_path):
                        continue
                    try:
                        dl_url = f"http://{peer_ip}:{peer_port}/preview/{item_path}?download=1"
                        dl_resp = requests.get(dl_url, timeout=30)
                        if dl_resp.status_code == 200:
                            file_name = Path(item_path).name
                            dest_file = target_dir / file_name
                            if not dest_file.exists() or dest_file.stat().st_size != len(dl_resp.content):
                                with open(dest_file, 'wb') as f:
                                    f.write(dl_resp.content)
                                count += 1
                    except Exception:
                        pass
                with _active_syncs_lock:
                    s = _active_syncs.get(sync_id)
                    if s:
                        s['files_synced'] = count
                        s['last_sync'] = time.time()
                        s['active'] = False
            except Exception as e:
                print(f"[SYNC] Initial sync failed for {sync_id}: {e}")
            # Start background sync thread
            threading.Thread(target=run_sync_job, args=(sync_id, state), daemon=True,
                             name=f"SyncThread-{sync_id}").start()
            print(f"[SYNC] Started sync {sync_id}: {peer_id} -> ~/{local_path}")
            with _active_syncs_lock:
                files_synced = _active_syncs.get(sync_id, {}).get('files_synced', 0)
            return jsonify({'success': True, 'sync_id': sync_id, 'files_synced': files_synced})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/active-syncs')
    def active_syncs_route():
        return jsonify({'syncs': get_active_syncs()})

    @app.route('/api/stop-sync/<sync_id>', methods=['POST'])
    def stop_sync_route(sync_id):
        result = stop_sync(sync_id)
        if result:
            print(f"[SYNC] Stopped sync {sync_id}")
        return jsonify({'success': result})



    @app.route('/api/remote-exec/<peer_id>', methods=['POST'])
    def remote_exec(peer_id):
        try:
            data = flask_request.get_json(force=True)
            cmd = data.get('command', '').strip()
            if not cmd:
                return jsonify({'error': 'No command provided'})
            if peer_id == str(state.my_id):
                # Permission check: block remote requests if not allowed
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, timeout=30,
                        cwd=str(Path.home())
                    )
                    output = result.stdout
                    if result.stderr:
                        output += result.stderr
                    return jsonify({'output': output or '(no output)', 'exit_code': result.returncode})
                except subprocess.TimeoutExpired:
                    return jsonify({'error': 'Command timed out (30s limit)'})
                except Exception as e:
                    return jsonify({'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/remote-exec/{peer_id}",
                json={'command': cmd}, timeout=35
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'error': str(e)})

    @app.route('/api/clipboard-send/<peer_id>', methods=['POST'])
    def clipboard_send(peer_id):
        try:
            data = flask_request.get_json(force=True)
            text = data.get('text', '')
            if not text:
                return jsonify({'success': False, 'error': 'No text provided'})
            if peer_id == str(state.my_id):
                # Permission check: block remote clipboard writes
                if not is_local_request() and not prompt_remote_permission('clipboard_write', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import tempfile
                    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                    tmp.write(text)
                    tmp.close()
                    tmp_path = tmp.name
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    subprocess.run(
                        ['powershell', '-Command', f'Get-Content -Raw -Path "{tmp_path}" | Set-Clipboard'],
                        capture_output=True, timeout=10, creationflags=cflags
                    )
                    os.unlink(tmp_path)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/clipboard-send/{peer_id}",
                json={'text': text}, timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/clipboard-grab/<peer_id>', methods=['POST'])
    def clipboard_grab(peer_id):
        try:
            if peer_id == str(state.my_id):
                # Permission check: block remote clipboard reads
                if not is_local_request() and not prompt_remote_permission('clipboard_read', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', 'Get-Clipboard'],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    )
                    return jsonify({'success': True, 'text': result.stdout.strip()})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/clipboard-grab/{peer_id}",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/power/<peer_id>/<action>', methods=['POST'])
    def power_control(peer_id, action):
        try:
            valid_actions = {'wake', 'sleep', 'restart', 'shutdown'}
            if action not in valid_actions:
                return jsonify({'success': False, 'error': f'Invalid action: {action}'})
            if action == 'wake':
                # Wake-on-LAN — need the peer's MAC address or IP
                peer_info = state.known_peers.get(peer_id)
                if not peer_info:
                    return jsonify({'success': False, 'error': 'Peer not found'})
                # Try to get MAC from ARP table
                try:
                    arp_result = subprocess.run(
                        ['arp', '-a', peer_info.ip],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    )
                    mac = None
                    for line in arp_result.stdout.splitlines():
                        if peer_info.ip in line:
                            parts = line.split()
                            for p in parts:
                                if len(p) == 17 and (p.count('-') == 5 or p.count(':') == 5):
                                    mac = p.replace('-', ':')
                                    break
                            if mac: break
                    if not mac:
                        return jsonify({'success': False, 'error': f'Could not find MAC address for {peer_info.ip}. Try pinging the peer first.'})
                    # Send WOL magic packet
                    mac_bytes = bytes.fromhex(mac.replace(':', ''))
                    magic = b'\xff' * 6 + mac_bytes * 16
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.sendto(magic, ('255.255.255.255', 9))
                    sock.sendto(magic, ('255.255.255.255', 7))
                    sock.close()
                    return jsonify({'success': True, 'message': f'Wake-on-LAN packet sent to {mac}'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            # For sleep/restart/shutdown — execute on peer
            if peer_id == str(state.my_id):
                # Permission check: block remote power commands
                if not is_local_request() and not prompt_remote_permission('power_control', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                cmds = {
                    'shutdown': 'shutdown /s /t 5 /c "Remote shutdown via GNA"',
                    'restart': 'shutdown /r /t 5 /c "Remote restart via GNA"',
                    'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
                }
                cmd = cmds.get(action)
                try:
                    subprocess.Popen(cmd, shell=True,
                                     creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                    return jsonify({'success': True, 'message': f'{action.title()} command executed locally'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/power/{peer_id}/{action}",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/bandwidth-test/<peer_id>', methods=['POST'])
    def bandwidth_test(peer_id):
        try:
            if peer_id == str(state.my_id):
                # Self-test: benchmark against own Flask via loopback
                base_url = f"http://127.0.0.1:{PORT}"
                lat_start = time.time()
                try:
                    requests.get(f"{base_url}/api/info", timeout=5)
                except Exception:
                    return jsonify({'success': False, 'error': 'Loopback unreachable'})
                latency_ms = round((time.time() - lat_start) * 1000)
                test_size = 2 * 1024 * 1024
                dl_start = time.time()
                try:
                    dl_resp = requests.get(f"{base_url}/api/bw-test-payload?size={test_size}", timeout=30)
                    dl_time = time.time() - dl_start
                    dl_mbps = (len(dl_resp.content) * 8) / (dl_time * 1_000_000) if dl_time > 0 else 0
                except Exception:
                    dl_mbps = 0
                payload = os.urandom(test_size)
                ul_start = time.time()
                try:
                    requests.post(f"{base_url}/api/bw-test-receive", data=payload, timeout=30,
                                  headers={'Content-Type': 'application/octet-stream'})
                    ul_time = time.time() - ul_start
                    ul_mbps = (len(payload) * 8) / (ul_time * 1_000_000) if ul_time > 0 else 0
                except Exception:
                    ul_mbps = 0
                return jsonify({'success': True, 'download_mbps': round(dl_mbps, 2),
                                'upload_mbps': round(ul_mbps, 2), 'latency_ms': latency_ms})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            base_url = f"http://{peer_info.ip}:{peer_info.port}"
            # Latency test
            lat_start = time.time()
            try:
                requests.get(f"{base_url}/api/info", timeout=5)
            except Exception:
                return jsonify({'success': False, 'error': 'Peer unreachable'})
            latency_ms = round((time.time() - lat_start) * 1000)
            # Download test: fetch the test payload from peer
            test_size = 2 * 1024 * 1024  # 2 MB payload
            dl_start = time.time()
            try:
                dl_resp = requests.get(f"{base_url}/api/bw-test-payload?size={test_size}", timeout=30)
                dl_bytes = len(dl_resp.content)
                dl_time = time.time() - dl_start
                dl_mbps = (dl_bytes * 8) / (dl_time * 1_000_000) if dl_time > 0 else 0
            except Exception:
                dl_mbps = 0
                dl_bytes = 0
                dl_time = 0
            # Upload test: send a test payload to peer
            payload = os.urandom(test_size)
            ul_start = time.time()
            try:
                requests.post(f"{base_url}/api/bw-test-receive", data=payload, timeout=30,
                              headers={'Content-Type': 'application/octet-stream'})
                ul_time = time.time() - ul_start
                ul_mbps = (len(payload) * 8) / (ul_time * 1_000_000) if ul_time > 0 else 0
            except Exception:
                ul_mbps = 0
            return jsonify({
                'success': True,
                'download_mbps': round(dl_mbps, 2),
                'upload_mbps': round(ul_mbps, 2),
                'latency_ms': latency_ms,
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/bw-test-payload')
    def bw_test_payload():
        size = min(int(flask_request.args.get('size', 2097152)), 10 * 1024 * 1024)  # Max 10 MB
        data = os.urandom(size)
        return Response(data, mimetype='application/octet-stream')

    @app.route('/api/bw-test-receive', methods=['POST'])
    def bw_test_receive():
        _ = flask_request.get_data()
        return jsonify({'success': True, 'bytes_received': len(_)})

    @app.route('/api/screenshot/<peer_id>', methods=['POST'])
    def screenshot_capture(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('screenshot', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import mss
                    import base64
                    with mss.mss() as sct:
                        monitor = sct.monitors[0]
                        img = sct.grab(monitor)
                        png_bytes = mss.tools.to_png(img.rgb, img.size)
                    encoded = base64.b64encode(png_bytes).decode('ascii')
                    return jsonify({'success': True, 'image': encoded})
                except ImportError:
                    # Fallback: use PowerShell screenshot
                    try:
                        import base64
                        ps_script = (
                            "Add-Type -AssemblyName System.Windows.Forms;"
                            "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                            "$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);"
                            "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                            "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
                            "$ms=New-Object System.IO.MemoryStream;"
                            "$bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png);"
                            "[Convert]::ToBase64String($ms.ToArray())"
                        )
                        result = subprocess.run(
                            ['powershell', '-Command', ps_script],
                            capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return jsonify({'success': True, 'image': result.stdout.strip()})
                        return jsonify({'success': False, 'error': 'Screenshot failed: ' + (result.stderr or 'no output')})
                    except Exception as e:
                        return jsonify({'success': False, 'error': f'Screenshot unavailable: {e}'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/screenshot/{peer_id}",
                timeout=20
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sysinfo/<peer_id>')
    def sysinfo_route(peer_id):
        try:
            if peer_id == str(state.my_id):
                import platform
                info = {
                    'os': f"{platform.system()} {platform.release()} ({platform.version()})",
                    'hostname': platform.node(),
                    'cpu': platform.processor() or 'N/A',
                    'cpu_cores': str(os.cpu_count() or 'N/A'),
                    'architecture': platform.machine(),
                    'python_version': platform.python_version(),
                }
                # RAM info
                try:
                    import psutil
                    vm = psutil.virtual_memory()
                    info['ram_total'] = f"{vm.total / (1024**3):.1f} GB"
                    info['ram_used'] = f"{vm.used / (1024**3):.1f} GB"
                    info['ram_percent'] = str(vm.percent)
                    du = psutil.disk_usage('/')
                    info['disk_total'] = f"{du.total / (1024**3):.1f} GB"
                    info['disk_used'] = f"{du.used / (1024**3):.1f} GB"
                    info['disk_free'] = f"{du.free / (1024**3):.1f} GB"
                    info['disk_percent'] = str(du.percent)
                    boot = psutil.boot_time()
                    uptime_sec = time.time() - boot
                    days = int(uptime_sec // 86400)
                    hours = int((uptime_sec % 86400) // 3600)
                    mins = int((uptime_sec % 3600) // 60)
                    info['uptime'] = f"{days}d {hours}h {mins}m"
                except ImportError:
                    # Fallback without psutil: use WMIC / PowerShell
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    # RAM via WMIC
                    try:
                        ram_r = subprocess.run(['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/value'],
                                               capture_output=True, text=True, timeout=10, creationflags=cflags)
                        vals = {}
                        for line in ram_r.stdout.splitlines():
                            if '=' in line:
                                k, v = line.strip().split('=', 1)
                                vals[k.strip()] = int(v.strip()) if v.strip().isdigit() else 0
                        total_kb = vals.get('TotalVisibleMemorySize', 0)
                        free_kb = vals.get('FreePhysicalMemory', 0)
                        used_kb = total_kb - free_kb
                        info['ram_total'] = f"{total_kb / (1024*1024):.1f} GB"
                        info['ram_used'] = f"{used_kb / (1024*1024):.1f} GB"
                        info['ram_percent'] = str(round(used_kb / total_kb * 100)) if total_kb else '0'
                    except Exception:
                        info['ram_total'] = 'N/A'
                        info['ram_used'] = 'N/A'
                        info['ram_percent'] = '0'
                    # Disk via WMIC
                    try:
                        disk_r = subprocess.run(['wmic', 'logicaldisk', 'where', 'DeviceID="C:"', 'get', 'Size,FreeSpace', '/value'],
                                                capture_output=True, text=True, timeout=10, creationflags=cflags)
                        vals = {}
                        for line in disk_r.stdout.splitlines():
                            if '=' in line:
                                k, v = line.strip().split('=', 1)
                                vals[k.strip()] = int(v.strip()) if v.strip().isdigit() else 0
                        d_total = vals.get('Size', 0)
                        d_free = vals.get('FreeSpace', 0)
                        d_used = d_total - d_free
                        info['disk_total'] = f"{d_total / (1024**3):.1f} GB"
                        info['disk_used'] = f"{d_used / (1024**3):.1f} GB"
                        info['disk_free'] = f"{d_free / (1024**3):.1f} GB"
                        info['disk_percent'] = str(round(d_used / d_total * 100)) if d_total else '0'
                    except Exception:
                        info['disk_total'] = 'N/A'
                        info['disk_used'] = 'N/A'
                        info['disk_free'] = 'N/A'
                        info['disk_percent'] = '0'
                    # Uptime via WMIC
                    try:
                        up_r = subprocess.run(['wmic', 'os', 'get', 'LastBootUpTime', '/value'],
                                              capture_output=True, text=True, timeout=10, creationflags=cflags)
                        for line in up_r.stdout.splitlines():
                            if 'LastBootUpTime=' in line:
                                boot_str = line.split('=', 1)[1].strip().split('.')[0]
                                from datetime import datetime
                                boot_time = datetime.strptime(boot_str, '%Y%m%d%H%M%S')
                                delta = datetime.now() - boot_time
                                days = delta.days
                                hours = delta.seconds // 3600
                                mins = (delta.seconds % 3600) // 60
                                info['uptime'] = f"{days}d {hours}h {mins}m"
                                break
                        else:
                            info['uptime'] = 'N/A'
                    except Exception:
                        info['uptime'] = 'N/A'
                    # GPU via WMIC
                    try:
                        gpu_r = subprocess.run(['wmic', 'path', 'win32_videocontroller', 'get', 'Name', '/value'],
                                               capture_output=True, text=True, timeout=10, creationflags=cflags)
                        gpus = []
                        for line in gpu_r.stdout.splitlines():
                            if 'Name=' in line:
                                gpus.append(line.split('=', 1)[1].strip())
                        info['gpu'] = ', '.join(gpus) if gpus else 'N/A'
                    except Exception:
                        info['gpu'] = 'N/A'
                # IP addresses
                try:
                    ips = []
                    try:
                        import psutil as _pu
                        for iface_name, addrs in _pu.net_if_addrs().items():
                            for addr in addrs:
                                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                                    ips.append(f"{addr.address} ({iface_name})")
                    except ImportError:
                        hostname = socket.gethostname()
                        for ip in socket.getaddrinfo(hostname, None, socket.AF_INET):
                            addr = ip[4][0]
                            if not addr.startswith('127.'):
                                ips.append(addr)
                    info['ip_addresses'] = ips or [socket.gethostbyname(socket.gethostname())]
                except Exception:
                    try:
                        info['ip_addresses'] = [socket.gethostbyname(socket.gethostname())]
                    except Exception:
                        info['ip_addresses'] = ['N/A']
                return jsonify({'success': True, 'info': info})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/sysinfo/{peer_id}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/notify/<peer_id>', methods=['POST'])
    def notify_route(peer_id):
        try:
            data = flask_request.get_json(force=True)
            title = data.get('title', 'GNA Notification')
            message = data.get('message', '')
            if not message:
                return jsonify({'success': False, 'error': 'No message provided'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('notify', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                # Write title+message to temp files to avoid any injection
                import tempfile
                tmp_t = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                tmp_t.write(title); tmp_t.close()
                tmp_m = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                tmp_m.write(message); tmp_m.close()
                try:
                    # Windows Forms MessageBox — do NOT use CREATE_NO_WINDOW or the popup is invisible
                    ps_script = (
                        f'Add-Type -AssemblyName System.Windows.Forms;'
                        f'$t = Get-Content -Raw -Path "{tmp_t.name}";'
                        f'$m = Get-Content -Raw -Path "{tmp_m.name}";'
                        f'[System.Windows.Forms.MessageBox]::Show($m, $t, "OK", "Information") | Out-Null'
                    )
                    subprocess.Popen(
                        ['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script]
                    )
                    # Clean up temp files after a short delay in a thread
                    def _cleanup():
                        time.sleep(60)
                        try: os.unlink(tmp_t.name)
                        except: pass
                        try: os.unlink(tmp_m.name)
                        except: pass
                    threading.Thread(target=_cleanup, daemon=True).start()
                    return jsonify({'success': True})
                except Exception as e:
                    try: os.unlink(tmp_t.name)
                    except: pass
                    try: os.unlink(tmp_m.name)
                    except: pass
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/notify/{peer_id}",
                json={'title': title, 'message': message}, timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/processes/<peer_id>')
    def list_processes(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('process_manager', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import psutil
                    procs = []
                    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                        try:
                            info = p.info
                            mem = info.get('memory_info')
                            mem_str = f"{mem.rss / (1024*1024):.1f} MB" if mem else '—'
                            procs.append({
                                'pid': info['pid'],
                                'name': info.get('name', '?'),
                                'cpu': str(info.get('cpu_percent', 0)),
                                'memory': mem_str,
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    procs.sort(key=lambda x: x['name'].lower())
                    return jsonify({'success': True, 'processes': procs})
                except ImportError:
                    # Fallback without psutil: use tasklist
                    try:
                        result = subprocess.run(
                            ['tasklist', '/FO', 'CSV', '/NH'],
                            capture_output=True, text=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        procs = []
                        for line in result.stdout.strip().splitlines():
                            parts = [p.strip('"') for p in line.split('","')]
                            if len(parts) >= 5:
                                procs.append({
                                    'pid': parts[1],
                                    'name': parts[0],
                                    'cpu': '—',
                                    'memory': parts[4],
                                })
                        procs.sort(key=lambda x: x['name'].lower())
                        return jsonify({'success': True, 'processes': procs})
                    except Exception as e:
                        return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/processes/{peer_id}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/kill-process/<peer_id>/<int:pid>', methods=['POST'])
    def kill_process(peer_id, pid):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('process_manager', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=5)
                    return jsonify({'success': True, 'message': f'Process {pid} terminated'})
                except ImportError:
                    # Fallback: taskkill
                    try:
                        result = subprocess.run(
                            ['taskkill', '/PID', str(pid), '/F'],
                            capture_output=True, text=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        if result.returncode == 0:
                            return jsonify({'success': True, 'message': f'Process {pid} killed'})
                        return jsonify({'success': False, 'error': result.stderr or result.stdout or 'Failed'})
                    except Exception as e:
                        return jsonify({'success': False, 'error': str(e)})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/kill-process/{peer_id}/{pid}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/start', methods=['POST'])
    def audio_stream_start(peer_id):
        global _audio_stream_active, _audio_stream_chunks, _audio_stream_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_audio', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _audio_stream_lock:
                    if _audio_stream_active:
                        return jsonify({'success': True, 'message': 'Already streaming'})
                    _audio_stream_active = True
                    _audio_stream_chunks.clear()
                def _audio_thread():
                    global _audio_stream_active
                    import wave, struct
                    sample_rate = 16000
                    channels = 1
                    chunk_seconds = 2
                    chunk_samples = sample_rate * chunk_seconds
                    # Find a working audio capture method
                    use_sd = False
                    sd_device = None
                    try:
                        import sounddevice as sd
                        # Try default input device first
                        default_in = sd.default.device[0]
                        candidates = []
                        if default_in is not None and default_in >= 0:
                            candidates.append(default_in)
                        # Then add all other input-capable devices
                        devices = sd.query_devices()
                        for i, d in enumerate(devices):
                            if d.get('max_input_channels', 0) > 0 and i not in candidates:
                                candidates.append(i)
                        # Test each candidate with a tiny recording
                        for dev_id in candidates:
                            try:
                                test = sd.rec(1600, samplerate=16000, channels=1, dtype='int16', device=dev_id)
                                sd.wait()
                                sd_device = dev_id
                                print(f"[AUDIO] Using device {dev_id}: {devices[dev_id]['name']}")
                                break
                            except Exception:
                                continue
                        if sd_device is not None:
                            use_sd = True
                    except ImportError:
                        pass
                    except Exception:
                        pass
                    if use_sd:
                        import sounddevice as sd
                        while _audio_stream_active:
                            try:
                                recording = sd.rec(chunk_samples, samplerate=sample_rate,
                                                   channels=channels, dtype='int16', device=sd_device)
                                sd.wait()
                                samples = recording.flatten()
                                wav_buf = _io.BytesIO()
                                with wave.open(wav_buf, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(samples.tobytes())
                                wav_buf.seek(0)
                                b64 = base64.b64encode(wav_buf.read()).decode('ascii')
                                with _audio_stream_lock:
                                    _audio_stream_chunks.append(b64)
                                    if len(_audio_stream_chunks) > 20:
                                        _audio_stream_chunks.pop(0)
                            except Exception as e:
                                print(f"[AUDIO] sounddevice error: {e}")
                                time.sleep(1)
                    else:
                        # Fallback: PowerShell to record via Windows audio APIs
                        cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        while _audio_stream_active:
                            try:
                                import tempfile
                                tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                                tmp.close()
                                ps = (
                                    f'Add-Type -AssemblyName System.Speech;'
                                    f'$r = New-Object System.Speech.Recognition.SpeechRecognitionEngine;'
                                    f'$r.SetInputToDefaultAudioDevice();'
                                    f'# Fallback: use ffmpeg or cmdlet'
                                    f'powershell -Command "'
                                    f'Add-Type -TypeDefinition @\\\"'
                                    f'using System;using System.Runtime.InteropServices;'
                                    f'public class WinMM{{'
                                    f'[DllImport(\\\"winmm.dll\\\")] public static extern int mciSendString(string c,System.Text.StringBuilder r,int l,IntPtr h);'
                                    f'}}'
                                    f'\\\"@;'
                                    f'[WinMM]::mciSendString(\\\"open new Type waveaudio Alias cap\\\",\\$null,0,0);'
                                    f'[WinMM]::mciSendString(\\\"record cap\\\",\\$null,0,0);'
                                    f'Start-Sleep -Seconds {chunk_seconds};'
                                    f'[WinMM]::mciSendString(\\\"save cap {tmp.name}\\\",\\$null,0,0);'
                                    f'[WinMM]::mciSendString(\\\"close cap\\\",\\$null,0,0);'
                                    f'"'
                                )
                                # Simpler approach: use ffmpeg if available
                                try:
                                    subprocess.run(
                                        ['ffmpeg', '-y', '-f', 'dshow', '-i', 'audio=default',
                                         '-t', str(chunk_seconds), '-ar', str(sample_rate),
                                         '-ac', '1', '-acodec', 'pcm_s16le', tmp.name],
                                        capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                    )
                                except FileNotFoundError:
                                    # No ffmpeg, try SoX
                                    try:
                                        subprocess.run(
                                            ['sox', '-d', '-r', str(sample_rate), '-c', '1', '-b', '16', tmp.name,
                                             'trim', '0', str(chunk_seconds)],
                                            capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                        )
                                    except FileNotFoundError:
                                        os.unlink(tmp.name)
                                        with _audio_stream_lock:
                                            _audio_stream_active = False
                                        return
                                if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 44:
                                    with open(tmp.name, 'rb') as f:
                                        b64 = base64.b64encode(f.read()).decode('ascii')
                                    with _audio_stream_lock:
                                        _audio_stream_chunks.append(b64)
                                        if len(_audio_stream_chunks) > 20:
                                            _audio_stream_chunks.pop(0)
                                os.unlink(tmp.name)
                            except Exception as e:
                                print(f"[AUDIO] fallback error: {e}")
                                time.sleep(1)
                _audio_stream_thread = threading.Thread(target=_audio_thread, daemon=True)
                _audio_stream_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/stop', methods=['POST'])
    def audio_stream_stop(peer_id):
        global _audio_stream_active
        try:
            if peer_id == str(state.my_id):
                with _audio_stream_lock:
                    _audio_stream_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/chunk')
    def audio_stream_chunk(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_audio', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _audio_stream_lock:
                    if _audio_stream_chunks:
                        chunk = _audio_stream_chunks.pop(0)
                        return jsonify({'success': True, 'audio': chunk, 'remaining': len(_audio_stream_chunks)})
                    return jsonify({'success': True, 'audio': None, 'remaining': 0})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/chunk",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/start', methods=['POST'])
    def sys_audio_stream_start(peer_id):
        global _sys_audio_active, _sys_audio_chunks, _sys_audio_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('system_audio', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _sys_audio_lock:
                    if _sys_audio_active:
                        return jsonify({'success': True, 'message': 'Already streaming'})
                    _sys_audio_active = True
                    _sys_audio_chunks.clear()
                def _sys_audio_thread_fn():
                    global _sys_audio_active
                    import wave
                    sample_rate = 44100
                    channels = 2
                    chunk_seconds = 2
                    # Method 1: sounddevice WASAPI loopback
                    use_sd = False
                    sd_device = None
                    try:
                        import sounddevice as sd
                        devices = sd.query_devices()
                        # Find a WASAPI output device to use as loopback
                        for i, d in enumerate(devices):
                            name = d.get('name', '').lower()
                            hostapi = sd.query_hostapis(d['hostapi'])['name'] if 'hostapi' in d else ''
                            if 'wasapi' in hostapi.lower() and d.get('max_output_channels', 0) > 0:
                                # Test if loopback works on this device
                                try:
                                    test_frames = int(sample_rate * 0.1)
                                    test = sd.rec(test_frames, samplerate=sample_rate, channels=channels,
                                                  dtype='int16', device=i,
                                                  extra_settings=sd.WasapiSettings(exclusive=False))
                                    sd.wait()
                                    sd_device = i
                                    print(f"[SYS-AUDIO] Using WASAPI loopback device {i}: {d['name']}")
                                    break
                                except Exception:
                                    continue
                        # If no WASAPI loopback, try default output as loopback
                        if sd_device is None:
                            default_out = sd.default.device[1]
                            if default_out is not None and default_out >= 0:
                                try:
                                    test = sd.rec(int(sample_rate * 0.1), samplerate=sample_rate,
                                                  channels=channels, dtype='int16', device=default_out)
                                    sd.wait()
                                    sd_device = default_out
                                    print(f"[SYS-AUDIO] Using default output device {default_out} as loopback")
                                except Exception:
                                    pass
                        if sd_device is not None:
                            use_sd = True
                    except ImportError:
                        pass
                    except Exception:
                        pass
                    if use_sd:
                        import sounddevice as sd
                        chunk_samples = sample_rate * chunk_seconds
                        while _sys_audio_active:
                            try:
                                recording = sd.rec(chunk_samples, samplerate=sample_rate,
                                                   channels=channels, dtype='int16', device=sd_device)
                                sd.wait()
                                samples = recording.flatten()
                                wav_buf = _io.BytesIO()
                                with wave.open(wav_buf, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(samples.tobytes())
                                wav_buf.seek(0)
                                b64 = base64.b64encode(wav_buf.read()).decode('ascii')
                                with _sys_audio_lock:
                                    _sys_audio_chunks.append(b64)
                                    if len(_sys_audio_chunks) > 20:
                                        _sys_audio_chunks.pop(0)
                            except Exception as e:
                                print(f"[SYS-AUDIO] error: {e}")
                                time.sleep(1)
                    else:
                        # Fallback: use ffmpeg to capture system audio via dshow
                        cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        while _sys_audio_active:
                            try:
                                tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                                tmp.close()
                                # Try ffmpeg with virtual-audio-capturer or stereo mix
                                try:
                                    subprocess.run(
                                        ['ffmpeg', '-y', '-f', 'dshow',
                                         '-i', 'audio=Stereo Mix (Realtek(R) Audio)',
                                         '-t', str(chunk_seconds), '-ar', str(sample_rate),
                                         '-ac', '2', '-acodec', 'pcm_s16le', tmp.name],
                                        capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                    )
                                except FileNotFoundError:
                                    try: os.unlink(tmp.name)
                                    except: pass
                                    with _sys_audio_lock:
                                        _sys_audio_active = False
                                    return
                                if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 44:
                                    with open(tmp.name, 'rb') as f:
                                        b64 = base64.b64encode(f.read()).decode('ascii')
                                    with _sys_audio_lock:
                                        _sys_audio_chunks.append(b64)
                                        if len(_sys_audio_chunks) > 20:
                                            _sys_audio_chunks.pop(0)
                                try: os.unlink(tmp.name)
                                except: pass
                            except Exception as e:
                                print(f"[SYS-AUDIO] fallback error: {e}")
                                time.sleep(1)
                _sys_audio_thread = threading.Thread(target=_sys_audio_thread_fn, daemon=True)
                _sys_audio_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/stop', methods=['POST'])
    def sys_audio_stream_stop(peer_id):
        global _sys_audio_active
        try:
            if peer_id == str(state.my_id):
                with _sys_audio_lock:
                    _sys_audio_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/chunk')
    def sys_audio_stream_chunk(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('system_audio', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _sys_audio_lock:
                    if _sys_audio_chunks:
                        chunk = _sys_audio_chunks.pop(0)
                        return jsonify({'success': True, 'audio': chunk, 'remaining': len(_sys_audio_chunks)})
                    return jsonify({'success': True, 'audio': None, 'remaining': 0})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/chunk",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/start', methods=['POST'])
    def input_monitor_start(peer_id):
        global _input_monitor_active, _input_monitor_events, _input_monitor_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('input_monitor', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _input_monitor_lock:
                    if _input_monitor_active:
                        return jsonify({'success': True, 'message': 'Already monitoring'})
                    _input_monitor_active = True
                    _input_monitor_events = []
                def _monitor_thread():
                    global _input_monitor_active
                    try:
                        from pynput import keyboard, mouse
                        def on_key_press(key):
                            if not _input_monitor_active:
                                return False
                            ts = time.strftime('%H:%M:%S')
                            try:
                                key_str = key.char if key.char else str(key)
                            except AttributeError:
                                key_str = str(key).replace('Key.', '')
                            with _input_monitor_lock:
                                _input_monitor_events.append({'type': 'key', 'key': key_str, 'time': ts})
                                if len(_input_monitor_events) > 5000:
                                    _input_monitor_events.pop(0)
                        def on_click(x, y, button, pressed):
                            if not _input_monitor_active:
                                return False
                            if pressed:
                                ts = time.strftime('%H:%M:%S')
                                btn = str(button).replace('Button.', '')
                                with _input_monitor_lock:
                                    _input_monitor_events.append({'type': 'mouse', 'button': btn, 'x': int(x), 'y': int(y), 'time': ts})
                                    if len(_input_monitor_events) > 5000:
                                        _input_monitor_events.pop(0)
                        kl = keyboard.Listener(on_press=on_key_press)
                        ml = mouse.Listener(on_click=on_click)
                        kl.start()
                        ml.start()
                        while _input_monitor_active:
                            time.sleep(0.5)
                        kl.stop()
                        ml.stop()
                    except ImportError:
                        # Fallback: use ctypes to call GetAsyncKeyState directly (fast, no subprocess)
                        import ctypes
                        import ctypes.wintypes
                        user32 = ctypes.windll.user32
                        # VK code to readable name map for special keys
                        VK_NAMES = {
                            8: 'Backspace', 9: 'Tab', 13: 'Enter', 16: 'Shift', 17: 'Ctrl', 18: 'Alt',
                            20: 'CapsLock', 27: 'Escape', 32: ' ', 37: 'Left', 38: 'Up', 39: 'Right', 40: 'Down',
                            46: 'Delete', 91: 'Win', 160: 'LShift', 161: 'RShift', 162: 'LCtrl', 163: 'RCtrl',
                            164: 'LAlt', 165: 'RAlt', 186: ';', 187: '=', 188: ',', 189: '-', 190: '.', 191: '/',
                            219: '[', 220: '\\', 221: ']', 222: "'",
                        }
                        SKIP_VKS = {16, 17, 18, 160, 161, 162, 163, 164, 165}  # modifier-only keys
                        # Mouse button VK codes
                        VK_LBUTTON, VK_RBUTTON, VK_MBUTTON = 1, 2, 4
                        class POINT(ctypes.Structure):
                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                        while _input_monitor_active:
                            ts = time.strftime('%H:%M:%S')
                            # Check mouse clicks
                            for vk_btn, btn_name in [(VK_LBUTTON, 'left'), (VK_RBUTTON, 'right'), (VK_MBUTTON, 'middle')]:
                                if user32.GetAsyncKeyState(vk_btn) & 1:
                                    pt = POINT()
                                    user32.GetCursorPos(ctypes.byref(pt))
                                    with _input_monitor_lock:
                                        _input_monitor_events.append({'type': 'mouse', 'button': btn_name, 'x': pt.x, 'y': pt.y, 'time': ts})
                                        if len(_input_monitor_events) > 5000:
                                            _input_monitor_events.pop(0)
                            # Check keyboard keys (VK 8-222)
                            for vk in range(8, 223):
                                if vk in SKIP_VKS:
                                    continue
                                if user32.GetAsyncKeyState(vk) & 1:
                                    if vk in VK_NAMES:
                                        key_str = VK_NAMES[vk]
                                    elif 65 <= vk <= 90:
                                        key_str = chr(vk).lower()
                                    elif 48 <= vk <= 57:
                                        key_str = chr(vk)
                                    elif 96 <= vk <= 105:
                                        key_str = str(vk - 96)
                                    else:
                                        key_str = f'VK_{vk}'
                                    with _input_monitor_lock:
                                        _input_monitor_events.append({'type': 'key', 'key': key_str, 'time': ts})
                                        if len(_input_monitor_events) > 5000:
                                            _input_monitor_events.pop(0)
                            time.sleep(0.02)
                    except Exception:
                        pass
                _input_monitor_thread = threading.Thread(target=_monitor_thread, daemon=True)
                _input_monitor_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/stop', methods=['POST'])
    def input_monitor_stop(peer_id):
        global _input_monitor_active
        try:
            if peer_id == str(state.my_id):
                with _input_monitor_lock:
                    _input_monitor_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/events')
    def input_monitor_events(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('input_monitor', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                with _input_monitor_lock:
                    events = list(_input_monitor_events)
                    _input_monitor_events.clear()
                return jsonify({'success': True, 'events': events})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/events",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})


    # ===== Wake-on-LAN (standalone) =====
    @app.route('/api/wol/<peer_id>', methods=['POST'])
    def wol_standalone(peer_id):
        try:
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            try:
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                arp_result = subprocess.run(['arp', '-a', peer_info.ip], capture_output=True, text=True, timeout=5, creationflags=cflags)
                mac = None
                for line in arp_result.stdout.splitlines():
                    if peer_info.ip in line:
                        parts = line.split()
                        for p in parts:
                            if len(p) == 17 and (p.count('-') == 5 or p.count(':') == 5):
                                mac = p.replace('-', ':'); break
                        if mac: break
                if not mac:
                    return jsonify({'success': False, 'error': f'Could not find MAC for {peer_info.ip}. Ping the peer first.'})
                mac_bytes = bytes.fromhex(mac.replace(':', ''))
                magic = b'\xff' * 6 + mac_bytes * 16
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(magic, ('255.255.255.255', 9))
                sock.sendto(magic, ('255.255.255.255', 7))
                sock.close()
                return jsonify({'success': True, 'message': f'WOL sent to {mac}'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Installed Apps List =====
    @app.route('/api/installed-apps/<peer_id>')
    def installed_apps(peer_id):
        try:
            if peer_id == str(state.my_id):
                apps = []
                seen = set()
                search_dirs = [
                    os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), r'Microsoft\Windows\Start Menu\Programs'),
                    os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs'),
                ]
                for sdir in search_dirs:
                    if not os.path.isdir(sdir):
                        continue
                    for root, dirs, files in os.walk(sdir):
                        for fname in files:
                            if not fname.lower().endswith('.lnk'):
                                continue
                            name = fname[:-4]
                            if name.lower() in seen:
                                continue
                            seen.add(name.lower())
                            full = os.path.join(root, fname)
                            try:
                                import ctypes.wintypes
                                import win32com.client
                                shell = win32com.client.Dispatch("WScript.Shell")
                                shortcut = shell.CreateShortCut(full)
                                target = shortcut.Targetpath
                                if target and os.path.isfile(target):
                                    apps.append({'name': name, 'path': target, 'args': shortcut.Arguments or ''})
                            except Exception:
                                apps.append({'name': name, 'path': full, 'args': ''})
                apps.sort(key=lambda a: a['name'].lower())
                return jsonify({'success': True, 'apps': apps})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/installed-apps/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== App Launch =====
    @app.route('/api/app-launch/<peer_id>', methods=['POST'])
    def app_launch(peer_id):
        try:
            data = flask_request.get_json(force=True)
            app_path = data.get('app', '').strip()
            app_args = data.get('args', '').strip()
            if not app_path:
                return jsonify({'success': False, 'error': 'No app specified'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    cmd = app_path if not app_args else f'{app_path} {app_args}'
                    subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/app-launch/{peer_id}", json=data, timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== File Exec =====
    @app.route('/api/file-exec/<peer_id>', methods=['POST'])
    def file_exec(peer_id):
        try:
            data = flask_request.get_json(force=True)
            fp = data.get('path', '').strip()
            if not fp:
                return jsonify({'success': False, 'error': 'No file path specified'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    os.startfile(fp)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/file-exec/{peer_id}", json=data, timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Disk Info =====
    @app.route('/api/disk-info/<peer_id>')
    def disk_info(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    import psutil
                    lines = []
                    for part in psutil.disk_partitions():
                        try:
                            usage = psutil.disk_usage(part.mountpoint)
                            lines.append(f"{part.device}  ({part.fstype})  Mount: {part.mountpoint}")
                            lines.append(f"  Total: {usage.total/(1024**3):.1f} GB  Used: {usage.used/(1024**3):.1f} GB  Free: {usage.free/(1024**3):.1f} GB  ({usage.percent}%)")
                        except PermissionError:
                            lines.append(f"{part.device}  ({part.fstype})  Mount: {part.mountpoint}  [Access Denied]")
                    return jsonify({'success': True, 'info': '\n'.join(lines)})
                except ImportError:
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['wmic', 'logicaldisk', 'get', 'DeviceID,FileSystem,FreeSpace,Size,VolumeName'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    return jsonify({'success': True, 'info': r.stdout.strip()})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/disk-info/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Event Log =====
    @app.route('/api/event-log/<peer_id>')
    def event_log(peer_id):
        try:
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['powershell', '-Command', "Get-EventLog -LogName System -Newest 50 | Format-Table -AutoSize -Wrap | Out-String -Width 300"], capture_output=True, text=True, timeout=20, creationflags=cflags)
                return jsonify({'success': True, 'info': r.stdout.strip() or r.stderr.strip() or 'No events'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/event-log/{peer_id}", timeout=25)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Health =====
    @app.route('/api/health/<peer_id>')
    def health_check(peer_id):
        try:
            if peer_id == str(state.my_id):
                lines = []
                try:
                    import psutil
                    cpu = psutil.cpu_percent(interval=1)
                    vm = psutil.virtual_memory()
                    temps = psutil.sensors_temperatures() if hasattr(psutil, 'sensors_temperatures') else {}
                    lines.append(f"CPU Usage: {cpu}%")
                    lines.append(f"RAM: {vm.used/(1024**3):.1f}/{vm.total/(1024**3):.1f} GB ({vm.percent}%)")
                    lines.append(f"Swap: {psutil.swap_memory().percent}%")
                    du = psutil.disk_usage('/')
                    lines.append(f"Disk C: {du.percent}% used")
                    boot = psutil.boot_time()
                    uptime_sec = time.time() - boot
                    days = int(uptime_sec // 86400); hours = int((uptime_sec % 86400) // 3600); mins = int((uptime_sec % 3600) // 60)
                    lines.append(f"Uptime: {days}d {hours}h {mins}m")
                    if temps:
                        for name, entries in temps.items():
                            for e in entries:
                                lines.append(f"Temp {name}/{e.label or 'core'}: {e.current}C")
                except ImportError:
                    lines.append("psutil not installed — limited info")
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['wmic', 'cpu', 'get', 'LoadPercentage', '/value'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    lines.append("CPU: " + r.stdout.strip())
                return jsonify({'success': True, 'info': '\n'.join(lines)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/health/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Printers =====
    @app.route('/api/printers/<peer_id>')
    def printers_list(peer_id):
        try:
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['wmic', 'printer', 'get', 'Name,PortName,DriverName,PrinterStatus'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                return jsonify({'success': True, 'info': r.stdout.strip() or 'No printers found'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/printers/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Wallpaper =====
    @app.route('/api/wallpaper/<peer_id>', methods=['POST'])
    def set_wallpaper(peer_id):
        try:
            data = flask_request.get_json(force=True)
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'success': False, 'error': 'No URL provided'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import tempfile, ctypes
                    resp_img = requests.get(url, timeout=15)
                    resp_img.raise_for_status()
                    ext = '.jpg'
                    if '.png' in url.lower(): ext = '.png'
                    elif '.bmp' in url.lower(): ext = '.bmp'
                    tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False, dir=str(Path.home() / 'Pictures'))
                    tmp.write(resp_img.content); tmp.close()
                    SPI_SETDESKWALLPAPER = 0x0014
                    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, tmp.name, 3)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/wallpaper/{peer_id}", json=data, timeout=20)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Software =====
    @app.route('/api/software/<peer_id>')
    def software_list(peer_id):
        try:
            if peer_id == str(state.my_id):
                items = []
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['powershell', '-Command', "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ConvertTo-Json -Compress"], capture_output=True, text=True, timeout=20, creationflags=cflags)
                try:
                    data = json.loads(r.stdout)
                    if isinstance(data, dict): data = [data]
                    for d in data:
                        items.append({'name': d.get('DisplayName', ''), 'version': d.get('DisplayVersion', '')})
                except Exception:
                    for line in r.stdout.strip().splitlines():
                        items.append({'name': line.strip(), 'version': ''})
                return jsonify({'success': True, 'items': items})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/software/{peer_id}", timeout=25)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Registry =====
    @app.route('/api/registry/<peer_id>', methods=['POST'])
    def registry_query(peer_id):
        try:
            data = flask_request.get_json(force=True)
            path = data.get('path', '').strip()
            if not path:
                return jsonify({'success': False, 'error': 'No registry path'})
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['reg', 'query', path], capture_output=True, text=True, timeout=10, creationflags=cflags)
                if r.returncode == 0:
                    return jsonify({'success': True, 'info': r.stdout.strip()})
                return jsonify({'success': False, 'error': r.stderr.strip() or 'Registry query failed'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/registry/{peer_id}", json=data, timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Net Conns =====
    @app.route('/api/net-conns/<peer_id>')
    def net_conns(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    import psutil
                    conns = psutil.net_connections(kind='inet')
                    lines = [f"{'Proto':<6} {'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'PID'}"]
                    for c in conns[:100]:
                        local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                        lines.append(f"{('TCP' if c.type==1 else 'UDP'):<6} {local:<25} {remote:<25} {c.status:<15} {c.pid or '-'}")
                    return jsonify({'success': True, 'info': '\n'.join(lines)})
                except ImportError:
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    return jsonify({'success': True, 'info': r.stdout.strip()})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/net-conns/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Env Vars =====
    @app.route('/api/env-vars/<peer_id>')
    def env_vars(peer_id):
        try:
            if peer_id == str(state.my_id):
                lines = [f"{k}={v}" for k, v in sorted(os.environ.items())]
                return jsonify({'success': True, 'info': '\n'.join(lines)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/env-vars/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Hosts File =====
    @app.route('/api/hosts-file/<peer_id>')
    def hosts_file(peer_id):
        try:
            if peer_id == str(state.my_id):
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
                try:
                    with open(hosts_path, 'r', encoding='utf-8', errors='replace') as f:
                        return jsonify({'success': True, 'content': f.read()})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/hosts-file/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== URL Open =====
    @app.route('/api/url-open/<peer_id>', methods=['POST'])
    def url_open(peer_id):
        try:
            data = flask_request.get_json(force=True)
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'success': False, 'error': 'No URL provided'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                import webbrowser
                webbrowser.open(url)
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/url-open/{peer_id}", json=data, timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Drivers =====
    @app.route('/api/drivers/<peer_id>')
    def drivers_list(peer_id):
        try:
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['driverquery', '/FO', 'TABLE'], capture_output=True, text=True, timeout=15, creationflags=cflags)
                return jsonify({'success': True, 'info': r.stdout.strip() or 'No driver data'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/drivers/{peer_id}", timeout=20)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Net Adapters =====
    @app.route('/api/net-adapters/<peer_id>')
    def net_adapters(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    import psutil
                    lines = []
                    addrs = psutil.net_if_addrs()
                    stats = psutil.net_if_stats()
                    for iface, addr_list in addrs.items():
                        s = stats.get(iface)
                        status = 'UP' if s and s.isup else 'DOWN'
                        speed = f"{s.speed}Mbps" if s and s.speed else ''
                        lines.append(f"\n{iface}  [{status}]  {speed}")
                        for a in addr_list:
                            if a.family == socket.AF_INET:
                                lines.append(f"  IPv4: {a.address}  Mask: {a.netmask}")
                            elif a.family.name == 'AF_LINK' if hasattr(a.family, 'name') else False:
                                lines.append(f"  MAC: {a.address}")
                    return jsonify({'success': True, 'info': '\n'.join(lines)})
                except ImportError:
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    return jsonify({'success': True, 'info': r.stdout.strip()})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/net-adapters/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Firewall =====
    @app.route('/api/firewall/<peer_id>')
    def firewall_rules(peer_id):
        try:
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                r = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'dir=in'], capture_output=True, text=True, timeout=15, creationflags=cflags)
                # Truncate if too long
                info = r.stdout.strip()
                if len(info) > 50000: info = info[:50000] + '\n... (truncated)'
                return jsonify({'success': True, 'info': info or 'No firewall data'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/firewall/{peer_id}", timeout=20)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Battery =====
    @app.route('/api/battery/<peer_id>')
    def battery_status(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    import psutil
                    bat = psutil.sensors_battery()
                    if bat is None:
                        return jsonify({'success': True, 'info': 'No battery detected (desktop PC?)'})
                    plugged = 'Plugged in' if bat.power_plugged else 'On battery'
                    secs = bat.secsleft
                    if secs == psutil.POWER_TIME_UNLIMITED: time_left = 'Charging'
                    elif secs == psutil.POWER_TIME_UNKNOWN: time_left = 'Unknown'
                    else:
                        hrs = secs // 3600; mins = (secs % 3600) // 60
                        time_left = f"{hrs}h {mins}m"
                    return jsonify({'success': True, 'info': f"Battery: {bat.percent}%\nStatus: {plugged}\nTime remaining: {time_left}"})
                except ImportError:
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['wmic', 'path', 'Win32_Battery', 'get', 'EstimatedChargeRemaining,BatteryStatus'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    return jsonify({'success': True, 'info': r.stdout.strip() or 'No battery info available'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/battery/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Webcam Snap =====
    @app.route('/api/webcam-snap/<peer_id>', methods=['POST'])
    def webcam_snap(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('screenshot', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import cv2
                    cap = cv2.VideoCapture(0)
                    if not cap.isOpened():
                        return jsonify({'success': False, 'error': 'No webcam found'})
                    ret, frame = cap.read()
                    cap.release()
                    if not ret:
                        return jsonify({'success': False, 'error': 'Failed to capture frame'})
                    _, buf = cv2.imencode('.png', frame)
                    encoded = base64.b64encode(buf.tobytes()).decode('ascii')
                    return jsonify({'success': True, 'image': encoded})
                except ImportError:
                    return jsonify({'success': False, 'error': 'opencv-python (cv2) not installed'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/webcam-snap/{peer_id}", timeout=20)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Location =====
    @app.route('/api/location/<peer_id>')
    def location_info(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    r = requests.get('http://ip-api.com/json/', timeout=5)
                    data = r.json()
                    lines = [
                        f"IP: {data.get('query', 'N/A')}",
                        f"City: {data.get('city', 'N/A')}",
                        f"Region: {data.get('regionName', 'N/A')}",
                        f"Country: {data.get('country', 'N/A')}",
                        f"ZIP: {data.get('zip', 'N/A')}",
                        f"ISP: {data.get('isp', 'N/A')}",
                        f"Lat: {data.get('lat', 'N/A')}, Lon: {data.get('lon', 'N/A')}",
                        f"Timezone: {data.get('timezone', 'N/A')}",
                    ]
                    return jsonify({'success': True, 'info': '\n'.join(lines)})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/location/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Recent Files =====
    @app.route('/api/recent-files/<peer_id>')
    def recent_files(peer_id):
        try:
            if peer_id == str(state.my_id):
                recent_dir = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Recent'
                if not recent_dir.exists():
                    return jsonify({'success': True, 'info': 'Recent folder not found'})
                items = sorted(recent_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:50]
                lines = []
                for item in items:
                    name = item.stem if item.suffix == '.lnk' else item.name
                    mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(item.stat().st_mtime))
                    lines.append(f"{mtime}  {name}")
                return jsonify({'success': True, 'info': '\n'.join(lines) or 'No recent files'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/recent-files/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== BIOS Info =====
    @app.route('/api/bios-info/<peer_id>')
    def bios_info(peer_id):
        try:
            if peer_id == str(state.my_id):
                cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                lines = []
                r1 = subprocess.run(['wmic', 'bios', 'get', 'Manufacturer,Name,SerialNumber,Version,ReleaseDate', '/value'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                lines.append("=== BIOS ==="); lines.append(r1.stdout.strip())
                r2 = subprocess.run(['wmic', 'baseboard', 'get', 'Manufacturer,Product,SerialNumber,Version', '/value'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                lines.append("\n=== Motherboard ==="); lines.append(r2.stdout.strip())
                r3 = subprocess.run(['wmic', 'csproduct', 'get', 'Name,Vendor,Version,UUID', '/value'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                lines.append("\n=== System ==="); lines.append(r3.stdout.strip())
                return jsonify({'success': True, 'info': '\n'.join(lines)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/bios-info/{peer_id}", timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Perf Monitor =====
    @app.route('/api/perf-monitor/<peer_id>')
    def perf_monitor(peer_id):
        try:
            if peer_id == str(state.my_id):
                try:
                    import psutil
                    cpu = psutil.cpu_percent(interval=0.5, percpu=True)
                    vm = psutil.virtual_memory()
                    dio = psutil.disk_io_counters()
                    nio = psutil.net_io_counters()
                    lines = [f"CPU per-core: {cpu}", f"CPU avg: {sum(cpu)/len(cpu):.1f}%",
                             f"RAM: {vm.percent}% ({vm.used/(1024**3):.1f}/{vm.total/(1024**3):.1f} GB)",
                             f"Disk Read: {dio.read_bytes/(1024**2):.0f} MB  Write: {dio.write_bytes/(1024**2):.0f} MB" if dio else "Disk I/O: N/A",
                             f"Net Sent: {nio.bytes_sent/(1024**2):.0f} MB  Recv: {nio.bytes_recv/(1024**2):.0f} MB"]
                    return jsonify({'success': True, 'info': '\n'.join(lines)})
                except ImportError:
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    r = subprocess.run(['wmic', 'cpu', 'get', 'LoadPercentage', '/value'], capture_output=True, text=True, timeout=10, creationflags=cflags)
                    return jsonify({'success': True, 'info': r.stdout.strip() or 'No perf data'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/perf-monitor/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Voice Note =====
    @app.route('/api/voice-note/<peer_id>', methods=['POST'])
    def voice_note(peer_id):
        try:
            data = flask_request.get_json(force=True)
            audio_b64 = data.get('audio', '')
            if not audio_b64:
                return jsonify({'success': False, 'error': 'No audio data'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('notify', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    audio_data = base64.b64decode(audio_b64)
                    tmp = tempfile.NamedTemporaryFile(suffix='.webm', delete=False)
                    tmp.write(audio_data); tmp.close()
                    os.startfile(tmp.name)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/voice-note/{peer_id}", json=data, timeout=30)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== TTS =====
    @app.route('/api/tts/<peer_id>', methods=['POST'])
    def tts_speak(peer_id):
        try:
            data = flask_request.get_json(force=True)
            text = data.get('text', '').strip()
            if not text:
                return jsonify({'success': False, 'error': 'No text provided'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('notify', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import tempfile
                    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                    tmp.write(text); tmp.close()
                    ps_script = f'Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Speak((Get-Content -Raw -Path "{tmp.name}")); Remove-Item -Path "{tmp.name}"'
                    subprocess.Popen(['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script])
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/tts/{peer_id}", json=data, timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Play Sound =====
    @app.route('/api/play-sound/<peer_id>', methods=['POST'])
    def play_sound(peer_id):
        try:
            data = flask_request.get_json(force=True)
            sound = data.get('sound', '').strip()
            if not sound:
                return jsonify({'success': False, 'error': 'No sound specified'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('notify', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    if sound.startswith('http'):
                        import tempfile
                        r = requests.get(sound, timeout=10)
                        r.raise_for_status()
                        tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                        tmp.write(r.content); tmp.close()
                        import winsound
                        winsound.PlaySound(tmp.name, winsound.SND_FILENAME | winsound.SND_ASYNC)
                    else:
                        import winsound
                        try:
                            winsound.PlaySound(sound, winsound.SND_ALIAS | winsound.SND_ASYNC)
                        except Exception:
                            winsound.PlaySound(sound, winsound.SND_FILENAME | winsound.SND_ASYNC)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/play-sound/{peer_id}", json=data, timeout=15)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Mouse Jiggler =====
    _mouse_jiggler_active = [False]
    _mouse_jiggler_thread = [None]
    @app.route('/api/mouse-jiggler/<peer_id>', methods=['POST'])
    def mouse_jiggler(peer_id):
        try:
            data = flask_request.get_json(force=True)
            action = data.get('action', 'start')
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                if action == 'stop':
                    _mouse_jiggler_active[0] = False
                    return jsonify({'success': True, 'active': False})
                if _mouse_jiggler_active[0]:
                    return jsonify({'success': True, 'active': True, 'message': 'Already running'})
                _mouse_jiggler_active[0] = True
                def jiggle():
                    import ctypes
                    while _mouse_jiggler_active[0]:
                        ctypes.windll.user32.mouse_event(0x0001, 1, 0, 0, 0)
                        time.sleep(0.5)
                        ctypes.windll.user32.mouse_event(0x0001, -1, 0, 0, 0)
                        time.sleep(30)
                _mouse_jiggler_thread[0] = threading.Thread(target=jiggle, daemon=True)
                _mouse_jiggler_thread[0].start()
                return jsonify({'success': True, 'active': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/mouse-jiggler/{peer_id}", json=data, timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # ===== Cursor Prank =====
    @app.route('/api/cursor-prank/<peer_id>', methods=['POST'])
    def cursor_prank(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not prompt_remote_permission('remote_exec', flask_request.remote_addr):
                    return jsonify({'error': 'Permission denied by host user.', 'success': False})
                try:
                    import ctypes
                    import random
                    def prank_fn():
                        for _ in range(20):
                            dx = random.randint(-50, 50)
                            dy = random.randint(-50, 50)
                            ctypes.windll.user32.mouse_event(0x0001, dx, dy, 0, 0)
                            time.sleep(0.15)
                    threading.Thread(target=prank_fn, daemon=True).start()
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(f"http://{peer_info.ip}:{peer_info.port}/api/cursor-prank/{peer_id}", timeout=10)
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})


    @app.route('/api/info')
    def api_info():
        return jsonify({'id': str(state.my_id), 'version': VERSION, 'call_number': state.call_number})


# ===========================================================================
# main entry point (from main.py + launcher.py)
# ===========================================================================

def setup_logging():
    log_file = DATA_DIR / "gna.log"
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.ERROR)
    logging.getLogger('zeroconf').setLevel(logging.WARNING)

def print_startup_banner():
    print(f">> {APP_NAME} v{VERSION} -- Starting (console will stay open forever)")
    print(f"   Project directory: {PROJECT_DIR}")

_sender_cache = {"status": "UNKNOWN", "ts": 0}
_signaling_cache = {"status": "UNKNOWN", "ts": 0}
_STATUS_CACHE_TTL = 15
_sender_pid = None  # PID of the sender.py subprocess we launched

def check_sender_status():
    global _sender_pid
    now = time.time()
    if now - _sender_cache["ts"] < _STATUS_CACHE_TTL: return _sender_cache["status"]
    result_status = "NOT DETECTED"
    # Method 1: check our own launched sender PID
    if _sender_pid is not None:
        try:
            os.kill(_sender_pid, 0)  # signal 0 = just check if alive
            result_status = "RUNNING"
        except (OSError, ProcessLookupError):
            _sender_pid = None  # process died
    # Method 2: check by window title (if launched via bat file)
    if result_status == "NOT DETECTED":
        try:
            result = subprocess.run(['tasklist', '/FI', 'WINDOWTITLE eq PubLAN Sender'], capture_output=True, text=True, timeout=5)
            if 'python' in result.stdout.lower(): result_status = "RUNNING"
        except Exception: pass
    # Method 3: check by command line containing sender.py
    if result_status == "NOT DETECTED":
        try:
            cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            result = subprocess.run(
                ['wmic', 'process', 'where', "commandline like '%sender.py%'", 'get', 'processid'],
                capture_output=True, text=True, timeout=5, creationflags=cflags
            )
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line.isdigit():
                    result_status = "RUNNING"
                    break
        except Exception: pass
    _sender_cache["status"] = result_status
    _sender_cache["ts"] = now
    return result_status

def check_signaling_server_status():
    now = time.time()
    if now - _signaling_cache["ts"] < _STATUS_CACHE_TTL: return _signaling_cache["status"]
    result_status = "NOT REACHABLE"
    try:
        resp = requests.get("http://localhost:3000/health", timeout=2)
        if resp.status_code == 200: result_status = "RUNNING"
        else: result_status = f"RESPONDING ({resp.status_code})"
    except Exception: pass
    _signaling_cache["status"] = result_status
    _signaling_cache["ts"] = now
    return result_status

def print_live_status(state):
    sorted_live = get_sorted_live_peers(state)
    my_role = get_current_role(state)
    sender_status = check_sender_status()
    signaling_status = check_signaling_server_status()
    global_svc = getattr(state, '_global_discovery', None)
    if global_svc and global_svc.enabled:
        relay_connected = global_svc.sio and global_svc.sio.connected
        relay_status = "LIVE" if relay_connected else "OFFLINE"
        relay_url = global_svc.relay_url if relay_connected else "(disconnected)"
        relay_peers = len(global_svc.global_peers)
    else:
        relay_status = "DISABLED"
        relay_url = ""
        relay_peers = 0
    print(f"\n{'='*80}")
    print(f"{APP_NAME} v{VERSION} LIVE STATUS — {time.strftime('%H:%M:%S')}")
    print(f"ID : {state.my_id}")
    print(f"Call Number : {state.call_number}")
    print(f"Role : {my_role}")
    print(f"Public IP : {state.public_ip}")
    print(f"Local IP:Port : {state.local_ip}:{PORT}")
    print(f"Live Peers : {len(sorted_live)}")
    print(f"Shared Items : {len(state.shared_paths)}")
    print(f"Sender.py : {sender_status}")
    print(f"Signal Server : {signaling_status}")
    if relay_status == "LIVE":
        print(f"Global Relay : {relay_status} — {relay_url} ({relay_peers} peers)")
    elif relay_status == "OFFLINE":
        print(f"Global Relay : {relay_status} — attempting {global_svc.relay_url}...")
    else:
        print(f"Global Relay : {relay_status}")
    print(f"Status : Active")
    print(f"{'='*80}")

def discovery_thread_fn(state):
    try:
        while True:
            update_peer_bookkeeping(state)
            time.sleep(DISCOVERY_INTERVAL_SECONDS)
    except Exception: pass

def status_thread_fn(state):
    try:
        while True:
            print_live_status(state)
            time.sleep(STATUS_PRINT_INTERVAL_SECONDS)
    except Exception: pass

def flask_thread_fn(app):
    try:
        app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)
    except Exception: pass

def launch_bat_file():
    """Run Start PubLAN.bat in the project directory (from launcher.py)."""
    try:
        exe_dir = PROJECT_DIR
        bat_path = exe_dir / "Start PubLAN.bat"
        if bat_path.exists():
            print(f"[OK] Launching Start PubLAN.bat from {exe_dir}")
            subprocess.Popen(
                ['cmd.exe', '/c', str(bat_path)],
                cwd=str(exe_dir),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            print(f"[WARNING] Start PubLAN.bat not found at {bat_path}")
    except Exception as e:
        print(f"[WARNING] Could not launch Start PubLAN.bat: {e}")

def main():
    setup_logging()
    print_startup_banner()

    # NOTE: Start PubLAN.bat is no longer launched here because the monolith
    # now directly starts the signaling server, sender.py, and caller.py.
    # The bat file would launch databank_explorer.py which creates a duplicate
    # Flask instance and a duplicate browser tab.

    try:
        # Self-verification check
        run_startup_integrity_check(PROJECT_DIR)

        migrate_legacy_files()

        my_id = generate_random_peer_id()
        my_call_number = generate_call_number()
        print(f"New random Bank ID this session: {my_id}")
        print(f"Call Number this session: {my_call_number}")

        my_join_time = load_join_time()
        local_ip = get_local_ip()
        public_ip = get_public_ip()

        state = ApplicationState(
            my_id=my_id, my_join_time=my_join_time,
            local_ip=local_ip, public_ip=public_ip,
            call_number=my_call_number,
            shared_paths=load_shared_paths(),
            known_peers=load_known_peers(),
        )

        shared_count = len(state.shared_paths)
        print(f"Loaded {shared_count} public paths")

        app = Flask(__name__)
        app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB upload limit
        app.logger.disabled = True
        create_routes(app, state)

        zc = Zeroconf()
        register_service(zc, my_id, local_ip)
        start_discovery(zc, state, my_id)

        # Start global discovery service
        state._global_call_numbers = {}

        def on_global_peers_updated(peers):
            for p in peers:
                pid = p.get('peerId', '')
                if not pid or pid == str(my_id): continue
                info = PeerInfo(ip=p.get('ip', ''), port=int(p.get('port', PORT)), join_time=time.time(), last_seen=time.time())
                state.add_known_peer(pid, info)
                cn = p.get('callNumber', '')
                if cn: state._global_call_numbers[pid] = cn

        global_svc = GlobalDiscoveryService(my_peer_id=str(my_id), my_call_number=my_call_number, local_ip=local_ip, local_port=PORT, on_peers_updated=on_global_peers_updated)
        state._global_discovery = global_svc
        global_svc.start()
        if global_svc.enabled:
            print(f"[OK] Global discovery enabled: network='{global_svc.network_code}'")
        else:
            print("[INFO] Global discovery disabled (configure global_config.json to enable)")

        # Spawn daemon threads
        threading.Thread(target=discovery_thread_fn, args=(state,), daemon=True, name="DiscoveryThread").start()
        threading.Thread(target=flask_thread_fn, args=(app,), daemon=True, name="FlaskThread").start()
        threading.Thread(target=status_thread_fn, args=(state,), daemon=True, name="StatusThread").start()

        # Start Node.js signaling server (if not already running)
        try:
            sig_running = False
            try:
                r = requests.get("http://localhost:3000/health", timeout=2)
                if r.status_code == 200:
                    sig_running = True
            except Exception:
                pass
            if not sig_running:
                server_js = PROJECT_DIR / 'server.js'
                if server_js.exists():
                    # npm install first if node_modules missing
                    pkg_json = PROJECT_DIR / 'package.json'
                    node_modules = PROJECT_DIR / 'node_modules'
                    if pkg_json.exists() and not node_modules.exists():
                        try:
                            subprocess.run(['npm', 'install', '--silent'], cwd=str(PROJECT_DIR),
                                           capture_output=True, timeout=60)
                        except Exception:
                            pass
                    subprocess.Popen(['node', str(server_js)], cwd=str(PROJECT_DIR),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                    time.sleep(2)
                    print("[OK] Signaling server (server.js) started in background")
                else:
                    print("[INFO] server.js not found — signaling server not started")
            else:
                print("[OK] Signaling server already running on port 3000")
        except Exception as e:
            print(f"[WARNING] Could not start signaling server: {e}")

        # Start sender.py in background (screen sharing)
        try:
            sender_path = PROJECT_DIR / 'sender.py'
            if sender_path.exists():
                # Write sender_session_id.txt (same as bat file does)
                session_id_file = PROJECT_DIR / 'sender_session_id.txt'
                sender_session_id = hashlib.md5(platform.node().encode()).hexdigest()
                try:
                    with open(session_id_file, 'w') as f:
                        f.write(sender_session_id)
                except Exception:
                    pass
                sender_proc = subprocess.Popen(
                    [sys.executable, str(sender_path)],
                    cwd=str(PROJECT_DIR),
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                global _sender_pid
                _sender_pid = sender_proc.pid
                time.sleep(2)
                print(f"[OK] Sender.py started in background (PID {_sender_pid})")
            else:
                print("[INFO] sender.py not found — screen sharing not started")
        except Exception as e:
            print(f"[WARNING] Could not start sender.py: {e}")

        # Start caller listener in background
        try:
            caller_path = PROJECT_DIR / 'caller.py'
            if caller_path.exists():
                subprocess.Popen([sys.executable, str(caller_path), str(my_id), my_call_number], creationflags=0)
                print("[OK] Call listener started in background")
        except Exception as e:
            print(f"[WARNING] Could not start call listener: {e}")

        # Open browser
        try:
            webbrowser.open(f"http://127.0.0.1:{PORT}")
            print("[OK] Browser opened to Dashboard!")
        except Exception as e:
            print(f"[WARNING] Could not open browser: {e}")
            print(f"         Navigate manually to http://127.0.0.1:{PORT}")

        # Launch MedianBox Monitor in a separate popup terminal
        try:
            print("[OK] Launching MedianBox Monitor in a new terminal window...")
            subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), '--medianbox'],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            print(f"[WARNING] Could not launch MedianBox Monitor: {e}")

        # Main thread blocks here forever
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[WARNING] Shutting down...")
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__} - {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\nConsole will stay open until you press Enter...")
        input("Press Enter to close this window...")


if __name__ == '__main__':
    if '--medianbox' in sys.argv:
        sys.argv.remove('--medianbox')
        medianbox_main()
    else:
        main()
