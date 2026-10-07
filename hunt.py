#!/usr/bin/env python3
"""
SOC L1 - TTP Hunter - T1490 Pyramid of Pain
Hunts behaviors, not hashes. Detects vssadmin delete shadows BEFORE encryption.

Author: astroyoungin600-art | Live: AstroJobSA.com (684 users)
"""

import re

# Simulated Sentinel log line
sample_logs = [
    '2025-10-07 cmd.exe vssadmin delete shadows /all /quiet',
    '2025-10-07 powershell.exe -enc aQBmACgAbQBhAGwAdwBhAHIAZQApAA==',
    '2025-10-07 outlook.exe spawned cmd.exe',
]

def detect_T1490(log: str) -> bool:
    """MITRE T1490 - Inhibit System Recovery"""
    return bool(re.search(r'vssadmin.*delete.*shadows', log, re.I))

def detect_T1059(log: str) -> bool:
    """MITRE T1059 - Command & Scripting Interpreter"""
    return bool(re.search(r'(outlook|winword).*->.*(cmd|powershell)', log, re.I))

def main():
    print("[*] SOC L1 TTP Hunt Started - Pyramid Top: TTPs > Tools > IOCs")
    for log in sample_logs:
        if detect_T1490(log):
            print(f"[ALERT] T1490 Inhibit System Recovery: {log} | Action: ISOLATE DEVICE")
        if detect_T1059(log):
            print(f"[ALERT] T1059 Suspicious Execution: {log}")
    print("[*] Hunt Complete - 3 KQL queries in queries/ folder for Microsoft Sentinel")

if __name__ == "__main__":
    main()
