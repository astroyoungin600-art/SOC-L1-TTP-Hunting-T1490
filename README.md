# SOC L1 - TTP Hunting - T1490

Hunts behaviors, not hashes. Pyramid of Pain: TTPs > Tools > IOCs

**Finding:** ANY.RUN analysis caught `vssadmin delete shadows /all /quiet` (T1490) BEFORE T1486 encryption.

**Impact:** Detecting T1490 stops all ransomware families, not just one hash.

**KQL:** DeviceProcessEvents | where ProcessCommandLine has_all("vssadmin","delete","shadows")

Portfolio: github.com/astroyoungin600-art | TryHackMe: astroyoungin600 | Live: AstroJobSA.com (684 users)
