# SOC L1 - TTP Hunting at Pyramid of Pain Top

**Hunts behaviors, not hashes.**

## 🚨 Key Finding - ANY.RUN Analysis
Detected `vssadmin delete shadows /all /quiet` (MITRE T1490 - Inhibit System Recovery) **BEFORE** T1486 Data Encrypted for Impact.

- If you block T1490, you stop ALL ransomware families (LockBit, BlackCat, Conti), not just one hash.
- IOCs change, TTPs don't - Pyramid of Pain.

## 🔍 KQL Detections for Microsoft Sentinel

**T1490.kql** - Shadow copy deletion
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all("vssadmin","delete","shadows")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
| extend MITRE="T1490", Tactic="Impact", Action="Isolate Device"
