# Splunk & Sigma Detection Package: LSASS Memory Dumping (T1003.001)

## Description
This project provides an end-to-end detection engineering package designed to identify **LSASS Memory Dumping** ([MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)), a critical post-exploitation technique used by threat actors to harvest credentials from memory.

### Why This Matters
The Local Security Authority Subsystem Service (`lsass.exe`) handles user authentication and security tokens on Windows systems. Attackers routinely target LSASS using tools like Mimikatz or ProcDump to steal high-privilege domain credentials.

### Key Detection Features
- **Sigma Rule:** Universal rule querying Sysmon Event ID 10 (Process Access) for elevated access masks (`0x1010` and `0x1F0FFF`).
- **Splunk SPL:** Targeted correlation search linking Sysmon Event ID 1 (Process Creation) and Event ID 10 to trace the full parent-child execution path.
- **False Positive Tuning:** Pre-built exclusions to suppress legitimate Windows system binaries (e.g., `svchost.exe`, `csrss.exe`).

---

## Log Requirements & Prerequisites
To ingest and trigger these detections, the host endpoint must run Microsoft Sysmon with process access auditing enabled in the configuration file:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
