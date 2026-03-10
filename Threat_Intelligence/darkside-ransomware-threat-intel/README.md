# DarkSide Ransomware — Threat Intelligence Investigation

> **Repo:** `Threat-Intelligence/darkside-ransomware-threat-intel/`  
> **Analyst:** Ejoke John | CyBlack SOC Academy  
> **Date:** July 2025  
> **Sample Hash (SHA-256):** `156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Sample Discovery — VirusTotal API](#2-sample-discovery--virustotal-api)
3. [Threat Actor Profile](#3-threat-actor-profile)
4. [Notable Attacks & Campaign Analysis](#4-notable-attacks--campaign-analysis)
5. [Attack Lifecycle — MITRE ATT&CK Mapping](#5-attack-lifecycle--mitre-attck-mapping)
6. [Current Status & Successor Groups](#6-current-status--successor-groups)
7. [Indicators of Compromise (IOCs)](#7-indicators-of-compromise-iocs)
8. [YARA Detection Rule](#8-yara-detection-rule)
9. [Detection & Prevention Strategies](#9-detection--prevention-strategies)
10. [Tools & Environment](#10-tools--environment)
11. [References](#11-references)

---

## 1. Project Overview

This project documents a complete threat intelligence cycle applied to a confirmed DarkSide ransomware sample — from initial hash discovery through structured research, MITRE ATT&CK mapping, YARA rule development, and actionable defense recommendations.

The investigation was conducted as part of a SOC home lab exercise within a controlled Ubuntu virtual machine environment. The sample was identified from a batch of 50 SHA-256 hashes submitted to the VirusTotal API and cross-correlated with MITRE ATT&CK Group G0139 (CARBON SPIDER / DarkSide).

**Intelligence Cycle Phases Covered:**

| Phase | Description |
|-------|-------------|
| **Discovery** | Identified malicious hash among 50 samples via VirusTotal API automation |
| **Research & Analysis** | Linked sample to DarkSide family; mapped full attack lifecycle to MITRE ATT&CK |
| **Detection Engineering** | Developed and validated a custom YARA rule (zero false positives) |
| **Mitigation** | Produced actionable defense and prevention recommendations |

---

## 2. Sample Discovery — VirusTotal API

### Methodology

A Python script was written to submit 50 SHA-256 hashes in batches to the VirusTotal v3 API. The script respected API rate limits (60-second waits between requests) and parsed each response for detection count and malware family classification.

One hash stood out immediately — flagged malicious by **over 60 security vendors**, with consistent attribution to the DarkSide ransomware family.

![VirusTotal API Hash Detection](screenshots/01_virustotal_api_hash_detection.png)
*Python script output showing the malicious hash flagged across multiple AV vendors via the VirusTotal API*

### Confirmed Malicious Hash

```
156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673
```

**VirusTotal Report:** https://www.virustotal.com/gui/file/156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673

### Vendor Detection Signatures

| Security Vendor | Detection Signature |
|----------------|---------------------|
| Microsoft | `Ransom:MSIL/Darkside.SK!MTB` |
| Elastic Security | `Windows.Ransomware.Darkside` |
| AVG / Avast | `Win32:DarkSide-C [Ransom]` |
| Kaspersky | `Trojan-Ransom.Win32.Gen.aayp` |
| BitDefender / Emsisoft / GData | `Gen:Variant.Ransom.DarkSide.16` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| TrendMicro | `Ransom_DarkSide.R002C0DE121` |
| Malwarebytes | `Malware.AI.4023494292` |
| Symantec | `Ransom.Darkside` |

The unanimous classification across vendor families — including behavioural engines (CrowdStrike, Elastic), signature engines (Microsoft, Kaspersky), and heuristic engines (Malwarebytes) — confirmed this as a high-confidence DarkSide sample requiring deeper investigation.

---

## 3. Threat Actor Profile

**Group:** DarkSide (also tracked as CARBON SPIDER by CrowdStrike; MITRE ATT&CK Group G0139)

| Attribute | Detail |
|-----------|--------|
| **First Observed** | April 2021 (creation timestamp: April 5, 2021) |
| **First Major Activity** | May 5, 2021 |
| **Shutdown Claimed** | May 2021 (post-Colonial Pipeline) |
| **Origin / Attribution** | Russian-speaking cybercriminal group |
| **Business Model** | Ransomware-as-a-Service (RaaS) |
| **Geographic Restrictions** | Explicitly avoided CIS (Commonwealth of Independent States) countries |
| **Sector Targets** | Energy, utilities, chemical distribution, manufacturing |
| **Excluded Targets** | Schools, hospitals, non-profits, government |
| **Successor Group** | BlackMatter (confirmed by CISA, July 2021) |
| **Links** | REvil (shared code/infrastructure patterns) |

### RaaS Business Model

DarkSide operated with a professional structure uncommon in cybercriminal groups at the time. The core developers maintained the ransomware codebase and infrastructure, while affiliates conducted intrusions and received a percentage of ransom payments. The group maintained:

- A dedicated **press room** for media communications
- A **victim hotline** for ransom negotiation support
- A **data leak site** (DLS) for double-extortion pressure
- Affiliate profit-sharing tiers (typically 75–90% to affiliates)

### Motivation & Tactics

- **Primary Motivation:** Financial extortion
- **Core Tactics:** Double-extortion (encrypt data + threaten public leak), RDP brute-force, phishing, PowerShell and registry abuse, data exfiltration via FTP or cloud staging

---

## 4. Notable Attacks & Campaign Analysis

### Colonial Pipeline — May 2021 (USA)

| Attribute | Detail |
|-----------|--------|
| **Target** | Colonial Pipeline Company |
| **Sector** | Energy / Critical Infrastructure |
| **Impact** | 5,500 miles of fuel pipeline shut down; ~45% of East Coast fuel supply disrupted |
| **Ransom Paid** | $4.4 million USD (partially recovered by DOJ) |
| **Consequence** | DarkSide publicly shut down operations shortly after due to law enforcement pressure |

The Colonial Pipeline attack was a watershed moment in ransomware history — the first time a ransomware group directly triggered a national emergency declaration in the United States (Executive Order signed by President Biden). The attack highlighted the catastrophic risk of ransomware to operational technology (OT) and industrial control systems (ICS) environments.

### Brenntag — May 2021 (Germany)

| Attribute | Detail |
|-----------|--------|
| **Target** | Brenntag SE |
| **Sector** | Chemical Distribution (world's largest) |
| **Data Stolen** | ~150 GB of employee and corporate data |
| **Ransom Paid** | $4.4 million USD |
| **Entry Vector** | Credential theft (purchased stolen credentials) |

### Target Industry Pattern

DarkSide and its affiliates showed a deliberate focus on high-revenue organisations in critical sectors with low tolerance for downtime — maximising both ransom pressure and payment likelihood. Energy and chemical sectors were particularly attractive due to operational continuity requirements.

---

## 5. Attack Lifecycle — MITRE ATT&CK Mapping

**MITRE ATT&CK Group:** [G0139 — CARBON SPIDER (DarkSide)](https://attack.mitre.org/groups/G0139/)

### Full Kill Chain

| Phase | Tactic | Technique | Details |
|-------|--------|-----------|---------|
| **Initial Access** | TA0001 | T1566 — Phishing | Spearphishing links/attachments; compromised RDP credentials via brute-force or dark web purchase |
| **Execution** | TA0002 | T1059.001 — PowerShell | DLL payload launched via PowerShell; encoded CMD commands |
| | | T1059.003 — CMD | Base64-encoded command execution for payload delivery |
| **Persistence** | TA0003 | T1543.003 — New Service | Creates `SysUpdateSvc` service for persistence |
| | | T1053.005 — Scheduled Task | `schtasks /create /tn` for recurring execution |
| | | T1547.001 — Registry Run Keys | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Privilege Escalation** | TA0004 | T1068 | Exploits vulnerabilities to achieve SYSTEM-level privileges |
| **Defense Evasion** | TA0005 | T1490 — Shadow Copy Deletion | `vssadmin delete shadows` to prevent recovery |
| | | T1070.001 — Log Clearing | Clears Windows event logs |
| | | T1027 — Obfuscation | PowerShell `-enc` (encoded commands) |
| | | T1036 — Masquerading | Copies itself to trusted paths (e.g., `System32`) |
| **Discovery** | TA0007 | T1083 — File & Directory Discovery | Enumerates files and directories for encryption targeting |
| | | T1135 — Network Share Discovery | Scans for accessible network shares |
| | | T1087.002 — AD Account Discovery | Enumerates Active Directory accounts |
| | | T1057 — Process Discovery | `cmd.exe /c whoami` for privilege discovery |
| **Command & Control** | TA0011 | T1071.001 — HTTPS | C2 communication over HTTPS to suspicious domains |
| **Exfiltration** | TA0010 | T1048 — Exfiltration via Alt Protocol | Data staged and exfiltrated via FTP or cloud storage |
| **Impact** | TA0040 | T1486 — Data Encrypted for Impact | RSA-1024 + Salsa20 encryption; `.darkside` extension appended |
| | | T1490 — Inhibit System Recovery | Shadow copy deletion; disables backup services |
| | | T1491 — Ransom Note | Drops `README_RECOVER_FILES.txt` in each encrypted directory |

### Encryption Implementation

DarkSide used a two-layer encryption scheme:
- **Salsa20** for file content encryption (fast, stream cipher)
- **RSA-1024** for encrypting the Salsa20 key (asymmetric key protection)

This design means decryption without the attacker's private RSA key is computationally infeasible.

---

## 6. Current Status & Successor Groups

### DarkSide "Shutdown" (May 2021)

Following the Colonial Pipeline attack and subsequent law enforcement pressure, DarkSide announced it was ceasing operations, claiming its servers and cryptocurrency funds had been seized. This announcement was widely viewed by security researchers and CISA as a tactical rebranding rather than a genuine closure.

### BlackMatter (July 2021)

BlackMatter emerged approximately two months after DarkSide's announced shutdown. CISA and multiple threat intelligence firms quickly identified strong technical and operational overlaps:

- Identical or near-identical encryption routines
- Shared code patterns in the ransomware binary
- Consistent RaaS affiliate structure and profit-sharing model
- Similar target selection criteria (avoiding CIS countries, hospitals, schools)

BlackMatter subsequently also shut down in November 2021, again likely due to law enforcement pressure. Elements of both groups are believed to have contributed to later RaaS operations.

---

## 7. Indicators of Compromise (IOCs)

### File Indicators

| Indicator Type | Value | Description |
|---------------|-------|-------------|
| **SHA-256** | `156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673` | Confirmed DarkSide ransomware sample |
| **Ransom Note** | `README_RECOVER_FILES.txt` | Dropped in each encrypted directory |
| **File Extension** | `.darkside` | Appended to encrypted files |
| **File Extension (alt)** | `.locked` | Observed in some variants |

### Registry Indicators

| Indicator Type | Value | Description |
|---------------|-------|-------------|
| **Registry Key** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence via run key |
| **Service Name** | `SysUpdateSvc` | Fake service created for persistence |

### Behavioural Indicators

| Indicator Type | Value | Description |
|---------------|-------|-------------|
| **Command** | `vssadmin delete shadows /all /quiet` | Shadow copy deletion |
| **Command** | `schtasks /create /tn` | Scheduled task creation |
| **Command** | `cmd.exe /c whoami` | Privilege discovery |
| **PowerShell** | `powershell -enc [base64]` | Encoded payload execution |

### Network Indicators

| Indicator Type | Value | Description |
|---------------|-------|-------------|
| **Protocol** | HTTPS | C2 communication channel |
| **Pattern** | Suspicious domains (dynamic DNS) | C2 beaconing pattern |

> **Note:** Specific C2 domain values were not present in the analysed samples. For current IOC feeds, reference [CISA AA21-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a) and [MITRE ATT&CK G0139](https://attack.mitre.org/groups/G0139/).

---

## 8. YARA Detection Rule

The YARA rule is located at: [`yara/darkside_ransomware_detection.yar`](yara/darkside_ransomware_detection.yar)

### Rule Summary

The rule was developed by identifying eight distinct behavioural indicators extracted from threat intelligence analysis of the confirmed DarkSide sample. Detection triggers when **3 or more** indicators are present in a scanned file, balancing sensitivity with specificity.

![YARA Rule Authoring](screenshots/02_yara_rule_authoring.png)
*YARA rule authored in Sublime Text with all eight DarkSide behavioural string indicators and detection condition*

**String indicators used:**
- `README_RECOVER_FILES.txt` — ransom note filename
- `.locked` / `.darkside` — encrypted file extension markers
- `SysUpdateSvc` — fake persistence service name
- `vssadmin delete shadows` — shadow copy deletion command
- `powershell -enc` — obfuscated PowerShell execution
- `cmd.exe /c whoami` — privilege discovery command
- `schtasks /create /tn` — scheduled task creation
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — registry persistence path

### Validation

The rule was tested using the YARA CLI on Kali Linux against a synthetic test file (`samplefile.txt`) containing embedded DarkSide behavioural strings. The scan confirmed a **successful match with zero false positives** on benign comparison samples.

![YARA Test Sample File](screenshots/03_yara_test_sample_file.png)
*Synthetic test file (samplefile.txt) containing embedded DarkSide behavioural indicators — ransom note reference, SysUpdateSvc persistence, shadow copy deletion, and registry run key*

![YARA Detection Confirmed](screenshots/04_yara_detection_confirmed.png)
*YARA CLI scan confirming successful detection: `DarkSide_Ransomware samplefile.txt` — zero false positives on benign samples*

```bash
# Command used for validation
yara darkside_ransomware_detection.yar samplefile.txt
# Output: DarkSide_Ransomware samplefile.txt  ✓
```

> **Tuning Note:** Increasing the condition threshold to `4 of them` or higher reduces false positive risk in noisy environments while maintaining strong detection coverage.

---

## 9. Detection & Prevention Strategies

### Endpoint & Detection

| Control | Description |
|---------|-------------|
| **EDR with Behavioural Detection** | Deploy endpoint detection tools capable of identifying DarkSide's behavioural patterns (shadow copy deletion, encoded PowerShell, service creation) |
| **SIEM Integration** | Centralise log collection; alert on `vssadmin delete shadows`, new service creation, and scheduled task anomalies |
| **Custom YARA Rules** | Deploy the YARA rule in this repository via your EDR or threat hunting platform |
| **IOC Feeds** | Subscribe to threat intelligence feeds (CISA, ISAC sharing, commercial TI) and integrate DarkSide IOCs |

### Network Security

| Control | Description |
|---------|-------------|
| **Network Segmentation / Micro-segmentation** | Isolate critical OT/ICS systems from corporate IT networks; limit lateral movement paths |
| **Zero Trust Architecture** | Apply ZTNA principles — no implicit trust based on network location |
| **Firewall Hardening** | Restrict inbound RDP (TCP 3389); disable unused ports; restrict outbound HTTPS to known-good destinations |
| **Secure Remote Access** | Replace open RDP with hardened VPN + MFA or a Zero Trust Network Access (ZTNA) solution |

### Identity & Access

| Control | Description |
|---------|-------------|
| **Multi-Factor Authentication (MFA)** | Enforce MFA on all remote access, email, and privileged accounts |
| **Least Privilege** | Restrict user permissions; prevent standard users from running PowerShell or modifying services |
| **Strong Credential Policy** | Enforce complex passwords; monitor for credential stuffing against exposed RDP/VPN endpoints |
| **Privileged Access Management (PAM)** | Monitor and vault privileged account usage |

### Resilience & Recovery

| Control | Description |
|---------|-------------|
| **Offline Backups** | Maintain encrypted, immutable, air-gapped backups — DarkSide specifically deletes VSS shadow copies and network-accessible backups |
| **Backup Testing** | Regularly test recovery procedures; a backup you haven't tested is not a reliable backup |
| **Patch Management** | Apply OS and application patches promptly; DarkSide affiliates actively exploit unpatched RDP and VPN vulnerabilities |
| **Email Filtering** | Block malicious attachments and URLs; enforce DMARC/DKIM/SPF |

### Security Awareness

| Control | Description |
|---------|-------------|
| **Phishing Simulations** | Regular simulated phishing campaigns to train users to recognise spearphishing |
| **Incident Response Drills** | Tabletop exercises simulating ransomware scenarios, particularly for critical infrastructure operators |

---

## 10. Tools & Environment

| Tool | Purpose |
|------|---------|
| **Ubuntu VM** | Isolated analysis environment |
| **Python 3 + `requests` library** | VirusTotal API hash batch submission |
| **VirusTotal v3 API** | Sample identification and vendor detection correlation |
| **YARA (CLI)** | Detection rule authoring and validation |
| **Kali Linux** | YARA rule testing environment |
| **Sublime Text** | YARA rule authoring |
| **MITRE ATT&CK Navigator** | Attack lifecycle mapping (Group G0139) |

---

## 11. References

| Source | Link |
|--------|------|
| MITRE ATT&CK — G0139 (DarkSide) | https://attack.mitre.org/groups/G0139/ |
| CISA Advisory AA21-131A | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a |
| FBI Flash MC-000147-MW | https://www.aha.org/system/files/media/file/2021/05/fbi-tlp-white-flash-darkside-ransomware.pdf |
| VirusTotal Sample Report | https://www.virustotal.com/gui/file/156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673 |
| Mandiant / FireEye DarkSide Report | https://www.mandiant.com/resources/darkside-ransomware-victims-sold-to-investors |
| Colonial Pipeline DOJ Recovery | https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside |

---

*This project was completed as part of a structured threat intelligence lab exercise at CyBlack SOC Academy. All analysis was conducted in a controlled, isolated environment. No malicious files were executed on production systems.*

*— Ejoke John | [[LinkedIn]](https://linkedin.com/in/YOUR-PROFILE) | [[GitHub]](https://github.com/YOUR-USERNAME)*
