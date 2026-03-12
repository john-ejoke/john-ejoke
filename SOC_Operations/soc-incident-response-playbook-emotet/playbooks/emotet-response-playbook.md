# Emotet Incident Response Playbook

**Type:** Active Response Reference  
**Use:** Follow this during a live Emotet incident. No narrative, just actions.  
**Framework:** NIST SP 800-61  
**Author:** [Ejoke John Oghenekewe](https://www.linkedin.com/in/john-ejoke/)

---

## Severity Classification

| Indicator Present | Severity |
|---|---|
| emotet.exe in System32 | HIGH |
| Encoded PowerShell beacon | HIGH |
| Firewall disabled | CRITICAL |
| Security log cleared | CRITICAL |
| SAM database accessed or copied | CRITICAL |
| 3 or more of the above on one host | CATASTROPHIC |

---

## Phase 1: Identification Checklist

- [ ] Confirm affected endpoints using Event ID correlation in SIEM
- [ ] Verify SHA256 hash of any suspicious executable against VirusTotal
- [ ] Check for Event ID 4688 with System32 path in CommandLine
- [ ] Check for Event ID 4104 with `-enc` or `-EncodedCommand` in ScriptBlockText
- [ ] Check for Event ID 2004 with `allprofiles state off`
- [ ] Check for Event ID 1102 (Security log cleared)
- [ ] Check for Event ID 4663 with `\config\SAM` in ObjectName
- [ ] Decode any Base64 PowerShell arguments to identify C2 IP
- [ ] Run full chain correlation query across all endpoints
- [ ] Classify incident severity using table above
- [ ] Notify stakeholders: management, legal, SOC lead

---

## Phase 2: Containment Checklist

- [ ] Isolate all affected endpoints from the network immediately
- [ ] Block identified C2 IP at the perimeter firewall
- [ ] Block C2 domain if resolved from the beacon
- [ ] Disable affected user accounts pending investigation
- [ ] Revoke all active sessions on compromised hosts
- [ ] Place any host where SAM was accessed under forensic hold
- [ ] Do not wipe or reimage any endpoint until forensic image is taken
- [ ] Document all containment actions with timestamps

---

## Phase 3: Eradication Checklist

- [ ] Remove emotet.exe from `C:\Windows\System32\`
- [ ] Delete any SAM backup files from accessible directories
- [ ] Terminate all unauthorized processes on affected hosts
- [ ] Close all unauthorized network connections
- [ ] Re-enable and harden Windows Firewall with strict rules
- [ ] Scan all endpoints with updated AV and EDR signatures
- [ ] Verify no persistence mechanisms remain (scheduled tasks, registry run keys, services)
- [ ] Reset all local account passwords on affected hosts
- [ ] Rotate all domain credentials if lateral movement is suspected

---

## Phase 4: Recovery Checklist

- [ ] Restore affected systems from last known clean backup
- [ ] Verify backup integrity before restoration
- [ ] Apply all outstanding Windows security patches
- [ ] Enable PowerShell Constrained Language Mode via Group Policy
- [ ] Re-enable centralized logging and confirm SIEM ingestion
- [ ] Enforce MFA on all privileged accounts
- [ ] Deploy EDR on all endpoints if not already present
- [ ] Conduct 72-hour enhanced monitoring before returning to normal ops
- [ ] Confirm no C2 communication from any endpoint post-recovery

---

## Phase 5: Post-Incident Checklist

- [ ] Conduct lessons-learned review with all stakeholders within 5 business days
- [ ] Document full incident timeline from first indicator to closure
- [ ] Deploy Splunk detection rules from `detection-rules/splunk/`
- [ ] Update this playbook based on anything that did not work as expected
- [ ] Restrict PowerShell execution policy to signed scripts only
- [ ] Implement tamper-proof centralized log storage
- [ ] Schedule next tabletop exercise within 90 days
- [ ] Share sanitized incident report with relevant teams

---

## Quick Reference: Key Event IDs

| Event ID | Description | Trigger |
|---|---|---|
| 4688 | Process Creation | New process started |
| 4104 | PowerShell Script Block | PS command executed |
| 2004 | Firewall Rule Modified | Firewall setting changed |
| 1102 | Security Log Cleared | wevtutil or similar used |
| 4663 | Object Access Attempt | File or registry accessed |

---

## Quick Reference: Emotet IOCs from This Investigation

| Type | Value |
|---|---|
| File | `emotet.exe` |
| SHA256 | `555dff455242a5f82f79eecb66539bfd1daa842481168f1f1df911ac05a1cfba` |
| C2 IP | `87.251.86.178` |
| C2 Port | `8080` |
| Dropped path | `C:\Windows\System32\emotet.exe` |
| SAM backup path | `C:\Users\Public\SAM_Backup` |

---

*For full investigation narrative and context, see the main [README](../README.md)*
