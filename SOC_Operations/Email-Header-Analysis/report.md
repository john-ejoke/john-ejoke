# Email Header Analysis

**Date:** March 2026
**Category:** SOC Operations | Cyblack Internship
**Status:** Complete

**Verdict:** Confirmed Spoofed Phishing Attempt

**Tools:** Sublime Text, PhishTool, MXToolbox, Google Admin Toolbox, AbuseIPDB, VirusTotal, WHOIS

**Summary:** Investigated a quarantined email impersonating Microsoft's security team. Traced the originating IP to an unregistered domain with no DNS records, confirmed SPF, DKIM, and DMARC failures across three independent tools, and identified the sending IP in multiple phishing campaigns via VirusTotal. The email body contained a tracking beacon, obfuscated CSS, and attacker-controlled links disguised as legitimate Microsoft actions.

**Full walkthrough:** [SOC-Operations/Email-Header-Analysis/README.md](../SOC_Operations/Email-Header-Analysis/README.md)
**Live video:** [YouTube — approx. 22 mins](https://youtu.be/EuG3D6nTctg?si=p3BG3LVA6O81Xcxl)
