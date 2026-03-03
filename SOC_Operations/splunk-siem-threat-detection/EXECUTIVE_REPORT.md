# Executive Security Report
## SSH Brute-Force Threat Detection and Response

**Prepared by:** Ejoke John, Cybersecurity Analyst
**Classification:** Internal Use

---

## Executive Summary

During a structured security monitoring exercise, authentication logs were analysed for signs of unauthorized access attempts. The investigation identified a significant volume of automated attacks targeting systems from multiple international sources.

The key finding is clear: **no unauthorized access occurred.** All brute-force attempts were unsuccessful and existing security controls proved effective. However, the scale and persistence of the attacks highlight gaps that, if left unaddressed, increase the organization's exposure to future compromise.

This report summarizes what was found, what it means for the business, and what actions are recommended.

---

## What We Found

Over the period analysed, systems recorded **520 failed login attempts** originating from six distinct international IP addresses. These attempts were not random. Attackers systematically targeted high-value accounts such as administrator and root accounts, using automated tools capable of trying thousands of password combinations per minute.

**Attack Origins:**

| Region | Failed Attempts |
|--------|----------------|
| China | 312 |
| Mexico | 80 |
| Vietnam | 46 |
| Russia | 18 |
| Unknown | 17 |

One of the attacking IP addresses was independently flagged by a cybersecurity vendor as linked to malware activity, confirming this was not benign or accidental traffic.

**Despite the volume of attacks, zero unauthorized logins were recorded.**

---

## Business Risk Assessment

| Risk Area | Level | Notes |
|-----------|-------|-------|
| Unauthorized system access | Medium | No breach occurred, but attack volume is significant |
| Credential compromise | Medium | Privileged accounts were repeatedly targeted |
| Operational disruption | Low | No service impact was observed |
| Data exposure | Low | No data loss detected during this period |

While current defenses held, the frequency and persistence of these attempts means the risk profile will grow over time without proactive hardening in place.

---

## What This Means for the Business

Brute-force attacks of this nature are largely automated and low-cost for attackers to run. A single successful login to a privileged account could result in:

- Unauthorized access to sensitive business and customer data
- Ransomware deployment or operational disruption
- Regulatory penalties depending on the data involved
- Reputational damage with clients and partners

The absence of a breach in this instance should not be mistaken for the absence of risk. These attacks are persistent and ongoing.

---

## Recommended Actions

**Immediate (within 7 days):**
- Block the identified attacking IP addresses at the network firewall
- Disable direct administrator account login over the network
- Enforce strong, complex password policies across all system accounts

**Short Term (within 30 days):**
- Implement Multi-Factor Authentication (MFA) for all remote access
- Restrict remote login access to approved locations and trusted devices only
- Configure automated alerts to notify the security team the moment attack thresholds are crossed

**Ongoing:**
- Conduct monthly reviews of authentication logs for new and emerging threat patterns
- Maintain continuous monitoring through the SIEM platform
- Review and update security controls regularly as the threat landscape evolves

---

## Conclusion

This investigation confirms that security monitoring is functioning as intended. Threats were detected, analysed, and documented before any damage occurred. The findings provide a clear roadmap for further strengthening defenses.

Investing in the recommended controls now is significantly less costly than responding to a breach after the fact. The security team is available to discuss implementation priorities and timelines at your convenience.

---

*For full technical methodology and detailed findings, refer to the accompanying technical walkthrough.*
