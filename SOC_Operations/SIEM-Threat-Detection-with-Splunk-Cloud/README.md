# 🛡️ SIEM Threat Detection with Splunk Cloud
### Investigating Brute-Force Attacks via OpenSSH Logs: A SOC Analyst Walkthrough

**Author:** Ejoke John | Cybersecurity Analyst
**Tools:** Splunk Cloud, SPL, VirusTotal, AbuseIPDB, WHOIS

---

## What This Project Is About

This project documents my end-to-end experience operating Splunk Cloud as a SIEM platform to investigate real-world SSH authentication logs. I ingested OpenSSH log data, wrote SPL queries to hunt for brute-force patterns, built dashboards, configured automated alerts, and validated suspicious IPs against external threat intelligence sources.

The goal was to simulate what a SOC analyst actually does: take raw log data, make sense of it, and turn it into actionable findings.

---

## My Environment

| Component | Details |
|-----------|---------|
| **Platform** | Splunk Cloud |
| **Log Source** | OpenSSH authentication log (CSV format) |
| **Query Language** | SPL (Splunk Processing Language) |
| **Threat Intel** | VirusTotal, AbuseIPDB, WHOIS |
| **Index** | main |

---

## 🔧 Setting Up Splunk Cloud

### User Management

First I set up the Splunk Cloud workspace properly. I created user accounts and assigned roles following the principle of least privilege, meaning each user only had access to what they actually needed. Roles ranged from standard user to power and admin depending on the level of access required.

I also configured the default timezone to WAT (West Africa Time) and enabled forced password changes on first login for all newly created accounts.

---

## 📥 Ingesting the Log Data

### Uploading the OpenSSH Log

I uploaded the OpenSSH log file through the Add Data workflow in Splunk Cloud:

- Navigated to the Search and Reporting app and selected Add Data
- Uploaded `openssh_log.csv` and set the source type to `csv`
- Indexed the data under the `main` index
- Confirmed successful ingestion from the upload confirmation screen

### Verifying Data Integrity

Before running any analysis I verified the data was clean and correctly indexed:

```spl
index=main "Failed password"
```

This returned expected results with intact timestamps, consistent host and sourcetype metadata, and no malformed entries. The data was ready to work with.

---

## 🔎 Hunting for Brute-Force Activity

### Finding Failed Login Attempts

I started with a broad search to see the full picture of failed authentication activity:

```spl
index=main "Failed password"
```

This returned **520 events** across multiple IP addresses. That number alone was a signal worth digging into.

### Extracting Source IPs with Regex

The raw logs didn't have source IP as a clean field, so I used regex to pull it out and immediately group by frequency:

```spl
index=main "Failed password"
| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| where count > 10
```

This surfaced the top offenders straight away:

| IP Address | Failed Attempts | Origin |
|------------|----------------|--------|
| 183.62.140.253 | 286 | China (ChinaNet, Shenzhen) |
| 187.141.143.180 | 80 | Mexico (Uninet S.A. de C.V.) |
| 103.99.0.122 | 46 | Vietnam (VPSONLINE Ltd.) |
| 112.95.230.3 | 26 | China (China Unicom, Guangdong) |
| 5.188.10.180 | 18 | Russia (Petersburg Internet Network) |
| 185.190.58.151 | 17 | Unknown origin |

286 failed attempts from a single IP is not accidental. That is automated brute-force.

### Checking for Successful Root Logins

After finding all those failures, the next question was obvious: did any of them get in?

```spl
index=* "Accepted password for root"
| rex "from\s+(?<src_ip>\d{1,3}(\.\d{1,3}){3})"
| stats dc(src_ip) AS unique_root_ips
```

**Result: zero successful root logins.** Every single brute-force attempt failed. The system held.

### Understanding Who Was Being Targeted

I took it a step further and correlated IPs with the usernames they were hitting:

```spl
index=main "Failed password"
| stats count by src_ip, user
```

The pattern was clear. Attackers were going after default and privileged accounts:

- `183.62.140.253` focused almost entirely on `root`
- `185.190.58.151` cycled through `admin` and `api`
- `5.188.10.180` probed `guest`, `ftp`, and `default`

This is textbook dictionary-based brute-force, targeting accounts that commonly exist on Linux systems with weak or default credentials.

---

## 🧩 Building the src_ip Field Extraction

Rather than running inline regex every time, I created a persistent field extraction in Splunk so `src_ip` would always be available as a structured field across all queries.

**Settings used:**
- Destination App: search
- Name: src_ip
- Apply to: `sourcetype=csv`
- Type: Inline
- Extraction: `| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"`

After saving, I validated it by running a count query and confirming the extracted IPs matched the raw event data exactly.

---

## 📊 Dashboards and Alerts

### Disconnect Events Dashboard

I built a dashboard around a specific event pattern: `Received disconnect from 112.95.230.3: 11: Bye Bye [preauth]`. This event appears when a connection is dropped before authentication completes, often a sign of automated probing.

```spl
source="openssh_log.csv" host="DESKTOP-GB191B6" index=*
Status="Received disconnect from 112.95.230.3: 11: Bye Bye [preauth]"
```

This returned **26 matching events**, which I visualized as a timeline panel on the dashboard.

### High-Frequency Offender Panel

I added a second panel to the dashboard showing the top attacking IPs filtered by count, giving a live view of the worst offenders at any point in time.

### Scheduled Alert Configuration

I configured a scheduled alert to automatically notify when brute-force thresholds were crossed:

- **Alert title:** failed login attempt
- **Trigger condition:** more than 5 failed login attempts
- **Schedule:** Cron expression `0 6 * * 1` (runs weekly)
- **Alert type:** Scheduled
- **Expiry:** 24 hours

I added all team email addresses as recipients and verified delivery by confirming the alert email arrived from `alerts@splunk...` with the correct alert title and result link.

---

## 🌐 Threat Intelligence Verification

Once I had the list of suspicious IPs, I went outside Splunk to validate them.

### AbuseIPDB

| IP | Reports | Confidence |
|----|---------|------------|
| 187.141.143.180 | 935 | 0% |
| 103.99.0.122 | 1 | 0% |
| 112.95.230.3 | Not found | N/A |
| 5.188.10.180 | Not found | N/A |

High report counts with 0% confidence suggests a lot of noise, but that doesn't make these IPs clean. It just means the reports lack strong consensus.

### VirusTotal

`183.62.140.253` was flagged by **Xcitium Verdict Cloud as malware-related**, while 94 other vendors marked it clean. One flag out of 95 vendors is a low signal on its own, but combined with 286 failed login attempts from that same IP, I classified it as high-risk.

### WHOIS

WHOIS confirmed `183.62.140.253` belongs to ChinaNet Guangdong with listed abuse contacts, which means it's traceable and reportable to the ISP if needed.

---

## 🧠 What the Data Told Me

Pulling everything together, here is how I classified the activity:

| Threat Category | Evidence | Example IPs |
|----------------|----------|-------------|
| Brute-force attacks | High failed login counts, sequential ports | 183.62.140.253, 187.141.143.180 |
| Distributed botnet traffic | Multiple international sources, data centers | 5.188.10.180, 103.99.0.122 |
| Noisy low-confidence reports | High report count, 0% abuse confidence | 187.141.143.180 |
| Malware-associated IP | Vendor flag combined with brute-force volume | 183.62.140.253 |
| Prevented intrusion | Zero successful root logins confirmed | All observed IPs |

The absence of any successful login is the most important finding. The attacks were real and persistent, but the defenses held.

---

## 🛠️ What I Would Recommend

Based on everything I found, these are the controls I would prioritize:

**Immediate:**
- Block the top offending IPs at the perimeter firewall
- Set `PermitRootLogin no` in `/etc/ssh/sshd_config`
- Deploy `fail2ban` configured to ban after 3 to 5 failed attempts within 5 minutes
- Disable password authentication entirely and enforce public key (PKI) only

**Short term:**
- Move SSH off port 22 to a non-standard port to reduce automated scanner noise
- Implement MFA for all SSH-capable accounts
- Restrict SSH access to known IPs or route it through a VPN

**Ongoing:**
- Weekly review of high-frequency IP offenders in Splunk
- Automate IP reputation enrichment using AbuseIPDB or AlienVault OTX lookup tables
- Build behavioral baselines so anomaly detection goes beyond static thresholds

---

## 💡 What I Practiced

- Splunk Cloud administration including user management, roles, and timezone configuration
- Log ingestion, source type configuration, and data integrity validation
- Writing SPL queries for authentication analysis and brute-force detection
- Regex-based field extraction to normalize raw log data
- Dashboard creation and scheduled alert configuration
- External threat intelligence verification using VirusTotal, AbuseIPDB, and WHOIS
- Threat classification and security recommendation writing

---

## ✅ Takeaways

The biggest thing this project reinforced is that raw logs are only useful if you know how to ask the right questions. Writing the SPL to extract IPs, grouping by frequency, correlating with usernames, and then going external to validate with VirusTotal and AbuseIPDB, that full chain is what turns log noise into an actual finding.

520 failed login attempts sounds alarming. Zero successful root logins is the reassuring punchline. But the work in between is what tells you whether to be worried or not.

**What I am working on next:**
- [ ] Build more advanced correlation searches using MITRE ATT&CK technique IDs
- [ ] Integrate automated threat intel lookups directly into Splunk via lookup tables
- [ ] Extend this lab using Elastic SIEM (ELK Stack) for a comparative analysis
