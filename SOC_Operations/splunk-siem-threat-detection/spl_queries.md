# SPL Query Reference
### SIEM Threat Detection with Splunk Cloud
**Author:** Ejoke John | Cybersecurity Analyst

All queries used during the SSH brute-force investigation, documented with context on what each one was trying to find.

## 1. Data Validation

Ran this first to confirm the OpenSSH log was correctly ingested before writing any detection logic.
```spl
index=main "Failed password"
```

## 2. Failed Login Attempts

Starting point for the investigation. Returns every failed SSH authentication event in the log.
```spl
index=main "Failed password"
```

**Result: 520 events**

## 3. Extract Source IPs and Rank by Frequency

The raw log did not have source IP as a structured field. This extracts it using regex and filters to IPs with more than 10 failed attempts.
```spl
index=main "Failed password"
| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| where count > 10
```

| IP Address | Failed Attempts | Origin |
|------------|----------------|--------|
| 183.62.140.253 | 286 | China, ChinaNet Shenzhen |
| 187.141.143.180 | 80 | Mexico, Uninet S.A. de C.V. |
| 103.99.0.122 | 46 | Vietnam, VPSONLINE Ltd. |
| 112.95.230.3 | 26 | China, China Unicom Guangdong |
| 5.188.10.180 | 18 | Russia, Petersburg Internet Network |
| 185.190.58.151 | 17 | Unknown origin |

## 4. Check for Successful Root Logins

The most important question after finding all those failures: did any of them get in?
```spl
index=* "Accepted password for root"
| rex "from\s+(?<src_ip>\d{1,3}(\.\d{1,3}){3})"
| stats dc(src_ip) AS unique_root_ips
```

**Result: zero successful root logins**

## 5. Correlate IPs with Targeted Usernames

Reveals which accounts each attacking IP was going after. This is where the dictionary-based attack pattern became clear.
```spl
index=main "Failed password"
| stats count by src_ip, user
```

Key findings:
- `183.62.140.253` targeted `root` almost exclusively
- `185.190.58.151` cycled through `admin` and `api`
- `5.188.10.180` probed `guest`, `ftp`, and `default`

## 6. Compare Failed vs Successful Root Logins

Side-by-side view to confirm no successful compromise alongside the failures.
```spl
index=* ("Failed password for root" OR "Accepted password for root")
| stats count by src_ip, user
```

## 7. Disconnect Events Dashboard Query

Isolates preauth disconnect events from a specific IP. A `[preauth]` disconnect means the connection dropped before credentials were exchanged, a common sign of automated scanning.
```spl
source="openssh_log.csv" host="DESKTOP-GB191B6" index=*
Status="Received disconnect from 112.95.230.3: 11: Bye Bye [preauth]"
```

**Result: 26 matching events** (powers the disconnect events dashboard panel)

## 8. High-Frequency Offender Dashboard Query

Powers the live attacking IPs panel on the dashboard so any analyst sees the top offenders without running a query manually.
```spl
index=main "Failed password"
| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| where count > 10
```

## 9. Field Extraction Validation

After configuring the persistent `src_ip` field extraction, I ran this to confirm extracted values matched raw event frequency exactly.
```spl
index=main "Failed password"
| stats count by src_ip
```

## 10. Scheduled Alert Base Query

The underlying query powering the automated brute-force alert. Triggers when any IP crosses 5 failed attempts.
```spl
index=main "Failed password"
| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
| where count > 5
```

| Setting | Value |
|---------|-------|
| Title | failed login attempt |
| Trigger | Results count greater than 5 |
| Alert type | Scheduled |
| Cron schedule | `0 6 * * 1` |
| Expiry | 24 hours |

## Field Extraction Configuration

Saved as a persistent extraction so `src_ip` is always available as a structured field without inline regex on every query.

| Setting | Value |
|---------|-------|
| Name | src_ip |
| Destination App | search |
| Apply To | sourcetype = csv |
| Type | Inline |
| Regex | `(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})` |

## Notes

- All queries run against `index=main` unless otherwise specified
- Log source: `openssh_log.csv` with `sourcetype=csv`
- Regex pattern matches standard IPv4 address format
- Threshold of 10 used for high-frequency IP detection
- Threshold of 5 used for the scheduled alert trigger
- Zero successful root logins confirmed across every query
