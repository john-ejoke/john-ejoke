# SOC Home Lab Build & Documentation

**Author:** Ejoke John Oghenekewe
**Role:** Cybersecurity Analyst
**LinkedIn:** [linkedin.com/in/john-ejoke](https://www.linkedin.com/in/john-ejoke/)
**Domain:** SOC Operations

---

![Splunk Lifecycle](assets/splunk_lifecycle.png)

## Overview

I built this SOC home lab from scratch to get hands-on experience with the full log monitoring pipeline — from endpoint telemetry collection through to real-time analysis in a SIEM. The lab runs on my physical laptop using VirtualBox, with three purpose-built VMs handling distinct roles: attacker, victim, and SIEM. Alongside the VirtualBox environment, I also deployed Splunk Enterprise natively on Kali Linux and configured a Universal Forwarder to ship live system logs directly into it — giving me two parallel Splunk deployments to work with and compare.

Everything documented here was built, configured, and tested by me. No pre-built OVAs, no shortcuts.

---

## Host Machine Specs

| Component | Detail |
|---|---|
| Device | Dell Latitude 7400 |
| Processor | Intel Core i7-8665U |
| RAM | 16GB |
| Storage | 512GB SSD |
| OS | Windows 11 Pro |
| Hypervisor | VirtualBox |

---

## Lab Architecture

![Lab Topology](assets/topology.png)

All three VMs sit on a VirtualBox internal network named **SOC-Lab** with the subnet `192.168.100.0/24`. None of them have direct internet access — traffic is isolated to the lab network. Each machine has a defined role:

| VM | IP Address | Role |
|---|---|---|
| Kali Linux | 192.168.100.10 | Attacker |
| Windows 10 | 192.168.100.11 | Victim endpoint |
| Ubuntu 22.04 | 192.168.100.12 | SIEM (Splunk Enterprise) |

![VirtualBox VM List](assets/vbox_vm_list.png)
![Host-Only Network Config](assets/vbox_host_only_network.png)

---

## Environment Setup

### Kali Linux — Attacker Machine

Kali serves as the attacker node. I configured its network adapter to the internal SOC-Lab network so all attack traffic stays contained within the lab.

![Kali Network Adapter](assets/kali_network_adapter.png)
![Kali Tools Installed](assets/kali_tools_installed.png)

### Windows 10 — Victim Endpoint

The Windows 10 VM is the target. I installed two monitoring agents on it:

- **Sysmon v15.15** — for deep endpoint telemetry (process creation, network connections, process access)
- **Splunk Universal Forwarder** — to ship Sysmon and Windows Event logs to the SIEM

![Sysmon Install via PowerShell](assets/sysmon_install_powershell.png)
![Sysmon Config Rules](assets/sysmon_config_rules.png)

### Ubuntu 22.04 — SIEM

Ubuntu hosts Splunk Enterprise, listening on port `8000` for the web interface and port `9997` to receive forwarded logs from endpoints.

![Splunk Install Terminal](assets/splunk_install_terminal.png)
![Splunk Web Login](assets/splunk_web_login.png)

---

## Splunk Universal Forwarder — Windows 10 Configuration

I installed the Splunk Universal Forwarder on the Windows 10 victim machine and configured it to forward logs to the Ubuntu SIEM at `192.168.100.12:9997`.

![Splunk UF Install](assets/splunk_uf_install.png)

### inputs.conf

The `inputs.conf` file tells the forwarder what to collect. I configured it to monitor the Windows Event Log channels most relevant to endpoint detection — Security, System, and the Sysmon operational channel.

![inputs.conf](assets/splunk_inputs_conf.png)

### outputs.conf

The `outputs.conf` file points the forwarder at the receiving indexer — in this case the Ubuntu SIEM on port `9997`.

![outputs.conf](assets/splunk_outputs_conf.png)

---

## Splunk Enterprise — Native Kali Deployment

In addition to the Ubuntu-based SIEM, I also deployed Splunk Enterprise directly on Kali Linux to practice the full installation workflow on a Linux host and test a second forwarding configuration.

### Downloading Splunk Enterprise

I navigated to the Splunk Enterprise download page and selected the Linux package matching my architecture. I used the `wget` link to pull it directly from the terminal.

![Splunk Enterprise Download Page](assets/Splunk_Ent__download_page.jpg)

### Starting Splunk Enterprise

After installation, I started Splunk using `sudo /opt/splunk/bin/splunk start`, accepted the license agreement, and created admin credentials. The startup output confirmed all ports were open and the web server was available at `http://127.0.0.1:8000`.

![Starting Splunk Enterprise](assets/starting_splunk_ent_.jpg)

### Accessing Splunk Web

With the service running, I accessed the Splunk Web Interface at `http://kali:8000` using my admin credentials.

![Splunk Web Login](assets/splunk_web_login_kali.png)
![Splunk Web Dashboard](assets/splunk_web_dashboard.png)

### Downloading and Installing the Universal Forwarder

I downloaded the Splunk Universal Forwarder using `wget` — the 130MB `.tgz` package for Linux AMD64. After extracting and installing it, I accepted the license agreement and set up admin credentials.

![Downloading and Installing UF](assets/downloading_and_installing_UF.jpg)

### Configuring the Universal Forwarder

I configured the forwarder to ship logs to the local Splunk Enterprise instance on port `9997`, then added `/var/log` as the monitored directory for real-time log collection. After applying the settings I restarted the forwarder to confirm everything was active.

![Configuring Splunk UF](assets/configuring_splunk_UF.jpg)

---

## Wireshark — Interface Verification

Before running attacks, I verified that Wireshark could see traffic on the lab network interfaces.

![Wireshark Interfaces](assets/wireshark_interfaces.png)

---

## Attack Simulation — Nmap Reconnaissance

With the lab fully operational, I launched a reconnaissance scan from the Kali attacker machine against the Windows 10 victim:

```bash
nmap -Pn -p 445,3389,80 192.168.100.11
```

I targeted ports 445 (SMB), 3389 (RDP), and 80 (HTTP) — three ports commonly probed during the initial access phase of an attack.

![Kali Nmap Attack](assets/kali_nmap_attack.png)

---

## Detection in Splunk — Windows 10 Endpoint

### Querying the Events

After the scan, I ran `index=main` in the Search & Reporting app on the Ubuntu SIEM to pull all indexed events.

![Splunk Search Query](assets/splunk_search_query.png)

### Results — 1,435 Events Indexed

The query returned **1,435 events** from the Windows 10 endpoint, confirming the UF was shipping logs successfully.

![Splunk Events Overview](assets/splunk_event_1_3_10.png)

### Sysmon EventCode Breakdown

Three Sysmon event codes confirmed the nmap scan was captured end to end:

**EventCode 1 — Process Creation**
Sysmon recorded the process that initiated the scan activity on the victim host.

![Sysmon EventCode 1](assets/sysmon_eventcode_1.png)

**EventCode 3 — Network Connection**
Outbound network connection events showed the specific ports being probed, with source and destination IPs logged.

![Sysmon EventCode 3](assets/sysmon_eventcode_3.png)

**EventCode 10 — Process Access**
Process access events showed inter-process activity triggered as a result of the scan.

![Sysmon EventCode 10](assets/sysmon_eventcode_10.png)

---

## Real-Time Logs — Kali Native Deployment

On the Kali-native Splunk instance, running `index=main` returned **20,089 events** from the `/var/log` directory over a 24-hour window, across 10 sources and 9 source types. This confirmed the Universal Forwarder was actively shipping live system logs into the local Splunk Enterprise instance.

![Real-Time Logs from Kali](assets/real_time_logs_from_kali.jpg)

The logs included Xorg display server events, VirtualBox integration messages, and kernel-level activity — all the background telemetry a real analyst learns to distinguish from actual security-relevant events.

---

## Snapshots — Lab State Preservation

After verifying everything worked, I took snapshots of all three VMs to preserve the clean baseline state. This means I can revert after any destructive test and return to a known-good configuration.

![Windows Snapshot](assets/snapshot_windows.png)
![Ubuntu Snapshot](assets/snapshot_ubuntu.png)
![Kali Snapshot](assets/snapshot_kali.png)

---

## Splunk Cloud — Additional Exposure

Beyond the on-premise lab setup, I also created a Splunk Cloud account to familiarise myself with the managed platform. Understanding both deployment models — self-hosted Enterprise and cloud-managed — reflects how organisations actually operate Splunk at scale.

![Accessing Splunk Cloud](assets/Accessing_splunk_cloud.png)

---

## Key Takeaways

Running this lab gave me practical experience across the full SOC toolchain:

- Deploying and configuring Splunk Enterprise in two different environments (Ubuntu SIEM and native Kali)
- Installing and tuning Sysmon for meaningful endpoint telemetry
- Configuring Universal Forwarders on both Windows and Linux hosts
- Writing and running SPL queries to surface real events
- Understanding the difference between noise (Xorg, VirtualBox messages) and security-relevant log entries
- Preserving lab state with snapshots for repeatable testing

---

---

## Future Additions

- `configs/` folder — `sysmonconfig.xml`, `inputs.conf`, `outputs.conf`
- Suricata IDS rules and alert configuration
- Cowrie honeypot setup and log integration
- Custom SPL detection rules for common attack patterns
