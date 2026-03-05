# Honeypot Deployment Steps

Step-by-step reproduction guide for deploying T-Pot 24.04.1 on AWS EC2.

**Requirements:** AWS account, Kali Linux (or any Linux terminal), ~30 minutes setup time

---

## 1. AWS Account and EC2 Instance

1. Register at [aws.amazon.com](https://aws.amazon.com) and navigate to the EC2 dashboard
2. Set your region to **Asia Pacific (Tokyo)** `ap-northeast-1` (or your preferred region)
3. Click **Launch Instance**
4. Under AMI, search the AWS Marketplace for **Debian 11** — do not use Debian 12 (T-Pot incompatible)
5. Select instance type **t2.large** (2 vCPU, 8 GiB RAM — minimum required for T-Pot)
6. Create a new **RSA key pair** in `.pem` format and save it to your local machine
7. Under Network Settings, set SSH source to **My IP only**
8. Set storage to **128 GiB gp2** EBS volume
9. Click **Launch Instance**

---

## 2. Security Group Inbound Rules

Navigate to your instance → Security tab → Edit inbound rules. Add three rules:

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| Custom TCP | 64295 | My IP | T-Pot management SSH |
| Custom TCP | 64297 | My IP | Kibana web dashboard |
| Custom TCP | 1 - 6400 | 0.0.0.0/0 | Honeypot trap (internet-facing) |

> The 1-6400 range is intentionally open to the entire internet. This is the trap surface.

---

## 3. SSH Into the Instance

From your terminal:

```bash
cd ~/Desktop                          # navigate to where your .pem file is saved
chmod 400 "key.pem"                   # lock down key permissions (required by SSH)
ssh -i "key.pem" admin@<your-ec2-public-dns>
```

Replace `<your-ec2-public-dns>` with the Public DNS shown in your EC2 console.

Successful connection will show: `admin@ip-172-31-XX-X:~$`

---

## 4. Install T-Pot

```bash
sudo apt update
sudo apt install git -y
git clone https://github.com/telekom-security/tpotce.git
cd tpotce
./install.sh
```

When prompted `Install? (y/n)` → type `y` and press Enter.

The installer will pull all Docker images automatically (~323 MB). This takes 5–10 minutes depending on connection speed. No manual daemon configuration is needed.

---

## 5. Reboot and Reconnect

Once installation completes:

```bash
sudo reboot
```

Wait ~60 seconds, then reconnect on T-Pot's dedicated management port:

```bash
ssh -i "key.pem" admin@<your-ec2-public-dns> -p 64295
```

> T-Pot moves SSH from port 22 to port 64295 during installation. Always use `-p 64295` after this point.

---

## 6. Access the T-Pot Web Interface

Open a browser and navigate to:

```
https://<your-ec2-public-ip>:64297
```

Accept the self-signed certificate warning. Log in with the credentials you set during installation.

The T-Pot landing page gives you access to:

- **Attack Map**: - real-time geolocation of incoming attacks
- **Kibana**: - full dashboard with attack breakdowns, histograms, and CVE detections
- **Elasticvue**: - direct Elasticsearch browser
- **Spiderfoot**: - OSINT and IP enrichment
- **Cyberchef**: - data decoding and analysis

---

## 7. Monitor Attacks

Open the **Attack Map** first. Within minutes you will see incoming connections plotted on the globe.

Open **Kibana** → T-Pot dashboard for structured data: attack counts by honeypot, by country, by destination port, and Suricata CVE alerts.

The honeypot is fully passive. No interaction is required - it captures everything automatically.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| T-Pot install fails | Confirm you are using Debian 11, not Debian 12 |
| Services crash on startup | Instance RAM too low - use t2.large minimum |
| Cannot reach Kibana | Check security group has port 64297 open to My IP |
| SSH refused after reboot | Use `-p 64295` - T-Pot changes the default SSH port |
| No attacks appearing | Confirm port range 1-6400 is open to 0.0.0.0/0 in security group |

---

## Cost Estimate

| Resource | Cost |
|----------|------|
| t2.large EC2 instance | ~$0.094/hr |
| 128 GiB gp2 EBS storage | ~$0.10/GB/month |
| 4-hour session total | < $1.00 |

> Terminate the instance when done to avoid ongoing charges.
