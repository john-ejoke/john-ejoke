
#!/bin/bash
# ─────────────────────────────────────────────────────────
# SOC Lab — EC2 Bootstrap Script
# Runs at instance launch via Terraform user_data
# Deploys: Wazuh Agent + Apache2 vulnerability target
# ─────────────────────────────────────────────────────────

set -e
LOG="/var/log/soc_deploy_status.log"
echo "Bootstrap started at $(date)" >> $LOG

# ─── 1. System Update ────────────────────────────────────
apt-get update -y >> $LOG 2>&1
echo "System updated" >> $LOG

# ─── 2. Install Wazuh Agent ──────────────────────────────
# Import GPG key
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import

chmod 644 /usr/share/keyrings/wazuh.gpg

# Add Wazuh repository
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  tee /etc/apt/sources.list.d/wazuh.list

apt-get update -y >> $LOG 2>&1

# Install pinned version — MUST match Wazuh Manager version
WAZUH_MANAGER='100.83.231.37' \
WAZUH_AGENT_NAME='Tokyo-SOC-Node' \
apt-get install wazuh-agent=4.9.2-1 -y >> $LOG 2>&1

# Pin version — prevent auto-upgrade drift
apt-mark hold wazuh-agent >> $LOG 2>&1

# Enable and start
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
echo "Wazuh agent deployed and started" >> $LOG

# ─── 3. Install Apache — Vulnerability Target ────────────
apt-get install -y apache2 >> $LOG 2>&1
systemctl enable apache2
systemctl start apache2
echo "Apache2 deployed on port 80" >> $LOG

# ─── 4. Install Tailscale ────────────────────────────────
# Tailscale allows cross-NAT connectivity to on-prem manager
curl -fsSL https://tailscale.com/install.sh | sh >> $LOG 2>&1
echo "Tailscale installed — run: sudo tailscale up" >> $LOG

# ─── 5. Deploy Status ────────────────────────────────────
echo "Deployment complete at $(date)" >> $LOG
echo "Public IP: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)" >> $LOG
