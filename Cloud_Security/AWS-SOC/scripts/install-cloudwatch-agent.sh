#!/bin/bash
# install-cloudwatch-agent.sh
# AWS-SOC Project: Phase 3 Host-Level Detection
# Purpose: Download, install, configure, and activate the Amazon CloudWatch Agent
#          on Ubuntu 24.04 LTS to stream /var/log/auth.log to CloudWatch.
#
# Prerequisites:
#   - EC2 instance with SOC-Host-Logging-Role IAM instance profile attached
#   - Ubuntu 24.04 LTS (Noble Numbat) or Ubuntu 22.04 LTS
#   - Outbound internet access to S3 (or VPC endpoint for S3)
#
# Usage:
#   chmod +x install-cloudwatch-agent.sh
#   sudo ./install-cloudwatch-agent.sh

set -euo pipefail

echo "=== AWS-SOC CloudWatch Agent Installation ==="
echo "Phase 3: Host-Level Detection"
echo "============================================="

# Update package list
echo "[1/6] Updating package lists..."
sudo apt-get update -y

# Install required dependencies
echo "[2/6] Installing dependencies..."
sudo apt-get install -y wget curl jq

# Download the CloudWatch Agent .deb package
echo "[3/6] Downloading Amazon CloudWatch Agent..."
AGENT_URL="https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
wget -O /tmp/amazon-cloudwatch-agent.deb "$AGENT_URL"

# Verify the download completed successfully
FILE_SIZE=$(stat -c%s /tmp/amazon-cloudwatch-agent.deb)
echo "    Downloaded: ${FILE_SIZE} bytes"

if [ "$FILE_SIZE" -lt 1000000 ]; then
  echo "ERROR: Download appears incomplete. File size too small."
  exit 1
fi

# Install the package
echo "[4/6] Installing CloudWatch Agent package..."
sudo dpkg -i -E /tmp/amazon-cloudwatch-agent.deb

# Verify installation
echo "[5/6] Verifying installation..."
if ! command -v /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl &> /dev/null; then
  echo "ERROR: CloudWatch Agent control utility not found after installation."
  exit 1
fi

AGENT_VERSION=$(/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent --version 2>&1 || echo "version check not available")
echo "    Agent installed: $AGENT_VERSION"

# Copy the agent config to the expected location
echo "[6/6] Applying agent configuration..."
CONFIG_SOURCE="./configs/cloudwatch-agent-config.json"

if [ -f "$CONFIG_SOURCE" ]; then
  sudo cp "$CONFIG_SOURCE" /opt/aws/amazon-cloudwatch-agent/bin/config.json
  echo "    Config applied from: $CONFIG_SOURCE"
else
  echo "WARNING: Config file not found at $CONFIG_SOURCE"
  echo "    Run the CloudWatch Agent wizard manually:"
  echo "    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard"
  echo "    Or create the config at /opt/aws/amazon-cloudwatch-agent/bin/config.json manually."
fi

echo ""
echo "=== Starting CloudWatch Agent ==="
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json

echo ""
echo "=== Verifying Agent Status ==="
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -m ec2 \
  -a status

echo ""
echo "=== Installation Complete ==="
echo "Next steps:"
echo "  1. Wait 2-3 minutes for initial log ingestion"
echo "  2. Check CloudWatch Logs console for the 'SOC-Auth-Logs' log group"
echo "  3. Verify log stream named after this instance ID is present"
echo "  4. Run validate-pipeline.sh to confirm end-to-end data flow"

# Cleanup
rm -f /tmp/amazon-cloudwatch-agent.deb

exit 0
