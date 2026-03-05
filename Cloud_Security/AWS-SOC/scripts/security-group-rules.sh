#!/bin/bash
# security-group-rules.sh
# AWS-SOC Project: Phase 2 Infrastructure and Network Telemetry
# Purpose: Create the SOC-Victim-SG security group with Principle of Least Privilege
#          ingress rules. SSH restricted to admin IP only. HTTP open for attack surface.
#
# Prerequisites:
#   - AWS CLI installed and configured (aws configure)
#   - IAM permissions: ec2:CreateSecurityGroup, ec2:AuthorizeSecurityGroupIngress
#   - Your admin IP address (run: curl ifconfig.me)
#
# Usage:
#   chmod +x security-group-rules.sh
#   ./security-group-rules.sh

set -euo pipefail

# Configuration - update these before running
AWS_REGION="eu-north-1"
VPC_ID="vpc-0593fa8a0cec6506a"          # Replace with your VPC ID
ADMIN_IP=$(curl -s ifconfig.me)/32       # Auto-detects your current public IP
SG_NAME="SOC-Victim-SG"
SG_DESCRIPTION="Allow SSH from Admin IP and HTTP from Everywhere"

echo "=== AWS-SOC Security Group Creation ==="
echo "Region:      $AWS_REGION"
echo "VPC:         $VPC_ID"
echo "Admin IP:    $ADMIN_IP"
echo "SG Name:     $SG_NAME"
echo "========================================"

# Create the security group
echo "[1/3] Creating security group..."
SG_ID=$(aws ec2 create-security-group \
  --group-name "$SG_NAME" \
  --description "$SG_DESCRIPTION" \
  --vpc-id "$VPC_ID" \
  --region "$AWS_REGION" \
  --query 'GroupId' \
  --output text)

echo "    Security Group ID: $SG_ID"

# Add SSH ingress rule - Admin IP only (Principle of Least Privilege)
echo "[2/3] Adding SSH rule (Admin IP only: $ADMIN_IP)..."
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "$ADMIN_IP" \
  --region "$AWS_REGION"

echo "    SSH (port 22) restricted to: $ADMIN_IP"

# Add HTTP ingress rule - open to all (intentional attack surface for SOC monitoring)
echo "[3/3] Adding HTTP rule (public access for attack surface simulation)..."
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 80 \
  --cidr "0.0.0.0/0" \
  --region "$AWS_REGION"

echo "    HTTP (port 80) open to: 0.0.0.0/0"

echo ""
echo "=== Security Group Created ==="
echo "Security Group ID: $SG_ID"
echo "Name:              $SG_NAME"
echo ""
echo "Inbound Rules:"
echo "  SSH  (22/tcp) <- $ADMIN_IP   [Admin only]"
echo "  HTTP (80/tcp) <- 0.0.0.0/0  [Public - intentional attack surface]"
echo ""
echo "Engineering Note:"
echo "  All other ports are implicitly denied. No egress restrictions are"
echo "  applied by default in AWS (outbound is open). For a hardened"
echo "  production environment, add explicit egress rules."
echo ""
echo "Next Step: Attach this security group when launching the EC2 instance."
echo "  SG ID to use: $SG_ID"

exit 0
