#!/bin/bash
# validate-pipeline.sh
# AWS-SOC Project: Phase 4 Threat Simulation and Incident Response
# Purpose: End-to-end smoke test of the detection and alerting pipeline.
#          Generates synthetic failed SSH events on the host and verifies
#          they propagate through CloudWatch to alarm state.
#
# Run this ON the SOC-Victim-Host after completing Phase 3 setup.
#
# Prerequisites:
#   - CloudWatch Agent running and streaming SOC-Auth-Logs
#   - Metric Filter "Failed-SSH-Attempts" configured on SOC-Auth-Logs
#   - CloudWatch Alarm "SOC-Brute-Force-Alert" configured (threshold >= 3 in 1 min)
#   - SNS subscription confirmed for alert notifications
#
# Usage:
#   chmod +x validate-pipeline.sh
#   sudo ./validate-pipeline.sh

set -euo pipefail

LOG_FILE="/var/log/auth.log"
ALARM_NAME="SOC-Brute-Force-Alert"
LOG_GROUP="SOC-Auth-Logs"
TRIGGER_COUNT=5    # Number of synthetic events to generate (above threshold of 3)
WAIT_SECONDS=90    # Time to wait for metric to propagate before checking

echo "=== AWS-SOC Pipeline Validation ==="
echo "This script validates the full detection pipeline by injecting"
echo "synthetic authentication failure events into $LOG_FILE."
echo ""
echo "Expected flow:"
echo "  auth.log -> CloudWatch Agent -> SOC-Auth-Logs -> Metric Filter"
echo "  -> FailedPasswordCount metric -> SOC-Brute-Force-Alert -> SNS Email"
echo "===================================="
echo ""

# Step 1: Confirm the CloudWatch Agent is running
echo "[Step 1] Checking CloudWatch Agent status..."
AGENT_STATUS=$(sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -m ec2 -a status 2>&1 | grep -o '"status": "[^"]*"' | head -1 || echo "unknown")

echo "    Agent status: $AGENT_STATUS"

if echo "$AGENT_STATUS" | grep -q "running"; then
  echo "    Agent is running. Continuing..."
else
  echo "    WARNING: Agent may not be running. Check agent status before proceeding."
  echo "    To start: sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json"
fi

echo ""

# Step 2: Record baseline timestamp
BASELINE_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[Step 2] Baseline timestamp: $BASELINE_TIME"
echo ""

# Step 3: Inject synthetic failed authentication events
echo "[Step 3] Injecting $TRIGGER_COUNT synthetic failed authentication events..."
echo "    These are written directly to $LOG_FILE and are indistinguishable"
echo "    from real failed SSH attempts to the metric filter."
echo ""

FAKE_IP="203.0.113.99"  # TEST-NET-3 range (RFC 5737) - documentation use only

for i in $(seq 1 $TRIGGER_COUNT); do
  TIMESTAMP=$(date "+%b %d %H:%M:%S")
  FAKE_PORT=$((50000 + RANDOM % 10000))
  
  # Simulate an "Invalid user" event
  echo "$TIMESTAMP ip-$(hostname -I | awk '{print $1}' | tr '.' '-') sshd[$$]: Invalid user testuser from $FAKE_IP port $FAKE_PORT" \
    | sudo tee -a "$LOG_FILE" > /dev/null
  
  # Simulate a "Failed password" event for the same attempt
  echo "$TIMESTAMP ip-$(hostname -I | awk '{print $1}' | tr '.' '-') sshd[$$]: Failed password for invalid user testuser from $FAKE_IP port $FAKE_PORT ssh2" \
    | sudo tee -a "$LOG_FILE" > /dev/null
  
  echo "    Injected event $i of $TRIGGER_COUNT (source: $FAKE_IP port $FAKE_PORT)"
  sleep 1
done

echo ""
echo "    $TRIGGER_COUNT events injected. Waiting $WAIT_SECONDS seconds for metric propagation..."
echo ""

# Step 4: Wait for propagation
for remaining in $(seq $WAIT_SECONDS -10 0); do
  echo -ne "    Time remaining: ${remaining}s \r"
  sleep 10
done
echo ""
echo ""

# Step 5: Verify log events appeared in CloudWatch
echo "[Step 4] Check the following in your AWS console:"
echo ""
echo "    a) CloudWatch Logs > Log groups > SOC-Auth-Logs"
echo "       Look for recent events containing 'Invalid user testuser from 203.0.113.99'"
echo ""
echo "    b) CloudWatch > Alarms > SOC-Brute-Force-Alert"
echo "       The alarm should have transitioned to ALARM state"
echo ""
echo "    c) Your email inbox"
echo "       An SNS notification from AWS Notifications should have arrived"
echo "       Subject: ALARM: 'SOC-Brute-Force-Alert' in EU (Stockholm)"
echo ""

# Step 6: Cleanup note
echo "[Step 5] Cleanup"
echo "    The synthetic log lines were written to $LOG_FILE."
echo "    They will rotate out naturally. If you want to remove them now:"
echo "    sudo grep -v '203.0.113.99' $LOG_FILE > /tmp/auth.log.clean"
echo "    sudo mv /tmp/auth.log.clean $LOG_FILE"
echo ""
echo "=== Validation Complete ==="
echo "If you received an email alert, the full pipeline is confirmed working."
echo "MTTD (Mean Time to Detect) = time from last injection to email receipt."

exit 0
