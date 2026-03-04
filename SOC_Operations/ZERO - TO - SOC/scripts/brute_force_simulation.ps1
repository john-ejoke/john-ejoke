# ============================================================
# Brute Force Simulation Script
# Project   : ZERO-TO-SOC
# Author    : John Ejoke Oghenekewe
# Purpose   : Simulate a brute-force attack against a local
#             Windows target to validate Wazuh detection and
#             Tines automated alert response pipeline
# WARNING   : For use in isolated lab environments only.
#             Do not run on production systems.
# ============================================================

# Step 1: Privilege Escalation Attempt
# Adds the guest account to the Administrators group
# This triggers Wazuh to log a suspicious privilege change

Write-Host "Attempting privilege escalation..." -ForegroundColor Yellow
net localgroup Administrators /add guest
Write-Host "Privilege escalation attempt sent." -ForegroundColor Green

# Step 2: Brute-Force Authentication Loop
# Fires 50 failed SMB authentication attempts against localhost
# Each attempt uses a wrong password to generate Event ID 4625
# Wazuh correlates repeated failures and fires Rule 60204
# at Level 10 (Multiple Windows Logon Failures)

Write-Host ""
Write-Host "Starting brute-force loop (50 attempts)..." -ForegroundColor Yellow
Write-Host ""

for ($i = 1; $i -le 50; $i++) {
    net use \\127.0.0.1\c$ /user:Administrator "WrongPass$i" 2>$null
    Write-Host "Nuclear Attempt $i sent..." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Simulation complete. Check Wazuh Threat Hunting dashboard." -ForegroundColor Green
Write-Host "Expected: Level 10 alert - Multiple Windows Logon Failures (Rule 60204)" -ForegroundColor Green
Write-Host "Expected: Tines webhook fires and email lands in analyst inbox." -ForegroundColor Green
