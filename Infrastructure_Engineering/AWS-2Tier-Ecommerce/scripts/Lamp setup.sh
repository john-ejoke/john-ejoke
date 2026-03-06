#!/bin/bash
# =============================================================================
# lamp-setup.sh
# PrestaShop 2-Tier AWS Deployment -- Web Tier Provisioning Script
# =============================================================================
# Author:  John Ejoke Oghenekewe
#          Cybersecurity Analyst | SOC Engineer | UTC+1
# Project: Architecting a Secure 2-Tier E-Commerce Infrastructure on AWS
# Target:  Ubuntu Server 24.04 LTS (ami-073130f74f5ffb161)
#          EC2 t3.micro -- eu-north-1 (Europe Stockholm)
#
# Purpose:
#   This script automates the complete Phase 3 web tier provisioning sequence.
#   It takes a fresh Ubuntu 24.04 EC2 instance from a clean SSH session to a
#   fully hardened, LAMP-equipped application server ready for PrestaShop
#   deployment. Every step mirrors the manual process documented in the README.
#
# Usage:
#   chmod +x lamp-setup.sh
#   ./lamp-setup.sh
#
# Prerequisites:
#   - Ubuntu 24.04 LTS EC2 instance running
#   - SSH access via: ssh -i SOC-Project-Key.pem ubuntu@<public-ip>
#   - PrestaShop-Web-SG attached (Port 80 open, Port 22 restricted to mgmt IP)
#   - RDS prestashop-database instance in Available state
# =============================================================================

set -euo pipefail
# set -e  : exit immediately if any command returns a non-zero status
# set -u  : treat unset variables as errors
# set -o pipefail : catch errors inside pipes, not just the last command

# -----------------------------------------------------------------------------
# CONFIGURATION
# Update these values before running in a new environment
# -----------------------------------------------------------------------------
PRESTASHOP_VERSION="8.1.5"
PRESTASHOP_ZIP="prestashop_${PRESTASHOP_VERSION}.zip"
PRESTASHOP_URL="https://github.com/PrestaShop/PrestaShop/releases/download/${PRESTASHOP_VERSION}/${PRESTASHOP_ZIP}"
WEB_ROOT="/var/www/html"
APP_DIR="${WEB_ROOT}/prestashop"
WEB_USER="www-data"

# -----------------------------------------------------------------------------
# LOGGING HELPER
# All steps echo with a timestamp so the output is readable as a run log
# -----------------------------------------------------------------------------
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "================================================================"
log " PrestaShop Web Tier Provisioning -- Starting"
log "================================================================"

# -----------------------------------------------------------------------------
# STEP 1: OS BASELINE HARDENING
# -----------------------------------------------------------------------------
# The first action on any new server is patching. Running a web application
# on an unpatched OS is not a security posture. apt update refreshes the
# package index. apt upgrade -y applies all available patches including kernel,
# libraries, and system binaries. This eliminates known CVEs before anything
# else is installed on top.
# -----------------------------------------------------------------------------
log "STEP 1: Running OS update and upgrade cycle..."
sudo apt update -y
sudo apt upgrade -y
log "OS baseline secured. All packages patched."

# -----------------------------------------------------------------------------
# STEP 2: LAMP STACK INSTALLATION
# -----------------------------------------------------------------------------
# Installing the core application environment:
#
#   apache2         -- the web server that will serve PrestaShop
#   mysql-client    -- needed to verify the RDS connection from the CLI
#   php8.3          -- PrestaShop 8.1.5 requires PHP 8.1 or higher
#   php8.3-mysql    -- PHP MySQL driver for RDS connectivity
#   php8.3-gd       -- image processing (product images in the storefront)
#   php8.3-xml      -- XML configuration and module parsing
#   php8.3-curl     -- outbound HTTP requests (payment gateways, APIs)
#   php8.3-mbstring -- multibyte string handling (international characters)
#   php8.3-intl     -- internationalisation support
#   php8.3-zip      -- zip archive handling for module installs
#   php8.3-opcache  -- PHP opcode caching for performance
#   unzip           -- needed to extract the PrestaShop archive
#
# All extensions are mandatory. PrestaShop's compatibility checker will
# block the installer if any are missing.
# -----------------------------------------------------------------------------
log "STEP 2: Installing LAMP stack and PHP extensions..."
sudo apt install -y \
  apache2 \
  mysql-client \
  php8.3 \
  php8.3-mysql \
  php8.3-gd \
  php8.3-xml \
  php8.3-curl \
  php8.3-mbstring \
  php8.3-intl \
  php8.3-zip \
  php8.3-opcache \
  unzip
log "LAMP stack installed. PHP 8.3 and all required extensions active."

# -----------------------------------------------------------------------------
# STEP 3: APACHE MODULE CONFIGURATION
# -----------------------------------------------------------------------------
# PrestaShop uses .htaccess files for URL rewriting (clean URLs like
# /category/product-name instead of /index.php?id=5). Apache's rewrite
# module must be explicitly enabled. Without it the storefront loads but
# all product and category links return 404 errors.
# Restarting Apache applies the module change immediately.
# -----------------------------------------------------------------------------
log "STEP 3: Enabling Apache mod_rewrite and restarting service..."
sudo a2enmod rewrite
sudo systemctl restart apache2
sudo systemctl enable apache2
log "mod_rewrite enabled. Apache restarted and set to start on boot."

# -----------------------------------------------------------------------------
# STEP 4: DOWNLOAD AND EXTRACT PRESTASHOP
# -----------------------------------------------------------------------------
# Downloading PrestaShop directly from the official GitHub release page
# ensures the archive is authentic and version-pinned. Extracting into
# /var/www/html/prestashop places the application in the correct web root
# for Apache to serve it. The working directory is set to the app directory
# for all subsequent operations.
# -----------------------------------------------------------------------------
log "STEP 4: Downloading PrestaShop ${PRESTASHOP_VERSION}..."
cd /tmp
wget -q "${PRESTASHOP_URL}" -O "${PRESTASHOP_ZIP}"
log "Download complete. Extracting to ${APP_DIR}..."
sudo mkdir -p "${APP_DIR}"
sudo unzip -q "${PRESTASHOP_ZIP}" -d "${APP_DIR}"
sudo unzip -q "${APP_DIR}/prestashop.zip" -d "${APP_DIR}" 2>/dev/null || true
sudo rm -f "${APP_DIR}/prestashop.zip" "${APP_DIR}/Install_PrestaShop.html"
log "PrestaShop extracted to ${APP_DIR}."

# -----------------------------------------------------------------------------
# STEP 5: FILESYSTEM PERMISSIONS -- THE FINAL PERMISSION LOCK
# -----------------------------------------------------------------------------
# This is the Principle of Least Privilege applied at the filesystem level.
#
# chown -R www-data:www-data
#   Transfers ownership of all application files to the Apache process user.
#   The web server can now read and write files it needs to (uploads, cache)
#   without running as root.
#
# chmod -R 755
#   Directories: rwxr-xr-x -- owner can write, everyone else can only read
#   and traverse. Files: rw-r--r-- at the file level via find below.
#
# This prevents an attacker who gains code execution through the web process
# from modifying core application files. The application logic is read-only
# from the perspective of any external process.
# -----------------------------------------------------------------------------
log "STEP 5: Applying filesystem permissions (chown + chmod)..."
sudo chown -R ${WEB_USER}:${WEB_USER} "${APP_DIR}"
sudo chmod -R 755 "${APP_DIR}"
log "Filesystem permissions locked. Principle of Least Privilege applied."

# -----------------------------------------------------------------------------
# STEP 6: APACHE VIRTUAL HOST CONFIGURATION
# -----------------------------------------------------------------------------
# Configuring Apache to allow .htaccess overrides for the PrestaShop
# directory. Without AllowOverride All, Apache ignores the .htaccess files
# that PrestaShop uses for URL rewriting and security headers, even with
# mod_rewrite enabled.
# -----------------------------------------------------------------------------
log "STEP 6: Configuring Apache for PrestaShop..."
sudo tee /etc/apache2/sites-available/prestashop.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot ${WEB_ROOT}

    <Directory ${APP_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/prestashop_error.log
    CustomLog \${APACHE_LOG_DIR}/prestashop_access.log combined
</VirtualHost>
EOF

sudo a2ensite prestashop.conf
sudo a2dissite 000-default.conf
sudo systemctl reload apache2
log "Apache virtual host configured and reloaded."

# -----------------------------------------------------------------------------
# STEP 7: VERIFY APACHE IS RUNNING
# -----------------------------------------------------------------------------
log "STEP 7: Verifying Apache service status..."
if sudo systemctl is-active --quiet apache2; then
  log "Apache is running. Web tier is live."
else
  log "ERROR: Apache is not running. Check /var/log/apache2/error.log"
  exit 1
fi

# -----------------------------------------------------------------------------
# STEP 8: POST-INSTALLATION SECURITY HARDENING
# -----------------------------------------------------------------------------
# After the PrestaShop web installer has been run through the browser,
# the install directory MUST be deleted. It contains scripts that could
# be used to reinstall or overwrite the application if left in place.
# This function is called manually after the browser-based installer
# completes, or can be run as: ./lamp-setup.sh --purge-install
# -----------------------------------------------------------------------------
purge_install_directory() {
  log "POST-INSTALL: Purging install directory..."
  if [ -d "${APP_DIR}/install" ]; then
    sudo rm -rf "${APP_DIR}/install"
    if [ ! -d "${APP_DIR}/install" ]; then
      log "Install directory purged and confirmed gone."
    else
      log "ERROR: Install directory still present. Remove manually."
    fi
  else
    log "Install directory already removed. Nothing to purge."
  fi
}

if [[ "${1:-}" == "--purge-install" ]]; then
  purge_install_directory
  exit 0
fi

# -----------------------------------------------------------------------------
# COMPLETION SUMMARY
# -----------------------------------------------------------------------------
log "================================================================"
log " Web Tier Provisioning Complete"
log "================================================================"
log ""
log " Apache:        $(apache2 -v 2>/dev/null | head -1)"
log " PHP:           $(php -v 2>/dev/null | head -1)"
log " App directory: ${APP_DIR}"
log " Web user:      ${WEB_USER}"
log ""
log " Next steps:"
log "   1. Navigate to http://<public-ip>/prestashop/install"
log "   2. Complete the PrestaShop browser installer"
log "   3. Point the database host to your RDS endpoint"
log "   4. Use DB name: prestashop, DB user: admin"
log "   5. After installation completes, run:"
log "      ./lamp-setup.sh --purge-install"
log ""
log " RDS Security reminder:"
log "   Ensure PrestaShop-DB-SG inbound rule allows Port 3306"
log "   from PrestaShop-Web-SG only. No public access."
log "================================================================"
