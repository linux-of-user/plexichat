# HTTPS Setup Guide for PlexiChat

This guide provides comprehensive instructions for setting up HTTPS/TLS encryption in PlexiChat, including development certificates, production Let's Encrypt certificates, quantum-ready TLS configurations, and advanced security features.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Development Setup (Self-Signed Certificates)](#development-setup-self-signed-certificates)
3. [Production Setup (Let's Encrypt)](#production-setup-lets-encrypt)
4. [Quantum-Ready TLS Configuration](#quantum-ready-tls-configuration)
5. [Certificate Management](#certificate-management)
6. [Security Best Practices](#security-best-practices)
7. [Load Balancer Integration](#load-balancer-integration)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Configuration](#advanced-configuration)

## Quick Start

For immediate HTTPS setup in development:

```bash
# Generate self-signed certificate
cd plexichat
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"

# Update configuration
echo "ssl_enabled: true" >> config/network.yaml
echo "ssl_cert_path: certs/cert.pem" >> config/network.yaml
echo "ssl_key_path: certs/key.pem" >> config/network.yaml

# Start PlexiChat
python run.py
```

Your PlexiChat instance will be available at `https://localhost:8080` (you'll need to accept the browser security warning for self-signed certificates).

## Development Setup (Self-Signed Certificates)

### 1. Generate Self-Signed Certificate

Create a development certificate with Subject Alternative Names (SAN) for multiple domains:

```bash
# Create certificate directory
mkdir -p certs

# Create OpenSSL configuration file
cat > certs/openssl.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Development
O = PlexiChat Development
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = 127.0.0.1
DNS.4 = plexichat.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
    -days 365 -nodes -config certs/openssl.conf -extensions v3_req

# Set appropriate permissions
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

### 2. Configure PlexiChat for Development HTTPS

Update your configuration file (`config/unified_config.yaml` or environment variables):

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "certs/cert.pem"
  ssl_key_path: "certs/key.pem"
  tls_version: "TLSv1.3"
  tls_ciphers: "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

Or using environment variables:

```bash
export PLEXICHAT_SSL_ENABLED=true
export PLEXICHAT_SSL_CERT_PATH=certs/cert.pem
export PLEXICHAT_SSL_KEY_PATH=certs/key.pem
export PLEXICHAT_TLS_VERSION=TLSv1.3
```

### 3. Trust Development Certificate (Optional)

To avoid browser warnings, add the certificate to your system's trust store:

**Linux (Ubuntu/Debian):**
```bash
sudo cp certs/cert.pem /usr/local/share/ca-certificates/plexichat-dev.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/cert.pem
```

**Windows (PowerShell as Administrator):**
```powershell
Import-Certificate -FilePath "certs\cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

## Production Setup (Let's Encrypt)

### 1. Prerequisites

- Domain name pointing to your server's public IP
- Ports 80 (HTTP) and 443 (HTTPS) open in firewall
- Root or sudo access to the server

### 2. Install Certbot

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

**CentOS/RHEL/Rocky Linux:**
```bash
sudo dnf install -y certbot python3-certbot-nginx
```

**Using Snap (Universal):**
```bash
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

### 3. Obtain Let's Encrypt Certificate

**Method 1: Standalone (Recommended for PlexiChat)**

Stop PlexiChat temporarily and use standalone mode:

```bash
# Stop PlexiChat
sudo systemctl stop plexichat  # or kill the process

# Obtain certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Certificate files will be in /etc/letsencrypt/live/yourdomain.com/
```

**Method 2: Webroot (If you have a web server running)**

```bash
# Create webroot directory
sudo mkdir -p /var/www/html/.well-known

# Obtain certificate
sudo certbot certonly --webroot -w /var/www/html -d yourdomain.com -d www.yourdomain.com
```

**Method 3: DNS Challenge (For wildcard certificates)**

```bash
# For wildcard certificates
sudo certbot certonly --manual --preferred-challenges dns -d "*.yourdomain.com" -d yourdomain.com
```

### 4. Configure PlexiChat with Let's Encrypt Certificate

Update your configuration:

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  ssl_key_path: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
  tls_version: "TLSv1.3"
  tls_ciphers: "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

### 5. Set Up Automatic Renewal

Create a renewal script:

```bash
sudo tee /etc/cron.d/certbot-plexichat << EOF
# Renew Let's Encrypt certificates and restart PlexiChat
0 2 * * * root certbot renew --quiet --deploy-hook "systemctl restart plexichat"
EOF
```

Or create a systemd timer:

```bash
# Create renewal service
sudo tee /etc/systemd/system/certbot-plexichat.service << EOF
[Unit]
Description=Renew Let's Encrypt certificates for PlexiChat
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet
ExecStartPost=/bin/systemctl restart plexichat
EOF

# Create timer
sudo tee /etc/systemd/system/certbot-plexichat.timer << EOF
[Unit]
Description=Run certbot-plexichat twice daily
Requires=certbot-plexichat.service

[Timer]
OnCalendar=*-*-* 02,14:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start timer
sudo systemctl enable certbot-plexichat.timer
sudo systemctl start certbot-plexichat.timer
```

## Quantum-Ready TLS Configuration

PlexiChat includes experimental support for post-quantum cryptography. This section covers enabling quantum-resistant TLS configurations.

### 1. Enable Post-Quantum Cryptography

Update your configuration to enable quantum-ready features:

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/path/to/cert.pem"
  ssl_key_path: "/path/to/key.pem"
  tls_version: "TLSv1.3"
  enable_post_quantum: true
  quantum_hybrid_mode: true
  tls_ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

security:
  quantum_encryption:
    enabled: true
    algorithms: ["kyber1024", "dilithium5"]
    hybrid_mode: true
    key_rotation_interval: 86400  # 24 hours
```

### 2. OpenSSL 3.5+ Configuration

If using OpenSSL 3.5 or later with native post-quantum support:

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/path/to/cert.pem"
  ssl_key_path: "/path/to/key.pem"
  tls_version: "TLSv1.3"
  tls_groups: "mlkem768:x25519:secp256r1"  # Hybrid PQ + classical
  tls_signature_algorithms: "mldsa2:rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"
```

### 3. Generate Post-Quantum Certificates

**Using OpenSSL 3.5+ with ML-DSA:**

```bash
# Generate ML-DSA private key
openssl genpkey -algorithm mldsa2 -out pq-key.pem

# Generate certificate signing request
openssl req -new -key pq-key.pem -out pq-csr.pem -subj "/CN=yourdomain.com"

# Self-sign for development
openssl x509 -req -in pq-csr.pem -signkey pq-key.pem -out pq-cert.pem -days 365
```

**Using OQS Provider (OpenSSL 3.x):**

```bash
# Install OQS provider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -S . -B _build && cmake --build _build && cmake --install _build

# Generate Dilithium key and certificate
openssl genpkey -algorithm dilithium3 -provider oqsprovider -out dilithium-key.pem
openssl req -new -x509 -key dilithium-key.pem -provider oqsprovider -out dilithium-cert.pem -days 365 -subj "/CN=yourdomain.com"
```

### 4. Hybrid Classical + Post-Quantum Setup

For maximum compatibility during the transition period:

```yaml
network:
  ssl_enabled: true
  # Classical certificates for compatibility
  ssl_cert_path: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  ssl_key_path: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
  # Post-quantum certificates for future-proofing
  pq_cert_path: "/etc/ssl/certs/pq-cert.pem"
  pq_key_path: "/etc/ssl/private/pq-key.pem"
  tls_version: "TLSv1.3"
  # Prefer PQ, fallback to classical
  tls_groups: "mlkem768:x25519_mlkem768:x25519:secp256r1"
  tls_signature_algorithms: "mldsa2:rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"
```

## Certificate Management

### 1. Web UI Certificate Management

PlexiChat provides a comprehensive web interface for certificate management. Access it at `https://yourdomain.com/admin/certificates`.

**Features:**
- Upload and manage SSL certificates
- Monitor certificate expiry dates
- Configure automatic renewal
- View certificate details and validation status
- Generate CSRs (Certificate Signing Requests)
- Test certificate configurations

**Uploading Certificates via Web UI:**

1. Navigate to **Admin Panel** → **Security** → **Certificates**
2. Click **"Upload New Certificate"**
3. Fill in the certificate details:
   - **Certificate Name**: Friendly name for identification
   - **Domain(s)**: Comma-separated list of domains
   - **Certificate File**: Upload the PEM-formatted certificate
   - **Private Key File**: Upload the private key (encrypted storage)
   - **Certificate Chain**: Upload intermediate certificates if needed
4. Click **"Validate & Save"**

**Automatic Renewal Configuration:**

1. Go to **Admin Panel** → **Security** → **Certificate Renewal**
2. Enable **"Auto-Renewal"**
3. Configure renewal settings:
   - **Renewal Method**: Let's Encrypt, Manual Upload, or External API
   - **Renewal Days Before Expiry**: Default 30 days
   - **Notification Settings**: Email, Webhook, or Slack notifications
   - **Post-Renewal Actions**: Restart services, run custom scripts

**Certificate Monitoring Dashboard:**

The web UI provides a real-time dashboard showing:
- Certificate expiry countdown
- Renewal status and history
- Security grade (A+, A, B, etc.)
- Cipher suite compatibility
- Certificate chain validation
- OCSP stapling status

### 2. Certificate Monitoring

PlexiChat includes built-in certificate monitoring. Enable it in your configuration:

```yaml
security:
  certificate_monitoring:
    enabled: true
    check_interval: 3600  # Check every hour
    expiry_warning_days: 30  # Warn 30 days before expiry
    auto_renewal: true
    notification_webhook: "https://your-monitoring-system.com/webhook"
    web_ui_alerts: true
    email_notifications:
      enabled: true
      smtp_server: "smtp.yourdomain.com"
      smtp_port: 587
      smtp_username: "alerts@yourdomain.com"
      smtp_password: "${SMTP_PASSWORD}"
      recipients: ["admin@yourdomain.com", "security@yourdomain.com"]
```

**Monitoring API Endpoints:**

```bash
# Get certificate status
curl -H "Authorization: Bearer $API_TOKEN" \
  https://yourdomain.com/api/v1/admin/certificates/status

# Get expiry information
curl -H "Authorization: Bearer $API_TOKEN" \
  https://yourdomain.com/api/v1/admin/certificates/expiry

# Trigger manual renewal check
curl -X POST -H "Authorization: Bearer $API_TOKEN" \
  https://yourdomain.com/api/v1/admin/certificates/check-renewal
```

### 3. Certificate Rotation

Set up automatic certificate rotation:

```bash
# Create certificate rotation script
sudo tee /usr/local/bin/plexichat-cert-rotate.sh << 'EOF'
#!/bin/bash
set -e

DOMAIN="yourdomain.com"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
BACKUP_DIR="/etc/ssl/backup/$(date +%Y%m%d_%H%M%S)"
API_TOKEN="${PLEXICHAT_API_TOKEN}"
PLEXICHAT_URL="https://localhost:8080"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$CERT_DIR"/* "$BACKUP_DIR/"

# Renew certificate
certbot renew --cert-name "$DOMAIN"

# Test new certificate
openssl x509 -in "$CERT_DIR/fullchain.pem" -text -noout | grep -A2 "Validity"

# Update certificate in PlexiChat via API
curl -X POST \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "certificate_path": "'$CERT_DIR'/fullchain.pem",
    "private_key_path": "'$CERT_DIR'/privkey.pem",
    "auto_reload": true
  }' \
  "$PLEXICHAT_URL/api/v1/admin/certificates/update"

# Restart PlexiChat if API update fails
if [ $? -ne 0 ]; then
    systemctl restart plexichat
fi

echo "Certificate rotation completed successfully"
EOF

chmod +x /usr/local/bin/plexichat-cert-rotate.sh
```

**Zero-Downtime Certificate Rotation:**

```yaml
network:
  ssl_enabled: true
  # Enable hot certificate reloading
  ssl_hot_reload: true
  # Grace period for existing connections
  ssl_reload_grace_period: 30
  # Dual certificate support during rotation
  ssl_dual_cert_mode: true
```

### 4. Certificate Validation

Validate your certificate setup:

```bash
# Check certificate details
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem -text -noout

# Test TLS connection
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate chain
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/letsencrypt/live/yourdomain.com/fullchain.pem

# Test with curl
curl -I https://yourdomain.com

# SSL Labs test (external)
curl -s "https://api.ssllabs.com/api/v3/analyze?host=yourdomain.com&publish=off&startNew=on"

# PlexiChat built-in certificate validator
curl -H "Authorization: Bearer $API_TOKEN" \
  https://yourdomain.com/api/v1/admin/certificates/validate
```

**Certificate Health Check Script:**

```bash
# Create comprehensive certificate health check
sudo tee /usr/local/bin/plexichat-cert-health.sh << 'EOF'
#!/bin/bash

DOMAIN="yourdomain.com"
PORT="443"
WARN_DAYS=30
CRIT_DAYS=7

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "=== PlexiChat Certificate Health Check ==="
echo "Domain: $DOMAIN"
echo "Date: $(date)"
echo

# Check certificate expiry
EXPIRY=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

echo "Certificate expires: $EXPIRY"
echo -n "Days until expiry: "

if [ $DAYS_LEFT -lt $CRIT_DAYS ]; then
    echo -e "${RED}$DAYS_LEFT (CRITICAL)${NC}"
    EXIT_CODE=2
elif [ $DAYS_LEFT -lt $WARN_DAYS ]; then
    echo -e "${YELLOW}$DAYS_LEFT (WARNING)${NC}"
    EXIT_CODE=1
else
    echo -e "${GREEN}$DAYS_LEFT (OK)${NC}"
    EXIT_CODE=0
fi

# Check certificate chain
echo
echo -n "Certificate chain: "
if openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | openssl x509 -noout >/dev/null 2>&1; then
    echo -e "${GREEN}Valid${NC}"
else
    echo -e "${RED}Invalid${NC}"
    EXIT_CODE=2
fi

# Check OCSP stapling
echo -n "OCSP stapling: "
OCSP_STATUS=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN -status 2>/dev/null | grep "OCSP Response Status")
if echo "$OCSP_STATUS" | grep -q "successful"; then
    echo -e "${GREEN}Active${NC}"
else
    echo -e "${YELLOW}Not configured${NC}"
fi

# Check TLS version
echo -n "TLS version: "
TLS_VERSION=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | grep "Protocol" | awk '{print $3}')
if [[ "$TLS_VERSION" == "TLSv1.3" ]]; then
    echo -e "${GREEN}$TLS_VERSION${NC}"
elif [[ "$TLS_VERSION" == "TLSv1.2" ]]; then
    echo -e "${YELLOW}$TLS_VERSION${NC}"
else
    echo -e "${RED}$TLS_VERSION (Upgrade recommended)${NC}"
fi

# Check cipher suite
echo -n "Cipher suite: "
CIPHER=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | grep "Cipher" | awk '{print $3}')
echo "$CIPHER"

# Check for weak ciphers
if echo "$CIPHER" | grep -qE "(RC4|DES|MD5|NULL)"; then
    echo -e "${RED}Warning: Weak cipher detected${NC}"
    EXIT_CODE=2
fi

echo
exit $EXIT_CODE
EOF

chmod +x /usr/local/bin/plexichat-cert-health.sh

# Add to monitoring system
echo "*/15 * * * * root /usr/local/bin/plexichat-cert-health.sh" | sudo tee -a /etc/crontab
```

## Security Best Practices

### 1. TLS Configuration Hardening

Use the most secure TLS configuration:

```yaml
network:
  ssl_enabled: true
  tls_version: "TLSv1.3"  # Only TLS 1.3
  tls_min_version: "TLSv1.3"
  # Strong cipher suites (TLS 1.3)
  tls_ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
  # Disable weak protocols
  disable_sslv2: true
  disable_sslv3: true
  disable_tlsv1: true
  disable_tlsv1_1: true
  # Security headers
  hsts_enabled: true
  hsts_max_age: 31536000  # 1 year
  hsts_include_subdomains: true
  hsts_preload: true
```

### 2. Security Headers

Configure security headers in PlexiChat:

```yaml
security:
  headers:
    strict_transport_security: "max-age=31536000; includeSubDomains; preload"
    content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    x_frame_options: "DENY"
    x_content_type_options: "nosniff"
    x_xss_protection: "1; mode=block"
    referrer_policy: "strict-origin-when-cross-origin"
    permissions_policy: "geolocation=(), microphone=(), camera=()"
```

### 3. Certificate Pinning

For high-security environments, enable certificate pinning:

```yaml
security:
  certificate_pinning:
    enabled: true
    pins:
      - "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # Your cert hash
      - "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  # Backup cert hash
    max_age: 2592000  # 30 days
    include_subdomains: true
    report_uri: "https://yourdomain.com/hpkp-report"
```

Generate certificate hashes:

```bash
# Get certificate hash for pinning
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

### 4. Perfect Forward Secrecy

Ensure perfect forward secrecy is enabled:

```yaml
network:
  ssl_enabled: true
  # Use ECDHE and DHE cipher suites for PFS
  tls_ciphers: "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4"
  # Strong DH parameters
  dh_params_path: "/etc/ssl/dhparam.pem"
```

Generate strong DH parameters:

```bash
# Generate 4096-bit DH parameters (takes time)
openssl dhparam -out /etc/ssl/dhparam.pem 4096
```

## Load Balancer Integration

### 1. SSL Termination at Load Balancer

**Nginx Load Balancer Configuration:**

```nginx
upstream plexichat_backend {
    server 127.0.0.1:8080 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8081 max_fails=3 fail_timeout=30s;  # Additional instances
    server 127.0.0.1:8082 backup;  # Backup server
    
    # Health check
    keepalive 32;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=plexichat_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=plexichat_conn:10m;

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_prefer_server_ciphers off;
    
    # SSL optimizations
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/yourdomain.com/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    # Rate limiting
    limit_req zone=plexichat_limit burst=20 nodelay;
    limit_conn plexichat_conn 10;

    # Main application
    location / {
        proxy_pass http://plexichat_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=plexichat_limit burst=10 nodelay;
        proxy_pass http://plexichat_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files with caching
    location /static/ {
        proxy_pass http://plexichat_backend;
        proxy_cache_valid 200 1h;
        add_header Cache-Control "public, max-age=3600";
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://plexichat_backend;
        proxy_set_header Host $host;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**Apache Load Balancer Configuration:**

```apache
# Enable required modules
LoadModule ssl_module modules/mod_ssl.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so

# SSL Configuration
SSLEngine on
SSLProtocol TLSv1.3
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
SSLHonorCipherOrder off
SSLSessionCache shmcb:/var/cache/mod_ssl/scache(512000)
SSLSessionCacheTimeout 300

# OCSP Stapling
SSLUseStapling on
SSLStaplingCache shmcb:/var/cache/mod_ssl/stapling(32768)

<VirtualHost *:443>
    ServerName yourdomain.com
    ServerAlias www.yourdomain.com
    
    # SSL Certificates
    SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'"
    
    # Load Balancer Configuration
    ProxyPreserveHost On
    ProxyRequests Off
    
    # Backend servers
    ProxyPass /ws/ balancer://plexichat-ws/
    ProxyPassReverse /ws/ balancer://plexichat-ws/
    ProxyPass / balancer://plexichat-http/
    ProxyPassReverse / balancer://plexichat-http/
    
    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "balancer://plexichat-ws/$1" [P,L]
    
    <Proxy balancer://plexichat-http>
        BalancerMember http://127.0.0.1:8080
        BalancerMember http://127.0.0.1:8081
        ProxySet hcmethod GET
        ProxySet hcuri /health
    </Proxy>
    
    <Proxy balancer://plexichat-ws>
        BalancerMember ws://127.0.0.1:8080
        BalancerMember ws://127.0.0.1:8081
    </Proxy>
</VirtualHost>

# HTTP to HTTPS redirect
<VirtualHost *:80>
    ServerName yourdomain.com
    ServerAlias www.yourdomain.com
    Redirect permanent / https://yourdomain.com/
</VirtualHost>
```

**Cloudflare Configuration:**

If using Cloudflare as a reverse proxy:

```yaml
# cloudflare-config.yaml
ssl: "strict"  # Full (strict) SSL mode
always_use_https: true
automatic_https_rewrites: true
min_tls_version: "1.3"
tls_1_3: "on"
http2: "on"
http3: "on"
brotli: "on"

# Page Rules
page_rules:
  - url: "yourdomain.com/*"
    settings:
      ssl: "strict"
      always_use_https: true
      security_level: "high"
      cache_level: "standard"
```

**PlexiChat Configuration for Load Balancer:**

```yaml
network:
  ssl_enabled: false  # SSL terminated at load balancer
  proxy_headers: true  # Trust proxy headers
  host: "127.0.0.1"
  port: 8080
  # Enable real IP detection
  real_ip_header: "X-Forwarded-For"
  real_ip_recursive: true

security:
  trusted_proxies:
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    # Cloudflare IP ranges
    - "173.245.48.0/20"
    - "103.21.244.0/22"
    - "103.22.200.0/22"
    - "103.31.4.0/22"
    - "141.101.64.0/18"
    - "108.162.192.0/18"
    - "190.93.240.0/20"
    - "188.114.96.0/20"
    - "197.234.240.0/22"
    - "198.41.128.0/17"
    - "162.158.0.0/15"
    - "104.16.0.0/13"
    - "104.24.0.0/14"
    - "172.64.0.0/13"
    - "131.0.72.0/22"
  
  # Validate proxy headers
  validate_proxy_headers: true
  require_proxy_auth: false
```

### 2. End-to-End SSL

For end-to-end encryption with load balancer:

**HAProxy Configuration:**

```
global
    ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.3
    ssl-default-server-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options ssl-min-ver TLSv1.3
    
    # Logging
    log stdout local0 info
    
    # Performance tuning
    tune.ssl.default-dh-param 2048
    tune.ssl.capture-cipherlist-size 1024

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull
    option redispatch
    retries 3

frontend plexichat_frontend
    bind *:443 ssl crt /etc/ssl/certs/yourdomain.com.pem alpn h2,http/1.1
    bind *:80
    
    # Redirect HTTP to HTTPS
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if { sc_http_req_rate(0) gt 20 }
    
    default_backend plexichat_backend

backend plexichat_backend
    balance roundrobin
    option httpchk GET /health
    option ssl-hello-chk
    
    # Backend servers with SSL
    server plexichat1 127.0.0.1:8080 check ssl verify none
    server plexichat2 127.0.0.1:8081 check ssl verify none
    server plexichat3 127.0.0.1:8082 check ssl verify none backup

# Statistics interface
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

**PlexiChat Configuration for End-to-End SSL:**

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/etc/ssl/certs/plexichat-backend.pem"
  ssl_key_path: "/etc/ssl/private/plexichat-backend.key"
  proxy_headers: true
  # Enable backend SSL
  backend_ssl: true
  ssl_verify_client: false  # Don't require client certs for backend

security:
  trusted_proxies:
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

### 3. Container Orchestration (Docker/Kubernetes)

**Docker Compose with Nginx:**

```yaml
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - plexichat1
      - plexichat2

  plexichat1:
    image: plexichat:latest
    environment:
      - PLEXICHAT_SSL_ENABLED=false
      - PLEXICHAT_PROXY_HEADERS=true
    volumes:
      - ./config:/app/config

  plexichat2:
    image: plexichat:latest
    environment:
      - PLEXICHAT_SSL_ENABLED=false
      - PLEXICHAT_PROXY_HEADERS=true
    volumes:
      - ./config:/app/config
```

**Kubernetes Ingress with cert-manager:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: plexichat-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
spec:
  tls:
  - hosts:
    - yourdomain.com
    secretName: plexichat-tls
  rules:
  - host: yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: plexichat-service
            port:
              number: 8080
```

## Troubleshooting

### 1. Common SSL/TLS Issues

**Certificate Not Found:**
```bash
# Check file permissions
ls -la /etc/letsencrypt/live/yourdomain.com/
# Should be readable by PlexiChat user

# Fix permissions if needed
sudo chown -R plexichat:plexichat /etc/letsencrypt/live/yourdomain.com/
sudo chmod 644 /etc/letsencrypt/live/yourdomain.com/fullchain.pem
sudo chmod 600 /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

**Certificate Expired:**
```bash
# Check expiry date
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem -noout -dates

# Force renewal
sudo certbot renew --force-renewal --cert-name yourdomain.com
```

**TLS Handshake Failures:**
```bash
# Test TLS connection
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com -debug

# Check cipher compatibility
nmap --script ssl-enum-ciphers -p 443 yourdomain.com
```

### 2. Debugging SSL Configuration

Enable SSL debugging in PlexiChat:

```yaml
logging:
  level: DEBUG
  ssl_debug: true
  
network:
  ssl_debug: true
```

Check PlexiChat logs:

```bash
# View SSL-related logs
journalctl -u plexichat | grep -i ssl
tail -f /var/log/plexichat/ssl.log
```

### 3. Certificate Chain Issues

**Verify certificate chain:**
```bash
# Check full chain
openssl s_client -connect yourdomain.com:443 -showcerts

# Verify against CA bundle
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/letsencrypt/live/yourdomain.com/fullchain.pem
```

**Fix incomplete chain:**
```bash
# Download intermediate certificates
wget -O intermediate.pem https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem

# Rebuild full chain
cat /etc/letsencrypt/live/yourdomain.com/cert.pem intermediate.pem > /etc/letsencrypt/live/yourdomain.com/fullchain.pem
```

### 4. Performance Issues

**SSL Performance Optimization:**

```yaml
network:
  ssl_enabled: true
  # Enable SSL session caching
  ssl_session_cache: true
  ssl_session_timeout: 300
  # Use hardware acceleration if available
  ssl_engine: "auto"
  # Optimize buffer sizes
  ssl_buffer_size: 16384
```

**Monitor SSL performance:**
```bash
# Check SSL handshake time
curl -w "@curl-format.txt" -o /dev/null -s https://yourdomain.com

# Create curl-format.txt:
cat > curl-format.txt << EOF
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
EOF
```

## Advanced Configuration

### 1. Multi-Domain Certificates

Configure multiple domains:

```bash
# Obtain multi-domain certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com -d api.yourdomain.com -d chat.yourdomain.com
```

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  ssl_key_path: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
  # SNI support for multiple domains
  sni_enabled: true
  domains:
    - name: "yourdomain.com"
      cert_path: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
      key_path: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
    - name: "api.yourdomain.com"
      cert_path: "/etc/letsencrypt/live/api.yourdomain.com/fullchain.pem"
      key_path: "/etc/letsencrypt/live/api.yourdomain.com/privkey.pem"
```

### 2. Client Certificate Authentication

Enable mutual TLS (mTLS):

```yaml
security:
  client_certificates:
    enabled: true
    ca_cert_path: "/etc/ssl/certs/client-ca.pem"
    verify_mode: "require"  # require, optional, none
    verify_depth: 3
```

Generate client certificates:

```bash
# Create client CA
openssl genrsa -out client-ca.key 4096
openssl req -new -x509 -key client-ca.key -out client-ca.pem -days 3650 -subj "/CN=PlexiChat Client CA"

# Generate client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client1"
openssl x509 -req -in client.csr -CA client-ca.pem -CAkey client-ca.key -out client.pem -days 365 -CAcreateserial
```

### 3. OCSP Stapling

Enable OCSP stapling for better performance:

```yaml
network:
  ssl_enabled: true
  ocsp_stapling: true
  ocsp_cache_timeout: 3600
```

### 4. Certificate Transparency

Monitor certificate transparency logs:

```bash
# Install ct-woodpecker for CT monitoring
pip install ct-woodpecker

# Monitor your domain
ct-woodpecker --domain yourdomain.com --output json
```

### 5. Automated Security Testing

Set up comprehensive automated SSL testing:

```bash
# Create comprehensive SSL test script
cat > /usr/local/bin/plexichat-ssl-test.sh << 'EOF'
#!/bin/bash
set -euo pipefail

DOMAIN="${1:-yourdomain.com}"
PORT="${2:-443}"
OUTPUT_DIR="/var/log/plexichat/ssl-tests"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$OUTPUT_DIR/ssl-test-$TIMESTAMP.json"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}=== PlexiChat SSL Security Test ===${NC}"
echo "Domain: $DOMAIN"
echo "Port: $PORT"
echo "Timestamp: $TIMESTAMP"
echo "Report: $REPORT_FILE"
echo

# Initialize JSON report
cat > "$REPORT_FILE" << JSON
{
  "domain": "$DOMAIN",
  "port": $PORT,
  "timestamp": "$TIMESTAMP",
  "tests": {}
}
JSON

# Function to update JSON report
update_report() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    jq --arg test "$test_name" --arg status "$status" --arg details "$details" \
       '.tests[$test] = {"status": $status, "details": $details}' \
       "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
}

# Test 1: Certificate Expiry
echo -n "Testing certificate expiry... "
EXPIRY=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt 7 ]; then
    echo -e "${RED}CRITICAL ($DAYS_LEFT days)${NC}"
    update_report "certificate_expiry" "CRITICAL" "$DAYS_LEFT days remaining"
elif [ $DAYS_LEFT -lt 30 ]; then
    echo -e "${YELLOW}WARNING ($DAYS_LEFT days)${NC}"
    update_report "certificate_expiry" "WARNING" "$DAYS_LEFT days remaining"
else
    echo -e "${GREEN}OK ($DAYS_LEFT days)${NC}"
    update_report "certificate_expiry" "OK" "$DAYS_LEFT days remaining"
fi

# Test 2: TLS Version
echo -n "Testing TLS version... "
TLS_VERSION=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | grep "Protocol" | awk '{print $3}')
if [[ "$TLS_VERSION" == "TLSv1.3" ]]; then
    echo -e "${GREEN}$TLS_VERSION${NC}"
    update_report "tls_version" "OK" "$TLS_VERSION"
elif [[ "$TLS_VERSION" == "TLSv1.2" ]]; then
    echo -e "${YELLOW}$TLS_VERSION (consider upgrading)${NC}"
    update_report "tls_version" "WARNING" "$TLS_VERSION"
else
    echo -e "${RED}$TLS_VERSION (upgrade required)${NC}"
    update_report "tls_version" "CRITICAL" "$TLS_VERSION"
fi

# Test 3: Certificate Chain
echo -n "Testing certificate chain... "
if openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN -verify_return_error 2>/dev/null >/dev/null; then
    echo -e "${GREEN}Valid${NC}"
    update_report "certificate_chain" "OK" "Valid certificate chain"
else
    echo -e "${RED}Invalid${NC}"
    update_report "certificate_chain" "CRITICAL" "Invalid certificate chain"
fi

# Test 4: OCSP Stapling
echo -n "Testing OCSP stapling... "
OCSP_STATUS=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN -status 2>/dev/null | grep "OCSP Response Status")
if echo "$OCSP_STATUS" | grep -q "successful"; then
    echo -e "${GREEN}Active${NC}"
    update_report "ocsp_stapling" "OK" "OCSP stapling active"
else
    echo -e "${YELLOW}Not configured${NC}"
    update_report "ocsp_stapling" "WARNING" "OCSP stapling not configured"
fi

# Test 5: Cipher Strength
echo -n "Testing cipher strength... "
CIPHER=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | grep "Cipher" | awk '{print $3}')
if echo "$CIPHER" | grep -qE "(AES256|CHACHA20)"; then
    echo -e "${GREEN}Strong ($CIPHER)${NC}"
    update_report "cipher_strength" "OK" "Strong cipher: $CIPHER"
elif echo "$CIPHER" | grep -qE "(AES128)"; then
    echo -e "${YELLOW}Moderate ($CIPHER)${NC}"
    update_report "cipher_strength" "WARNING" "Moderate cipher: $CIPHER"
else
    echo -e "${RED}Weak ($CIPHER)${NC}"
    update_report "cipher_strength" "CRITICAL" "Weak cipher: $CIPHER"
fi

# Test 6: Perfect Forward Secrecy
echo -n "Testing Perfect Forward Secrecy... "
PFS_CIPHER=$(openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN 2>/dev/null | grep "Cipher" | awk '{print $3}')
if echo "$PFS_CIPHER" | grep -qE "(ECDHE|DHE)"; then
    echo -e "${GREEN}Enabled${NC}"
    update_report "perfect_forward_secrecy" "OK" "PFS enabled with $PFS_CIPHER"
else
    echo -e "${RED}Disabled${NC}"
    update_report "perfect_forward_secrecy" "CRITICAL" "PFS not enabled"
fi

# Test 7: HSTS Header
echo -n "Testing HSTS header... "
HSTS_HEADER=$(curl -s -I https://$DOMAIN | grep -i "strict-transport-security" || echo "")
if [[ -n "$HSTS_HEADER" ]]; then
    echo -e "${GREEN}Present${NC}"
    update_report "hsts_header" "OK" "HSTS header present"
else
    echo -e "${YELLOW}Missing${NC}"
    update_report "hsts_header" "WARNING" "HSTS header missing"
fi

# Test 8: SSL Labs Grade (if available)
echo -n "Testing SSL Labs grade... "
if command -v jq &> /dev/null; then
    SSL_GRADE=$(curl -s "https://api.ssllabs.com/api/v3/analyze?host=$DOMAIN&publish=off&all=done" | jq -r '.endpoints[0].grade // "Unknown"' 2>/dev/null || echo "Unknown")
    if [[ "$SSL_GRADE" == "A+" ]] || [[ "$SSL_GRADE" == "A" ]]; then
        echo -e "${GREEN}$SSL_GRADE${NC}"
        update_report "ssl_labs_grade" "OK" "Grade: $SSL_GRADE"
    elif [[ "$SSL_GRADE" == "B" ]]; then
        echo -e "${YELLOW}$SSL_GRADE${NC}"
        update_report "ssl_labs_grade" "WARNING" "Grade: $SSL_GRADE"
    elif [[ "$SSL_GRADE" == "Unknown" ]]; then
        echo -e "${YELLOW}$SSL_GRADE${NC}"
        update_report "ssl_labs_grade" "INFO" "Grade: $SSL_GRADE"
    else
        echo -e "${RED}$SSL_GRADE${NC}"
        update_report "ssl_labs_grade" "CRITICAL" "Grade: $SSL_GRADE"
    fi
else
    echo -e "${YELLOW}jq not available${NC}"
    update_report "ssl_labs_grade" "INFO" "jq not available for testing"
fi

# Test 9: Vulnerability Scan with testssl.sh (if available)
echo -n "Testing for vulnerabilities... "
if command -v testssl.sh &> /dev/null; then
    VULN_OUTPUT=$(testssl.sh --quiet --jsonfile-pretty "$OUTPUT_DIR/testssl-$TIMESTAMP.json" $DOMAIN 2>/dev/null || echo "")
    if [[ -f "$OUTPUT_DIR/testssl-$TIMESTAMP.json" ]]; then
        CRITICAL_VULNS=$(jq '[.scanResult[] | select(.severity == "CRITICAL")] | length' "$OUTPUT_DIR/testssl-$TIMESTAMP.json" 2>/dev/null || echo "0")
        HIGH_VULNS=$(jq '[.scanResult[] | select(.severity == "HIGH")] | length' "$OUTPUT_DIR/testssl-$TIMESTAMP.json" 2>/dev/null || echo "0")
        
        if [[ "$CRITICAL_VULNS" -gt 0 ]]; then
            echo -e "${RED}$CRITICAL_VULNS critical vulnerabilities${NC}"
            update_report "vulnerability_scan" "CRITICAL" "$CRITICAL_VULNS critical, $HIGH_VULNS high vulnerabilities"
        elif [[ "$HIGH_VULNS" -gt 0 ]]; then
            echo -e "${YELLOW}$HIGH_VULNS high vulnerabilities${NC}"
            update_report "vulnerability_scan" "WARNING" "$HIGH_VULNS high vulnerabilities"
        else
            echo -e "${GREEN}No critical vulnerabilities${NC}"
            update_report "vulnerability_scan" "OK" "No critical vulnerabilities found"
        fi
    else
        echo -e "${YELLOW}Scan failed${NC}"
        update_report "vulnerability_scan" "WARNING" "Vulnerability scan failed"
    fi
else
    echo -e "${YELLOW}testssl.sh not available${NC}"
    update_report "vulnerability_scan" "INFO" "testssl.sh not available"
fi

# Test 10: Certificate Transparency
echo -n "Testing Certificate Transparency... "
if command -v curl &> /dev/null && command -v jq &> /dev/null; then
    CT_LOGS=$(curl -s "https://crt.sh/?q=$DOMAIN&output=json" | jq length 2>/dev/null || echo "0")
    if [[ "$CT_LOGS" -gt 0 ]]; then
        echo -e "${GREEN}$CT_LOGS entries found${NC}"
        update_report "certificate_transparency" "OK" "$CT_LOGS CT log entries"
    else
        echo -e "${YELLOW}No entries found${NC}"
        update_report "certificate_transparency" "WARNING" "No CT log entries found"
    fi
else
    echo -e "${YELLOW}Tools not available${NC}"
    update_report "certificate_transparency" "INFO" "CT check tools not available"
fi

# Generate summary
echo
echo -e "${BLUE}=== Test Summary ===${NC}"
CRITICAL_COUNT=$(jq '[.tests[] | select(.status == "CRITICAL")] | length' "$REPORT_FILE")
WARNING_COUNT=$(jq '[.tests[] | select(.status == "WARNING")] | length' "$REPORT_FILE")
OK_COUNT=$(jq '[.tests[] | select(.status == "OK")] | length' "$REPORT_FILE")

echo "Critical issues: $CRITICAL_COUNT"
echo "Warnings: $WARNING_COUNT"
echo "Passed tests: $OK_COUNT"

# Update summary in JSON
jq --argjson critical "$CRITICAL_COUNT" --argjson warning "$WARNING_COUNT" --argjson ok "$OK_COUNT" \
   '.summary = {"critical": $critical, "warning": $warning, "ok": $ok}' \
   "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"

echo
echo "Detailed report saved to: $REPORT_FILE"

# Exit with appropriate code
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
    exit 2
elif [[ "$WARNING_COUNT" -gt 0 ]]; then
    exit 1
else
    exit 0
fi
EOF

chmod +x /usr/local/bin/plexichat-ssl-test.sh

# Create monitoring script for continuous testing
cat > /usr/local/bin/plexichat-ssl-monitor.sh << 'EOF'
#!/bin/bash

DOMAIN="yourdomain.com"
WEBHOOK_URL="${PLEXICHAT_WEBHOOK_URL:-}"
EMAIL_RECIPIENTS="${PLEXICHAT_EMAIL_RECIPIENTS:-admin@yourdomain.com}"

# Run SSL test
/usr/local/bin/plexichat-ssl-test.sh "$DOMAIN"
EXIT_CODE=$?

# Get latest report
LATEST_REPORT=$(ls -t /var/log/plexichat/ssl-tests/ssl-test-*.json | head -1)

if [[ -f "$LATEST_REPORT" ]]; then
    CRITICAL_COUNT=$(jq '.summary.critical' "$LATEST_REPORT")
    WARNING_COUNT=$(jq '.summary.warning' "$LATEST_REPORT")
    
    # Send notifications if issues found
    if [[ "$CRITICAL_COUNT" -gt 0 ]] || [[ "$WARNING_COUNT" -gt 0 ]]; then
        MESSAGE="SSL Security Alert for $DOMAIN: $CRITICAL_COUNT critical, $WARNING_COUNT warning issues found."
        
        # Send webhook notification
        if [[ -n "$WEBHOOK_URL" ]]; then
            curl -X POST "$WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "{\"text\": \"$MESSAGE\", \"report\": $(cat "$LATEST_REPORT")}"
        fi
        
        # Send email notification
        if command -v mail &> /dev/null; then
            echo "$MESSAGE" | mail -s "PlexiChat SSL Alert" "$EMAIL_RECIPIENTS"
        fi
    fi
fi

exit $EXIT_CODE
EOF

chmod +x /usr/local/bin/plexichat-ssl-monitor.sh

# Add to cron for daily testing
echo "0 6 * * * root /usr/local/bin/plexichat-ssl-monitor.sh" | sudo tee -a /etc/crontab

# Add to systemd for more reliable scheduling
cat > /etc/systemd/system/plexichat-ssl-test.service << 'EOF'
[Unit]
Description=PlexiChat SSL Security Test
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/plexichat-ssl-monitor.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

cat > /etc/systemd/system/plexichat-ssl-test.timer << 'EOF'
[Unit]
Description=Run PlexiChat SSL test daily
Requires=plexichat-ssl-test.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable plexichat-ssl-test.timer
systemctl start plexichat-ssl-test.timer
```

**Continuous Security Monitoring Integration:**

```bash
# Create Prometheus metrics exporter for SSL status
cat > /usr/local/bin/plexichat-ssl-metrics.sh << 'EOF'
#!/bin/bash

METRICS_FILE="/var/lib/prometheus/node-exporter/plexichat_ssl.prom"
DOMAIN="yourdomain.com"

# Get latest SSL test report
LATEST_REPORT=$(ls -t /var/log/plexichat/ssl-tests/ssl-test-*.json 2>/dev/null | head -1)

if [[ -f "$LATEST_REPORT" ]]; then
    CRITICAL_COUNT=$(jq '.summary.critical' "$LATEST_REPORT")
    WARNING_COUNT=$(jq '.summary.warning' "$LATEST_REPORT")
    OK_COUNT=$(jq '.summary.ok' "$LATEST_REPORT")
    
    # Certificate expiry days
    CERT_DAYS=$(jq -r '.tests.certificate_expiry.details' "$LATEST_REPORT" | grep -o '[0-9]\+' || echo "0")
    
    # TLS version score (1.3=3, 1.2=2, 1.1=1, 1.0=0)
    TLS_VERSION=$(jq -r '.tests.tls_version.details' "$LATEST_REPORT")
    case "$TLS_VERSION" in
        "TLSv1.3") TLS_SCORE=3 ;;
        "TLSv1.2") TLS_SCORE=2 ;;
        "TLSv1.1") TLS_SCORE=1 ;;
        *) TLS_SCORE=0 ;;
    esac
    
    # Write metrics
    cat > "$METRICS_FILE" << METRICS
# HELP plexichat_ssl_critical_issues Number of critical SSL issues
# TYPE plexichat_ssl_critical_issues gauge
plexichat_ssl_critical_issues{domain="$DOMAIN"} $CRITICAL_COUNT

# HELP plexichat_ssl_warning_issues Number of SSL warning issues
# TYPE plexichat_ssl_warning_issues gauge
plexichat_ssl_warning_issues{domain="$DOMAIN"} $WARNING_COUNT

# HELP plexichat_ssl_ok_tests Number of passed SSL tests
# TYPE plexichat_ssl_ok_tests gauge
plexichat_ssl_ok_tests{domain="$DOMAIN"} $OK_COUNT

# HELP plexichat_ssl_cert_expiry_days Days until certificate expiry
# TYPE plexichat_ssl_cert_expiry_days gauge
plexichat_ssl_cert_expiry_days{domain="$DOMAIN"} $CERT_DAYS

# HELP plexichat_ssl_tls_version_score TLS version score (3=1.3, 2=1.2, etc.)
# TYPE plexichat_ssl_tls_version_score gauge
plexichat_ssl_tls_version_score{domain="$DOMAIN"} $TLS_SCORE
METRICS
fi
EOF

chmod +x /usr/local/bin/plexichat-ssl-metrics.sh

# Add to cron for metrics collection
echo "*/5 * * * * root /usr/local/bin/plexichat-ssl-metrics.sh" | sudo tee -a /etc/crontab
```

---

## Summary

This comprehensive guide covers HTTPS setup for PlexiChat, from basic development certificates to enterprise-grade production configurations with post-quantum cryptography support. Key highlights:

### Quick Reference

**Development Setup:**
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"

# Configure PlexiChat
export PLEXICHAT_SSL_ENABLED=true
export PLEXICHAT_SSL_CERT_PATH=certs/cert.pem
export PLEXICHAT_SSL_KEY_PATH=certs/key.pem
```

**Production Setup:**
```bash
# Get Let's Encrypt certificate
sudo certbot certonly --standalone -d yourdomain.com

# Configure auto-renewal
echo "0 2 * * * root certbot renew --quiet --deploy-hook 'systemctl restart plexichat'" | sudo tee -a /etc/crontab
```

**Security Testing:**
```bash
# Run comprehensive SSL test
/usr/local/bin/plexichat-ssl-test.sh yourdomain.com

# Check certificate expiry
openssl x509 -in cert.pem -noout -dates
```

### Key Features Covered

1. **Development**: Self-signed certificates with proper SAN configuration and trust store integration
2. **Production**: Let's Encrypt integration with automated renewal and monitoring
3. **Security**: TLS 1.3, strong cipher suites, security headers, and HSTS configuration
4. **Future-Proofing**: Post-quantum cryptography support with hybrid classical/PQ modes
5. **Load Balancers**: Comprehensive configurations for Nginx, Apache, HAProxy, and Cloudflare
6. **Monitoring**: Certificate health checks, automated testing, and Prometheus metrics
7. **Web UI**: Certificate management through PlexiChat's admin interface
8. **Container Support**: Docker and Kubernetes deployment configurations
9. **Troubleshooting**: Comprehensive debugging guides and common issue resolution
10. **Compliance**: Security best practices and automated compliance checking

### Security Grades Achievable

Following this guide, you can achieve:
- **SSL Labs Grade**: A+ with proper configuration
- **TLS Version**: TLS 1.3 only for maximum security
- **Cipher Strength**: 256-bit encryption with perfect forward secrecy
- **Certificate Security**: Automated monitoring and renewal
- **Quantum Resistance**: Future-proof with post-quantum cryptography

### Maintenance Checklist

**Daily:**
- [ ] Automated SSL security tests run
- [ ] Certificate expiry monitoring active
- [ ] Security metrics collected

**Weekly:**
- [ ] Review SSL test reports
- [ ] Check certificate renewal logs
- [ ] Validate security headers

**Monthly:**
- [ ] Update cipher suites if needed
- [ ] Review and update security policies
- [ ] Test disaster recovery procedures

**Quarterly:**
- [ ] Security audit and penetration testing
- [ ] Update post-quantum cryptography configuration
- [ ] Review and update documentation

### Getting Help

**Immediate Issues:**
- Check the [Troubleshooting](#troubleshooting) section above
- Review PlexiChat logs: `journalctl -u plexichat | grep -i ssl`
- Test SSL configuration: `openssl s_client -connect yourdomain.com:443`

**Online Tools:**
- [SSL Labs Test](https://www.ssllabs.com/ssltest/) - Comprehensive SSL analysis
- [Security Headers](https://securityheaders.com/) - HTTP security headers check
- [Certificate Transparency](https://crt.sh/) - Certificate transparency logs

**Community Support:**
- PlexiChat Documentation: [docs.plexichat.com](https://docs.plexichat.com)
- Community Forum: [community.plexichat.com](https://community.plexichat.com)
- GitHub Issues: [github.com/plexichat/plexichat/issues](https://github.com/plexichat/plexichat/issues)

**Professional Support:**
- Enterprise Support: [support@plexichat.com](mailto:support@plexichat.com)
- Security Consulting: [security@plexichat.com](mailto:security@plexichat.com)
- Custom Implementation: [consulting@plexichat.com](mailto:consulting@plexichat.com)

For additional security considerations and advanced configurations, refer to:
- [Security Best Practices](SECURITY.md)
- [Quantum Encryption Guide](QUANTUM_ENCRYPTION.md)
- [Network Security Configuration](NETWORK_SECURITY.md)
- [Compliance and Auditing](COMPLIANCE.md)
