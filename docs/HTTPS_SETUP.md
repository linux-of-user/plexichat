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

### 1. Certificate Monitoring

PlexiChat includes built-in certificate monitoring. Enable it in your configuration:

```yaml
security:
  certificate_monitoring:
    enabled: true
    check_interval: 3600  # Check every hour
    expiry_warning_days: 30  # Warn 30 days before expiry
    auto_renewal: true
    notification_webhook: "https://your-monitoring-system.com/webhook"
```

### 2. Certificate Rotation

Set up automatic certificate rotation:

```bash
# Create certificate rotation script
sudo tee /usr/local/bin/plexichat-cert-rotate.sh << 'EOF'
#!/bin/bash
set -e

DOMAIN="yourdomain.com"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
BACKUP_DIR="/etc/ssl/backup/$(date +%Y%m%d_%H%M%S)"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$CERT_DIR"/* "$BACKUP_DIR/"

# Renew certificate
certbot renew --cert-name "$DOMAIN"

# Test new certificate
openssl x509 -in "$CERT_DIR/fullchain.pem" -text -noout | grep -A2 "Validity"

# Restart PlexiChat
systemctl restart plexichat

echo "Certificate rotation completed successfully"
EOF

chmod +x /usr/local/bin/plexichat-cert-rotate.sh
```

### 3. Certificate Validation

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
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;  # Additional instances
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass http://plexichat_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**PlexiChat Configuration for Load Balancer:**

```yaml
network:
  ssl_enabled: false  # SSL terminated at load balancer
  proxy_headers: true  # Trust proxy headers
  host: "127.0.0.1"
  port: 8080

security:
  trusted_proxies:
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

### 2. End-to-End SSL

For end-to-end encryption with load balancer:

**HAProxy Configuration:**

```
global
    ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.3

frontend plexichat_frontend
    bind *:443 ssl crt /etc/ssl/certs/yourdomain.com.pem
    redirect scheme https if !{ ssl_fc }
    default_backend plexichat_backend

backend plexichat_backend
    balance roundrobin
    option httpchk GET /health
    server plexichat1 127.0.0.1:8080 check ssl verify none
    server plexichat2 127.0.0.1:8081 check ssl verify none
```

**PlexiChat Configuration:**

```yaml
network:
  ssl_enabled: true
  ssl_cert_path: "/etc/ssl/certs/plexichat-backend.pem"
  ssl_key_path: "/etc/ssl/private/plexichat-backend.key"
  proxy_headers: true
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

Set up automated SSL testing:

```bash
# Create SSL test script
cat > /usr/local/bin/plexichat-ssl-test.sh << 'EOF'
#!/bin/bash
DOMAIN="yourdomain.com"

echo "Testing SSL configuration for $DOMAIN"

# Test with testssl.sh
if command -v testssl.sh &> /dev/null; then
    testssl.sh --quiet --color 0 $DOMAIN
fi

# Test with SSL Labs API
curl -s "https://api.ssllabs.com/api/v3/analyze?host=$DOMAIN&publish=off&all=done" | jq '.endpoints[0].grade'

# Test certificate expiry
EXPIRY=$(openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

echo "Certificate expires in $DAYS_LEFT days"

if [ $DAYS_LEFT -lt 30 ]; then
    echo "WARNING: Certificate expires soon!"
    exit 1
fi
EOF

chmod +x /usr/local/bin/plexichat-ssl-test.sh

# Add to cron for daily testing
echo "0 6 * * * root /usr/local/bin/plexichat-ssl-test.sh" | sudo tee -a /etc/crontab
```

---

## Summary

This guide covers comprehensive HTTPS setup for PlexiChat, from basic development certificates to production-ready configurations with post-quantum cryptography support. Key points:

1. **Development**: Use self-signed certificates with proper SAN configuration
2. **Production**: Use Let's Encrypt with automated renewal
3. **Security**: Enable TLS 1.3, strong ciphers, and security headers
4. **Future-Proofing**: Configure post-quantum cryptography for quantum resistance
5. **Monitoring**: Set up certificate monitoring and automated testing
6. **Load Balancers**: Proper configuration for various load balancer scenarios

For additional security considerations, refer to the [Security Best Practices](SECURITY.md) documentation.

**Need Help?**
- Check the [Troubleshooting](#troubleshooting) section above
- Review PlexiChat logs: `journalctl -u plexichat`
- Test your SSL configuration: `openssl s_client -connect yourdomain.com:443`
- Use online tools: [SSL Labs Test](https://www.ssllabs.com/ssltest/)