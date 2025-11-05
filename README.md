# Traefik with ModSecurity WAF (Nginx)

This project sets up a Web Application Firewall (WAF) using Traefik as a reverse proxy and ModSecurity with Nginx for security rules. It's designed to protect your web applications from common attacks.

## What's Included

- **Traefik (v3.5.4)**: Acts as the main gateway for web traffic
- **ModSecurity-nginx**: Provides WAF capabilities through Nginx
- **OWASP Core Rule Set (CRS)**: A set of security rules that protect against common web attacks

## Project Structure

```
├── docker-compose.yaml        # Main configuration for all services
├── modsec/
│   ├── nginx.conf            # Nginx configuration
│   ├── crs-setup.conf        # Core Rule Set configuration
│   ├── modsec.conf          # ModSecurity main configuration
│   ├── rules.conf           # Custom rules configuration
│   └── data/
│       ├── audit/           # Security audit logs
│       └── collections/     # ModSecurity persistent data
└── traefik/
    └── traefik.yaml         # Traefik configuration
```

## How to Use

### 1. Prerequisites

- Docker
- Docker Compose

### 2. Quick Start

1. Clone this repository:
   ```bash
   git clone https://github.com/eslam-adel92/traefik_waf_modsec.git
   cd traefik_waf_modsec
   ```

2. Start the services:
   ```bash
   docker compose up -d
   ```

3. Check if everything is running:
   ```bash
   docker compose ps
   ```

### 3. What's Protected?

The WAF protects against:
- SQL Injection attempts
- Cross-Site Scripting (XSS)
- Sensitive file access (like .env files)
- Unauthorized API access
- Malicious file uploads
- And many other web attacks

### 4. Configuration Details

#### Traefik Configuration
- Port 8000: Web traffic
- Port 8080: Traefik dashboard
- Port 443: HTTPS traffic (optional)
- ModSecurity plugin enabled
- Security headers middleware

#### ModSecurity Configuration
- Engine: ModSecurity-nginx
- Paranoia Level: 1 (Configurable via environment variables)
- Anomaly Scoring Thresholds:
  - Inbound: 10
  - Outbound: 5
- Audit Logging: JSON format
- Core Rule Set: Latest version via owasp/modsecurity-crs

### 5. Security Tests and Results

Below are comprehensive security tests performed on the WAF setup. Each test includes the command and expected result.

#### 5.1 Basic Connectivity Test
```bash
# Without Host header (should return 404 - this is expected)
curl -i http://localhost:8000/

# With Host header (should return 200 OK with whoami service information)
curl -i -H "Host: whoami.localhost" http://localhost:8000/
```
✅ Results:
- Without Host header: Returns 404 (This is correct behavior - Traefik requires Host header for routing)
- With Host header: Returns 200 OK with proper security headers

Note: The Host header is required because Traefik uses virtual hosting to route requests. 
The `whoami.localhost` host is defined in the service labels in `docker-compose.yaml`:
```yaml
traefik.http.routers.whoami.rule=Host(`whoami.localhost`)
```

#### 5.2 XSS Protection Tests
```bash
# Basic XSS Test
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?q=<script>alert(1)</script>"

# Event Handler XSS Test
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?q=<img src=x onerror=alert(1)>"

# JavaScript URL XSS Test
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?q=<a href=javascript:alert(1)>click</a>"
```
✅ Results:
- Blocks XSS attempts with 403 Forbidden
- Anomaly score: 15 for basic XSS attacks
- Proper logging of attack vectors

#### 5.3 SQL Injection Tests
```bash
# UNION-based SQLi
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?id=1%20UNION%20SELECT%20username,password%20FROM%20users"

# Boolean-based SQLi
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?id=1%20AND%201=1"

# Time-based SQLi
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?id=1%20AND%20SLEEP(5)"

# Quote-based SQLi
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?id=1%27%20OR%20%271%27=%271"
```
✅ Results:
- UNION-based attacks: Blocked (Anomaly score: 20)
- Boolean-based attacks: Blocked (Anomaly score: 5)
- Time-based attacks: Blocked (Anomaly score: 10)
- Quote-based attacks: Blocked (Anomaly score: 5)

#### 5.4 Path Traversal Tests
```bash
# Basic traversal
curl -i -H "Host: whoami.localhost" "http://localhost:8000/../etc/passwd"

# Encoded traversal
curl -i -H "Host: whoami.localhost" "http://localhost:8000/%2e%2e/%2e%2e/etc/passwd"

# Double-encoded traversal
curl -i -H "Host: whoami.localhost" "http://localhost:8000/%252e%252e/%252e%252e/etc/passwd"
```
⚠️ Results:
- Double-encoded attempts: Blocked
- Recommendation: Consider increasing paranoia level for better path traversal protection

#### 5.5 Command Injection Tests
```bash
# Basic command injection
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?cmd=cat%20/etc/passwd"

# Command chaining
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?cmd=whoami;id"

# Command substitution
curl -i -H "Host: whoami.localhost" "http://localhost:8000/?cmd=\$(id)"
```
✅ Results:
- Basic command injection: Blocked (Anomaly score: 10)
- Command chaining: Blocked (Anomaly score: 5)
- Command substitution: Blocked (Anomaly score: 5)

#### 5.6 Security Headers
The setup includes essential security headers:
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-Permitted-Cross-Domain-Policies: none
- Referrer-Policy: strict-origin-when-cross-origin
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

#### 5.7 ModSecurity Audit Logging
- Format: JSON
- Location: `/var/log/modsec/audit.log`
- Includes: Attack details, anomaly scores, and matched rules
- View logs: `docker logs modsecurity`
```

All these requests should be blocked with a 403 Forbidden response.

### 6. Customizing Rules

To modify security rules:
1. Adjust environment variables in `docker-compose.yaml`:
   - `PARANOIA`: Set paranoia level (1-4)
   - `ANOMALY_INBOUND`: Inbound anomaly score threshold
   - `ANOMALY_OUTBOUND`: Outbound anomaly score threshold
2. Restart containers to apply changes:
   ```bash
   docker compose restart
   ```

### 7. Viewing Logs

To check ModSecurity audit logs:
```bash
docker logs modsecurity
```

### 8. Security Considerations

For production use:
1. Enable HTTPS with proper certificates
2. Disable Traefik dashboard or secure it
3. Adjust paranoia levels based on your security needs
4. Regular monitoring of audit logs
5. Keep Core Rule Set updated

### 7. Checking Logs

To view security logs:
```bash
docker compose logs modsecurity
```

## Security Notes

- Default configuration is set to high security (Paranoia Level 3)
- All sensitive endpoints are protected
- Authentication is required for sensitive operations
- Regular security updates are recommended

## Troubleshooting

1. If services don't start:
   ```bash
   docker compose down
   docker compose up -d
   ```

2. If rules are too strict:
   - Lower the paranoia level in `modsec/crs-setup.conf`
   - Restart the services

3. To check if WAF is working:
   ```bash
   curl http://localhost:8000/
   ```
   Should show a normal response for valid requests.

## Contributing

Feel free to open issues or submit pull requests if you have suggestions for improvements!