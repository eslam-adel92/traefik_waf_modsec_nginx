# Traefik with ModSecurity WAF

This project sets up a Web Application Firewall (WAF) using Traefik as a reverse proxy and ModSecurity for security rules. It's designed to protect your web applications from common attacks.

## What's Included

- **Traefik (v3.5.4)**: Acts as the main gateway for web traffic
- **ModSecurity**: Provides security rules to protect against attacks
- **Core Rule Set (CRS)**: A set of security rules that protect against common web attacks

## Project Structure

```
├── docker-compose.yaml       # Main configuration for all services
├── modsec/
│   ├── crs-setup.conf       # Core Rule Set configuration
│   ├── modsec.conf         # ModSecurity main configuration
│   └── data/
│       └── audit/          # Security audit logs
└── traefik/
    ├── traefik.yaml        # Main Traefik configuration
    └── config/
        └── dynamic.yaml    # Traefik dynamic configuration
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
- Port 8080: Traefik dashboard (disabled by default for security)
- Automatic HTTPS redirect
- Security headers enabled

#### ModSecurity Configuration
- Paranoia Level: 3 (Strong security)
- Anomaly Scoring: Enabled
- Core Rule Set: v3.3.7
- Audit logging: Enabled

### 5. Testing the Security

You can test if the WAF is working by trying these (they should be blocked):

```bash
# Try to access a sensitive file
curl http://localhost:8000/.env

# Try a basic SQL injection
curl "http://localhost:8000/api/users?id=1%20OR%201=1"

# Try an XSS attack
curl "http://localhost:8000/?q=<script>alert(1)</script>"
```

All these requests should be blocked with a 403 Forbidden response.

### 6. Customizing Rules

To modify security rules:
1. Edit `modsec/crs-setup.conf` for Core Rule Set settings
2. Edit `modsec/modsec.conf` for ModSecurity main settings
3. Restart containers to apply changes:
   ```bash
   docker compose restart
   ```

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