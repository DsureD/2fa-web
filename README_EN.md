<div align="center">

 English | [中文](README.md)

# 2FA Web Authenticator

**An elegant, secure, and ready-to-use web-based two-factor authenticator.**

Break free from phone apps — manage your TOTP codes in any browser, self-hosted, with full control over your data.

</div>
---

## Why 2FA Web?

### Access Anywhere

No more pulling out your phone to open Google Authenticator. Open your browser, enter your password, and your codes are right there. Click to copy, double your efficiency.

### Extremely Lightweight

The entire project consists of just **1 Python file + 1 HTML file**, with only 3 Python dependencies. No Node.js, no build steps, no complex configuration. Run `pip install` and you're up in 30 seconds.

### Apple Design Aesthetic

A carefully crafted UI featuring frosted glass effects, rounded cards, smooth animations, and circular countdown timers. Supports light / dark / system-follow theme modes, perfectly adapted for both mobile and desktop.

### Multi-Layer Security

Six layers of security protection from network to data:

| Layer | Protection |
|-------|-----------|
| Network | Strict CSP policy, X-Frame-Options DENY, CDN resource SRI verification |
| Bot Protection | Optional hCaptcha integration (invisible mode, seamless verification) |
| Rate Limiting | Max 5 failed logins within 5 minutes, IP-level lockout |
| Password Security | Constant-time comparison (`hmac.compare_digest`), prevents timing attacks |
| Session Security | HttpOnly / SameSite=Lax / Secure cookies, 12-hour auto-expiration |
| Sensitive Operations | Viewing secrets and deleting accounts require secondary password verification |

### Full Data Ownership

All data is stored in a local SQLite database with no reliance on any third-party cloud services. Your secrets never leave your server.

---

## Features

- **Code Management** — Add, edit, delete TOTP accounts with real-time 6-digit / 8-digit code display
- **Smart Refresh** — Local second-level countdown + automatic fetch on expiry, smooth and flicker-free
- **QR Code Scanning** — Upload an image or Ctrl+V paste a QR code, auto-parse otpauth:// URIs
- **QR Code Export** — One-click QR code generation for easy migration to phone apps
- **Group Management** — Organize by service, quick filtering, create / rename / delete groups
- **Search & Filter** — Real-time search by site name, username, notes, or group
- **One-Click Copy** — Click the code or copy button to automatically write to clipboard
- **Multi-Algorithm Support** — SHA1 / SHA256 / SHA512 algorithms, 30s / 60s periods
- **Theme Switching** — Light / dark / system-follow, preferences persisted locally
- **Responsive Layout** — Perfect adaptation for phones, tablets, and desktops, with PWA safe-area support
- **hCaptcha** — Optional, invisible mode seamless bot protection

---

## Quick Start

### Requirements

- Python 3.8+

### Installation & Running

```bash
# Clone the project
git clone https://github.com/yourname/2fa-web.git
cd 2fa-web

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env to set your passwords and keys

# Start
python app.py
```

Open your browser and visit `http://localhost:5000`, enter your password to get started.

### Environment Variables

Create a `.env` file in the project root directory:

```ini
# Required - Login password
ACCESS_PASSWORD=your_strong_password_here

# Optional - Secondary password for sensitive operations (viewing secrets/deleting accounts, leave empty to disable)
SENSITIVE_PASSWORD=

# Optional - hCaptcha bot protection (leave empty to disable)
HCAPTCHA_SITE_KEY=
HCAPTCHA_SECRET_KEY=

# Flask session secret key (recommended: set to a random long string)
SECRET_KEY=change_me_to_a_random_string

# Server listening configuration
HOST=0.0.0.0
PORT=5000
DEBUG=false
```

---

## Production Deployment

Recommended setup: **Nginx reverse proxy + HTTPS**:

```nginx
server {
    listen 443 ssl http2;
    server_name 2fa.yourdomain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> **Important**: Always use HTTPS in production. The application automatically enables Secure cookies in non-DEBUG mode, requiring an HTTPS connection.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python / Flask 3.1 |
| Database | SQLite (WAL mode) |
| TOTP | PyOTP 2.9 |
| Frontend | Vanilla HTML / CSS / JS (no frameworks) |
| QR Decode | jsQR 1.4 (CDN + SRI) |
| QR Encode | qrcode-generator 1.4 (CDN + SRI) |
| Bot Protection | hCaptcha (optional) |

---

## Project Structure

```
2fa-web/
  app.py              # Backend: all APIs and business logic
  templates/
    index.html         # Frontend: complete single-page application
  requirements.txt     # Python dependencies (only 3)
  .env                 # Environment config (not version-controlled)
  2fa.db               # SQLite database (auto-created)
```

No Webpack, no Babel, no node_modules. Copy the entire project to any machine and it just runs.

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/login` | Login (rate-limited + hCaptcha) |
| `POST` | `/api/logout` | Logout |
| `GET` | `/api/status` | Login status and configuration info |
| `GET` | `/api/accounts` | Get all accounts with real-time codes |
| `POST` | `/api/accounts` | Add account |
| `PUT` | `/api/accounts/<id>` | Update account |
| `DELETE` | `/api/accounts/<id>` | Delete account (requires sensitive password) |
| `GET` | `/api/totp/<id>` | Get single TOTP code |
| `POST` | `/api/accounts/<id>/secret` | Get secret (requires sensitive password) |
| `GET` | `/api/groups` | List groups |
| `POST` | `/api/groups` | Create group |
| `POST` | `/api/groups/rename` | Rename group |
| `DELETE` | `/api/groups` | Delete group |

---

## Security Notes

- TOTP secrets are stored in plaintext in the database. Security relies on server filesystem permissions and access control. Ensure your server itself is secure.
- Login rate limiting is memory-based and resets on service restart.
- External JS libraries are loaded via CDN with SRI (Subresource Integrity) verification to ensure resources have not been tampered with.
- It is recommended to restrict access source IPs in production, or deploy within an intranet / VPN environment.

---

## License

MIT License
