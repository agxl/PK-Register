<div align="center">
  <h1>🚀 PK-Register</h1>
  <p><b>The Ultimate, Database-Free Plesk Registration Portal</b></p>
  <p>
    <i>Developed by Andy Goldau | © 2026 PanelLayer (Subdomain LTD) &amp; GoMaKe UG</i>
  </p>
  <p>
    📦 <b>Product Page:</b> <a href="https://pk-register.panellayer.com/">PK-Register</a> &nbsp;|&nbsp;
    🧪 <b>Live Demo:</b> <a href="https://demo.pk-register.panellayer.com/">Demo</a> &nbsp;|&nbsp;
    🌐 <b>Project:</b> <a href="https://panellayer.com/">PanelLayer</a>
  </p>
</div>

---

**PK-Register** is an incredibly robust, secure, and fully-featured self-service registration portal built specifically for **Plesk**. Designed from the ground up for maximum security, beautiful UI/UX, and GDPR compliance, it requires **zero database setup** (100% flat-file logic) and handles user & subscription creation flawlessly through a **Dual API Engine** supporting both **Plesk REST API v2** and **Plesk XML-RPC API**.

> **DISCLAIMER:** This software is provided "as is" without any warranty of any kind. PK-Register is an independent software solution and is not affiliated with, endorsed by, or sponsored by Plesk International GmbH or its affiliates.

---

## ✨ Enterprise-Grade Features

### 🔌 Dual API Engine (REST API v2 & XML-RPC)
- **REST API v2 Mode (`rest_api`):** Uses modern JSON REST API calls (`/api/v2/clients` and `/api/v2/domains`) authenticated via API Key (`PLESK_API_KEY`). Ideal for Plesk Administrators.
- **XML-RPC API Mode (`xmlrpc`):** Communicates with Plesk's XML API (`/enterprise/control/agent.php`) using credentials (`PLESK_API_LOGIN` / `PLESK_API_PASSWORD`) or API secret keys. Perfect for Resellers without API Token generation rights or legacy Plesk environments.
- **Automatic Fallback & Error Mapping:** Human-readable error messages for both REST and XML-RPC API error responses.

### 🛡️ Unrivaled Security & Privacy
- **k-Anonymity Password Checks:** Integrates the *Have I Been Pwned* API directly in the client's browser using the Web Crypto API. Only the first 5 characters of a SHA-1 hash are transmitted—your plaintext password never leaves your browser.
- **Advanced Rate-Limiting (Token Bucket):** Fully protects the Plesk API against brute-force and DDoS spam attacks using a highly efficient, session-independent Token Bucket algorithm based on cryptographically hashed IPs.
- **No Database Required:** Works strictly with local flat files (JSON/PHP). All sensitive log files (`audit.log.php`, `used_codes.php`, `demo_accounts.json`) are completely locked down and unreadable from the web via `.htaccess`.
- **Strict Content Security Policy (CSP):** Ships with hardened HTTP response headers (CSP, HSTS, X-Frame-Options) out of the box, mitigating XSS and iframe-injection attacks.

### 🌐 Internationalization & UX
- **23+ Supported Languages:** Comes fully translated into 23 languages including English, German, French, Spanish, Russian, Chinese, Japanese, Thai, and more.
- **Automatic Dark/Light Mode:** Adapts its premium UI automatically to the system color scheme preferences of your users.
- **Full Name Field:** Registration collects a separate mandatory **Full Name** field (in addition to username) which is transmitted to Plesk as the customer display name — configurable via `PLESK_USERNAME_AS_NAME`.
- **Live Password Checklist:** A real-time, side-by-side interactive UI element that instantly visually validates password complexity requirements.
- **Fail-open DNS MX Checks:** Automatically verifies the existence of mail servers (MX records) for the email domains entered during registration to prevent bot signups, featuring built-in caching.

### ⏳ Demo Mode & Web Cron Cleanup
- **Automatic Account Expiry:** Supports a built-in Demo Mode (`DEMO_MODE`) with automatic cleanup script (`cron_cleanup.php`) protected by `CRON_SECRET_KEY` via web cron or CLI.

### 🤖 Ultimate Anti-Bot Protection
Forget spam. We support natively integrated setups for:
- **hCaptcha**
- **reCAPTCHA (Google)**
- **Cloudflare Turnstile**
- **Altcha** (Proof-of-Work, 100% GDPR compliant)
- **MTCaptcha**

### 🎟️ Exclusive Access Modes
- **Invite-Only Mode:** Optionally lock your registration portal so only users with pre-generated, single-use, or multi-use invitation codes can join your platform.

---

## 🔌 How it Works (Plesk Dual API)

Registration is handled in **two sequential API calls** depending on your configured `PLESK_AUTH_METHOD`:

### Option A: REST API v2 (`PLESK_AUTH_METHOD = 'rest_api'`)
1. **`POST /api/v2/clients`** — Creates the customer account (login, password, full name, email). Returns a `client_id`.
2. **`POST /api/v2/domains`** — Creates the hosting subscription and links it to the new client using the `client_id`, applying the configured Service Plan and IP address.
*Authenticated via `X-API-Key` header with `PLESK_API_KEY`.*

### Option B: XML-RPC API (`PLESK_AUTH_METHOD = 'xmlrpc'`)
1. **`<customer><add>`** — Sends an XML request to `/enterprise/control/agent.php` to create the customer. Returns the customer `id`.
2. **`<webspace><add>`** — Sends an XML request to create the hosting subscription linked to the customer `id`, applying the Service Plan (`gen_setup -> plan-name`) and IP address.
*Authenticated via HTTP Basic Auth or HTTP headers using `PLESK_API_LOGIN` & `PLESK_API_PASSWORD` (works for Resellers and Admins).*

---

## 🚀 Installation & Setup

1. **Upload & Extract:** Upload the contents to any PHP 8.x web directory.
2. **Configure:** Open `config.php` (or copy from `config-blank.php`) and enter your:
   - **`PLESK_HOST`** — Your Plesk server URL (e.g. `https://plesk.example.com`)
   - **`PLESK_PORT`** — Default is `8443`
   - **`PLESK_AUTH_METHOD`** — Select `'rest_api'` or `'xmlrpc'`
   - **Authentication:**
     - For REST API (`'rest_api'`): Set `PLESK_API_KEY` (Plesk Panel → Tools & Settings → Remote API (REST) → API Tokens → Add Token)
     - For XML-RPC (`'xmlrpc'`): Set `PLESK_API_LOGIN` and `PLESK_API_PASSWORD` (Reseller or Admin credentials)
   - **`PLESK_SERVICE_PLAN`** — Exact name of an existing Hosting Plan in Plesk
   - **`PLESK_IP`** — A valid IP address from your Plesk server's IP pool
   - **`PLESK_USERNAME_AS_NAME`** — Set to `false` (default) to show the separate Full Name field; set to `true` to use the username as the Plesk display name instead
   - **`CRON_SECRET_KEY`** — Secret key for web-accessible cron cleanup in Demo Mode
   - Desired Captcha Provider Keys
   - Security toggles (HIBP, Invite-Mode, Audit Logging)
3. **Generate a Salt:** Replace the default `LOG_IP_SALT` in `config.php` with a random 32-character string to ensure IP pseudonymization in your audit logs.
   ```bash
   openssl rand -hex 16
   ```
4. **Done:** The system automatically creates and protects the necessary `data/` and `logs/` folders upon the first registration.

---

## ⚙️ Plesk API Prerequisites

- **REST API v2 Mode:**
  - Plesk Obsidian **18.0.47+**
  - The API Token must be generated by an **Administrator** or a **Reseller** with API access.
- **XML-RPC API Mode:**
  - Compatible with all Plesk Obsidian versions.
  - For Resellers: The Plesk Admin must enable **"Ability to use XML API"** in *Plesk Panel → Resellers → [Account] → Permissions*.
- **Hosting Plan:** The `PLESK_SERVICE_PLAN` must exist as a **Service Plan / Hosting Plan** in Plesk.
- **IP Address:** `PLESK_IP` must be a valid IP address in the Plesk server's IP pool.

---

## 📄 License & Attribution

This project is licensed under the **MIT License**.

> **Developer:** Andy Goldau  
> **Copyright:** © 2026 PK-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.  
> **Project:** [https://panellayer.com/](https://panellayer.com/)

The above copyright notice, the developer attribution, and the permission notice must be included in all copies or substantial portions of the Software.
