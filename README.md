GV-Simple-Firewall

A lightweight, performance-focused firewall providing essential security hardening for WordPress sites.

This plugin is designed to be a simple, "set it and forget it" security baseline that blocks the most common attacks without complex configuration or performance overhead.


# GV Simple Firewall

## Minimal WordPress request firewall plugin
Blocks XML-RPC, bad user-agents, and common injection patterns. Adds rate limits, REST & enumeration hardening, security headers, and lightweight logging.

---

# Changelog: Version 2.0

## ✨ New Features

### Security Headers
Added a new option to send essential security headers (**HSTS**, **X-Frame-Options**, **X-Content-Type-Options**, **Referrer-Policy**, **Permissions-Policy**).

### Content-Security-Policy (CSP)
The plugin now sends a robust, baseline CSP (in "Report-Only" mode by default) to help block XSS and data-injection attacks.

### REST API Hardening
Added an option to block unauthenticated requests to the **wp/v2/users** REST endpoint, preventing user-enumeration.

### User Enumeration Blocking
Added an option to block **?author=N** scans with a 404 error.

### HTTP Method Gate
Added a new protection to block all HTTP methods except **GET**, **HEAD**, and **POST**, returning a 405 error.

### Per-Username Rate Limiting
Added an optional, separate rate limit that throttles login attempts per username, in addition to the existing IP-based limit.

### Log File Manager
The **Tools → GV Firewall Logs** page now lists all available log files from `wp-content/uploads/gv-firewall/` and allows downloading any historical log, not just the latest one.

---

## 🚀 Enhancements

### Major Signature Engine Upgrade
Replaced the basic signature scanner with **trips_signatures_hardened**.  
The new engine is significantly more powerful:
- Scans `$_GET`, `$_POST`, and `$_COOKIE` variables recursively
- Uses a larger, more precise set of regex rules for SQLi, XSS, LFI, and RCE

### Detailed Block Logging
Signature-based blocks now include detailed context in the logs such as:
- **RULE** triggered
- **SOURCE** (e.g., POST, COOKIE)
- **KEY** (parameter name)
- **VALUE** (truncated)

### Robust Log Parser
Re-engineered **parse_log_line** to read all detailed fields in any order.

### Improved Dashboard Widgets
The “Recent Blocks” and “Recent Logins” widgets now read from **all log files (newest first)**, making them more reliable after daily log rotation.

### UI Update
Added new sections and toggles to the admin settings page for all new features.

---

## 🧠 Notes
- Requires **WordPress 6.0+** and **PHP 7.4+**
- Logs stored at `wp-content/uploads/gv-firewall/`
- Compatible with **GardeVault Core**, but works standalone

---

## 🛡️ Author
**GardeVault**  
[https://gardevault.eu/plugins/gv-simple-firewall](https://gardevault.eu/plugins/gv-simple-firewall)


#### Screenshots

![GV Firewall Main Settings UI](./assets/imgs/gvfirewall.png)
*The main firewall dashboard, showing settings, recent blocks, and recent logins.*

####Features

Modern Admin UI: A clean, dark-mode-first interface. No more boring settings tables.

NEW - Login Logging: Optionally log all successful and failed login attempts, including the username, to easily monitor access.

NEW - Dashboard Widgets: See Recent Blocks and Recent Logins in real-time directly on the firewall's admin page.

Core Protections: Blocks XML-RPC access, filters common bad user agents, and includes basic signature detection against SQL injection (SQLi) and Cross-Site Scripting (XSS) attempts.

Rate Limiting: Protects against brute-force attacks by limiting login and XML-RPC attempts per IP.

Advanced IP/CIDR Management: Supports IPv4 & IPv6 for Allow/Deny lists. The IP lists are now more flexible, accepting commas, spaces, or newlines as separators.

Smart IP Detection: Accurately identifies visitor IPs, even behind reverse proxies like Cloudflare or Load Balancers.

Secure File Logging: Logs all blocked events to a protected directory within wp-content/uploads, secured with .htaccess and index.html rules.

Optional HTTPS Enforcement: Can force SSL for wp-login.php and the /wp-admin/ area.

####Installation

Download the latest .zip file from the Releases page.

In your WordPress admin, go to Plugins > Add New.

Click Upload Plugin and choose the .zip file you downloaded.

Activate the plugin.

Find the new "GV Firewall" menu item in your WordPress admin sidebar to configure settings.
