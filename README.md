# GV-Simple-Firewall
Okay, great news that the Cloudflare integration is working and logging correctly in your gv-core plugin!

Here are some concise descriptions for your GitHub README.md or website, highlighting the key strengths of each plugin based on the code you provided:

1. GV Contact Form Pro

A robust and secure AJAX contact form for WordPress. Features include:

Visual Form Builder: Easily create and manage form fields via drag-and-drop.

CPT Storage: Securely stores submissions as private Custom Post Type entries, keeping your database clean.

Multi-Layered Spam Defense: Combines honeypot, server-side reCAPTCHA v3 verification, and IP/UA rate limiting.

Performance Optimized: Lazy-loads reCAPTCHA JS for minimal impact on page speed scores.

Admin Features: Includes GDPR consent checkbox, auto-reply emails, and easy CSV export of entries.

2. GV Simple 2FA

A hardened Two-Factor Authentication (2FA) solution for WordPress logins, prioritizing security and usability.

TOTP Standard: Works with standard authenticator apps (Google Authenticator, Authy, etc.).

Secure Login Flow: Intercepts login after password validation using a dedicated, transient-protected verification page.

Backup Codes: Provides secure, one-time-use backup codes for recovery.

Signed "Remember Device": Implements a robust, HMAC-signed cookie mechanism for the "Remember Me" feature.

Role Enforcement: Allows administrators to require 2FA for specific user roles.

3. GV Simple Firewall

A lightweight, performance-focused firewall providing essential security hardening for WordPress sites.

Core Protections: Blocks XML-RPC access, filters common bad user agents, and includes basic signature detection against SQL injection and XSS attempts.

Rate Limiting: Protects against brute-force attacks by limiting login and XML-RPC attempts per IP.

Secure File Logging: Logs blocked events to a protected directory within wp-content/uploads, secured with .htaccess rules to prevent public access.

IP/CIDR Management: Supports Allow/Deny lists for specific IP addresses or network ranges.

Optional HTTPS Enforcement: Can force SSL for login and admin pages.
