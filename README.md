# GV-Simple-Firewall

A lightweight, performance-focused firewall providing essential security hardening for WordPress sites.

Core Protections: Blocks XML-RPC access, filters common bad user agents, and includes basic signature detection against SQL injection and XSS attempts.

Rate Limiting: Protects against brute-force attacks by limiting login and XML-RPC attempts per IP.

Secure File Logging: Logs blocked events to a protected directory within wp-content/uploads, secured with .htaccess rules to prevent public access.

IP/CIDR Management: Supports Allow/Deny lists for specific IP addresses or network ranges.

Optional HTTPS Enforcement: Can force SSL for login and admin pages.
