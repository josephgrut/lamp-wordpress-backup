WordPress LEMP Auto-Provisioner (Ubuntu 24.04)

Overview
This tool provisions a production-ready WordPress hosting stack on a fresh Ubuntu 24.04 VPS (4 GB RAM / 40 GB disk recommended) and creates WordPress sites in one command.

What you get
- LEMP stack: Nginx, PHP 8.3 (FPM), MySQL (server), Redis
- Security: UFW firewall, Fail2ban, Nginx hardening (rate limits, XML-RPC off, bad-bot blocking), unattended security updates, optional SSH key setup (with password auth disable)
- WordPress: Latest core via WP-CLI, auto-updates enabled, optional plugins and theme installation
- Backups: Daily database/files backup with rotation
- Traffic analytics: AWStats with hourly updates and daily static HTML reports (protected by HTTP Basic Auth)
- Credentials: All generated credentials are shown at the end and saved under /root/wp-stack-credentials-<domain>.txt

Files
- wp-stack-ubuntu24.sh – main script with interactive menu
- lemp-wp-backup.sh, lamp-wp-backup.sh – legacy scripts (kept for reference)

Requirements
- OS: Ubuntu 24.04 (tested). Must run as root.
- Fresh VPS recommended. Script is idempotent for most steps.

Quick start
1) Base stack install/update
	 - Run: sudo bash wp-stack-ubuntu24.sh
	 - Choose: 1) Install/Update Base LEMP Stack
	- Optionally: вставьте SSH-публичный ключ для root и отключите парольную аутентификацию

2) Create a new WordPress site
	 - Run: sudo bash wp-stack-ubuntu24.sh
	 - Choose: 2) Create New WordPress Site
	 - Provide: domain (example.com), Linux username, admin email, site title
	 - Optionally: comma-separated plugin slugs (e.g. redis-cache,wordpress-seo,contact-form-7) and a theme slug (e.g. astra)

Outputs
- All credentials and important paths are printed at the end and saved to: /root/wp-stack-credentials-<domain>.txt
- Includes Linux user, database credentials, WP admin login, backup location, and AWStats access (URL + basic-auth).

Features in detail
- Nginx
	- Per-site vhost under /etc/nginx/sites-available/<domain>.conf
	- Separate logs in /var/log/nginx/<domain> (used by AWStats)
	- PHP handling via /run/php/php8.3-fpm.sock
	- Rate limiting for /wp-login.php and /wp-admin/admin-ajax.php
	- XML-RPC disabled by default
	- Bad-bot blocking based on User-Agent map

- PHP 8.3 tuning
	- memory_limit=256M, upload_max_filesize/post_max_size=128M, max_execution_time=300
	- opcache enabled and sized for production

- MySQL (local)
	- Basic hardening (remove test DB, empty users, restrict root to localhost)
	- Per-site DB/user with random strong password

- WordPress via WP-CLI
	- Latest core download, config with salts, secure defaults
	- FS_METHOD=direct, auto-updates enabled, file editor disabled
	- Optional plugin and theme installation in one go
	- Real cron: runs wp cron event run --due-now every 5 minutes via /etc/cron.d

- Backups
	- Daily 03:30 cron: dumps DB and archives site files + Nginx logs to /var/www/<user>/<domain>/backups
	- Retains 7 days by default (edit /usr/local/bin/wp-backup-<domain>.sh)

- AWStats
	- Installed via apt; per-site config under /etc/awstats/awstats.<domain>.conf
	- Hourly updates, daily static HTML report in /var/www/<user>/<domain>/www/awstats
	- Access at http://<domain>/awstats/ (protected with basic auth – credentials are in the summary file)

Security notes
- UFW allows OpenSSH and Nginx Full by default
- Fail2ban enabled for SSH and a basic nginx-4xx jail for repeated 403/404
- For HTTPS, set up TLS (e.g., with Certbot) after DNS points to the server
 - SSH: скрипт может установить SSH-ключ для root и (по желанию) отключить вход по паролю; после отключения входите по ключу

Tips
- Plugin/theme slugs are the same as on wordpress.org (e.g., contact-form-7, classic-editor, astra)
- If Redis is desired, include the redis-cache plugin slug; it is auto-enabled if present

Uninstall/cleanup (manual)
- Remove site vhost: /etc/nginx/sites-enabled/<domain>.conf and reload Nginx
- Drop DB/user: use mysql and run DROP DATABASE and DROP USER
- Remove site files under /var/www/<user>/<domain>
- Remove cron files under /etc/cron.d (backup-, awstats-, wp-cron-)

Versioning
- Script version is defined at the top of wp-stack-ubuntu24.sh (VERSION)

Changelog
- 1.0.0 – Initial Ubuntu 24.04 release: LEMP, WP-CLI, AWStats, backups with rotation, bot protection, credentials summary

License
MIT