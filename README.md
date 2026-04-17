WordPress LEMP Auto-Provisioner (Ubuntu 24.04)

Overview
This tool provisions a production-ready WordPress hosting stack on a fresh Ubuntu 24.04 VPS (4 GB RAM / 40 GB disk recommended) and creates WordPress sites in one command.

What you get
- LEMP stack: Nginx, PHP 8.3 (FPM), MySQL (server), Redis
- Security: UFW firewall, Fail2ban, Nginx hardening (rate limits, XML-RPC off, bad-bot blocking), unattended security updates, optional SSH key setup (with password auth disable)
- WordPress: Latest core via WP-CLI, auto-updates enabled, optional plugins and theme installation
- Backups: Daily database/files backup with rotation
- Traffic analytics: AWStats with hourly updates and daily static HTML reports (protected by HTTP Basic Auth)
- HTTPS: Опциональная автоматическая выдача и настройка сертификатов Let's Encrypt (certbot --nginx, с редиректом на HTTPS)
- Credentials: All generated credentials are shown at the end and saved under /root/wp-stack-credentials-<domain>.txt

Files
- wp-stack-ubuntu24.sh – main script with interactive menu
- wp-stack-ubuntu24-apache.sh – Apache (LAMP) variant with the same features
- lemp-wp-backup.sh, lamp-wp-backup.sh – legacy scripts (kept for reference)

Requirements
- OS: Ubuntu 24.04 (tested). Must run as root.
- Fresh VPS recommended. Script is idempotent for most steps.

Quick start
1) Base stack install/update
	- Nginx: sudo bash wp-stack-ubuntu24.sh → 1) Install/Update Base LEMP Stack
	- Apache: sudo bash wp-stack-ubuntu24-apache.sh → 1) Install/Update Base LAMP Stack (Apache)
	- Optionally: вставьте SSH-публичный ключ для root и отключите парольную аутентификацию

2) Create a new WordPress site
	- Nginx: sudo bash wp-stack-ubuntu24.sh → 2) Create New WordPress Site
	- Apache: sudo bash wp-stack-ubuntu24-apache.sh → 2) Create New WordPress Site (Apache)
	- Provide: domain (example.com), Linux username, admin email, site title
	 - Optionally: comma-separated plugin slugs (e.g. redis-cache,wordpress-seo,contact-form-7) and a theme slug (e.g. astra)
	- Примечание: на этом шаге скрипт НЕ переустанавливает LEMP-стек. Он только проверяет, что службы запущены, и при необходимости установит WP-CLI.
	- После создания сайта скрипт предложит автоматически выпустить SSL-сертификат (Let's Encrypt). Для включения www.<domain> автоматически проверяется наличие DNS‑записи, иначе www будет пропущен.

Outputs
- All credentials and important paths are printed at the end and saved to: /root/wp-stack-credentials-<domain>.txt
- Includes Linux user, database credentials, WP admin login, backup location, and AWStats access (URL + basic-auth).
 - Сводка с логинами/паролями также печатается в консоль после завершения создания сайта.

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
	- Nginx использует универсальный сокет /run/php/php-fpm.sock (скрипт создаёт symlink к актуальной версии PHP-FPM)

- MySQL (local)
	- Basic hardening (remove test DB, empty users, restrict root to localhost)
	- Per-site DB/user with random strong password
	- Поддержка MySQL/MariaDB (службы mysql/mariadb/mysqld)

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
 - Для успешного выпускa сертификатов Let's Encrypt домен(ы) должны указывать на IP сервера (DNS A/AAAA записи), а прокси (например, Cloudflare) — по возможности отключён на время выдачи (или используйте DNS‑челлендж вручную)

Tips
- Plugin/theme slugs are the same as on wordpress.org (e.g., contact-form-7, classic-editor, astra)
- If Redis is desired, include the redis-cache plugin slug; it is auto-enabled if present
- Linux username: допускаются только латинские буквы, цифры и подчёркивание; имя автоматически нормализуется к нижнему регистру и не может начинаться с цифры.

Troubleshooting
- 413 Request Entity Too Large при загрузке плагина/темы:
	- В nginx для новых сайтов лимит уже выставлен (client_max_body_size 128M) в vhost-конфиге.
	- Скрипт также ставит глобальный лимит client_max_body_size 128M (conf.d/uploads.conf), что покрывает HTTP и HTTPS (включая серверные блоки Certbot).
	- Если меняли конфиги вручную, убедитесь, что нигде не переопределён меньший лимит.
	- Убедитесь, что в PHP (php.ini FPM) upload_max_filesize и post_max_size >= размеру архива (скрипт настраивает по 128M).
	- Перезагрузите nginx и php-fpm: systemctl reload nginx && systemctl restart php*-fpm

- 405 Not Allowed при обновлении/установке через админку:
	- Исправлено в сниппете wp-protect.conf: admin-ajax.php направляется в PHP-FPM. Перезагрузите nginx.

- Ошибки БД для плагина Redirection (например, отсутствуют таблицы wp_redirection_*):
	- Часто решается переактивацией: wp plugin deactivate redirection && wp plugin activate redirection
	- Затем в админке пройдите Tools → Redirection и завершите установку/миграцию БД (кнопка Finish setup/Upgrade).

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