#!/usr/bin/env bash
set -Eeuo pipefail

# WordPress LEMP Auto-Provisioner for Ubuntu 24.04
# Version: 1.0.0
# Author: Your Team
# License: MIT

# Changelog (see README.md for details):
# 1.0.0 - Initial release for Ubuntu 24.04 (LEMP, WP-CLI, AWStats, backups, basic bot protection)

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

VERSION="1.0.0"

log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
err()  { echo -e "[x] $*" >&2; }

# Basic error trap to surface failing step
trap 'err "Error on line $LINENO: $BASH_COMMAND"' ERR

random_password() {
  # 24-char mixed password
  tr -dc 'A-Za-z0-9!@#%^*_+-=' </dev/urandom | head -c 24
}

# Normalize and validate a Linux username: lowercase, [a-z0-9_], start with a letter, max 31 chars
normalize_linux_username() {
  local in="$1"
  local out
  out=$(echo -n "$in" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_')
  out=$(echo -n "$out" | sed -E 's/^[^a-z]+//')
  out=${out:0:31}
  echo -n "$out"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

ensure_ubuntu_2404() {
  . /etc/os-release
  if [[ "${ID}" != "ubuntu" ]]; then
    err "This script supports Ubuntu only. Detected: ${ID}"
    exit 1
  fi
  if [[ "${VERSION_ID}" != "24.04" ]]; then
    warn "Detected Ubuntu ${VERSION_ID}. Continuing, but tested on 24.04 only."
  fi
}

apt_install_base() {
  log "Updating system and installing base packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y \
    software-properties-common apt-transport-https ca-certificates \
    curl wget unzip zip git htop mc nano jq pwgen whois \
    ufw fail2ban unattended-upgrades openssh-server \
    nginx mysql-server \
    php8.3 php8.3-fpm php8.3-cli php8.3-opcache php8.3-mysql php8.3-curl \
    php8.3-xml php8.3-zip php8.3-mbstring php8.3-gd php8.3-intl php8.3-soap \
    php-imagick redis-server php8.3-redis \
    awstats perl apache2-utils

  systemctl enable --now nginx
  systemctl enable --now mysql
  systemctl enable --now php8.3-fpm
  systemctl enable --now redis-server
}

secure_mysql_if_needed() {
  # On Ubuntu 24.04, MySQL root typically uses auth_socket. We run secure steps directly.
  log "Hardening MySQL (local only, remove test DB)..."
  mysql --protocol=socket <<SQL
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
SQL
}

configure_php() {
  log "Configuring PHP 8.3..."
  local ini=/etc/php/8.3/fpm/php.ini
  sed -ri 's/^;?memory_limit\s*=.*/memory_limit = 256M/' "$ini"
  sed -ri 's/^;?upload_max_filesize\s*=.*/upload_max_filesize = 128M/' "$ini"
  sed -ri 's/^;?post_max_size\s*=.*/post_max_size = 128M/' "$ini"
  sed -ri 's/^;?max_execution_time\s*=.*/max_execution_time = 300/' "$ini"
  sed -ri 's/^;?opcache.enable\s*=.*/opcache.enable=1/' "$ini"
  sed -ri 's/^;?opcache.memory_consumption\s*=.*/opcache.memory_consumption=256/' "$ini"
  sed -ri 's/^;?opcache.max_accelerated_files\s*=.*/opcache.max_accelerated_files=20000/' "$ini"
  sed -ri 's/^;?cgi.fix_pathinfo\s*=.*/cgi.fix_pathinfo=0/' "$ini"
  systemctl restart php8.3-fpm
}

configure_ufw() {
  log "Configuring UFW firewall..."
  ufw --force reset || true
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
  ufw --force enable
}

configure_unattended_upgrades() {
  log "Enabling unattended security upgrades..."
  dpkg-reconfigure -f noninteractive unattended-upgrades || true
}

setup_ssh_access() {
  echo ""; echo "--- SSH access setup (optional) ---"
  read -rp "Add SSH public key for root user now? [y/N]: " addkey
  if [[ "${addkey,,}" == "y" ]]; then
    read -rp "Paste SSH public key (ssh-ed25519/ssh-rsa...): " sshkey
    if [[ -z "$sshkey" || "$sshkey" != ssh-* ]]; then
      warn "SSH key not provided or invalid. Skipping."
    else
      install -d -m 700 /root/.ssh
      touch /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
      if ! grep -Fq "$sshkey" /root/.ssh/authorized_keys; then
        echo "$sshkey" >> /root/.ssh/authorized_keys
      fi
      log "SSH key installed for root."
    fi
  fi

  read -rp "Disable SSH password authentication? (recommended) [y/N]: " dispass
  if [[ "${dispass,,}" == "y" ]]; then
    local cfg=/etc/ssh/sshd_config
    sed -ri 's/^#?PasswordAuthentication\s+.*/PasswordAuthentication no/' "$cfg"
    sed -ri 's/^#?ChallengeResponseAuthentication\s+.*/ChallengeResponseAuthentication no/' "$cfg"
    sed -ri 's/^#?UsePAM\s+.*/UsePAM yes/' "$cfg"
    # Allow root with key only (no password)
    sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin prohibit-password/' "$cfg"
    sed -ri 's/^#?PubkeyAuthentication\s+.*/PubkeyAuthentication yes/' "$cfg"
    systemctl restart ssh || systemctl restart sshd || true
    log "SSH password authentication disabled. Root login allowed with key only."
  fi
}

install_wp_cli() {
  if ! command -v wp >/dev/null 2>&1; then
    log "Installing WP-CLI..."
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
    chmod +x /usr/local/bin/wp
  fi
}

ensure_site_prereqs() {
  log "Checking prerequisites for site creation..."
  # Ensure core services exist and are running
  if command -v nginx >/dev/null 2>&1; then
    systemctl is-active --quiet nginx || systemctl start nginx || true
  else
    err "Nginx not found. Please run 'Install/Update Base LEMP Stack' first."
    exit 1
  fi

  # Detect MySQL/MariaDB service name robustly
  local db_service=""
  for svc in mysql mariadb mysqld; do
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "${svc}.service"; then
      db_service="$svc"; break
    fi
  done
  if [[ -z "$db_service" ]]; then
    # Fallback: if mysql client exists, try starting common service names
    if command -v mysql >/dev/null 2>&1; then
      for svc in mysql mariadb mysqld; do systemctl start "$svc" 2>/dev/null && db_service="$svc" && break; done
    fi
  fi
  if [[ -z "$db_service" ]]; then
    err "MySQL/MariaDB service not found. Please run 'Install/Update Base LEMP Stack' first."
    exit 1
  else
    systemctl is-active --quiet "$db_service" || systemctl start "$db_service" || true
  fi

  # PHP-FPM 8.3 service check
  local fpm_service="php8.3-fpm"
  if systemctl list-unit-files | awk '{print $1}' | grep -qx "${fpm_service}.service"; then
    systemctl is-active --quiet "$fpm_service" || systemctl start "$fpm_service" || true
  else
    err "PHP 8.3 FPM service not found. Please run 'Install/Update Base LEMP Stack' first."
    exit 1
  fi

  install_wp_cli

  # Ensure global hardening applied at least once
  [[ -f /etc/nginx/conf.d/limits.conf ]] || nginx_global_hardening
}

nginx_global_hardening() {
  log "Configuring Nginx global hardening & rate limits..."
  # Global http context config
  cat >/etc/nginx/conf.d/limits.conf <<'NGX'
limit_req_zone $binary_remote_addr zone=wp:10m rate=10r/s;
map $http_user_agent $bad_bot {
    default 0;
    ~*(ahrefs|semrush|mj12bot|dotbot|curl|wget|python-requests|axios|scrapy|libwww-perl) 1;
}
NGX

  # Snippet to include in server blocks
  mkdir -p /etc/nginx/snippets
  cat >/etc/nginx/snippets/security-common.conf <<'NGX'
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-XSS-Protection "1; mode=block" always;
NGX

  cat >/etc/nginx/snippets/wp-protect.conf <<'NGX'
# Basic bot deny
if ($bad_bot) { return 403; }

# Block XML-RPC (reduce brute force and pingback abuse)
location = /xmlrpc.php { deny all; }

# Harden uploads - no script execution
location ~* /(?:uploads|files)/.*\.php$ { deny all; }

# Tighten login/heartbeat rate limits
location = /wp-login.php { limit_req zone=wp burst=20 nodelay; include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php8.3-fpm.sock; }
location ~* /wp-admin/admin-ajax\.php$ { limit_req zone=wp burst=60 nodelay; }
NGX

  systemctl reload nginx || systemctl restart nginx
}

create_site() {
  local domain user email title plugins theme
  echo "Enter primary domain (example.com):"; read -r domain
  echo "Enter Linux username to own the site (letters, digits, underscore):"; read -r user
  echo "Admin email (WordPress):"; read -r email
  echo "Site title:"; read -r title
  echo "Comma-separated plugin slugs to install (e.g. redis-cache,wordpress-seo,contact-form-7):"; read -r plugins
  echo "Theme slug to install and activate (e.g. astra, generatepress) or leave blank:"; read -r theme

  if [[ -z "$domain" || -z "$user" || -z "$email" || -z "$title" ]]; then
    err "Domain, user, email, and site title are required."
    exit 1
  fi

  # Sanitize and validate Linux username
  local user_raw="$user"
  user=$(normalize_linux_username "$user_raw")
  if [[ -z "$user" ]]; then
    err "Provided username '$user_raw' is invalid after normalization. Use letters, digits or underscore, starting with a letter."
    exit 1
  fi
  if [[ "$user" == "root" ]]; then
    err "Username 'root' is not allowed. Choose another."
    exit 1
  fi
  if [[ "$user" != "$user_raw" ]]; then
    warn "Username normalized to '$user' from '$user_raw'."
  fi

  local db_name db_user db_pass sys_pass admin_user admin_pass root_dir web_dir log_dir backup_dir aw_dir
  db_name="${user//[^a-zA-Z0-9_]/_}_wp"
  db_user="${user//[^a-zA-Z0-9_]/_}_u"
  db_pass=$(random_password)
  sys_pass=$(random_password)
  admin_user="admin"
  admin_pass=$(random_password)

  root_dir="/var/www/${user}/${domain}"
  web_dir="${root_dir}/www"
  log_dir="/var/log/nginx/${domain}"
  backup_dir="${root_dir}/backups"

  log "Creating system user and directories..."
  # Ensure target home path exists prior to adduser (nested path)
  mkdir -p "$web_dir" "$log_dir"
  id -u "$user" >/dev/null 2>&1 || adduser --quiet --disabled-password --gecos "" --home "$web_dir" "$user"
  echo "$user:$sys_pass" | chpasswd
  mkdir -p "$backup_dir"
  chown -R "$user":www-data "/var/www/${user}"
  chmod -R 775 "/var/www/${user}"

    aw_dir="${web_dir}/awstats"
    log "Configuring Nginx vhost for ${domain}..."
  cat >"/etc/nginx/sites-available/${domain}.conf" <<NGX
server {
    listen 80;
    server_name ${domain} www.${domain};
    root ${web_dir};
    index index.php index.html index.htm;

    access_log ${log_dir}/access.log;
    error_log  ${log_dir}/error.log;

    include snippets/security-common.conf;
    include snippets/wp-protect.conf;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp)$ {
        expires max;
        log_not_found off;
    }

    # AWStats static reports (protected)
    location /awstats {
      auth_basic "Restricted";
      auth_basic_user_file ${aw_dir}/.htpasswd;
      alias ${aw_dir}/;
      autoindex on;
      try_files \$uri \$uri/ =404;
    }
}
NGX
  ln -sf "/etc/nginx/sites-available/${domain}.conf" "/etc/nginx/sites-enabled/${domain}.conf"
  nginx -t
  systemctl reload nginx

  log "Creating MySQL database and user..."
  mysql --protocol=socket <<SQL
CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';
FLUSH PRIVILEGES;
SQL

  log "Installing WordPress (latest) via WP-CLI..."
  install_wp_cli
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp core download --force"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config create --dbname='${db_name}' --dbuser='${db_user}' --dbpass='${db_pass}' --dbhost='localhost' --dbprefix='wp_' --skip-check"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set FS_METHOD direct --type=constant --raw"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_AUTO_UPDATE_CORE true --type=constant --raw"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set DISALLOW_FILE_EDIT true --type=constant --raw"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_MEMORY_LIMIT 256M --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_MAX_MEMORY_LIMIT 256M --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_REDIS_HOST 127.0.0.1 --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config shuffle-salts"

  local site_url="http://${domain}"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp core install --url='${site_url}' --title='${title}' --admin_user='${admin_user}' --admin_password='${admin_pass}' --admin_email='${email}'"

  # Plugins
  if [[ -n "${plugins//,/}" ]]; then
    IFS=',' read -ra P_ARR <<<"$plugins"
    for p in "${P_ARR[@]}"; do
      p_trim=$(echo "$p" | xargs)
      [[ -z "$p_trim" ]] && continue
      sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin install '$p_trim' --activate || true"
    done
  fi

  # Theme
  if [[ -n "${theme:-}" ]]; then
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp theme install '${theme}' --activate || true"
  fi

  # Redis cache if plugin requested or installed separately
  if sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin is-installed redis-cache" >/dev/null 2>&1; then
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin activate redis-cache || true"
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp redis enable || true"
  fi

  # WordPress settings requested: disable year/month folders and set permalink structure
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp option update uploads_use_yearmonth_folders 0"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp rewrite structure '/%category%/%postname%'"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp rewrite flush --hard"

  # Set secure permissions for uploads dir
  mkdir -p "$web_dir/wp-content/uploads"
  chown -R "$user":www-data "$web_dir"
  find "$web_dir" -type d -exec chmod 755 {} \;
  find "$web_dir" -type f -exec chmod 644 {} \;

  # robots.txt (basic)
  cat >"$web_dir/robots.txt" <<ROB
User-agent: *
Disallow: /cgi-bin/
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /wp-content/themes/
ROB
  chown "$user":www-data "$web_dir/robots.txt"
  chmod 644 "$web_dir/robots.txt"

  # AWStats per-site configuration and nightly static reports
  log "Configuring AWStats for ${domain}..."
  local awconf="/etc/awstats/awstats.${domain}.conf"
  if [[ ! -f "$awconf" ]]; then
    cp /etc/awstats/awstats.conf "$awconf"
    perl -pi -e "s#^LogFile=.*#LogFile=\"/var/log/nginx/${domain}/access.log\"#" "$awconf"
    perl -pi -e "s#^SiteDomain=.*#SiteDomain=\"${domain}\"#" "$awconf"
    perl -pi -e "s#^HostAliases=.*#HostAliases=\"www.${domain} 127.0.0.1 localhost\"#" "$awconf"
    perl -pi -e "s#^LogFormat=.*#LogFormat=1#" "$awconf"  # Nginx combined
    perl -pi -e "s#^DirData=.*#DirData=\"/var/lib/awstats\"#" "$awconf"
  fi

  # Generate static reports daily and protect with basic auth
  mkdir -p "$aw_dir"
  local aw_user="awstats"
  local aw_pass
  aw_pass=$(random_password)
  htpasswd -b -c "$aw_dir/.htpasswd" "$aw_user" "$aw_pass" >/dev/null 2>&1 || true

  nginx -t && systemctl reload nginx

  # Cron for AWStats updates and static pages
  cat >"/etc/cron.d/awstats-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 * * * * root /usr/lib/cgi-bin/awstats.pl -update -config=${domain} >/dev/null 2>&1
15 2 * * * root perl /usr/share/awstats/tools/awstats_buildstaticpages.pl -update -config=${domain} -dir=${aw_dir} -awstatsprog=/usr/lib/cgi-bin/awstats.pl >/dev/null 2>&1
CRON

  # Real cron for WP events via WP-CLI (avoids web traffic triggered cron)
  cat >"/etc/cron.d/wp-cron-${user}-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * ${user} /usr/local/bin/wp --path=${web_dir} --allow-root cron event run --due-now >/dev/null 2>&1
CRON

  # Backups: daily DB + files, retention 7 days
  log "Setting up daily backups with rotation..."
  local bscript="/usr/local/bin/wp-backup-${domain}.sh"
  cat >"$bscript" <<BASH
#!/usr/bin/env bash
set -Eeuo pipefail
keepdays=7
backupdate=\$(date +%Y%m%d-%H%M)
web_dir="${web_dir}"
backup_dir="${backup_dir}"
db_name="${db_name}"
db_user="${db_user}"
db_pass="${db_pass}"
mkdir -p "\${backup_dir}"
cd "\${backup_dir}"
mysqldump -u "\${db_user}" -p"\${db_pass}" "\${db_name}" | gzip -9 > "\${backupdate}-${domain}-db.sql.gz"
tar -czf "\${backupdate}-${domain}-files.tar.gz" -C "\${web_dir}" .
tar -czf "\${backupdate}-${domain}-nginx-logs.tar.gz" -C "/var/log/nginx/${domain}" . || true
chmod 600 "\${backupdate}-${domain}-"*.gz
find "\${backup_dir}" -type f -mtime +"\${keepdays}" -delete
BASH
  chmod +x "$bscript"
  cat >"/etc/cron.d/backup-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * * root ${bscript} >/dev/null 2>&1
CRON

  # Fail2ban basic protection (sshd enabled by default);
  # Add a jail to act on repeated 403/404 (rate-limited/bad bot behavior)
  mkdir -p /etc/fail2ban/filter.d
  cat >/etc/fail2ban/filter.d/nginx-4xx.conf <<'F2B'
[Definition]
failregex = ^<HOST> -.* "(GET|POST).*" (403|404) .*
ignoreregex =
F2B
  if ! grep -q "\[nginx-4xx\]" /etc/fail2ban/jail.local 2>/dev/null; then
    cat >>/etc/fail2ban/jail.local <<'F2B'
[nginx-4xx]
enabled = true
filter = nginx-4xx
port = http,https
logpath = /var/log/nginx/*/access.log
maxretry = 50
findtime = 600
bantime = 1800
F2B
    systemctl restart fail2ban
  fi

  # Credentials summary
  local summary="/root/wp-stack-credentials-${domain}.txt"
  cat >"$summary" <<CREDS
WordPress LEMP Provisioner v${VERSION} - Credentials for ${domain}
=================================================================
Linux user:     ${user}
Linux password: ${sys_pass}

DB name:        ${db_name}
DB user:        ${db_user}
DB password:    ${db_pass}

WP admin URL:   ${site_url}/wp-login.php
WP admin user:  ${admin_user}
WP admin pass:  ${admin_pass}
WP path:        ${web_dir}

Backups dir:    ${backup_dir}
Backup script:  /usr/local/bin/wp-backup-${domain}.sh (daily 03:30)

AWStats URL:    http://${domain}/awstats/
AWStats user:   ${aw_user}
AWStats pass:   ${aw_pass}
CREDS

  echo ""; echo "=============================================="
  echo "Setup complete for ${domain}. Credentials saved to: ${summary}"
  echo "----------------------------------------------"
  echo "Credentials summary:"
  echo "----------------------------------------------"
  cat "$summary"
  echo "=============================================="; echo ""
}

setup_stack_only() {
  apt_install_base
  secure_mysql_if_needed
  configure_php
  configure_ufw
  configure_unattended_upgrades
  install_wp_cli
  nginx_global_hardening
  setup_ssh_access
  log "Base stack installed. You can now add a site."
}

main_menu() {
  clear
  echo ""
  echo "============================================"
  echo "WordPress LEMP Provisioner (Ubuntu 24.04) v${VERSION}"
  echo "============================================"
  echo "1) Install/Update Base LEMP Stack"
  echo "2) Create New WordPress Site"
  echo "3) Exit"
  read -rp "Choose an option [1-3]: " choice
  case "$choice" in
    1)
      ensure_ubuntu_2404
      setup_stack_only
      ;;
    2)
      ensure_ubuntu_2404
      # Ensure stack pieces exist before site creation (do not reinstall stack)
      ensure_site_prereqs
      create_site
      ;;
    *)
      exit 0
      ;;
  esac
}

main_menu
