#!/usr/bin/env bash
set -Eeuo pipefail

# WordPress LAMP Auto-Provisioner for Ubuntu 24.04 (Apache)
# Version: 1.1.0
# Author: Your Team
# License: MIT

# Changelog
# 1.1.0 - Added existing-domain SSL management and WordPress multisite subdomain support
# 1.0.0 - Initial Apache-based release (LAMP, WP-CLI, AWStats static, backups, bot protection, optional SSL)

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

VERSION="1.1.0"
DEBUG_MODE="${DEBUG_MODE:-0}"

log()  { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
err()  { echo -e "[x] $*" >&2; }
debug() { [[ "$DEBUG_MODE" == "1" ]] && echo -e "[debug] $*"; }
trap 'err "Error on line $LINENO: $BASH_COMMAND"' ERR

random_password() {
  perl -e 'my @c=("a".."z","A".."Z",0..9,qw(! @ # % ^ * _ + - =)); print join("", map { $c[int rand @c] } 1..24)'
}

# Normalize and validate a Linux username: lowercase, [a-z0-9_], start with a letter, max 31 chars
normalize_linux_username() {
  local in="$1" out
  out=$(echo -n "$in" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_')
  out=$(echo -n "$out" | sed -E 's/^[^a-z]+//')
  out=${out:0:31}
  echo -n "$out"
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
  log "Updating system and installing base LAMP packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  # Preseed Postfix to operate in 'Local only' mode (provides /usr/sbin/sendmail)
  echo "postfix postfix/main_mailer_type string 'Local only'" | debconf-set-selections || true
  apt-get install -y \
    software-properties-common apt-transport-https ca-certificates \
    curl wget unzip zip git htop mc nano jq pwgen whois \
    ufw fail2ban unattended-upgrades openssh-server \
    apache2 mysql-server \
    php8.3 libapache2-mod-php8.3 php8.3-cli php8.3-opcache php8.3-mysql php8.3-curl \
    php8.3-xml php8.3-zip php8.3-mbstring php8.3-gd php8.3-intl php8.3-soap \
    php-imagick redis-server php8.3-redis \
    awstats perl apache2-utils \
    certbot python3-certbot-apache

  a2enmod rewrite headers expires http2 ssl proxy proxy_http proxy_fcgi setenvif >/dev/null 2>&1 || true
  systemctl enable --now apache2
  systemctl enable --now mysql
  systemctl enable --now redis-server
  # Ensure postfix (MTA) is enabled to provide sendmail compatibility
  systemctl enable --now postfix >/dev/null 2>&1 || true
}

secure_mysql_if_needed() {
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
  log "Configuring PHP 8.3 (apache2 SAPI)..."
  local ini=/etc/php/8.3/apache2/php.ini
  sed -ri 's/^;?memory_limit\s*=.*/memory_limit = 256M/' "$ini"
  sed -ri 's/^;?upload_max_filesize\s*=.*/upload_max_filesize = 128M/' "$ini"
  sed -ri 's/^;?post_max_size\s*=.*/post_max_size = 128M/' "$ini"
  sed -ri 's/^;?max_execution_time\s*=.*/max_execution_time = 300/' "$ini"
  sed -ri 's/^;?opcache.enable\s*=.*/opcache.enable=1/' "$ini"
  sed -ri 's/^;?opcache.memory_consumption\s*=.*/opcache.memory_consumption=256/' "$ini"
  sed -ri 's/^;?opcache.max_accelerated_files\s*=.*/opcache.max_accelerated_files=20000/' "$ini"
  systemctl restart apache2
}

configure_ufw() {
  log "Configuring UFW firewall..."
  ufw --force reset || true
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 'Apache Full'
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

install_certbot() {
  if ! command -v certbot >/dev/null 2>&1; then
    log "Installing Certbot (Let's Encrypt) for Apache..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y certbot python3-certbot-apache
  fi
}

has_dns_record() {
  local name="$1"
  getent ahosts "$name" >/dev/null 2>&1
}

systemd_unit_exists() {
  local unit="$1"
  local state
  state=$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)
  debug "systemd unit check: unit=${unit} LoadState=${state:-<empty>}"
  [[ -n "$state" && "$state" != "not-found" ]]
}

find_db_service_unit() {
  local svc
  for svc in mysql mariadb mysqld; do
    if systemd_unit_exists "${svc}.service"; then
      debug "database service detected: ${svc}.service"
      echo -n "$svc"
      return 0
    fi
  done
  debug "database service detection failed for mysql/mariadb/mysqld"
  return 1
}

normalize_hostname() {
  echo -n "$1" | tr 'A-Z' 'a-z' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.$//'
}

is_valid_hostname() {
  local host="$1"
  [[ "$host" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
}

is_valid_subdomain_label() {
  local label="$1"
  [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

hostname_from_url() {
  local url="$1"
  url="${url#*://}"
  url="${url%%/*}"
  url="${url%%:*}"
  echo -n "$url"
}

get_parent_candidate() {
  local hostname="$1"
  echo -n "${hostname#*.}"
}

apache_get_first_directive() {
  local conf="$1"
  local directive="$2"
  awk -v d="$directive" 'tolower($1) == tolower(d) { print $2; exit }' "$conf"
}

apache_conf_has_wildcard_alias() {
  local conf="$1"
  local domain="$2"
  awk -v alias="*.${domain}" 'tolower($1)=="serveralias"{for(i=2;i<=NF;i++) if($i==alias) found=1} END{exit(found?0:1)}' "$conf"
}

ensure_server_alias() {
  local conf="$1"
  local alias="$2"
  if awk -v alias="$alias" 'tolower($1)=="serveralias"{for(i=2;i<=NF;i++) if($i==alias) found=1} END{exit(found?0:1)}' "$conf"; then
    return 0
  fi
  if grep -Eq '^[[:space:]]*ServerAlias[[:space:]]' "$conf"; then
    sed -i -E "0,/^[[:space:]]*ServerAlias[[:space:]]/ s|\$| ${alias}|" "$conf"
  else
    sed -i -E "/^[[:space:]]*ServerName[[:space:]]/a\\    ServerAlias ${alias}" "$conf"
  fi
}

ensure_multisite_server_alias() {
  local conf="$1"
  local domain="$2"
  if apache_conf_has_wildcard_alias "$conf" "$domain"; then
    return 0
  fi
  ensure_server_alias "$conf" "*.${domain}"
  apache2ctl configtest
  systemctl reload apache2
}

ensure_awstats_location_block() {
  local conf="$1"
  local aw_dir="$2"
  if grep -q '/awstats' "$conf"; then
    return 0
  fi

  local tmpconf
  tmpconf=$(mktemp)
  grep -v '</VirtualHost>' "$conf" > "$tmpconf"
  cat >>"$tmpconf" <<APV

    <Location "/awstats">
        AuthType Basic
        AuthName "Restricted"
        AuthUserFile ${aw_dir}/.htpasswd
        Require valid-user
    </Location>
    Alias /awstats ${aw_dir}/
    <Directory ${aw_dir}>
        Require all granted
        Options Indexes FollowSymLinks
        AllowOverride None
    </Directory>
</VirtualHost>
APV
  mv "$tmpconf" "$conf"
  apache2ctl configtest
  systemctl reload apache2
}

get_site_owner_from_path() {
  local path="$1"
  stat -c '%U' "$path"
}

wp_run() {
  local owner="$1"
  shift
  sudo -u "$owner" -H wp "$@"
}

wp_capture() {
  local owner="$1"
  shift
  sudo -u "$owner" -H wp "$@" 2>/dev/null
}

wordpress_is_installed() {
  local web_dir="$1"
  local owner="$2"
  wp_run "$owner" --path="$web_dir" core is-installed >/dev/null 2>&1
}

wordpress_is_multisite() {
  local web_dir="$1"
  local owner="$2"
  wp_run "$owner" --path="$web_dir" core is-installed --network >/dev/null 2>&1
}

get_wordpress_admin_email() {
  local web_dir="$1"
  local owner="$2"
  local url="$3"
  wp_capture "$owner" --path="$web_dir" --url="$url" option get admin_email | head -n1
}

get_wordpress_home_url() {
  local web_dir="$1"
  local owner="$2"
  local url="$3"
  local value
  value=$(wp_capture "$owner" --path="$web_dir" --url="$url" option get home | head -n1 || true)
  if [[ -z "$value" ]]; then
    if [[ "$url" == http://* || "$url" == https://* ]]; then
      echo -n "$url"
    else
      echo -n "http://${url}"
    fi
  else
    echo -n "$value"
  fi
}

get_wordpress_blogname() {
  local web_dir="$1"
  local owner="$2"
  local url="$3"
  local value
  value=$(wp_capture "$owner" --path="$web_dir" --url="$url" option get blogname | head -n1 || true)
  if [[ -z "$value" ]]; then
    echo -n "$url"
  else
    echo -n "$value"
  fi
}

prompt_yes_no() {
  local prompt="$1"
  local answer
  read -rp "${prompt} [y/N]: " answer
  [[ "${answer,,}" == "y" ]]
}

declare -ga INVENTORY_HOSTS=()
declare -ga INVENTORY_CONFS=()
declare -ga INVENTORY_DOCROOTS=()
declare -ga INVENTORY_KINDS=()
declare -gA INVENTORY_SEEN=()

add_inventory_entry() {
  local host="$1"
  local conf="$2"
  local docroot="$3"
  local kind="$4"
  [[ -z "$host" || -z "$conf" || -z "$docroot" ]] && return 0
  [[ -n "${INVENTORY_SEEN[$host]:-}" ]] && return 0
  INVENTORY_HOSTS+=("$host")
  INVENTORY_CONFS+=("$conf")
  INVENTORY_DOCROOTS+=("$docroot")
  INVENTORY_KINDS+=("$kind")
  INVENTORY_SEEN["$host"]=1
}

build_existing_sites_inventory() {
  INVENTORY_HOSTS=()
  INVENTORY_CONFS=()
  INVENTORY_DOCROOTS=()
  INVENTORY_KINDS=()
  INVENTORY_SEEN=()

  local conf host docroot owner
  shopt -s nullglob
  for conf in /etc/apache2/sites-available/*.conf; do
    [[ "$conf" == *-le-ssl.conf ]] && continue
    grep -q '<VirtualHost \*:80>' "$conf" || continue
    host=$(normalize_hostname "$(apache_get_first_directive "$conf" "ServerName")")
    docroot=$(apache_get_first_directive "$conf" "DocumentRoot")
    [[ -z "$host" || -z "$docroot" || "$host" == "localhost" ]] && continue

    add_inventory_entry "$host" "$conf" "$docroot" "primary"

    if [[ -f "${docroot}/wp-config.php" ]]; then
      owner=$(get_site_owner_from_path "$docroot")
      if wordpress_is_multisite "$docroot" "$owner"; then
        while IFS= read -r site_url; do
          local ms_host
          ms_host=$(normalize_hostname "$(hostname_from_url "$site_url")")
          [[ -n "$ms_host" ]] && add_inventory_entry "$ms_host" "$conf" "$docroot" "multisite"
        done < <(wp_capture "$owner" --path="$docroot" site list --field=url || true)
      fi
    fi
  done
  shopt -u nullglob
}

select_inventory_entry() {
  local mode="${1:-all}"
  build_existing_sites_inventory

  local -a filtered=()
  local idx
  for idx in "${!INVENTORY_HOSTS[@]}"; do
    if [[ "$mode" == "primary" && "${INVENTORY_KINDS[$idx]}" != "primary" ]]; then
      continue
    fi
    filtered+=("$idx")
  done

  if [[ ${#filtered[@]} -eq 0 ]]; then
    err "No matching Apache sites were detected."
    return 1
  fi

  echo ""
  echo "Detected sites:"
  local n=1 host kind conf
  for idx in "${filtered[@]}"; do
    host="${INVENTORY_HOSTS[$idx]}"
    kind="${INVENTORY_KINDS[$idx]}"
    conf="${INVENTORY_CONFS[$idx]}"
    printf " %d) %s [%s] (%s)\n" "$n" "$host" "$kind" "$conf"
    ((n++))
  done

  local choice selected_idx
  read -rp "Choose a site [1-${#filtered[@]}]: " choice
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#filtered[@]} )); then
    err "Invalid selection."
    return 1
  fi

  selected_idx="${filtered[$((choice-1))]}"
  SELECTED_HOST="${INVENTORY_HOSTS[$selected_idx]}"
  SELECTED_CONF="${INVENTORY_CONFS[$selected_idx]}"
  SELECTED_DOCROOT="${INVENTORY_DOCROOTS[$selected_idx]}"
  SELECTED_KIND="${INVENTORY_KINDS[$selected_idx]}"
  return 0
}

get_certbot_domains_for_host() {
  local host="$1"
  CERTBOT_NAMES=("$host")
  local alias="www.${host}"
  if has_dns_record "$alias"; then
    CERTBOT_NAMES+=("$alias")
  else
    warn "No DNS record detected for ${alias}; skipping it."
  fi
}

create_ssl_vhost() {
  local hostname="$1"
  local web_dir="$2"
  local log_dir="$3"
  shift 3
  local aliases=("$@")
  local conf="/etc/apache2/sites-available/${hostname}-le-ssl.conf"

  mkdir -p "$log_dir"

  local alias_lines=""
  local alias
  for alias in "${aliases[@]}"; do
    alias_lines+="    ServerAlias ${alias}"$'\n'
  done

  cat >"$conf" <<APV
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName ${hostname}
${alias_lines}    DocumentRoot ${web_dir}
    ErrorLog ${log_dir}/error.log
    CustomLog ${log_dir}/access.log combined

    <Directory ${web_dir}>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
        LimitRequestBody 0
    </Directory>

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set X-XSS-Protection "1; mode=block"

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${hostname}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${hostname}/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/${hostname}/chain.pem

    <FilesMatch "\.(css|js)$">
      Header set Cache-Control "public, max-age=31536000"
    </FilesMatch>
    <FilesMatch "\.(jpg|jpeg|png|gif|webp|avif|ico|svg|svgz|ttf|otf|woff|woff2|eot)$">
      Header set Cache-Control "public, max-age=31536000"
    </FilesMatch>
    <FilesMatch "\.(html)$">
      Header set Cache-Control "no-cache"
    </FilesMatch>

    <Files "xmlrpc.php">
        Require all denied
    </Files>

    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/ [NC]
    RewriteCond %{HTTP_USER_AGENT} (ahrefs|semrush|mj12bot|dotbot|curl|wget|python-requests|axios|scrapy|libwww-perl) [NC]
    RewriteRule ^ - [F]
</VirtualHost>
</IfModule>
APV

  a2ensite "${hostname}-le-ssl.conf" >/dev/null 2>&1 || true
  apache2ctl configtest && systemctl reload apache2
}

issue_ssl_certificate() {
  local hostname="$1"
  local web_dir="$2"
  local email="$3"
  install_certbot

  get_certbot_domains_for_host "$hostname"
  local cert_domains=("-w" "$web_dir")
  local cert_name
  for cert_name in "${CERTBOT_NAMES[@]}"; do
    cert_domains+=("-d" "$cert_name")
  done

  LAST_SSL_NAMES_STR=$(IFS=', '; echo "${CERTBOT_NAMES[*]}")
  LAST_SSL_STATUS="failed"

  ufw allow 'Apache Full' >/dev/null 2>&1 || true
  apache2ctl configtest && systemctl reload apache2 || true

  if certbot certonly --webroot "${cert_domains[@]}" --agree-tos -m "${email}" --deploy-hook "systemctl reload apache2" -n; then
    LAST_SSL_STATUS="issued"
    log "Let's Encrypt certificate issued successfully for ${hostname}: ${LAST_SSL_NAMES_STR}"
    create_ssl_vhost "$hostname" "$web_dir" "/var/log/apache2/${hostname}" "${CERTBOT_NAMES[@]:1}"
  else
    warn "Certbot webroot issuance failed. Please verify DNS and rerun: certbot certonly --webroot -w ${web_dir} -d ${hostname} [-d www.${hostname}]"
  fi
}

convert_to_multisite_if_needed() {
  local hostname="$1"
  local conf="$2"
  local web_dir="$3"
  local owner="$4"
  local home_url="$5"

  MULTISITE_CONVERTED="no"
  if wordpress_is_multisite "$web_dir" "$owner"; then
    return 0
  fi

  warn "The site ${hostname} is currently a single-site WordPress install."
  if ! prompt_yes_no "Convert ${hostname} to WordPress Multisite now? This updates wp-config.php and .htaccess."; then
    err "Multisite conversion was declined."
    return 1
  fi

  local network_title
  network_title=$(get_wordpress_blogname "$web_dir" "$owner" "$home_url")
  cp -f "${web_dir}/wp-config.php" "${web_dir}/wp-config.php.bak.$(date +%Y%m%d%H%M%S)"
  [[ -f "${web_dir}/.htaccess" ]] && cp -f "${web_dir}/.htaccess" "${web_dir}/.htaccess.bak.$(date +%Y%m%d%H%M%S)"

  wp_run "$owner" --path="$web_dir" --url="$home_url" core multisite-convert --title="$network_title" --base=/ --subdomains

  cat >"${web_dir}/.htaccess" <<'HT'
# BEGIN WordPress Multisite
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]

# add a trailing slash to /wp-admin
RewriteRule ^wp-admin$ wp-admin/ [R=301,L]
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]
RewriteRule ^(wp-(content|admin|includes).*) $1 [L]
RewriteRule ^(.*\.php)$ $1 [L]
RewriteRule . index.php [L]
# END WordPress Multisite
HT
  chown "$owner":www-data "${web_dir}/.htaccess"
  chmod 644 "${web_dir}/.htaccess"

  ensure_multisite_server_alias "$conf" "$hostname"
  MULTISITE_CONVERTED="yes"
  log "Converted ${hostname} to WordPress Multisite with subdomain routing."
}

manage_existing_ssl() {
  local cert_email
  if ! select_inventory_entry "all"; then
    return 1
  fi

  if [[ ! -d "$SELECTED_DOCROOT" ]]; then
    err "DocumentRoot not found for ${SELECTED_HOST}: ${SELECTED_DOCROOT}"
    return 1
  fi

  local owner
  owner=$(get_site_owner_from_path "$SELECTED_DOCROOT")
  local default_email=""
  if [[ -f "${SELECTED_DOCROOT}/wp-config.php" ]] && wordpress_is_installed "$SELECTED_DOCROOT" "$owner"; then
    default_email=$(get_wordpress_admin_email "$SELECTED_DOCROOT" "$owner" "http://${SELECTED_HOST}")
  fi

  read -rp "Admin email for Let's Encrypt [${default_email:-required}]: " cert_email
  cert_email="${cert_email:-$default_email}"
  if [[ -z "$cert_email" ]]; then
    err "Admin email is required for certificate issuance."
    return 1
  fi

  issue_ssl_certificate "$SELECTED_HOST" "$SELECTED_DOCROOT" "$cert_email"
}

create_multisite_subdomain_site() {
  if ! select_inventory_entry "primary"; then
    return 1
  fi

  local parent_domain="$SELECTED_HOST"
  local conf="$SELECTED_CONF"
  local web_dir="$SELECTED_DOCROOT"

  if [[ ! -f "${web_dir}/wp-config.php" ]]; then
    err "${parent_domain} does not appear to contain a WordPress installation."
    return 1
  fi

  local owner
  owner=$(get_site_owner_from_path "$web_dir")
  if ! wordpress_is_installed "$web_dir" "$owner"; then
    err "WP-CLI could not confirm a WordPress install in ${web_dir}."
    return 1
  fi

  local home_url
  home_url=$(get_wordpress_home_url "$web_dir" "$owner" "http://${parent_domain}")
  convert_to_multisite_if_needed "$parent_domain" "$conf" "$web_dir" "$owner" "$home_url"

  local sub_label site_title site_email
  read -rp "Enter new subdomain label (example: blog for blog.${parent_domain}): " sub_label
  sub_label=$(normalize_hostname "$sub_label")
  if ! is_valid_subdomain_label "$sub_label"; then
    err "Invalid subdomain label. Use lowercase letters, digits and hyphens only."
    return 1
  fi

  local hostname="${sub_label}.${parent_domain}"
  local default_email
  default_email=$(get_wordpress_admin_email "$web_dir" "$owner" "$home_url")
  read -rp "Site title for ${hostname}: " site_title
  read -rp "Admin email for ${hostname} [${default_email}]: " site_email
  site_email="${site_email:-$default_email}"

  if [[ -z "$site_title" || -z "$site_email" ]]; then
    err "Site title and admin email are required."
    return 1
  fi

  if ! has_dns_record "$hostname"; then
    warn "DNS for ${hostname} was not detected. SSL issuance may fail until DNS points to this server."
  fi

  wp_run "$owner" --path="$web_dir" --url="$home_url" site create --slug="$sub_label" --title="$site_title" --email="$site_email"
  issue_ssl_certificate "$hostname" "$web_dir" "$site_email"

  local summary="/root/wp-stack-subdomain-${hostname}.txt"
  cat >"$summary" <<CREDS
WordPress LAMP Provisioner (Apache) v${VERSION} - Multisite subdomain ${hostname}
==========================================================================
Parent domain:           ${parent_domain}
WordPress path:          ${web_dir}
Linux owner:             ${owner}
Multisite conversion:    ${MULTISITE_CONVERTED}
New site URL:            https://${hostname}/
SSL status:              ${LAST_SSL_STATUS}
SSL SAN names:           ${LAST_SSL_NAMES_STR}
CREDS

  echo ""
  echo "=============================================="
  echo "Subdomain site created for ${hostname}. Summary saved to: ${summary}"
  echo "----------------------------------------------"
  cat "$summary"
  echo "=============================================="
}

manage_existing_domains_menu() {
  while true; do
    echo ""
    echo "Manage Existing Domains"
    echo "1) Issue SSL for existing domain/subdomain"
    echo "2) Create WordPress subdomain site"
    echo "3) Back"
    read -rp "Choose an option [1-3]: " manage_choice
    case "$manage_choice" in
      1) manage_existing_ssl ;;
      2) create_multisite_subdomain_site ;;
      3) return 0 ;;
      *) warn "Invalid option. Please choose 1, 2 or 3." ;;
    esac
  done
}

apache_global_hardening() {
  log "Configuring Apache global security headers..."
  cat >/etc/apache2/conf-available/security-headers.conf <<'APC'
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set X-XSS-Protection "1; mode=block"
</IfModule>
APC
  cat >/etc/apache2/conf-available/servername.conf <<'APC'
ServerName localhost
APC
  a2enconf security-headers >/dev/null 2>&1 || true
  a2enconf servername >/dev/null 2>&1 || true
  systemctl reload apache2 || systemctl restart apache2
}

ensure_site_prereqs() {
  log "Checking prerequisites for site creation..."
  debug "DEBUG_MODE=${DEBUG_MODE}"
  debug "apache2ctl path: $(command -v apache2ctl 2>/dev/null || echo '<missing>')"
  debug "wp path: $(command -v wp 2>/dev/null || echo '<missing>')"
  debug "systemctl version: $(systemctl --version 2>/dev/null | head -n1 || echo '<unavailable>')"

  if ! command -v apache2ctl >/dev/null 2>&1 && ! dpkg -s apache2 >/dev/null 2>&1; then
    err "Apache2 not installed. Please run 'Install/Update Base LAMP Stack' first."
    exit 1
  fi

  if ! systemd_unit_exists apache2.service; then
    err "Apache2 systemd unit not found. Please run 'Install/Update Base LAMP Stack' first."
    exit 1
  fi

  debug "apache2 is-enabled: $(systemctl is-enabled apache2 2>/dev/null || echo '<unknown>')"
  debug "apache2 is-active: $(systemctl is-active apache2 2>/dev/null || echo '<unknown>')"
  systemctl is-active --quiet apache2 || systemctl start apache2 || true
  # MySQL/MariaDB
  local db_service=""
  db_service=$(find_db_service_unit || true)
  if [[ -z "$db_service" ]]; then
    if command -v mysql >/dev/null 2>&1; then for svc in mysql mariadb mysqld; do systemctl start "$svc" 2>/dev/null && db_service="$svc" && break; done; fi
  fi
  debug "selected database service: ${db_service:-<none>}"
  if [[ -z "$db_service" ]]; then err "MySQL/MariaDB service not found. Install base stack first."; exit 1; fi
  debug "${db_service} is-active: $(systemctl is-active "$db_service" 2>/dev/null || echo '<unknown>')"
  systemctl is-active --quiet "$db_service" || systemctl start "$db_service" || true
  install_wp_cli
  apache_global_hardening
}

create_site() {
  local domain user email title plugins theme
  echo "Enter primary domain (example.com):"; read -r domain
  echo "Enter Linux username to own the site (letters, digits, underscore):"; read -r user
  echo "Admin email (WordPress):"; read -r email
  echo "Site title:"; read -r title
  echo "Comma-separated plugin slugs to install (defaults included automatically: redis-cache,wordpress-seo,contact-form-7,flamingo,redirection,safe-svg,classic-editor):"; read -r plugins
  echo "Theme slug to install and activate (default generatepress; leave blank to use it):"; read -r theme

  if [[ -z "$domain" || -z "$user" || -z "$email" || -z "$title" ]]; then
    err "Domain, user, email, and site title are required."
    exit 1
  fi

  local user_raw="$user"
  user=$(normalize_linux_username "$user_raw")
  if [[ -z "$user" || "$user" == "root" ]]; then
    err "Invalid username. Use letters, digits or underscore, starting with a letter (not 'root')."
    exit 1
  fi
  if [[ "$user" != "$user_raw" ]]; then warn "Username normalized to '$user' from '$user_raw'."; fi

  local db_name db_user db_pass sys_pass admin_user admin_pass root_dir web_dir log_dir backup_dir
  db_name="${user//[^a-zA-Z0-9_]/_}_wp"
  db_user="${user//[^a-zA-Z0-9_]/_}_u"
  db_pass=$(random_password)
  sys_pass=$(random_password)
  admin_user="admin"
  admin_pass=$(random_password)

  root_dir="/var/www/${user}/${domain}"
  web_dir="${root_dir}/www"
  log_dir="/var/log/apache2/${domain}"
  backup_dir="${root_dir}/backups"

  log "Creating system user and directories..."
  mkdir -p "$web_dir" "$log_dir"
  # Prepare ACME challenge path to avoid rewrite/404 issues
  mkdir -p "$web_dir/.well-known/acme-challenge"
  id -u "$user" >/dev/null 2>&1 || adduser --quiet --disabled-password --gecos "" --home "$web_dir" "$user"
  echo "$user:$sys_pass" | chpasswd
  mkdir -p "$backup_dir"
  chown -R "$user":www-data "/var/www/${user}"
  chmod -R 775 "/var/www/${user}"

  log "Configuring Apache vhost for ${domain}..."
  cat >"/etc/apache2/sites-available/${domain}.conf" <<APV
<VirtualHost *:80>
    ServerName ${domain}
    ServerAlias www.${domain}
    DocumentRoot ${web_dir}

    ErrorLog ${log_dir}/error.log
    CustomLog ${log_dir}/access.log combined

    <Directory ${web_dir}>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
        # Unlimited body size at Apache level (PHP still enforces 128M)
        LimitRequestBody 0
    </Directory>

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set X-XSS-Protection "1; mode=block"

    # ACME challenge alias (Let's Encrypt)
    Alias /.well-known/acme-challenge/ ${web_dir}/.well-known/acme-challenge/
    <Directory ${web_dir}/.well-known/acme-challenge/>
      # Allow FollowSymLinks so webroot ACME challenges and rewrite rules work
      Options -Indexes +FollowSymLinks
      AllowOverride None
      ForceType text/plain
      Require all granted
    </Directory>

    # Static asset caching
    <IfModule mod_expires.c>
      ExpiresActive On
      ExpiresDefault "access plus 1 month"
      ExpiresByType text/css "access plus 1 year"
      ExpiresByType application/javascript "access plus 1 year"
      ExpiresByType application/x-javascript "access plus 1 year"
      ExpiresByType application/json "access plus 1 hour"
      ExpiresByType image/svg+xml "access plus 1 year"
      ExpiresByType image/x-icon "access plus 1 year"
      ExpiresByType image/jpeg "access plus 1 year"
      ExpiresByType image/jpg  "access plus 1 year"
      ExpiresByType image/png  "access plus 1 year"
      ExpiresByType image/gif  "access plus 1 year"
      ExpiresByType image/webp "access plus 1 year"
      ExpiresByType font/ttf   "access plus 1 year"
      ExpiresByType font/otf   "access plus 1 year"
      ExpiresByType font/woff  "access plus 1 year"
      ExpiresByType font/woff2 "access plus 1 year"
    </IfModule>

    <IfModule mod_headers.c>
      <FilesMatch "\.(css|js)$">
        Header set Cache-Control "public, max-age=31536000"
      </FilesMatch>
      <FilesMatch "\.(jpg|jpeg|png|gif|webp|avif|ico|svg|svgz|ttf|otf|woff|woff2|eot)$">
        Header set Cache-Control "public, max-age=31536000"
      </FilesMatch>
      <FilesMatch "\.(html)$">
        Header set Cache-Control "no-cache"
      </FilesMatch>
    </IfModule>

    # Block XML-RPC
    <Files "xmlrpc.php">
        Require all denied
    </Files>

    # Basic bad bot blocking
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/ [NC]
    RewriteCond %{HTTP_USER_AGENT} (ahrefs|semrush|mj12bot|dotbot|curl|wget|python-requests|axios|scrapy|libwww-perl) [NC]
    RewriteRule ^ - [F]
</VirtualHost>
APV
  a2ensite "${domain}.conf" >/dev/null 2>&1 || true
  apache2ctl configtest
  systemctl reload apache2

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
  if [[ ! -f "${web_dir}/wp-config.php" ]]; then
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp config create --dbname='${db_name}' --dbuser='${db_user}' --dbpass='${db_pass}' --dbhost='localhost' --dbprefix='wp_' --skip-check"
  fi
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set FS_METHOD direct --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_AUTO_UPDATE_CORE true --type=constant --raw"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set DISALLOW_FILE_EDIT true --type=constant --raw"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_MEMORY_LIMIT 256M --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_MAX_MEMORY_LIMIT 256M --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config set WP_REDIS_HOST 127.0.0.1 --type=constant"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp config shuffle-salts"

  local site_url="http://${domain}"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp core install --url='${site_url}' --title='${title}' --admin_user='${admin_user}' --admin_password='${admin_pass}' --admin_email='${email}'"

  # Plugins: install defaults "out of the box" and also any user-specified
  DEFAULT_PLUGINS=(redis-cache wordpress-seo contact-form-7 flamingo redirection safe-svg classic-editor)
  for p in "${DEFAULT_PLUGINS[@]}"; do
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin install '$p' --activate || true"
  done
  if [[ -n "${plugins//,/}" ]]; then
    IFS=',' read -ra P_ARR <<<"$plugins"
    for p in "${P_ARR[@]}"; do
      p_trim=$(echo "$p" | xargs)
      [[ -z "$p_trim" ]] && continue
      sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin install '$p_trim' --activate || true"
    done
  fi

  # Theme: always ensure generatepress installed; activate it if no custom theme provided
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp theme install generatepress || true"
  if [[ -n "${theme:-}" ]]; then
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp theme install '${theme}' --activate || true"
  else
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp theme activate generatepress || true"
  fi

  # Redis cache if plugin requested or installed separately
  if sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin is-installed redis-cache" >/dev/null 2>&1; then
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp plugin activate redis-cache || true"
    sudo -u "$user" -H bash -c "cd '$web_dir' && wp redis enable || true"
  fi

  # WordPress options
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp option update uploads_use_yearmonth_folders 0"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp rewrite structure '/%category%/%postname%'"
  sudo -u "$user" -H bash -c "cd '$web_dir' && wp rewrite flush --hard"

  # Ensure .htaccess exists with WordPress rewrite rules so pretty permalinks work
  if [[ ! -f "$web_dir/.htaccess" ]]; then
    cat >"$web_dir/.htaccess" <<'HT'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
HT
    chown "$user":www-data "$web_dir/.htaccess"
    chmod 644 "$web_dir/.htaccess"
  fi

  # Permissions
  mkdir -p "$web_dir/wp-content/uploads"
  chown -R "$user":www-data "$web_dir"
  find "$web_dir" -type d -exec chmod 755 {} +
  find "$web_dir" -type f -exec chmod 644 {} +
  if [[ -d "$web_dir/wp-content" ]]; then
    find "$web_dir/wp-content" -type d -exec chmod 775 {} +
    find "$web_dir/wp-content" -type f -exec chmod 664 {} +
    chmod g+s "$web_dir/wp-content" "$web_dir/wp-content/uploads" 2>/dev/null || true
  fi

  # robots.txt
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

  # AWStats per-site config and static pages
  log "Configuring AWStats for ${domain}..."
  local awconf="/etc/awstats/awstats.${domain}.conf"
  if [[ ! -f "$awconf" ]]; then
    cp /etc/awstats/awstats.conf "$awconf"
    perl -pi -e "s#^LogFile=.*#LogFile=\"/var/log/apache2/${domain}/access.log\"#" "$awconf"
    perl -pi -e "s#^SiteDomain=.*#SiteDomain=\"${domain}\"#" "$awconf"
    perl -pi -e "s#^HostAliases=.*#HostAliases=\"www.${domain} 127.0.0.1 localhost\"#" "$awconf"
    perl -pi -e "s#^LogFormat=.*#LogFormat=1#" "$awconf"
    perl -pi -e "s#^DirData=.*#DirData=\"/var/lib/awstats\"#" "$awconf"
  fi

  local aw_dir="${web_dir}/awstats"
  mkdir -p "$aw_dir"
  local aw_user="awstats"
  local aw_pass
  aw_pass=$(random_password)
  htpasswd -b -c "$aw_dir/.htpasswd" "$aw_user" "$aw_pass" >/dev/null 2>&1 || true

  # Serve static reports via /awstats with Basic Auth
  ensure_awstats_location_block "/etc/apache2/sites-available/${domain}.conf" "$aw_dir"

  # Cron for AWStats updates and static HTML
  cat >"/etc/cron.d/awstats-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 * * * * root /usr/lib/cgi-bin/awstats.pl -update -config=${domain} >/dev/null 2>&1
15 2 * * * root perl /usr/share/awstats/tools/awstats_buildstaticpages.pl -update -config=${domain} -dir=${aw_dir} -awstatsprog=/usr/lib/cgi-bin/awstats.pl >/dev/null 2>&1
CRON

  # Real cron for WP events
  cat >"/etc/cron.d/wp-cron-${user}-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * ${user} /usr/local/bin/wp --path=${web_dir} --allow-root cron event run --due-now >/dev/null 2>&1
CRON

  # Backups: daily DB + files, rotation 7 days
  log "Setting up daily backups with rotation..."
  local bscript="/usr/local/bin/wp-backup-${domain}.sh"
  cat >"$bscript" <<BASH
#!/usr/bin/env bash
set -Eeuo pipefail
keepdays=28
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
tar -czf "\${backupdate}-${domain}-apache-logs.tar.gz" -C "/var/log/apache2/${domain}" . || true
chmod 600 "\${backupdate}-${domain}-"*.gz
find "\${backup_dir}" -type f -mtime +"\${keepdays}" -delete
BASH
  chmod +x "$bscript"
  cat >"/etc/cron.d/backup-${domain}" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Weekly backups: Sunday 03:30
30 3 * * 0 root ${bscript} >/dev/null 2>&1
CRON

  # Fail2ban jail for repeated 403/404 in Apache logs
  mkdir -p /etc/fail2ban/filter.d
  cat >/etc/fail2ban/filter.d/apache-4xx.conf <<'F2B'
[Definition]
failregex = ^<HOST> -.* "(GET|POST).*" (403|404) .*
ignoreregex =
F2B
  if ! grep -q "\[apache-4xx\]" /etc/fail2ban/jail.local 2>/dev/null; then
    cat >>/etc/fail2ban/jail.local <<'F2B'
[apache-4xx]
enabled = true
filter = apache-4xx
port = http,https
logpath = /var/log/apache2/*/access.log
maxretry = 50
findtime = 600
bantime = 1800
F2B
    systemctl restart fail2ban
  fi

  # Credentials summary
  local summary="/root/wp-stack-credentials-${domain}.txt"
  cat >"$summary" <<CREDS
WordPress LAMP Provisioner (Apache) v${VERSION} - Credentials for ${domain}
==========================================================================
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
Backup script:  /usr/local/bin/wp-backup-${domain}.sh (weekly Sun 03:30, retain 4 weeks)

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

  # Offer to set up HTTPS with Let's Encrypt
  echo ""
  read -rp "Issue and configure Let's Encrypt SSL now for ${domain}? [y/N]: " do_ssl
  if [[ "${do_ssl,,}" == "y" ]]; then
    issue_ssl_certificate "$domain" "$web_dir" "$email"
  fi
}

setup_stack_only() {
  apt_install_base
  secure_mysql_if_needed
  configure_php
  configure_ufw
  configure_unattended_upgrades
  install_wp_cli
  apache_global_hardening
  setup_ssh_access
  log "Base stack installed. You can now add a site."
}

main_menu() {
  while true; do
    clear
    echo ""
    echo "============================================"
    echo "WordPress LAMP Provisioner (Ubuntu 24.04, Apache) v${VERSION}"
    echo "============================================"
    echo "1) Install/Update Base LAMP Stack (Apache)"
    echo "2) Create New WordPress Site (Apache)"
    echo "3) Manage existing domains"
    echo "4) Exit"
    read -rp "Choose an option [1-4]: " choice
    case "$choice" in
      1)
        ensure_ubuntu_2404
        setup_stack_only
        ;;
      2)
        ensure_ubuntu_2404
        ensure_site_prereqs
        create_site
        ;;
      3)
        ensure_ubuntu_2404
        ensure_site_prereqs
        manage_existing_domains_menu
        ;;
      4)
        exit 0
        ;;
      *)
        warn "Invalid option. Please choose 1, 2, 3 or 4."
        ;;
    esac
    echo ""
    read -rp "Press Enter to continue..." _
  done
}

main_menu
