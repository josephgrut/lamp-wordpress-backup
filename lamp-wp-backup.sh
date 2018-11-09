#!/bin/bash -e
clear
echo " ";
echo "============================================"
echo "Install software: "
echo "============================================"
echo "What to do:
1. Install LAMP
2. New virtual host + Wordpress"
read -e run
if [ "$run" == "1" ] ; then
clear
echo " ";
echo "============================================"
echo "Install LAMP"
echo "============================================"
apt-get update && apt-get upgrade -y

# Installing SSH Public Key
mkdir ~/.ssh && touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
cat >> ~/.ssh/authorized_keys <<EOL
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAgEAmgga8N0mB/KDC5PPiEbRsaA46X8yey9iizgdGvAG1EEge6yGk91F/Rm7NMKkD4oRNKj23Udoh4LL6FXfJ/oRaEUz6p7gOidz5Ty6K9ghD6WvQaoXAhiWyeS66jfrz1UgmsF/F/J61pWTNlxjCqsOop+FlFwkET2dmKNDlwuibd1ezfu5XHxNWg+5LkabOVuuhSyfBewIaziWvsldFj4bMLl1h62ecV1qS4Xpd/aDfm8MglTlWq8FpPkjJJy7fBISsMIj06PG/ZhEZELEWVdqbAA4bxSw8qIM/7JMP9faUYKr/U7wRSsssenHznWRXYCF2J53LFJZe7GE3eGOa7jKtLFa42X7Oz23/bcagKjdsgC+6ptCybXYzxQ5GD7lbuc+nHKdLjV1tgsivs4mxj57sojl/l7MH+eGRfQPeMNzxBFh1wYvDqlpylNCbLqXXkTFQchOu8lBEeFvTaPopm6uqbYcR30gaIlQ/bwcw3Pn4UHGgnZAQbdEgnLYMEWbE5ayp7STJqaA+8CaDHh+UH0TdS35carUECK7BhzaxUvA6v/Ypy46HIGsnri8wWq6E1C9u2fjWBGCKQT/PRBW22CjNDRUdiiV+vU7/t101uYj5fZTv1cNsAOyXexmNjScM3Cia5UAI/isNLLjHdYlyo1P6b5w/zTZ5jrB7Y3N7dp/f6s= rsa-key-20181022
EOL
cat >> /etc/ssh/ssh_config <<EOL
PasswordAuthentication no
EOL
service ssh restart

apt-get -y install nano zip unzip mc htop curl git software-properties-common \
 apache2 apache2-utils php7.0 libapache2-mod-php7.0 php7.0-opcache php-apcu \
 php7.0-mysql php7.0-curl php7.0-json php7.0-cgi php-mysql \
 php-gd php-mbstring php-mcrypt php-xml php-xmlrpc mysql-server \
 memcached libmemcached-tools php-memcache php-memcached php7.0-tidy

cat >> /etc/php/7.0/apache2/php.ini <<EOL
 
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=10
opcache.max_accelerated_files=10000
EOL

perl -pi -e "s/expose_php = On/expose_php = Off/g" /etc/php/7.0/apache2/php.ini

cat >> /etc/memcached.conf <<EOL

# disable UDP
-U 0
EOL
# Configure RAM for Memcached
RAM="`free -m | grep Mem | awk '{print $2}'`"
RAM_M=$(($RAM / 3))
perl -pi -e "s/-m 64/-m $RAM_M/g" /etc/memcached.conf
systemctl enable memcached.service
service memcached restart

perl -pi -e "s/ServerTokens OS/ServerTokens Prod/g" /etc/apache2/conf-enabled/security.conf
perl -pi -e "s/ServerSignature On/ServerSignature Off/g" /etc/apache2/conf-enabled/security.conf

P_IP="`wget http://ipinfo.io/ip -qO -`"

cat > /etc/apache2/sites-available/000-default.conf <<EOL
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName $P_IP
        DocumentRoot /var/www/html
        <Directory />
                Options +FollowSymLinks
                AllowOverride All
        </Directory>
        <Directory /var/www/html>
                Options -Indexes +FollowSymLinks +MultiViews
                AllowOverride All
                Order allow,deny
                allow from all
                Include custom.d/globalblacklist.conf
        </Directory>
        ErrorLog \${APACHE_LOG_DIR}/error.log
        CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOL

mkdir /etc/apache2/custom.d
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/globalblacklist.conf -O /etc/apache2/custom.d/globalblacklist.conf
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/whitelist-ips.conf -O /etc/apache2/custom.d/whitelist-ips.conf
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/whitelist-domains.conf -O /etc/apache2/custom.d/whitelist-domains.conf
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/blacklist-ips.conf -O /etc/apache2/custom.d/blacklist-ips.conf
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/blacklist-user-agents.conf -O /etc/apache2/custom.d/blacklist-user-agents.conf
wget https://raw.githubusercontent.com/josephgrut/apache-ultimate-bad-bot-blocker/master/Apache_2.2/custom.d/bad-referrer-words.conf -O /etc/apache2/custom.d/bad-referrer-words.conf

a2ensite 000-default
service apache2 reload

cat >/etc/apache2/mods-available/mpm_prefork.conf <<EOL
<IfModule mpm_prefork_module>
  StartServers       1
  MinSpareServers     10
  MaxSpareServers    30
  MaxClients         30
  MaxRequestWorkers   120
  MaxConnectionsPerChild   6000
</IfModule>
EOL

cat > /etc/apache2/mods-available/mpm_worker.conf <<EOL
<IfModule mpm_worker_module>
  StartServers       1
  MinSpareThreads    5
  MaxSpareThreads    15
  ThreadLimit      25
  ThreadsPerChild    5
  MaxRequestWorkers   25
  MaxConnectionsPerChild   200
</IfModule>
EOL
a2enmod rewrite
a2enmod ssl
a2enmod php7.0
a2enmod expires
a2enmod headers
a2dismod status

systemctl enable apache2.service
systemctl enable mysql.service

service apache2 restart
service mysql restart
#sleep 5
clear
#echo "============================================"
#echo "Adding SWAP"
#echo "============================================"

#RAM="`free -m | grep Mem | awk '{print $2}'`"
#swap_allowed=$(($RAM * 2))
#swap=$swap_allowed"M"
#fallocate -l $swap /var/swap.img
#chmod 600 /var/swap.img
#mkswap /var/swap.img
#swapon /var/swap.img
#echo -e "RAM detected: $RAM
#  Swap was created: $swap"
#sleep 5

#service apache2 restart
#service mysql restart
clear
echo " ";
echo "============================================"
echo "Lamp is installed!"
echo "============================================"

elif [ "$run" == "2" ] ; then
clear
echo " ";
echo "============================================"
echo "Adding new Virtual host + Wordpress"
echo "============================================"
echo -e "New user:"
read username
echo -e "New website name:"
read websitename
P_IP="`wget http://ipinfo.io/ip -qO -`"
db_pass=$(date +%s | sha256sum | base64 | head -c 18 ; echo)

groupadd $username
adduser --quiet --disabled-password --gecos "" --home /var/www/$username/$websitename/www --ingroup $username $username
echo "$username:$db_pass" | chpasswd

clear
echo " ";
echo "============================================"
echo "Configuring Apache"
echo "============================================"


 cat > /etc/apache2/sites-available/$websitename.conf <<EOL
  <VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName $websitename
        ServerAlias www.$websitename
        DocumentRoot /var/www/$username/$websitename/www/
        <Directory />
                Options +FollowSymLinks
                AllowOverride All
        </Directory>
        <Directory /var/www/$username/$websitename/www>
                Options -Indexes +FollowSymLinks +MultiViews
                AllowOverride All
                Order allow,deny
                allow from all
                Include custom.d/globalblacklist.conf
        </Directory>
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride None
                Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog \${APACHE_LOG_DIR}/$websitename-error.log
        LogLevel warn
        SetEnvIf Remote_Addr "127\.0\.0\.1" loopback
        CustomLog \${APACHE_LOG_DIR}/$websitename-access.log combined env=!loopback
</VirtualHost>
EOL
a2ensite $websitename

service apache2 reload
service mysql restart
clear
echo " ";
echo "============================================"
echo "Installing Wordpress"
echo "============================================"
#su $username
#cd /var/www/$username/$websitename/www
wget https://wordpress.org/latest.zip -O /tmp/latest.zip
unzip /tmp/latest.zip -d /var/www/$username/$websitename/www/
mv /var/www/$username/$websitename/www/wordpress/* /var/www/$username/$websitename/www
rm -rf /var/www/$username/$websitename/www/wordpress
rm /tmp/latest.zip
mkdir /var/www/$username/$websitename/www/wp-content/uploads
chmod -R 777 /var/www/$username/$websitename/www/wp-content/uploads
chmod 664 /var/www/$username/$websitename/www/readme.html

echo "============================================"
echo "Configuring .htaccess"
echo "============================================"

htpasswd -b -c /etc/apache2/.htpasswd a b

cat >/var/www/$username/$websitename/www/.htaccess <<EOL
AuthType Basic
AuthName "Restricted Content"
AuthUserFile /etc/apache2/.htpasswd
Require valid-user

php_value upload_max_filesize 128M
php_value max_execution_time 120
php_value max_input_vars 2000

<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
RewriteCond %{query_string} concat.*\( [NC,OR]
RewriteCond %{query_string} union.*select.*\( [NC,OR]
RewriteCond %{query_string} union.*all.*select [NC]
RewriteRule ^(.*)$ index.php [F,L]
RewriteCond %{QUERY_STRING} base64_encode[^(]*\([^)]*\) [OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
</IfModule>

<Files .htaccess>
Order Allow,Deny
Deny from all
</Files>

<Files wp-config.php>
Order Allow,Deny
Deny from all
</Files>

<Files wp-config-sample.php>
Order Allow,Deny
Deny from all
</Files>

<Files readme.html>
Order Allow,Deny
Deny from all
</Files>

<Files xmlrpc.php>
Order allow,deny
Deny from all
</files>

# Gzip
<ifModule mod_deflate.c>
AddOutputFilterByType DEFLATE text/text text/html text/plain text/xml text/css application/x-javascript application/javascript text/javascript
</ifModule>

Options +FollowSymLinks -Indexes

<IfModule mod_expires.c>
  ExpiresActive On

  # Images
  ExpiresByType image/jpeg "access plus 1 year"
  ExpiresByType image/gif "access plus 1 year"
  ExpiresByType image/png "access plus 1 year"
  ExpiresByType image/webp "access plus 1 year"
  ExpiresByType image/svg+xml "access plus 1 year"
  ExpiresByType image/x-icon "access plus 1 year"

  # Video
  ExpiresByType video/mp4 "access plus 1 year"
  ExpiresByType video/mpeg "access plus 1 year"

  # CSS, JavaScript
  ExpiresByType text/css "access plus 1 month"
  ExpiresByType text/javascript "access plus 1 month"
  ExpiresByType application/javascript "access plus 1 month"

  # Others
  ExpiresByType application/pdf "access plus 1 month"
  ExpiresByType application/x-shockwave-flash "access plus 1 month"
</IfModule>
EOL

chmod 644 /var/www/$username/$websitename/www/.htaccess

echo " ";
echo "============================================"
echo "Creating robots.txt"
echo "============================================"

cat >/var/www/$username/$websitename/www/robots.txt <<EOL
User-agent: *
Disallow: /cgi-bin
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/
Disallow: /wp-content/plugins/
Disallow: /wp-content/themes/
Disallow: /trackback
Disallow: */trackback
Disallow: */*/trackback
Disallow: */*/feed/*/
Disallow: */feed
Disallow: /*?*
Disallow: /tag
Disallow: /?author=*
EOL
chmod 644 /var/www/$username/$websitename/www/robots.txt

echo " ";
echo "============================================"
echo "Configuring Database for Wordpress"
echo "============================================"
echo "Input your ROOT password for mysql database"
mysql -u root -p <<EOF
CREATE USER '$username'@'localhost' IDENTIFIED BY '$db_pass';
CREATE DATABASE IF NOT EXISTS $username;
GRANT ALL PRIVILEGES ON $username.* TO '$username'@'localhost';
ALTER DATABASE $username CHARACTER SET utf8 COLLATE utf8_general_ci;
EOF

cd /var/www/$username/$websitename/www/
cp wp-config-sample.php wp-config.php
perl -pi -e "s/database_name_here/$username/g" wp-config.php
perl -pi -e "s/username_here/$username/g" wp-config.php
perl -pi -e "s/password_here/$db_pass/g" wp-config.php

#set WP salts
perl -i -pe'
  BEGIN {
    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
    push @chars, split //, "!@#$%^&*()-_ []{}<>~\`+=,.;:/?|";
    sub salt { join "", map $chars[ rand @chars ], 1 .. 64 }
  }
  s/put your unique phrase here/salt()/ge
' wp-config.php

echo "define('FS_METHOD', 'direct');" >> wp-config.php
echo "define( 'WP_AUTO_UPDATE_CORE', true );" >> wp-config.php

chown -R $username:www-data /var/www/$username/$websitename
chmod -R g+w /var/www/$username/$websitename/www/wp-content

echo " ";
echo "============================================"
echo "Configuring Backups for Wordpress"
echo "============================================"
cat > /var/www/$username/$websitename/backup-$websitename.sh <<EOL
#!/bin/bash
keepdays=2
backupdate=\$(date +%Y%m%d)
username=$username
websitename=$websitename
wp_config=/var/www/\$username/\$websitename/www/wp-config.php

db_name=\$(grep DB_NAME "\${wp_config}" | cut -f4 -d"'")
db_user=\$(grep DB_USER "\${wp_config}" | cut -f4 -d"'")
db_pass=\$(grep DB_PASSWORD "\${wp_config}" | cut -f4 -d"'")
table_prefix=\$(grep table_prefix "\${wp_config}" | cut -f2 -d"'")

mkdir /var/www/\$username/\$websitename/backups && cd /var/www/\$username/\$websitename/backups
mysqldump -u \$db_user -p\$db_pass \$db_name | gzip > \$backupdate-\$websitename-DB.sql.gz
zip -rq \$backupdate-\$websitename-FILES.zip /var/www/\$username/\$websitename/www/*

# Compresses the MySQL Dump and the Home Directory
tar zcPf \$websitename-\$backupdate.tar.gz *
chmod 600 \$websitename-\$backupdate.tar.gz

#Removes the SQL dump and Home DIR to conserve space
rm -rf \$backupdate-\$websitename-FILES.zip \$backupdate-\$websitename-DB.sql.gz

#Deletes any Backup older than X days
find /var/www/\$username/\$websitename/backups -type f -atime +\$keepdays -exec rm {} \;
EOL
cp /var/www/$username/$websitename/backup-$websitename.sh /etc/cron.weekly/backup-$websitename.sh
chmod +x /etc/cron.weekly/backup-$websitename.sh

clear
echo " ";
echo -e "User, group and home folder were succesfully created!
Username (db_user, db_name): $username
Password (db_pass): $db_pass
Home folder: /var/www/$username/$websitename
Website folder: /var/www/$username/$websitename/www
Backups folder: /var/www/$username/$websitename/backups
Apache config: /etc/apache2/sites-available/$websitename.conf
Website IP: $P_IP
login: http://$websitename/wp-login.php
 "
echo " ";
echo "========================="
echo "All is done!"
echo "========================="
fi
