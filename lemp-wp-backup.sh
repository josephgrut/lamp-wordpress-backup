#!/bin/bash -e
clear
echo " ";
echo "============================================"
echo "Install software: "
echo "============================================"
echo "What to do:
1. Install LEMP
2. New virtual host + Wordpress"
read -e run
if [ "$run" == "1" ] ; then
clear
echo " ";
echo "============================================"
echo "Install LEMP"
echo "============================================"
apt-get update && apt-get upgrade -y

# Installing SSH Public Key
mkdir ~/.ssh && touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
cat >> ~/.ssh/authorized_keys <<EOL
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAgEAmgga8N0mB/KDC5PPiEbRsaA46X8yey9iizgdGvAG1EEge6yGk91F/Rm7NMKkD4oRNKj23Udoh4LL6FXfJ/oRaEUz6p7gOidz5Ty6K9ghD6WvQaoXAhiWyeS66jfrz1UgmsF/F/J61pWTNlxjCqsOop+FlFwkET2dmKNDlwuibd1ezfu5XHxNWg+5LkabOVuuhSyfBewIaziWvsldFj4bMLl1h62ecV1qS4Xpd/aDfm8MglTlWq8FpPkjJJy7fBISsMIj06PG/ZhEZELEWVdqbAA4bxSw8qIM/7JMP9faUYKr/U7wRSsssenHznWRXYCF2J53LFJZe7GE3eGOa7jKtLFa42X7Oz23/bcagKjdsgC+6ptCybXYzxQ5GD7lbuc+nHKdLjV1tgsivs4mxj57sojl/l7MH+eGRfQPeMNzxBFh1wYvDqlpylNCbLqXXkTFQchOu8lBEeFvTaPopm6uqbYcR30gaIlQ/bwcw3Pn4UHGgnZAQbdEgnLYMEWbE5ayp7STJqaA+8CaDHh+UH0TdS35carUECK7BhzaxUvA6v/Ypy46HIGsnri8wWq6E1C9u2fjWBGCKQT/PRBW22CjNDRUdiiV+vU7/t101uYj5fZTv1cNsAOyXexmNjScM3Cia5UAI/isNLLjHdYlyo1P6b5w/zTZ5jrB7Y3N7dp/f6s= rsa-key-20181022
EOL
#cat >> /etc/ssh/ssh_config <<EOL
#PasswordAuthentication no
#EOL
#service ssh restart

apt-get -y install nano zip unzip mc htop curl git software-properties-common \
 nginx php7.0 php7.0-fpm php7.0-opcache php-apcu php7.0-mysql php7.0-curl \
 php7.0-json php7.0-cgi php7.0-mysql php7.0-common php7.0-gd php7.0-mbstring \
 php7.0-mcrypt php7.0-tidy php7.0-xml php7.0-xmlrpc mysql-server \
 memcached libmemcached-tools php-memcached

cat >> /etc/php/7.0/fpm/php.ini <<EOL
 
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=10
opcache.max_accelerated_files=10000
EOL

cat >> /etc/memcached.conf <<EOL

# disable UDP
-U 0
EOL

# Configure RAM for Memcached
RAM="`free -m | grep Mem | awk '{print $2}'`"
RAM_M=$(($RAM / 4))
perl -pi -e "s/-m 64/-m $RAM_M/g" /etc/memcached.conf

#perl -pi -e "s/ServerTokens OS/ServerTokens Prod/g" /etc/apache2/conf-enabled/security.conf
#perl -pi -e "s/ServerSignature On/ServerSignature Off/g" /etc/apache2/conf-enabled/security.conf

P_IP="`wget http://ipinfo.io/ip -qO -`"
cat > /etc/nginx/sites-available/default <<EOL
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name $P_IP;

        location / {
                try_files \$uri \$uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        }

        location ~ /\.ht {
                deny all;
        }
}
EOL
systemctl enable nginx.service
systemctl enable mysql.service
systemctl enable memcached.service

service memcached restart
service nginx restart
service mysql restart

clear
echo " ";
echo "============================================"
echo "LEMP is installed!"
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
echo "Configuring Nginx"
echo "============================================"


 cat > /etc/nginx/sites-available/$websitename.conf <<EOL
server {
    listen 80;
    server_name $websitename www.$websitename;
    root /var/www/$username/$websitename/www;
    index index.php index.html index.htm;
    
    gzip    on;
    gzip_comp_level   9;
    gzip_min_length   512;
    gzip_buffers  8 64k;
    gzip_types    text/plain;
    gzip_proxied    any;
    
    location / {
      index index.php index.html index.htm;
      try_files \$uri \$uri/ /index.php?\$args;
        }

    location ~ \.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/run/php/php7.0-fpm.sock;
      fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
      include fastcgi_params;
        }

        location ~ /\.ht {
                deny all;
        }
} 
EOL
ln -s /etc/nginx/sites-available/$websitename.conf /etc/nginx/sites-enabled/$websitename.conf

service nginx reload
service mysql restart
service php7.0-fpm restart

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

service nginx reload
service php7.0-fpm restart

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
