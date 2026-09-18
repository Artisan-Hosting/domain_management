The config files each new cert needs: 
root@certs:/mnt/nginx_local/snippets# cat artisanhosting_cert.conf 
#ssl_certificate /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/fullchain.pem;
#ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/privkey.pem;

ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/ecc.pem;
ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/ecc.key;

ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/rsa.pem;
ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/rsa.key;
root@certs:/mnt/nginx_local/snippets# cat artisanstudio_cert.conf 
#ssl_certificate /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/fullchain.pem;
#ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/privkey.pem;

ssl_certificate     /etc/nginx/certs/_.artisanstudio.net/ecc.pem;
ssl_certificate_key /etc/nginx/certs/_.artisanstudio.net/ecc.key;

ssl_certificate     /etc/nginx/certs/_.artisanstudio.net/rsa.pem;
ssl_certificate_key /etc/nginx/certs/_.artisanstudio.net/rsa.key;
root@certs:/mnt/nginx_local/snippets# 

root@certs:/mnt/nginx_local/snippets# pwd && ls -al
/mnt/nginx_local/snippets
total 68
drwxr-x---  2 root root 4096 Aug 26 22:27 .
drwxr-xr-x 13 root root 4096 Sep  9 15:38 ..
-rw-r-----  1 root root  235 Sep 29  2025 arhst_cert.conf
-rw-r-----  1 root root  446 Sep 29  2025 artisanhosting_cert.conf
-rw-r-----  1 root root  442 Feb 16  2026 artisanstudio_cert.conf
-rw-r-----  1 root root  426 Nov 20  2025 dywnotary_cert.conf
-rw-r-----  1 root root  423 Sep 29  2025 fastcgi-php.conf
-rw-r-----  1 root root  262 Sep 29  2025 makasecurity_cert.conf
-rw-r-----  1 root root  174 Sep 29  2025 mitobyte_cert.conf
-rw-r-----  1 root root  356 Feb 17  2026 piercedbybugg_cert.conf
-rw-r-----  1 root root  178 Sep 29  2025 piercedbybugg_cert.conf.old
-rw-r-----  1 root root  410 Jun  6 12:55 ramfield_cert.conf
-rw-r-----  1 root root  342 Aug 26 17:54 ritetoform_cert.conf
-rw-r-----  1 root root  112 Sep 29  2025 self-signed.conf
-rw-r-----  1 root root  217 Sep 29  2025 snakeoil.conf
-rw-r-----  1 root root  397 Aug 26 22:27 ssl-params.conf
-rw-r-----  1 root root  622 Sep 29  2025 ssl-params.conf.weak
root@certs:/mnt/nginx_local/snippets# 

root@certs:/mnt/nginx_local/sites-enabled# sl
bash: sl: command not found
root@certs:/mnt/nginx_local/sites-enabled# ls
artisan_api        artisan_nextcloud        artisanstudio                 dwhitfield_couchdb        jakwoun_postiz       maka_openproject
artisan_auth       artisan_plausible        artisanstudio_analitics       dwhitfield_doge           link1_artisanstudio  maka_staging
artisan_beta       artisan_postiz           artisanstudio_captcha         dwhitfield_immich         link2_artisanstudio  mitobyte_staging
artisan_blog       artisan_proxmox          artisanstudio_qrcodes         dwhitfield_matrix         link3_artisanstudio  picmke_demo
artisan_dap        artisan_relay            artisanstudio_staging         dwhitfield_passbolt       link4_artisanstudio  ritetoform
artisan_dashboard  artisan_uptime           deborah_wordpress             dwhitfield_test           link5_artisanstudio  ritetoform_redirect
artisan_demo       artisanhosting           dwhitfield_accountant         dywnotary                 link6_artisanstudio  template1_artisanstudio
artisan_docs       artisanhosting_mail      dwhitfield_accountant_import  fallback                  m1tobyte             template2_artisanstudio
artisan_links      artisanhosting_services  dwhitfield_bitwarden          health                    mac_staging          template3_artisanstudio
artisan_n80        artisanhosting_staging   dwhitfield_cookout            inprogress_artisanstudio  maka                 template4_artisanstudio
root@certs:/mnt/nginx_local/sites-enabled# cat artisanhosting
server {
    access_log /var/log/nginx/access.log otel_json; 
    error_log /var/log/nginx/error.log warn;
    listen 443 ssl http2;
    server_name www.artisanhosting.net artisanhosting.net;

    include snippets/artisanhosting_cert.conf;
    include snippets/ssl-params.conf;
    
    location / {

        add_header 'Access-Control-Allow-Origin' '*';
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range';
#               add_header Content-Security-Policy "script-src 'self' https://static.cloudflareinsights.com;";


        if ($request_method = 'OPTIONS') {
            return 204;
        }

        proxy_pass http://artisan_release;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

upstream artisan_release {
    random;
    server ahpn-2973453917896704.ah.internal:8093 max_fails=10 fail_timeout=10s;
    server ahpn-3091229306929152.ah.internal:8093 max_fails=10 fail_timeout=10s;
#    server 10.11.0.12:8081 max_fails=10 fail_timeout=10s;
#    server 10.11.0.13:8081 max_fails=10 fail_timeout=10s;
#    server 10.11.0.14:8081 max_fails=10 fail_timeout=10s;
}
root@certs:/mnt/nginx_local/sites-enabled# 

root@certs:/mnt/nginx_local/sites-enabled# cat link6_artisanstudio 
server {
    access_log /var/log/nginx/access.log otel_json; 
    error_log /var/log/nginx/error.log warn;
    listen 443 ssl http2;
    server_name link6.artisanstudio.net;

    include snippets/artisanstudio_cert.conf;
    include snippets/ssl-params.conf;
    
    location / {
        proxy_pass http://10.4.1.2:4015;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}



