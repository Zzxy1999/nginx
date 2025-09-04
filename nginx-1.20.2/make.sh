#!/bin/bash

set -e

# 创建目录(使用用户目录避免sudo)
mkdir -p ~/nginx/{logs,cache/{client,proxy,fastcgi,uwsgi,scgi}_temp}

# 清理
[ -f Makefile ] && make clean 2>/dev/null || true

# 配置
./configure \
  --prefix=/usr/local/nginx \
  --sbin-path=/usr/local/nginx/sbin/nginx \
  --conf-path=/usr/local/nginx/conf/nginx.conf \
  --error-log-path=$HOME/nginx/logs/error.log \
  --http-log-path=$HOME/nginx/logs/access.log \
  --with-debug \
  --with-cc-opt='-g -O0 -DNGX_DEBUG' \
  --with-openssl-opt='-g -O0' \
  --pid-path=$HOME/nginx/nginx.pid \
  --lock-path=$HOME/nginx/nginx.lock \
  --http-client-body-temp-path=$HOME/nginx/cache/client_temp \
  --http-proxy-temp-path=$HOME/nginx/cache/proxy_temp \
  --http-fastcgi-temp-path=$HOME/nginx/cache/fastcgi_temp \
  --http-uwsgi-temp-path=$HOME/nginx/cache/uwsgi_temp \
  --http-scgi-temp-path=$HOME/nginx/cache/scgi_temp \
  --with-openssl=../openssl-1.1.1h \
  --user=www-data \
  --group=www-data \
  --with-file-aio \
  --with-threads \
  --with-http_addition_module \
  --with-http_auth_request_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_mp4_module \
  --with-http_realip_module \
  --with-http_secure_link_module \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=../third-modules/nginx-ssl-fingerprint

# 编译
make -j$(nproc)

# 安装
sudo make install

echo "完成! nginx安装在 /usr/local/nginx"
echo "启动: sudo /usr/local/nginx/sbin/nginx"