#
# Copyright (C) 2009-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nginx
PKG_VERSION:=1.2.2
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=http://nginx.org/download/
#PKG_MD5SUM:=53105bbe3ac9319db54d9eb46119695b

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

PKG_CONFIG_DEPENDS := \
	CONFIG_NGINX_STUB_STATUS \
	CONFIG_NGINX_FLV \
	CONFIG_NGINX_SSL \
	CONFIG_NGINX_DAV

#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/nginx
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Nginx web server
  URL:=http://nginx.org/
  DEPENDS:=+libpcre +libopenssl +zlib +libpthread +lua
  MENU:=1
endef

define Package/nginx/description
 nginx is an HTTP and reverse proxy server, as well as a mail proxy server,
 written by Igor Sysoev.
endef

define Package/nginx/config
  source "$(SOURCE)/Config.in"
endef

config_files=mime.types fastcgi_params koi-utf koi-win win-utf

define Package/nginx/conffiles
/etc/nginx/
endef

ADDITIONAL_MODULES:=

ifeq ($(CONFIG_IPV6),y)
  ADDITIONAL_MODULES += --with-ipv6
endif
ifeq ($(CONFIG_NGINX_STUB_STATUS),y)
  ADDITIONAL_MODULES += --with-http_stub_status_module
endif
ifeq ($(CONFIG_NGINX_FLV),y)
  ADDITIONAL_MODULES += --with-http_flv_module
endif
ifeq ($(CONFIG_NGINX_SSL),y)
  ADDITIONAL_MODULES += --with-http_ssl_module
#else
#  ADDITIONAL_MODULES += --without-http-cache
endif
ifeq ($(CONFIG_NGINX_DAV),y)
  ADDITIONAL_MODULES += --with-http_dav_module
endif

ADDITIONAL_MODULES += --with-tproxy
ADDITIONAL_MODULES += --add-module=src/tcp --add-module=src/handoff --add-module=src/filter

ADDITIONAL_MODULES += --with-debug

ADDITIONAL_MODULES += --without-http_ssi_module --without-http_geo_module --without-http_map_module \
	--without-http_uwsgi_module --without-http_scgi_module --without-http_memcached_module \
	--without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./pkg-src/* $(PKG_BUILD_DIR)
endef

#TARGET_CFLAGS += -I$(PKG_BUILD_DIR)/src/libevent
#CONFIGURE_PATH := ./src
#CONFIGURE_ARGS += ac_cv_path_PPPD=/usr/sbin/pppd --enable-plugin=$(STAGING_DIR)/usr/include/
#MAKE_FLAGS := DESTDIR="$(PKG_INSTALL_DIR)" install
#MAKE_PATH := ./src

define Build/Configure
	# TODO: fix --crossbuild
	(cd $(PKG_BUILD_DIR) ;\
		./configure \
			--crossbuild=Linux::$(ARCH) \
			--prefix=/usr \
			--conf-path=/etc/nginx/nginx.conf \
			--error-log-path=/userdisk/nginx/log/error.log \
			--pid-path=/var/run/nginx.pid \
			--lock-path=/userdisk/nginx/lock/nginx.lock \
			--http-log-path=/userdisk/nginx/log/access.log \
			--http-client-body-temp-path=/userdisk/nginx/body \
			--http-proxy-temp-path=/userdisk/nginx/proxy \
			--http-fastcgi-temp-path=/userdisk/nginx/fastcgi \
			--with-cc="$(TARGET_CC)" \
			--add-module=$(PKG_BUILD_DIR)/src/lua/ngx_devel_kit \
			--add-module=$(PKG_BUILD_DIR)/src/lua/lua-nginx-module \
			--with-cc-opt="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
			--with-ld-opt="$(TARGET_LDFLAGS)" \
			$(ADDITIONAL_MODULES) )
endef

define Package/nginx/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/nginx $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/nginx.loader $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/nginx.monitor $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/nginx.hotplug $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/nginx
	$(INSTALL_DATA) ./files/nginx.conf $(1)/etc/nginx/
	$(INSTALL_DATA) ./files/nginx.autocache.conf $(1)/etc/nginx/
	$(INSTALL_DATA) $(addprefix $(PKG_INSTALL_DIR)/etc/nginx/,$(config_files)) $(1)/etc/nginx/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nginx.init $(1)/etc/init.d/nginx
	$(INSTALL_DIR) $(1)/etc/nginx/htdocs/
	$(INSTALL_DATA) ./files/proxy.index.html $(1)/etc/nginx/htdocs/index.html
	$(INSTALL_DIR) $(1)/data/
	$(INSTALL_DATA) ./files/data.readme $(1)/data/data.readme
	$(INSTALL_DIR) $(1)/userdisk/nginx/
	$(INSTALL_DATA) ./files/nginxdata.readme $(1)/userdisk/nginx/nginxdata.readme
endef

$(eval $(call BuildPackage,nginx))
