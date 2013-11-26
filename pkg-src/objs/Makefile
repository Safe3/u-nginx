
CC =	gcc
CFLAGS =   -DNDK_SET_VAR
CPP =	
LINK =	$(CC)


ALL_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/os/unix \
	-I src/tcp/modules \
	-I src/tcp/parsers \
	-I src/tcp \
	-I src/handoff/modules \
	-I src/handoff/parsers \
	-I src/handoff \
	-I src/filter/modules \
	-I src/filter/parsers \
	-I src/filter \
	-I src/lua/ngx_devel_kit/objs \
	-I objs/addon/ndk \
	-I /usr/include/luajit-2.0 \
	-I src/lua/lua-nginx-module/src/api \
	-I objs \
	-I src/http \
	-I src/http/modules \
	-I src/lua/ngx_devel_kit/src \
	-I src/mail


CORE_DEPS = src/core/nginx.h \
	src/core/ngx_config.h \
	src/core/ngx_core.h \
	src/core/ngx_log.h \
	src/core/ngx_palloc.h \
	src/core/ngx_array.h \
	src/core/ngx_list.h \
	src/core/ngx_hash.h \
	src/core/ngx_buf.h \
	src/core/ngx_queue.h \
	src/core/ngx_string.h \
	src/core/ngx_parse.h \
	src/core/ngx_inet.h \
	src/core/ngx_file.h \
	src/core/ngx_crc.h \
	src/core/ngx_crc32.h \
	src/core/ngx_murmurhash.h \
	src/core/ngx_md5.h \
	src/core/ngx_sha1.h \
	src/core/ngx_rbtree.h \
	src/core/ngx_radix_tree.h \
	src/core/ngx_slab.h \
	src/core/ngx_times.h \
	src/core/ngx_shmtx.h \
	src/core/ngx_connection.h \
	src/core/ngx_cycle.h \
	src/core/ngx_conf_file.h \
	src/core/ngx_resolver.h \
	src/core/ngx_open_file_cache.h \
	src/core/ngx_crypt.h \
	src/event/ngx_event.h \
	src/event/ngx_event_timer.h \
	src/event/ngx_event_posted.h \
	src/event/ngx_event_busy_lock.h \
	src/event/ngx_event_connect.h \
	src/event/ngx_event_pipe.h \
	src/os/unix/ngx_time.h \
	src/os/unix/ngx_errno.h \
	src/os/unix/ngx_alloc.h \
	src/os/unix/ngx_files.h \
	src/os/unix/ngx_channel.h \
	src/os/unix/ngx_shmem.h \
	src/os/unix/ngx_process.h \
	src/os/unix/ngx_setaffinity.h \
	src/os/unix/ngx_setproctitle.h \
	src/os/unix/ngx_atomic.h \
	src/os/unix/ngx_gcc_atomic_x86.h \
	src/os/unix/ngx_thread.h \
	src/os/unix/ngx_socket.h \
	src/os/unix/ngx_os.h \
	src/os/unix/ngx_user.h \
	src/os/unix/ngx_process_cycle.h \
	src/os/unix/ngx_linux_config.h \
	src/os/unix/ngx_linux.h \
	src/event/ngx_event_openssl.h \
	src/core/ngx_regex.h \
	objs/ngx_auto_config.h


CORE_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/os/unix \
	-I src/tcp/modules \
	-I src/tcp/parsers \
	-I src/tcp \
	-I src/handoff/modules \
	-I src/handoff/parsers \
	-I src/handoff \
	-I src/filter/modules \
	-I src/filter/parsers \
	-I src/filter \
	-I src/lua/ngx_devel_kit/objs \
	-I objs/addon/ndk \
	-I /usr/include/luajit-2.0 \
	-I src/lua/lua-nginx-module/src/api \
	-I objs


HTTP_DEPS = src/http/ngx_http.h \
	src/http/ngx_http_request.h \
	src/http/ngx_http_config.h \
	src/http/ngx_http_core_module.h \
	src/http/ngx_http_cache.h \
	src/http/ngx_http_variables.h \
	src/http/ngx_http_script.h \
	src/http/ngx_http_upstream.h \
	src/http/ngx_http_upstream_round_robin.h \
	src/http/ngx_http_busy_lock.h


HTTP_INCS = -I src/http \
	-I src/http/modules \
	-I src/lua/ngx_devel_kit/src


ADDON_DEPS = $(CORE_DEPS)  src/tcp/ngx_tcp.h src/tcp/ngx_tcp_session.h src/tcp/ngx_tcp_upstream.h src/tcp/ngx_tcp_upstream_check.h src/tcp/ngx_tcp_upstream_round_robin.h src/tcp/parsers/parser.h src/tcp/parsers/http_request_parser.h src/tcp/parsers/http_response_parser.h src/tcp/parsers/smtp_response_parser.h src/tcp/modules/ngx_tcp_ssl_module.h src/handoff/ngx_handoff.h src/handoff/ngx_handoff_session.h  src/filter/ngx_filter.h src/filter/ngx_filter_session.h                  src/lua/lua-nginx-module/src/ddebug.h                 src/lua/lua-nginx-module/src/ngx_http_lua_script.h                 src/lua/lua-nginx-module/src/ngx_http_lua_log.h                 src/lua/lua-nginx-module/src/ngx_http_lua_subrequest.h                 src/lua/lua-nginx-module/src/ngx_http_lua_ndk.h                 src/lua/lua-nginx-module/src/ngx_http_lua_control.h                 src/lua/lua-nginx-module/src/ngx_http_lua_time.h                 src/lua/lua-nginx-module/src/ngx_http_lua_string.h                 src/lua/lua-nginx-module/src/ngx_http_lua_misc.h                 src/lua/lua-nginx-module/src/ngx_http_lua_variable.h                 src/lua/lua-nginx-module/src/ngx_http_lua_output.h                 src/lua/lua-nginx-module/src/ngx_http_lua_headers.h                 src/lua/lua-nginx-module/src/ngx_http_lua_uri.h                 src/lua/lua-nginx-module/src/ngx_http_lua_req_body.h                 src/lua/lua-nginx-module/src/ngx_http_lua_args.h                 src/lua/lua-nginx-module/src/ngx_http_lua_ctx.h                 src/lua/lua-nginx-module/src/ngx_http_lua_regex.h                 src/lua/lua-nginx-module/src/ngx_http_lua_common.h                 src/lua/lua-nginx-module/src/ngx_http_lua_directive.h                 src/lua/lua-nginx-module/src/ngx_http_lua_headers_out.h                 src/lua/lua-nginx-module/src/ngx_http_lua_headers_in.h                 src/lua/lua-nginx-module/src/ngx_http_lua_consts.h                 src/lua/lua-nginx-module/src/ngx_http_lua_exception.h                 src/lua/lua-nginx-module/src/ngx_http_lua_util.h                 src/lua/lua-nginx-module/src/ngx_http_lua_cache.h                 src/lua/lua-nginx-module/src/ngx_http_lua_contentby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_rewriteby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_accessby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_setby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_capturefilter.h                 src/lua/lua-nginx-module/src/ngx_http_lua_clfactory.h                 src/lua/lua-nginx-module/src/ngx_http_lua_pcrefix.h                 src/lua/lua-nginx-module/src/ngx_http_lua_headerfilterby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_shdict.h                 src/lua/lua-nginx-module/src/ngx_http_lua_socket_tcp.h                 src/lua/lua-nginx-module/src/api/ngx_http_lua_api.h                 src/lua/lua-nginx-module/src/ngx_http_lua_logby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_sleep.h                 src/lua/lua-nginx-module/src/ngx_http_lua_coroutine.h                 src/lua/lua-nginx-module/src/ngx_http_lua_bodyfilterby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_initby.h                 src/lua/lua-nginx-module/src/ngx_http_lua_socket_udp.h                 src/lua/lua-nginx-module/src/ngx_http_lua_req_method.h                 src/lua/lua-nginx-module/src/ngx_http_lua_phase.h                 src/lua/lua-nginx-module/src/ngx_http_lua_probe.h                 src/lua/lua-nginx-module/src/ngx_http_lua_uthread.h                 src/lua/lua-nginx-module/src/ngx_http_lua_timer.h                 src/lua/lua-nginx-module/src/ngx_http_lua_config.h                  $(HTTP_DEPS)


objs/nginx:	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_busy_lock.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_parse_time.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/ngx_http_busy_lock.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_userid_filter_module.o \
	objs/src/http/modules/ngx_http_preload_cache_module.o \
	objs/src/http/modules/ngx_http_preload_filter_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_split_clients_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_empty_gif_module.o \
	objs/src/http/modules/ngx_http_browser_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/addon/tcp/ngx_tcp.o \
	objs/addon/tcp/ngx_tcp_core_module.o \
	objs/addon/tcp/ngx_tcp_session.o \
	objs/addon/tcp/ngx_tcp_access.o \
	objs/addon/tcp/ngx_tcp_log.o \
	objs/addon/tcp/ngx_tcp_upstream.o \
	objs/addon/tcp/ngx_tcp_upstream_round_robin.o \
	objs/addon/modules/ngx_tcp_generic_proxy_module.o \
	objs/addon/modules/ngx_tcp_websocket_proxy_module.o \
	objs/addon/modules/ngx_tcp_upstream_ip_hash_module.o \
	objs/addon/modules/ngx_tcp_upstream_busyness_module.o \
	objs/addon/tcp/ngx_tcp_upstream_check.o \
	objs/addon/parsers/http_request_parser.o \
	objs/addon/parsers/http_response_parser.o \
	objs/addon/parsers/smtp_response_parser.o \
	objs/addon/modules/ngx_tcp_ssl_module.o \
	objs/addon/handoff/ngx_handoff.o \
	objs/addon/handoff/ngx_handoff_core_module.o \
	objs/addon/handoff/ngx_handoff_log.o \
	objs/addon/handoff/ngx_handoff_session.o \
	objs/addon/filter/ngx_filter.o \
	objs/addon/filter/ngx_filter_core_module.o \
	objs/addon/filter/ngx_filter_log.o \
	objs/addon/filter/ngx_filter_session.o \
	objs/addon/src/ndk.o \
	objs/addon/src/ngx_http_lua_script.o \
	objs/addon/src/ngx_http_lua_log.o \
	objs/addon/src/ngx_http_lua_subrequest.o \
	objs/addon/src/ngx_http_lua_ndk.o \
	objs/addon/src/ngx_http_lua_control.o \
	objs/addon/src/ngx_http_lua_time.o \
	objs/addon/src/ngx_http_lua_misc.o \
	objs/addon/src/ngx_http_lua_variable.o \
	objs/addon/src/ngx_http_lua_string.o \
	objs/addon/src/ngx_http_lua_output.o \
	objs/addon/src/ngx_http_lua_headers.o \
	objs/addon/src/ngx_http_lua_req_body.o \
	objs/addon/src/ngx_http_lua_uri.o \
	objs/addon/src/ngx_http_lua_args.o \
	objs/addon/src/ngx_http_lua_ctx.o \
	objs/addon/src/ngx_http_lua_regex.o \
	objs/addon/src/ngx_http_lua_module.o \
	objs/addon/src/ngx_http_lua_headers_out.o \
	objs/addon/src/ngx_http_lua_headers_in.o \
	objs/addon/src/ngx_http_lua_directive.o \
	objs/addon/src/ngx_http_lua_consts.o \
	objs/addon/src/ngx_http_lua_exception.o \
	objs/addon/src/ngx_http_lua_util.o \
	objs/addon/src/ngx_http_lua_cache.o \
	objs/addon/src/ngx_http_lua_contentby.o \
	objs/addon/src/ngx_http_lua_rewriteby.o \
	objs/addon/src/ngx_http_lua_accessby.o \
	objs/addon/src/ngx_http_lua_setby.o \
	objs/addon/src/ngx_http_lua_capturefilter.o \
	objs/addon/src/ngx_http_lua_clfactory.o \
	objs/addon/src/ngx_http_lua_pcrefix.o \
	objs/addon/src/ngx_http_lua_headerfilterby.o \
	objs/addon/src/ngx_http_lua_shdict.o \
	objs/addon/src/ngx_http_lua_socket_tcp.o \
	objs/addon/src/ngx_http_lua_api.o \
	objs/addon/src/ngx_http_lua_logby.o \
	objs/addon/src/ngx_http_lua_sleep.o \
	objs/addon/src/ngx_http_lua_coroutine.o \
	objs/addon/src/ngx_http_lua_bodyfilterby.o \
	objs/addon/src/ngx_http_lua_initby.o \
	objs/addon/src/ngx_http_lua_socket_udp.o \
	objs/addon/src/ngx_http_lua_req_method.o \
	objs/addon/src/ngx_http_lua_phase.o \
	objs/addon/src/ngx_http_lua_uthread.o \
	objs/addon/src/ngx_http_lua_timer.o \
	objs/addon/src/ngx_http_lua_config.o \
	objs/ngx_modules.o

	$(LINK) -o objs/nginx \
	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_busy_lock.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_parse_time.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/ngx_http_busy_lock.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_userid_filter_module.o \
	objs/src/http/modules/ngx_http_preload_cache_module.o \
	objs/src/http/modules/ngx_http_preload_filter_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_split_clients_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_empty_gif_module.o \
	objs/src/http/modules/ngx_http_browser_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/addon/tcp/ngx_tcp.o \
	objs/addon/tcp/ngx_tcp_core_module.o \
	objs/addon/tcp/ngx_tcp_session.o \
	objs/addon/tcp/ngx_tcp_access.o \
	objs/addon/tcp/ngx_tcp_log.o \
	objs/addon/tcp/ngx_tcp_upstream.o \
	objs/addon/tcp/ngx_tcp_upstream_round_robin.o \
	objs/addon/modules/ngx_tcp_generic_proxy_module.o \
	objs/addon/modules/ngx_tcp_websocket_proxy_module.o \
	objs/addon/modules/ngx_tcp_upstream_ip_hash_module.o \
	objs/addon/modules/ngx_tcp_upstream_busyness_module.o \
	objs/addon/tcp/ngx_tcp_upstream_check.o \
	objs/addon/parsers/http_request_parser.o \
	objs/addon/parsers/http_response_parser.o \
	objs/addon/parsers/smtp_response_parser.o \
	objs/addon/modules/ngx_tcp_ssl_module.o \
	objs/addon/handoff/ngx_handoff.o \
	objs/addon/handoff/ngx_handoff_core_module.o \
	objs/addon/handoff/ngx_handoff_log.o \
	objs/addon/handoff/ngx_handoff_session.o \
	objs/addon/filter/ngx_filter.o \
	objs/addon/filter/ngx_filter_core_module.o \
	objs/addon/filter/ngx_filter_log.o \
	objs/addon/filter/ngx_filter_session.o \
	objs/addon/src/ndk.o \
	objs/addon/src/ngx_http_lua_script.o \
	objs/addon/src/ngx_http_lua_log.o \
	objs/addon/src/ngx_http_lua_subrequest.o \
	objs/addon/src/ngx_http_lua_ndk.o \
	objs/addon/src/ngx_http_lua_control.o \
	objs/addon/src/ngx_http_lua_time.o \
	objs/addon/src/ngx_http_lua_misc.o \
	objs/addon/src/ngx_http_lua_variable.o \
	objs/addon/src/ngx_http_lua_string.o \
	objs/addon/src/ngx_http_lua_output.o \
	objs/addon/src/ngx_http_lua_headers.o \
	objs/addon/src/ngx_http_lua_req_body.o \
	objs/addon/src/ngx_http_lua_uri.o \
	objs/addon/src/ngx_http_lua_args.o \
	objs/addon/src/ngx_http_lua_ctx.o \
	objs/addon/src/ngx_http_lua_regex.o \
	objs/addon/src/ngx_http_lua_module.o \
	objs/addon/src/ngx_http_lua_headers_out.o \
	objs/addon/src/ngx_http_lua_headers_in.o \
	objs/addon/src/ngx_http_lua_directive.o \
	objs/addon/src/ngx_http_lua_consts.o \
	objs/addon/src/ngx_http_lua_exception.o \
	objs/addon/src/ngx_http_lua_util.o \
	objs/addon/src/ngx_http_lua_cache.o \
	objs/addon/src/ngx_http_lua_contentby.o \
	objs/addon/src/ngx_http_lua_rewriteby.o \
	objs/addon/src/ngx_http_lua_accessby.o \
	objs/addon/src/ngx_http_lua_setby.o \
	objs/addon/src/ngx_http_lua_capturefilter.o \
	objs/addon/src/ngx_http_lua_clfactory.o \
	objs/addon/src/ngx_http_lua_pcrefix.o \
	objs/addon/src/ngx_http_lua_headerfilterby.o \
	objs/addon/src/ngx_http_lua_shdict.o \
	objs/addon/src/ngx_http_lua_socket_tcp.o \
	objs/addon/src/ngx_http_lua_api.o \
	objs/addon/src/ngx_http_lua_logby.o \
	objs/addon/src/ngx_http_lua_sleep.o \
	objs/addon/src/ngx_http_lua_coroutine.o \
	objs/addon/src/ngx_http_lua_bodyfilterby.o \
	objs/addon/src/ngx_http_lua_initby.o \
	objs/addon/src/ngx_http_lua_socket_udp.o \
	objs/addon/src/ngx_http_lua_req_method.o \
	objs/addon/src/ngx_http_lua_phase.o \
	objs/addon/src/ngx_http_lua_uthread.o \
	objs/addon/src/ngx_http_lua_timer.o \
	objs/addon/src/ngx_http_lua_config.o \
	objs/ngx_modules.o \
	-Wl,-E -lpthread -lcrypt -L/usr/lib/x86_64-linux-gnu/ -lluajit-5.1 -lm -lpcre -lssl -lcrypto -ldl -lz
	


objs/ngx_modules.o:	$(CORE_DEPS) \
	objs/ngx_modules.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/ngx_modules.o \
		objs/ngx_modules.c


objs/src/core/nginx.o:	$(CORE_DEPS) \
	src/core/nginx.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/nginx.o \
		src/core/nginx.c


objs/src/core/ngx_log.o:	$(CORE_DEPS) \
	src/core/ngx_log.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_log.o \
		src/core/ngx_log.c


objs/src/core/ngx_palloc.o:	$(CORE_DEPS) \
	src/core/ngx_palloc.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_palloc.o \
		src/core/ngx_palloc.c


objs/src/core/ngx_array.o:	$(CORE_DEPS) \
	src/core/ngx_array.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_array.o \
		src/core/ngx_array.c


objs/src/core/ngx_list.o:	$(CORE_DEPS) \
	src/core/ngx_list.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_list.o \
		src/core/ngx_list.c


objs/src/core/ngx_hash.o:	$(CORE_DEPS) \
	src/core/ngx_hash.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_hash.o \
		src/core/ngx_hash.c


objs/src/core/ngx_buf.o:	$(CORE_DEPS) \
	src/core/ngx_buf.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_buf.o \
		src/core/ngx_buf.c


objs/src/core/ngx_queue.o:	$(CORE_DEPS) \
	src/core/ngx_queue.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_queue.o \
		src/core/ngx_queue.c


objs/src/core/ngx_output_chain.o:	$(CORE_DEPS) \
	src/core/ngx_output_chain.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_output_chain.o \
		src/core/ngx_output_chain.c


objs/src/core/ngx_string.o:	$(CORE_DEPS) \
	src/core/ngx_string.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_string.o \
		src/core/ngx_string.c


objs/src/core/ngx_parse.o:	$(CORE_DEPS) \
	src/core/ngx_parse.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_parse.o \
		src/core/ngx_parse.c


objs/src/core/ngx_inet.o:	$(CORE_DEPS) \
	src/core/ngx_inet.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_inet.o \
		src/core/ngx_inet.c


objs/src/core/ngx_file.o:	$(CORE_DEPS) \
	src/core/ngx_file.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_file.o \
		src/core/ngx_file.c


objs/src/core/ngx_crc32.o:	$(CORE_DEPS) \
	src/core/ngx_crc32.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crc32.o \
		src/core/ngx_crc32.c


objs/src/core/ngx_murmurhash.o:	$(CORE_DEPS) \
	src/core/ngx_murmurhash.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_murmurhash.o \
		src/core/ngx_murmurhash.c


objs/src/core/ngx_md5.o:	$(CORE_DEPS) \
	src/core/ngx_md5.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_md5.o \
		src/core/ngx_md5.c


objs/src/core/ngx_rbtree.o:	$(CORE_DEPS) \
	src/core/ngx_rbtree.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_rbtree.o \
		src/core/ngx_rbtree.c


objs/src/core/ngx_radix_tree.o:	$(CORE_DEPS) \
	src/core/ngx_radix_tree.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_radix_tree.o \
		src/core/ngx_radix_tree.c


objs/src/core/ngx_slab.o:	$(CORE_DEPS) \
	src/core/ngx_slab.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_slab.o \
		src/core/ngx_slab.c


objs/src/core/ngx_times.o:	$(CORE_DEPS) \
	src/core/ngx_times.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_times.o \
		src/core/ngx_times.c


objs/src/core/ngx_shmtx.o:	$(CORE_DEPS) \
	src/core/ngx_shmtx.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_shmtx.o \
		src/core/ngx_shmtx.c


objs/src/core/ngx_connection.o:	$(CORE_DEPS) \
	src/core/ngx_connection.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_connection.o \
		src/core/ngx_connection.c


objs/src/core/ngx_cycle.o:	$(CORE_DEPS) \
	src/core/ngx_cycle.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cycle.o \
		src/core/ngx_cycle.c


objs/src/core/ngx_spinlock.o:	$(CORE_DEPS) \
	src/core/ngx_spinlock.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_spinlock.o \
		src/core/ngx_spinlock.c


objs/src/core/ngx_cpuinfo.o:	$(CORE_DEPS) \
	src/core/ngx_cpuinfo.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cpuinfo.o \
		src/core/ngx_cpuinfo.c


objs/src/core/ngx_conf_file.o:	$(CORE_DEPS) \
	src/core/ngx_conf_file.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_conf_file.o \
		src/core/ngx_conf_file.c


objs/src/core/ngx_resolver.o:	$(CORE_DEPS) \
	src/core/ngx_resolver.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_resolver.o \
		src/core/ngx_resolver.c


objs/src/core/ngx_open_file_cache.o:	$(CORE_DEPS) \
	src/core/ngx_open_file_cache.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_open_file_cache.o \
		src/core/ngx_open_file_cache.c


objs/src/core/ngx_crypt.o:	$(CORE_DEPS) \
	src/core/ngx_crypt.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crypt.o \
		src/core/ngx_crypt.c


objs/src/event/ngx_event.o:	$(CORE_DEPS) \
	src/event/ngx_event.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event.o \
		src/event/ngx_event.c


objs/src/event/ngx_event_timer.o:	$(CORE_DEPS) \
	src/event/ngx_event_timer.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_timer.o \
		src/event/ngx_event_timer.c


objs/src/event/ngx_event_posted.o:	$(CORE_DEPS) \
	src/event/ngx_event_posted.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_posted.o \
		src/event/ngx_event_posted.c


objs/src/event/ngx_event_busy_lock.o:	$(CORE_DEPS) \
	src/event/ngx_event_busy_lock.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_busy_lock.o \
		src/event/ngx_event_busy_lock.c


objs/src/event/ngx_event_accept.o:	$(CORE_DEPS) \
	src/event/ngx_event_accept.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_accept.o \
		src/event/ngx_event_accept.c


objs/src/event/ngx_event_connect.o:	$(CORE_DEPS) \
	src/event/ngx_event_connect.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_connect.o \
		src/event/ngx_event_connect.c


objs/src/event/ngx_event_pipe.o:	$(CORE_DEPS) \
	src/event/ngx_event_pipe.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_pipe.o \
		src/event/ngx_event_pipe.c


objs/src/os/unix/ngx_time.o:	$(CORE_DEPS) \
	src/os/unix/ngx_time.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_time.o \
		src/os/unix/ngx_time.c


objs/src/os/unix/ngx_errno.o:	$(CORE_DEPS) \
	src/os/unix/ngx_errno.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_errno.o \
		src/os/unix/ngx_errno.c


objs/src/os/unix/ngx_alloc.o:	$(CORE_DEPS) \
	src/os/unix/ngx_alloc.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_alloc.o \
		src/os/unix/ngx_alloc.c


objs/src/os/unix/ngx_files.o:	$(CORE_DEPS) \
	src/os/unix/ngx_files.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_files.o \
		src/os/unix/ngx_files.c


objs/src/os/unix/ngx_socket.o:	$(CORE_DEPS) \
	src/os/unix/ngx_socket.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_socket.o \
		src/os/unix/ngx_socket.c


objs/src/os/unix/ngx_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_recv.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_recv.o \
		src/os/unix/ngx_recv.c


objs/src/os/unix/ngx_readv_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_readv_chain.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_readv_chain.o \
		src/os/unix/ngx_readv_chain.c


objs/src/os/unix/ngx_udp_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_recv.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_recv.o \
		src/os/unix/ngx_udp_recv.c


objs/src/os/unix/ngx_send.o:	$(CORE_DEPS) \
	src/os/unix/ngx_send.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_send.o \
		src/os/unix/ngx_send.c


objs/src/os/unix/ngx_writev_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_writev_chain.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_writev_chain.o \
		src/os/unix/ngx_writev_chain.c


objs/src/os/unix/ngx_channel.o:	$(CORE_DEPS) \
	src/os/unix/ngx_channel.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_channel.o \
		src/os/unix/ngx_channel.c


objs/src/os/unix/ngx_shmem.o:	$(CORE_DEPS) \
	src/os/unix/ngx_shmem.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_shmem.o \
		src/os/unix/ngx_shmem.c


objs/src/os/unix/ngx_process.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process.o \
		src/os/unix/ngx_process.c


objs/src/os/unix/ngx_daemon.o:	$(CORE_DEPS) \
	src/os/unix/ngx_daemon.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_daemon.o \
		src/os/unix/ngx_daemon.c


objs/src/os/unix/ngx_setaffinity.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setaffinity.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setaffinity.o \
		src/os/unix/ngx_setaffinity.c


objs/src/os/unix/ngx_setproctitle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setproctitle.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setproctitle.o \
		src/os/unix/ngx_setproctitle.c


objs/src/os/unix/ngx_posix_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_posix_init.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_posix_init.o \
		src/os/unix/ngx_posix_init.c


objs/src/os/unix/ngx_user.o:	$(CORE_DEPS) \
	src/os/unix/ngx_user.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_user.o \
		src/os/unix/ngx_user.c


objs/src/os/unix/ngx_process_cycle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process_cycle.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process_cycle.o \
		src/os/unix/ngx_process_cycle.c


objs/src/os/unix/ngx_linux_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_init.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_init.o \
		src/os/unix/ngx_linux_init.c


objs/src/event/modules/ngx_epoll_module.o:	$(CORE_DEPS) \
	src/event/modules/ngx_epoll_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/modules/ngx_epoll_module.o \
		src/event/modules/ngx_epoll_module.c


objs/src/os/unix/ngx_linux_sendfile_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_sendfile_chain.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_sendfile_chain.o \
		src/os/unix/ngx_linux_sendfile_chain.c


objs/src/event/ngx_event_openssl.o:	$(CORE_DEPS) \
	src/event/ngx_event_openssl.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_openssl.o \
		src/event/ngx_event_openssl.c


objs/src/core/ngx_regex.o:	$(CORE_DEPS) \
	src/core/ngx_regex.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_regex.o \
		src/core/ngx_regex.c


objs/src/http/ngx_http.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http.o \
		src/http/ngx_http.c


objs/src/http/ngx_http_core_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_core_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_core_module.o \
		src/http/ngx_http_core_module.c


objs/src/http/ngx_http_special_response.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_special_response.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_special_response.o \
		src/http/ngx_http_special_response.c


objs/src/http/ngx_http_request.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request.o \
		src/http/ngx_http_request.c


objs/src/http/ngx_http_parse.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_parse.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_parse.o \
		src/http/ngx_http_parse.c


objs/src/http/ngx_http_header_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_header_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_header_filter_module.o \
		src/http/ngx_http_header_filter_module.c


objs/src/http/ngx_http_write_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_write_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_write_filter_module.o \
		src/http/ngx_http_write_filter_module.c


objs/src/http/ngx_http_copy_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_copy_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_copy_filter_module.o \
		src/http/ngx_http_copy_filter_module.c


objs/src/http/modules/ngx_http_log_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_log_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_log_module.o \
		src/http/modules/ngx_http_log_module.c


objs/src/http/ngx_http_request_body.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request_body.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request_body.o \
		src/http/ngx_http_request_body.c


objs/src/http/ngx_http_variables.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_variables.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_variables.o \
		src/http/ngx_http_variables.c


objs/src/http/ngx_http_script.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_script.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_script.o \
		src/http/ngx_http_script.c


objs/src/http/ngx_http_upstream.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream.o \
		src/http/ngx_http_upstream.c


objs/src/http/ngx_http_upstream_round_robin.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream_round_robin.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream_round_robin.o \
		src/http/ngx_http_upstream_round_robin.c


objs/src/http/ngx_http_parse_time.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_parse_time.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_parse_time.o \
		src/http/ngx_http_parse_time.c


objs/src/http/modules/ngx_http_static_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_static_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_static_module.o \
		src/http/modules/ngx_http_static_module.c


objs/src/http/modules/ngx_http_index_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_index_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_index_module.o \
		src/http/modules/ngx_http_index_module.c


objs/src/http/modules/ngx_http_chunked_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_chunked_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_chunked_filter_module.o \
		src/http/modules/ngx_http_chunked_filter_module.c


objs/src/http/modules/ngx_http_range_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_range_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_range_filter_module.o \
		src/http/modules/ngx_http_range_filter_module.c


objs/src/http/modules/ngx_http_headers_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_headers_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_headers_filter_module.o \
		src/http/modules/ngx_http_headers_filter_module.c


objs/src/http/modules/ngx_http_not_modified_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_not_modified_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_not_modified_filter_module.o \
		src/http/modules/ngx_http_not_modified_filter_module.c


objs/src/http/ngx_http_busy_lock.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_busy_lock.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_busy_lock.o \
		src/http/ngx_http_busy_lock.c


objs/src/http/ngx_http_file_cache.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_file_cache.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_file_cache.o \
		src/http/ngx_http_file_cache.c


objs/src/http/modules/ngx_http_gzip_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gzip_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gzip_filter_module.o \
		src/http/modules/ngx_http_gzip_filter_module.c


objs/src/http/modules/ngx_http_charset_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_charset_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_charset_filter_module.o \
		src/http/modules/ngx_http_charset_filter_module.c


objs/src/http/modules/ngx_http_userid_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_userid_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_userid_filter_module.o \
		src/http/modules/ngx_http_userid_filter_module.c


objs/src/http/modules/ngx_http_preload_cache_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_preload_cache_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_preload_cache_module.o \
		src/http/modules/ngx_http_preload_cache_module.c


objs/src/http/modules/ngx_http_preload_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_preload_filter_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_preload_filter_module.o \
		src/http/modules/ngx_http_preload_filter_module.c


objs/src/http/modules/ngx_http_autoindex_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_autoindex_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_autoindex_module.o \
		src/http/modules/ngx_http_autoindex_module.c


objs/src/http/modules/ngx_http_auth_basic_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_auth_basic_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_auth_basic_module.o \
		src/http/modules/ngx_http_auth_basic_module.c


objs/src/http/modules/ngx_http_access_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_access_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_access_module.o \
		src/http/modules/ngx_http_access_module.c


objs/src/http/modules/ngx_http_limit_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_conn_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_conn_module.o \
		src/http/modules/ngx_http_limit_conn_module.c


objs/src/http/modules/ngx_http_limit_req_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_req_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_req_module.o \
		src/http/modules/ngx_http_limit_req_module.c


objs/src/http/modules/ngx_http_split_clients_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_split_clients_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_split_clients_module.o \
		src/http/modules/ngx_http_split_clients_module.c


objs/src/http/modules/ngx_http_referer_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_referer_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_referer_module.o \
		src/http/modules/ngx_http_referer_module.c


objs/src/http/modules/ngx_http_rewrite_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_rewrite_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_rewrite_module.o \
		src/http/modules/ngx_http_rewrite_module.c


objs/src/http/modules/ngx_http_proxy_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_proxy_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_proxy_module.o \
		src/http/modules/ngx_http_proxy_module.c


objs/src/http/modules/ngx_http_fastcgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_fastcgi_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_fastcgi_module.o \
		src/http/modules/ngx_http_fastcgi_module.c


objs/src/http/modules/ngx_http_empty_gif_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_empty_gif_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_empty_gif_module.o \
		src/http/modules/ngx_http_empty_gif_module.c


objs/src/http/modules/ngx_http_browser_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_browser_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_browser_module.o \
		src/http/modules/ngx_http_browser_module.c


objs/src/http/modules/ngx_http_upstream_ip_hash_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_ip_hash_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
		src/http/modules/ngx_http_upstream_ip_hash_module.c


objs/src/http/modules/ngx_http_upstream_least_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_least_conn_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
		src/http/modules/ngx_http_upstream_least_conn_module.c


objs/src/http/modules/ngx_http_upstream_keepalive_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_keepalive_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
		src/http/modules/ngx_http_upstream_keepalive_module.c


objs/src/http/modules/ngx_http_stub_status_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_stub_status_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_stub_status_module.o \
		src/http/modules/ngx_http_stub_status_module.c


objs/addon/tcp/ngx_tcp.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp.o \
		src/tcp/ngx_tcp.c


objs/addon/tcp/ngx_tcp_core_module.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_core_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_core_module.o \
		src/tcp/ngx_tcp_core_module.c


objs/addon/tcp/ngx_tcp_session.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_session.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_session.o \
		src/tcp/ngx_tcp_session.c


objs/addon/tcp/ngx_tcp_access.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_access.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_access.o \
		src/tcp/ngx_tcp_access.c


objs/addon/tcp/ngx_tcp_log.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_log.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_log.o \
		src/tcp/ngx_tcp_log.c


objs/addon/tcp/ngx_tcp_upstream.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_upstream.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_upstream.o \
		src/tcp/ngx_tcp_upstream.c


objs/addon/tcp/ngx_tcp_upstream_round_robin.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_upstream_round_robin.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_upstream_round_robin.o \
		src/tcp/ngx_tcp_upstream_round_robin.c


objs/addon/modules/ngx_tcp_generic_proxy_module.o:	$(ADDON_DEPS) \
	src/tcp/modules/ngx_tcp_generic_proxy_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/modules/ngx_tcp_generic_proxy_module.o \
		src/tcp/modules/ngx_tcp_generic_proxy_module.c


objs/addon/modules/ngx_tcp_websocket_proxy_module.o:	$(ADDON_DEPS) \
	src/tcp/modules/ngx_tcp_websocket_proxy_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/modules/ngx_tcp_websocket_proxy_module.o \
		src/tcp/modules/ngx_tcp_websocket_proxy_module.c


objs/addon/modules/ngx_tcp_upstream_ip_hash_module.o:	$(ADDON_DEPS) \
	src/tcp/modules/ngx_tcp_upstream_ip_hash_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/modules/ngx_tcp_upstream_ip_hash_module.o \
		src/tcp/modules/ngx_tcp_upstream_ip_hash_module.c


objs/addon/modules/ngx_tcp_upstream_busyness_module.o:	$(ADDON_DEPS) \
	src/tcp/modules/ngx_tcp_upstream_busyness_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/modules/ngx_tcp_upstream_busyness_module.o \
		src/tcp/modules/ngx_tcp_upstream_busyness_module.c


objs/addon/tcp/ngx_tcp_upstream_check.o:	$(ADDON_DEPS) \
	src/tcp/ngx_tcp_upstream_check.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/tcp/ngx_tcp_upstream_check.o \
		src/tcp/ngx_tcp_upstream_check.c


objs/addon/parsers/http_request_parser.o:	$(ADDON_DEPS) \
	src/tcp/parsers/http_request_parser.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/parsers/http_request_parser.o \
		src/tcp/parsers/http_request_parser.c


objs/addon/parsers/http_response_parser.o:	$(ADDON_DEPS) \
	src/tcp/parsers/http_response_parser.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/parsers/http_response_parser.o \
		src/tcp/parsers/http_response_parser.c


objs/addon/parsers/smtp_response_parser.o:	$(ADDON_DEPS) \
	src/tcp/parsers/smtp_response_parser.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/parsers/smtp_response_parser.o \
		src/tcp/parsers/smtp_response_parser.c


objs/addon/modules/ngx_tcp_ssl_module.o:	$(ADDON_DEPS) \
	src/tcp/modules/ngx_tcp_ssl_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/modules/ngx_tcp_ssl_module.o \
		src/tcp/modules/ngx_tcp_ssl_module.c


objs/addon/handoff/ngx_handoff.o:	$(ADDON_DEPS) \
	src/handoff/ngx_handoff.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/handoff/ngx_handoff.o \
		src/handoff/ngx_handoff.c


objs/addon/handoff/ngx_handoff_core_module.o:	$(ADDON_DEPS) \
	src/handoff/ngx_handoff_core_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/handoff/ngx_handoff_core_module.o \
		src/handoff/ngx_handoff_core_module.c


objs/addon/handoff/ngx_handoff_log.o:	$(ADDON_DEPS) \
	src/handoff/ngx_handoff_log.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/handoff/ngx_handoff_log.o \
		src/handoff/ngx_handoff_log.c


objs/addon/handoff/ngx_handoff_session.o:	$(ADDON_DEPS) \
	src/handoff/ngx_handoff_session.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/handoff/ngx_handoff_session.o \
		src/handoff/ngx_handoff_session.c


objs/addon/filter/ngx_filter.o:	$(ADDON_DEPS) \
	src/filter/ngx_filter.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/filter/ngx_filter.o \
		src/filter/ngx_filter.c


objs/addon/filter/ngx_filter_core_module.o:	$(ADDON_DEPS) \
	src/filter/ngx_filter_core_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/filter/ngx_filter_core_module.o \
		src/filter/ngx_filter_core_module.c


objs/addon/filter/ngx_filter_log.o:	$(ADDON_DEPS) \
	src/filter/ngx_filter_log.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/filter/ngx_filter_log.o \
		src/filter/ngx_filter_log.c


objs/addon/filter/ngx_filter_session.o:	$(ADDON_DEPS) \
	src/filter/ngx_filter_session.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/filter/ngx_filter_session.o \
		src/filter/ngx_filter_session.c


objs/addon/src/ndk.o:	$(ADDON_DEPS) \
	src/lua/ngx_devel_kit/src/ndk.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ndk.o \
		src/lua/ngx_devel_kit/src/ndk.c


objs/addon/src/ngx_http_lua_script.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_script.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_script.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_script.c


objs/addon/src/ngx_http_lua_log.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_log.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_log.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_log.c


objs/addon/src/ngx_http_lua_subrequest.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_subrequest.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_subrequest.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_subrequest.c


objs/addon/src/ngx_http_lua_ndk.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_ndk.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ndk.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_ndk.c


objs/addon/src/ngx_http_lua_control.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_control.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_control.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_control.c


objs/addon/src/ngx_http_lua_time.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_time.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_time.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_time.c


objs/addon/src/ngx_http_lua_misc.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_misc.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_misc.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_misc.c


objs/addon/src/ngx_http_lua_variable.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_variable.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_variable.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_variable.c


objs/addon/src/ngx_http_lua_string.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_string.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_string.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_string.c


objs/addon/src/ngx_http_lua_output.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_output.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_output.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_output.c


objs/addon/src/ngx_http_lua_headers.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_headers.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_headers.c


objs/addon/src/ngx_http_lua_req_body.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_req_body.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_req_body.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_req_body.c


objs/addon/src/ngx_http_lua_uri.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_uri.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_uri.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_uri.c


objs/addon/src/ngx_http_lua_args.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_args.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_args.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_args.c


objs/addon/src/ngx_http_lua_ctx.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_ctx.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ctx.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_ctx.c


objs/addon/src/ngx_http_lua_regex.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_regex.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_regex.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_regex.c


objs/addon/src/ngx_http_lua_module.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_module.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_module.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_module.c


objs/addon/src/ngx_http_lua_headers_out.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_headers_out.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers_out.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_headers_out.c


objs/addon/src/ngx_http_lua_headers_in.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_headers_in.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers_in.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_headers_in.c


objs/addon/src/ngx_http_lua_directive.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_directive.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_directive.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_directive.c


objs/addon/src/ngx_http_lua_consts.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_consts.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_consts.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_consts.c


objs/addon/src/ngx_http_lua_exception.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_exception.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_exception.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_exception.c


objs/addon/src/ngx_http_lua_util.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_util.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_util.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_util.c


objs/addon/src/ngx_http_lua_cache.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_cache.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_cache.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_cache.c


objs/addon/src/ngx_http_lua_contentby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_contentby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_contentby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_contentby.c


objs/addon/src/ngx_http_lua_rewriteby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_rewriteby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_rewriteby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_rewriteby.c


objs/addon/src/ngx_http_lua_accessby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_accessby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_accessby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_accessby.c


objs/addon/src/ngx_http_lua_setby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_setby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_setby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_setby.c


objs/addon/src/ngx_http_lua_capturefilter.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_capturefilter.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_capturefilter.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_capturefilter.c


objs/addon/src/ngx_http_lua_clfactory.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_clfactory.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_clfactory.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_clfactory.c


objs/addon/src/ngx_http_lua_pcrefix.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_pcrefix.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_pcrefix.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_pcrefix.c


objs/addon/src/ngx_http_lua_headerfilterby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_headerfilterby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headerfilterby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_headerfilterby.c


objs/addon/src/ngx_http_lua_shdict.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_shdict.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_shdict.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_shdict.c


objs/addon/src/ngx_http_lua_socket_tcp.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_socket_tcp.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_socket_tcp.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_socket_tcp.c


objs/addon/src/ngx_http_lua_api.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_api.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_api.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_api.c


objs/addon/src/ngx_http_lua_logby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_logby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_logby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_logby.c


objs/addon/src/ngx_http_lua_sleep.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_sleep.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_sleep.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_sleep.c


objs/addon/src/ngx_http_lua_coroutine.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_coroutine.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_coroutine.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_coroutine.c


objs/addon/src/ngx_http_lua_bodyfilterby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_bodyfilterby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_bodyfilterby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_bodyfilterby.c


objs/addon/src/ngx_http_lua_initby.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_initby.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_initby.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_initby.c


objs/addon/src/ngx_http_lua_socket_udp.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_socket_udp.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_socket_udp.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_socket_udp.c


objs/addon/src/ngx_http_lua_req_method.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_req_method.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_req_method.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_req_method.c


objs/addon/src/ngx_http_lua_phase.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_phase.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_phase.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_phase.c


objs/addon/src/ngx_http_lua_uthread.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_uthread.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_uthread.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_uthread.c


objs/addon/src/ngx_http_lua_timer.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_timer.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_timer.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_timer.c


objs/addon/src/ngx_http_lua_config.o:	$(ADDON_DEPS) \
	src/lua/lua-nginx-module/src/ngx_http_lua_config.c
	$(CC) -c -gdwarf-4  $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_config.o \
		src/lua/lua-nginx-module/src/ngx_http_lua_config.c


manpage:	objs/nginx.8

objs/nginx.8:	man/nginx.8 objs/ngx_auto_config.h
	sed -e "s|%%PREFIX%%|/usr/local/nginx|" \
		-e "s|%%PID_PATH%%|/usr/local/nginx/logs/nginx.pid|" \
		-e "s|%%CONF_PATH%%|/usr/local/nginx/conf/nginx.conf|" \
		-e "s|%%ERROR_LOG_PATH%%|/usr/local/nginx/logs/error.log|" \
		< man/nginx.8 > $@

install:	objs/nginx 		
	test -d '$(DESTDIR)/usr/local/nginx' || mkdir -p '$(DESTDIR)/usr/local/nginx'

	test -d '$(DESTDIR)/usr/local/nginx/sbin' 		|| mkdir -p '$(DESTDIR)/usr/local/nginx/sbin'
	test ! -f '$(DESTDIR)/usr/local/nginx/sbin/nginx' 		|| mv '$(DESTDIR)/usr/local/nginx/sbin/nginx' 			'$(DESTDIR)/usr/local/nginx/sbin/nginx.old'
	cp objs/nginx '$(DESTDIR)/usr/local/nginx/sbin/nginx'

	test -d '$(DESTDIR)/usr/local/nginx/conf' 		|| mkdir -p '$(DESTDIR)/usr/local/nginx/conf'

	cp conf/koi-win '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/koi-utf '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/win-utf '$(DESTDIR)/usr/local/nginx/conf'

	test -f '$(DESTDIR)/usr/local/nginx/conf/mime.types' 		|| cp conf/mime.types '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/mime.types '$(DESTDIR)/usr/local/nginx/conf/mime.types.default'

	test -f '$(DESTDIR)/usr/local/nginx/conf/fastcgi_params' 		|| cp conf/fastcgi_params '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/fastcgi_params 		'$(DESTDIR)/usr/local/nginx/conf/fastcgi_params.default'

	test -f '$(DESTDIR)/usr/local/nginx/conf/fastcgi.conf' 		|| cp conf/fastcgi.conf '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/fastcgi.conf '$(DESTDIR)/usr/local/nginx/conf/fastcgi.conf.default'

	test -f '$(DESTDIR)/usr/local/nginx/conf/uwsgi_params' 		|| cp conf/uwsgi_params '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/uwsgi_params 		'$(DESTDIR)/usr/local/nginx/conf/uwsgi_params.default'

	test -f '$(DESTDIR)/usr/local/nginx/conf/scgi_params' 		|| cp conf/scgi_params '$(DESTDIR)/usr/local/nginx/conf'
	cp conf/scgi_params 		'$(DESTDIR)/usr/local/nginx/conf/scgi_params.default'

	test -f '$(DESTDIR)/usr/local/nginx/conf/nginx.conf' 		|| cp conf/nginx.conf '$(DESTDIR)/usr/local/nginx/conf/nginx.conf'
	cp conf/nginx.conf '$(DESTDIR)/usr/local/nginx/conf/nginx.conf.default'

	test -d '$(DESTDIR)/usr/local/nginx/logs' 		|| mkdir -p '$(DESTDIR)/usr/local/nginx/logs'

	test -d '$(DESTDIR)/usr/local/nginx/logs' || 		mkdir -p '$(DESTDIR)/usr/local/nginx/logs'

	test -d '$(DESTDIR)/usr/local/nginx/html' 		|| cp -R html '$(DESTDIR)/usr/local/nginx'

	test -d '$(DESTDIR)/usr/local/nginx/logs' || 		mkdir -p '$(DESTDIR)/usr/local/nginx/logs'
