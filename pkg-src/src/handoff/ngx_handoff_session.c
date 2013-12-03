/*
 * author : yubo@xiaomi.com
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_handoff.h>


static void ngx_handoff_init_session_connection(ngx_connection_t *c);
static void ngx_handoff_init_session(ngx_handoff_session_t *s);
static void ngx_handoff_write_handler(ngx_event_t *wev);
static void ngx_handoff_read_handler(ngx_event_t *rev);
static void ngx_handoff_redirect_to(ngx_event_t *rev, ngx_listening_t *ls);
static int ngx_handoff_redirect_regex(ngx_connection_t *c, ngx_listening_t **lsp);
static int ngx_handoff_redirect_parse(ngx_connection_t *c, ngx_listening_t **lsp);




#if (NGX_HANDOFF_SSL)
static void ngx_handoff_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_handoff_ssl_handshake_handler(ngx_connection_t *c);
#endif


static uint32_t  usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
#if (NGX_WIN32)
    0xefffffff, /* 1110 1111 1111 1111  1111 1111 1111 1111 */
#else
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
#endif

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)


#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && m[4] == c4

#else /* !(NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED) */

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#endif




void
ngx_handoff_init_connection(ngx_connection_t *c)
{
    ngx_uint_t            i;
    ngx_handoff_port_t       *port;
    struct sockaddr      *sa;
    struct sockaddr_in   *sin;
    ngx_handoff_log_ctx_t    *ctx;
    ngx_handoff_in_addr_t    *addr;
    ngx_handoff_session_t    *s;
    ngx_handoff_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    ngx_handoff_in6_addr_t   *addr6;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_handoff_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_handoff_session_t));
    if (s == NULL) {
        ngx_handoff_close_connection(c);
        return;
    }

    if (addr_conf->default_ctx) {
        s->main_conf = addr_conf->default_ctx->main_conf;
        s->srv_conf = addr_conf->default_ctx->srv_conf;
    }
    else {
        s->main_conf = addr_conf->ctx->main_conf;
        s->srv_conf = addr_conf->ctx->srv_conf;
    }

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_handoff_log_ctx_t));
    if (ctx == NULL) {
        ngx_handoff_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_handoff_log_error;
    c->log->data = ctx;
    c->log->action = "nginx tcp module init connection";

    c->log_error = NGX_ERROR_INFO;


    ngx_handoff_init_session_connection(c);
}





static void
ngx_handoff_init_session_connection(ngx_connection_t *c)
{
    ngx_time_t               *tp;
    ngx_handoff_session_t        *s;
    ngx_handoff_core_srv_conf_t  *cscf;

    s = c->data;

    s->signature = NGX_HANDOFF_MODULE;
    s->pool = c->pool;

    cscf = ngx_handoff_get_module_srv_conf(s, ngx_handoff_core_module);
    if (cscf == NULL) {
        ngx_handoff_finalize_session(s);
        return;
    }

    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_handoff_max_module);
    if (s->ctx == NULL) {
        ngx_handoff_finalize_session(s);
        return;
    }

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    s->bytes_read = 0;
    s->bytes_write = 0;
    ngx_handoff_init_session(s);
}






static void
ngx_handoff_init_session(ngx_handoff_session_t *s)
{
    ngx_connection_t             *c;
    ngx_handoff_core_srv_conf_t  *cscf;

	c = s->connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HANDOFF, c->log, 0, "handoff init session");

	cscf = ngx_handoff_get_module_srv_conf(s, ngx_handoff_core_module);

    s->buffer = ngx_create_temp_buf(s->connection->pool, cscf->buffer_size);
    if (s->buffer == NULL) {
		ngx_handoff_close_connection(c);
        return;
    }

	s->out.len = 0;

	c->write->handler = ngx_handoff_write_handler;
	c->read->handler = ngx_handoff_read_handler;

	//timeout handle ?
	ngx_add_timer(c->read, cscf->timeout);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
#if (NGX_STAT_STUB)
		(void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
		ngx_handoff_close_connection(c);
		return;
	}
	return;


}


static void
ngx_handoff_write_handler(ngx_event_t *wev)
{
    ngx_connection_t    *c;

    c = wev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, wev->log, 0,
                   "handoff dummy write handler: %d", c->fd);

	return;
}

static void
ngx_handoff_read_handler(ngx_event_t *rev)
{
    ngx_connection_t    *c;
	int                 ret;
	ngx_handoff_core_srv_conf_t  *cscf;
	ngx_listening_t     *ls;

    c = rev->data;
	cscf = ngx_handoff_get_module_srv_conf((ngx_handoff_session_t *)c->data, ngx_handoff_core_module);
	ngx_event_add_timer(rev, cscf->timeout);


    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, rev->log, 0,
                   "handoff dummy read handler: %d", c->fd);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out redirect to default");
        ngx_handoff_redirect_to(rev, cscf->default_ls);

        return;
    }

	//ret = ngx_handoff_redirect_regex(c, &ls);
	ret = ngx_handoff_redirect_parse(c, &ls);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
#if (NGX_STAT_STUB)
		(void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
		ngx_handoff_close_connection(c);
		return;
	}


	switch (ret) {
		case NGX_ERROR:
			ngx_handoff_close_connection(c);
            break;
		case NGX_REDIRECT_TO_PRELOAD:
			ngx_handoff_redirect_to(rev, cscf->preload_ls);
			break;
		case NGX_REDIRECT_TO_DEFAULT:
			ngx_handoff_redirect_to(rev, cscf->default_ls);
			break;
		default: // NGX_REDIRECT_PASS
		    break;
	}
	return;

}


typedef struct {
    u_char                           color;
    u_char                           dummy;
    u_short                          url_len;
    u_short                          path_len;
    u_short                          disposition_len;
    ngx_int_t                        code;
    time_t                           start;
    time_t                           expires;
    u_char                           data[1];
} ngx_http_preload_cache_node_t;

typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    time_t                           ts;
} ngx_http_preload_cache_shctx_t;


typedef struct {
    ngx_http_preload_cache_shctx_t   *sh;
    ngx_slab_pool_t                  *shpool;
} ngx_http_preload_cache_ctx_t;


typedef struct {
    ngx_shm_zone_t                   *shm_zone;
} ngx_http_preload_cache_conf_t;


static ngx_http_preload_cache_node_t *
ngx_http_preload_cache_lookup(ngx_shm_zone_t *shm_zone,
                              ngx_str_t *url)
{
    ngx_int_t                      rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_preload_cache_ctx_t   *ctx;
    ngx_http_preload_cache_node_t  *pc = NULL, *rcpc = NULL;
    ngx_uint_t hash = ngx_crc32_short(url->data, url->len);

    if (shm_zone == NULL){
        return NULL;
    }

    ctx = shm_zone->data;
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;
    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        // hash == node->key

        pc = (ngx_http_preload_cache_node_t *) &node->color;

        rc = ngx_memn2cmp(url->data, pc->data, url->len, (size_t) pc->url_len);

        if (rc == 0) {
            rcpc = pc;
            break;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return rcpc;
}



static int
	ngx_handoff_uri_lookup(u_char *uri, ngx_uint_t ul)
{
	return 1;
}


static ngx_http_preload_cache_node_t *
	ngx_handoff_host_uri_lookup(ngx_connection_t *c, u_char *host, ngx_uint_t hl, u_char *uri, ngx_uint_t ul)
{
    ngx_handoff_session_t   *s;
	ngx_handoff_core_srv_conf_t  *cscf;

	ngx_http_preload_cache_node_t *node;
	ngx_str_t* url = ngx_pcalloc(c->pool, sizeof(ngx_str_t));

    s = c->data;
	cscf = ngx_handoff_get_module_srv_conf(s, ngx_handoff_core_module);


	url->len = hl+ul;
	url->data = ngx_pcalloc(c->pool, url->len);
	ngx_memcpy(url->data, host, hl);
	ngx_memcpy(url->data + hl, uri, ul);


    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, c->log, 0,
			   "ngx_handoff_host_uri_lookup(): %V", url);

	//ngx_http_preload_cache_ctx_t	*ctx;
	//ctx = re[i].preload_shm_zone->data;
	//ngx_shmtx_lock(&ctx->shpool->mutex);
	node = ngx_http_preload_cache_lookup(cscf->preload_shm_zone, url);
	//ngx_shmtx_unlock(&ctx->shpool->mutex);

	return node;
}



//GET http://www.w3.org/index.html HTTP/1.0
//GET /index.html HTTP/1.0
static int ngx_handoff_redirect_parse(ngx_connection_t *con, ngx_listening_t **lsp)
{
    ngx_handoff_session_t   *s;
	ngx_handoff_core_srv_conf_t  *cscf;
	ngx_uint_t                  i;
    ssize_t                     n;
    ngx_int_t                   ret;
	ngx_err_t            err;
	u_char                 buf[NGX_BUF_SIZE];
    //ngx_handoff_regex_elt_t  *re;
	ngx_handoff_request_t *r;
    u_char  c, ch, *p, *m;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_host_http_09,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_check_uri_http_09,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done,
        sw_header_start,
        sw_header_key,
        sw_header_spaces_before_value,
        sw_header_in_value
    } state;



    s = con->data;
	cscf = ngx_handoff_get_module_srv_conf(s, ngx_handoff_core_module);
	r = &s->request;
	state = r->state;

	n = recv(con->fd, buf, NGX_BUF_SIZE, MSG_PEEK);
	err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HANDOFF, con->log, 0,
			   "handoff check recv(): [%d](%s)", n, buf);
	if (n > 0) {

		ret = NGX_REGEX_NO_MATCHED;


		for (p = buf + r->last; p < buf + n; p++) {
			ch = *p;
			ngx_log_debug3(NGX_LOG_DEBUG_HANDOFF, con->log, 0,
			   "state[%d] ch[%d:%c]", state, ch, ch);

			switch(state) {


			case sw_start:
				r->request_start = p - buf;

	            if (ch == CR || ch == LF) {
	                break;
	            }

				if ((ch < 'A' || ch > 'Z') && ch != '_') {
					return NGX_REDIRECT_TO_DEFAULT;
				}
				state = sw_method;
				break;

			case sw_method:
				if (ch == ' ') {
					r->method_end = p - 1 - buf;
					m = buf + r->request_start;

					switch (p - m) {
					case 3:
						if (ngx_str3_cmp(m, 'G', 'E', 'T', ' ')) {
							/*r->method = NGX_HTTP_GET;*/
							break;
						}
						break;
					case 4:
                        if (ngx_str4cmp(m, 'H', 'E', 'A', 'D')) {
                            /* r->method = NGX_HTTP_HEAD; */
                            break;
                        }
						break;
					default:
						return NGX_REDIRECT_TO_DEFAULT;
					}

					state = sw_spaces_before_uri;
					break;
				}
				if (((ch < 'A' || ch > 'Z') && ch != '_')
					|| (p - buf - r->request_start > 4)) {
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;


			/* space* before URI */
			case sw_spaces_before_uri:

				if (ch == '/') {
					r->uri_start = p - buf;
					state = sw_after_slash_in_uri;
					break;
				}

				c = (u_char) (ch | 0x20);
				if (c >= 'a' && c <= 'z') {
					r->schema_start = p - buf;
					state = sw_schema;
					break;
				}

				switch (ch) {
				case ' ':
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;


			case sw_schema:
				c = (u_char) (ch | 0x20);
				if (c >= 'a' && c <= 'z') {
					break;
				}
				switch (ch) {
				case ':':
					r->schema_end = p - buf;
					state = sw_schema_slash;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			case sw_schema_slash:
				switch (ch) {
				case '/':
					state = sw_schema_slash_slash;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			case sw_schema_slash_slash:
				switch (ch) {
				case '/':
					state = sw_host_start;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			case sw_host_start:
				r->host_start = p - buf;
				if (ch == '[') {
					state = sw_host_ip_literal;
					break;
				}
				state = sw_host;


			case sw_host_end:

				r->host_end = p - buf;

				switch (ch) {
				case ':':
					state = sw_port;
					break;
				case '/':
					r->uri_start = p - buf;
					state = sw_after_slash_in_uri;
					break;
				case ' ':
					/*
					 * use single "/" from request line to preserve pointers,
					 * if request line will be copied to large client buffer
					 */
					r->uri_start = r->schema_end + 1;
					r->uri_end = r->schema_end + 2;
					state = sw_host_http_09;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

        case sw_host_ip_literal:

            if (ch >= '0' && ch <= '9') {
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return NGX_REDIRECT_TO_DEFAULT;
            }
            break;


			case sw_port:
				if (ch >= '0' && ch <= '9') {
					break;
				}

				switch (ch) {
				case '/':
					r->port_end = p - buf;
					r->uri_start = p - buf;
					state = sw_after_slash_in_uri;
					break;
				case ' ':
					r->port_end = p - buf;
					/*
					 * use single "/" from request line to preserve pointers,
					 * if request line will be copied to large client buffer
					 */
					r->uri_start = r->schema_end + 1;
					r->uri_end = r->schema_end + 2;
					state = sw_host_http_09;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			/* space+ after "http://host[:port] " */
			case sw_host_http_09:
				switch (ch) {
				case ' ':
					break;
				case CR:
					/* r->http_minor = 9; */
					state = sw_almost_done;
					break;
				case LF:
					/* r->http_minor = 9;*/
					state = sw_header_start;
					break;
				case 'H':
					/* r->http_protocol.data = p; */
					state = sw_http_H;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;



			/* check "/.", "//", "%", and "\" (Win32) in URI */
			case sw_after_slash_in_uri:

				if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
					state = sw_check_uri;
					break;
				}

				switch (ch) {
				case ' ':
					r->uri_end = p - buf;
					state = sw_check_uri_http_09;
					break;
				case CR:
					r->uri_end = p - buf;
					/* r->http_minor = 9; */
					state = sw_almost_done;
					break;
				case LF:
					r->uri_end = p - buf;
					/* r->http_minor = 9; */
					state = sw_header_start;
					break;
				case '.':
					/* r->complex_uri = 1; */
					state = sw_uri;
					break;
				case '%':
					/* r->quoted_uri = 1; */
					state = sw_uri;
					break;
				case '/':
					/* r->complex_uri = 1; */
					state = sw_uri;
					break;
#if (NGX_WIN32)
				case '\\':
					/* r->complex_uri = 1; */
					state = sw_uri;
					break;
#endif
				case '?':
					/* r->args_start = p + 1 - buf; */
					state = sw_uri;
					break;
				case '#':
					/* r->complex_uri = 1; */
					state = sw_uri;
					break;
				case '+':
					/* r->plus_in_uri = 1; */
					break;
				case '\0':
					return NGX_REDIRECT_TO_DEFAULT;
				default:
					state = sw_check_uri;
					break;
				}
				break;

			/* check "/", "%" and "\" (Win32) in URI */
			case sw_check_uri:

				if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
					break;
				}

				switch (ch) {
				case '/':
#if (NGX_WIN32)
					if (r->uri_ext == p) {
						r->complex_uri = 1;
						state = sw_uri;
						break;
					}
#endif
					/* r->uri_ext = NULL; */
					state = sw_after_slash_in_uri;
					break;
				case '.':
					/* r->uri_ext = p + 1; */
					break;
				case ' ':
					r->uri_end = p - buf;
					state = sw_check_uri_http_09;
					break;
				case CR:
					r->uri_end = p - buf;
					/* r->http_minor = 9;*/
					state = sw_almost_done;
					break;
				case LF:
					r->uri_end = p - buf;
					/* r->http_minor = 9; */
					state = sw_header_start;
					break;
#if (NGX_WIN32)
				case '\\':
					/* r->complex_uri = 1; */
					state = sw_after_slash_in_uri;
					break;
#endif
				case '%':
					/* r->quoted_uri = 1; */
					state = sw_uri;
					break;
				case '?':
					/* r->args_start = p + 1; */
					state = sw_uri;
					break;
				case '#':
					/* r->complex_uri = 1; */
					state = sw_uri;
					break;
				case '+':
					/* r->plus_in_uri = 1; */
					break;
				case '\0':
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			/* space+ after URI */
			case sw_check_uri_http_09:
				switch (ch) {
				case ' ':
					break;
				case CR:
					/* r->http_minor = 9;*/
					state = sw_almost_done;
					break;
				case LF:
					/* r->http_minor = 9;*/
					state = sw_header_start;
					break;
				case 'H':
					/* r->http_protocol.data = p; */
					state = sw_http_H;
					break;
				default:
					/* r->space_in_uri = 1; */
					state = sw_check_uri;
					break;
				}
				break;

			/* URI */
			case sw_uri:

				if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
					break;
				}

				switch (ch) {
				case ' ':
					r->uri_end = p - buf;
					state = sw_http_09;
					break;
				case CR:
					r->uri_end = p - buf;
					/* r->http_minor = 9; */
					state = sw_almost_done;
					break;
				case LF:
					r->uri_end = p - buf;
					/* r->http_minor = 9; */
					state = sw_header_start;
					break;
				case '#':
					/* r->complex_uri = 1; */
					break;
				case '\0':
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;

			/* space+ after URI */
			case sw_http_09:
				switch (ch) {
				case ' ':
					break;
				case CR:
					/* r->http_minor = 9; */
					state = sw_almost_done;
					break;
				case LF:
					/* r->http_minor = 9;*/
					state = sw_header_start;
					break;
				case 'H':
					/* r->http_protocol.data = p;*/
					state = sw_http_H;
					break;
				default:
					/* r->space_in_uri = 1;*/
					state = sw_uri;
					break;
				}
				break;

			case sw_http_H:
				switch (ch) {
				case CR:
					state = sw_almost_done;
					break;
				case LF:
					state = sw_header_start;
					break;
				}
				break;


			/* end of request line */
			case sw_almost_done:
				switch (ch) {
				case LF:
					state = sw_header_start;
					break;
				default:
					return NGX_REDIRECT_TO_DEFAULT;
				}
				break;


			/* end of request line */
			case sw_header_start:
				if(!r->uri_checked){
					if(r->host_start && r->host_end){
						if (ngx_handoff_host_uri_lookup(con,
							buf + r->host_start, r->host_end - r->host_start,
							buf + r->uri_start, r->uri_end - r->uri_start)){
							/* HIT */
							return NGX_REDIRECT_TO_PRELOAD;
						}else{
							return NGX_REDIRECT_TO_DEFAULT;
						}
					}else if (ngx_handoff_uri_lookup(buf + r->uri_start, r->uri_end - r->uri_start)){
						/* HIT so continue */
						r->uri_checked = 1;
					}else{
						return NGX_REDIRECT_TO_DEFAULT;
					}
				}
				r->key_start = p - buf;
				if (ch == CR || ch == LF) {
					return NGX_REDIRECT_TO_DEFAULT;
				}
				state = sw_header_key;
				break;



			case sw_header_key:
				if (ch == ' ') {
					r->key_end = p - 1 - buf;
					m = buf + r->key_start;

					if(p - m == 5) {
						if(ngx_str5cmp(m, 'H', 'o', 's', 't', ':')){
							state = sw_header_spaces_before_value;
						}
					}
				}

				if (ch == CR){
					state = sw_almost_done;
				}

				if (ch == LF) {
					state = sw_header_start;
				}
				break;

			case sw_header_spaces_before_value:
				switch (ch) {
				case ' ':
					break;
				default:
					r->value_start = p - buf;
					state = sw_header_in_value;
					break;
				}
				break;

			case sw_header_in_value:
				switch (ch) {
				case CR:
				case LF:
				case ' ':
					r->value_end = p - buf;
					if (ngx_handoff_host_uri_lookup(con,
						buf + r->value_start, r->value_end - r->value_start,
						buf + r->uri_start, r->uri_end - r->uri_start)){
						/* HIT */
						return NGX_REDIRECT_TO_PRELOAD;
					}else{
						return NGX_REDIRECT_TO_DEFAULT;
					}
					break;
				default:
					break;
				}
				break;
			}
		}

		r->last = p - buf;
		r->state = state;

		return NGX_REDIRECT_PASS;
	}

    if (n == NGX_AGAIN || n == 0) {
        return NGX_REDIRECT_PASS;;
    }

    if (n == NGX_ERROR) {
        return NGX_REDIRECT_TO_DEFAULT;
    }

	return NGX_REDIRECT_PASS;

}




static void ngx_handoff_redirect_to(ngx_event_t *rev, ngx_listening_t *ls) {
	ngx_connection_t *c;
	ngx_handoff_session_t   *s;
	ngx_handoff_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;
	cscf = ngx_handoff_get_module_srv_conf(s, ngx_handoff_core_module);

	rev->timedout = 0;
	ngx_event_add_timer(rev, cscf->timeout);
	c->listening->post_accept_timeout = cscf->timeout;

	c->listening = ls;

    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, c->log, 0,
                   "handoff ngx_handoff_redirect_to: %V", &ls->addr_text);
	c->data = NULL;
	ls->handler(c);

//    ngx_log_debug(NGX_LOG_DEBUG_HANDOFF, c->log, 0,
//                   "handoff c->read->handler(c->read)");
	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
		ngx_handoff_close_connection(c);
		return;
	}
}




void
ngx_handoff_finalize_session(ngx_handoff_session_t *s)
{
    ngx_connection_t *c;
    ngx_handoff_cleanup_t *cln;

    c = s->connection;

    ngx_handoff_log_handler(s);

    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, c->log, 0,
                   "close tcp session: %d", c->fd);

    for (cln = s->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
            cln->handler = NULL;
        }
    }

    ngx_handoff_close_connection(c);

    return;
}


void
ngx_handoff_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HANDOFF, c->log, 0,
                   "close HANDOFF connection: %d", c->fd);


#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


u_char *
ngx_handoff_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_handoff_session_t   *s;
    ngx_handoff_log_ctx_t   *ctx;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(p, len + (buf - p), " while %s", log->action);
    }

    ctx = log->data;

    p = ngx_snprintf(p, len + (buf - p), ", client: %V", ctx->client);

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(p, len + (buf - p), ", server: %V", s->addr_text);


    return p;
}


