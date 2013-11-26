/*
 * author : yubo@xiaomi.com
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_filter.h>


static void ngx_filter_init_session_connection(ngx_connection_t *c);
static void ngx_filter_init_session(ngx_filter_session_t *s);
static void ngx_filter_write_handler(ngx_event_t *wev);
static void ngx_filter_read_handler(ngx_event_t *rev);
static void ngx_filter_redirect_to(ngx_event_t *rev, ngx_listening_t *ls);
static int ngx_filter_redirect_regex(ngx_connection_t *c, ngx_listening_t **lsp);




#if (NGX_FILTER_SSL)
static void ngx_filter_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_filter_ssl_handshake_handler(ngx_connection_t *c);
#endif


void
ngx_filter_init_connection(ngx_connection_t *c)
{
    ngx_uint_t            i;
    ngx_filter_port_t       *port;
    struct sockaddr      *sa;
    struct sockaddr_in   *sin;
    ngx_filter_log_ctx_t    *ctx;
    ngx_filter_in_addr_t    *addr;
    ngx_filter_session_t    *s;
    ngx_filter_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    ngx_filter_in6_addr_t   *addr6;
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
            ngx_filter_close_connection(c);
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

    s = ngx_pcalloc(c->pool, sizeof(ngx_filter_session_t));
    if (s == NULL) {
        ngx_filter_close_connection(c);
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

    ctx = ngx_palloc(c->pool, sizeof(ngx_filter_log_ctx_t));
    if (ctx == NULL) {
        ngx_filter_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_filter_log_error;
    c->log->data = ctx;
    c->log->action = "nginx tcp module init connection";

    c->log_error = NGX_ERROR_INFO;


    ngx_filter_init_session_connection(c);
}





static void
ngx_filter_init_session_connection(ngx_connection_t *c)
{
    ngx_time_t               *tp;
    ngx_filter_session_t        *s;
    ngx_filter_core_srv_conf_t  *cscf;

    s = c->data;

    s->signature = NGX_FILTER_MODULE;
    s->pool = c->pool;

    cscf = ngx_filter_get_module_srv_conf(s, ngx_filter_core_module);
    if (cscf == NULL) {
        ngx_filter_finalize_session(s);
        return;
    }

    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_filter_max_module);
    if (s->ctx == NULL) {
        ngx_filter_finalize_session(s);
        return;
    }

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    s->bytes_read = 0;
    s->bytes_write = 0;
    ngx_filter_init_session(s);
}






static void
ngx_filter_init_session(ngx_filter_session_t *s)
{
    ngx_connection_t             *c;
    ngx_filter_core_srv_conf_t  *cscf;

	c = s->connection;

	ngx_log_debug0(NGX_LOG_DEBUG_FILTER, c->log, 0, "filter init session");

	cscf = ngx_filter_get_module_srv_conf(s, ngx_filter_core_module);

    s->buffer = ngx_create_temp_buf(s->connection->pool, cscf->buffer_size);
    if (s->buffer == NULL) {
		ngx_filter_close_connection(c);
        return;
    }

	s->out.len = 0;

	c->write->handler = ngx_filter_write_handler;
	c->read->handler = ngx_filter_read_handler;

	//timeout handle ?
	ngx_add_timer(c->read, cscf->timeout);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
#if (NGX_STAT_STUB)
		(void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
		ngx_filter_close_connection(c);
		return;
	}	
	return;
	

}


static void
ngx_filter_write_handler(ngx_event_t *wev) 
{
    ngx_connection_t    *c;

    c = wev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_FILTER, wev->log, 0,
                   "filter dummy write handler: %d", c->fd);

	return;
}

static void
ngx_filter_read_handler(ngx_event_t *rev) 
{
    ngx_connection_t    *c;
	int                 ret;
	ngx_filter_core_srv_conf_t  *cscf;
	ngx_listening_t     *ls;

    c = rev->data;
	cscf = ngx_filter_get_module_srv_conf((ngx_filter_session_t *)c->data, ngx_filter_core_module);
	ngx_event_add_timer(rev, cscf->timeout);


    ngx_log_debug1(NGX_LOG_DEBUG_FILTER, rev->log, 0,
                   "filter dummy read handler: %d", c->fd);	

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out redirect to default");
        ngx_filter_redirect_to(rev, cscf->default_ls);
		
        return;
    }

	ret = ngx_filter_redirect_regex(c, &ls);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
#if (NGX_STAT_STUB)
		(void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
		ngx_filter_close_connection(c);
		return;
	}

	
	switch (ret) {
		case NGX_ERROR:
			ngx_filter_close_connection(c);
            break;
		case NGX_REDIRECT_TO:
			ngx_filter_redirect_to(rev, ls);
			break;
		case NGX_REDIRECT_TO_DEFAULT:
			ngx_filter_redirect_to(rev, cscf->default_ls);
			break;
		default: // NGX_REDIRECT_PAAS
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


static int ngx_filter_redirect_regex(ngx_connection_t *c, ngx_listening_t **lsp)
{
    ngx_filter_session_t   *s;
	ngx_filter_core_srv_conf_t  *cscf;
	ngx_uint_t                  i;
    ssize_t                     n;
    ngx_int_t                   ret;
	ngx_err_t            err;
	char                 buf[NGX_BUF_SIZE];
    ngx_filter_regex_elt_t  *re;
	int vector[18];

    s = c->data;
	cscf = ngx_filter_get_module_srv_conf(s, ngx_filter_core_module);

	re = cscf->regex->elts;
	
	n = recv(c->fd, buf, NGX_BUF_SIZE, MSG_PEEK);
	err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, err,
			   "filter check recv(): [%d](%s)", n, buf);

	n = recv(c->fd, buf, NGX_BUF_SIZE, MSG_PEEK);
	err = ngx_socket_errno;
	if (n > 0 || err == NGX_EAGAIN) {

		ret = NGX_REGEX_NO_MATCHED;
		for (i = 0; i < cscf->regex->nelts; i++) {
		
			ret = pcre_exec(re[i].regex->code, 
				re[i].regex->extra,
				(const char *) buf,
				(size_t)n > cscf->buffer_size ? cscf->buffer_size : (size_t)n, 
				0, 
				PCRE_BSR_ANYCRLF, 
				vector, 
				18);
			if (ret == NGX_REGEX_NO_MATCHED) {
				continue;
			}
			if (ret < 0) {
				ngx_log_error(NGX_LOG_ALERT, c->log, 0,
							  ngx_regex_exec_n " failed: %i on \"%s\"",
							  ret, buf);
				break;
			}
		
			/* match */
			*lsp = re[i].ls;

			break;
		}



        if (ret == NGX_REGEX_NO_MATCHED) {
			if (n >= (ngx_int_t)cscf->buffer_size) {
            	return NGX_REDIRECT_TO_DEFAULT;
			}
			return NGX_REDIRECT_PAAS;
        }else if (ret < 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_FILTER, c->log, 0,
                          " failed: %i on \"%s\"",
                          n, buf);
			return NGX_ERROR;
        }else{  /* match */

			/* check preload */
			if(re[i].preload && ret == 6){
				ngx_str_t* url = ngx_pcalloc(c->pool, sizeof(ngx_str_t));
				url->len = vector[2*5+1] - vector[2*5] + vector[2*2+1] - vector[2*2];
				url->data = ngx_pcalloc(c->pool, url->len);
				ngx_memcpy(url->data, buf+vector[2*5],
					vector[2*5+1] - vector[2*5]);
				ngx_memcpy(url->data + vector[2*5+1] - vector[2*5],
					buf+vector[2*2], vector[2*2+1] - vector[2*2]);

				ngx_http_preload_cache_node_t *node;
				//ngx_http_preload_cache_ctx_t  *ctx;
				//ctx = re[i].preload_shm_zone->data;
				//ngx_shmtx_lock(&ctx->shpool->mutex);
				node = ngx_http_preload_cache_lookup(re[i].preload_shm_zone, url);
				//ngx_shmtx_unlock(&ctx->shpool->mutex);

				if (!node){
					ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "preload MISS: url:[%V] header[%s]",url, buf);				
					return NGX_REDIRECT_TO_DEFAULT;

				}else{
					ngx_log_error(NGX_LOG_INFO, c->log, err,
								  "preload HIT: url:[%V] header[%s]",url, buf);
					return NGX_REDIRECT_TO;
				}

			}

		
	        return NGX_REDIRECT_TO;
        }
	}

    if (n == NGX_AGAIN || n == 0) {
        return NGX_REDIRECT_PAAS;;
    }

    if (n == NGX_ERROR) {
        return NGX_REDIRECT_TO_DEFAULT;
    }

    return NGX_REDIRECT_PAAS;
}

static void ngx_filter_redirect_to(ngx_event_t *rev, ngx_listening_t *ls) {
	ngx_connection_t *c;
	ngx_filter_session_t   *s;
	ngx_filter_core_srv_conf_t  *cscf;  

    c = rev->data;
    s = c->data;
	cscf = ngx_filter_get_module_srv_conf(s, ngx_filter_core_module);

	rev->timedout = 0;
	ngx_event_add_timer(rev, cscf->timeout);
	c->listening->post_accept_timeout = cscf->timeout;

	c->listening = ls;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                   "filter ngx_filter_redirect_to: %V", &ls->addr_text);
	c->data = NULL;
	ls->handler(c);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
		ngx_filter_close_connection(c);
		return;
	}
}




void 
ngx_filter_finalize_session(ngx_filter_session_t *s)
{
    ngx_connection_t *c;
    ngx_filter_cleanup_t *cln;

    c = s->connection;

    ngx_filter_log_handler(s);

    ngx_log_debug1(NGX_LOG_DEBUG_FILTER, c->log, 0,
                   "close tcp session: %d", c->fd);

    for (cln = s->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
            cln->handler = NULL;
        }
    }

    ngx_filter_close_connection(c);

    return;
}


void
ngx_filter_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_FILTER, c->log, 0,
                   "close FILTER connection: %d", c->fd);


#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


u_char *
ngx_filter_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_filter_session_t   *s;
    ngx_filter_log_ctx_t   *ctx;

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


