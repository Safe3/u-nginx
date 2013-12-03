/*
 * author : yubo@xiaomi.com
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_handoff.h>
#include <nginx.h>


static void *ngx_handoff_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_handoff_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_handoff_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_handoff_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_handoff_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_handoff_core_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_listening_t *ngx_handoff_find_ls(ngx_conf_t *cf, in_port_t port);
static char *ngx_handoff_log_set_access_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


extern ngx_module_t  ngx_http_preload_cache_module;


static ngx_command_t  ngx_handoff_core_commands[] = {

    { ngx_string("server"),
      NGX_HANDOFF_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS,
      ngx_handoff_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_HANDOFF_SRV_CONF|NGX_CONF_1MORE,
      ngx_handoff_core_listen,
      NGX_HANDOFF_SRV_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("redirect"),
      NGX_HANDOFF_SRV_CONF|NGX_CONF_TAKE3,
      ngx_handoff_core_redirect,
      NGX_HANDOFF_SRV_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("timeout"),
      NGX_HANDOFF_MAIN_CONF|NGX_HANDOFF_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HANDOFF_SRV_CONF_OFFSET,
      offsetof(ngx_handoff_core_srv_conf_t, timeout),
      NULL },
    { ngx_string("access_log"),
      NGX_HANDOFF_MAIN_CONF|NGX_HANDOFF_SRV_CONF|NGX_CONF_TAKE12,
      ngx_handoff_log_set_access_log,
      NGX_HANDOFF_SRV_CONF_OFFSET,
      0,
      NULL },
	{ ngx_string("proxy_buffer"),
	  NGX_HANDOFF_MAIN_CONF|NGX_HANDOFF_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HANDOFF_SRV_CONF_OFFSET,
	  offsetof(ngx_handoff_core_srv_conf_t, buffer_size),
	  NULL },

    ngx_null_command
};


static ngx_handoff_module_t  ngx_handoff_core_module_ctx = {
    NULL,                                  /* protocol */

    ngx_handoff_core_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_handoff_core_create_srv_conf,          /* create server configuration */
    ngx_handoff_core_merge_srv_conf            /* merge server configuration */
};


ngx_module_t  ngx_handoff_core_module = {
    NGX_MODULE_V1,
    &ngx_handoff_core_module_ctx,              /* module context */
    ngx_handoff_core_commands,                 /* module directives */
    NGX_HANDOFF_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_handoff_access_log = ngx_string("logs/handoff_access.log");


static void *
ngx_handoff_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_handoff_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_handoff_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_handoff_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_handoff_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->virtual_servers, cf->pool, 4,
                       sizeof(ngx_handoff_virtual_server_t)) != NGX_OK)
    {
        return NULL;
    }



    return cmcf;
}


static void *
ngx_handoff_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_handoff_core_srv_conf_t  *cscf;
    ngx_handoff_log_srv_conf_t   *lscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_handoff_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     */

	cscf->default_ls = NGX_CONF_UNSET_PTR;
	cscf->preload_ls = NGX_CONF_UNSET_PTR;
	cscf->preload_shm_zone= NGX_CONF_UNSET_PTR;



    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->buffer_size = NGX_CONF_UNSET_SIZE;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    lscf = cscf->access_log = ngx_pcalloc(cf->pool,
                                          sizeof(ngx_handoff_log_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     lscf->logs = NULL;
     */

    lscf->open_file_cache = NGX_CONF_UNSET_PTR;

    return cscf;
}


static char *
ngx_handoff_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_handoff_log_t           *log;
    ngx_handoff_core_srv_conf_t *prev = parent;
    ngx_handoff_core_srv_conf_t *conf = child;
    ngx_handoff_log_srv_conf_t  *plscf = prev->access_log;
    ngx_handoff_log_srv_conf_t  *lscf = conf->access_log;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);



    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);



    if (lscf->open_file_cache == NGX_CONF_UNSET_PTR) {

        lscf->open_file_cache = plscf->open_file_cache;
        lscf->open_file_cache_valid = plscf->open_file_cache_valid;
        lscf->open_file_cache_min_uses = plscf->open_file_cache_min_uses;

        if (lscf->open_file_cache == NGX_CONF_UNSET_PTR) {
            lscf->open_file_cache = NULL;
        }
    }

    if (lscf->logs || lscf->off) {
        return NGX_CONF_OK;
    }

    lscf->logs = plscf->logs;
    lscf->off = plscf->off;

    if (lscf->logs || lscf->off) {
        return NGX_CONF_OK;
    }

    lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_handoff_log_t));
    if (lscf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(lscf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    log->file = ngx_conf_open_file(cf->cycle, &ngx_handoff_access_log);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    log->disk_full_time = 0;
    log->error_log_time = 0;

    return NGX_CONF_OK;
}


static char *
ngx_handoff_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_handoff_module_t           *module;
    ngx_handoff_conf_ctx_t         *ctx, *handoff_ctx;
    ngx_handoff_core_srv_conf_t    *cscf, **cscfp;
    ngx_handoff_core_main_conf_t   *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_handoff_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    handoff_ctx = cf->ctx;
    ctx->main_conf = handoff_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_handoff_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HANDOFF_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_handoff_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_handoff_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;

    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HANDOFF_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_handoff_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    ngx_handoff_listen_t       *ls;
    struct sockaddr_in         *sin;
    ngx_handoff_core_main_conf_t   *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_handoff_conf_get_module_main_conf(cf, ngx_handoff_core_module);

    ls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                off = offsetof(struct sockaddr_in6, sin6_addr);
                len = 16;
                sin6 = (struct sockaddr_in6 *) sa;
                port = sin6->sin6_port;
                break;
#endif

            default: /* AF_INET */
                off = offsetof(struct sockaddr_in, sin_addr);
                len = 4;
                sin = (struct sockaddr_in *) sa;
                port = sin->sin_port;
                break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_handoff_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;
    ls->conf = conf;

    for (i = 2; i < cf->args->nelts; i++) {
		if (ngx_strcmp(value[i].data, "tproxy") == 0) {
#if (NGX_HAVE_TPROXY)
			ls->tproxy = 1;
#else
			ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
			"TPROXY support is not enabled, ignoring option \"tproxy\" in %V",
			&value[i]);
#endif
			continue;
		}


        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "default") == 0) {
            ls->default_port = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 2;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid ipv6only flags \"%s\"",
                            &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
#if defined(nginx_version) && nginx_version >= 1005003
                len = ngx_sock_ntop(sa, ls->socklen, buf, NGX_SOCKADDR_STRLEN, 1);
#else
                len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);
#endif

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "ipv6only is not supported "
                        "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "bind ipv6only is not supported "
                    "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_HANDOFF_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_handoff_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}




static char *
ngx_handoff_core_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_handoff_core_srv_conf_t *cscf = conf;

    ngx_str_t                  *value, v;
	int                         port, i;
	ngx_listening_t            *ls;
	u_char                      errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;


    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "preload_port=", 13) == 0) {
            v.len = value[i].len - 13;
            v.data = value[i].data + 13;

			//check port
			port = ngx_atoi(v.data, v.len);
			if (port < 1 || port > 65535) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"the invalid \"%V\" preload port", &v);
				return NGX_CONF_ERROR;
			}

			cscf->preload_ls = ngx_handoff_find_ls(cf, (in_port_t)port);
			if(cscf->preload_ls == NULL){
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"\"%V\" preload port isn't listening", &v);
				return NGX_CONF_ERROR;
			}
            continue;
        }

		if (ngx_strncmp(value[i].data, "default_port=", 13) == 0) {
			v.len = value[i].len - 13;
			v.data = value[i].data + 13;

			//check port
			port = ngx_atoi(v.data, v.len);
			if (port < 1 || port > 65535) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"the invalid \"%V\" default port", &v);
				return NGX_CONF_ERROR;
			}

			cscf->default_ls= ngx_handoff_find_ls(cf, (in_port_t)port);
			if(cscf->default_ls == NULL){
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"\"%V\" port isn't default listening", &v);
				return NGX_CONF_ERROR;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

			v.len = value[i].len - 5;
			v.data = value[i].data + 5;

			cscf->preload_shm_zone = ngx_shared_memory_add(cf, &v, 0,
				&ngx_http_preload_cache_module);
			if (cscf->preload_shm_zone == NULL) {
				return NGX_CONF_ERROR;
			}

    	}
    }

    return NGX_CONF_OK;



}



static ngx_listening_t *
ngx_handoff_find_ls(ngx_conf_t *cf, in_port_t port)
{
	ngx_listening_t       *ls;
	ngx_uint_t             n;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    in_port_t              p;


	ls = cf->cycle->listening.elts;
	for (n = 0; n < cf->cycle->listening.nelts; n++){
		sa = (struct sockaddr *) (&ls[n])->sockaddr;

		switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
		case AF_INET6:
			return NULL;
#endif

		default: /* AF_INET */
			sin = (struct sockaddr_in *) sa;
			p = ntohs(sin->sin_port);
			break;
		}
		if (p == port) {
			return &ls[n];
		}
	}
	return NULL;
}

static char *
ngx_handoff_log_set_access_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_handoff_core_srv_conf_t *cscf = conf;
    ngx_handoff_log_srv_conf_t  *lscf = cscf->access_log;

    ssize_t                     size;
    ngx_str_t                  *value, name;
    ngx_handoff_log_t              *log;
#if (nginx_version) >= 1003010 || (nginx_version) >= 1002007 && (nginx_version) < 1003000
    ngx_handoff_log_buf_t         *buffer;
#endif

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lscf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (lscf->logs == NULL) {
        lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_handoff_log_t));
        if (lscf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    log = ngx_array_push(lscf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_handoff_log_t));

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strncmp(value[2].data, "buffer=", 7) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        name.len = value[2].len - 7;
        name.data = value[2].data + 7;

        size = ngx_parse_size(&name);

        if (size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

#if (nginx_version) >= 1003010 || (nginx_version) >= 1002007 && (nginx_version) < 1003000
        if (log->file->data) {

            buffer = log->file->data;

            if (buffer->last - buffer->pos != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "access_log \"%V\" already defined "
                        "with different buffer size", &value[1]);
                return NGX_CONF_ERROR;
            }

            return NGX_CONF_OK;
        }

        buffer = ngx_pcalloc(cf->pool, sizeof(ngx_handoff_log_buf_t));
        if (buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->start = ngx_palloc(cf->pool, size);
        if (buffer->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        log->file->data = buffer;
#else
        if (log->file->buffer) {
            if (log->file->last - log->file->pos != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with different buffer size", &value[1]);
                return NGX_CONF_ERROR;
            }

            return NGX_CONF_OK;
        }

        log->file->buffer = ngx_palloc(cf->pool, size);
        if (log->file->buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        log->file->pos = log->file->buffer;
        log->file->last = log->file->buffer + size;
#endif
    }

    return NGX_CONF_OK;
}
