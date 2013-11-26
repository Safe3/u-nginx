#ifndef _NGX_HANDOFF_H_INCLUDED_
#define _NGX_HANDOFF_H_INCLUDED_
/*
 * author : yubo@xiaomi.com
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct ngx_handoff_protocol_s  ngx_handoff_protocol_t;
typedef struct ngx_handoff_cleanup_s  ngx_handoff_cleanup_t;

typedef struct ngx_handoff_core_srv_conf_s ngx_handoff_core_srv_conf_t;


typedef struct check_conf_s check_conf_t;

/* make nginx-0.8.22+ happy */
#if defined(nginx_version) && nginx_version >= 8022
typedef ngx_addr_t ngx_peer_addr_t; 
#endif

#include <ngx_handoff_session.h>


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_handoff_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_handoff_conf_ctx_t     *ctx;

    unsigned                default_port:1;
    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HANDOFF_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
#if (NGX_HAVE_TPROXY)
		unsigned		    tproxy:1;
#endif

    ngx_handoff_core_srv_conf_t *conf;


} ngx_handoff_listen_t;


typedef struct {
    ngx_str_t                name;
} ngx_handoff_server_name_t;


typedef struct {
    ngx_uint_t               hash;
    ngx_str_t                name;
    ngx_handoff_listen_t        *listen;
    ngx_handoff_conf_ctx_t      *ctx;

	
} ngx_handoff_virtual_server_t;




typedef struct {
    ngx_str_t                name;
} ngx_handoff_core_loc_t;


typedef struct {
    ngx_handoff_conf_ctx_t      *ctx;
    ngx_handoff_conf_ctx_t      *default_ctx;
    ngx_str_t                addr_text;
#if (NGX_HANDOFF_SSL)
    ngx_uint_t               ssl;    /* unsigned   ssl:1; */
#endif
} ngx_handoff_addr_conf_t;

typedef struct {
    in_addr_t                addr;
    ngx_handoff_addr_conf_t      conf;
} ngx_handoff_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr          addr6;
    ngx_handoff_addr_conf_t      conf;
} ngx_handoff_in6_addr_t;

#endif


typedef struct {
    /* ngx_handoff_in_addr_t or ngx_handoff_in6_addr_t */
    void                    *addrs;
    ngx_uint_t               naddrs;
    ngx_listening_t         *default_ls;    
#if (NGX_PCRE)
    ngx_array_t             *regex;
#endif
} ngx_handoff_port_t;

typedef struct {
    ngx_regex_t     *regex;
    ngx_listening_t *ls;
} ngx_handoff_regex_elt_t;


typedef struct {
    int                           family;
    in_port_t                     port;
    ngx_array_t                   addrs;       /* array of ngx_handoff_conf_addr_t */
} ngx_handoff_conf_port_t;


typedef struct {
    struct sockaddr         *sockaddr;
    socklen_t                socklen;

    ngx_handoff_conf_ctx_t      *ctx;
    ngx_handoff_conf_ctx_t      *default_ctx;

    unsigned                 bind:1;
    unsigned                 wildcard:1;
#if (NGX_HANDOFF_SSL)
    unsigned                 ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                 ipv6only:2;
#endif
#if (NGX_HAVE_TPROXY)
    unsigned                 tproxy:1;
#endif
} ngx_handoff_conf_addr_t;

typedef struct {
    in_addr_t                mask;
    in_addr_t                addr;
    ngx_uint_t               deny;      /* unsigned  deny:1; */
} ngx_handoff_access_rule_t;

typedef struct {
    ngx_array_t              servers;         /* ngx_handoff_core_srv_conf_t */
    ngx_array_t              listen;          /* ngx_handoff_listen_t */
    ngx_array_t              virtual_servers; /* ngx_handoff_virtual_server_t */
    ngx_array_t              regexs;          /* ngx_handoff_regex_t */
} ngx_handoff_core_main_conf_t;

typedef struct {
    ngx_open_file_t         *file;
    time_t                   disk_full_time;
    time_t                   error_log_time;
} ngx_handoff_log_t;

typedef struct {
    u_char                  *start;
    u_char                  *pos;
    u_char                  *last;
} ngx_handoff_log_buf_t;

typedef struct {
    ngx_array_t             *logs;       /* array of ngx_handoff_log_t */

    ngx_open_file_cache_t   *open_file_cache;
    time_t                   open_file_cache_valid;
    ngx_uint_t               open_file_cache_min_uses;

    ngx_uint_t               off;        /* unsigned  off:1 */
} ngx_handoff_log_srv_conf_t;


#define NGX_HANDOFF_GENERIC_PROTOCOL    0
#define NGX_HANDOFF_WEBSOCKET_PROTOCOL  1



struct ngx_handoff_core_srv_conf_s {

	ngx_array_t 			*regex;
	ngx_listening_t         *default_ls;

    size_t                   buffer_size;

    ngx_msec_t               timeout;
	u_char					*file_name;
    ngx_int_t                line;


    ngx_resolver_t          *resolver;


    ngx_handoff_log_srv_conf_t  *access_log;

    /* server ctx */
    ngx_handoff_conf_ctx_t      *ctx;
};


typedef struct {
    ngx_str_t              *client;
    ngx_handoff_session_t      *session;
} ngx_handoff_log_ctx_t;


typedef void (*ngx_handoff_init_session_pt)(ngx_handoff_session_t *s);
typedef void (*ngx_handoff_init_protocol_pt)(ngx_event_t *rev);
typedef void (*ngx_handoff_parse_protocol_pt)(ngx_event_t *rev);


struct ngx_handoff_protocol_s {
    ngx_str_t                   name;
    in_port_t                   port[4];
    ngx_uint_t                  type;

    ngx_handoff_init_session_pt     init_session;
    ngx_handoff_init_protocol_pt    init_protocol;
    ngx_handoff_parse_protocol_pt   parse_protocol;

    ngx_str_t                   internal_server_error;
};


typedef struct {
    ngx_handoff_protocol_t         *protocol;

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_handoff_module_t;


#define NGX_HANDOFF_MODULE         0x00501007     /* "HANDOFF" */

#define NGX_HANDOFF_MAIN_CONF      0x02000000
#define NGX_HANDOFF_SRV_CONF       0x04000000
#define NGX_HANDOFF_LOC_CONF       0x08000000
#define NGX_HANDOFF_UPS_CONF       0x10000000


#define NGX_HANDOFF_MAIN_CONF_OFFSET  offsetof(ngx_handoff_conf_ctx_t, main_conf)
#define NGX_HANDOFF_SRV_CONF_OFFSET   offsetof(ngx_handoff_conf_ctx_t, srv_conf)


#define ngx_handoff_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_handoff_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_handoff_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_handoff_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_handoff_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_handoff_conf_get_module_main_conf(cf, module)                       \
    ((ngx_handoff_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_handoff_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_handoff_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


extern ngx_uint_t    ngx_handoff_max_module;
extern ngx_module_t  ngx_handoff_core_module;

#endif /* _NGX_HANDOFF_H_INCLUDED_ */
