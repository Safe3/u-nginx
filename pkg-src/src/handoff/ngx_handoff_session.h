
#ifndef _NGX_HANDOFF_SESSION_H_INCLUDED_
#define _NGX_HANDOFF_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_handoff.h>

#define NGX_REDIRECT_PASS        1
#define NGX_REDIRECT_TO_PRELOAD  2
#define NGX_REDIRECT_TO_DEFAULT  3




#define NGX_BUF_SIZE               10240

typedef struct ngx_handoff_request_s     ngx_handoff_request_t;
struct ngx_handoff_request_s {
    /* used to parse HTTP headers */

    ngx_uint_t                        state;
	ngx_uint_t                        last;


	ngx_uint_t                        method_end;
	ngx_uint_t                        port_end;
	ngx_uint_t                        request_start;
	ngx_uint_t                        uri_start;
	ngx_uint_t                        uri_end;
	ngx_uint_t                        schema_start;
	ngx_uint_t                        schema_end;
	ngx_uint_t                        host_start;
	ngx_uint_t                        host_end;
	ngx_uint_t                        key_start;
	ngx_uint_t                        key_end;
	ngx_uint_t                        value_start;
	ngx_uint_t                        value_end;

    unsigned                          uri_checked:1;

};


typedef struct ngx_handoff_session_s {
    uint32_t                signature;         /* "HANDOFF" */

    ngx_pool_t             *pool;

    ngx_connection_t       *connection;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

	ngx_handoff_request_t	request;

    ngx_resolver_ctx_t     *resolver_ctx;

    ngx_handoff_cleanup_t  *cleanup;

    time_t                  start_sec;
    ngx_msec_t              start_msec;

    off_t                   bytes_read;
    off_t                   bytes_write;

    unsigned                quit:1;
    ngx_str_t              *addr_text;
    ngx_str_t               host;

} ngx_handoff_session_t;


typedef void (*ngx_handoff_cleanup_pt)(void *data);

struct ngx_handoff_cleanup_s {
    ngx_handoff_cleanup_pt      handler;
    void                       *data;
    ngx_handoff_cleanup_t      *next;
};

void ngx_handoff_init_connection(ngx_connection_t *c);

void ngx_handoff_close_connection(ngx_connection_t *c);

u_char *ngx_handoff_log_error(ngx_log_t *log, u_char *buf, size_t len);

void ngx_handoff_finalize_session(ngx_handoff_session_t *s);


ngx_int_t ngx_handoff_log_handler(ngx_handoff_session_t *s);

#endif
