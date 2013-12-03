
/*
 * author : chenxianlin@xiaomi.com
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t ngx_http_preload_cache_module;
ngx_int_t 
ngx_http_preload_cache_find_cache(ngx_http_request_t *r, 
                                  ngx_shm_zone_t *shm_zone, 
                                  ngx_str_t *url, 
                                  ngx_str_t *path,
                                  ngx_str_t *disposition);


typedef struct {
    ngx_shm_zone_t              *shm_zone;
} ngx_http_preload_filter_conf_t;


static char *
ngx_http_preload_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t 
ngx_http_preload_filter_handler(ngx_http_request_t *r);
static ngx_str_t* 
ngx_get_full_url(ngx_http_request_t *r);
static char *
ngx_http_preload_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void *
ngx_http_preload_filter_create_conf(ngx_conf_t *cf);
static ngx_int_t 
ngx_add_http_header(ngx_http_request_t *r, 
                    ngx_str_t *key, 
                    ngx_str_t *value);
static ngx_int_t 
ngx_add_http_content_disposition_header(ngx_http_request_t *r, 
                                        ngx_str_t *disposition);
static ngx_int_t
ngx_http_preload_filter_from_cache(ngx_http_request_t *r, 
                                   ngx_str_t *path,
                                   ngx_str_t *disposition);
static ngx_int_t
ngx_http_preload_filter_init(ngx_conf_t *cf);
static ngx_int_t 
ngx_add_http_hit_mark_header(ngx_http_request_t *r, 
                             ngx_str_t *path);


static ngx_command_t  ngx_http_preload_filter_commands[] ={

    { ngx_string("preload_filter"),
      NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_preload_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_preload_filter_module_ctx ={
    NULL,                                    /* preconfiguration */
    ngx_http_preload_filter_init,            /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_preload_filter_create_conf,     /* create location configuration */
    ngx_http_preload_filter_merge_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_preload_filter_module ={
    NGX_MODULE_V1,
    &ngx_http_preload_filter_module_ctx,     /* module context */
    ngx_http_preload_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_preload_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value, s;
    ngx_uint_t   i;
    ngx_http_preload_filter_conf_t  *pfcf = conf;

    if (pfcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            pfcf->shm_zone = ngx_shared_memory_add(cf, &s, 0,
                &ngx_http_preload_cache_module);
            if (pfcf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    if (pfcf->shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"%V\" must have \"zone\" parameter",
            &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (pfcf->shm_zone->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown limit_req_zone \"%V\"",
            &pfcf->shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_str_t* 
ngx_get_full_url(ngx_http_request_t *r)
{
    ngx_str_t* url = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    ngx_str_t* host = &r->headers_in.host->value;
    url->len = host->len + r->unparsed_uri.len;
    url->data = ngx_pcalloc(r->pool, url->len);
    ngx_memcpy(url->data, host->data, host->len);
    ngx_memcpy(url->data + host->len, r->unparsed_uri.data, r->unparsed_uri.len);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_get_full_url, host : %V, url : %V .", host, url);

    return url;
}


static ngx_int_t 
ngx_add_http_header(ngx_http_request_t *r, 
                    ngx_str_t *key, 
                    ngx_str_t *value)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL){
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key = *key;
    h->value = *value;

    return NGX_OK;
}

static ngx_int_t 
ngx_add_http_content_disposition_header(ngx_http_request_t *r, 
                                        ngx_str_t *disposition)
{
    if (disposition->len == 0 || disposition->data == NULL){

        return NGX_OK;
    }

    ngx_str_t key = ngx_string("Content-Disposition");
    return ngx_add_http_header(r, &key, disposition);
}

static ngx_int_t 
ngx_add_http_hit_mark_header(ngx_http_request_t *r, 
                             ngx_str_t *path)
{
    ngx_str_t preload_key = ngx_string("MiXr-Preload");
    ngx_str_t preload_value = ngx_string("yes");
    if (ngx_add_http_header(r, &preload_key, &preload_value) == NGX_ERROR){
        return NGX_ERROR;
    }

    ngx_str_t fuuid_key = ngx_string("MiXr-FUUID");
    if (ngx_add_http_header(r, &fuuid_key, path) == NGX_ERROR){
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_preload_filter_from_cache(ngx_http_request_t *r, 
                                   ngx_str_t *path,
                                   ngx_str_t *disposition)
{
    ngx_str_t                      *url;
    ngx_http_preload_filter_conf_t *pfcf;

    pfcf = ngx_http_get_module_loc_conf(r, ngx_http_preload_filter_module);
    if (pfcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    url = ngx_get_full_url(r);
    return ngx_http_preload_cache_find_cache(r, pfcf->shm_zone, 
        url, path, disposition);
}

static ngx_int_t
ngx_http_preload_filter_handler(ngx_http_request_t *r)
{
    ngx_int_t                 code;
    ngx_str_t                 path;
    ngx_str_t                 disposition;
    ngx_int_t                 rc;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t               out;
    ngx_open_file_info_t      of;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_str_null(&disposition);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    code = ngx_http_preload_filter_from_cache(r, &path, &disposition);
    if (code == NGX_DECLINED){
        return NGX_DECLINED;
    }

    if (code != NGX_HTTP_OK){
        return code;
    }
    
    log = r->connection->log;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK){
        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_add_http_content_disposition_header(r, &disposition) != NGX_OK){
        return NGX_DECLINED;
    }

    if (ngx_add_http_hit_mark_header(r, &path) != NGX_OK){
        return NGX_DECLINED;
    }

    /*
    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }
    */

    r->allow_ranges = 1;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
    rc = ngx_http_send_header(r);
    */

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    //out.buf = b;
    //out.next = NULL;

    //return ngx_http_output_filter(r, &out);

    ngx_str_t uri = ngx_string("/hit");
    return ngx_http_internal_redirect(r,&uri,NULL);
}


static void *
ngx_http_preload_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_preload_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_preload_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->shm_zone = NULL;

    return conf;
}


static char *
ngx_http_preload_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_preload_filter_conf_t *prev = parent;
    ngx_http_preload_filter_conf_t *conf = child;

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_preload_filter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_preload_filter_handler;

    return NGX_OK;
}
