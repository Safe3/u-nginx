
/*
 * author : chenxianlin@xiaomi.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_PRELOAD_CACHE_BUFFER                 4096
#define NGX_PRELOAD_CACHE_RESPONSE_BODY_BUFFER   36

typedef enum{
    ERROR_CODE_OK,
    ERROR_CODE_UNKOWN,
    ERROR_CODE_OUT_OF_MEMORY,
    ERROR_CODE_FORMAT_ERROR,
} ngx_http_preload_cache_error_code_t;


typedef enum{
    CACHE_ACTION_UNKOWN,
    CACHE_ACTION_ADD,
    CACHE_ACTION_DELETE,
    CACHE_ACTION_UPDATE,
} ngx_http_preload_cache_action_t;


typedef enum{
    CACHE_INFO_SET_URL               = 1 << 0,
    CACHE_INFO_SET_PATH              = 1 << 1,
    CACHE_INFO_SET_ACTION            = 1 << 2,
    CACHE_INFO_SET_START             = 1 << 3,
    CACHE_INFO_SET_EXPIRES           = 1 << 4,
    CACHE_INFO_SET_CODE              = 1 << 5
} ngx_http_preload_cache_set_flag_t;


typedef struct{
    ngx_uint_t                       flag;
    ngx_int_t                        code;
    ngx_http_preload_cache_action_t  action;
    ngx_str_t                        url;
    ngx_str_t                        path;
    ngx_str_t                        disposition;
    time_t                           start;
    time_t                           expires;
} ngx_http_preload_cache_info_t;


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


ngx_int_t
ngx_http_preload_cache_find_cache(ngx_http_request_t *r, 
                                  ngx_shm_zone_t *shm_zone, 
                                  ngx_str_t *url, 
                                  ngx_str_t *path,
                                  ngx_str_t *disposition);
static char *
ngx_http_preload_cache_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_preload_cache(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static ngx_int_t 
ngx_http_preload_cache_handler(ngx_http_request_t *r);
static char *
ngx_http_preload_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void *
ngx_http_preload_cache_create_conf(ngx_conf_t *cf);
static void 
ngx_http_preload_cache_display_cache(ngx_http_request_t *r);
static ngx_http_preload_cache_error_code_t 
ngx_http_preload_cache_insert_cache(ngx_http_request_t *r,
                                    ngx_shm_zone_t *shm_zone,
                                    ngx_http_preload_cache_info_t* cache_info);
static void
ngx_parse_cache_info_line(ngx_http_preload_cache_info_t *cache_info, 
                          u_char *buf, 
                          ssize_t size);
static void 
ngx_display_cache(ngx_http_request_t *r, 
                  ngx_rbtree_node_t *node, 
                  ngx_rbtree_node_t *sentinel);
static ngx_http_preload_cache_node_t *
ngx_http_preload_cache_lookup(ngx_shm_zone_t *shm_zone, 
                              ngx_str_t *url);
static void
ngx_http_preload_cache_do_delete_cache(ngx_shm_zone_t *shm_zone,
                                       ngx_http_preload_cache_node_t *node);
static void 
ngx_http_preload_cache_delete_cache(ngx_http_request_t *r, 
                                    ngx_shm_zone_t *shm_zone,
                                    ngx_http_preload_cache_info_t* cache_info);
static ngx_http_preload_cache_error_code_t 
ngx_http_preload_cache_do_insert_cache(ngx_shm_zone_t *shm_zone,
                                       ngx_http_preload_cache_info_t* cache_info);
static ngx_http_preload_cache_error_code_t 
ngx_handle_cache_info(ngx_http_request_t *r, 
                      ngx_http_preload_cache_info_t *cache_info);
static ngx_int_t
ngx_http_preload_cache_response(ngx_http_request_t *r, 
                                ngx_http_preload_cache_error_code_t err,
                                time_t last_ts);
static ngx_str_t *
ngx_build_response_body(ngx_http_request_t *r, 
                        ngx_http_preload_cache_error_code_t err,
                        time_t last_ts);
static void
ngx_parse_cache_info(ngx_http_request_t *r, 
                     ngx_http_preload_cache_info_t* cache_info, 
                     u_char *buf);
static ngx_http_preload_cache_error_code_t 
ngx_parse_and_handle_cache_info(ngx_http_request_t *r, u_char *buf);
static ngx_http_preload_cache_error_code_t
ngx_parse_and_handle_cache_infos(ngx_http_request_t *r, 
                                 u_char *buf, 
                                 ssize_t *offset);
static ngx_int_t 
ngx_http_preload_cache_clear_cache(ngx_http_request_t *r);
static void 
ngx_http_preload_cache_do_clear_cache(ngx_http_request_t *r);
static void 
ngx_delete_cache(ngx_shm_zone_t *shm_zone, 
                 ngx_rbtree_node_t *node, 
                 ngx_rbtree_node_t *sentinel);
static void 
ngx_http_preload_cache_do_delete_expires_cache(ngx_shm_zone_t *shm_zone);
static void 
ngx_delete_expires_cache(ngx_shm_zone_t *shm_zone, 
                         ngx_rbtree_node_t *node, 
                         ngx_rbtree_node_t *sentinel);
static ngx_http_preload_cache_error_code_t
ngx_parse_and_handle_cache_ts(ngx_http_request_t *r, 
                              u_char *buf, 
                              ssize_t *offset,
                              time_t *last_ts);
static ngx_http_preload_cache_error_code_t
ngx_parse_cache_ts_line(u_char *buf, 
                        ssize_t size,
                        time_t *ts);
static void
ngx_init_http_preload_cache_info(ngx_http_preload_cache_info_t* cache_info);


static ngx_command_t  ngx_http_preload_cache_commands[] = {

    { ngx_string("preload_cache_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_preload_cache_zone,
      0,
      0,
      NULL },

    { ngx_string("preload_cache"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_preload_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_preload_cache_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_preload_cache_create_conf,    /* create location configuration */
    ngx_http_preload_cache_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_preload_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_preload_cache_module_ctx,    /* module context */
    ngx_http_preload_cache_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void 
ngx_display_cache(ngx_http_request_t *r, 
                  ngx_rbtree_node_t *node, 
                  ngx_rbtree_node_t *sentinel)
{
    ngx_int_t                      code;                       
    ngx_str_t                      url, path, disposition;
    ngx_http_preload_cache_node_t  *pc;

    if (node != sentinel){

        pc = (ngx_http_preload_cache_node_t *) &node->color;
        code = pc->code;
        url.len = pc->url_len;
        url.data = pc->data;
        path.len = pc->path_len;
        path.data = pc->data + pc->url_len;
        disposition.len = pc->disposition_len;
        disposition.data = pc->data + pc->url_len + pc->path_len;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_display_cache, url : %V , path : %V , start : %T, expires: %T"
            " , disposition : %V, code : %d .",
            &url, &path, pc->start, pc->expires, &disposition, code);

        ngx_display_cache(r, node->left, sentinel);
        ngx_display_cache(r, node->right, sentinel);
    }
}

static void 
ngx_http_preload_cache_do_delete_expires_cache(ngx_shm_zone_t *shm_zone)
{
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_preload_cache_ctx_t   *ctx;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    ngx_delete_expires_cache(shm_zone, node, sentinel);
}

static void 
ngx_delete_expires_cache(ngx_shm_zone_t *shm_zone, 
                         ngx_rbtree_node_t *node, 
                         ngx_rbtree_node_t *sentinel)
{
    ngx_http_preload_cache_node_t  *pc;

    if (node != sentinel){

        pc = (ngx_http_preload_cache_node_t *) &node->color;

        ngx_delete_expires_cache(shm_zone, node->left, sentinel);
        ngx_delete_expires_cache(shm_zone, node->right, sentinel);

        time_t now = time(NULL);
        if (now >= pc->expires){

            ngx_http_preload_cache_do_delete_cache(shm_zone, pc);
        }
    }
}

static void 
ngx_http_preload_cache_do_clear_cache(ngx_http_request_t *r)
{
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_preload_cache_ctx_t   *ctx;
    ngx_http_preload_cache_conf_t  *pccf = ngx_http_get_module_loc_conf(r, 
        ngx_http_preload_cache_module);

    ctx = pccf->shm_zone->data;
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    ngx_delete_cache(pccf->shm_zone, node, sentinel);
}


static void 
ngx_delete_cache(ngx_shm_zone_t *shm_zone, 
                 ngx_rbtree_node_t *node, 
                 ngx_rbtree_node_t *sentinel)
{
    ngx_http_preload_cache_node_t  *pc;

    if (node != sentinel){

        pc = (ngx_http_preload_cache_node_t *) &node->color;

        ngx_delete_cache(shm_zone, node->left, sentinel);
        ngx_delete_cache(shm_zone, node->right, sentinel);

        ngx_http_preload_cache_do_delete_cache(shm_zone, pc);
    }
}


static void 
ngx_http_preload_cache_display_cache(ngx_http_request_t *r)
{
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_preload_cache_ctx_t   *ctx;
    ngx_http_preload_cache_conf_t  *pccf = ngx_http_get_module_loc_conf(r, 
        ngx_http_preload_cache_module);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "inter ngx_http_preload_cache_display_cache.");

    ctx = pccf->shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    ngx_display_cache(r, node, sentinel);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "leave ngx_http_preload_cache_display_cache.");
}


static void 
ngx_http_preload_cache_delete_cache(ngx_http_request_t *r,
                                    ngx_shm_zone_t *shm_zone,
                                    ngx_http_preload_cache_info_t* cache_info)
{
    ngx_http_preload_cache_node_t *node;
    node = ngx_http_preload_cache_lookup(shm_zone, &cache_info->url);
    if (node){
        ngx_http_preload_cache_do_delete_cache(shm_zone, node);

    } else{
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "ngx_http_preload_cache_delete_cache, delete failed, url %V not exist",
            &cache_info->url);
    }
}

static void
ngx_http_preload_cache_do_delete_cache(ngx_shm_zone_t *shm_zone,
                                       ngx_http_preload_cache_node_t *node)
{
    ngx_rbtree_node_t * rb_node;
    ngx_http_preload_cache_ctx_t *ctx;
    ctx = shm_zone->data;

    rb_node = (ngx_rbtree_node_t *)
        ((u_char *) node - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, rb_node);
    ngx_slab_free_locked(ctx->shpool, rb_node);
}

static ngx_http_preload_cache_error_code_t 
ngx_http_preload_cache_insert_cache(ngx_http_request_t *r,
                                    ngx_shm_zone_t *shm_zone,
                                    ngx_http_preload_cache_info_t* cache_info)
{
    ngx_http_preload_cache_node_t *node;
    node = ngx_http_preload_cache_lookup(shm_zone, &cache_info->url);
    if (node){

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "inter ngx_http_preload_cache_insert_cache, url %V already exist",
            &cache_info->url);

        ngx_http_preload_cache_do_delete_cache(shm_zone, node);
    }

    return ngx_http_preload_cache_do_insert_cache(shm_zone, cache_info);
}

static ngx_http_preload_cache_error_code_t 
ngx_http_preload_cache_do_insert_cache(ngx_shm_zone_t *shm_zone,
                                       ngx_http_preload_cache_info_t* cache_info)
{
    size_t                            n;
    uint32_t                          hash;
    ngx_rbtree_node_t                *node;
    ngx_http_preload_cache_node_t    *pc;
    ngx_http_preload_cache_ctx_t     *ctx;


    hash = ngx_crc32_short(cache_info->url.data, cache_info->url.len);

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_preload_cache_node_t, data)
        + cache_info->url.len 
        + cache_info->path.len 
        + cache_info->disposition.len;

    ctx = shm_zone->data;
    node = ngx_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {

        ngx_http_preload_cache_do_delete_expires_cache(shm_zone);

        node = ngx_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL){
            return ERROR_CODE_OUT_OF_MEMORY;
        }
    }

    pc = (ngx_http_preload_cache_node_t *) &node->color;

    node->key = hash;
    pc->code = cache_info->code;
    pc->url_len = cache_info->url.len;
    pc->path_len = cache_info->path.len;
    pc->start = cache_info->start;
    pc->expires = cache_info->expires;
    pc->disposition_len = cache_info->disposition.len;

    ngx_memcpy(pc->data, cache_info->url.data, cache_info->url.len);
    ngx_memcpy(pc->data + cache_info->url.len, cache_info->path.data, 
        cache_info->path.len);
    ngx_memcpy(pc->data + cache_info->url.len + cache_info->path.len, 
        cache_info->disposition.data, cache_info->disposition.len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    return ERROR_CODE_OK;
}


static void
ngx_parse_cache_info_line(ngx_http_preload_cache_info_t *cache_info, 
                          u_char *buf, 
                          ssize_t size)
{
    u_char *p;
    if (ngx_strncmp(buf, "path:", 5) == 0) {

        cache_info->flag |= CACHE_INFO_SET_PATH;
        cache_info->path.data = buf + 5;
        cache_info->path.len = size - 5;

    } else if (ngx_strncmp(buf, "url:", 4) == 0){

        cache_info->flag |= CACHE_INFO_SET_URL;
        cache_info->url.data = buf + 4;
        cache_info->url.len = size - 4;
    }
    else if (ngx_strncmp(buf, "action:", 7) == 0){

        p = buf + 7;
        if (ngx_strncmp(p, "add", 3) == 0){

            cache_info->action = CACHE_ACTION_ADD;

        }else if (ngx_strncmp(p, "delete", 6) == 0){

            cache_info->action = CACHE_ACTION_DELETE;

        }else if (ngx_strncmp(p, "update", 6) == 0){

            cache_info->action = CACHE_ACTION_UPDATE;

        }else{

            return;
        }

        cache_info->flag |= CACHE_INFO_SET_ACTION;

    }else if (ngx_strncmp(buf, "start:", 6) == 0){

        cache_info->start = ngx_atotm(buf + 6, size - 6);
        if (cache_info->start != NGX_ERROR){

            cache_info->flag |= CACHE_INFO_SET_START;
        }
    }else if (ngx_strncmp(buf, "expires:", 8) == 0){

        cache_info->expires = ngx_atotm(buf + 8, size - 8);
        if (cache_info->expires != NGX_ERROR){
            cache_info->flag |= CACHE_INFO_SET_EXPIRES;
        }

    }else if (ngx_strncmp(buf, "content-disposition:", 20) == 0){

        cache_info->disposition.data = buf + 20;
        cache_info->disposition.len = size - 20;

    }else if (ngx_strncmp(buf, "code:", 5) == 0){

        cache_info->code = ngx_atotm(buf + 5, size - 5);
        if (cache_info->code != NGX_ERROR){
            cache_info->flag |= CACHE_INFO_SET_CODE;
        }
    }
}

static ngx_http_preload_cache_error_code_t 
ngx_handle_cache_info(ngx_http_request_t *r, 
                      ngx_http_preload_cache_info_t *cache_info)
{
    if (!((cache_info->flag & CACHE_INFO_SET_URL) &&
        ((cache_info->flag & CACHE_INFO_SET_PATH) || 
        (cache_info->flag & CACHE_INFO_SET_CODE)) &&
        (cache_info->flag & CACHE_INFO_SET_ACTION) &&
        (cache_info->flag & CACHE_INFO_SET_START) &&
        (cache_info->flag & CACHE_INFO_SET_EXPIRES))){

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "ngx_handle_cache_info,  url : %V, path : %V, flag : %d ", 
            &cache_info->url, &cache_info->path, cache_info->flag);
        return ERROR_CODE_FORMAT_ERROR;
    }

    ngx_http_preload_cache_conf_t  *pccf;
    pccf = ngx_http_get_module_loc_conf(r, ngx_http_preload_cache_module);
    if (pccf->shm_zone == NULL) {
        return ERROR_CODE_UNKOWN;
    }

    ngx_http_preload_cache_ctx_t* ctx = pccf->shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_preload_cache_error_code_t err = ERROR_CODE_OK;
    switch (cache_info->action)
    {
    case CACHE_ACTION_ADD:
    case CACHE_ACTION_UPDATE:{
            err = ngx_http_preload_cache_insert_cache(r, pccf->shm_zone, cache_info);
        }                    
        break;

    case CACHE_ACTION_DELETE:{
            ngx_http_preload_cache_delete_cache(r, pccf->shm_zone, cache_info);
        }
        break;

    default:{
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ngx_handle_cache_info,  url : %V, path : %V, action : %d ", 
                &cache_info->url, &cache_info->path, cache_info->action);

            err = ERROR_CODE_FORMAT_ERROR;
        }
        break;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return err;
}

static void
ngx_parse_cache_info(ngx_http_request_t *r, 
                     ngx_http_preload_cache_info_t* cache_info, 
                     u_char *buf)
{
    ngx_int_t len;
    u_char *p;
    while(1){

        p = (u_char *) ngx_strstr(buf, "\r\n");

        if (!p){
            break;
        }

        len = p - buf;
        *p = '\0';
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_parse_cache_info, buf : %s, n : %d", 
            buf, p - buf);

        ngx_parse_cache_info_line(cache_info, buf, len);
        p += 2;
        buf = p;
    }
}

static void
ngx_init_http_preload_cache_info(ngx_http_preload_cache_info_t* cache_info)
{
    cache_info->code = NGX_HTTP_OK;
    cache_info->action = 0;
    cache_info->flag = 0;
    cache_info->expires = 0;
    cache_info->start = 0;
    ngx_str_null(&cache_info->url);
    ngx_str_null(&cache_info->path);
    ngx_str_null(&cache_info->disposition);
}

static ngx_http_preload_cache_error_code_t 
ngx_parse_and_handle_cache_info(ngx_http_request_t *r, u_char *buf)
{
    ngx_http_preload_cache_info_t cache_info;
    ngx_init_http_preload_cache_info(&cache_info);
    ngx_parse_cache_info(r, &cache_info, buf);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_parse_and_handle_cache_info,  url : %V, path : %V, flag : %d", 
        &cache_info.url, &cache_info.path, cache_info.flag);

    return ngx_handle_cache_info(r, &cache_info);
}

static ngx_http_preload_cache_error_code_t
ngx_parse_and_handle_cache_infos(ngx_http_request_t *r, 
                                 u_char *buf, 
                                 ssize_t *offset)
{
    ngx_http_preload_cache_error_code_t err = ERROR_CODE_OK; 
    u_char *p, *q = buf;
    while(1){

        p = (u_char *) ngx_strstr(q, "\r\n\r\n");

        if (!p){
            break;
        }
        
        p += 3;
        *p = '\0';

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_parse_and_handle_cache_infos, buf : %s, len : %d, err : %d", 
            q, p - q, err);

        err = ngx_parse_and_handle_cache_info(r, q);
        if (err != ERROR_CODE_OK){
            break;
        }
        
        ++p;
        q = p;
    }

    *offset = q - buf;

    return err;
}


static ngx_http_preload_cache_error_code_t
ngx_parse_and_handle_cache_ts(ngx_http_request_t *r, 
                              u_char *buf, 
                              ssize_t *offset,
                              time_t *last_ts)
{
    u_char    *p;
    ngx_int_t len;
    time_t    ts;
    ngx_http_preload_cache_error_code_t err = ERROR_CODE_OK;

    p = (u_char *) ngx_strstr(buf, "\r\n");
    if (!p){
        return ERROR_CODE_FORMAT_ERROR;
    }

    *offset = p - buf + 2;
    *p = '\0';

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_parse_and_handle_cache_ts, buf : %s, n : %d", 
        buf, p - buf);

    len = p - buf;
    err = ngx_parse_cache_ts_line(buf, len, &ts);
    if (err != ERROR_CODE_OK){
        return err;
    }

    ngx_http_preload_cache_conf_t  *pccf;
    pccf = ngx_http_get_module_loc_conf(r, ngx_http_preload_cache_module);
    if (pccf->shm_zone == NULL) {
        return ERROR_CODE_UNKOWN;
    }

    ngx_http_preload_cache_ctx_t* ctx = pccf->shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);
    *last_ts = ctx->sh->ts;
    ctx->sh->ts = ts;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return ERROR_CODE_OK;
}


static ngx_http_preload_cache_error_code_t
ngx_parse_cache_ts_line(u_char *buf, 
                        ssize_t size,
                        time_t *ts)
{
    if (ngx_strncmp(buf, "ts:", 3) == 0) {

        *ts = ngx_atotm(buf + 3, size - 3);
        return ERROR_CODE_OK;

    } else{
        return ERROR_CODE_FORMAT_ERROR;
    }
}


static void
ngx_http_preload_cache_update_post_handler(ngx_http_request_t *r)
{
    ngx_http_preload_cache_error_code_t err = ERROR_CODE_OK;
    u_char     buf[NGX_PRELOAD_CACHE_BUFFER];
    u_char     *q;
    ssize_t    n;
    ssize_t    offset = 0;
    ssize_t    handle_len = 0;
    ssize_t    ts_len = 0;
    time_t     last_ts = 0;
    ngx_int_t  frist = 1;

    while(1){

        n = ngx_read_file(&r->request_body->temp_file->file, buf, 
            NGX_PRELOAD_CACHE_BUFFER, offset);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                ngx_read_file_n " \"%s\" failed", 
                r->request_body->temp_file->file.name);
            break;
        }

        q = buf;

        if (n == NGX_PRELOAD_CACHE_BUFFER){

            *(q + n - 1 ) = '\0';

        }else{

            *(q + n) = '\0';
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_http_preload_cache_update_post_handler, "
            "buf: %s, n : %d, offset : %d", q, n, offset);

        if (frist){

            frist = 0;

            err = ngx_parse_and_handle_cache_ts(r, q, &ts_len, &last_ts);
            if (err != ERROR_CODE_OK){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_preload_cache_update_post_handler, "
                    "ngx_parse_and_handle_cache_ts err : ", err);
                break; 
            }

            q += ts_len;
            offset += ts_len;

            ts_len = 0;
        }
        
        err = ngx_parse_and_handle_cache_infos(r, q, &handle_len);

        offset += handle_len;

        if (n < NGX_PRELOAD_CACHE_BUFFER || err != ERROR_CODE_OK){
            break;
        }
    }

    ngx_http_preload_cache_display_cache(r);

    ngx_http_finalize_request(r, ngx_http_preload_cache_response(r, err, last_ts));

    return;
}

static ngx_str_t *
ngx_build_response_body(ngx_http_request_t *r, 
                        ngx_http_preload_cache_error_code_t err,
                        time_t last_ts)
{
    u_char body_buf[NGX_PRELOAD_CACHE_RESPONSE_BODY_BUFFER] = {'\0'};
    ngx_sprintf(body_buf, "code:%d\r\nlast_ts:%T\r\n", (ngx_int_t)err, last_ts);

    ngx_str_t *body = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    body->len = ngx_strlen(body_buf);
    body->data = ngx_pcalloc(r->pool, body->len);
    ngx_memcpy(body->data, body_buf, body->len);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_build_response_body, body: %V, len : %d", body, body->len);

    return body;
}

static ngx_int_t
ngx_http_preload_cache_response(ngx_http_request_t *r, 
                                ngx_http_preload_cache_error_code_t err,
                                time_t last_ts)
{
    ngx_int_t rc;
    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t *response = ngx_build_response_body(r, err, last_ts);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response->len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
        return rc;
    }

    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, response->len);
    if (b == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, response->data, response->len);
    b->last = b->pos + response->len;
    b->last_buf = 1;

    ngx_chain_t    out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t 
ngx_http_preload_cache_clear_cache(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_preload_cache_conf_t  *pccf;
    ngx_http_preload_cache_ctx_t   *ctx;

    pccf = ngx_http_get_module_loc_conf(r, ngx_http_preload_cache_module);
    if (pccf->shm_zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = pccf->shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_preload_cache_do_clear_cache(r);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    ngx_http_preload_cache_display_cache(r);

    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response = ngx_string("code:0\r\n");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
        return rc;
    }

    ngx_buf_t                 *b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL){
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    ngx_chain_t	out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t 
ngx_http_preload_cache_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_preload_cache_conf_t  *pccf;

    pccf = ngx_http_get_module_loc_conf(r, ngx_http_preload_cache_module);
    if (pccf->shm_zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_http_preload_cache_handler, uri : %V", &r->uri);

    if (r->method == NGX_HTTP_POST){

        if (r->uri.len >= 13 && 
            ngx_strncmp(r->uri.data, "/cache_update", 13) == 0){

            r->request_body_in_file_only = 1;
            r->request_body_in_clean_file = 1;

            rc = ngx_http_read_client_request_body(r, 
                ngx_http_preload_cache_update_post_handler);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            return NGX_DONE;
        }
        else if (r->uri.len >= 12 && 
            ngx_strncmp(r->uri.data, "/cache_clear", 12) == 0){

            ngx_int_t rc = ngx_http_discard_request_body(r);
            if (rc != NGX_OK){
                return rc;
            }

            return ngx_http_preload_cache_clear_cache(r);

        }else{
            return NGX_HTTP_NOT_FOUND;
        }
    }

    return NGX_HTTP_NOT_ALLOWED;
}


static void
ngx_http_preload_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_preload_cache_node_t   *pcn, *pcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            pcn = (ngx_http_preload_cache_node_t *) &node->color;
            pcnt = (ngx_http_preload_cache_node_t *) &temp->color;

            p = (ngx_memn2cmp(pcn->data, pcnt->data, pcn->url_len, pcnt->url_len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

ngx_int_t
ngx_http_preload_cache_find_cache(ngx_http_request_t *r, 
                                  ngx_shm_zone_t *shm_zone, 
                                  ngx_str_t *url, 
                                  ngx_str_t *path,
                                  ngx_str_t *disposition)
{
    ngx_int_t                      code;
    ngx_http_preload_cache_node_t *node;
    ngx_http_preload_cache_ctx_t  *ctx;

    ctx = shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    node = ngx_http_preload_cache_lookup(shm_zone, url);
    if (!node){

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_DECLINED;
    }

    time_t now = time(NULL);
    if (now > node->start && (now < node->expires || node->expires == 0)){
        
        path->len = node->path_len;
        path->data = ngx_pcalloc(r->pool, path->len + 1);
        ngx_memcpy(path->data, node->data + node->url_len, path->len);
        *(path->data + path->len) = '\0';

        disposition->len = node->disposition_len;
        disposition->data = ngx_pcalloc(r->pool, disposition->len);
        ngx_memcpy(disposition->data, 
            node->data + node->url_len + node->path_len, disposition->len);
        
        code = node->code;

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "hit url, ngx_http_preload_cache_find_cache, url : %V , path : %V ,"
            " disposition : %V , code : %d .", url, path, disposition, code);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return code;
    }
    else{
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "cache expires, ngx_http_preload_cache_find_cache, url : %V , now :" 
            "%T , start : %T, expires: %T", 
            url, now, node->start, node->expires);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_DECLINED;
    }    
}


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


static ngx_int_t
ngx_http_preload_cache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                        len;
    ngx_http_preload_cache_ctx_t  *ctx;
    ngx_http_preload_cache_ctx_t  *octx = data;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_preload_cache_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ctx->sh->ts = 0;
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_preload_cache_rbtree_insert_value);

    len = sizeof(" in preload_cache zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in preload_cache zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static char *
ngx_http_preload_cache_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                        *p;
    size_t                        size;
    ngx_str_t                     *value, name, s;
    ngx_uint_t                    i;
    ngx_shm_zone_t                *shm_zone;
    ngx_http_preload_cache_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                *p = '\0';

                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_STDERR, cf, 0,
                               "invalid zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_preload_cache_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_STDERR, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_preload_cache_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_STDERR, cf, 0,
                   "preload_cache_zone already exist");
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_preload_cache_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_preload_cache(ngx_conf_t * cf, ngx_command_t * cmd, void * conf)
{
    ngx_str_t   *value, s;
    ngx_uint_t   i;
    ngx_http_preload_cache_conf_t  *pccf = conf;
    ngx_http_core_loc_conf_t  *clcf;

    if (pccf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            pccf->shm_zone = ngx_shared_memory_add(cf, &s, 0,
                &ngx_http_preload_cache_module);
            if (pccf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    if (pccf->shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"%V\" must have \"zone\" parameter",
            &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (pccf->shm_zone->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown limit_req_zone \"%V\"",
            &pccf->shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_preload_cache_handler;

    return NGX_CONF_OK;
}

static void *
ngx_http_preload_cache_create_conf(ngx_conf_t *cf)
{
    ngx_http_preload_cache_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_preload_cache_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->shm_zone = NULL;

    return conf;
}


static char *
ngx_http_preload_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_preload_cache_conf_t *prev = parent;
    ngx_http_preload_cache_conf_t *conf = child;

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    return NGX_CONF_OK;
}