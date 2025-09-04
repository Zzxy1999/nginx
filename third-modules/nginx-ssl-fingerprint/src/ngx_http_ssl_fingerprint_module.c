
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <nginx_ssl_fingerprint.h>

static ngx_int_t ngx_http_ssl_fingerprint_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_ja3_fp(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_http2_fp(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_header(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_cipher(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_ext(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_hash(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_module_t ngx_http_ssl_fingerprint_module_ctx = {
    ngx_http_ssl_fingerprint_init,  /* preconfiguration */
    NULL,                           /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx, /* module context */
    NULL,                                 /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_variable_t ngx_http_ssl_fingerprint_variables_list[] = {
    {ngx_string("http_ssl_ja3_fp"), NULL, ngx_http_ssl_ja3_fp,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja3_hash"), NULL, ngx_http_ssl_ja3_hash,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http2_fingerprint"), NULL, ngx_http_http2_fp,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja4_header"), NULL, ngx_http_ssl_ja4_header,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja4_cipher"), NULL, ngx_http_ssl_ja4_cipher,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja4_ext"), NULL, ngx_http_ssl_ja4_ext,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja4_hash"), NULL, ngx_http_ssl_ja4_hash,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    ngx_http_null_variable
};

static ngx_int_t
ngx_http_ssl_ja3_fp(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja_data(r->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja3_str.data;
    v->len = r->connection->ssl->fp_ja3_str.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3_hash(r->connection) != NGX_OK) {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_hash.data;
    v->len = r->connection->ssl->fp_ja3_hash.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_http2_fp(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->stream == NULL) {
        return NGX_OK;
    }

    if (ngx_http2_fingerprint(r->connection, r->stream->connection)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    v->data = r->stream->connection->fp_str.data;
    v->len = r->stream->connection->fp_str.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_fingerprint_init(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_fingerprint_variables_list; v->name.len; v++) {

        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        /** NOTE: update it, if set_handler will be needed */
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4_header(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_header(r->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_header.data;
    v->len = r->connection->ssl->fp_ja4_header.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4_cipher(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_cipher(r->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_cipher.data;
    v->len = r->connection->ssl->fp_ja4_cipher.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4_ext(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_ext(r->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_ext.data;
    v->len = r->connection->ssl->fp_ja4_ext.len;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4_hash(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_hash(r->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_hash.data;
    v->len = r->connection->ssl->fp_ja4_hash.len;
    v->not_found = 0;

    return NGX_OK;
}

