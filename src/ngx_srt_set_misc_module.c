#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_srt.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include <openssl/evp.h>


#define NGX_SRT_SET_MISC_CRYPT_KEY_LEN  (256 / 8)
#define NGX_SRT_SET_MISC_CRYPT_IV_LEN   EVP_MAX_IV_LENGTH


typedef struct {
    ngx_srt_complex_value_t  key;
    ngx_srt_complex_value_t  iv;
    ngx_srt_complex_value_t  value;
} ngx_srt_set_misc_crypt_ctx_t;


static char *ngx_srt_set_misc_decrypt(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif


typedef struct {
    ngx_srt_complex_value_t  value;
    unsigned                 url_safe:1;
} ngx_srt_set_misc_base64_ctx_t;


static char *ngx_srt_set_misc_base64(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_srt_set_misc_commands[] = {

    { ngx_string("set_decode_base64"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_srt_set_misc_base64,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      (void *) 0 },

    { ngx_string("set_decode_base64url"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_srt_set_misc_base64,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      (void *) 1 },

#if (NGX_HAVE_OPENSSL_EVP)
    { ngx_string("set_aes_decrypt"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE4,
      ngx_srt_set_misc_decrypt,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      NULL },
#endif

      ngx_null_command
};


static ngx_srt_module_t  ngx_srt_set_misc_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_srt_set_misc_module = {
    NGX_MODULE_V1,
    &ngx_srt_set_misc_module_ctx,          /* module context */
    ngx_srt_set_misc_commands,             /* module directives */
    NGX_SRT_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_srt_set_misc_base64_decode(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src, ngx_flag_t url_safe)
{
    dst->data = ngx_pnalloc(pool, ngx_base64_decoded_length(src->len));
    if (dst->data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_srt_set_misc_base64_decode: alloc failed");
        return NGX_ERROR;
    }

    if (url_safe) {
        if (ngx_decode_base64url(dst, src) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_srt_set_misc_base64_decode: ngx_decode_base64url failed");
            return NGX_ERROR;
        }

    } else {
        if (ngx_decode_base64(dst, src) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_srt_set_misc_base64_decode: ngx_decode_base64 failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_set_misc_base64_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                       val, decode_str;
    ngx_srt_set_misc_base64_ctx_t  *base64;

    base64 = (ngx_srt_set_misc_base64_ctx_t *) data;

    ngx_log_debug0(NGX_LOG_DEBUG_SRT, s->connection->log, 0,
        "srt base64 started");

    if (ngx_srt_complex_value(s, &base64->value, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_base64_variable: failed to eval complex value");
        return NGX_ERROR;
    }

    if (ngx_srt_set_misc_base64_decode(s->connection->pool, &decode_str, &val,
        base64->url_safe) != NGX_OK)
    {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = decode_str.len;
    v->data = decode_str.data;

    return NGX_OK;
}


static char *
ngx_srt_set_misc_base64(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                        *value, name;
    ngx_srt_variable_t               *var;
    ngx_srt_set_misc_base64_ctx_t    *base64;
    ngx_srt_compile_complex_value_t   ccv;

    base64 = ngx_pcalloc(cf->pool, sizeof(ngx_srt_set_misc_base64_ctx_t));
    if (base64 == NULL) {
        return NGX_CONF_ERROR;
    }

    base64->url_safe = (uintptr_t) cmd->post;
    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &base64->value;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_srt_add_variable(cf, &name, NGX_SRT_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_srt_set_misc_base64_variable;
    var->data = (uintptr_t) base64;

    return NGX_CONF_OK;
}


#if (NGX_HAVE_OPENSSL_EVP)
static ngx_int_t
ngx_srt_set_misc_decrypt_aes(ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *iv,
    ngx_str_t *input, ngx_str_t *dst)
{
    int                dst_len;
    size_t             block_size;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    cipher = EVP_aes_256_cbc();
    block_size = EVP_CIPHER_block_size(cipher);

    dst->data = ngx_pnalloc(pool, input->len + block_size);
    if (dst->data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_srt_set_misc_decrypt_aes: alloc failed");
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_srt_set_misc_decrypt_aes: EVP_CIPHER_CTX_new failed");
        return NGX_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key->data, iv->data)) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_srt_set_misc_decrypt_aes: EVP_DecryptInit_ex failed");
        goto failed;
    }

    if (!EVP_DecryptUpdate(ctx, dst->data,
        &dst_len, input->data, input->len))
    {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_srt_set_misc_decrypt_aes: EVP_DecryptUpdate failed");
        goto failed;
    }

    dst->len = dst_len;

    if (!EVP_DecryptFinal_ex(ctx, dst->data + dst->len, &dst_len)) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_srt_set_misc_decrypt_aes: EVP_DecryptFinal_ex failed");
        goto failed;
    }

    dst->len += dst_len;

    EVP_CIPHER_CTX_cleanup(ctx);

    return NGX_OK;

failed:

    EVP_CIPHER_CTX_cleanup(ctx);

    return NGX_ERROR;
}


ngx_int_t
ngx_srt_complex_value_base64(ngx_srt_session_t *s, ngx_srt_complex_value_t *val,
    ngx_str_t *dst)
{
    ngx_str_t value;

    if (ngx_srt_complex_value(s, val, &value) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_complex_value_base64: failed to eval complex value");
        return NGX_ERROR;
    }

    if (ngx_srt_set_misc_base64_decode(s->connection->pool, dst, &value, 0)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_complex_value_base64: base64_decode failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_set_misc_decrypt_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                      key, iv, val, decrypt_str;
    ngx_srt_set_misc_crypt_ctx_t  *decrypt;

    decrypt = (ngx_srt_set_misc_crypt_ctx_t *) data;

    ngx_log_debug0(NGX_LOG_DEBUG_SRT, s->connection->log, 0,
                   "srt decrypt started");

    if (ngx_srt_complex_value_base64(s, &decrypt->key, &key) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_decrypt_variable: "
            "ngx_srt_complex_value_base64 for key failed");
        return NGX_ERROR;
    }

    if (ngx_srt_complex_value_base64(s, &decrypt->iv, &iv) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_decrypt_variable: "
            "ngx_srt_complex_value_base64 for iv failed");
        return NGX_ERROR;
    }

    if (key.len != NGX_SRT_SET_MISC_CRYPT_KEY_LEN ||
        iv.len != NGX_SRT_SET_MISC_CRYPT_IV_LEN)
    {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_decrypt_variable: "
            "key length or iv length is not correct");
        return NGX_ERROR;
    }

    if (ngx_srt_complex_value(s, &decrypt->value, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_decrypt_variable: failed to eval val");
        return NGX_ERROR;
    }

    if (val.len <= 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_srt_set_misc_decrypt_aes(s->connection->pool, &key,
        &iv, &val, &decrypt_str) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_srt_set_misc_decrypt_variable: "
            "decrypt failed, val=\"%V\"", &val);
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = decrypt_str.len;
    v->data = decrypt_str.data;

    return NGX_OK;
}


static char *
ngx_srt_set_misc_decrypt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                        *value, name;
    ngx_srt_variable_t               *var;
    ngx_srt_set_misc_crypt_ctx_t     *decrypt;
    ngx_srt_compile_complex_value_t   ccv;

    decrypt = ngx_pcalloc(cf->pool, sizeof(ngx_srt_set_misc_crypt_ctx_t));
    if (decrypt == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &decrypt->key;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &decrypt->iv;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[4];
    ccv.complex_value = &decrypt->value;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_srt_add_variable(cf, &name, NGX_SRT_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_srt_set_misc_decrypt_variable;
    var->data = (uintptr_t) decrypt;

    return NGX_CONF_OK;
}
#endif
