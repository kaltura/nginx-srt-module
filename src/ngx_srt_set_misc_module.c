#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>
#include <openssl/md5.h>

#include "ngx_srt.h"


typedef struct {
    ngx_srt_complex_value_t  value;
} ngx_srt_base64_ctx_t;

typedef struct {
    ngx_str_t                key;
    ngx_str_t                iv;
    ngx_srt_complex_value_t  value;
} ngx_srt_encrypt_decrypt_ctx_t;

enum {
    ngx_encrypt_key_length = 256 / 8,
    ngx_encrypt_iv_length = EVP_MAX_IV_LENGTH
};


static char *ngx_srt_set_misc_decrypt(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_srt_set_misc_base64(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_srt_set_misc_commands[] = {

    { ngx_string("set_decode_base64"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_srt_set_misc_base64,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_aes_decrypt"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE4,
      ngx_srt_set_misc_decrypt,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      NULL },

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
    &ngx_srt_set_misc_module_ctx,             /* module context */
    ngx_srt_set_misc_commands,                /* module directives */
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
ngx_srt_set_misc_base64_variable(ngx_srt_session_t *s, ngx_srt_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t              val, decode_str;
    ngx_srt_base64_ctx_t  *base64;

    base64 = (ngx_srt_base64_ctx_t *) data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
        "srt base64 started");

    if (ngx_srt_complex_value(s, &base64->value, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
        "ngx_srt_set_misc_base64_variable: failed to eval complex value");
        return NGX_ERROR;
    }

    decode_str.len = ngx_base64_decoded_length(val.len);
    decode_str.data = ngx_pnalloc(s->connection->pool, decode_str.len);
    ngx_decode_base64(&decode_str, &val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = decode_str.len;
    v->data = decode_str.data;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "srt base64: \"%V\" \"%v\"", &val, v);

    return NGX_OK;
}

static char *
ngx_srt_set_misc_base64(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value, name;
    ngx_srt_variable_t              *var;
    ngx_srt_base64_ctx_t            *base64;
    ngx_srt_compile_complex_value_t  ccv;

    base64 = ngx_pcalloc(cf->pool, sizeof(ngx_srt_base64_ctx_t));
    if (base64 == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &base64->value;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    name = value[2];

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


ngx_int_t
ngx_srt_set_misc_decrypt_aes(ngx_connection_t *c, ngx_str_t key,
    ngx_str_t iv, ngx_str_t input, ngx_str_t *dst)
{
    size_t             block_size, buf_size;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    if (key.len != ngx_encrypt_key_length || iv.len < MD5_DIGEST_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_srt_set_misc_decrypt_aes:"
            "key length and iv length is not correct");
        return NGX_ERROR;
    }

    cipher = EVP_aes_256_cbc();
    block_size = EVP_CIPHER_block_size(cipher);
    buf_size = input.len + block_size /* for EVP_DecryptUpdate */
                       + block_size; /* for EVP_DecryptFinal_ex */

    dst->len = buf_size;
    dst->data = ngx_palloc(c->pool, buf_size);
    if (dst->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_srt_set_misc_decrypt_aes:"
            "alloc failed");
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key.data, iv.data))
    {
       ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_srt_set_misc_decrypt_aes:"
            "EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        return NGX_ERROR;
    }

    if (!EVP_DecryptUpdate(ctx, dst->data, (int *) &dst->len, input.data, input.len))
    {
       ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_srt_set_misc_decrypt_aes:"
            "EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        return NGX_ERROR;
    }

    if (!EVP_DecryptFinal_ex(ctx, dst->data + dst->len, (int *) &dst->len))
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_srt_set_misc_decrypt_aes:"
            "EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_srt_set_misc_decrypt_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    ngx_str_t               val, decrypt_str;
    ngx_srt_encrypt_decrypt_ctx_t  *decrypt;

    decrypt = (ngx_srt_encrypt_decrypt_ctx_t *) data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "srt decrypt started");

    if (ngx_srt_complex_value(s, &decrypt->value, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
        "ngx_srt_set_misc_decrypt_variable: failed to eval complex value");
        return NGX_ERROR;
    }

    decrypt_str.len = val.len;
    decrypt_str.data = val.data;

    ngx_srt_set_misc_decrypt_aes(s->connection, decrypt->key, decrypt->iv,
        val, &decrypt_str);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = decrypt_str.len;
    v->data = decrypt_str.data;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "srt decrypt: \"%V\" \"%v\"", &val, v);

    return NGX_OK;
}

static char *
ngx_srt_set_misc_decrypt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                        *value, name;
    ngx_srt_variable_t               *var;
    ngx_srt_encrypt_decrypt_ctx_t    *decrypt;
    ngx_srt_compile_complex_value_t   ccv;

    decrypt = ngx_pcalloc(cf->pool, sizeof(ngx_srt_encrypt_decrypt_ctx_t));
    if (decrypt == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    decrypt->key = value[1];
    decrypt->iv  = value[2];

    ngx_memzero(&ccv, sizeof(ngx_srt_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &decrypt->value;

    if (ngx_srt_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    name = value[4];

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