
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_srt.h"


static ngx_int_t ngx_srt_upstream_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_srt_upstream_addr_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_srt_upstream_response_time_variable(
    ngx_srt_session_t *s, ngx_srt_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_srt_upstream_bytes_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data);


static ngx_srt_module_t  ngx_srt_upstream_module_ctx = {
    ngx_srt_upstream_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_srt_upstream_module = {
    NGX_MODULE_V1,
    &ngx_srt_upstream_module_ctx,          /* module context */
    NULL,                                  /* module directives */
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


static ngx_srt_variable_t  ngx_srt_upstream_vars[] = {

    { ngx_string("upstream_addr"), NULL,
      ngx_srt_upstream_addr_variable, 0,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_bytes_sent"), NULL,
      ngx_srt_upstream_bytes_variable, 0,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_connect_time"), NULL,
      ngx_srt_upstream_response_time_variable, 2,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_first_byte_time"), NULL,
      ngx_srt_upstream_response_time_variable, 1,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_session_time"), NULL,
      ngx_srt_upstream_response_time_variable, 0,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_bytes_received"), NULL,
      ngx_srt_upstream_bytes_variable, 1,
      NGX_SRT_VAR_NOCACHEABLE, 0 },

      ngx_srt_null_variable
};


static ngx_int_t
ngx_srt_upstream_add_variables(ngx_conf_t *cf)
{
    ngx_srt_variable_t  *var, *v;

    for (v = ngx_srt_upstream_vars; v->name.len; v++) {
        var = ngx_srt_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_upstream_addr_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    size_t                     len;
    ngx_uint_t                 i;
    ngx_srt_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = 0;
    state = s->upstream_states->elts;

    for (i = 0; i < s->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len;
        }

        len += 2;
    }

    p = ngx_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = ngx_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_srt_upstream_bytes_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    size_t                     len;
    ngx_uint_t                 i;
    ngx_srt_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = s->upstream_states->nelts * (NGX_OFF_T_LEN + 2);

    p = ngx_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = ngx_sprintf(p, "%O", state[i].bytes_received);

        } else {
            p = ngx_sprintf(p, "%O", state[i].bytes_sent);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_srt_upstream_response_time_variable(ngx_srt_session_t *s,
    ngx_srt_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    size_t                     len;
    ngx_uint_t                 i;
    ngx_msec_int_t             ms;
    ngx_srt_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = s->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            ms = state[i].first_byte_time;

        } else if (data == 2) {
            ms = state[i].connect_time;

        } else {
            ms = state[i].response_time;
        }

        if (ms != -1) {
            ms = ngx_max(ms, 0);
            p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NGX_OK;
}
