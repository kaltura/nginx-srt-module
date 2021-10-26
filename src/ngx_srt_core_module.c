
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_srt.h"


static ngx_int_t ngx_srt_core_preconfiguration(ngx_conf_t *cf);
static void *ngx_srt_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_srt_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_srt_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_srt_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_srt_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_srt_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_srt_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_srt_core_commands[] = {

    { ngx_string("variables_hash_max_size"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SRT_MAIN_CONF_OFFSET,
      offsetof(ngx_srt_core_main_conf_t, variables_hash_max_size),
      NULL },

    { ngx_string("variables_hash_bucket_size"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SRT_MAIN_CONF_OFFSET,
      offsetof(ngx_srt_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { ngx_string("server"),
      NGX_SRT_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_srt_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_SRT_SRV_CONF|NGX_CONF_1MORE,
      ngx_srt_core_listen,
      NGX_SRT_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("error_log"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_1MORE,
      ngx_srt_core_error_log,
      NGX_SRT_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("in_buf_size"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, in_buf_size),
      NULL },


    { ngx_string("fc_pkts"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.fc_pkts),
      NULL },

    { ngx_string("mss"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.mss),
      NULL },


    { ngx_string("recv_buf"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.recv_buf),
      NULL },

    { ngx_string("recv_udp_buf"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.recv_udp_buf),
      NULL },

    { ngx_string("recv_latency"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.recv_latency),
      NULL },


    { ngx_string("send_buf"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.send_buf),
      NULL },

    { ngx_string("send_udp_buf"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.send_udp_buf),
      NULL },

    { ngx_string("send_latency"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_core_srv_conf_t, srt_opts.send_latency),
      NULL },

      ngx_null_command
};


static ngx_srt_module_t  ngx_srt_core_module_ctx = {
    ngx_srt_core_preconfiguration,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_srt_core_create_main_conf,         /* create main configuration */
    ngx_srt_core_init_main_conf,           /* init main configuration */

    ngx_srt_core_create_srv_conf,          /* create server configuration */
    ngx_srt_core_merge_srv_conf            /* merge server configuration */
};


ngx_module_t  ngx_srt_core_module = {
    NGX_MODULE_V1,
    &ngx_srt_core_module_ctx,              /* module context */
    ngx_srt_core_commands,                 /* module directives */
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
ngx_srt_core_preconfiguration(ngx_conf_t *cf)
{
    return ngx_srt_variables_add_core_vars(cf);
}


static void *
ngx_srt_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_srt_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_srt_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_srt_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listening, cf->pool, 4, sizeof(ngx_listening_t))
        != NGX_OK)
    {
        return NULL;
    }

    cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_srt_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_srt_core_main_conf_t  *cmcf = conf;

    ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NGX_CONF_OK;
}


static void *
ngx_srt_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_srt_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_srt_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     *     cscf->listen = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->in_buf_size = NGX_CONF_UNSET_SIZE;

    ngx_memset(&cscf->srt_opts, 0xff, sizeof(cscf->srt_opts));

    return cscf;
}


static char *
ngx_srt_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_srt_core_srv_conf_t  *prev = parent;
    ngx_srt_core_srv_conf_t  *conf = child;

    if (conf->handler == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    ngx_conf_merge_size_value(conf->in_buf_size, prev->in_buf_size, 64 * 1024);

    ngx_srt_merge_options(&conf->srt_opts, &prev->srt_opts);

    return NGX_CONF_OK;
}


static char *
ngx_srt_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_srt_core_srv_conf_t  *cscf = conf;

    return ngx_log_set_log(cf, &cscf->error_log);
}


static char *
ngx_srt_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                      *rv;
    void                      *mconf;
    ngx_uint_t                 m;
    ngx_conf_t                 pcf;
    ngx_srt_module_t          *module;
    ngx_srt_conf_ctx_t        *ctx, *srt_ctx;
    ngx_srt_core_srv_conf_t   *cscf, **cscfp;
    ngx_srt_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_srt_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    srt_ctx = cf->ctx;
    ctx->main_conf = srt_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_srt_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SRT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_srt_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_srt_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_SRT_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_srt_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_srt_core_srv_conf_t    *cscf = conf;

    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i, n;
    ngx_srt_listen_t           *ls, *als;

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

    if (cscf->listen == NULL) {
        cscf->listen = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_srt_listen_t));
        if (cscf->listen == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ls = ngx_array_push_n(cscf->listen, u.naddrs);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_srt_listen_t));

    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->type = SOCK_DGRAM;
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                ls->ipv6only = 1;

            } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                ls->ipv6only = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return NGX_CONF_ERROR;
            }

            ls->bind = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    als = cscf->listen->elts;

    for (n = 0; n < u.naddrs; n++) {
        ls[n] = ls[0];

        ls[n].sockaddr = u.addrs[n].sockaddr;
        ls[n].socklen = u.addrs[n].socklen;
        ls[n].addr_text = u.addrs[n].name;

        /* Note: forcing wildcard to off, if it is on, nginx enables
            IP_PKTINFO on the socket, which breaks libsrt */
        ls[n].wildcard = 0;

        for (i = 0; i < cscf->listen->nelts - u.naddrs + n; i++) {
            if (ls[n].type != als[i].type) {
                continue;
            }

            if (ngx_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
                                 ls[n].sockaddr, ls[n].socklen, 1)
                != NGX_OK)
            {
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" address and port pair",
                               &ls[n].addr_text);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
