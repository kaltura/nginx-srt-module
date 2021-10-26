#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_srt.h"


#define NGX_SRT_SESSION       0x53545253     /* "SRTS" */

#define NGX_INVALID_SOCKET  ((ngx_socket_t) -1)


static char *ngx_srt_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_srt_init_phases(ngx_conf_t *cf,
    ngx_srt_core_main_conf_t *cmcf);

static ngx_int_t ngx_srt_create_listening(ngx_conf_t *cf);
static char *ngx_srt_init_listening(ngx_cycle_t *cycle, void *conf);

static void ngx_srt_conn_handler(ngx_connection_t *c);
static void ngx_srt_log_session(void *data);


ngx_uint_t  ngx_srt_max_module;


ngx_srt_filter_pt  ngx_srt_top_filter;


static ngx_command_t  ngx_srt_commands[] = {

    { ngx_string("srt"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_srt_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_srt_module_ctx = {
    ngx_string("srt"),
    NULL,
    ngx_srt_init_listening,
};


ngx_module_t  ngx_srt_module = {
    NGX_MODULE_V1,
    &ngx_srt_module_ctx,                   /* module context */
    ngx_srt_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_srt_init_worker,                   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_srt_exit_worker,                   /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_srt_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_uint_t                  m, mi, s;
    ngx_conf_t                  pcf;
    ngx_srt_module_t           *module;
    ngx_srt_conf_ctx_t         *ctx;
    ngx_srt_core_srv_conf_t   **cscfp;
    ngx_srt_core_main_conf_t   *cmcf;

    if (*(ngx_srt_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main srt context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_srt_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_srt_conf_ctx_t **) conf = ctx;

    /* count the number of the srt modules and set up their indices */

    ngx_srt_max_module = ngx_count_modules(cf->cycle, NGX_SRT_MODULE);


    /* the srt main_conf context, it's the same in the all srt contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_srt_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the srt null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_srt_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all srt modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SRT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SRT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the srt{} block */

    cf->module_type = NGX_SRT_MODULE;
    cf->cmd_type = NGX_SRT_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init srt{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_srt_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SRT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init srt{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    if (ngx_srt_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_SRT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_srt_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_srt_create_listening(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *cf = pcf;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_srt_init_phases(ngx_conf_t *cf, ngx_srt_core_main_conf_t *cmcf)
{
    if (ngx_array_init(&cmcf->phases[NGX_SRT_PRE_LOG_PHASE].handlers,
        cf->pool, 1, sizeof(ngx_srt_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_SRT_LOG_PHASE].handlers,
        cf->pool, 1, sizeof(ngx_srt_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_create_listening(ngx_conf_t *cf)
{
    ngx_uint_t                  s, n;
    ngx_cycle_t                *cycle;
    ngx_listening_t            *ls;
    ngx_srt_listen_t           *opt, *opts;
    ngx_srt_core_srv_conf_t   **cscfp, *cscf;
    ngx_srt_core_main_conf_t   *cmcf;

    cmcf = ngx_srt_conf_get_module_main_conf(cf, ngx_srt_core_module);

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {

        cscf = ngx_srt_conf_get_module_srv_conf(cscfp[s],
            ngx_srt_core_module);

        opts = cscf->listen->elts;
        for (n = 0; n < cscf->listen->nelts; n++) {

            opt = &opts[n];

            /* trick ngx_create_listening to add the socket to cmcf */

            cycle = cf->cycle;
            cf->cycle = (void *)((u_char *) &cmcf->listening -
                offsetof(ngx_cycle_t, listening));

            ls = ngx_create_listening(cf, opt->sockaddr, opt->socklen);

            cf->cycle = cycle;

            if (ls == NULL) {
                return NGX_ERROR;
            }

            /*
             * set by ngx_memzero():
             *
             *      ls->log.handler = NULL;
             */

            ls->addr_ntop = 1;
            ls->handler = ngx_srt_conn_handler;
            ls->pool_size = 256;
            ls->type = opt->type;

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;

            ls->backlog = opt->backlog;

            ls->wildcard = opt->wildcard;

#if (NGX_HAVE_INET6)
            ls->ipv6only = opt->ipv6only;
#endif

#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = opt->reuseport;
#endif

            ls->servers = opt->ctx;
        }
    }

    return NGX_OK;
}


static char *
ngx_srt_init_listening(ngx_cycle_t *cycle, void *conf)
{
    ngx_int_t                  rc;
    ngx_uint_t                 i, n;
    ngx_uint_t                 orig_flags;
    ngx_cycle_t               *old_cycle;
    ngx_cycle_t                dummy_cycle;
    ngx_array_t                listening;
    ngx_array_t                old_listening;
    ngx_listening_t           *ls, *nls;
    ngx_srt_core_main_conf_t  *old_cmcf;
    ngx_srt_core_main_conf_t  *cmcf;

    if (ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_CONF_OK;
    }

    old_cycle = cycle->old_cycle;

    if (old_cycle->conf_ctx != NULL) {
        old_cmcf = ngx_srt_cycle_get_module_main_conf(old_cycle,
            ngx_srt_core_module);
        old_listening = old_cmcf->listening;

    } else {
        old_listening.nelts = 0;
        old_listening.elts = NULL;
    }

    cmcf = ngx_srt_cycle_get_module_main_conf(cycle, ngx_srt_core_module);
    if (cmcf != NULL) {
        listening = cmcf->listening;

    } else {
        listening.nelts = 0;
        listening.elts = NULL;
    }

    /* Note: code copied from ngx_init_cycle */

    /* handle the listening sockets */

    if (old_listening.nelts) {
        ls = old_listening.elts;
        for (i = 0; i < old_listening.nelts; i++) {
            ls[i].remain = 0;
        }

        nls = listening.elts;
        for (n = 0; n < listening.nelts; n++) {

            for (i = 0; i < old_listening.nelts; i++) {
                if (ls[i].ignore) {
                    continue;
                }

                if (ls[i].remain) {
                    continue;
                }

                if (ls[i].type != nls[n].type) {
                    continue;
                }

                if (ngx_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
                    ls[i].sockaddr, ls[i].socklen, 1)
                    == NGX_OK)
                {
                    nls[n].fd = ls[i].fd;
                    nls[n].previous = &ls[i];
                    ls[i].remain = 1;

                    if (ls[i].backlog != nls[n].backlog) {
                        nls[n].listen = 1;
                    }

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                    /*
                     * FreeBSD, except the most recent versions,
                     * could not remove accept filter
                     */
                    nls[n].deferred_accept = ls[i].deferred_accept;

                    if (ls[i].accept_filter && nls[n].accept_filter) {
                        if (ngx_strcmp(ls[i].accept_filter,
                            nls[n].accept_filter)
                            != 0)
                        {
                            nls[n].delete_deferred = 1;
                            nls[n].add_deferred = 1;
                        }

                    } else if (ls[i].accept_filter) {
                        nls[n].delete_deferred = 1;

                    } else if (nls[n].accept_filter) {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                    if (ls[i].deferred_accept && !nls[n].deferred_accept) {
                        nls[n].delete_deferred = 1;

                    } else if (ls[i].deferred_accept != nls[n].deferred_accept)
                    {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (NGX_HAVE_REUSEPORT)
                    if (nls[n].reuseport && !ls[i].reuseport) {
                        nls[n].add_reuseport = 1;
                    }
#endif

                    break;
                }
            }

            if (nls[n].fd == NGX_INVALID_SOCKET) {
                nls[n].open = 1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                if (nls[n].accept_filter) {
                    nls[n].add_deferred = 1;
                }
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
                if (nls[n].deferred_accept) {
                    nls[n].add_deferred = 1;
                }
#endif
            }
        }

    } else {
        ls = listening.elts;
        for (i = 0; i < listening.nelts; i++) {
            ls[i].open = 1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            if (ls[i].accept_filter) {
                ls[i].add_deferred = 1;
            }
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            if (ls[i].deferred_accept) {
                ls[i].add_deferred = 1;
            }
#endif
        }
    }

    /* trick ngx_open_listening_sockets to process cmcf sockets */

    dummy_cycle.log = cycle->log;
    dummy_cycle.listening = listening;

    /* enable iocp flag to avoid setting the socket as nonblocking */

    orig_flags = ngx_event_flags;
    ngx_event_flags |= NGX_USE_IOCP_EVENT;

    rc = ngx_open_listening_sockets(&dummy_cycle);

    ngx_event_flags = orig_flags;

    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (!ngx_test_config) {
        ngx_configure_listening_sockets(&dummy_cycle);
    }

    /* close the unnecessary listening sockets */

    ls = old_listening.elts;
    for (i = 0; i < old_listening.nelts; i++) {

        if (ls[i].remain || ls[i].fd == NGX_INVALID_SOCKET) {
            continue;
        }

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                ngx_close_socket_n " listening socket on %V failed",
                &ls[i].addr_text);
        }
    }

    return NGX_CONF_OK;
}


static ngx_srt_session_t *
ngx_srt_init_session(ngx_srt_conn_t *sc)
{
    ngx_connection_t          *c;
    ngx_srt_session_t         *s;
    ngx_srt_conf_ctx_t        *ctx;
    ngx_srt_core_main_conf_t  *cmcf;

    c = sc->connection;

    s = ngx_pcalloc(c->pool, sizeof(ngx_srt_session_t));
    if (s == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_init_session: alloc session failed");
        return NULL;
    }

    s->sc = sc;

    s->signature = NGX_SRT_SESSION;

    ctx = c->listening->servers;

    s->main_conf = ctx->main_conf;
    s->srv_conf = ctx->srv_conf;

    s->connection = c;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_srt_max_module);
    if (s->ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_init_session: alloc ctx failed");
        return NULL;
    }

    cmcf = ngx_srt_get_module_main_conf(s, ngx_srt_core_module);

    s->variables = ngx_pcalloc(c->pool, cmcf->variables.nelts
                                        * sizeof(ngx_srt_variable_value_t));
    if (s->variables == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_init_session: alloc variables failed");
        return NULL;
    }

    sc->session = s;

    sc->log_session = ngx_srt_log_session;

    return s;
}


static void
ngx_srt_log_session(void *data)
{
    ngx_uint_t                 i, n;
    ngx_srt_conn_t            *sc;
    ngx_srt_session_t         *s;
    ngx_srt_handler_pt        *log_handler;
    ngx_srt_core_main_conf_t  *cmcf;

    sc = data;
    s = sc->session;

    cmcf = ngx_srt_get_module_main_conf(s, ngx_srt_core_module);

    /* pre log */

    log_handler = cmcf->phases[NGX_SRT_PRE_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_SRT_PRE_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }

    /* log */

    log_handler = cmcf->phases[NGX_SRT_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_SRT_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
ngx_srt_conn_handler(ngx_connection_t *c)
{
    ngx_srt_conn_t           *sc;
    ngx_srt_session_t        *s;
    ngx_srt_core_srv_conf_t  *cscf;

    sc = c->data;

    s = ngx_srt_init_session(sc);
    if (s == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    cscf = ngx_srt_get_module_srv_conf(s, ngx_srt_core_module);

    cscf->handler(s);
}


/* Context: SRT thread */
ngx_int_t
ngx_srt_start_listening(ngx_cycle_t *cycle)
{
    ngx_uint_t                 i;
    ngx_listening_t           *ls;
    ngx_srt_conf_ctx_t        *ctx;
    ngx_srt_core_srv_conf_t   *cscf;
    ngx_srt_core_main_conf_t  *cmcf;

    cmcf = ngx_srt_cycle_get_module_main_conf(cycle, ngx_srt_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    ls = cmcf->listening.elts;
    for (i = 0; i < cmcf->listening.nelts; i++) {
        ctx = ls[i].servers;

        cscf = ngx_srt_get_module_srv_conf(ctx, ngx_srt_core_module);

        if (ngx_srt_listen(cycle, &ls[i], cscf->error_log, cscf->in_buf_size,
            &cscf->srt_opts) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
