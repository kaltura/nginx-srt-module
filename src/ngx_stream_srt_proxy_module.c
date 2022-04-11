#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_srt.h"


typedef struct {
    ngx_url_t                    *url;
    ngx_msec_t                    connect_timeout;
    ngx_msec_t                    timeout;
    size_t                        buffer_size;
    ngx_stream_complex_value_t   *stream_id;
    ngx_stream_complex_value_t   *passphrase;
} ngx_stream_srt_proxy_srv_conf_t;


typedef struct {
    ngx_stream_upstream_state_t  *state;
    ngx_msec_t                    start_time;
} ngx_stream_srt_proxy_upstream_t;


static void ngx_stream_srt_proxy_srt_handler(ngx_event_t *ev);
static void ngx_stream_srt_proxy_ngx_handler(ngx_event_t *ev);
static void ngx_stream_srt_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_srt_proxy_test_finalize(ngx_srt_conn_t *sc,
    ngx_uint_t from_upstream);
static u_char *ngx_stream_srt_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);
static void ngx_stream_srt_proxy_log_session(void *data);
static void ngx_stream_srt_proxy_cleanup(void *data);

static void *ngx_stream_srt_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_srt_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_srt_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_srt_proxy_commands[] = {

    { ngx_string("srt_proxy_pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_srt_proxy_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("srt_proxy_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_srt_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("srt_proxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_srt_proxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("srt_proxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_srt_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("srt_proxy_stream_id"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_srt_proxy_srv_conf_t, stream_id),
      NULL },

    { ngx_string("srt_proxy_passphrase"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_srt_proxy_srv_conf_t, passphrase),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_srt_proxy_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_srt_proxy_create_srv_conf,     /* create server configuration */
    ngx_stream_srt_proxy_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_stream_srt_proxy_module = {
    NGX_MODULE_V1,
    &ngx_stream_srt_proxy_module_ctx,         /* module context */
    ngx_stream_srt_proxy_commands,            /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_srt_proxy_handler(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_str_t                         stream_id;
    ngx_str_t                         passphrase;
    ngx_chain_t                      *cl;
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *c, *pc;
    ngx_srt_stream_t                 *st;
    ngx_pool_cleanup_t               *cln;
    ngx_stream_upstream_state_t      *state;
    ngx_stream_srt_proxy_upstream_t  *u;
    ngx_stream_srt_proxy_srv_conf_t  *pscf;

    c = s->connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_srt_proxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "ngx_stream_srt_proxy_handler: called");

    if (pscf->stream_id) {
        if (ngx_stream_complex_value(s, pscf->stream_id, &stream_id)
            != NGX_OK)
        {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        stream_id.len = 0;
    }

    if (pscf->passphrase) {
        if (ngx_stream_complex_value(s, pscf->passphrase, &passphrase)
            != NGX_OK)
        {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        passphrase.len = 0;
    }

    c->log->action = "connecting to upstream";

    sc = ngx_srt_conn_create_connect(s->connection->log, pscf->url,
        pscf->buffer_size, &stream_id, &passphrase);
    if (sc == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    cln = ngx_pool_cleanup_add(sc->connection->pool, 0);
    if (cln == NULL) {
        ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_stream_srt_proxy_cleanup;
    cln->data = sc;

    sc->log_session = ngx_stream_srt_proxy_log_session;

    ngx_stream_set_ctx(s, sc, ngx_stream_srt_proxy_module);
    sc->session = s;

    st = ngx_pcalloc(c->pool, sizeof(ngx_srt_stream_t));
    if (st == NULL) {
        ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Note: not setting close_conn - connection owned by stream module */
    st->connection = c;
    st->connected = 1;

    sc->stream = st;

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
            "stream srt proxy add preread buffer: %uz",
            c->buffer->last - c->buffer->pos);

        cl = ngx_chain_get_free_buf(c->pool, &st->free);
        if (cl == NULL) {
            ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (ngx_buf_tag_t) &ngx_srt_module;
        cl->buf->temporary = 1;
        cl->buf->flush = 1;

        cl->next = st->out;
        st->out = cl;

        st->received += cl->buf->last - cl->buf->pos;
    }

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_srt_proxy_upstream_t));
    if (u == NULL) {
        ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->start_time = ngx_current_msec;

    sc->upstream = u;

    s->log_handler = ngx_stream_srt_proxy_log_error;

    c->read->handler = ngx_stream_srt_proxy_ngx_handler;
    c->write->handler = ngx_stream_srt_proxy_ngx_handler;

    s->upstream_states = ngx_array_create(c->pool, 1,
        sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    state = ngx_array_push(s->upstream_states);
    if (state == NULL) {
        ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(state, sizeof(*state));

    state->connect_time = (ngx_msec_t) -1;
    state->first_byte_time = (ngx_msec_t) -1;
    state->response_time = (ngx_msec_t) -1;
    state->peer = &pscf->url->host;

    u->state = state;

    if (st->buf.start == NULL) {
        p = ngx_pnalloc(s->connection->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_srt_conn_finalize(sc, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        st->buf.start = p;
        st->buf.end = p + pscf->buffer_size;
        st->buf.pos = p;
        st->buf.last = p;
    }

    pc = sc->connection;

    pc->read->handler = ngx_stream_srt_proxy_connect_handler;
    pc->write->handler = ngx_stream_srt_proxy_connect_handler;

    ngx_add_timer(pc->write, pscf->connect_timeout);

    ngx_stream_srt_proxy_ngx_handler(c->read);
}


static void
ngx_stream_srt_proxy_init_upstream(ngx_stream_session_t *s)
{
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *c, *pc;
    ngx_stream_srt_proxy_upstream_t  *u;

    sc = ngx_stream_get_module_ctx(s, ngx_stream_srt_proxy_module);
    c = s->connection;
    pc = sc->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.data = addr;
        str.len = ngx_sock_ntop(pc->local_sockaddr, pc->local_socklen,
            str.data, NGX_SOCKADDR_STRLEN, 1);

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_stream_srt_proxy_init_upstream: srtproxy %V connected to %V",
            &str, &pc->addr_text);
    }

    u = sc->upstream;
    u->state->connect_time = ngx_current_msec - u->start_time;

    pc->read->handler = ngx_stream_srt_proxy_srt_handler;
    pc->write->handler = ngx_stream_srt_proxy_srt_handler;

    sc->connected = 1;

    ngx_stream_srt_proxy_srt_handler(pc->write);
}


static void
ngx_stream_srt_proxy_ngx_handler(ngx_event_t *ev)
{
    ngx_uint_t                        from_srt;
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *c;
    ngx_stream_session_t             *s;
    ngx_stream_srt_proxy_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;
    sc = ngx_stream_get_module_ctx(s, ngx_stream_srt_proxy_module);

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_stream_srt_proxy_ngx_handler: shutdown timeout");
        ngx_srt_conn_finalize(sc, NGX_SRT_OK);
        return;
    }

    if (ev->timedout) {
        ev->timedout = 0;

        ngx_connection_error(c, NGX_ETIMEDOUT,
            "ngx_stream_srt_proxy_ngx_handler: connection timed out");

        ngx_srt_conn_finalize(sc, NGX_SRT_OK);
        return;
    }

    from_srt = ev->write;

    if (from_srt) {
        ngx_srt_proxy_process_srt_to_ngx(sc);

        if (ngx_stream_srt_proxy_test_finalize(sc, 0) == NGX_OK) {
            return;
        }

        if (ngx_handle_write_event(ev, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        ngx_srt_proxy_process_ngx_to_srt(sc);

        if (ngx_stream_srt_proxy_test_finalize(sc, 1) == NGX_OK) {
            return;
        }

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (sc->connected) {
        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_srt_proxy_module);

        ngx_add_timer(c->write, pscf->timeout);
    }
}


static void
ngx_stream_srt_proxy_srt_handler(ngx_event_t *ev)
{
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *c, *pc;
    ngx_stream_session_t             *s;
    ngx_stream_srt_proxy_upstream_t  *u;
    ngx_stream_srt_proxy_srv_conf_t  *pscf;

    pc = ev->data;
    sc = pc->data;

    s = sc->session;
    c = s->connection;

    if (ev->write) {
        ngx_srt_proxy_process_ngx_to_srt(sc);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        ngx_srt_proxy_process_srt_to_ngx(sc);

        if (sc->received) {
            u = sc->upstream;
            if (u->state->first_byte_time == (ngx_msec_t) -1) {
                u->state->first_byte_time = ngx_current_msec
                    - u->start_time;
            }
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (sc->connected) {
        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_srt_proxy_module);

        ngx_add_timer(c->write, pscf->timeout);
    }
}


static void
ngx_stream_srt_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_srt_conn_t        *sc;
    ngx_connection_t      *pc;
    ngx_stream_session_t  *s;

    pc = ev->data;
    sc = pc->data;
    s = sc->session;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, pc->log, NGX_ETIMEDOUT,
            "ngx_stream_srt_proxy_connect_handler: upstream timed out");
        ngx_srt_conn_finalize(sc, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_del_timer(pc->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
        "ngx_stream_srt_proxy_connect_handler: called");

    ngx_stream_srt_proxy_init_upstream(s);
}


static ngx_int_t
ngx_stream_srt_proxy_test_finalize(ngx_srt_conn_t *sc,
    ngx_uint_t from_upstream)
{
    ngx_srt_stream_t    *st;
    ngx_connection_t    *c, *pc;
    ngx_log_handler_pt   handler;

    st = sc->stream;
    c = st->connection;
    pc = sc->connected ? sc->connection : NULL;

    c->log->action = "proxying connection";

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "ngx_stream_srt_proxy_test_finalize: %s disconnected"
        ", bytes from/to client:%O/%O"
        ", bytes from/to upstream:%O/%O",
        from_upstream ? "upstream" : "client",
        st->received, c->sent, sc->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_srt_conn_finalize(sc, NGX_STREAM_OK);

    return NGX_OK;
}


static void
ngx_stream_srt_proxy_log_session(void *data)
{
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *pc;
    ngx_stream_srt_proxy_upstream_t  *u;

    sc = data;
    u = sc->upstream;

    if (u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    pc = sc->connection;
    if (pc) {
        u->state->bytes_received = sc->received;
        u->state->bytes_sent = pc->sent;
    }
}

static void
ngx_stream_srt_proxy_cleanup(void *data)
{
    ngx_srt_conn_t        *sc;
    ngx_stream_session_t  *s;

    sc = data;
    s = sc->session;

    ngx_stream_finalize_session(s, sc->status);
}


static u_char *
ngx_stream_srt_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                           *p;
    ngx_srt_conn_t                   *sc;
    ngx_connection_t                 *pc;
    ngx_srt_stream_t                 *st;
    ngx_stream_session_t             *s;
    ngx_stream_srt_proxy_upstream_t  *u;

    s = log->data;

    sc = ngx_stream_get_module_ctx(s, ngx_stream_srt_proxy_module);

    p = buf;

    u = sc->upstream;

    if (u->state && u->state->peer) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->state->peer);
        len -= p - buf;
    }

    pc = sc->connection;
    st = sc->stream;

    p = ngx_snprintf(p, len,
        ", bytes from/to client:%O/%O"
        ", bytes from/to upstream:%O/%O",
        st->received, s->connection->sent,
        sc->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_srt_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_srt_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_srt_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_stream_srt_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_srt_proxy_srv_conf_t  *prev = parent;
    ngx_stream_srt_proxy_srv_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 64 * 1024);

    if (conf->stream_id == NULL) {
        conf->stream_id = prev->stream_id;
    }

    if (conf->passphrase == NULL) {
        conf->passphrase = prev->passphrase;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_srt_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                            add;
    ngx_url_t                        *u;
    ngx_str_t                        *value;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_srt_proxy_srv_conf_t  *pscf = conf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_stream_srt_proxy_handler;

    value = cf->args->elts;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    add = 0;
    if (ngx_strncasecmp(value[1].data, (u_char *) "srt://", 6) == 0) {
        add = 6;
    }

    u->url.len = value[1].len - add;
    u->url.data = value[1].data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }

    pscf->url = u;

    return NGX_CONF_OK;
}
