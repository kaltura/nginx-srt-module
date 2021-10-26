#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include "ngx_srt.h"


typedef struct {
    ngx_url_t                 *url;
    ngx_msec_t                 connect_timeout;
    ngx_msec_t                 timeout;
    size_t                     buffer_size;
    ngx_flag_t                 proxy_protocol;
    ngx_flag_t                 tcp_nodelay;
    ngx_srt_complex_value_t   *header;
} ngx_srt_proxy_srv_conf_t;


typedef struct {
    ngx_srt_upstream_state_t  *state;
    ngx_msec_t                 start_time;
    unsigned                   proxy_protocol:1;
} ngx_srt_proxy_upstream_t;


static void ngx_srt_proxy_connect(ngx_srt_session_t *s);
static void ngx_srt_proxy_init_upstream(ngx_srt_session_t *s);
static void ngx_srt_proxy_ngx_handler(ngx_event_t *ev);
static void ngx_srt_proxy_srt_handler(ngx_event_t *ev);
static void ngx_srt_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_srt_proxy_test_connect(ngx_connection_t *c);
static ngx_int_t ngx_srt_proxy_test_finalize(ngx_srt_conn_t *sc,
    ngx_uint_t from_upstream);
static void ngx_srt_proxy_next_upstream(ngx_srt_session_t *s);
static u_char *ngx_srt_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_srt_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_srt_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_srt_proxy_init(ngx_conf_t *cf);
static char *ngx_srt_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_srt_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_srt_proxy_pass,
      NGX_SRT_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("proxy_buffer_size"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_protocol"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, proxy_protocol),
      NULL },

    { ngx_string("proxy_tcp_nodelay"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, tcp_nodelay),
      NULL },

    { ngx_string("proxy_header"),
      NGX_SRT_MAIN_CONF|NGX_SRT_SRV_CONF|NGX_CONF_FLAG,
      ngx_srt_set_complex_value_slot,
      NGX_SRT_SRV_CONF_OFFSET,
      offsetof(ngx_srt_proxy_srv_conf_t, header),
      NULL },

      ngx_null_command
};


static ngx_srt_module_t  ngx_srt_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_srt_proxy_init,                    /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_srt_proxy_create_srv_conf,         /* create server configuration */
    ngx_srt_proxy_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_srt_proxy_module = {
    NGX_MODULE_V1,
    &ngx_srt_proxy_module_ctx,             /* module context */
    ngx_srt_proxy_commands,                /* module directives */
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


static void
ngx_srt_proxy_handler(ngx_srt_session_t *s)
{
    ngx_srt_conn_t            *sc;
    ngx_srt_stream_t          *st;
    ngx_connection_t          *c;
    ngx_srt_proxy_upstream_t  *u;

    sc = s->sc;
    c = sc->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "ngx_srt_proxy_handler: called");

    st = ngx_pcalloc(c->pool, sizeof(ngx_srt_stream_t));
    if (st == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->stream = st;

    u = ngx_pcalloc(c->pool, sizeof(ngx_srt_proxy_upstream_t));
    if (u == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->upstream = u;

    s->upstream_states = ngx_array_create(c->pool, 1,
        sizeof(ngx_srt_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->log_handler = ngx_srt_proxy_log_error;

    c->write->handler = ngx_srt_proxy_srt_handler;
    c->read->handler = ngx_srt_proxy_srt_handler;

    ngx_srt_proxy_connect(s);
}


static void
ngx_srt_proxy_connect(ngx_srt_session_t *s)
{
    ngx_int_t                  rc;
    ngx_srt_conn_t            *sc;
    ngx_connection_t          *c, *pc;
    ngx_srt_stream_t          *st;
    ngx_peer_connection_t     *peer;
    ngx_srt_proxy_upstream_t  *u;
    ngx_srt_proxy_srv_conf_t  *pscf;

    sc = s->sc;
    c = sc->connection;

    c->log->action = "connecting to upstream";

    pscf = ngx_srt_get_module_srv_conf(s, ngx_srt_proxy_module);

    st = sc->stream;
    st->connected = 0;

    u = sc->upstream;

    u->proxy_protocol = pscf->proxy_protocol;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_srt_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = (ngx_msec_t) -1;

    peer = ngx_pcalloc(c->pool, sizeof(*peer));
    if (peer == NULL) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    peer->sockaddr = &pscf->url->sockaddr.sockaddr;
    peer->socklen = pscf->url->socklen;

    peer->name = &pscf->url->host;
    peer->get = ngx_event_get_peer;
    peer->log = c->log;
    peer->log_error = NGX_ERROR_ERR;

    peer->type = SOCK_STREAM;

    rc = ngx_event_connect_peer(peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "ngx_srt_proxy_connect: proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = peer->name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_srt_proxy_connect: no live upstreams");
        ngx_srt_conn_finalize(sc, NGX_SRT_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_srt_proxy_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */
    pc = peer->connection;
    st->connection = pc;
    st->close_conn = 1;

    pc->data = sc;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;
    pc->addr_text = pscf->url->url;

    if (rc != NGX_AGAIN) {
        ngx_srt_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_srt_proxy_connect_handler;
    pc->write->handler = ngx_srt_proxy_connect_handler;

    ngx_add_timer(pc->write, pscf->connect_timeout);
}


static void
ngx_srt_proxy_init_upstream(ngx_srt_session_t *s)
{
    u_char                    *p, *last;
    ngx_str_t                  header;
    ngx_srt_conn_t            *sc;
    ngx_srt_stream_t          *st;
    ngx_connection_t          *c, *pc;
    ngx_log_handler_pt         handler;
    ngx_srt_proxy_upstream_t  *u;
    ngx_srt_proxy_srv_conf_t  *pscf;

    sc = s->sc;
    st = sc->stream;
    pc = st->connection;

    pscf = ngx_srt_get_module_srv_conf(s, ngx_srt_proxy_module);

    if (pc->type == SOCK_STREAM
        && pscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_srt_proxy_next_upstream(s);
        return;
    }

    c = sc->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "ngx_srt_proxy_init_upstream: proxy %V connected to %V",
                &str, &pc->addr_text);

            c->log->handler = handler;
        }
    }

    u = sc->upstream;

    u->state->connect_time = ngx_current_msec - u->start_time;

    if (st->buf.start == NULL) {
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_srt_conn_finalize(s->sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

        st->buf.start = p;
        st->buf.end = p + pscf->buffer_size;
        st->buf.pos = p;
        st->buf.last = p;
    }


    if (pscf->header) {
        if (ngx_srt_complex_value(s, pscf->header, &header) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

        if (header.len) {
            if (ngx_srt_conn_in_insert_head(sc, header.data,
                header.data + header.len) != NGX_OK)
            {
                ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    if (u->proxy_protocol) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
            "ngx_srt_proxy_init_upstream: add PROXY protocol header");

        p = ngx_pnalloc(c->pool, NGX_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

        last = ngx_proxy_protocol_write(c, p,
            p + NGX_PROXY_PROTOCOL_MAX_HEADER);
        if (last == NULL) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_srt_conn_in_insert_head(sc, p, last) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

        u->proxy_protocol = 0;
    }

    st->connected = 1;

    pc->read->handler = ngx_srt_proxy_ngx_handler;
    pc->write->handler = ngx_srt_proxy_ngx_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_srt_proxy_ngx_handler(pc->write);
}


static void
ngx_srt_proxy_ngx_handler(ngx_event_t *ev)
{
    ngx_uint_t                 from_srt;
    ngx_srt_conn_t            *sc;
    ngx_srt_stream_t          *st;
    ngx_connection_t          *c, *pc;
    ngx_srt_session_t         *s;
    ngx_srt_proxy_upstream_t  *u;
    ngx_srt_proxy_srv_conf_t  *pscf;

    pc = ev->data;
    sc = pc->data;
    s = sc->session;

    if (pc->close) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0,
            "ngx_srt_proxy_ngx_handler: shutdown timeout");
        ngx_srt_conn_finalize(sc, NGX_SRT_OK);
        return;
    }

    c = sc->connection;

    if (ev->timedout) {
        ev->timedout = 0;

        ngx_connection_error(c, NGX_ETIMEDOUT,
            "ngx_srt_proxy_ngx_handler: connection timed out");

        ngx_srt_conn_finalize(sc, NGX_SRT_OK);

        return;
    }

    from_srt = ev->write;

    if (from_srt) {
        ngx_srt_proxy_process_srt_to_ngx(sc);

        if (ngx_srt_proxy_test_finalize(sc, 0) == NGX_OK) {
            return;
        }

        if (ngx_handle_write_event(ev, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        ngx_srt_proxy_process_ngx_to_srt(sc);

        st = sc->stream;

        if (st->received) {
            u = sc->upstream;
            if (u->state->first_byte_time == (ngx_msec_t) -1) {
                u->state->first_byte_time = ngx_current_msec
                    - u->start_time;
            }
        }

        if (ngx_srt_proxy_test_finalize(sc, 1) == NGX_OK) {
            return;
        }

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    pscf = ngx_srt_get_module_srv_conf(s, ngx_srt_proxy_module);

    ngx_add_timer(c->write, pscf->timeout);
}


static void
ngx_srt_proxy_srt_handler(ngx_event_t *ev)
{
    ngx_srt_conn_t            *sc;
    ngx_connection_t          *c, *pc;
    ngx_srt_stream_t          *st;
    ngx_srt_session_t         *s;
    ngx_srt_proxy_srv_conf_t  *pscf;

    c = ev->data;
    sc = c->data;

    st = sc->stream;
    if (!st->connected) {
        return;
    }

    pc = st->connection;

    if (ev->write) {
        ngx_srt_proxy_process_ngx_to_srt(sc);

        if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {
        ngx_srt_proxy_process_srt_to_ngx(sc);

        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s = sc->session;

    pscf = ngx_srt_get_module_srv_conf(s, ngx_srt_proxy_module);

    ngx_add_timer(c->write, pscf->timeout);
}


static void
ngx_srt_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_srt_conn_t     *sc;
    ngx_connection_t   *pc;
    ngx_srt_session_t  *s;

    pc = ev->data;
    sc = pc->data;
    s = sc->session;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, pc->log, NGX_ETIMEDOUT,
            "ngx_srt_proxy_connect_handler: upstream timed out");
        goto failed;
    }

    ngx_del_timer(pc->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
        "ngx_srt_proxy_connect_handler: called");


    if (ngx_srt_proxy_test_connect(pc) != NGX_OK) {
        goto failed;
    }

    ngx_srt_proxy_init_upstream(s);

    return;

failed:

    ngx_srt_proxy_next_upstream(s);
}


static ngx_int_t
ngx_srt_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
        * BSDs and Linux return 0 and set a pending error in err
        * Solaris returns -1 and sets errno
        */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_proxy_test_finalize(ngx_srt_conn_t *sc, ngx_uint_t from_upstream)
{
    ngx_srt_stream_t    *st;
    ngx_connection_t    *c, *pc;
    ngx_log_handler_pt   handler;

    c = sc->connection;
    st = sc->stream;
    pc = st->connected ? st->connection : NULL;

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
        "ngx_srt_proxy_test_finalize: %s disconnected"
        ", bytes from/to client:%O/%O"
        ", bytes from/to upstream:%O/%O",
        from_upstream ? "upstream" : "client",
        sc->received, c->sent, st->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_srt_conn_finalize(sc, NGX_SRT_OK);

    return NGX_OK;
}


static void
ngx_srt_proxy_next_upstream(ngx_srt_session_t *s)
{
    /* supporting only one upstream */
    ngx_srt_conn_finalize(s->sc, NGX_SRT_BAD_GATEWAY);
}


static ngx_int_t
ngx_srt_proxy_log_handler(ngx_srt_session_t *s)
{
    ngx_srt_conn_t            *sc;
    ngx_srt_stream_t          *st;
    ngx_connection_t          *pc;
    ngx_srt_proxy_upstream_t  *u;

    sc = s->sc;

    u = sc->upstream;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        st = sc->stream;
        pc = st->connection;

        if (pc) {
            u->state->bytes_received = st->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    return NGX_OK;
}


static u_char *
ngx_srt_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                    *p;
    ngx_srt_conn_t            *sc;
    ngx_srt_stream_t          *st;
    ngx_connection_t          *pc;
    ngx_srt_proxy_upstream_t  *u;

    sc = log->data;

    st = sc->stream;

    p = buf;

    u = sc->upstream;

    if (u->state && u->state->peer) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->state->peer);
        len -= p - buf;
    }

    pc = st->connection;

    p = ngx_snprintf(p, len,
        ", bytes from/to client:%O/%O"
        ", bytes from/to upstream:%O/%O",
        sc->received, sc->connection->sent,
        st->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_srt_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_srt_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_srt_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->proxy_protocol = NGX_CONF_UNSET;
    conf->tcp_nodelay = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_srt_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_srt_proxy_srv_conf_t  *prev = parent;
    ngx_srt_proxy_srv_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 64 * 1024);

    ngx_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    if (conf->header == NULL) {
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


static char *
ngx_srt_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                     add;
    ngx_url_t                 *u;
    ngx_str_t                 *value;
    ngx_srt_core_srv_conf_t   *cscf;
    ngx_srt_proxy_srv_conf_t  *pscf = conf;

    cscf = ngx_srt_conf_get_module_srv_conf(cf, ngx_srt_core_module);

    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_srt_proxy_handler;

    value = cf->args->elts;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    add = 0;
    if (ngx_strncasecmp(value[1].data, (u_char *) "tcp://", 6) == 0) {
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


static ngx_int_t
ngx_srt_proxy_init(ngx_conf_t *cf)
{
    ngx_srt_handler_pt        *h;
    ngx_srt_core_main_conf_t  *cmcf;

    cmcf = ngx_srt_conf_get_module_main_conf(cf, ngx_srt_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_SRT_PRE_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_srt_proxy_log_handler;

    return NGX_OK;
}
