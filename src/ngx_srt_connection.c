#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <pthread.h>
#include <srt/srt.h>
#include "ngx_srt.h"


#define NGX_SRT_POST_EVENTS_CHUNK  (32)
#define NGX_SRT_EPOLL_EVENTS       (128)
#define NGX_SRT_EPOLL_TIMEOUT      (1000)

#define NGX_SRT_MIN_RECV_SIZE      (1456)   /* max value of SRTO_PAYLOADSIZE */

#define NGX_SRT_STREAM_ID_LEN      (512)


#define ngx_srt_session_sock(s)    (s)->node.key


#ifndef ngx_rbtree_data
#define ngx_rbtree_data(node, type, link)                                    \
    (type *) ((u_char *) (node) - offsetof(type, link))
#endif


static void ngx_srt_conn_close(ngx_srt_conn_t *sc);
static void ngx_srt_conn_destroy(ngx_srt_conn_t *sc);
static void ngx_srt_conn_terminate(ngx_srt_conn_t *sc);

static void ngx_srt_conn_read_handler(ngx_srt_conn_t *sc);
static void ngx_srt_conn_write_handler(ngx_srt_conn_t *sc);
static void ngx_srt_conn_connect_handler(ngx_srt_conn_t *sc);


typedef struct {
    ngx_rbtree_node_t      node;
    ngx_listening_t       *ls;
    ngx_log_t             *error_log;
    size_t                 in_buf_size;
} ngx_srt_listening_t;


typedef struct {
    ngx_srt_conn_t        *sc;
    uint32_t               flags;
} ngx_srt_conn_event_t;


static ngx_atomic_int_t    srt_threads = 0;
static ngx_atomic_int_t   *ngx_srt_threads = &srt_threads;

static ngx_rbtree_t        ngx_srt_conns;
static ngx_rbtree_node_t   ngx_srt_conns_sentinel;

static int                 ngx_srt_epoll_id = -1;


/* srt -> ngx notifications */
static ngx_srt_conn_t     *ngx_srt_ngx_posted;
static ngx_atomic_t        ngx_srt_ngx_posted_lock;

/* ngx -> srt notifications */
static int                 ngx_srt_notify_fd = -1;
static ngx_srt_conn_t     *ngx_srt_srt_posted;
static ngx_atomic_t        ngx_srt_srt_posted_lock;


static ngx_str_t  ngx_srt_status_names[] = {
    ngx_string("UNKNOWN"),
    ngx_string("INIT"),
    ngx_string("OPENED"),
    ngx_string("LISTENING"),
    ngx_string("CONNECTING"),
    ngx_string("CONNECTED"),
    ngx_string("BROKEN"),
    ngx_string("CLOSING"),
    ngx_string("CLOSED"),
    ngx_string("NONEXIST"),
};


/* Context: NGX thread */
static void
ngx_srt_ngx_posted_handler(ngx_event_t *ev)
{
    ngx_uint_t             i, n;
    ngx_event_t           *rev, *wev;
    ngx_srt_conn_t        *sc;
    ngx_srt_conn_event_t  *event;
    ngx_srt_conn_event_t   events[NGX_SRT_POST_EVENTS_CHUNK];

    ngx_spinlock(&ngx_srt_ngx_posted_lock, 1, 2048);

    n = 0;
    for (sc = ngx_srt_ngx_posted; ; sc = sc->ngx_next) {
        if (!sc) {
            break;
        }

        if (n >= NGX_SRT_POST_EVENTS_CHUNK) {
            ngx_post_event(ev, &ngx_posted_events);
            break;
        }

        events[n].flags = sc->ngx_post_flags;
        events[n].sc = sc;
        n++;

        sc->ngx_post_flags = 0;
    }

    ngx_srt_ngx_posted = sc;

    ngx_memory_barrier();

    ngx_unlock(&ngx_srt_ngx_posted_lock);

    for (i = 0; i < n; i++) {
        event = &events[i];
        sc = event->sc;

        if (event->flags & NGX_SRT_POST_CLOSE) {
            ngx_srt_conn_terminate(sc);
            continue;
        }

        if (event->flags & NGX_SRT_POST_READ) {
            rev = sc->connection->read;
            rev->handler(rev);
        }

        if (event->flags & NGX_SRT_POST_WRITE) {
            wev = sc->connection->write;
            wev->handler(wev);
        }
    }
}


/* Context: SRT thread */
static void
ngx_srt_conn_post_ngx(ngx_srt_conn_t *sc, uint32_t flags)
{
    ngx_flag_t  notify;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, sc->srt_pool->log, 0,
        "ngx_srt_conn_post_ngx: conn: %p, flags: 0x%uxD", sc, flags);

    ngx_spinlock(&ngx_srt_ngx_posted_lock, 1, 2048);

    if (!sc->ngx_post_flags) {
        sc->ngx_next = ngx_srt_ngx_posted;
        ngx_srt_ngx_posted = sc;

        notify = 1;

    } else {
        notify = 0;
    }

    sc->ngx_post_flags |= flags;

    ngx_memory_barrier();

    ngx_unlock(&ngx_srt_ngx_posted_lock);

    if (notify && ngx_notify(ngx_srt_ngx_posted_handler) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, sc->srt_pool->log, 0,
            "ngx_srt_conn_post_ngx: ngx_notify() failed");
    }
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_epoll_notify_init(ngx_log_t *log)
{
    int  events;
    int  serr, serrno;

#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_srt_notify_fd = eventfd(0, 0);
#else
    ngx_srt_notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_srt_notify_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
            "ngx_srt_epoll_notify_init: eventfd() failed");
        return NGX_ERROR;
    }

    events = SRT_EPOLL_IN|SRT_EPOLL_ET;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
        "ngx_srt_epoll_notify_init: epoll add event: fd:%D ev:%08Xd",
        ngx_srt_notify_fd, events);

    if (srt_epoll_add_ssock(ngx_srt_epoll_id, ngx_srt_notify_fd, &events) < 0)
    {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, log, serrno,
            "ngx_srt_epoll_notify_init: srt_epoll_add_ssock() failed %d",
            serr);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: NGX thread */
static ngx_int_t
ngx_srt_epoll_notify(ngx_log_t *log)
{
    static uint64_t  inc = 1;

    if ((size_t) write(ngx_srt_notify_fd, &inc, sizeof(uint64_t))
        != sizeof(uint64_t))
    {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
            "ngx_srt_epoll_notify: write() to eventfd %d failed",
            ngx_srt_notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_epoll_read(ngx_log_t *log)
{
    ssize_t    n;
    uint64_t   count;
    ngx_err_t  err;

    n = read(ngx_srt_notify_fd, &count, sizeof(uint64_t));

    err = ngx_errno;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
        "ngx_srt_epoll_read: read() eventfd %d: %z count: %uL",
        ngx_srt_notify_fd, n, count);

    if ((size_t) n != sizeof(uint64_t)) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
            "ngx_srt_epoll_read: read() eventfd %d failed", ngx_srt_notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: NGX thread */
static void
ngx_srt_conn_post_srt(ngx_srt_conn_t *sc, uint32_t flags)
{
    ngx_flag_t  notify;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, sc->connection->log, 0,
        "ngx_srt_conn_post_srt: conn: %p, flags: 0x%uxD", sc, flags);

    ngx_spinlock(&ngx_srt_srt_posted_lock, 1, 2048);

    if (!sc->srt_post_flags) {
        sc->srt_next = ngx_srt_srt_posted;
        ngx_srt_srt_posted = sc;

        notify = 1;

    } else {
        notify = 0;
    }

    sc->srt_post_flags |= flags;

    ngx_memory_barrier();

    ngx_unlock(&ngx_srt_srt_posted_lock);

    if (notify) {
        (void) ngx_srt_epoll_notify(sc->connection->log);
    }
}


static void
ngx_srt_conn_unpost_srt(ngx_srt_conn_t *sc)
{
    ngx_srt_conn_t  **cur;

    ngx_spinlock(&ngx_srt_srt_posted_lock, 1, 2048);

    /* remove from list */
    if (sc->srt_post_flags) {
        for (cur = &ngx_srt_srt_posted; *cur; cur = &(*cur)->srt_next) {
            if (*cur == sc) {
                *cur = sc->srt_next;
                break;
            }
        }
    }

    /* prevent further posts */
    sc->srt_post_flags = NGX_MAX_UINT32_VALUE;

    ngx_memory_barrier();

    ngx_unlock(&ngx_srt_srt_posted_lock);
}


/* Context: SRT thread */
static ngx_flag_t
ngx_srt_srt_posted_handler(ngx_log_t *log)
{
    ngx_flag_t             more;
    ngx_uint_t             i, n;
    ngx_srt_conn_t        *sc;
    ngx_srt_conn_event_t  *event;
    ngx_srt_conn_event_t   events[NGX_SRT_POST_EVENTS_CHUNK];

    /* must read since SRT_EPOLL_ET is not honored for system sockets */
    (void) ngx_srt_epoll_read(log);

    ngx_spinlock(&ngx_srt_srt_posted_lock, 1, 2048);

    n = 0;
    for (sc = ngx_srt_srt_posted; ; sc = sc->srt_next) {
        if (!sc) {
            more = 0;
            break;
        }

        if (n >= NGX_SRT_POST_EVENTS_CHUNK) {
            more = 1;
            break;
        }

        events[n].sc = sc;
        events[n].flags = sc->srt_post_flags;
        n++;

        sc->srt_post_flags = 0;
    }

    ngx_srt_srt_posted = sc;

    ngx_memory_barrier();

    ngx_unlock(&ngx_srt_srt_posted_lock);

    for (i = 0; i < n; i++) {
        event = &events[i];
        sc = event->sc;

        if (event->flags & NGX_SRT_POST_CLOSE) {
            ngx_srt_conn_close(sc);
            continue;
        }

        if (event->flags & NGX_SRT_POST_CONNECT) {
            ngx_srt_conn_connect_handler(sc);
        }

        if (event->flags & NGX_SRT_POST_READ) {
            ngx_srt_conn_read_handler(sc);
        }

        if (event->flags & NGX_SRT_POST_WRITE) {
            ngx_srt_conn_write_handler(sc);
        }
    }

    return more;
}


/* Context: SRT thread */
static ngx_str_t *
ngx_srt_get_status_str(SRT_SOCKSTATUS status)
{
    if (status < 0 || status >= sizeof(ngx_srt_status_names)
        / sizeof(ngx_srt_status_names[0]))
    {
        status = 0;
    }

    return &ngx_srt_status_names[status];
}


/* Context: SRT thread / NGX thread */
static ngx_chain_t *
ngx_srt_get_chain(ngx_chain_t **out, ngx_atomic_t *lock)
{
    ngx_chain_t  *cl;

    ngx_spinlock(lock, 1, 2048);

    cl = *out;
    *out = NULL;

    ngx_memory_barrier();

    ngx_unlock(lock);

    return cl;
}


/* Context: SRT thread / NGX thread */
static ngx_chain_t *
ngx_srt_chain_get_free_buf(ngx_pool_t *p, ngx_atomic_t *lock,
    ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    ngx_spinlock(lock, 1, 2048);

    if (*free) {
        cl = *free;
        *free = cl->next;

    } else {
        cl = NULL;
    }

    ngx_memory_barrier();

    ngx_unlock(lock);

    if (cl == NULL) {
        cl = ngx_alloc_chain_link(p);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = ngx_calloc_buf(p);
        if (cl->buf == NULL) {
            return NULL;
        }
    }

    cl->next = NULL;

    return cl;
}


/* Context: NGX thread */
ngx_chain_t *
ngx_srt_conn_in_get_chain(ngx_srt_conn_t *sc)
{
    return ngx_srt_get_chain(&sc->srt_in.out, &sc->srt_in.lock);
}


/* Context: NGX thread */
void
ngx_srt_conn_in_update_chains(ngx_srt_conn_t *sc, ngx_chain_t *out)
{
    ngx_buf_t         *b;
    ngx_flag_t         notify;
    ngx_chain_t       *free = NULL, *last;
    ngx_connection_t  *c;

    c = sc->connection;

    /* out -> busy, empty busy -> free */
    ngx_chain_update_chains(c->pool, &free, &sc->srt_in.busy, &out,
        (ngx_buf_tag_t) &ngx_srt_module);

    if (free) {
        for (last = free; last->next; last = last->next) { /* void */ }

    } else {
        last = NULL;        /* suppress warning */
    }

    b = &sc->srt_in.buf;

    ngx_spinlock(&sc->srt_in.lock, 1, 2048);

    if (sc->srt_in.busy == NULL && sc->srt_in.out == NULL) {
        notify = (b->end - b->last < NGX_SRT_MIN_RECV_SIZE);
        b->last = b->start;

    } else {
        notify = 0;
    }

    if (free) {
        last->next = sc->srt_in.free;
        sc->srt_in.free = free;
    }

    ngx_memory_barrier();

    ngx_unlock(&sc->srt_in.lock);

    if (notify) {
        ngx_srt_conn_post_srt(sc, NGX_SRT_POST_READ);
    }
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_in_insert_tail(ngx_srt_conn_t *sc, u_char *start,
    u_char *end)
{
    ngx_chain_t  *cl, **ll;

    cl = ngx_srt_chain_get_free_buf(sc->srt_pool, &sc->srt_in.lock,
        &sc->srt_in.free);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, sc->srt_pool->log, 0,
            "ngx_srt_conn_in_insert_tail: get buf failed");
        return NGX_ERROR;
    }

    cl->buf->pos = start;
    cl->buf->last = end;
    cl->buf->tag = (ngx_buf_tag_t) &ngx_srt_module;

    cl->buf->temporary = (start < end ? 1 : 0);
    cl->buf->last_buf = sc->connection->read->eof;
    cl->buf->flush = 1;

    sc->received += end - start;

    ngx_spinlock(&sc->srt_in.lock, 1, 2048);

    sc->srt_in.buf.last = end;

    for (ll = &sc->srt_in.out; *ll; ll = &(*ll)->next) { /* void */ }

    *ll = cl;

    ngx_memory_barrier();

    ngx_unlock(&sc->srt_in.lock);

    return NGX_OK;
}


/* Context: NGX thread */
ngx_int_t
ngx_srt_conn_in_insert_head(ngx_srt_conn_t *sc,
    u_char *start, u_char *end)
{
    ngx_chain_t  *cl;

    cl = ngx_srt_chain_get_free_buf(sc->connection->pool, &sc->srt_in.lock,
        &sc->srt_in.free);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, sc->connection->log, 0,
            "ngx_srt_conn_in_insert_head: get buf failed");
        return NGX_ERROR;
    }

    cl->buf->pos = start;
    cl->buf->last = end;
    cl->buf->tag = (ngx_buf_tag_t) &ngx_srt_module;

    cl->buf->temporary = (start < end ? 1 : 0);
    cl->buf->last_buf = 0;
    cl->buf->flush = 1;

    ngx_spinlock(&sc->srt_in.lock, 1, 2048);

    cl->next = sc->srt_in.out;
    sc->srt_in.out = cl;

    ngx_memory_barrier();

    ngx_unlock(&sc->srt_in.lock);

    return NGX_OK;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_recv(ngx_srt_conn_t *sc)
{
    int         n;
    int         serr, serrno;
    size_t      size;
    u_char     *start, *p;
    ngx_buf_t  *b;
    SRTSOCKET   ss;

    ss = ngx_srt_session_sock(sc);

    b = &sc->srt_in.buf;

    start = b->last;

    ngx_memory_barrier();

    for (p = start; p < b->end; ) {

        size = b->end - p;
        if (size < NGX_SRT_MIN_RECV_SIZE) {
            ngx_log_debug1(NGX_LOG_DEBUG_SRT, sc->srt_pool->log, 0,
                "ngx_srt_conn_recv: input buffer too small, size: %uz", size);
            break;
        }

        n = srt_recv(ss, (char *) p, size);
        if (n < 0) {
            serr = srt_getlasterror(&serrno);
            if (serr == SRT_EASYNCRCV) {
                break;
            }

            sc->connection->read->eof = 1;
            ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                "ngx_srt_conn_recv: srt_recv() failed %d", serr);
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_SRT, sc->srt_pool->log, 0,
            "ngx_srt_conn_recv: srt recv %d, fd: %D, size: %uz", n, ss, size);

        p += n;
    }

    if (p > start) {
        if (ngx_srt_conn_in_insert_tail(sc, start, p) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_srt_conn_post_ngx(sc, NGX_SRT_POST_READ);
    }

    return NGX_OK;
}


/* Context: SRT thread */
static void
ngx_srt_conn_read_handler(ngx_srt_conn_t *sc)
{
    SRTSOCKET       ss;
    SRT_SOCKSTATUS  status;

    ss = ngx_srt_session_sock(sc);

    status = srt_getsockstate(ss);
    if (status != SRTS_CONNECTED) {
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, 0,
            "ngx_srt_conn_read_handler: invalid socket status %d (%V)",
            status, ngx_srt_get_status_str(status));
        goto failed;
    }

    if (ngx_srt_conn_recv(sc) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_srt_conn_close(sc);
}


/* Context: NGX thread */
static void
ngx_srt_chain_insert_tail(ngx_chain_t **out, ngx_chain_t *cl,
    ngx_atomic_t *lock)
{
    ngx_chain_t  **ll;

    ngx_spinlock(lock, 1, 2048);

    for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }
    *ll = cl;

    ngx_memory_barrier();

    ngx_unlock(lock);
}


/* Context: SRT thread */
static void
ngx_srt_chain_insert_head(ngx_chain_t **out, ngx_chain_t *cl,
    ngx_atomic_t *lock)
{
    ngx_spinlock(lock, 1, 2048);

    cl->next = *out;
    *out = cl;

    ngx_memory_barrier();

    ngx_unlock(lock);
}


/* Context: NGX thread */
static ngx_chain_t *
ngx_srt_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    size_t           size;
    size_t           sent, left;
    size_t           added, skip;
    ngx_buf_t       *b, *nb;
    ngx_chain_t     *cp, *cl, *out, **ll;
    ngx_srt_conn_t  *sc;

    /* Note: limit is not supported */

    sc = c->data;

    /* copy input chains and bufs, skip previously added data */

    skip = sc->srt_out.added - sc->srt_out.acked;

    ll = &out;
    added = 0;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;

        size = b->last - b->pos;
        if (skip >= size) {
            skip -= size;
            continue;
        }

        cp = ngx_srt_chain_get_free_buf(c->pool, &sc->srt_out.free_lock,
            &sc->srt_out.free);
        if (cp == NULL) {
            return NGX_CHAIN_ERROR;
        }

        *ll = cp;
        ll = &cp->next;

        nb = cp->buf;

        nb->pos = b->pos + skip;
        nb->last = b->last;
        nb->tag = (ngx_buf_tag_t) &ngx_srt_module;

        nb->temporary = (b->pos < b->last ? 1 : 0);
        nb->last_buf = b->last_buf;
        nb->flush = 1;

        skip = 0;
        added += nb->last - nb->pos;
    }

    sc->srt_out.added += added;

    *ll = NULL;

    /* add to the end of the output chain */

    if (out) {
        ngx_srt_chain_insert_tail(&sc->srt_out.out, out,
            &sc->srt_out.out_lock);

        ngx_srt_conn_post_srt(sc, NGX_SRT_POST_WRITE);
    }

    /* advance the positions of sent buffers */
    sent = c->sent;

    ngx_memory_barrier();

    left = sent - sc->srt_out.acked;
    sc->srt_out.acked = sent;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;

        size = b->last - b->pos;
        if (left < size) {
            b->pos += left;
            break;
        }

        b->pos = b->last = b->start;
        left -= size;
    }

    return cl;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_send(ngx_srt_conn_t *sc)
{
    int           n;
    int           serr, serrno;
    size_t        sent;
    size_t        size;
    ngx_buf_t    *b;
    SRTSOCKET     ss;
    ngx_chain_t  *out, *cl;

    /* move from out to busy */

    out = ngx_srt_get_chain(&sc->srt_out.out, &sc->srt_out.out_lock);
    if (out) {
        if (sc->srt_out.busy == NULL) {
            sc->srt_out.busy = out;

        } else {
            for (cl = sc->srt_out.busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = out;
        }
    }

    /* send as much as possible */

    ss = ngx_srt_session_sock(sc);
    sent = 0;

    for ( ;; ) {

        cl = sc->srt_out.busy;
        if (!cl) {
            break;
        }

        b = cl->buf;

        while (b->pos < b->last) {

            size = b->last - b->pos;
            if (size > sc->payload_size) {
                size = sc->payload_size;
            }

            n = srt_send(ss, (char *) b->pos, size);
            if (n < 0) {
                serr = srt_getlasterror(&serrno);
                if (serr == SRT_EASYNCSND) {
                    goto done;
                }

                ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                    "ngx_srt_conn_send: srt_send() failed %d", serr);
                return NGX_ERROR;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_SRT, sc->srt_pool->log, 0,
                "ngx_srt_conn_send: srt send %d, fd: %D, size: %uz",
                n, ss, size);

            b->pos += n;
            sent += n;
        }

        sc->srt_out.busy = cl->next;

        ngx_srt_chain_insert_head(&sc->srt_out.free, cl,
            &sc->srt_out.free_lock);
    }

done:

    /* update sent counter */

    if (sent) {
        sc->connection->sent += sent;

        ngx_srt_conn_post_ngx(sc, NGX_SRT_POST_WRITE);
    }

    return NGX_OK;
}


/* Context: SRT thread */
static void
ngx_srt_conn_write_handler(ngx_srt_conn_t *sc)
{
    int             len;
    int             serr, serrno;
    SRTSOCKET       ss;
    SRT_SOCKSTATUS  status;

    ss = ngx_srt_session_sock(sc);
    status = srt_getsockstate(ss);
    switch (status) {

    case SRTS_CONNECTED:
        break;

    case SRTS_CONNECTING:
        ngx_log_debug1(NGX_LOG_DEBUG_SRT, sc->srt_pool->log, 0,
            "ngx_srt_conn_write_handler: socket %D connecting", ss);
        return;

    default:
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, 0,
            "ngx_srt_conn_write_handler: invalid socket status %d (%V)",
            status, ngx_srt_get_status_str(status));
        goto failed;
    }

    if (!sc->peer_version) {
        len = sizeof(sc->peer_version);
        if (srt_getsockflag(ss, SRTO_PEERVERSION, &sc->peer_version, &len)
            != 0)
        {
            serr = srt_getlasterror(&serrno);
            ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                "ngx_srt_conn_write_handler: "
                "srt_getsockflag(SRTO_PEERVERSION) failed %d", serr);
            sc->peer_version = -1;

        }

        len = sizeof(sc->payload_size);
        if (srt_getsockflag(ss, SRTO_PAYLOADSIZE, &sc->payload_size, &len)
            != 0)
        {
            serr = srt_getlasterror(&serrno);
            ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                "ngx_srt_conn_write_handler: "
                "srt_getsockflag(SRTO_PAYLOADSIZE) failed %d", serr);
            sc->payload_size = 1316;

        } else if (sc->payload_size <= 0) {
            sc->payload_size = NGX_MAX_INT32_VALUE;
        }

        ngx_log_error(NGX_LOG_INFO, sc->srt_pool->log, 0,
            "ngx_srt_conn_write_handler: "
            "peer_version: 0x%xD, payload_size: %D",
            sc->peer_version, sc->payload_size);
    }

    if (ngx_srt_conn_send(sc) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_srt_conn_close(sc);
}


/* Context: SRT thread (accept) / NGX thread (connect) */
static ngx_pool_t *
ngx_srt_create_pool(size_t size, ngx_log_t *error_log)
{
    ngx_log_t   *log;
    ngx_pool_t  *pool;

    pool = ngx_create_pool(1024, error_log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, error_log, 0,
            "ngx_srt_create_pool: create pool failed");
        return NULL;
    }

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, error_log, 0,
            "ngx_srt_create_pool: alloc failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *error_log;

    pool->log = log;

    return pool;
}


/* Context: SRT thread */
static SRTSOCKET
ngx_srt_create_socket(ngx_log_t *log)
{
    int        blocking;
    int        serr, serrno;
    SRTSOCKET  ss;

    ss = srt_create_socket();
    if (ss == SRT_INVALID_SOCK) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, log, serrno,
            "ngx_srt_create_socket: srt_create_socket() failed %d", serr);
        return SRT_INVALID_SOCK;
    }

    blocking = 0;

    if (srt_setsockflag(ss, SRTO_SNDSYN, &blocking, sizeof (blocking)) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, log, serrno,
            "ngx_srt_create_socket: srt_setsockflag(SRTO_SNDSYN) failed %d",
            serr);
        goto failed;
    }

    if (srt_setsockflag(ss, SRTO_RCVSYN, &blocking, sizeof (blocking)) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, log, serrno,
            "ngx_srt_create_socket: srt_setsockflag(SRTO_RCVSYN) failed %d",
            serr);
        goto failed;
    }

    return ss;

failed:

    if (srt_close(ss) < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_srt_create_socket: srt_close() failed");
    }

    return SRT_INVALID_SOCK;
}


/* Context: NGX thread */
void
ngx_srt_merge_options(ngx_srt_conn_options_t *conf,
    ngx_srt_conn_options_t *prev)
{
    ngx_conf_init_uint_value(conf->fc_pkts, prev->fc_pkts);
    ngx_conf_init_size_value(conf->mss, prev->mss);

    ngx_conf_init_size_value(conf->recv_buf, prev->recv_buf);
    ngx_conf_init_size_value(conf->recv_udp_buf, prev->recv_udp_buf);
    ngx_conf_init_msec_value(conf->recv_latency, prev->recv_latency);

    ngx_conf_init_size_value(conf->send_buf, prev->send_buf);
    ngx_conf_init_size_value(conf->send_udp_buf, prev->send_udp_buf);
    ngx_conf_init_msec_value(conf->send_latency, prev->send_latency);
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_set_socket_opt_int32(ngx_log_t *log, SRTSOCKET ss, SRT_SOCKOPT opt,
    int32_t val)
{
    int  serr, serrno;

    if (srt_setsockflag(ss, opt, &val, sizeof(val)) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, log, serrno,
            "ngx_srt_set_socket_opt_int32: "
            "srt_setsockflag(%d) failed %d", (int) opt, serr);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: SRT thread */
static void
ngx_srt_configure_socket(ngx_log_t *log, SRTSOCKET ss,
    ngx_srt_conn_options_t *opts)
{
    if (opts->fc_pkts != NGX_CONF_UNSET_UINT) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_FC, opts->fc_pkts);
    }

    if (opts->mss != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_MSS, opts->mss);
    }


    if (opts->recv_buf != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_RCVBUF,
            opts->recv_buf);
    }

    if (opts->recv_udp_buf != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_UDP_RCVBUF,
            opts->recv_udp_buf);
    }

    if (opts->recv_latency != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_RCVLATENCY,
            opts->recv_latency);
    }


    if (opts->send_buf != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_SNDBUF,
            opts->send_buf);
    }

    if (opts->send_udp_buf != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_UDP_SNDBUF,
            opts->send_udp_buf);
    }

    if (opts->send_latency != NGX_CONF_UNSET_SIZE) {
        (void) ngx_srt_set_socket_opt_int32(log, ss, SRTO_PEERLATENCY,
            opts->send_latency);
    }
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_local_sockaddr(ngx_srt_conn_t *sc, SRTSOCKET ss)
{
    int                socklen;
    int                serr, serrno;
    ngx_sockaddr_t    *sa;
    ngx_connection_t  *c;

    sa = ngx_palloc(sc->srt_pool, sizeof(*sa));
    if (sa == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, sc->srt_pool->log, 0,
            "ngx_srt_conn_local_sockaddr: alloc failed");
        return NGX_ERROR;
    }

    c = sc->connection;

    socklen = sizeof(*sa);
    if (srt_getsockname(ss, &sa->sockaddr, &socklen) < 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
            "ngx_srt_conn_local_sockaddr: srt_getsockname() failed %d", serr);
        return NGX_ERROR;
    }

    c->local_sockaddr = &sa->sockaddr;
    c->local_socklen = socklen;

    return NGX_OK;
}


/* Context: SRT thread / NGX thread */
static u_char *
ngx_srt_conn_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char            *p;
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    sc = log->data;

    c = sc->connection;

    p = ngx_snprintf(buf, len, ", srtclient: %V, server: %V",
        &c->addr_text, &c->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (sc->log_handler) {
        p = sc->log_handler(log, buf, len);
    }

    return p;
}


/* Context: SRT thread (accept) / NGX thread (connect) */
static ngx_srt_conn_t *
ngx_srt_conn_alloc(ngx_log_t *error_log)
{
    ngx_pool_t        *pool;
    ngx_time_t        *tp;
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;

    pool = ngx_srt_create_pool(1024, error_log);
    if (pool == NULL) {
        return NULL;
    }

    sc = ngx_pcalloc(pool, sizeof(ngx_srt_conn_t));
    if (sc == NULL) {
        goto failed;
    }

    c = ngx_pcalloc(pool, sizeof(ngx_connection_t));
    if (c == NULL) {
        goto failed;
    }

    c->type = SOCK_STREAM;
    c->pool = pool;

    c->log = pool->log;
    c->log->action = "initializing session";

    sc->connection = c;
    c->data = sc;

    tp = ngx_timeofday();
    sc->start_sec = tp->sec;
    sc->start_msec = tp->msec;

    return sc;

failed:

    ngx_destroy_pool(pool);

    return NULL;
}


/* Context: SRT thread (accept) / NGX thread (connect) */
ngx_srt_conn_t *
ngx_srt_conn_create(ngx_log_t *error_log, size_t in_buf_size)
{
    ngx_buf_t         *b;
    ngx_pool_t        *pool;
    ngx_event_t       *rev, *wev;
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;

    sc = ngx_srt_conn_alloc(error_log);
    if (sc == NULL) {
        return NULL;
    }

    c = sc->connection;
    pool = c->pool;

    rev = ngx_pcalloc(pool, sizeof(ngx_event_t));
    if (rev == NULL) {
        goto failed;
    }

    wev = ngx_pcalloc(pool, sizeof(ngx_event_t));
    if (wev == NULL) {
        goto failed;
    }

    b = &sc->srt_in.buf;

    b->start = ngx_pnalloc(pool, in_buf_size);
    if (b->start == NULL) {
        goto failed;
    }

    b->pos = b->last = b->start;
    b->end = b->start + in_buf_size;

    sc->srt_pool = ngx_srt_create_pool(1024, error_log);
    if (sc->srt_pool == NULL) {
        goto failed;
    }

    rev->index = NGX_INVALID_INDEX;
    rev->data = c;
    rev->log = pool->log;

    wev->index = NGX_INVALID_INDEX;
    wev->data = c;
    wev->log = pool->log;
    wev->write = 1;

    c->read = rev;
    c->write = wev;

    c->send_chain = ngx_srt_send_chain;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->log->connection = c->number;

    sc->srt_pool->log->connection = c->number;
    c->log_error = NGX_ERROR_INFO;

    c->fd = SRT_INVALID_SOCK;
    sc->node.key = SRT_INVALID_SOCK;

    return sc;

failed:

    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
        "ngx_srt_conn_create: alloc failed");

    ngx_destroy_pool(pool);

    return NULL;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_attach(ngx_srt_conn_t *sc, SRTSOCKET ss)
{
    if (ngx_srt_conn_local_sockaddr(sc, ss) != NGX_OK) {
        return NGX_ERROR;
    }

    sc->connection->fd = ss;
    sc->node.key = ss;

    ngx_rbtree_insert(&ngx_srt_conns, &sc->node);

    return NGX_OK;
}


/* Context: NGX thread */
ngx_srt_conn_t *
ngx_srt_conn_create_connect(ngx_log_t *log, ngx_url_t *url, size_t in_buf_size,
    ngx_str_t *stream_id, ngx_str_t *passphrase)
{
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;

    sc = ngx_srt_conn_create(log, in_buf_size);
    if (sc == NULL) {
        return NULL;
    }

    c = sc->connection;

    c->addr_text = url->url;
    c->sockaddr = &url->sockaddr.sockaddr;
    c->socklen = url->socklen;

    if (stream_id->len > 0) {
        sc->stream_id.data = ngx_pstrdup(c->pool, stream_id);
        if (sc->stream_id.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, sc->srt_pool->log, 0,
                "ngx_srt_conn_create_connect: alloc stream id failed");
            ngx_srt_conn_destroy(sc);
            return NULL;
        }

        sc->stream_id.len = stream_id->len;
    }

    if (passphrase->len > 0) {
        sc->passphrase.data = ngx_pstrdup(c->pool, passphrase);
        if (sc->passphrase.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, sc->srt_pool->log, 0,
                "ngx_srt_conn_create_connect: alloc passphrase failed");
            ngx_srt_conn_destroy(sc);
            return NULL;
        }

        sc->passphrase.len = passphrase->len;
    }

    ngx_srt_conn_post_srt(sc, NGX_SRT_POST_CONNECT);

    return sc;
}


/* Context: SRT thread */
static void
ngx_srt_conn_connect_handler(ngx_srt_conn_t *sc)
{
    int                events;
    int                serr, serrno;
    SRTSOCKET          ss;
    ngx_connection_t  *c;

    ss = ngx_srt_create_socket(sc->srt_pool->log);
    if (ss == SRT_INVALID_SOCK) {
        goto failed;
    }

    if (sc->stream_id.len > 0) {
        if (srt_setsockflag(ss, SRTO_STREAMID,
            sc->stream_id.data, sc->stream_id.len) != 0)
        {
            serr = srt_getlasterror(&serrno);
            ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                "ngx_srt_conn_connect: "
                "srt_setsockflag(SRTO_STREAMID) failed %d", serr);
            goto failed;
        }
    }

    if (sc->passphrase.len > 0) {
        if (srt_setsockflag(ss, SRTO_PASSPHRASE,
            sc->passphrase.data, sc->passphrase.len) != 0)
        {
            serr = srt_getlasterror(&serrno);
            ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
                "ngx_srt_conn_connect: "
                "srt_setsockflag(SRTO_PASSPHRASE) failed %d", serr);
            goto failed;
        }
    }

    events = SRT_EPOLL_IN|SRT_EPOLL_OUT|SRT_EPOLL_ERR|SRT_EPOLL_ET;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, sc->srt_pool->log, 0,
        "ngx_srt_conn_connect: epoll add event: fd:%D ev:%08Xd", ss, events);

    if (srt_epoll_add_usock(ngx_srt_epoll_id, ss, &events) < 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
            "ngx_srt_conn_connect: srt_epoll_add_usock() failed %d", serr);
        goto failed;
    }

    c = sc->connection;

    if (srt_connect(ss, c->sockaddr, c->socklen) < 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
            "ngx_srt_conn_connect: srt_connect() failed %d", serr);
        goto failed;
    }

    if (ngx_srt_conn_attach(sc, ss) != NGX_OK) {
        goto failed;
    }

    ngx_log_error(NGX_LOG_INFO, sc->srt_pool->log, 0,
        "ngx_srt_conn_connect: socket %D connecting to \"%V\", conn: %p",
        ss, &c->addr_text, sc);

    ngx_srt_conn_post_ngx(sc, NGX_SRT_POST_WRITE);

    return;

failed:

    if (ss != SRT_INVALID_SOCK) {
        if (srt_close(ss) < 0) {
            ngx_log_error(NGX_LOG_ALERT, sc->srt_pool->log, 0,
                "ngx_srt_conn_connect: srt_close() failed");
        }
    }

    ngx_srt_conn_close(sc);
}


/* Context: NGX thread / SRT thread (only when not fully initialized) */
static void
ngx_srt_conn_destroy(ngx_srt_conn_t *sc)
{
    ngx_connection_t  *c;

    c = sc->connection;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    ngx_destroy_pool(sc->srt_pool);
    ngx_destroy_pool(sc->connection->pool);
}


/* Context: NGX thread */
void
ngx_srt_conn_finalize(ngx_srt_conn_t *sc, ngx_uint_t rc)
{
    ngx_srt_stream_t  *st;
    ngx_connection_t  *pc;

    ngx_log_debug1(NGX_LOG_DEBUG_SRT, sc->connection->log, 0,
        "ngx_srt_conn_finalize: finalize srt conn: %i", rc);

    sc->status = rc;

    if (sc->log_session) {
        sc->log_session(sc);
        sc->log_session = NULL;
    }

    st = sc->stream;
    if (st && st->close_conn) {
        pc = st->connection;
        ngx_log_debug1(NGX_LOG_DEBUG_SRT, sc->connection->log, 0,
            "ngx_srt_conn_finalize: close srt stream connection: %d", pc->fd);

        ngx_close_connection(pc);
        st->connection = NULL;
        st->connected = 0;
        st->close_conn = 0;
    }

    ngx_srt_conn_post_srt(sc, NGX_SRT_POST_CLOSE);
}


/* Context: SRT thread */
static void
ngx_srt_conn_close(ngx_srt_conn_t *sc)
{
    SRTSOCKET          ss;
    ngx_connection_t  *c;

    c = sc->connection;
    c->error = 1;

    ss = ngx_srt_session_sock(sc);
    if (ss != SRT_INVALID_SOCK) {
        ngx_log_error(NGX_LOG_INFO, sc->srt_pool->log, 0,
            "ngx_srt_conn_close: closing socket %D", ss);

        if (srt_close(ss) < 0) {
            ngx_log_error(NGX_LOG_ALERT, sc->srt_pool->log, 0,
                "ngx_srt_conn_close: srt_close() failed");
        }

        ngx_rbtree_delete(&ngx_srt_conns, &sc->node);

#if (NGX_STAT_STUB)
        if (c->listening) {
            (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
        }
#endif

        c->fd = SRT_INVALID_SOCK;
        sc->node.key = SRT_INVALID_SOCK;
    }

    ngx_srt_conn_unpost_srt(sc);

    ngx_srt_conn_post_ngx(sc, NGX_SRT_POST_CLOSE);
}


/* Context: NGX thread */
static void
ngx_srt_conn_terminate(ngx_srt_conn_t *sc)
{
    ngx_srt_stream_t  *st;
    ngx_connection_t  *pc;

    if (sc->log_session) {
        sc->log_session(sc);
    }

    st = sc->stream;
    if (st && st->close_conn) {
        pc = st->connection;
        ngx_log_debug1(NGX_LOG_DEBUG_SRT, sc->connection->log, 0,
            "ngx_srt_conn_terminate: close srt stream connection: %d",
            pc->fd);

        ngx_close_connection(pc);
        st->connection = NULL;
        st->connected = 0;
    }

    ngx_srt_conn_destroy(sc);
}


/* Context: SRT thread */
static ngx_rbtree_node_t *
ngx_srt_conn_lookup(SRTSOCKET ss)
{
    ngx_rbtree_t       *rbtree = &ngx_srt_conns;
    ngx_rbtree_node_t  *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if ((ngx_rbtree_key_t) ss < node->key) {
            node = node->left;

        } else if ((ngx_rbtree_key_t) ss > node->key) {
            node = node->right;

        } else {
            return node;
        }
    }

    return NULL;
}


/* Context: NGX thread */
static void
ngx_srt_conn_accept_handler(ngx_event_t *ev)
{
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;

    c = ev->data;
    sc = c->data;

    sc->connected = 1;

    c->listening->handler(c);
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_set_remote_addr(ngx_connection_t *c,
    const struct sockaddr *sockaddr, int socklen)
{
    c->sockaddr = ngx_palloc(c->pool, socklen);
    if (c->sockaddr == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_conn_set_remote_addr: alloc sockaddr failed");
        return NGX_ERROR;
    }

    ngx_memcpy(c->sockaddr, sockaddr, socklen);
    c->socklen = socklen;

    c->addr_text.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (c->addr_text.data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_conn_set_remote_addr: alloc addr text failed");
        return NGX_ERROR;
    }

    c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
        c->addr_text.data, NGX_SOCKADDR_STRLEN, 1);
    if (c->addr_text.len == 0) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_srt_conn_set_remote_addr: ngx_sock_ntop() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_conn_accept(ngx_srt_listening_t *sls, SRTSOCKET ss,
    struct sockaddr *sockaddr, int socklen)
{
    int                serr, serrno;
    int                stream_id_len;
    ngx_srt_conn_t    *sc;
    ngx_connection_t  *c;
    char               stream_id[NGX_SRT_STREAM_ID_LEN];

    sc = ngx_srt_conn_create(sls->error_log, sls->in_buf_size);
    if (sc == NULL) {
        return NGX_ERROR;
    }

    c = sc->connection;

    c->log->handler = ngx_srt_conn_log_error;
    c->log->data = sc;

    sc->srt_pool->log->handler = ngx_srt_conn_log_error;
    sc->srt_pool->log->data = sc;

    c->listening = sls->ls;

    /* copy stream id */

    stream_id_len = sizeof(stream_id);
    if (srt_getsockflag(ss, SRTO_STREAMID, &stream_id, &stream_id_len) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, serrno,
            "ngx_srt_conn_accept: srt_getsockflag(SRTO_STREAMID) failed %d",
            serr);
        goto failed;
    }

    if (stream_id_len > 0) {
        sc->stream_id.data = ngx_palloc(c->pool, stream_id_len);
        if (sc->stream_id.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, sc->srt_pool->log, 0,
                "ngx_srt_conn_accept: alloc stream id failed");
            goto failed;
        }

        ngx_memcpy(sc->stream_id.data, stream_id, stream_id_len);
        sc->stream_id.len = stream_id_len;
    }

    /* get remote addr */

    if (ngx_srt_conn_set_remote_addr(c, sockaddr, socklen) != NGX_OK) {
        goto failed;
    }

    /* attach */

    if (ngx_srt_conn_attach(sc, ss) != NGX_OK) {
        goto failed;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    ngx_log_error(NGX_LOG_INFO, sc->srt_pool->log, 0,
        "ngx_srt_conn_accept: socket %D accepted, conn: %p", ss, sc);

    /* invoke handler */

    c->read->handler = ngx_srt_conn_accept_handler;

    ngx_srt_conn_post_ngx(sc, NGX_SRT_POST_READ);

    return NGX_OK;

failed:

    ngx_srt_conn_destroy(sc);

    return NGX_ERROR;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_accept(ngx_srt_listening_t *sls)
{
    int             events;
    int             socklen;
    int             serr, serrno;
    SRTSOCKET       ss, lss;
    SRT_SOCKSTATUS  status;
    ngx_sockaddr_t  sa;

    lss = ngx_srt_session_sock(sls);

    status = srt_getsockstate(lss);
    if (status != SRTS_LISTENING) {
        ngx_log_error(NGX_LOG_ALERT, &sls->ls->log, 0,
            "ngx_srt_accept: unexpected socket status %d (%V)",
            status, ngx_srt_get_status_str(status));
    }

    socklen = sizeof(ngx_sockaddr_t);

    ss = srt_accept(lss, &sa.sockaddr, &socklen);
    if (SRT_INVALID_SOCK == ss) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, &sls->ls->log, serrno,
            "ngx_srt_accept: srt_accept() failed %d", serr);
        return NGX_ERROR;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

    events = SRT_EPOLL_IN|SRT_EPOLL_OUT|SRT_EPOLL_ERR|SRT_EPOLL_ET;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, &sls->ls->log, 0,
        "ngx_srt_accept: epoll add event: fd:%D ev:%08Xd", ss, events);

    if (srt_epoll_add_usock(ngx_srt_epoll_id, ss, &events) < 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, &sls->ls->log, serrno,
            "ngx_srt_accept: srt_epoll_add_usock() failed %d", serr);
        goto failed;
    }

    if (ngx_srt_conn_accept(sls, ss, &sa.sockaddr, socklen) != NGX_OK) {
        goto failed;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

    return NGX_OK;

failed:

    if (srt_close(ss) < 0) {
        ngx_log_error(NGX_LOG_ALERT, &sls->ls->log, 0,
            "ngx_srt_accept: srt_close() failed");
    }

    return NGX_ERROR;
}


/* Context: libsrt accept thread */
static int
ngx_srt_listen_callback(void *data, SRTSOCKET ns, int hs_version,
    const struct sockaddr *peeraddr, const char *stream_id)
{
    int                       socklen;
    int                       serr, serrno;
    ngx_str_t                 value;
    ngx_log_t                *log;
    ngx_srt_conn_t           *sc;
    ngx_connection_t         *c;
    ngx_srt_session_t        *s;
    ngx_srt_conf_ctx_t       *ctx;
    ngx_srt_listening_t      *sls = data;
    ngx_srt_core_srv_conf_t  *cscf;

    ctx = sls->ls->servers;

    cscf = ngx_srt_get_module_srv_conf(ctx, ngx_srt_core_module);

    if (cscf->passphrase == NULL) {
        return 0;
    }

    /* allocate temp session for variable eval */
    log = cscf->error_log;

    sc = ngx_srt_conn_alloc(log);
    if (sc == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_srt_listen_callback: alloc conn failed");
        return -1;
    }

    c = sc->connection;
    c->listening = sls->ls;
    sc->srt_pool = c->pool;

    s = ngx_srt_init_session(sc);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_srt_listen_callback: init session failed");
        goto failed;
    }

    /* initialize fields used by variable handlers */
    switch (peeraddr->sa_family) {

    case AF_INET:
        socklen = sizeof(struct sockaddr_in);
        break;

    case AF_INET6:
        socklen = sizeof(struct sockaddr_in6);
        break;

    default:
        socklen = 0;
    }

    if (ngx_srt_conn_set_remote_addr(c, peeraddr, socklen) != NGX_OK) {
        goto failed;
    }

    sc->stream_id.data = (u_char *) stream_id;
    sc->stream_id.len = ngx_strlen(stream_id);

    /* evaluate the passphrase */
    if (ngx_srt_complex_value(s, cscf->passphrase, &value) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_srt_listen_callback: complex value failed");
        goto failed;
    }

    if (value.len == 0) {
        ngx_destroy_pool(c->pool);
        return 0;
    }

    /* set the passphrase */
    if (value.len < 10 || value.len >= 80) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_srt_listen_callback: invalid passphrase \"%V\"", &value);
        goto failed;
    }

    if (srt_setsockflag(ns, SRTO_PASSPHRASE, value.data, value.len) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_ERR, log, serrno,
            "ngx_srt_listen_callback: "
            "srt_setsockflag(SRTO_PASSPHRASE) failed %d", serr);
        goto failed;
    }

    ngx_destroy_pool(c->pool);

    return 0;

failed:

    ngx_destroy_pool(c->pool);

    return -1;
}


/* Context: SRT thread */
ngx_int_t
ngx_srt_listen(ngx_cycle_t *cycle, ngx_listening_t *ls, ngx_log_t *error_log,
    size_t in_buf_size, ngx_srt_conn_options_t *opts)
{
    int                   events;
    int                   serr, serrno;
    SRTSOCKET             ss;
    ngx_srt_listening_t  *sls;

    ss = ngx_srt_create_socket(&ls->log);
    if (ss == SRT_INVALID_SOCK) {
        return NGX_ERROR;
    }

    ngx_srt_configure_socket(&ls->log, ss, opts);

    sls = ngx_pcalloc(cycle->pool, sizeof(ngx_srt_listening_t));
    if (sls == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
            "ngx_srt_listen: ngx_srt_listen: alloc session failed");
        return NGX_ERROR;
    }

    if (srt_listen_callback(ss, ngx_srt_listen_callback, sls) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_listen: srt_listen_callback() failed %d", serr);
        return NGX_ERROR;
    }

    if (srt_bind_acquire(ss, ls->fd) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_listen: srt_bind_acquire() failed %d", serr);
        return NGX_ERROR;
    }

    if (srt_listen(ss, ls->backlog) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_listen: srt_listen() failed %d", serr);
        return NGX_ERROR;
    }

    events = SRT_EPOLL_IN|SRT_EPOLL_ERR;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
        "ngx_srt_listen: epoll add event: fd:%D ev:%08Xd", ss, events);

    if (srt_epoll_add_usock(ngx_srt_epoll_id, ss, &events) != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_listen: srt_epoll_add_usock() failed %d", serr);
        return NGX_ERROR;
    }

    sls->ls = ls;

    sls->error_log = error_log;
    sls->in_buf_size = in_buf_size;

    sls->node.key = ss;
    sls->node.data = 1;

    ngx_rbtree_insert(&ngx_srt_conns, &sls->node);

    ngx_log_error(NGX_LOG_INFO, &ls->log, 0,
        "ngx_srt_listen: %D listening on \"%V\"", ss, &ls->addr_text);

    return NGX_OK;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_thread_init(ngx_cycle_t *cycle)
{
    int  epoll_id;
    int  serr, serrno;

    epoll_id = srt_epoll_create();
    if (epoll_id < 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_thread_init: srt_epoll_create() failed %d", serr);
        return NGX_ERROR;
    }

    ngx_srt_epoll_id = epoll_id;

    if (ngx_srt_epoll_notify_init(cycle->log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_srt_start_listening(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_flag_t
ngx_srt_is_socket_in_list(SRTSOCKET ss, SRTSOCKET *fds, int fds_len)
{
    int  i;

    for (i = 0; i < fds_len; i++) {
        if (fds[i] == ss) {
            return 1;
        }
    }

    return 0;
}


/* Context: SRT thread */
static ngx_int_t
ngx_srt_process_events(ngx_cycle_t *cycle)
{
    int                   i, n;
    int                   serr, serrno;
    int                   sys_fds_len;
    int                   read_fds_len;
    int                   write_fds_len;
    ngx_uint_t            level;
    SRTSOCKET             ss;
    SYSSOCKET             sys_fds[1];
    SRTSOCKET             read_fds[NGX_SRT_EPOLL_EVENTS];
    SRTSOCKET             write_fds[NGX_SRT_EPOLL_EVENTS];
    ngx_srt_conn_t       *sc;
    ngx_rbtree_node_t    *node;
    ngx_srt_listening_t  *sls;

    read_fds_len = NGX_SRT_EPOLL_EVENTS;
    write_fds_len = NGX_SRT_EPOLL_EVENTS;
    sys_fds_len = 1;

    n = srt_epoll_wait(ngx_srt_epoll_id, read_fds, &read_fds_len,
        write_fds, &write_fds_len, NGX_SRT_EPOLL_TIMEOUT,
        sys_fds, &sys_fds_len, NULL, NULL);
    if (n < 0) {
        serr = srt_getlasterror(&serrno);
        if (serr == SRT_ETIMEOUT) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, serrno,
            "ngx_srt_process_events: srt_epoll_wait() failed %d", serr);
        return NGX_ERROR;
    }

    ngx_time_update();

    /* notifications */

    if (sys_fds_len > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
            "ngx_srt_process_events: epoll sys fd:%D", sys_fds[0]);

        while (ngx_srt_srt_posted_handler(cycle->log));
    }

    /* read / accept */

    for (i = 0; i < read_fds_len; i++) {
        ss = read_fds[i];

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
            "ngx_srt_process_events: epoll read fd:%D", ss);

        node = ngx_srt_conn_lookup(ss);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "ngx_srt_process_events: read socket %D not found", ss);
            continue;
        }

        if (node->data) {
            /* listening sock */
            sls = ngx_rbtree_data(node, ngx_srt_listening_t, node);

            (void) ngx_srt_accept(sls);

        } else {
            /* connected sock */
            sc = ngx_rbtree_data(node, ngx_srt_conn_t, node);

            ngx_srt_conn_read_handler(sc);
        }
    }

    /* write */

    for (i = 0; i < write_fds_len; i++) {
        ss = write_fds[i];

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
            "ngx_srt_process_events: epoll write fd:%D", ss);

        node = ngx_srt_conn_lookup(ss);
        if (node == NULL) {
            if (ngx_srt_is_socket_in_list(ss, read_fds, read_fds_len)) {
                /* socket was probably closed while handling read event */
                level = NGX_LOG_INFO;

            } else {
                level = NGX_LOG_ALERT;
            }

            ngx_log_error(level, cycle->log, 0,
                "ngx_srt_process_events: write socket %D not found", ss);
            continue;
        }

        sc = ngx_rbtree_data(node, ngx_srt_conn_t, node);

        ngx_srt_conn_write_handler(sc);
    }

    return NGX_OK;
}


/* Context: SRT thread */
static void *
ngx_srt_thread_cycle(void *data)
{
    ngx_cycle_t  *cycle;

    cycle = data;

    ngx_log_debug0(NGX_LOG_DEBUG_SRT, ngx_cycle->log, 0,
        "ngx_srt_thread_cycle: thread started");

    if (ngx_srt_thread_init(cycle) != NGX_OK) {
        /* set the thread counter to -1 to report error */
        goto done;
    }

    (void) ngx_atomic_fetch_add(ngx_srt_threads, 1);

    while (!ngx_terminate && !ngx_exiting) {

        if (ngx_srt_process_events(cycle) != NGX_OK) {
            break;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_SRT, ngx_cycle->log, 0,
        "ngx_srt_thread_cycle: thread done");

done:

    (void) ngx_atomic_fetch_add(ngx_srt_threads, -1);

    return NULL;
}


/* Context: NGX thread */
static ngx_int_t
ngx_srt_thread_create(ngx_cycle_t *cycle)
{
    int             err;
    pthread_t       tid;
    ngx_uint_t      i;
    pthread_attr_t  attr;

    err = pthread_attr_init(&attr);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
            "ngx_srt_thread_create: pthread_attr_init() failed");
        return NGX_ERROR;
    }

    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
            "ngx_srt_thread_create: pthread_attr_setdetachstate() failed");
        (void) pthread_attr_destroy(&attr);
        return NGX_ERROR;
    }

    err = pthread_create(&tid, &attr, ngx_srt_thread_cycle, cycle);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
            "ngx_srt_thread_create: pthread_create() failed");
        (void) pthread_attr_destroy(&attr);
        return NGX_ERROR;
    }

    (void) pthread_attr_destroy(&attr);

    /* wait until the thread initializes */

    for (i = 0; ; i++) {

        if (i >= 50) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "ngx_srt_thread_create: "
                "timed out waiting for thread to start");
            return NGX_ERROR;
        }

        if (*ngx_srt_threads > 0) {
            break;
        }

        if (*ngx_srt_threads < 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                "ngx_srt_thread_create: thread failed to initialize");
            break;
        }

        ngx_msleep(100);
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, err,
        "ngx_srt_thread_create: thread initialized successfully");

    return NGX_OK;
}


/* Context: NGX thread */
ngx_int_t
ngx_srt_init_worker(ngx_cycle_t *cycle)
{
    int  serr, serrno;

    if (srt_startup() != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_init_worker: srt_startup() failed %d", serr);
        return NGX_ERROR;
    }

    ngx_rbtree_init(&ngx_srt_conns, &ngx_srt_conns_sentinel,
        ngx_rbtree_insert_value);

    if (ngx_srt_thread_create(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Context: NGX thread */
void
ngx_srt_exit_worker(ngx_cycle_t *cycle)
{
    int         serr, serrno;
    ngx_uint_t  i;

    for (i = 0; ; i++) {

        if (i >= 50) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "ngx_srt_exit_worker: timed out waiting for threads to quit");
            return;
        }

        if (*ngx_srt_threads <= 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_SRT, cycle->log, 0,
                "ngx_srt_exit_worker: all threads finished");
            break;
        }

        ngx_msleep(100);
    }

    if (srt_cleanup() != 0) {
        serr = srt_getlasterror(&serrno);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, serrno,
            "ngx_srt_exit_worker: srt_cleanup() failed %d", serr);
    }
}
