#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_srt.h"


void
ngx_srt_proxy_process_srt_to_ngx(ngx_srt_conn_t *sc)
{
    ngx_int_t          rc;
    ngx_chain_t       *out;
    ngx_srt_stream_t  *st;
    ngx_connection_t  *c, *dst;

    st = sc->stream;
    if (!st->connected) {
        return;
    }

    dst = st->connection;

    out = ngx_srt_conn_in_get_chain(sc);

    if (out || sc->srt_in.busy || dst->buffered) {
        c = sc->connection;

        c->log->action = "proxying and sending to stream";

        rc = ngx_srt_top_filter(sc, out, 1);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_srt_proxy_process_srt_to_ngx: filter failed %i", rc);
            ngx_srt_conn_finalize(sc, NGX_SRT_OK);
            return;
        }

        ngx_srt_conn_in_update_chains(sc, out);
    }
}


void
ngx_srt_proxy_process_ngx_to_srt(ngx_srt_conn_t *sc)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_int_t          rc;
    ngx_chain_t       *cl, **ll, **out, **busy;
    ngx_connection_t  *c, *pc, *src, *dst;
    ngx_srt_stream_t  *st;

    st = sc->stream;

    c = sc->connection;
    pc = st->connected ? st->connection : NULL;

    src = pc;
    dst = c;
    b = &st->buf;
    out = &st->out;
    busy = &st->busy;

    for ( ;; ) {

        if (dst) {

            if (*out || *busy || dst->buffered) {

                c->log->action = "proxying and sending to srt";

                rc = ngx_srt_top_filter(sc, *out, 0);

                if (rc == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                        "ngx_srt_proxy_process_ngx_to_srt: filter failed %i",
                        rc);
                    ngx_srt_conn_finalize(sc, NGX_SRT_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &st->free, busy, out,
                    (ngx_buf_tag_t) &ngx_srt_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed
            && !src->read->error)
        {
            c->log->action = "proxying and reading from stream";

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = ngx_chain_get_free_buf(src->pool, &st->free);
                if (cl == NULL) {
                    ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                        "ngx_srt_proxy_process_ngx_to_srt: get buf failed");
                    ngx_srt_conn_finalize(sc, NGX_SRT_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_srt_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                st->received += n;
                b->last += n;

                continue;
            }
        }

        break;
    }
}
