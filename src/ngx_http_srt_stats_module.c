
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_srt_stats.h"


/*
 * Upper bound on the JSON text for a single connection object. The 2048-byte
 * base covers all field names plus the worst-case decimal width of every
 * numeric value (~1.2 KB in practice); the two escaped-string terms add the
 * worst-case 6x (\u00xx) expansion of the stream id and remote address.
 * The response buffer reserves this many bytes per connection, and the render
 * loop never renders a node without this much room left, so the buffer cannot
 * overflow.
 */
#define NGX_HTTP_SRT_STATS_PER_NODE                                          \
    (2048 + NGX_SRT_STATS_STREAM_ID_LEN * 6 + NGX_SRT_STATS_ADDR_LEN * 6)


static char *ngx_http_srt_stats(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_srt_stats_commands[] = {

    { ngx_string("srt_stats"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_srt_stats,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_srt_stats_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_srt_stats_module = {
    NGX_MODULE_V1,
    &ngx_http_srt_stats_module_ctx,        /* module context */
    ngx_http_srt_stats_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char *
ngx_http_srt_stats_json_str(u_char *p, u_char *src, size_t len)
{
    size_t         i;
    u_char         c;
    static u_char  hex[] = "0123456789abcdef";

    for (i = 0; i < len; i++) {
        c = src[i];

        switch (c) {
        case '"':  *p++ = '\\'; *p++ = '"'; break;
        case '\\': *p++ = '\\'; *p++ = '\\'; break;
        case '\n': *p++ = '\\'; *p++ = 'n'; break;
        case '\r': *p++ = '\\'; *p++ = 'r'; break;
        case '\t': *p++ = '\\'; *p++ = 't'; break;
        default:
            if (c < 0x20) {
                *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                *p++ = hex[(c >> 4) & 0x0f];
                *p++ = hex[c & 0x0f];

            } else {
                *p++ = c;
            }
        }
    }

    return p;
}


static u_char *
ngx_http_srt_stats_node(u_char *p, ngx_srt_stat_node_t *sn)
{
    time_t  uptime;

    uptime = ngx_time() - sn->start_sec;
    if (uptime < 0) {
        uptime = 0;
    }

    p = ngx_sprintf(p, "{\"pid\":%P,\"socket\":%d,\"connection\":%ui,"
                       "\"status\":%ui,\"uptime_sec\":%T,",
                    sn->pid, sn->socket, sn->connection, sn->status, uptime);

    p = ngx_cpymem(p, "\"stream_id\":\"", sizeof("\"stream_id\":\"") - 1);
    p = ngx_http_srt_stats_json_str(p, sn->stream_id, sn->stream_id_len);

    p = ngx_cpymem(p, "\",\"remote_addr\":\"",
                   sizeof("\",\"remote_addr\":\"") - 1);
    p = ngx_http_srt_stats_json_str(p, sn->addr, sn->addr_len);
    *p++ = '"';
    *p++ = ',';

    p = ngx_sprintf(p, "\"pkt_sent_total\":%L,\"pkt_recv_total\":%L,"
                       "\"pkt_snd_loss_total\":%L,\"pkt_rcv_loss_total\":%L,"
                       "\"pkt_retrans_total\":%L,\"pkt_rcv_retrans\":%L,"
                       "\"pkt_snd_drop_total\":%L,\"pkt_rcv_drop_total\":%L,"
                       "\"pkt_rcv_undecrypt_total\":%L,\"pkt_rcv_belated\":%L,",
                    sn->pkt_sent_total, sn->pkt_recv_total,
                    sn->pkt_snd_loss_total, sn->pkt_rcv_loss_total,
                    sn->pkt_retrans_total, sn->pkt_rcv_retrans,
                    sn->pkt_snd_drop_total, sn->pkt_rcv_drop_total,
                    sn->pkt_rcv_undecrypt_total, sn->pkt_rcv_belated);

    p = ngx_sprintf(p, "\"byte_sent_total\":%uL,\"byte_recv_total\":%uL,"
                       "\"byte_rcv_loss_total\":%uL,\"byte_retrans_total\":%uL,",
                    sn->byte_sent_total, sn->byte_recv_total,
                    sn->byte_rcv_loss_total, sn->byte_retrans_total);

    p = ngx_sprintf(p, "\"ms_rtt\":%.3f,\"mbps_bandwidth\":%.3f,"
                       "\"mbps_recv_rate\":%.3f,\"mbps_send_rate\":%.3f,"
                       "\"pkt_flow_window\":%L,\"pkt_congestion_window\":%L,"
                       "\"pkt_flight_size\":%L,\"ms_rcv_buf\":%L,"
                       "\"ms_snd_buf\":%L}",
                    sn->ms_rtt, sn->mbps_bandwidth, sn->mbps_recv_rate,
                    sn->mbps_send_rate, sn->pkt_flow_window,
                    sn->pkt_congestion_window, sn->pkt_flight_size,
                    sn->ms_rcv_buf, sn->ms_snd_buf);

    return p;
}


static ngx_int_t
ngx_http_srt_stats_handler(ngx_http_request_t *r)
{
    size_t                  size;
    u_char                 *p, *last;
    ngx_uint_t              n, i;
    ngx_int_t               rc;
    ngx_buf_t              *b;
    ngx_queue_t            *q, *head;
    ngx_chain_t             out;
    ngx_slab_pool_t        *shpool;
    ngx_srt_stat_node_t    *sn;
    ngx_srt_stats_shctx_t  *ctx;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ngx_srt_stats_shm_zone == NULL) {

        /* "srt_stats_zone" not configured -> nothing to report */

        size = sizeof("[]\n") - 1;

        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_cpymem(b->last, "[]\n", size);

        goto send;
    }

    shpool = (ngx_slab_pool_t *) ngx_srt_stats_shm_zone->shm.addr;
    ctx = ngx_srt_stats_shm_zone->data;

    /* count entries to size the response buffer */

    ngx_shmtx_lock(&shpool->mutex);

    n = 0;
    for (q = ngx_queue_head(&ctx->queue);
         q != ngx_queue_sentinel(&ctx->queue);
         q = ngx_queue_next(q))
    {
        n++;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    size = 1 /* '[' */ + 2 /* "]\n" */
           + (size_t) n * (NGX_HTTP_SRT_STATS_PER_NODE + 1 /* ',' */);

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->last;
    last = b->end;

    *p++ = '[';

    ngx_shmtx_lock(&shpool->mutex);

    head = &ctx->queue;
    i = 0;

    for (q = ngx_queue_head(head);
         q != ngx_queue_sentinel(head);
         q = ngx_queue_next(q))
    {
        /* do not exceed what we counted / allocated */
        if (i >= n || p + NGX_HTTP_SRT_STATS_PER_NODE + 1 > last) {
            break;
        }

        if (i > 0) {
            *p++ = ',';
        }

        sn = ngx_queue_data(q, ngx_srt_stat_node_t, queue);

        p = ngx_http_srt_stats_node(p, sn);

        i++;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    *p++ = ']';
    *p++ = '\n';

    b->last = p;

send:

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_srt_stats(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_srt_stats_handler;

    return NGX_CONF_OK;
}
