
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <srt/srt.h>
#include "ngx_srt.h"
#include "ngx_srt_stats.h"


#define NGX_SRT_STATS_DEFAULT_ZONE  "srt_stats"
#define NGX_SRT_STATS_DEFAULT_SIZE  (1024 * 1024)


static char *ngx_srt_stats_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_srt_stats_create_zone(ngx_conf_t *cf, ngx_str_t *name,
    ssize_t size);
static ngx_int_t ngx_srt_stats_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_srt_stats_init_zone(ngx_shm_zone_t *shm_zone, void *data);


ngx_shm_zone_t  *ngx_srt_stats_shm_zone = NULL;


static ngx_command_t  ngx_srt_stats_commands[] = {

    { ngx_string("srt_stats_zone"),
      NGX_SRT_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_srt_stats_zone,
      NGX_SRT_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_srt_module_t  ngx_srt_stats_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_srt_stats_postconfiguration,       /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_srt_stats_module = {
    NGX_MODULE_V1,
    &ngx_srt_stats_module_ctx,             /* module context */
    ngx_srt_stats_commands,                /* module directives */
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


static char *
ngx_srt_stats_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char      *p;
    ssize_t      size;
    ngx_str_t   *value, name, s;

    value = cf->args->elts;

    if (ngx_srt_stats_shm_zone != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"srt_stats_zone\" is specified more than once");
        return NGX_CONF_ERROR;
    }

    /* value[1] is "<name>:<size>" */

    p = (u_char *) ngx_strlchr(value[1].data, value[1].data + value[1].len,
                               ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"srt_stats_zone\" value \"%V\", "
                           "expected \"name:size\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len = p - value[1].data;

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = ngx_parse_size(&s);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone size \"%V\"", &s);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || (size_t) size < 8 * ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"srt_stats_zone\" value \"%V\", "
                           "zone must have a name and be at least %uz bytes",
                           &value[1], (size_t) (8 * ngx_pagesize));
        return NGX_CONF_ERROR;
    }

    return ngx_srt_stats_create_zone(cf, &name, size);
}


/*
 * Register the stats shared memory zone. Shared by the "srt_stats_zone"
 * directive (explicit name/size) and by postconfiguration (built-in default).
 */
static char *
ngx_srt_stats_create_zone(ngx_conf_t *cf, ngx_str_t *name, ssize_t size)
{
    ngx_shm_zone_t  *shm_zone;

    shm_zone = ngx_shared_memory_add(cf, name, size, &ngx_srt_stats_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate shared memory zone \"%V\"", name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_srt_stats_init_zone;

    ngx_srt_stats_shm_zone = shm_zone;

    return NGX_CONF_OK;
}


/*
 * When "srt_stats_zone" is not configured, create a default zone so the SRT
 * stats feature works out of the box. An explicit directive overrides this.
 */
static ngx_int_t
ngx_srt_stats_postconfiguration(ngx_conf_t *cf)
{
    size_t     size;
    ngx_str_t  name = ngx_string(NGX_SRT_STATS_DEFAULT_ZONE);

    if (ngx_srt_stats_shm_zone != NULL) {
        /* explicitly configured via "srt_stats_zone" */
        return NGX_OK;
    }

    size = ngx_max((size_t) NGX_SRT_STATS_DEFAULT_SIZE, 8 * ngx_pagesize);

    if (ngx_srt_stats_create_zone(cf, &name, (ssize_t) size) != NGX_CONF_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_srt_stats_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_srt_stats_shctx_t  *octx = data;

    ngx_slab_pool_t        *shpool;
    ngx_srt_stats_shctx_t  *ctx;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (octx) {
        /* reload: keep the entries collected by the previous cycle */
        shm_zone->data = octx;
        return NGX_OK;
    }

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    ctx = ngx_slab_alloc(shpool, sizeof(ngx_srt_stats_shctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&ctx->queue);

    shpool->data = ctx;
    shm_zone->data = ctx;

    return NGX_OK;
}


/* Context: SRT thread */
void
ngx_srt_stats_add(ngx_srt_conn_t *sc)
{
    size_t                  len;
    ngx_slab_pool_t        *shpool;
    ngx_srt_stat_node_t    *node;
    ngx_srt_stats_shctx_t  *ctx;

    if (ngx_srt_stats_shm_zone == NULL) {
        return;
    }

    ctx = ngx_srt_stats_shm_zone->data;
    shpool = (ngx_slab_pool_t *) ngx_srt_stats_shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_slab_calloc_locked(shpool, sizeof(ngx_srt_stat_node_t));
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, sc->srt_pool->log, 0,
            "ngx_srt_stats_add: no memory in srt_stats_zone, "
            "connection not tracked");
        return;
    }

    node->pid = ngx_pid;
    node->socket = (int) sc->node.key;
    node->connection = (sc->connection != NULL) ? sc->connection->number : 0;
    node->status = sc->status;
    node->start_sec = sc->start_sec;
    node->last_update = ngx_current_msec;

    len = ngx_min(sc->stream_id.len, (size_t) NGX_SRT_STATS_STREAM_ID_LEN);
    ngx_memcpy(node->stream_id, sc->stream_id.data, len);
    node->stream_id_len = len;

    if (sc->connection != NULL) {
        len = ngx_min(sc->connection->addr_text.len,
                      (size_t) NGX_SRT_STATS_ADDR_LEN);
        ngx_memcpy(node->addr, sc->connection->addr_text.data, len);
        node->addr_len = len;
    }

    ngx_queue_insert_head(&ctx->queue, &node->queue);

    ngx_shmtx_unlock(&shpool->mutex);

    sc->stats_node = node;
}


/* Context: SRT thread */
void
ngx_srt_stats_update(ngx_srt_conn_t *sc, SRT_TRACEBSTATS *stats)
{
    ngx_slab_pool_t      *shpool;
    ngx_srt_stat_node_t  *node;

    node = sc->stats_node;
    if (node == NULL) {
        return;
    }

    shpool = (ngx_slab_pool_t *) ngx_srt_stats_shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node->status = sc->status;
    node->last_update = ngx_current_msec;

    node->pkt_sent_total = stats->pktSentTotal;
    node->pkt_recv_total = stats->pktRecvTotal;
    node->pkt_snd_loss_total = stats->pktSndLossTotal;
    node->pkt_rcv_loss_total = stats->pktRcvLossTotal;
    node->pkt_retrans_total = stats->pktRetransTotal;
    node->pkt_snd_drop_total = stats->pktSndDropTotal;
    node->pkt_rcv_drop_total = stats->pktRcvDropTotal;
    node->pkt_rcv_undecrypt_total = stats->pktRcvUndecryptTotal;
    node->pkt_rcv_belated = stats->pktRcvBelated;
    node->pkt_rcv_retrans = stats->pktRcvRetrans;

    node->byte_sent_total = stats->byteSentTotal;
    node->byte_recv_total = stats->byteRecvTotal;
    node->byte_rcv_loss_total = stats->byteRcvLossTotal;
    node->byte_retrans_total = stats->byteRetransTotal;

    node->ms_rtt = stats->msRTT;
    node->mbps_bandwidth = stats->mbpsBandwidth;
    node->mbps_recv_rate = stats->mbpsRecvRate;
    node->mbps_send_rate = stats->mbpsSendRate;
    node->pkt_flow_window = stats->pktFlowWindow;
    node->pkt_congestion_window = stats->pktCongestionWindow;
    node->pkt_flight_size = stats->pktFlightSize;
    node->ms_rcv_buf = stats->msRcvBuf;
    node->ms_snd_buf = stats->msSndBuf;

    ngx_shmtx_unlock(&shpool->mutex);
}


/* Context: SRT thread */
void
ngx_srt_stats_remove(ngx_srt_conn_t *sc)
{
    ngx_slab_pool_t      *shpool;
    ngx_srt_stat_node_t  *node;

    node = sc->stats_node;
    if (node == NULL) {
        return;
    }

    shpool = (ngx_slab_pool_t *) ngx_srt_stats_shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_queue_remove(&node->queue);
    ngx_slab_free_locked(shpool, node);

    ngx_shmtx_unlock(&shpool->mutex);

    sc->stats_node = NULL;
}
