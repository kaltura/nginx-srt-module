#ifndef _NGX_SRT_STATS_H_INCLUDED_
#define _NGX_SRT_STATS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <srt/srt.h>
#include "ngx_srt.h"


#define NGX_SRT_STATS_STREAM_ID_LEN  256
#define NGX_SRT_STATS_ADDR_LEN       NGX_SOCKADDR_STRLEN

/* min interval between srt_bstats() collection passes, in milliseconds */
#define NGX_SRT_STATS_INTERVAL       1000


/* shared context, stored in the slab pool's ->data */
typedef struct {
    ngx_queue_t   queue;        /* of ngx_srt_stat_node_t.queue */
} ngx_srt_stats_shctx_t;


/*
 * One entry per live connection, allocated from the shm slab by the owning
 * worker's SRT thread. All pointers live in shared memory that is mapped at
 * the same address in every worker (the zone is created before fork), so the
 * queue is walkable from any worker's HTTP handler.
 */
typedef struct {
    ngx_queue_t   queue;

    ngx_pid_t     pid;
    int           socket;
    ngx_uint_t    connection;   /* nginx connection serial ($connection) */

    ngx_uint_t    status;
    time_t        start_sec;
    ngx_msec_t    last_update;

    /* identity */
    u_char        stream_id[NGX_SRT_STATS_STREAM_ID_LEN];
    size_t        stream_id_len;
    u_char        addr[NGX_SRT_STATS_ADDR_LEN];
    size_t        addr_len;

    /* cumulative packet counters (SRT_TRACEBSTATS *Total fields) */
    int64_t       pkt_sent_total;
    int64_t       pkt_recv_total;
    int64_t       pkt_snd_loss_total;
    int64_t       pkt_rcv_loss_total;
    int64_t       pkt_retrans_total;         /* retransmitted by sender */
    int64_t       pkt_snd_drop_total;
    int64_t       pkt_rcv_drop_total;
    int64_t       pkt_rcv_undecrypt_total;
    int64_t       pkt_rcv_belated;           /* no cumulative field in libsrt */

    /* interval-scoped: retransmitted packets received (i.e. recovered) */
    int64_t       pkt_rcv_retrans;

    /* cumulative byte counters */
    uint64_t      byte_sent_total;
    uint64_t      byte_recv_total;
    uint64_t      byte_rcv_loss_total;
    uint64_t      byte_retrans_total;

    /* instantaneous health */
    double        ms_rtt;
    double        mbps_bandwidth;
    double        mbps_recv_rate;
    double        mbps_send_rate;
    int64_t       pkt_flow_window;
    int64_t       pkt_congestion_window;
    int64_t       pkt_flight_size;
    int64_t       ms_rcv_buf;
    int64_t       ms_snd_buf;
} ngx_srt_stat_node_t;


/*
 * Set by the "srt_stats_zone" directive (single zone). NULL => the whole
 * stats feature is disabled and all helpers below are no-ops.
 */
extern ngx_shm_zone_t  *ngx_srt_stats_shm_zone;


/* Context: SRT thread. Create/remove this connection's shm entry. */
void ngx_srt_stats_add(ngx_srt_conn_t *sc);
void ngx_srt_stats_remove(ngx_srt_conn_t *sc);

/* Context: SRT thread. Copy a fresh srt_bstats() snapshot into the entry. */
void ngx_srt_stats_update(ngx_srt_conn_t *sc, SRT_TRACEBSTATS *stats);


#endif /* _NGX_SRT_STATS_H_INCLUDED_ */
