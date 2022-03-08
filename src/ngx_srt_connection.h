#ifndef _NGX_SRT_CONNECTION_H_INCLUDED_
#define _NGX_SRT_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SRT_POST_READ        0x1
#define NGX_SRT_POST_WRITE       0x2
#define NGX_SRT_POST_CONNECT     0x4
#define NGX_SRT_POST_CLOSE       0x8


typedef struct {
    ngx_uint_t                   fc_pkts;
    size_t                       mss;

    size_t                       recv_buf;
    size_t                       recv_udp_buf;
    ngx_msec_t                   recv_latency;

    size_t                       send_buf;
    size_t                       send_udp_buf;
    ngx_msec_t                   send_latency;
} ngx_srt_conn_options_t;


typedef struct {
    ngx_buf_t                    buf;               /* last - shared */

    ngx_chain_t                 *free;              /* shared */
    ngx_chain_t                 *out;               /* shared */
    ngx_chain_t                 *busy;              /* ngx */

    ngx_atomic_t                 lock;
} ngx_srt_conn_in_t;


typedef struct {
    ngx_chain_t                 *free;              /* shared */
    ngx_chain_t                 *out;               /* shared */
    ngx_chain_t                 *busy;              /* srt */

    ngx_atomic_t                 out_lock;
    ngx_atomic_t                 free_lock;

    size_t                       added;             /* ngx */
    size_t                       acked;             /* ngx */
} ngx_srt_conn_out_t;


typedef struct {
    ngx_chain_t                 *from_srt;          /* ngx */
    ngx_chain_t                 *from_ngx;          /* ngx */
} ngx_srt_write_filter_ctx_t;


struct ngx_srt_conn_s {
    ngx_rbtree_node_t            node;              /* srt */

    ngx_pool_t                  *srt_pool;          /* srt */
    ngx_connection_t            *connection;        /* sent, fd - srt
                                                pool, log, read, write - ngx */

    ngx_srt_stream_t            *stream;            /* ngx */
    void                        *session;           /* ngx */
    void                        *upstream;          /* ngx */

    ngx_str_t                    stream_id;
    ngx_str_t                    passphrase;
    uint32_t                     peer_version;
    uint32_t                     payload_size;

    ngx_log_handler_pt           log_handler;
    ngx_pool_cleanup_pt          log_session;

    ngx_uint_t                   status;
    off_t                        received;
    time_t                       start_sec;
    ngx_msec_t                   start_msec;

    ngx_srt_conn_t              *ngx_next;          /* shared */
    uint32_t                     ngx_post_flags;    /* shared */

    ngx_srt_conn_t              *srt_next;          /* shared */
    uint32_t                     srt_post_flags;    /* shared */

    ngx_srt_conn_in_t            srt_in;
    ngx_srt_conn_out_t           srt_out;

    ngx_srt_write_filter_ctx_t   writer_ctx;        /* ngx */

    unsigned                     connected:1;
};


ngx_int_t ngx_srt_init_worker(ngx_cycle_t *cycle);

void ngx_srt_exit_worker(ngx_cycle_t *cycle);


void ngx_srt_merge_options(ngx_srt_conn_options_t *conf,
    ngx_srt_conn_options_t *prev);

ngx_int_t ngx_srt_listen(ngx_cycle_t *cycle, ngx_listening_t *ls,
    ngx_log_t *error_log, size_t in_buf_size, ngx_srt_conn_options_t *opts);

ngx_srt_conn_t *ngx_srt_conn_create_connect(ngx_log_t *log, ngx_url_t *url,
    size_t in_buf_size, ngx_str_t *stream_id, ngx_str_t *passphrase);

void ngx_srt_conn_finalize(ngx_srt_conn_t *sc, ngx_uint_t rc);


ngx_int_t ngx_srt_conn_in_insert_head(ngx_srt_conn_t *sc,
    u_char *start, u_char *end);

ngx_chain_t *ngx_srt_conn_in_get_chain(ngx_srt_conn_t *sc);

void ngx_srt_conn_in_update_chains(ngx_srt_conn_t *sc, ngx_chain_t *out);

#endif /* _NGX_SRT_CONNECTION_H_INCLUDED_ */
