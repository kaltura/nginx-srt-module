#ifndef _NGX_SRT_STREAM_H_INCLUDED_
#define _NGX_SRT_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_srt.h"


typedef struct {
    ngx_connection_t  *connection;

    /* ngx -> srt bufs */
    ngx_buf_t          buf;
    ngx_chain_t       *free;
    ngx_chain_t       *out;
    ngx_chain_t       *busy;

    off_t              received;

    unsigned           connected:1;
    unsigned           close_conn:1;
} ngx_srt_stream_t;


void ngx_srt_proxy_process_srt_to_ngx(ngx_srt_conn_t *sc);

void ngx_srt_proxy_process_ngx_to_srt(ngx_srt_conn_t *sc);

#endif /* _NGX_SRT_STREAM_H_INCLUDED_ */
