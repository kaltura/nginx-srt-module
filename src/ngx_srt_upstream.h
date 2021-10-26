
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SRT_UPSTREAM_H_INCLUDED_
#define _NGX_SRT_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_srt.h"


typedef struct {
    ngx_msec_t                         response_time;
    ngx_msec_t                         connect_time;
    ngx_msec_t                         first_byte_time;
    off_t                              bytes_sent;
    off_t                              bytes_received;

    ngx_str_t                         *peer;
} ngx_srt_upstream_state_t;

#endif /* _NGX_SRT_UPSTREAM_H_INCLUDED_ */
