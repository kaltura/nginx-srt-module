#ifndef _NGX_SRT_H_INCLUDED_
#define _NGX_SRT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_srt_session_s  ngx_srt_session_t;
typedef struct ngx_srt_conn_s     ngx_srt_conn_t;


#include "ngx_srt_variables.h"
#include "ngx_srt_script.h"
#include "ngx_srt_stream.h"
#include "ngx_srt_upstream.h"
#include "ngx_srt_connection.h"


#define NGX_SRT_OK                        200
#define NGX_SRT_INTERNAL_SERVER_ERROR     500
#define NGX_SRT_BAD_GATEWAY               502


#define NGX_LOG_DEBUG_SRT                 NGX_LOG_DEBUG_STREAM


typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} ngx_srt_conf_ctx_t;


typedef struct {
    struct sockaddr               *sockaddr;
    socklen_t                      socklen;
    ngx_str_t                      addr_text;

    /* server ctx */
    ngx_srt_conf_ctx_t            *ctx;

    unsigned                       bind:1;
    unsigned                       wildcard:1;
#if (NGX_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif
    unsigned                       reuseport:1;
    int                            backlog;
    int                            type;
} ngx_srt_listen_t;


typedef enum {
    NGX_SRT_PRE_LOG_PHASE = 0,
    NGX_SRT_LOG_PHASE
} ngx_srt_phases;


typedef ngx_int_t (*ngx_srt_handler_pt)(ngx_srt_session_t *s);
typedef void (*ngx_srt_content_handler_pt)(ngx_srt_session_t *s);


typedef struct {
    ngx_array_t                    handlers;
} ngx_srt_phase_t;


typedef struct {
    ngx_array_t                    servers;     /* ngx_srt_core_srv_conf_t */
    ngx_array_t                    listening;   /* ngx_srt_listen_t */

    ngx_hash_t                     variables_hash;

    ngx_array_t                    variables;        /* ngx_srt_variable_t */
    ngx_array_t                    prefix_variables; /* ngx_srt_variable_t */
    ngx_uint_t                     ncaptures;

    ngx_uint_t                     variables_hash_max_size;
    ngx_uint_t                     variables_hash_bucket_size;

    ngx_hash_keys_arrays_t        *variables_keys;

    ngx_srt_phase_t                phases[NGX_SRT_LOG_PHASE + 1];
} ngx_srt_core_main_conf_t;


typedef struct {
    ngx_srt_content_handler_pt     handler;

    ngx_srt_conf_ctx_t            *ctx;

    ngx_array_t                   *listen;      /* ngx_srt_listen_t */

    u_char                        *file_name;
    ngx_uint_t                     line;

    ngx_log_t                     *error_log;

    size_t                         in_buf_size;

    ngx_srt_conn_options_t         srt_opts;
    ngx_srt_complex_value_t       *passphrase;
    ngx_srt_complex_value_t       *cryptomode;
} ngx_srt_core_srv_conf_t;


struct ngx_srt_session_s {
    uint32_t                       signature;         /* "SRT " */

    /* Note: connection is copied from ngx_srt_conn_t for script/variables */
    ngx_connection_t              *connection;

    void                         **ctx;
    void                         **main_conf;
    void                         **srv_conf;

    ngx_array_t                   *upstream_states;
                                              /* of ngx_srt_upstream_state_t */
    ngx_srt_variable_value_t      *variables;

#if (NGX_PCRE)
    ngx_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

    ngx_srt_conn_t                *sc;
};


typedef struct {
    ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);

    void                        *(*create_main_conf)(ngx_conf_t *cf);
    char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(ngx_conf_t *cf);
    char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                                   void *conf);
} ngx_srt_module_t;


#define NGX_SRT_MODULE       0x20545253     /* "SRT " */

#define NGX_SRT_MAIN_CONF    0x02000000
#define NGX_SRT_SRV_CONF     0x04000000
#define NGX_SRT_UPS_CONF     0x08000000


#define NGX_SRT_MAIN_CONF_OFFSET  offsetof(ngx_srt_conf_ctx_t, main_conf)
#define NGX_SRT_SRV_CONF_OFFSET   offsetof(ngx_srt_conf_ctx_t, srv_conf)


#define ngx_srt_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_srt_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_srt_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_srt_get_module_main_conf(s, module)                              \
    (s)->main_conf[module.ctx_index]
#define ngx_srt_get_module_srv_conf(s, module)                               \
    (s)->srv_conf[module.ctx_index]

#define ngx_srt_conf_get_module_main_conf(cf, module)                        \
    ((ngx_srt_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_srt_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_srt_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_srt_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_srt_module.index] ?                                 \
        ((ngx_srt_conf_ctx_t *) cycle->conf_ctx[ngx_srt_module.index])       \
            ->main_conf[module.ctx_index]:                                   \
        NULL)


#define NGX_SRT_WRITE_BUFFERED  0x10


extern ngx_module_t  ngx_srt_module;
extern ngx_uint_t    ngx_srt_max_module;
extern ngx_module_t  ngx_srt_core_module;


ngx_int_t ngx_srt_start_listening(ngx_cycle_t *cycle);

ngx_srt_session_t *ngx_srt_init_session(ngx_srt_conn_t *sc);


typedef ngx_int_t (*ngx_srt_filter_pt)(ngx_srt_conn_t *sc,
    ngx_chain_t *chain, ngx_uint_t from_srt);


extern ngx_srt_filter_pt  ngx_srt_top_filter;


#endif /* _NGX_SRT_H_INCLUDED_ */
