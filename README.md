# Nginx SRT Module

Haivision SRT (Secure Reliable Transfer) / TCP gateway.
Supports both SRT to TCP and TCP to SRT, including bidirectional data transfer.

The implementation uses libsrt for SRT communication.
The libsrt code executes on a side thread, eventfd notifications are used in order to communicate
with the main nginx thread.

## Build

![Build Status](https://github.com/kaltura/nginx-srt-module/actions/workflows/ci.yml/badge.svg)

To link statically against nginx, cd to nginx source directory and execute:

    ./configure --add-module=/path/to/nginx-srt-module --with-stream --with-threads

To compile as a dynamic module (nginx 1.9.11+), use:

    ./configure --add-dynamic-module=/path/to/nginx-srt-module --with-stream --with-threads

In this case, the `load_module` directive should be used in nginx.conf to load the module.

## Configuration

### Sample configuration

```
# SRT -> TCP proxy
srt {
    server {
        listen 4321;
        proxy_pass tcp://127.0.0.1:5678;
    }
}

# TCP -> SRT proxy
stream {
    server {
        listen 5432;
        srt_proxy_pass srt://127.0.0.1:4321;
    }
}
```

### srt core directives

#### srt
* **syntax**: `srt { ... }`
* **default**: `-`
* **context**: `main`

Provides the configuration file context in which the srt `server` directives are specified.

#### server
* **syntax**: `server { ... }`
* **default**: `-`
* **context**: `srt`

Sets the configuration for a server.

#### listen
* **syntax**: `listen address:port [backlog=number] [bind] [ipv6only=on|off] [reuseport];`
* **default**: `-`
* **context**: `server`

Sets the address and port for the UDP socket on which the server will accept connections.

See the documentation of the `listen` directive of the nginx `stream` module for more details on the optional parameters supported by this directive.

#### variables_hash_max_size
* **syntax**: `variables_hash_max_size size;`
* **default**: `1024`
* **context**: `srt`

Sets the maximum size of the variables hash table.

#### variables_hash_bucket_size
* **syntax**: `variables_hash_bucket_size size;`
* **default**: `64`
* **context**: `srt`

Sets the bucket size for the variables hash table.

#### error_log
* **syntax**: `error_log file [level];`
* **default**: `logs/error.log error`
* **context**: `srt, server`

Configures logging, see the documentation of the nginx core `error_log` directive for more details.

#### fc_pkts
* **syntax**: `fc_pkts number;`
* **default**: `25600`
* **context**: `srt, server`

Sets the maximum number of "in flight" packets (packets that were sent, but not yet acknowledged).

See the libsrt documentation of the `SRTO_FC` option for more details.

#### mss
* **syntax**: `mss size;`
* **default**: `1500`
* **context**: `srt, server`

Maximum segment size, in bytes.

See the libsrt documentation of the `SRTO_MSS` option for more details.

#### recv_buf
* **syntax**: `recv_buf size;`
* **default**: `8192 buffers`
* **context**: `srt, server`

Receive buffer size, in bytes.

See the libsrt documentation of the `SRTO_RCVBUF` option for more details.

#### recv_udp_buf
* **syntax**: `recv_udp_buf size;`
* **default**: `8192 buffers`
* **context**: `srt, server`

UDP socket receive buffer size, in bytes.

See the libsrt documentation of the `SRTO_UDP_RCVBUF` option for more details.

#### recv_latency
* **syntax**: `recv_latency size;`
* **default**: `120ms`
* **context**: `srt, server`

The latency on the receiving side, in milliseconds.

See the libsrt documentation of the `SRTO_RCVLATENCY` option for more details.

#### send_buf
* **syntax**: `send_buf size;`
* **default**: `8192 buffers`
* **context**: `srt, server`

Send buffer size, in bytes.

See the libsrt documentation of the `SRTO_SNDBUF` option for more details.

#### send_udp_buf
* **syntax**: `send_udp_buf size;`
* **default**: `65536`
* **context**: `srt, server`

UDP socket send buffer size, in bytes.

See the libsrt documentation of the `SRTO_UDP_SNDBUF` option for more details.

#### send_latency
* **syntax**: `send_latency size;`
* **default**: `120ms`
* **context**: `srt, server`

The minimum receiving latency, provided by the sender.

See the libsrt documentation of the `SRTO_PEERLATENCY` option for more details.

#### passphrase
* **syntax**: `passphrase expr;`
* **default**: ``
* **context**: `srt, server`

Sets a passphrase for encryption, see the libsrt documentation of the `SRTO_PASSPHRASE` option for more details.

The parameter value can contain variables.

#### in_buf_size
* **syntax**: `in_buf_size size;`
* **default**: `64k`
* **context**: `srt, server`

Sets the size of the buffer used for reading data from the client.

### srt stats directives

#### srt_stats_zone
* **syntax**: `srt_stats_zone name:size;`
* **default**: ``
* **context**: `srt`

Enables collection of per-connection SRT statistics and allocates a shared memory zone of the given `size` (which must be at least `8 * pagesize`) to hold them.

Each worker's SRT thread refreshes the metrics of its own connections roughly once per second (via libsrt's `srt_bstats`) and publishes them into this zone. Because the zone is shared, the [`srt_stats`](#srt_stats) HTTP endpoint returns the union of all connections across all worker processes, regardless of which worker handles the request.

Only a single zone may be defined. When the directive is absent, statistics collection is disabled and the `srt_stats` endpoint returns an empty array.

> Note: if a worker process crashes, its entries are not removed and become stale. Each entry exposes `pid` and `uptime_sec` so consumers can detect this; a clean worker shutdown removes its entries normally.

### srt map directives

#### map
* **syntax**: `map string $variable { ... }`
* **default**: ``
* **context**: `srt`

Creates a new variable whose value depends on values of one or more of the source variables specified in the first parameter.

See the documentation of the `map` directive of the nginx `stream` module for more details.

#### map_hash_max_size
* **syntax**: `map_hash_max_size size;`
* **default**: `2048`
* **context**: `srt`

Sets the maximum size of the map variables hash table.

#### map_hash_bucket_size
* **syntax**: `map_hash_bucket_size size;`
* **default**: `32|64|128`
* **context**: `srt`

Sets the bucket size for the map variables hash table.

### srt log directives

#### access_log
* **syntax**: `access_log path format [buffer=size] [gzip[=level]] [flush=time] [if=condition];`
* **default**: `off`
* **context**: `srt, server`

Sets the path, format, and configuration for a buffered log write.

See the documentation of the `access_log` directive of the nginx `stream` module for more details.

#### log_format
* **syntax**: `log_format name [escape=default|json|none] string ...;`
* **default**: ``
* **context**: `srt`

Defines a log format.

See the documentation of the `log_format` directive of the nginx `stream` module for more details.

#### open_log_file_cache
* **syntax**: `open_log_file_cache max=N [inactive=time] [min_uses=N] [valid=time];`
* **default**: `off`
* **context**: `srt, server`

Defines a cache that stores the file descriptors of frequently used logs whose names contain variables.

See the documentation of the `open_log_file_cache` directive of the nginx `stream` module for more details.

### srt proxy directives

#### proxy_pass
* **syntax**: `proxy_pass address;`
* **default**: ``
* **context**: `srt, server`

Sets the address of the proxied server.

#### proxy_connect_timeout
* **syntax**: `proxy_connect_timeout timeout;`
* **default**: `60s`
* **context**: `srt, server`

Defines a timeout for establishing a connection with a proxied server.

#### proxy_timeout
* **syntax**: `proxy_timeout timeout;`
* **default**: `10m`
* **context**: `srt, server`

Sets the timeout between two successive read or write operations on client or proxied server connections.
If no data is transmitted within this time, the connection is closed.

#### proxy_buffer_size
* **syntax**: `proxy_buffer_size size;`
* **default**: `64k`
* **context**: `srt, server`

Sets the size of the buffer used for reading data from the proxied server.

#### proxy_protocol
* **syntax**: `proxy_protocol on | off;`
* **default**: `off`
* **context**: `srt, server`

Enables the PROXY protocol for connections to a proxied server.

#### proxy_header
* **syntax**: `proxy_header expr;`
* **default**: ``
* **context**: `srt, server`

Defines a string that is sent to the proxied server before any data received over SRT.

The parameter value can contain variables.

### srt set misc directives

#### set_decode_base64
* **syntax**: `set_decode_base64 $dst src;`
* **default**: ``
* **context**: `srt`

Performs base64 decode of the value of the second argument, and assigns the result to the variable specified in the first argument.

#### set_decode_base64url
* **syntax**: `set_decode_base64url $dst src;`
* **default**: ``
* **context**: `srt`

Performs url-safe-base64 decode of the value of the second argument, and assigns the result to the variable specified in the first argument.

#### set_aes_decrypt
* **syntax**: `set_aes_decrypt $dst base64_key base64_iv src;`
* **default**: ``
* **context**: `srt`

Performs AES-256-CBC decryption of the value of the last argument, using the supplied key/iv, and assigns the result to the variable specified in the first argument.

### stream srt proxy directives

#### srt_proxy_pass
* **syntax**: `srt_proxy_pass address;`
* **default**: ``
* **context**: `stream, server`

Sets the address of the proxied server.

#### srt_proxy_connect_timeout
* **syntax**: `srt_proxy_connect_timeout timeout;`
* **default**: `60s`
* **context**: `srt, server`

Defines a timeout for establishing a connection with a proxied server.

#### srt_proxy_timeout
* **syntax**: `srt_proxy_timeout timeout;`
* **default**: `10m`
* **context**: `srt, server`

Sets the timeout between two successive read or write operations on client or proxied server connections.
If no data is transmitted within this time, the connection is closed.

#### srt_proxy_buffer_size
* **syntax**: `srt_proxy_buffer_size size;`
* **default**: `64k`
* **context**: `srt, server`

Sets the size of the buffer used for reading data from the proxied server.

#### srt_proxy_stream_id
* **syntax**: `srt_proxy_stream_id expr;`
* **default**: ``
* **context**: `srt, server`

Sets the SRT stream id, see the libsrt documentation of the `SRTO_STREAMID` option for more details.

The parameter value can contain variables.

#### srt_proxy_passphrase
* **syntax**: `srt_proxy_passphrase expr;`
* **default**: ``
* **context**: `srt, server`

Sets a passphrase for encryption, see the libsrt documentation of the `SRTO_PASSPHRASE` option for more details.

The parameter value can contain variables.

### http srt stats directives

#### srt_stats
* **syntax**: `srt_stats;`
* **default**: ``
* **context**: `location`

Turns the surrounding `location` into a live SRT statistics endpoint. The handler reads the shared memory zone configured by [`srt_stats_zone`](#srt_stats_zone) and responds with a JSON array (`Content-Type: application/json`) holding one object per active connection, aggregated across all worker processes. If no `srt_stats_zone` is configured, the endpoint responds with an empty array (`[]`).

Each object contains:

* Identity: `pid`, `socket`, `connection` (the nginx connection serial, i.e. the `$connection` variable), `stream_id`, `remote_addr`, `status`, `uptime_sec`.
* Packet counters (cumulative unless noted): `pkt_sent_total`, `pkt_recv_total`, `pkt_snd_loss_total`, `pkt_rcv_loss_total`, `pkt_retrans_total` (retransmitted by the sender), `pkt_rcv_retrans` (retransmitted packets received / recovered, interval-scoped), `pkt_snd_drop_total`, `pkt_rcv_drop_total`, `pkt_rcv_undecrypt_total`, `pkt_rcv_belated`.
* Byte counters (cumulative): `byte_sent_total`, `byte_recv_total`, `byte_rcv_loss_total`, `byte_retrans_total`.
* Instantaneous health: `ms_rtt`, `mbps_bandwidth`, `mbps_recv_rate`, `mbps_send_rate`, `pkt_flow_window`, `pkt_congestion_window`, `pkt_flight_size`, `ms_rcv_buf`, `ms_snd_buf`.

All fields are taken from libsrt's `SRT_TRACEBSTATS` structure; see the libsrt documentation for their precise meaning. The values are refreshed about once per second, so the endpoint is "live to within ~1 second".

Sample configuration:

```
srt {
    srt_stats_zone srt_stats:1m;

    server {
        listen 4321;
        proxy_pass tcp://127.0.0.1:5678;
    }
}

http {
    server {
        listen 8080;

        location /srt_stats {
            srt_stats;
        }
    }
}
```

Sample response:

```json
[
  {
    "pid": 12345,
    "socket": 1075118292,
    "connection": 7,
    "status": 200,
    "uptime_sec": 42,
    "stream_id": "channel-1",
    "remote_addr": "10.0.0.5",
    "pkt_sent_total": 0,
    "pkt_recv_total": 51234,
    "pkt_snd_loss_total": 0,
    "pkt_rcv_loss_total": 17,
    "pkt_retrans_total": 0,
    "pkt_rcv_retrans": 3,
    "pkt_snd_drop_total": 0,
    "pkt_rcv_drop_total": 0,
    "pkt_rcv_undecrypt_total": 0,
    "pkt_rcv_belated": 2,
    "byte_sent_total": 0,
    "byte_recv_total": 71724800,
    "byte_rcv_loss_total": 23800,
    "byte_retrans_total": 0,
    "ms_rtt": 12.431,
    "mbps_bandwidth": 120.500,
    "mbps_recv_rate": 6.200,
    "mbps_send_rate": 0.000,
    "pkt_flow_window": 25600,
    "pkt_congestion_window": 940,
    "pkt_flight_size": 3,
    "ms_rcv_buf": 118,
    "ms_snd_buf": 0
  }
]
```

## Embedded Variables

### Core

* `binary_remote_addr` - client address in a binary form, the length of the value is always 4 bytes for IPv4 addresses or 16 bytes for IPv6 addresses
* `bytes_received` - number of bytes received from the client
* `bytes_sent` - number of bytes sent to the client
* `connection` - connection serial number
* `hostname` - host name
* `msec` - current time, in seconds with milliseconds resolution
* `nginx_version` - nginx version
* `peer_version` - libsrt version of the remote peer, see the libsrt documentation of the `SRTO_PEERVERSION` option for more details.
* `pid` - PID of the worker process
* `protocol` - protocol used to communicate with the client, always evaluates to `SRT`
* `remote_addr` - client address
* `remote_port` - client port
* `server_addr` - the address of the server which accepted the connection
* `server_port` - the port of the server which accepted the connection
* `session_time` - session duration, in seconds with a milliseconds resolution
* `status` - session status
* `stream_id` - SRT stream id, see the libsrt documentation of the `SRTO_STREAMID` option for more details.
* `time_iso8601` - local time, in ISO 8601 standard format
* `time_local` - local time, in the Common Log Format

### Upstream

* `upstream_addr` - the IP address and port of the upstream server
* `upstream_bytes_received` - number of bytes received from the upstream server
* `upstream_bytes_sent` - number of bytes sent to the upstream server
* `upstream_connect_time` - time to connect to the upstream server, in seconds with millisecond resolution
* `upstream_first_byte_time` - time to receive the first byte of data, in seconds with millisecond resolution
* `upstream_session_time` - session duration, in seconds with millisecond resolution

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path.

Copyright © Kaltura Inc. All rights reserved.
