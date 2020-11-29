#include <stdio.h>
#include <lsquic.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include "ev.h"

#include "net.h"
#include "lsquic_utils.h"


static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);

static void on_conn_closed_cb(lsquic_conn_t *conn);

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

typedef struct State {
    // event loop
    struct ev_loop *loop;
    ev_io sock_watcher;
    ev_timer conn_watcher;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine;

    // SSL
    SSL_CTX *ssl_ctx;

    // response
    char *response;
    int size;
} State;

void process_conns(State *state);


const struct lsquic_stream_if stream_if = {
        .on_new_conn            = on_new_conn_cb,
        .on_conn_closed         = on_conn_closed_cb,
        .on_new_stream          = on_new_stream_cb,
        .on_read                = on_read_cb,
        .on_write               = on_write_cb,
};


static int send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs) {
    struct msghdr msg;
    int *sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int *) ctx;

    for (n = 0; n < n_specs; ++n) {
        msg.msg_name = (void *) specs[n].dest_sa;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = specs[n].iov;
        msg.msg_iovlen = specs[n].iovlen;
        if (sendmsg(*sockfd, &msg, 0) < 0) {
            perror("sendmsg");
            break;
        }
    }

    return (int) n;
}

static lsquic_conn_ctx_t *on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn) {
    printf("On new connection\n");
    fflush(stdout);
    State *state = ea_stream_if_ctx;
    return (void *) state;
}

static void on_conn_closed_cb(lsquic_conn_t *conn) {
    printf("On connection close\n");
    fflush(stdout);
}

static lsquic_stream_ctx_t *on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream) {
    printf("On new stream\n");
    fflush(stdout);
    lsquic_stream_wantread(stream, 1);
    return NULL;
}

static void on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    State *state = (void *) lsquic_conn_get_ctx(conn);

    unsigned char buf[256] = {0};
    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
    buf[nr] = '\0';
    printf("recv %zd bytes: %s\n", nr, buf);
    fflush(stdout);

    char *response = (char *) malloc(sizeof(char) * nr + 2);
    char *server_prefix = "s:";

    int response_size = snprintf(response, nr + strlen(server_prefix), "%s%s", server_prefix, buf);
    state->response = response;
    state->size = response_size;

    lsquic_stream_wantread(stream, 0);
    lsquic_stream_wantwrite(stream, 1);
}

static void on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    State *state = (void *) lsquic_conn_get_ctx(conn);

    lsquic_stream_write(stream, state->response, state->size);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
    lsquic_stream_flush(stream);
}


SSL_CTX *ssl_ctx;

struct ssl_ctx_st *get_ssl_ctx(void *peer_ctx) {
    // TODO pass ssl_ctx in peer_ctx
    return ssl_ctx;
}

void create_ssl_ctx(State *state) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "./certs/server.cert") != 1) {
        printf("Cannot load cert\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "./certs/server.key", SSL_FILETYPE_PEM) != 1) {
        printf("Cannot load key\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    state->ssl_ctx = ssl_ctx;
}

static void read_sock(EV_P_ ev_io *w, int revents) {
    State *state = w->data;
    ssize_t nread;
    struct sockaddr_storage peer_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{buf, sizeof(buf)}};

    struct msghdr msg = {
            .msg_name       = &peer_sas,
            .msg_namelen    = sizeof(peer_sas),
            .msg_iov        = vec,
            .msg_iovlen     = 1,
    };
    nread = recvmsg(w->fd, &msg, 0);
    if (-1 == nread) {
        return;
    }

    // TODO handle ECN properly
    int ecn = 0;

    (void) lsquic_engine_packet_in(state->engine, buf, nread,
                                   (struct sockaddr *) &state->local_sas,
                                   (struct sockaddr *) &peer_sas,
                                   (void *) (uintptr_t) w->fd, ecn);

    process_conns(state);
}

static void process_conns_cb(EV_P_ ev_timer *conn_watcher, int revents) {
    process_conns(conn_watcher->data);
}

void process_conns(State *state) {
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(state->loop, &state->conn_watcher);
    lsquic_engine_process_conns(state->engine);
    if (lsquic_engine_earliest_adv_tick(state->engine, &diff)) {
        if (diff > 0) {
            timeout = (ev_tstamp) diff / 1000000;
        } else {
            timeout = 0;
        }
        ev_timer_init(&state->conn_watcher, process_conns_cb, timeout, 0.);
        ev_timer_start(state->loop, &state->conn_watcher);
    }
}

void create_event_loop(State *state) {
    state->loop = EV_DEFAULT;
    state->sock_watcher.data = state;
    state->conn_watcher.data = state;
    ev_io_init (&state->sock_watcher, read_sock, state->sockfd, EV_READ);
    ev_io_start(state->loop, &state->sock_watcher);
    ev_init(&state->conn_watcher, process_conns_cb);
}

int main(int argc, char **argv) {
    State state;
    create_ssl_ctx(&state);
    ssl_ctx = state.ssl_ctx;
    state.sockfd = create_sock(argv[1], atoi(argv[2]), &state.local_sas);
    create_event_loop(&state);

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        exit(EXIT_FAILURE);
    }

//    init_logger("info");

    struct lsquic_engine_api engine_api = {
            .ea_packets_out     = send_packets_out,
            .ea_packets_out_ctx = (void *) &state.sockfd,
            .ea_stream_if       = &stream_if,
            .ea_stream_if_ctx   = (void *) &state,
            .ea_get_ssl_ctx     = get_ssl_ctx
    };

    state.engine = lsquic_engine_new(LSENG_SERVER, &engine_api);

    ev_run(state.loop, 0);

    lsquic_global_cleanup();

    return 0;
}
