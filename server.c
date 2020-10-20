#include <stdio.h>
#include <lsquic.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include "net.h"
#include "lsquic_utils.h"


static lsquic_conn_ctx_t *on_new_conn_cb (void *ea_stream_if_ctx, lsquic_conn_t *conn);
static void on_conn_closed_cb (lsquic_conn_t *conn);
static lsquic_stream_ctx_t *on_new_stream_cb (void *ea_stream_if_ctx, lsquic_stream_t *stream);
static void on_read_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
static void on_write_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *h);

static char BUF[256];

SSL_CTX *ssl_ctx;

const struct lsquic_stream_if stream_if = {
        .on_new_conn            = on_new_conn_cb,
        .on_conn_closed         = on_conn_closed_cb,
        .on_new_stream          = on_new_stream_cb,
        .on_read                = on_read_cb,
        .on_write               = on_write_cb,
};


static int send_packets_out (void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs)
{
    printf("on packets send out\n");
    fflush(stdout);

    struct msghdr msg;
    int sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int) (uintptr_t) ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        if (sendmsg(sockfd, &msg, 0) < 0)
            break;
    }

    return (int) n;
}

static lsquic_conn_ctx_t *on_new_conn_cb (void *ea_stream_if_ctx, lsquic_conn_t *conn) {
    printf("On new connection\n");
    lsquic_conn_make_stream(conn);
    fflush(stdout);
    return NULL;
}

static void on_conn_closed_cb (lsquic_conn_t *conn) {
    printf("On connection close\n");
    fflush(stdout);
}

static lsquic_stream_ctx_t *on_new_stream_cb (void *ea_stream_if_ctx, lsquic_stream_t *stream) {
    printf("On new stream\n");
    fflush(stdout);
    return NULL;
}

static void on_read_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    unsigned char buf[256];

    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));

    printf("Got data: %s\n", buf);

    if (nr == 0) /* EOF */ {
        lsquic_stream_shutdown(stream, 0);
        lsquic_stream_wantwrite(stream, 1); /* Want to reply */
    }
}

static void on_write_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    printf("on write\n");
    fflush(stdout);
    char *buf = "Hello from client";
    lsquic_stream_write(stream, buf, strlen(buf));
}

struct ssl_ctx_st *get_ssl_ctx(void *peer_ctx) {
    return ssl_ctx;
}

void create_ssl_ctx() {
    ssl_ctx = SSL_CTX_new(TLS_method());
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
}

int main() {
    // CRYPTO_library_init();
    create_ssl_ctx();
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        printf("Error creating socket\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in local_addr = new_addr("127.0.0.1", 7777);
    if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        printf("Cannot bind");
        fflush(stdout);
    }


    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        exit(EXIT_FAILURE);
    }
    init_logger("debug");

    struct lsquic_engine_api engine_api = {
            .ea_packets_out     = send_packets_out,
            .ea_packets_out_ctx = (void *) &sockfd,
            .ea_stream_if       = &stream_if,
            .ea_stream_if_ctx   = NULL,
            .ea_get_ssl_ctx     = get_ssl_ctx
    };

    lsquic_engine_t *engine = lsquic_engine_new(LSENG_SERVER, &engine_api);

    lsquic_engine_process_conns(engine);

    int diff;
    while (1) {
        if(lsquic_engine_earliest_adv_tick(engine, &diff)) {
            printf("processing conns\n");
            fflush(stdout);
            lsquic_engine_process_conns(engine);
        }
    }

    lsquic_global_cleanup();

    return 0;
}
