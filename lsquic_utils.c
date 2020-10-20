#include "lsquic_utils.h"

char *get_conn_status_str(enum LSQUIC_CONN_STATUS status) {
    switch(status) {
        case LSCONN_ST_HSK_IN_PROGRESS:
            return "LSCONN_ST_HSK_IN_PROGRESS";
        case LSCONN_ST_CONNECTED:
            return "LSCONN_ST_CONNECTED";
        case LSCONN_ST_HSK_FAILURE:
            return "LSCONN_ST_HSK_FAILURE";
        case LSCONN_ST_GOING_AWAY:
            return "LSCONN_ST_GOING_AWAY";
        case LSCONN_ST_TIMED_OUT:
            return "LSCONN_ST_TIMED_OUT";
        case LSCONN_ST_RESET:
            return "LSCONN_ST_RESET";
        case LSCONN_ST_USER_ABORTED:
            return "LSCONN_ST_USER_ABORTED";
        case LSCONN_ST_ERROR:
            return "LSCONN_ST_ERROR";
        case LSCONN_ST_CLOSED:
            return "LSCONN_ST_CLOSED";
        case LSCONN_ST_PEER_GOING_AWAY:
            return "LSCONN_ST_PEER_GOING_AWAY";
        default:
            return "UNKNOWN";
    }
}

static int log_buf(void *logger_ctx, const char *buf, size_t len) {
    (void) logger_ctx;
    (void) len;
    printf("%s", buf);
    fflush(stdout);
    return 0;
}

struct lsquic_logger_if logger_if = {
        .log_buf = log_buf
};

void init_logger(char *level) {
    lsquic_logger_init(&logger_if, NULL, LLTS_HHMMSSMS);
    if(lsquic_set_log_level(level) != 0) {
        printf("Cannot set logger to %s level\n", level);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    printf("Logger initialized\n");
    fflush(stdout);
}
