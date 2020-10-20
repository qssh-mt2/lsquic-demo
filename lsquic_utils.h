#pragma once

#ifndef LSQUIC_DEMO_LSQUIC_UTILS_H
#define LSQUIC_DEMO_LSQUIC_UTILS_H

#endif //LSQUIC_DEMO_LSQUIC_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <lsquic.h>

char *get_conn_status_str(enum LSQUIC_CONN_STATUS status);

void init_logger(char *level);
