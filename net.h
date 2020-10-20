#pragma once

#ifndef LSQUIC_DEMO_NET_H
#define LSQUIC_DEMO_NET_H

#endif //LSQUIC_DEMO_NET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct sockaddr_in new_addr(char *ip, uint port);
