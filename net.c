#include "net.h"
#include "string.h"

struct sockaddr_in new_addr(char *ip, unsigned int port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

int create_sock(char *ip, unsigned int port, struct sockaddr_storage *local_sas) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        printf("Error creating socket\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in local_addr = new_addr(ip, port);
    if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        printf("Cannot bind");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    if(!memcpy(local_sas, &local_addr, sizeof(local_addr))) {
        printf("memcpy local_sas error\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}
