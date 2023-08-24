#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

// #define DCPIM_ADD_FLOW 0xFFAB
// #define DCPIM_REMOVE_FLOW 0xFFAC
// #define IPPROTO_DCPIM 0xFE
// typedef int (*template_connect_t)(int, const struct sockaddr*, socklen_t);
// typedef int (*template_accept_t)(int, struct sockaddr*, socklen_t*);
// typedef int (*close_t)(int);
typedef int (*real_socket_t)(int, int, int);
int real_socket(int domain, int type, int protocol)
{
  printf("domain: %d,PF_INET:%d,  type: %d\n", domain, PF_INET, type);
  if((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_STREAM){
     return ((real_socket_t) dlsym(RTLD_NEXT, "socket")) (domain, type, protocol);
  }
  else
     return ((real_socket_t) dlsym(RTLD_NEXT, "socket")) (PF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
}

int socket(int domain, int type, int protocol)
{
    return real_socket(domain, type, protocol);
}

// int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen) {
//    int devicefd = open("/dev/customdevice", O_WRONLY);
//    if(devicefd > 0) {
//       ioctl(devicefd, DCPIM_ADD_FLOW, sockfd);
//    }
//    return ((template_connect_t) dlsym(RTLD_NEXT, "accept")) (sockfd, serv_addr, addrlen);

// }

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
//    int devicefd = open("/dev/customdevice", O_WRONLY);
//    if(devicefd > 0) {
//       ioctl(devicefd, DCPIM_ADD_FLOW, sockfd);
//    }
//    return ((template_accept_t) dlsym(RTLD_NEXT, "accept")) (sockfd, addr, addrlen);
// }

// int close(int fd) {
//    int devicefd = open("/dev/customdevice", O_WRONLY);
//    if(devicefd > 0) {
//       ioctl(devicefd, DCPIM_REMOVE_FLOW, fd);
//    }
//    return ((close_t) dlsym(RTLD_NEXT, "close")) (fd);
// }
