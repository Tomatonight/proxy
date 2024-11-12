#ifndef PROXY_H
#define PROXY_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include<sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include<arpa/inet.h>
#include <linux/if.h>
#include <linux/if_xdp.h>
void* tcp_loop();
void* udp_loop();
#endif