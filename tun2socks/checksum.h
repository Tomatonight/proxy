#pragma once
#include <sys/types.h>
#include <memory.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<stdio.h>
#include <arpa/inet.h>
class pseudo_head
{
public:
    u_int32_t saddr;
    u_int32_t daddr;
    char zero;
    char proto;
    u_int16_t len;
};
bool set_timeout(int fd, int seconds);
void print(iphdr *iph);
u_int16_t checksum(char *buff, int len, int start_sum);
u_int16_t checksum_tran(u_int32_t saddr, u_int32_t daddr, char proto, char *data, u_int16_t len);