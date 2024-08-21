#include "checksum.h"
#include<linux/types.h>
static u_int32_t sum_every_16bits(char *data, int len);
u_int16_t checksum(char *buff, int len, int start_sum)
{
    uint32_t sum = start_sum;
    sum += sum_every_16bits(buff, len);
    while (sum>>16)
    {
        sum = (sum & 0xFFFF) + (sum>>16);
    }
    return ~sum;
}
u_int16_t checksum_tran(u_int32_t saddr, u_int32_t daddr, char proto, char *data, u_int16_t len)
{
    u_int32_t sum = 0;
    struct pseudo_head head;
    memset(&head, 0, sizeof(pseudo_head));
    /* 需要保证传入的daddr以及saddr是网络字节序 */
    head.daddr = daddr;
    head.saddr = saddr;
    head.proto = proto;
    head.zero = 0;
    head.len = htons(len);
    sum = sum_every_16bits((char *)&head, sizeof(pseudo_head));
    return checksum(data, len, sum);
}
static u_int32_t sum_every_16bits(char *data, int len)
{
    u_int32_t sum = 0;
    u_int16_t *ptr = (u_int16_t *)data;
    u_int16_t answer = 0;

    while (len > 1)
    {
        /*  This is the inner loop */
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
    {
        *(char *)(&answer) = *(char *)ptr;
        sum += answer;
    }

    return sum;
}
bool set_timeout(int fd, int seconds)
{
    struct timeval timeout;
    timeout.tv_sec = seconds; // 秒
    timeout.tv_usec = 0;      // 微秒
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        return false;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        return false;
    }
    return true;
}
void print(iphdr *iph)
{

    struct sockaddr_in source, dest;
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    printf("s IP: %s  ", inet_ntoa(source.sin_addr));
    printf("d IP: %s\n", inet_ntoa(dest.sin_addr));
    switch (iph->protocol)
    {
    case 6: // TCP 协议
    {
        tcphdr *tcp = (tcphdr *)((char *)iph + iph->ihl * 4);
        printf("tcp s port: %d  ", ntohs(tcp->source));
        printf("tcp d port: %d\n\n", ntohs(tcp->dest));
        break;
    }
    case 17: // UDP 协议
    {
        udphdr *udp = (udphdr *)((char *)iph + iph->ihl * 4);
        printf("udp s port: %d  ", ntohs(udp->source));
        printf("udp d port: %d\n\n", ntohs(udp->dest));
        break;
    }
    default: // 其他协议
        break;
    }
}