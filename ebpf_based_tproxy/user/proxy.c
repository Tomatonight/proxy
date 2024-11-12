#include "proxy.h"
extern int search_daddr(uint32_t sip, uint16_t sport, uint32_t *dip, uint16_t *dport,__u16 protocol);
static char *local_ip = "127.0.0.1";
static u_int16_t local_port = 1234;
void *tcp_loop()
{
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0)
    {
        perror("socket");
        exit(-1);
    }
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = inet_addr(local_ip);
    if (bind(tcp_fd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr)) < 0)
    {
        perror("bind err");
        exit(-1);
    }
    if (listen(tcp_fd, 1000) < 0)
    {
        perror("listen err");
        exit(-1);
    }
    while (1)
    {
        struct sockaddr_in saddr;
        socklen_t len;
        int new_fd = accept(tcp_fd, (struct sockaddr *)&saddr, &len);
        uint32_t ip=0;
        uint16_t port=0;
        if (search_daddr(saddr.sin_addr.s_addr, saddr.sin_port, &ip, &port,IPPROTO_TCP) < 0)
        {
            printf("t cant find");
            close(new_fd);
            continue;
        }
        struct in_addr addr = {.s_addr = saddr.sin_addr.s_addr};
        printf("tcp sip: %s sport:%d ", inet_ntoa(addr), ntohs(saddr.sin_port));
        addr.s_addr=ip;
        printf("dip: %s dport:%d\n", inet_ntoa(addr), ntohs(port));
        close(new_fd);
    }
    return NULL;
}
void* udp_loop()
{
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0)
    {
        perror("socket");
        exit(-1);
    }
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = inet_addr(local_ip);
     if (bind(udp_fd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr)) < 0)
    {
        perror("bind err");
        exit(-1);
    }
    while (1)
    {
        char buffer[1024]={0};
        struct sockaddr_in saddr;
        socklen_t len;
        int re=recvfrom(udp_fd,buffer,1023,0,(struct sockaddr*)&saddr,&len);
        if(re<=0)continue;
        uint32_t ip;
        uint16_t port;
        if (search_daddr(saddr.sin_addr.s_addr, saddr.sin_port, &ip, &port,IPPROTO_UDP) < 0)
        {
            printf("u cant find %d %d\n", saddr.sin_addr.s_addr,saddr.sin_port);
            continue;
        }
       // printf("%d %d\n",ip,port);
        struct in_addr addr = {.s_addr = saddr.sin_addr.s_addr};
       printf("udp sip: %s sport:%d ", inet_ntoa(addr), ntohs(saddr.sin_port));
        addr.s_addr=ip;
        printf("dip: %s dport:%d\n", inet_ntoa(addr), ntohs(port));

    }
    return NULL;
}