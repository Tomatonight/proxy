#include "channel.h"
#include "epoll.h"
#include <netdb.h>
#include <time.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <sys/uio.h>
/*
X’00’ succeeded
X’01’ general SOCKS server failure
X’02’ connection not allowed by ruleset
X’03’ Network unreachable
X’04’ Host unreachable
X’05’ Connection refused
X’06’ TTL expired
X’07’ Command not supported
X’08’ Address type not supported
X’09’ to X’FF’ unassigned
*/
int create_udp_socket(sockaddr_in *addr)
{
    int udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp < 0)
    {
        return -1;
    }
    sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = 0;
    bind_addr.sin_port = 0;
    if (bind(udp, (sockaddr *)&bind_addr, sizeof(sockaddr)) < 0)
    {
        return -1;
    }
    socklen_t len=0;
    if(getsockname(udp,(sockaddr*)addr,&len)<0)
    {
        printf("get sock name err\n");
    }
    return udp;
}
int connect_by_hostname(char *hostname, uint16_t dport, int *error)
{
    //  printf("hostname:%s dport:%d\n", hostname, ntohs(dport));
    struct addrinfo hints;
    struct addrinfo *res = NULL, *cur = NULL;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
    {
        *error = 0x4;
        freeaddrinfo(res);
        return -1;
    }
    cur = res;
    int new_tcp = -1;
    for (int cnt = 0; cur != NULL; cur = cur->ai_next, cnt++)
    {
        new_tcp = tcp_connect(((struct sockaddr_in *)cur->ai_addr)->sin_addr.s_addr, dport, 2);
        if (new_tcp > 0)
            break;
    }
    if (new_tcp < 0)
    {
        *error = 0x5;
        freeaddrinfo(res);
        return -1;
    }
    *error = 0;
    freeaddrinfo(res);
    return new_tcp;
}
int tcp_connect(uint32_t ip, uint16_t port, int timeout_)
{
    sockaddr_in addr;
    int new_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (new_fd < 0)
    {
        return -1;
    }
    memset(&addr, 0, sizeof(sockaddr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = (port);
    struct timeval timeout;
    timeout.tv_sec = timeout_;
    timeout.tv_usec = 0;
    setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    if (connect(new_fd, (sockaddr *)&addr, sizeof(sockaddr)) < 0)
    {
        close(new_fd);
        return -1;
    }
    return new_fd;
}
void channel_client::process_read(epoll *ep)
{

    switch (state)
    {
    case SOCK5_WAIT_NEGOTIATE_REQUEST:
    {
        process_read_wait(ep);
    }
    break;
    case SOCK5_WAIT_BUILD_REQUEST:
    {
        process_read_build(ep);
    }
    break;
    case SOCK5_TRANSMIT_DATA:
    {

        process_read_transmit(ep);
    }
    break;
    default:
        printf("err state\n");
        break;
    }
}
void channel_client::process_err(epoll *ep)
{
   
    if (state == SOCK5_TRANSMIT_DATA)
    {
        ep->erase_fd(peer_channel);
        ep->erase_fd(this);
        close(fd);
        close(peer_channel->fd);
        delete peer_channel;
        delete this;
    }
    else
    {
        ep->erase_fd(this);
        close(fd);
        delete this;
    }
}
void channel_client::process_rdhub(epoll *ep)
{
    process_err(ep);
    return;
}
void channel_transmit::process_read(epoll *ep)
{
    if (!peer_channel)
    {
        printf("peer channel err\n");
        return;
    }
    if (proxy_kind == SOCK5_KINDS_TCP)
    {
        char buffer[65535];
        int re = read(fd, buffer, 65535);
        if (re <= 0)
        {
            process_err(ep);
            return;
        }
        int len = 0;
        while (len < re)
        {
            int ret = write(peer_channel->fd, buffer + len, re - len);
            if (ret <= 0 && errno != EAGAIN)
            {
                process_err(ep);
                return;
            }

            len += ret;
        }
    }
    else if (proxy_kind == SOCK5_KINDS_UDP)
    {
        sockaddr_in daddr;
        char buffer[4096];
        socklen_t len = 0;
        printf("transmit udp\n");
        int re = recvfrom(fd, buffer, 4096, 0, (sockaddr *)&daddr, &len);
        if (re < 0)
        {
            process_err(ep);
        }

        if (daddr.sin_addr.s_addr == client_addr.sin_addr.s_addr && daddr.sin_port == client_addr.sin_port)
        {
            sock5_udp_packet *udp_pkt = (sock5_udp_packet *)buffer;
            if (udp_pkt->atype != 0x1)
            {
                process_err(ep);
                return;
            }
            sockaddr_in dest_addr;
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = udp_pkt->dport;
            dest_addr.sin_addr.s_addr = udp_pkt->addr;
            int len = sizeof(sock5_udp_packet);
            while (len < re)
            {
                int ret = sendto(fd, buffer + len, re - len, 0, (sockaddr *)&dest_addr, sizeof(sockaddr_in));
                if (ret < 0)
                {
                    process_err(ep);
                    return;
                }
                len += ret;
            }
        }
        else
        {
            iovec iov[2];
            sock5_udp_packet udp_pkt;
            memset(&udp_pkt, 0, sizeof(sock5_udp_packet));
            udp_pkt.atype = 0x1;
            udp_pkt.dport = daddr.sin_port;
            udp_pkt.addr = daddr.sin_addr.s_addr;
            iov[0].iov_base = &udp_pkt;
            iov[0].iov_len = sizeof(sock5_udp_packet);
            iov[1].iov_base = buffer;
            iov[1].iov_len = re;
            int len = 0;
            while (len < re + sizeof(udp_pkt))
            {
                int ret = sendto(fd, iov, sizeof(iov) / sizeof(iov[0]), 0, (sockaddr *)&client_addr, sizeof(sockaddr));
                if (ret < 0)
                {
                    process_err(ep);
                    return;
                }
                len += ret;
            }
        }
    }
    else
    {
        exit(-1);
    }
}
void channel_transmit::process_err(epoll *ep)
{
    ep->erase_fd(peer_channel);
    ep->erase_fd(this);
    close(fd);
    close(peer_channel->fd);
    delete peer_channel;
    delete this;
}
void channel_transmit::process_rdhub(epoll *ep)
{
    process_err(ep);
}
void channel_client::process_read_wait(epoll *ep)
{

    char buffer[300];
    int re = read(fd, buffer, 300);
    if (re < 0)
    {

        process_err(ep);
        return;
    }
    scok5_negotiate_request *nego_request = (scok5_negotiate_request *)buffer;
    bool flag = false;
    if (nego_request->version != 0x5)
    {
        printf("unsupport request\n");
        process_err(ep);
        return;
    }
    for (int i = 0; i < (nego_request->methodNum); i++)
    {
        //  printf("me %d\n",nego_request->method[i]);
        if (nego_request->method[i] == 0x0)
        {
            flag = true;
            break;
        }
    }
    sock5_negotiate_response nego_response;
    nego_response.version = 0x5;
    if (!flag)
        nego_response.method = 0xff;
    else
        nego_response.method = 0;
    re = write(fd, &nego_response, sizeof(nego_response));
    if (re < 0)
    {
        printf("err write\n");
        return;
    }
    if (!flag)
    {
        process_err(ep);
        return;
    }
    state = SOCK5_WAIT_BUILD_REQUEST;
}
void channel_client::process_read_build(epoll *ep)
{
    int error = 0;
    char buffer[300] = {0};
    sockaddr_in bind_addr;
    int tcp_fd = -1;
    int re = read(fd, buffer, 300);
    if (re < 0)
    {
        process_err(ep);
        return;
    }
    unsigned short dport = *(unsigned short *)(buffer + re - 2);
    sock5_build_request *build_request = (sock5_build_request *)buffer;
    if (build_request->rsv != 0 || build_request->version != 0x5)
    {
     //   printf("err build\n");
        process_err(ep);
        return;
    }
    switch (build_request->cmd)
    {
    case 0x1: // tcp
    {
        proxy_kind = SOCK5_KINDS_TCP;
        switch (build_request->atyp)
        {
        case 0x1: // ip4
        {
        
            uint32_t ip = *(uint32_t*)(&build_request->addrLength);
            in_addr t={.s_addr=ip};
         //  printf("ip4: %s dport:%d\n",inet_ntoa(t),ntohs(dport));
            tcp_fd = tcp_connect((ip), (dport), 5);
            if (tcp_fd <= 0)
            {
                error = 0x5;
            }
            else
            {
                channel *tran_channel = new channel_transmit(tcp_fd, SOCK5_KINDS_TCP);
                tran_channel->peer_channel = this;
                peer_channel = tran_channel;
                ep->add_fd(tran_channel);
            }
            break;
        }
        case 0x3: // host
        {
            char *hostname = ((char *)(&(build_request->addrLength)) + 1);
            std::string host(hostname, hostname + build_request->addrLength);
            tcp_fd = connect_by_hostname(host.data(), (dport), &error);
            if (tcp_fd > 0)
            {
                channel *tran_channel = new channel_transmit(tcp_fd, SOCK5_KINDS_TCP);
                tran_channel->peer_channel = this;
                peer_channel = tran_channel;
                ep->add_fd(tran_channel);
            }
            else
            {
                error = 0x5;
            }
        }
        break;
        case 0x4: // ip6
        {
            error = 0x2;
        }
        break;
        }
        break;
    }
    case 0x2: // bind
    {
        exit(-1);
        error = 0x2;
        break;
    }
    case 0x3: // udp
    {
      
        proxy_kind = SOCK5_KINDS_UDP;
        if (build_request->atyp != 0x1)
        {
            error = 0x2;
            break;
        }
        client_addr.sin_port = dport;
        client_addr.sin_addr.s_addr = *(uint32_t*)(&build_request->addrLength);
        in_addr addr={.s_addr=client_addr.sin_addr.s_addr};

     //   printf("client addr %s port %d\n",inet_ntoa(addr),ntohl(dport));
        int new_udp = create_udp_socket(&bind_addr);
        if (new_udp < 0)
        {
            error = 0x2;
            break;
        }
        channel *new_channel = new channel_transmit(new_udp, SOCK5_KINDS_UDP);
        new_channel->peer_channel = this;
        peer_channel = new_channel;
        state = SOCK5_TRANSMIT_DATA;
        ep->add_fd(new_channel);
        break;
    }
    default:
        printf("err cmd\n");
        return;
    }
    sock5_build_response build_response;
    memset(&build_response, 0, sizeof(sock5_build_response));
    build_response.version = 0x5;
    build_response.atyp = 0x1;
    build_response.rep = error;
    build_response.rsv = 0;
    // build_response.addrLength = 0;
    build_response.bind_addr = 0;
    build_response.bndPort = 0;
    if (proxy_kind == SOCK5_KINDS_TCP)
    {
        build_response.bind_addr = 0;
        build_response.bndPort = 0;
    }
    else if (proxy_kind == SOCK5_KINDS_UDP)
    {
        build_response.bind_addr = bind_addr.sin_addr.s_addr;
        build_response.bndPort = bind_addr.sin_port;
    }
    else
    {
        printf("proxy kind err\n");
        return;
    }
    re = write(fd, &build_response, sizeof(sock5_build_response));
    if (error != 0 || re != sizeof(sock5_build_response))
    {
        printf("connect fault\n");
        process_err(ep);
        return;
    }
    state = SOCK5_TRANSMIT_DATA;
}
void channel_client::process_read_transmit(epoll *ep)
{
    if (!peer_channel)
    {
        process_err(ep);
        return;
    }
    if (proxy_kind == SOCK5_KINDS_TCP)
    {

        char buffer[65535];
        int re = read(fd, buffer, 65535);
        if (re <= 0)
        {
            process_err(ep);
            return;
        }
        int len = 0;
        while (len < re)
        {
            int ret = write(peer_channel->fd, buffer + len, re - len);
            if (ret <= 0)
            {
                process_err(ep);
                return;
            }
            len += ret;
        }
    }
    else if (proxy_kind == SOCK5_KINDS_UDP)
    {
        printf("client err\n");
        process_err(ep);
    }
    else
    {
        printf("unsupport kind\n");
        exit(-1);
    }
}