#include "tun2socks.h"
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
char first_if_name[IFNAMSIZ];
sockaddr_in if_addr;
char udp_buffer[2048];
/*
static void child_exit(int sig)
{
    pid_t pid;
    int stat;
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0)
    {
    }
};
static void child_exit_(int sig)
{
    pid_t pid;
    int stat;
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0)
    {
    }
    exit(-1);
};*/

void tun2socks::init()
{
    get_eth_name();
    parse_configure();
    tun_init();
    printf("tun init done\n");
    listen_init();
    printf("listen init done\n");
    Entry = new Entrys;
    Entry->init(VIRTUAL_NET, VIRTUAL_MASK, &tcp_addr, &udp_addr);
    //  signal(SIGCHLD, child_exit);
    printf("init done\n");
}
void tun2socks::get_eth_name()
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK))
        {
            strncpy(first_if_name, ifa->ifa_name, IFNAMSIZ);
            memcpy(&if_addr, ifa->ifa_addr, sizeof(sockaddr));
            break;
        }
    }
    if (strlen(first_if_name) == 0)
    {
        fprintf(stderr, "No suitable network interface found\n");
        freeifaddrs(ifaddr);
        exit(EXIT_FAILURE);
    }
    freeifaddrs(ifaddr);
}
void tun2socks::parse_configure()
{
    int file_fd = open("configure", O_RDONLY);
    if (file_fd < 0)
    {
        printf("open congigure err\n");
        exit(-1);
    }
    char buffer[1024] = {0};
    /*
   SOCKS5_TCP_PROXY:192.168.72.123 1234
SOCKS5_UDP_PROXY:192.168.72.123 1234
    */
    if (read(file_fd, buffer, 1023) < 0)
    {
        printf("read congigure err\n");
        exit(-1);
    }
    close(file_fd);
    std::cmatch match;
    std::regex reg("SOCKS5_TCP_PROXY:([^ ]+)[ ]+([0-9]+)\nSOCKS5_UDP_PROXY:([^ ]+)[ ]+([0-9]+)");
    if (std::regex_search(buffer, match, reg))
    {
        memset(&socks5_tcp, 0, sizeof(sockaddr));
        memset(&socks5_udp, 0, sizeof(sockaddr));
        socks5_tcp.sin_family = AF_INET;
        socks5_udp.sin_family = AF_INET;
        socks5_tcp.sin_addr.s_addr = inet_addr(std::string(match[1]).data());
        socks5_tcp.sin_port = htons(atoi(std::string(match[2]).data()));
        socks5_udp.sin_addr.s_addr = inet_addr(std::string(match[3]).data());
        socks5_udp.sin_port = htons(atoi(std::string(match[4]).data()));
    }
    else
    {
        printf("configure err\n");
        exit(-1);
    }
}
void tun2socks::process_tcp()
{
    
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(sockaddr));
    socklen_t len = sizeof(sockaddr);
    int new_tcp = accept(listen_tcp_fd, (sockaddr *)&saddr, &len);
    // get real daddr
    if (new_tcp < 0)
    {
        printf("accept err\n");
        return;
    }
     
    uint32_t unreal_sip = saddr.sin_addr.s_addr;
    uint16_t unreal_sport = saddr.sin_port;
    uint32_t unreal_dip = tcp_addr.sin_addr.s_addr;
    uint32_t unreal_dport = tcp_addr.sin_port;
    struct entry *entry = Entry->search(unreal_dip, unreal_dport, unreal_sip, unreal_sport, IPPROTO_TCP);
    if (!entry)
    {
        printf("tcp find entry err\n");
        close(new_tcp);
        return;
    }
    sockaddr_in real_daddr;
    memset(&real_daddr, 0, sizeof(sockaddr));
    real_daddr.sin_family = AF_INET;
    real_daddr.sin_addr.s_addr = entry->real_dst_ip;
    real_daddr.sin_port = entry->real_dst_port;
    std::thread thread = std::move(std::thread([new_tcp,real_daddr,this]()
                                               {
        if(thread_cnt>30)
        {
            close(new_tcp);
            return;
        }
        thread_cnt++;

        int new_socks5_fd=connect_socks5_tcp(real_daddr);
        if(new_socks5_fd<0)
        {
            thread_cnt--;
            close(new_tcp);
            return;
        }
        fd_set read_set,tmp_set;
        FD_ZERO(&read_set);
        FD_ZERO(&tmp_set);
        int max_fd=new_tcp>new_socks5_fd?new_tcp:new_socks5_fd;
        FD_SET(new_tcp,&read_set);
        FD_SET(new_socks5_fd,&read_set);
        char* data_buffer=new char[2048];
        while (true)
        {
            tmp_set=read_set;
            int re=select(max_fd+1,&tmp_set,nullptr,nullptr,0);
            if(re<=0)
            {
                perror("select err\n");
                 goto exit_;
            }
                if(FD_ISSET(new_tcp,&tmp_set))
                {
                        int ret=read(new_tcp,data_buffer,2048);
                        if(ret<=0)
                        {
                            goto exit_;
                        }
                        write(new_socks5_fd,data_buffer,ret);
                }
                if(FD_ISSET(new_socks5_fd,&tmp_set))
                {
                      int ret=read(new_socks5_fd,data_buffer,2048);
                        if(ret<=0)
                        {
                            goto exit_;
                        }
                        write(new_tcp,data_buffer,ret);
                        
                }
             
            
        }
    exit_:
        delete [] data_buffer;
        close(new_tcp);
        close(new_socks5_fd);
         thread_cnt--; }));
    thread.detach();
}
void tun2socks::process_udp()
{
    sockaddr_in unreal_saddr;
    socklen_t len = sizeof(sockaddr);
    int re;
    if ((re = recvfrom(listen_udp_fd, udp_buffer, 2048, 0, (sockaddr *)&unreal_saddr, &len)) <= 0)
    {
        printf(" udp listen err\n");
        exit(-1);
    }

    uint32_t unreal_sip = unreal_saddr.sin_addr.s_addr;
    uint16_t unreal_sport = unreal_saddr.sin_port;
    uint32_t unreal_dip = udp_addr.sin_addr.s_addr;
    uint16_t unreal_dport = udp_addr.sin_port;
    struct entry *entry = Entry->search(unreal_dip, unreal_dport, unreal_sip, unreal_sport, IPPROTO_UDP);
    if (!entry)
    {
        printf("udp find entry err\n");
        return;
    }
    if (unrealip_to_udp_socks.find(unreal_sip) == unrealip_to_udp_socks.end())
    {
        unrealip_to_udp_socks[unreal_sip] = new UDP_TO_SOCKS(&socks5_udp, listen_udp_fd, unreal_sip);
    }
    UDP_TO_SOCKS *udp_socks = unrealip_to_udp_socks[unreal_sip];

    udp_socks->process_data(udp_buffer, re, unreal_sip, unreal_sport, entry->real_dst_ip, entry->real_dst_port);
}
void tun2socks::process_tun()
{
    char buffer[1600];
    int recv_len = read(tun_fd, buffer, 1600);
    if (recv_len <= 0)
    {
        printf("tun read err\n");
        exit(-1);
    }
    iphdr *ip = (iphdr *)buffer;
    uint32_t sip = ip->saddr, dip = ip->daddr;
    uint16_t sport, dport;
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        tcphdr *tcp = (tcphdr *)((char *)ip + ip->ihl * 4);
        sport = tcp->source;
        dport = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        udphdr *udp = (udphdr *)((char *)ip + ip->ihl * 4);
        sport = udp->source;
        dport = udp->dest;
        break;
    }
    default:
        return;
    }
    class entry *entry = Entry->search(sip, sport, dip, dport, ip->protocol);
    if (!entry)
    {
        printf("cant find\n");
        return;
    }
    //    printf("before\n");
    //  print(ip);
    
    // if (ip->protocol == IPPROTO_UDP)
    // {
    //     printf("before\n");
    //     print(ip);
    // }
    if ((sip == tcp_addr.sin_addr.s_addr && sport == tcp_addr.sin_port && ip->protocol == IPPROTO_TCP) ||
        (sip == udp_addr.sin_addr.s_addr && sport == udp_addr.sin_port && ip->protocol == IPPROTO_UDP))
    { // unreal ---->real
        // printf("a\n");
        ip->saddr = entry->real_dst_ip;
        ip->daddr = entry->real_src_ip;
        ip->check = 0;
        ip->check = checksum((char *)ip, ip->ihl * 4, 0);
        switch (ip->protocol)
        {
        case IPPROTO_TCP:
        {
            tcphdr *tcp = (tcphdr *)((char *)ip + ip->ihl * 4);
            tcp->source = entry->real_dst_port;
            tcp->dest = entry->real_src_port;
            tcp->check = 0;
            tcp->check = checksum_tran(ip->saddr, ip->daddr, IPPROTO_TCP, (char *)tcp, ntohs(ip->tot_len) - ip->ihl * 4);
            break;
        }
        case IPPROTO_UDP:
        {
            udphdr *udp = (udphdr *)((char *)ip + ip->ihl * 4);
            udp->source = entry->real_dst_port;
            udp->dest = entry->real_src_port;
            udp->check = 0;
            udp->check = checksum_tran(ip->saddr, ip->daddr, IPPROTO_UDP, (char *)udp, ntohs(udp->len));
            break;
        }
        default:
            return;
        }
    }
    else
    {
        // real ---->unreal
        //  printf("b\n");
        ip->saddr = entry->unreal_src_ip;
        ip->daddr = entry->unreal_dst_ip;
        ip->check = 0;
        ip->check = checksum((char *)ip, ip->ihl * 4, 0);
        switch (ip->protocol)
        {
        case IPPROTO_TCP:
        {
            tcphdr *tcp = (tcphdr *)((char *)ip + ip->ihl * 4);
            tcp->source = entry->unreal_src_port;
            tcp->dest = entry->unreal_dst_port;
            tcp->check = 0;
            tcp->check = checksum_tran(ip->saddr, ip->daddr, IPPROTO_TCP, (char *)tcp, ntohs(ip->tot_len) - ip->ihl * 4);
            break;
        }
        case IPPROTO_UDP:
        {
            udphdr *udp = (udphdr *)((char *)ip + ip->ihl * 4);
            udp->source = entry->unreal_src_port;
            udp->dest = entry->unreal_dst_port;
            udp->check = 0;
            udp->check = checksum_tran(ip->saddr, ip->daddr, IPPROTO_UDP, (char *)udp, ntohs(udp->len));
            break;
        }
        default:
            return;
        }
    }
    // if (ip->protocol == IPPROTO_UDP)
    // {
    //     printf("after\n");
    //     print(ip);
    // }
    if (write(tun_fd, buffer, recv_len) != recv_len)
    {
        printf("tun write size err\n");
    }
}
void tun2socks::tun_init()
{
    FILE *fp;
    char line[500];
    char iface[IFNAMSIZ];
    unsigned long dest, gateway;
    struct in_addr gw_addr;

    // 打开 /proc/net/route 文件
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
    {
        perror("fopen");
        exit(1);
    }

    // 读取文件每一行
    while (fgets(line, sizeof(line), fp))
    {
        // 解析行内容
        if (sscanf(line, "%s\t%lx\t%lx", iface, &dest, &gateway) == 3)
        {
            // 检查是否为默认路由（目标地址为 0.0.0.0）
            if (dest == 0)
            {
                gw_addr.s_addr = gateway;
                break;
            }
        }
    }

    fclose(fp);
    ifreq ifr;
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd <= 0)
    {
        printf("open tun err\n");
        exit(-1);
    }
    memset(&ifr, 0, sizeof(ifreq));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_UP;
    strncpy(ifr.ifr_name, "tun", IFNAMSIZ);
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        printf("ioctl tun err\n");
        exit(-1);
    }
    char buffer[100] = {0};
    // sudo ifconfig %s %s/24", tun_dev_name, tun_ip
    sprintf(buffer, "sudo ifconfig tun %s/%d", TUN_IP, VIRTUAL_MASK);
    system(buffer);
    system("sudo ip route add default dev tun");
    system("sudo ifconfig tun up");
    // sudo ip route add 192.168.100.1 via <Your-Gateway-IP> dev <Your-Network-Interface>
    memset(buffer, 0, 100);
    in_addr addr = {.s_addr = gw_addr.s_addr};
    char tmp[20] = {0};
    inet_ntop(AF_INET, &socks5_tcp.sin_addr.s_addr, tmp, 20);
    sprintf(buffer, " sudo ip route add %s via %s dev %s", tmp, inet_ntoa(addr), first_if_name);
    system(buffer);
    memset(buffer, 0, 100);
}
void tun2socks::listen_init()
{
    listen_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_tcp_fd < 0)
    {
        printf("create tcp socket err\n");
        exit(-1);
    }
    int opt = 1;
    setsockopt(listen_tcp_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = inet_addr(TUN_IP);
    tcp_addr.sin_port = htons(VIRTUAL_LISTEN_TCP_PORT);
    if (bind(listen_tcp_fd, (sockaddr *)&tcp_addr, sizeof(sockaddr)) < 0)
    {
        printf("bind saddr err\n");
        exit(-1);
    }
    if (listen(listen_tcp_fd, 20) < 0)
    {
        printf("tcp listen err\n");
        exit(-1);
    }
    listen_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_udp_fd < 0)
    {
        printf("create udp socket err\n");
        exit(-1);
    }
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = inet_addr(TUN_IP);
    udp_addr.sin_port = htons(VIRTUAL_LISTEN_UDP_PORT);
    if (bind(listen_udp_fd, (sockaddr *)&udp_addr, sizeof(sockaddr)) < 0)
    {
        printf("bind saddr err\n");
        exit(-1);
    }
}
void tun2socks::loop()
{
    FD_ZERO(&read_set);
    FD_ZERO(&tmp_set);
    FD_SET(tun_fd, &read_set);
    FD_SET(listen_tcp_fd, &read_set);
    FD_SET(listen_udp_fd, &read_set);
    printf("loop start\n");
    while (true)
    {
        tmp_set = read_set;
        int re = select(FD_SETSIZE, &tmp_set, nullptr, nullptr, 0);
        if (re <= 0)
        {
            printf("select err\n");
            exit(-1);
        }
        for (int i = 0; i < FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &tmp_set))
            {
                if (i == listen_tcp_fd)
                {

                    process_tcp();
                }
                else if (i == listen_udp_fd)
                {
                    //     printf("udp read\n");
                    process_udp();
                }
                else if (i == tun_fd)
                {
                    process_tun();
                }
                else
                {
                    printf("fd err\n");
                }
            }
        }
    }
}
int tun2socks::connect_socks5_tcp(sockaddr_in real_daddr)
{
    int socks5_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socks5_fd < 0)
    {
        printf("create socks5 fd err\n");
        return -1;
    }

    if (setsockopt(socks5_fd, SOL_SOCKET, SO_BINDTODEVICE, first_if_name, IFNAMSIZ) < 0)
    {
        printf("bind socks5 dev err\n");
        close(socks5_fd);
        return -1;
    }
    /*
        if (bind(socks5_fd, (sockaddr *)&if_addr, sizeof(sockaddr)) < 0)
        {
            printf("bind socks5  err\n");
            close(socks5_fd);
            return -1;
        }*/
    if (!set_timeout(socks5_fd, 5))
    {
        close(socks5_fd);
        return -1;
    }
    /*
    if (setsockopt(socks5_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt SO_SNDTIMEO");
        close(socks5_fd);
        return -1;
    }
   // in_addr addr = {.s_addr = socks5_tcp.sin_addr.s_addr};
   // printf("start %s %d\n", inet_ntoa(addr),ntohs(socks5_tcp.sin_port));
*/
    if (connect(socks5_fd, (sockaddr *)&socks5_tcp, sizeof(sockaddr)) < 0)
    {
        close(socks5_fd);
        //  printf("connect socks5  err\n");
        return -1;
    }

    //  system("ip route get 192.168.72.123");

    unsigned char request[] = {
        SOCKS5_VERSION, // SOCKS5 版本
        0x01,           // 支持的认证方法数量
        0x00            // 无认证
    };
    if (write(socks5_fd, request, sizeof(request)) != sizeof(request))
    {
        close(socks5_fd);
        printf("write size err\n");
        return -1;
    }
    unsigned char response[2];
    if (read(socks5_fd, response, sizeof(response)) != sizeof(response))
    {
        close(socks5_fd);
        printf("recv size err\n");
        return -1;
    }

    if (response[0] != SOCKS5_VERSION || response[1] != 0x00)
    {
        close(socks5_fd);
        printf("SOCKS5 initialization failed\n");
        return -1;
    }

    unsigned char connect_request[10] = {
        SOCKS5_VERSION,     // SOCKS5 版本
        SOCKS5_CMD_CONNECT, // 连接命令
        0x00,               // 保留字段
        SOCKS5_ATYP_IPV4    // 地址类型: IPv4
    };
    memcpy(&connect_request[4], &real_daddr.sin_addr.s_addr, 4);
    memcpy(&connect_request[8], &real_daddr.sin_port, 2);
    if (write(socks5_fd, connect_request, sizeof(connect_request)) != sizeof(connect_request))
    {
        close(socks5_fd);
        printf("send size err\n");
        return -1;
    }
    unsigned char connect_response[20];
    if (read(socks5_fd, connect_response, sizeof(connect_response)) <= 0)
    {
        close(socks5_fd);
        printf("recv size err\n");
        return -1;
    }
    if (connect_response[1] != 0x00)
    {
        close(socks5_fd);
    //    printf("response err\n");
        return -1;
    }
    if (!set_timeout(socks5_fd, 0))
    {
        close(socks5_fd);
        return -1;
    }
    return socks5_fd;
}
