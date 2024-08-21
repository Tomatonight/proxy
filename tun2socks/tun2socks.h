#pragma once
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <openssl/err.h>
#include <linux/if_tun.h>
#include<memory.h>
#include<arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<atomic>
#include<regex>
#include<signal.h>
#include<thread>
#include <sys/wait.h>
#include <ifaddrs.h>
#include"entry.h"
#include"addrpool.h"
#include"udp_proxy.h"
#include"checksum.h"
#define VIRTUAL_NET "10.0.0.0"
#define TUN_IP "10.0.0.1"
#define VIRTUAL_MASK 24
#define VIRTUAL_LISTEN_TCP_PORT 1234
#define VIRTUAL_LISTEN_UDP_PORT 1234
class tun2socks
{
public:
    void init();
    void loop();
private:
    void parse_configure();
    void tun_init();
    void get_eth_name();
    void listen_init();
    void process_tun();
    void process_tcp();
    void process_udp();
    int connect_socks5_tcp(sockaddr_in real_dst);

    int tun_fd;
    int listen_tcp_fd;
    int listen_udp_fd;
    std::atomic<int> thread_cnt=0;
    sockaddr_in tcp_addr,udp_addr;
    sockaddr_in socks5_tcp,socks5_udp;
    uint32_t tun_ip;
    uint32_t tun_mask;
    fd_set read_set,tmp_set;
    Entrys *Entry;
    std::unordered_map<uint32_t,UDP_TO_SOCKS*> unrealip_to_udp_socks;
};