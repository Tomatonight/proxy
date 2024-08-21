#pragma once
#include <unordered_map>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <memory.h>
#include <mutex>
#include"checksum.h"
struct pair_hash {
    template <class T1, class T2>
    std::size_t operator() (const std::pair<T1, T2>& p) const {
        auto hash1 = std::hash<T1>{}(p.first);
        auto hash2 = std::hash<T2>{}(p.second);
        return hash1 ^ (hash2 << 1); // 组合两个哈希值
    }
};

struct socks5_udp_header
{
    char RSV[2];
    char FRAG;
    char ATYP;
    uint32_t ADDR;
    uint16_t PORT;
} __attribute__((packed));
class UDP_TO_SOCKS
{
public:
    UDP_TO_SOCKS(sockaddr_in *addr,int fd,uint32_t ip):local_fd(fd),unreal_src_ip(ip)
    {
        buffer=new char[2048];
        memcpy(&socks5_tcp_addr, addr, sizeof(sockaddr));
    }
    ~UDP_TO_SOCKS()
    {
        delete [] buffer;
    }
    bool create_proxy_connection();
    void process_data(char *data, int len,uint32_t unreal_sip,uint16_t unreal_dport ,uint32_t real_dip, uint16_t real_dport);

    int udp_fd;
    int tcp_fd;
    int local_fd;
    char* buffer;
    bool wait_for_establish = true;
    std::thread *thread = nullptr;
    std::mutex mtx;
    sockaddr_in socks5_tcp_addr;
    sockaddr_in socks5_udp_addr;
    sockaddr_in local_udp_addr;
    uint32_t unreal_src_ip;
    std::unordered_map<std::pair<uint32_t,uint16_t>,uint16_t,pair_hash> session;
    fd_set read_set;
    fd_set tmp_set;
    
};
