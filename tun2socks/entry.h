#pragma once
#include <iostream>
#include <unordered_map>
#include <mutex>
#include<arpa/inet.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<tuple>
#include "addrpool.h"
struct entry // net 25*65535
{
    uint32_t real_src_ip;
    uint16_t real_src_port;
    uint32_t real_dst_ip;
    uint16_t real_dst_port;
    /***************************/
    uint32_t unreal_src_ip;
    uint16_t unreal_src_port;
    uint32_t unreal_dst_ip;
    uint16_t unreal_dst_port;
    uint8_t protocol;
};
struct TupleHash {
    template <typename T1, typename T2, typename T3>
    std::size_t operator()(const std::tuple<T1, T2, T3>& t) const {
        std::size_t h1 = std::hash<T1>{}(std::get<0>(t));
        std::size_t h2 = std::hash<T2>{}(std::get<1>(t));
        std::size_t h3 = std::hash<T3>{}(std::get<2>(t));
        return h1 ^ (h2 << 1) ^ (h3 << 2);  
    }
};
class Entrys
{
public:
    Entrys(){};
    void init(char* ip_,int mask,sockaddr_in* unreal_tcp_listen,sockaddr_in* unreal_udp_listen);
    entry *search(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint8_t protocol);
private:
    std::mutex mtx;
    uint32_t virtual_listen_ip_tcp;   // net
    uint16_t virtual_listen_port_tcp; // net
    uint32_t virtual_listen_ip_udp;   // net
    uint16_t virtual_listen_port_udp; // net
    Addrpool unreal_ip_pool;
    std::unordered_map<uint32_t, uint32_t> real_to_unreal_ip;
    std::unordered_map<std::tuple<uint32_t, uint16_t, uint8_t>, entry *, TupleHash> entrys;
};