#include "entry.h"
void Entrys::init(char *ip_, int mask, sockaddr_in *unreal_tcp_listen, sockaddr_in *unreal_udp_listen)
{
    unreal_ip_pool.init(ip_, mask);
    virtual_listen_ip_tcp = unreal_tcp_listen->sin_addr.s_addr;
    virtual_listen_port_tcp = unreal_tcp_listen->sin_port;
    virtual_listen_ip_udp = unreal_udp_listen->sin_addr.s_addr;
    virtual_listen_port_udp = unreal_udp_listen->sin_port;
}
entry *Entrys::search(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint8_t protocol)
{
   

    if ((sip == virtual_listen_ip_tcp && sport == virtual_listen_port_tcp && protocol == IPPROTO_TCP) ||
        (sip == virtual_listen_ip_udp && sport == virtual_listen_port_udp && protocol == IPPROTO_UDP)) // unreal
    {
        if (real_to_unreal_ip.find(dip) == real_to_unreal_ip.end())
        {
            return nullptr;
        }
        uint32_t real_src_ip = real_to_unreal_ip[dip];
        if (entrys.find({real_src_ip, dport, protocol}) == entrys.end())
        {
            return nullptr;
        }
        return entrys[{real_src_ip, dport, protocol}];
    }
    else // real
    {
        if (entrys.find({sip, sport, protocol}) == entrys.end())
        {
            if (real_to_unreal_ip.find(sip) == real_to_unreal_ip.end())
            {
                uint32_t alloced_ip = unreal_ip_pool.alloc_ip();
                if (!alloced_ip)
                {
                    printf("alloc ip err\n");
                    return nullptr;
                }
                real_to_unreal_ip[sip] = alloced_ip;
                real_to_unreal_ip[alloced_ip] = sip;
            }
            entry *new_entry = new entry;
            new_entry->protocol = protocol;
            new_entry->real_src_ip = sip;
            new_entry->real_src_port = sport;
            new_entry->real_dst_ip = dip;
            new_entry->real_dst_port = dport;
            new_entry->unreal_src_ip = real_to_unreal_ip[sip];
            new_entry->unreal_src_port = sport;
            if (protocol == IPPROTO_TCP)
            {
                new_entry->unreal_dst_ip = virtual_listen_ip_tcp;
                new_entry->unreal_dst_port = virtual_listen_port_tcp;
                new_entry->protocol = IPPROTO_TCP;
            }
            else if (protocol == IPPROTO_UDP)
            {
                new_entry->unreal_dst_ip = virtual_listen_ip_udp;
                new_entry->unreal_dst_port = virtual_listen_port_udp;
                new_entry->protocol = IPPROTO_UDP;
            }
            else
            {
                printf("protocol err\n");
                exit(-1);
            }
            entrys[{sip, sport, protocol}] = new_entry;
        }
        class entry *entry = entrys[{sip, sport, protocol}];
        entry->real_dst_ip = dip;
        entry->real_dst_port = dport;
        //  if (entry->protocol == IPPROTO_UDP)
        //  {
        //      in_addr addr = {.s_addr = entry->real_dst_ip };
        //      printf("add dip %s\n", inet_ntoa(addr));
        //  }
        return entry;
    }
    return nullptr;
}
