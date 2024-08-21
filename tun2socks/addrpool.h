#pragma once
#include<iostream>
#include<vector>
#include<arpa/inet.h>
#include<math.h>
class Addrpool
{
    public:
    Addrpool(){};
    void init(char* ip_,int mask)
    {
        
        ip=ntohl(inet_addr(ip_));
        int nb=pow(2,32-mask);
        while (mask--)
        {
            ip_mask=(ip_mask>>1)|0x80000000;
        }
        pool.resize(nb,0);
        pool[0]=1;
        pool[1]=1;
    }
    uint32_t alloc_ip()//net
    {
        for(int i=0;i<pool.size();i++)
        {
            if(!pool[i])
            {
                pool[i]=1;
                return htonl((ip&ip_mask)+i);
            }
        }
        return 0;
    }
    void free_ip(uint32_t ip)//net
    {
        ip=ntohl(ip);
        ip&=~ip_mask;
        pool[ip]=0;
    }
    private:
    uint32_t ip;
    uint32_t ip_mask;
    std::vector<bool> pool;
};