#include "udp_proxy.h"
#define SOCKS5_VERSION 0x05
#define SOCKS5_METHOD_NO_AUTH 0x00
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ADDR_TYPE_IPV4 0x01
#define SOCKS5_ATYP_DOMAINNAME 0x03
extern char first_if_name[IFNAMSIZ];
extern sockaddr_in if_addr;
bool UDP_TO_SOCKS::create_proxy_connection()
{
    socklen_t len = sizeof(sockaddr);
    int re;
    char requets_step_1[3] = {SOCKS5_VERSION, 0x1, SOCKS5_METHOD_NO_AUTH};
    char response_step_1[10];
    char requets_step_2[10] = {SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0, SOCKS5_ADDR_TYPE_IPV4};
    char response_step_2[30] = {0};
    if ((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("create tcp fd err");
        return false;
    }
    if ((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("create udp fd err");
        close(tcp_fd);
        return false;
    }
    // bind udp
    if (setsockopt(udp_fd, SOL_SOCKET, SO_BINDTODEVICE, first_if_name, sizeof(first_if_name)) < 0)
    {
        perror("setsockopt err");
        goto error;
    }
    local_udp_addr.sin_addr.s_addr = if_addr.sin_addr.s_addr;
    local_udp_addr.sin_port = 0;
    local_udp_addr.sin_family = AF_INET;
    in_addr addr;
    if (bind(udp_fd, (sockaddr *)&local_udp_addr, sizeof(sockaddr)) < 0)
    {
        perror("bind udp err");
        goto error;
    }
    if (getsockname(udp_fd, (sockaddr *)&local_udp_addr, &len) < 0)
    {
        perror("getsockname err");
        goto error;
    }
    if (!set_timeout(tcp_fd, 5))
        goto error;
    if ((connect(tcp_fd, (sockaddr *)&socks5_tcp_addr, sizeof(sockaddr))) < 0)
    {
        perror("connect tcp fd err");
        goto error;
    }
    if (write(tcp_fd, requets_step_1, sizeof(requets_step_1)) != sizeof(requets_step_1))
    {
        perror("request step 1 err");
        goto error;
    }
    if (read(tcp_fd, response_step_1, sizeof(response_step_1)) <= 0)
    {
        perror("response step 1 err");
        goto error;
    }
    if (response_step_1[0] != SOCKS5_VERSION || response_step_1[1] != SOCKS5_METHOD_NO_AUTH)
    {
        perror("response step 1 pkt err");
        goto error;
    }
    memcpy(&requets_step_2[4], &local_udp_addr.sin_addr.s_addr, 4);
    //   memset(&requets_step_2[4], 0, 4);
    memcpy(&requets_step_2[8], &local_udp_addr.sin_port, 2);
    //addr = {.s_addr = local_udp_addr.sin_addr.s_addr};
 //   printf(" local %s\n", inet_ntoa(addr));
    if (write(tcp_fd, requets_step_2, sizeof(requets_step_2)) != sizeof(requets_step_2))
    {
        perror("request step 2 err");
        goto error;
    }
    if ((re = read(tcp_fd, response_step_2, sizeof(response_step_2))) <= 0)
    {
        perror("response step 2 err");
        goto error;
    }
    if (response_step_2[0] != SOCKS5_VERSION || response_step_2[1] != 0 ||
        response_step_2[2] != 0)
    {
        printf("response step 2 return error\n");
        goto error;
    }
    memcpy(&socks5_udp_addr.sin_addr.s_addr, response_step_2 + re - 6, 4);
    memcpy(&socks5_udp_addr.sin_port, response_step_2 + re - 2, 2);
    socks5_udp_addr.sin_family = AF_INET;
    // addr = {.s_addr = socks5_udp_addr.sin_addr.s_addr};
    // printf("%s\n", inet_ntoa(addr));
    if (connect(udp_fd, (sockaddr *)&socks5_udp_addr, sizeof(sockaddr)) < 0)
    {
        perror("udp connect err");
        goto error;
    }
    if (!set_timeout(tcp_fd, 0))
        goto error;

    return true;
error:

    close(tcp_fd);
    close(udp_fd);
    return false;
}
void UDP_TO_SOCKS::process_data(char *data, int len, uint32_t unreal_sip, uint16_t unreal_sport, uint32_t real_dip, uint16_t real_dport)
{
    // send data
    if (unreal_sip != unreal_src_ip)
    {
        printf("udp unreal sip err");
        exit(-1);
    }
    std::unique_lock<std::mutex> l(mtx);
    if (!thread)
    {
        thread = new std::thread([this]()
                                 {
        //recv data 
        char* data_buffer=new char[1600];
        int max_fd;

        if(!create_proxy_connection())
        goto thread_exit;
        wait_for_establish=false;
        FD_ZERO(&read_set);
        FD_SET(tcp_fd,&read_set);
        FD_SET(udp_fd,&read_set);
        max_fd=std::max(tcp_fd,udp_fd);
        while (true)
        {
            tmp_set=read_set;
            int re=select(max_fd+1,&tmp_set,nullptr,nullptr,0);
            if(re<=0)
            {
                printf("select err\n");
                break;
            }
            std::unique_lock<std::mutex> l(mtx);
                if(FD_ISSET(tcp_fd,&tmp_set))
                {
                
                    int ret=read(tcp_fd,data_buffer,1600);
                        if(ret<=0)
                        {
                            goto exit;
                        }
                }
                if(FD_ISSET(udp_fd,&tmp_set))
                {
            
                        int ret=read(udp_fd,data_buffer,1600);
                        socks5_udp_header* hdr=(socks5_udp_header*)data_buffer;
                        if(hdr->ATYP!=SOCKS5_ADDR_TYPE_IPV4||hdr->FRAG!=0)
                        {
                            return;
                        }
                  
                        uint32_t remote_ip=hdr->ADDR;
                        uint16_t remote_port=hdr->PORT;
                        if(session.find({remote_ip,remote_port})==session.end())
                        {
                            printf("remote find false\n");
                            continue;
                        }
                 
                        uint16_t unreal_sport=session[{remote_ip,remote_port}];
                        sockaddr_in to_addr;
                        to_addr.sin_family=AF_INET;
                        to_addr.sin_port=unreal_sport;
                        to_addr.sin_addr.s_addr=unreal_src_ip;
                   
                        if(sendto(local_fd,data_buffer+sizeof(socks5_udp_header),ret-sizeof(socks5_udp_header),0,(sockaddr*)&to_addr,sizeof(sockaddr))<=0)
                        {
                            printf("local udp sendto err\n");
                            continue;
                        }
                    
                }
            
        }
        
exit:
        if(udp_fd>0)close(udp_fd);
        if(tcp_fd>0)close(tcp_fd);
thread_exit:
        wait_for_establish=true;
        delete [] data_buffer;
        delete thread;
        thread=nullptr;
        return; });
        thread->detach();
    }

    if (wait_for_establish)
    {
        return;
    }

    socks5_udp_header *socks5_header = (socks5_udp_header *)buffer;
    socks5_header->RSV[0] = 0;
    socks5_header->RSV[1] = 0;
    socks5_header->FRAG = 0;
    socks5_header->ATYP = SOCKS5_ADDR_TYPE_IPV4;
    socks5_header->ADDR = real_dip;
    socks5_header->PORT = real_dport;
    session[{real_dip, real_dport}] = unreal_sport;
    memcpy(buffer + sizeof(socks5_udp_header), data, len);
    if (write(udp_fd, buffer, sizeof(socks5_udp_header) + len) <= 0)
    {
        close(tcp_fd);
        close(udp_fd);
        tcp_fd = -1;
        udp_fd = -1;
    }
}
