#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <errno.h>
#include "proxy.h"
static int map_fd=0;
static int map_fd_udp=0;
void print()
{
    FILE *fp = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!fp)
    {
        perror("Failed to open trace_pipe");
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp))
    {
        printf("%s", buffer);
    }

    fclose(fp);
}
void start_listen()
{

    pthread_t t, t_;
    pthread_create(&t, NULL, tcp_loop, NULL);
    pthread_detach(t);
    pthread_create(&t_, NULL, udp_loop, NULL);
    pthread_detach(t_);
}
void add_hook(const char *path, struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    prog = bpf_object__find_program_by_name(obj, path);
    if (!prog)
    {
        fprintf(stderr, "Error finding BPF program by name\n");
        return;
    }
    link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "Error attaching BPF program to tracepoint\n");
        return;
    }
}
static __u64 get_key(__u32 ip, __u16 port)
{
    return ((__u64)ip) & 0x00000000FFFFFFFF | ((((__u64)port) << 32) & 0x0000FFFF00000000);
};
static __u32 get_ip(__u64 value)
{
    return (value & 0x00000000FFFFFFFF);
};
static __u16 get_port(__u64 value)
{
    return (value >> 32) & 0x000000000000FFFF;
}
int search_daddr(uint32_t sip, uint16_t sport, uint32_t *dip, uint16_t *dport, __u16 protocol)
{
    __u64 key = get_key(sip, sport);
    __u64 value=0;
    int ret=0;
    if (protocol == IPPROTO_TCP)
    {
       // printf("aaaaaaaaaaa %d %d %llu\n", sip,sport,key);
        ret = bpf_map_lookup_elem(map_fd,&key, &value);
    }
    else if(protocol==IPPROTO_UDP)
    {
        ret = bpf_map_lookup_elem(map_fd_udp, &key, &value);
    //     printf("find key %d %d %llu\n",sip,sport,key);
    }
    else 
    {
        printf("protocol err\n");
        return -1;
    }
    if (ret < 0)
    {
         printf("find key %d %d %llu\n",sip,sport,key);
        perror("Error in bpf_map_lookup_elem");
        return -1;
    }
    *dip = get_ip(value);
    *dport = get_port(value);
    return 0;
}
int main()
{
    struct bpf_object *obj = NULL;
    int ret;
    // 加载 BPF 对象
    obj = bpf_object__open_file("build/test.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    // 加载和附加 BPF 程序
    ret = bpf_object__load(obj);
    if (ret)
    {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }
    map_fd = bpf_object__find_map_fd_by_name(obj, "addr_map");
    map_fd_udp = bpf_object__find_map_fd_by_name(obj, "addr_map_udp");
    // __u64 key=1;
    // __u64 value;
    // if(bpf_map_update_elem(map_fd,&key,&value,BPF_ANY)!=0)
    // {
    //     printf("rrxxxxxxxxx\n");
    // }
    // int re=bpf_map_lookup_elem(map_fd,&key,&value);
    // printf("rrrrrrrrrrr %d\n",re);
    if (map_fd < 0 || map_fd_udp < 0)
    {
        perror("Failed to find map");
        return 0;
    }
    add_hook("tcp_connect", obj);
    add_hook("hook_tcp_state", obj);
     add_hook("udp_sendmsg", obj);
     add_hook("udp_sendmsg_ret", obj);
    
    start_listen();
    print();
    bpf_object__close(obj);
    return 0;
}
