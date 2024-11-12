#define __TARGET_ARCH_x86 1
#include "vmlinux.h"
#include <linux/module.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define AF_INET 2
#define LOCAL_PORT 1234
#define LOCAL_IP ((127 << 24) | (0 << 16) | (0 << 8) | (1))
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048); // 最大存储 1024 项
    __type(key, __u64);        // 键的类型
    __type(value, __u64);      // 值的类型
} sock_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048); 
    __type(key, __u64);        // 键的类型
    __type(value, __u64);      // 值的类型
} addr_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048); 
    __type(key, __u64);        // 键的类型
    __type(value, __u64);      // 值的类型
} addr_map_udp SEC(".maps");

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

static struct sock *search_sock(int fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files_struct = NULL; // BPF_CORE_READ(task,files);
    if (bpf_probe_read_kernel(&files_struct, 8, &task->files) < 0)
    {
        bpf_printk("read err 1");
    }
    struct fdtable *fdt = NULL;
    bpf_probe_read_kernel(&fdt, 8, &files_struct->fdt);
    struct file **files = NULL;
    bpf_probe_read_kernel(&files, 8, &fdt->fd);
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, 8, &files[fd]);
    struct socket *sk = (struct socket *)BPF_CORE_READ(file, private_data);

    return (struct sock *)BPF_CORE_READ(sk, sk);
}
SEC("tracepoint/syscalls/sys_enter_connect") // fd sockaddr* int
int tcp_connect(struct trace_event_raw_sys_enter *ctx)
{
    // struct bpf_sock_addr addr;
    //  bpf_probe_read(&len,4,&ctx->args[2])
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(struct sockaddr), (char *)ctx->args[1]) < 0)
    {
        bpf_printk("read err \n");
        return 0;
    }
    if (addr.sin_family != AF_INET)
        return 0;
    struct sock *sock = search_sock(ctx->args[0]);
    if (!sock)
    {
        bpf_printk("search sock err fd:%d\n", ctx->args[0]);
        return 0;
    }
    __u16 protocol = BPF_CORE_READ(sock, sk_protocol);
    if (protocol != 0x6)
    {
        return 0;
    }

    // bpf_printk("%d %d",addr.sin_family,ctx->args[2]);
    __u64 key = (__u64)sock;
    __u64 value = get_key(addr.sin_addr.s_addr, addr.sin_port);
    addr.sin_port = bpf_htons(1234);
    addr.sin_addr.s_addr = bpf_htonl(((127 << 24) & 0xff000000 | (1)));
  //  bpf_printk("add key %llu\n",key);
    if(bpf_map_update_elem(&sock_map, (void *)&key, (void *)&value, BPF_ANY)<0)
    {
        bpf_printk("add sock err");
    }

    if (bpf_probe_write_user((char *)ctx->args[1], (char *)&addr, 16) < 0)
    {
        bpf_printk("write err \n");
        return 0;
    }
    return 0;
}

SEC("kprobe/tcp_set_state")
int hook_tcp_state(struct pt_regs *ctx)
{

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int new_state = (int)PT_REGS_PARM2(ctx);
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (new_state == TCP_ESTABLISHED && protocol == 0x6)
    {

        struct inet_sock *inet = (struct inet_sock *)sk;
        __u64 tmp = (__u64)sk;
        // 获取源 IP 和目的 IP 地址
        __u32 saddr = BPF_CORE_READ(inet, inet_saddr); // 源 IP
        __u16 sport = BPF_CORE_READ(inet, inet_sport); // 源端口
        __u64 value = (__u64)bpf_map_lookup_elem(&sock_map, (const void *)&tmp);
        if (value)
        {
            
            value = *((__u64 *)value);
            __u64 key = get_key(saddr, sport);
     //       bpf_printk("key %d %d %llu\n",saddr,sport,key);
            if(bpf_map_update_elem(&addr_map, &key,&value, BPF_ANY)<0)
            {
                bpf_printk("add key %llu err\n",key);
            }
        }
        else
        {
           // bpf_printk("err %llu\n", tmp);
            return 0;
        }
    }
    return 0;
}

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048); // 最大存储 1024 项
    __type(key, __u32);        // 键的类型
    __type(value, __u64);      // 值的类型
} udp_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int udp_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    int fd = ctx->args[0];
    struct msghdr *m = (struct msghdr *)ctx->args[1];
    struct sock *sock = search_sock(fd);
    if (!sock)
        return 0;
    __u16 protocol = BPF_CORE_READ(sock, sk_protocol);
    if (protocol != 17)
    {
        return 0;
    }

    __u64 key = (__u64)sock;
    struct msghdr msg;
    if (bpf_probe_read_user(&msg, sizeof(struct msghdr), m))
    {
        bpf_printk("read err\n");
        goto exit;
    }
    if (!msg.msg_name)
    {
        bpf_printk("msg_name err\n");
        goto exit;
    }
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(struct sockaddr_in), msg.msg_name))
    {
        bpf_printk("read err\n");
        goto exit;
    }
    if (addr.sin_family != AF_INET)
    {
        bpf_printk("sin_family err\n");
        goto exit;
    }
    __u64 value = get_key(addr.sin_addr.s_addr, addr.sin_port);
   // bpf_printk("test %d %d\n",addr.sin_addr.s_addr, addr.sin_port);
    bpf_map_update_elem(&sock_map, (void *)&key, (void *)&value, BPF_ANY);
    addr.sin_port = bpf_htons(1234);
    addr.sin_addr.s_addr = bpf_htonl(((127 << 24) & 0xff000000 | (1)));
    if (bpf_probe_write_user(msg.msg_name, (char *)&addr, sizeof(struct sockaddr_in)) < 0)
    {
        bpf_printk("write err \n");
        goto exit;
    }
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 tmp = (__u64)sock;
    bpf_map_update_elem(&udp_map, &pid, &tmp, BPF_ANY);
exit:
    return 0;
}
SEC("kretprobe/udp_sendmsg")
int udp_sendmsg_ret(struct pt_regs *ctx)
{

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *tmp = (__u64 *)bpf_map_lookup_elem(&udp_map, &pid);
    if (!tmp)
    {
        goto exit;
    }
    struct sock *sk = (struct sock *)(*tmp);
    struct inet_sock *inet = (struct inet_sock *)sk;
    __u32 saddr = BPF_CORE_READ(inet, inet_saddr); // 源 IP
    __u16 sport = BPF_CORE_READ(inet, inet_sport); // 源端口
    tmp = (__u64 *)bpf_map_lookup_elem(&sock_map, &sk);
    if (!tmp)
    {
        bpf_printk("tmp_");
        goto exit;
    }
    __u32 daddr = get_ip(*tmp);
    __u32 dport = get_ip(*tmp);
    __u64 key = get_key(saddr, sport);
    __u64 value = get_key(daddr, dport);
  //  bpf_printk("add key %d %d %llu",saddr,sport,key);
    bpf_map_update_elem(&addr_map_udp, &key, &value, BPF_ANY);
exit:
    return 0;
}

char LICENSE[] SEC("license") = "GPL";