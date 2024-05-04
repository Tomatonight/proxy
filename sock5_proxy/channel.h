#pragma once
#include "msg.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unordered_map>
class epoll;
class channel
{
public:
    int fd;
    channel *peer_channel = NULL;
    epoll_event events;
    int state;
    int proxy_kind;
    //int pfd[2];

    sockaddr_in client_addr;
    virtual void process_read(epoll *ep) = 0;
    virtual void process_err(epoll *ep) = 0;
    virtual void process_rdhub(epoll *ep) = 0;

};
class channel_client : public channel
{
public:
    channel_client(int fd_)
    {

        fd = fd_;
        events.data.fd = fd_;
        state = SOCK5_WAIT_NEGOTIATE_REQUEST;
        events.events = EPOLLIN | EPOLLERR | EPOLLHUP;

    }
    void process_read(epoll *ep);
    void process_err(epoll *ep);
    void process_rdhub(epoll *ep);

private:
    void process_read_wait(epoll *ep);
    void process_read_build(epoll *ep);
    void process_read_transmit(epoll *ep);
};

class channel_transmit : public channel
{
public:
    channel_transmit(int fd_, int kind)
    {

        fd = fd_;
        events.data.fd = fd_;
        proxy_kind = kind;
        events.events = EPOLLIN | EPOLLERR | EPOLLHUP;

    }
    void process_read(epoll *ep);
    void process_err(epoll *ep);
    void process_rdhub(epoll *ep);
};
class channel_umap
{
public:
    inline channel *get(int fd)
    {
        if (umap.find(fd) == umap.end())
        {
            return nullptr;
        }
        return umap[fd];
    }
    inline void erase(channel *channel_)
    {
        if (umap.find(channel_->fd) == umap.end())
        {
            printf("err erase \n");
        }
        umap.erase(channel_->fd);
    }
    inline void add(channel *channel_)
    {
        if (umap.find(channel_->fd) != umap.end())
        {
            printf("err add \n");
        }
        umap[channel_->fd] = channel_;
    }

private:
    std::unordered_map<int, channel *> umap;
};
int connect_by_hostname(char *, uint16_t dport, int *error);
int tcp_connect(uint32_t ip, uint16_t port, int timeout);
int create_udp_socket(sockaddr_in *addr);