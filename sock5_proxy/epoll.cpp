#include "epoll.h"
#include <memory.h>
extern char *server_ip;
extern char *server_port;
int create_listen_fd()
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0)
    {
        printf("create listen fd err\n");
        exit(-1);
    }
    sockaddr_in addr_server;
    memset(&addr_server, 0, sizeof(sockaddr));
    addr_server.sin_family = AF_INET;
    addr_server.sin_addr.s_addr = inet_addr(server_ip);
    addr_server.sin_port = htons(atoi(server_port));
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    if (bind(listen_fd, (sockaddr *)&addr_server, sizeof(sockaddr)) < 0)
    {
        printf("bind listen fd err\n");
        exit(-1);
    }
    if (listen(listen_fd, 100) < 0)
    {
        printf("listen listen fd err\n");
        exit(-1);
    }
    return listen_fd;
}
void epoll::init()
{
    epoll_fd = epoll_create(1);
    if (epoll_fd < 0)
    {
        printf("create epoll fd err\n");
        exit(-1);
    }
}
void epoll::add_fd(channel *channel_)
{
  //  printf("add %d\n", channel_->fd);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel_->fd, &channel_->events);
    channels.add(channel_);
}
void epoll::erase_fd(channel *channel_)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, channel_->fd, NULL);
    channels.erase(channel_);
}
void epoll::loop()
{
    while (true)
    {
        //      printf("start loop \n");
        int cnt = epoll_wait(epoll_fd, events, MAX_EVENTS_NUM, -1);
        for (int i = 0; i < cnt; i++)
        {
            epoll_event *event = events + i;
            channel *channel_ = channels.get(event->data.fd);
            if (!channel_)
            {
                continue;
            }
            if (event->events & EPOLLERR || events->events & EPOLLHUP)
            {
                channel_->process_err(this);
            }
            else if (event->events & EPOLLIN)
            {
                channel_->process_read(this);
            }
        }
    }
}