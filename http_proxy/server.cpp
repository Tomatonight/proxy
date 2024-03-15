#include "server.h"
#include <signal.h>
#include <sys/types.h>
#include <pthread.h>
#include "channel.h"
#include <sys/socket.h>
extern char* server_ip;
extern char* server_port;
void server::server_init()
{
    thread_pool.init();
    signal(SIGPIPE, SIG_IGN);
    epoll_fd = epoll_create(10);
    if (epoll_fd < 0)
    {
        printf("create epollfd err\n");
        exit(-1);
    }
    public_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (public_fd < 0)
    {
        printf("public port init err\n");
        exit(-1);
    }
    sockaddr_in addr_public;
    memset(&addr_public, 0, sizeof(sockaddr));
    addr_public.sin_addr.s_addr = inet_addr(server_ip); // htonl(INADDR_ANY);
    addr_public.sin_port = htons(atoi(server_port));
    addr_public.sin_family = AF_INET;
    int opt = 1;
    setsockopt(public_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    if (bind(public_fd, (sockaddr *)&addr_public, sizeof(sockaddr)) < 0)
    {
        printf("public bind err\n");
        exit(-1);
    }
    public_channel = new channel_public;
    public_channel->fd = public_fd;
    public_channel->event.data.fd = public_fd;
    public_channel->event.events = EPOLLIN | EPOLLERR | EPOLLONESHOT;
    if (listen(public_fd, 10))
    {
        printf("listen err\n");
        exit(-1);
    }
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, public_fd, &public_channel->event);
    fd_map[public_fd] = public_channel;
    // debug("server init done\n");
}
void server::loop()
{
    while (true)
    {
        //  debug("loop\n");
        int cnt = epoll_wait(epoll_fd, epoll_events, MAX_EVENTS - 1, -1);
        for (int i = 0; i < cnt; i++)
        {
            int fd = epoll_events[i].data.fd;
            if (fd != public_fd)
            {
                if (fd_map.find(fd) == fd_map.end())
                {
                    // debug("over \n");
                    continue;
                }
            }
            if (fd_map.find(fd) == fd_map.end())
                continue;
            channel *con = fd_map[fd];
            if (test_stop(fd))
            {
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &con->event);
                continue;
            }
            if (epoll_events[i].events & EPOLLERR || epoll_events[i].events & EPOLLHUP)
            {
                if (test_reading(fd))
                {
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &con->event);
                    continue;
                }
                con->stop_read = true;
                con->process_error(this);
            }
            else if (epoll_events[i].events & EPOLLRDHUP)
            {
                if (test_reading(fd))
                {
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &con->event);
                    continue;
                }
                con->stop_read = true;
                con->process_rdhub(this);
            }
            else if (epoll_events[i].events & EPOLLIN)
            {
                //  if(con->conn_state==CHANNEL_CONN_NORMAL_WAIT_MSG)
                //   {
                //   std::thread t([=](){con->process_read(this);});
                //   t.detach();
                con->doing_read = true;
                thread_pool.push_task([=]()
                                      { con->process_read(this);
                                      
                                      });
                //  }
                //   else
                //  {
                //   con->process_read(this);
                //   }
            }
        }
    }
}
bool server::test_stop(int fd)
{
    int peer_fd = entrys.search_from(fd);
    if (peer_fd < 0)
        return false;
    channel *per_conn = fd_map[peer_fd];
    if (per_conn->stop_read)
        return true;
    return false;
}
bool server::test_reading(int fd)
{
    int peer_fd = entrys.search_from(fd);
    if (peer_fd < 0)
        return false;
    channel *per_conn = fd_map[peer_fd];
    if (per_conn->doing_read)
        return true;
    return false;
}