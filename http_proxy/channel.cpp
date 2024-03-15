#include "channel.h"
#include "server.h"
#include <netdb.h>
#include <regex>
void set_no_block(int fd)
{
    int opts;
    opts = fcntl(fd, F_GETFL);
    if (opts < 0)
    {
        printf("fcntl err\n");
    }
    opts = opts | O_NONBLOCK;
    if (fcntl(fd, F_SETFL, opts) < 0)
    {
        printf("set no block\n");
    }
}
void channel_public::process_read(server *server)
{
    //  debug("public recv\n");
    int new_fd = accept(fd, NULL, NULL);
    // set_no_block(new_fd);
    channel *new_channel = new channel_conn_normal;
    new_channel->fd = new_fd;
    new_channel->event.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT;
    new_channel->event.data.fd = new_fd;
    new_channel->conn_state = CHANNEL_CONN_NORMAL_WAIT_MSG;
    server->fd_map[new_fd] = new_channel;
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, new_fd, &new_channel->event);
    epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}
void channel_public::process_error(server *)
{
    printf("public conn err\n");
    exit(-1);
}
void channel_conn_normal::process_read(server *server)
{
    //   debug("normal recv\n");
    switch (conn_state)
    {
    case CHANNEL_CONN_NORMAL_WAIT_MSG:
        parse_recv_msg(server);
        break;
    case CHANNEL_CONN_NORMAL_WORK:
        //  printf("transmit\n");
        transmit_data(server);
        break;
    default:
        printf("process read err\n");
        break;
    }
}
void channel_conn_normal::process_error(server *server)
{
    // debug("normal err\n");
    switch (conn_state)
    {
    case CHANNEL_CONN_NORMAL_WAIT_MSG:
        clear_this_fd(server);
        break;
    case CHANNEL_CONN_NORMAL_WORK:
        clear_this_and_peer_fd(server);
        break;
    default:
        printf("unknown conn state\n");
        break;
    }
}
void channel_conn_normal::process_rdhub(server *server)
{
    //  debug("normal rdhub\n");
    switch (conn_state)
    {
    case CHANNEL_CONN_NORMAL_WAIT_MSG:
        clear_this_fd(server);
        break;
    case CHANNEL_CONN_NORMAL_WORK:
    {
        if (peer_recv_fin = true)
        {
            clear_this_and_peer_fd(server);
            return;
        }
        channel *peer_conn = server->fd_map[server->entrys.search_from(fd)];
        peer_conn->peer_recv_fin = true;
        stop_read = false;
        break;
    }
    default:
        printf("err conn_stat\n");
        break;
    }
}
void channel_conn_normal::parse_recv_msg(server *server)
{
    //  printf("parse msg\n");
    // std::unique_lock<std::mutex> l(server->get_name_mtx);
    //  getaddrinfo()
    char buffer[2048] = {0};
    int re = read(fd, buffer, 2047);
    if (re <= 0 || re >= 2047)
    {
        clear_this_fd(server);
        return;
    }
    // CONNECT www.baidu.com:80 HTTP/1.1
    std::regex reg("CONNECT[ ]*([^:]*):([0-9]*)");
    std::smatch match;
    std::string str(std::move(buffer));
    std::string url, port;
    if (std::regex_search(str, match, reg))
    {
        url = match[1];
        port = match[2];
    }
    else
    {
        clear_this_fd(server);
        return;
    }
    uint32_t fast_ip = server->fastip.search(url);
    uint32_t ip = 0;
    if (fast_ip != 0)
    {
        // printf("find fast %s \n", url.data());
        ip = fast_ip;
    }
    //  struct hostent *hptr;
    struct addrinfo hints;
    struct addrinfo *res = NULL, *cur = NULL;
    memset(&hints, 0, sizeof(struct addrinfo));
    if (!fast_ip)
    {
        hints.ai_family = AF_INET;   /* Allow IPv4 */
        hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(url.data(), NULL, &hints, &res) != 0)
        {
            char *buf = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write(fd, buf, strlen(buf));
            clear_this_fd(server);
            return;
        }
        cur = res;
        ip = ((struct sockaddr_in *)cur->ai_addr)->sin_addr.s_addr;
    }
    uint16_t port_ = atoi(port.data());
    sockaddr_in addr_dest;
    memset(&addr_dest, 0, sizeof(sockaddr));
    addr_dest.sin_family = AF_INET;
    addr_dest.sin_port = htons(port_);
    addr_dest.sin_addr.s_addr = ip;
    int new_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (new_fd < 0)
    {
        freeaddrinfo(res);
        const char *buf = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write(fd, buf, strlen(buf));
        close(new_fd);
        clear_this_fd(server);
        return;
    }
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    bool success = false;

    if (fast_ip)
    {
        if (connect(new_fd, (sockaddr *)&addr_dest, sizeof(sockaddr)) >= 0)
            success = true;
    }
    else
    {
        for (int cnt = 0; cur != NULL; cur = cur->ai_next, cnt++)
        {

            if (cnt > 2)
                break;
            addr_dest.sin_addr.s_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr.s_addr;
            if (connect(new_fd, (sockaddr *)&addr_dest, sizeof(sockaddr)) < 0)
                continue;
            else
            {
                success = true;
                break;
            }
        }
    }
    if (!fast_ip)
        freeaddrinfo(res);
    if (!success)
    {
        //  printf("create new fd err %s %s %s\n%s\n", url.data(), inet_ntoa(*(struct in_addr *)ip), port.data(), buffer);
        if (fast_ip)
            server->fastip.remove(url);
        const char *buf = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write(fd, buf, strlen(buf));
        close(new_fd);
        clear_this_fd(server);
        return;
    }
    if (!fast_ip)
        server->fastip.add(url, ip);
    const char *buf = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int ret = write(fd, buf, strlen(buf));
    conn_state = CHANNEL_CONN_NORMAL_WORK;
    channel *new_channel = new channel_conn_normal;
    new_channel->event.events = EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLONESHOT | EPOLLRDHUP;
    new_channel->event.data.fd = new_fd;
    new_channel->fd = new_fd;
    new_channel->conn_state = CHANNEL_CONN_NORMAL_WORK;
    server->fd_map[new_fd] = new_channel;
    server->entrys.add_entry(fd, new_fd);
    pipe(pfd);
    pipe(((channel_conn_normal *)new_channel)->pfd);
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, new_fd, &new_channel->event);
    epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}
void channel_conn_normal::clear_this_and_peer_fd(server *server)
{
    //  debug("clear two conn\n");
    int peer_fd = server->entrys.search_from(fd);
    epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, peer_fd, NULL);
    close(fd);
    close(peer_fd);
    server->entrys.remove_entry(fd, peer_fd);
    server->fd_map.erase(fd);
    channel *con_peer = server->fd_map[peer_fd];
    close(pfd[0]);
    close(pfd[1]);
    close(((channel_conn_normal *)con_peer)->pfd[0]);
    close(((channel_conn_normal *)con_peer)->pfd[1]);
    server->fd_map.erase(peer_fd);
    delete con_peer;
    delete this;
}
void channel_conn_normal::transmit_data(server *server)
{
    // debug("trasmit data\n");
    int peer_fd = server->entrys.search_from(fd);
    if (peer_fd < 0)
    {
        printf("transmit peer fd err\n");
    }
    int re = splice(fd, NULL, pfd[1], NULL, 65535, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (re > 0)
    {
        splice(pfd[0], NULL, peer_fd, NULL, re, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    }
    else if (re <= 0)
        return;
    // printf("transmit %d\n", re);
    doing_read = false;
    epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}
void channel_conn_normal::clear_this_fd(server *server)
{
    //  debug("clear this fd\n");
    epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
    server->fd_map.erase(fd);
    delete this;
}