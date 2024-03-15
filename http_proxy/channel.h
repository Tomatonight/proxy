#pragma once
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include<algorithm>

#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include<atomic>
class server;
#define CHANNEL_CONN_NORMAL_WAIT_MSG 0x1
#define CHANNEL_CONN_NORMAL_WORK 0x2

class channel
{
public:
    int fd;
    epoll_event event;
    int conn_state = 0;
    std::atomic<bool> doing_read=false; 
    std::atomic<bool> peer_recv_fin=false;
    std::atomic<bool> stop_read=false;
    virtual void process_read(server *){};
    virtual void process_error(server *){};
    virtual void process_rdhub(server *){}; // recv fin
};
class channel_public : public channel
{
    void process_read(server *);
    void process_error(server *);
};

class channel_conn_normal : public channel
{
public:
    void parse_recv_msg(server*);
    void transmit_data(server *server);
    void clear_this_and_peer_fd(server *server);
    void clear_this_fd(server* server);
    void process_read(server *);
    void process_error(server *);
    void process_rdhub(server *);
    int pfd[2];
};
void set_no_block(int);
