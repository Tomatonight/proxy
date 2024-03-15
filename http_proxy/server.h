#pragma once
#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <memory.h>
#include <arpa/inet.h>
#include "channel.h"
#include "entry.h"
#include "safe_map.h"
#include"threadpool.h"
#include"fast_ip.h"
#include <map>
#include <unordered_set>
#define MAX_EVENTS 20
#define DEBUG

#ifdef DEBUG
#define debug(str) \ 
printf(str);
#endif
#ifndef DEBUG
#define debug(str) void
#endif
class server
{
public:
    void server_init();
    void loop();
    bool test_reading(int fd);
    bool test_stop(int fd);
    channel *public_channel;
    int epoll_fd;
    int public_fd;
    conn_entrys entrys;
    safe_map<int, channel *> fd_map;
    fast_ip fastip;
  //  std::mutex get_name_mtx;
    threadpool thread_pool;
private:
    std::mutex mtx_map;
    epoll_event epoll_events[MAX_EVENTS];

};