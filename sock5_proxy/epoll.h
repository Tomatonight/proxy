#pragma once
#include "channel.h"

#define MAX_EVENTS_NUM 1000
int create_listen_fd();
class epoll
{
public:
    void init();
    void loop();
    void add_fd(channel* channel_);
    void erase_fd(channel* channel_);
    int epoll_fd;
    channel_umap channels;
private:
    
    int listen_fd;
  //  channel listen_channel;
    epoll_event events[MAX_EVENTS_NUM];
    
};
