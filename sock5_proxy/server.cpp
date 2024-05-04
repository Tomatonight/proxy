#include "server.h"
void server::init()
{
    listen_fd=create_listen_fd();
    for(int i=0;i<THREAD_NUM;i++)
    {
        epolls[i]=new epoll;
        epolls[i]->init();
    }
    for(int i=0;i<THREAD_NUM;i++)
    {
        epoll* ep=epolls[i];
        threads[i]=std::move(std::thread([ep](){
            ep->loop();
        }));
    }
}
void server::loop()
{
    while(true)
    {
        int new_fd=accept(listen_fd,NULL,NULL);
        epoll* ep= epolls[epoll_index];
        epoll_index=(epoll_index+1)%THREAD_NUM;
        channel* new_channel=new channel_client(new_fd);
        ep->add_fd(new_channel);
    }
}
