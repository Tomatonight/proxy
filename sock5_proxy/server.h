#include"epoll.h"
#include<thread>
#include<mutex>
#define THREAD_NUM 1
class server
{
    public:
    void init();
    void loop();
    private:
    int listen_fd;
    int epoll_index=0;
    epoll* epolls[THREAD_NUM];
    std::thread threads[THREAD_NUM];
};