#pragma once
#include<thread>
#include<mutex>
#include<list>
#include<vector>
#include<functional>
#include<condition_variable>
#define MAX_POOL_SIZE 30
class threadpool
{
    public:
    void push_task(std::function<void()> fcn);
    void init();
    ~threadpool();
    std::vector<std::thread> threads;
    std::list<std::function<void()>> tasks;
    std::mutex mtx;
    std::condition_variable cv;
};