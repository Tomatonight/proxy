#include "threadpool.h"
void threadpool::push_task(std::function<void()> fcn)
{
    std::unique_lock<std::mutex> l(mtx);
    tasks.push_back(fcn);
    cv.notify_one();
}
threadpool::~threadpool()
{
for (int i = 0; i < MAX_POOL_SIZE; i++)
{
    threads[i].detach();
}
}
void threadpool::init()
{
    threads.resize(MAX_POOL_SIZE);
    for (int i = 0; i < MAX_POOL_SIZE; i++)
    {
        threads[i] = std::move(std::thread([this]()
                                           {
        while(true)
        {
            std::function<void()> task;
        {
        std::unique_lock<std::mutex> l(mtx);
        while(tasks.empty())
        {
            cv.wait(l);
        } 
        task=tasks.front();
        tasks.pop_front();
        }
        task();
        }

        }));
    }
}