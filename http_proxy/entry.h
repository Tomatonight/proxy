#pragma once
#include <map>
#include<mutex>
#include "channel.h"
struct conn_entry
{
public:
    int left_fd;
    int right_fd;
};
struct conn_entrys
{
    int search_from(int);
    void add_entry(int,int);
    void remove_entry(int,int);
private:
    std::mutex mtx;
    std::map<int, int> entry_map;
};
