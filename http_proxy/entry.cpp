#include "entry.h"
#include <mutex>
#include <thread>
#include "stdio.h"
int conn_entrys::search_from(int fd)
{
    std::unique_lock<std::mutex> lo(mtx);
    if (entry_map.find(fd) == entry_map.end())
    {
        return -1;
    }
    return entry_map[fd];
}
void conn_entrys::add_entry(int l, int r)
{
    std::unique_lock<std::mutex> lo(mtx);
    if (entry_map.find(l) != entry_map.end())
    {
        printf("entry add error\n");
        exit(-1);
    }
    entry_map[l] = r;
    entry_map[r] = l;
}
void conn_entrys::remove_entry(int l, int r)
{
    std::unique_lock<std::mutex> lo(mtx);
    if (entry_map.find(l) == entry_map.end() || entry_map[l] != r || entry_map[r] != l)
    {
        printf("entry remove error\n");
        exit(-1);
    }
    entry_map.erase(l);
    entry_map.erase(r);
}