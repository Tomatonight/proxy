#include "fast_ip.h"
void fast_ip::add(const std::string &s,uint32_t ip)
{
    std::unique_lock<std::mutex> l(mtx);
    if (flag)
    {
        map_1.insert({s, ip});
    }
    else
    {
        map_2.insert({s, ip});
    }
    clear();
}
uint32_t fast_ip::search(const std::string &s)
{
    std::unique_lock<std::mutex> l(mtx);
    if (flag)
    {
        if(map_1.find(s)!=map_1.end())
        {
            return map_1[s];
        }
        else if(map_2.find(s)!=map_2.end())
        {
            map_1.insert({s,map_2[s]});
            return map_1[s];
        }
        else return 0;
    }
    else
    {
        if(map_2.find(s)!=map_2.end())
        {
            return map_2[s];
        }
        else if(map_1.find(s)!=map_1.end())
        {
            map_2.insert({s,map_1[s]});
            return map_2[s];
        }
        else return 0;
    }
}
void fast_ip::clear()
{
    if (flag&&map_1.size()>MAX_STRORE_IP)
    {
        flag = false;
        map_2.clear();
    }
    else if(map_2.size()>MAX_STRORE_IP)
    {
        flag = true;
        map_1.clear();
    }
}
void fast_ip::remove(const std::string &s)
{
    std::unique_lock<std::mutex> l(mtx);
    map_1.erase(s);
    map_2.erase(s);
}