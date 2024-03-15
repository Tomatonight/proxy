#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#define MAX_STRORE_IP 100
class fast_ip
{
public:
    void add(const std::string &s, uint32_t ip);
    uint32_t search(const std::string &s);
    void remove(const std::string &s);

private:
    void clear();
    bool flag = true;
    std::mutex mtx;
    std::unordered_map<std::string, uint32_t> map_1, map_2;
};