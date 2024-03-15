#pragma once
#include <map>
#include <mutex>
#include <unordered_set>
template <typename T1, typename T2>
class safe_map
{
public:
    inline T2 &operator[](T1 t)
    {
        std::unique_lock<std::mutex> l(mtx);
        return maps[t];
    }
    inline void erase(T1 t)
    {
        std::unique_lock<std::mutex> l(mtx);
        maps.erase(t);
    }
    inline typename std::map<T1, T2>::iterator find(T1 t)
    {
        std::unique_lock<std::mutex> l(mtx);
        return maps.find(t);
    }
    inline typename std::map<T1, T2>::iterator end()
    {
        std::unique_lock<std::mutex> l(mtx);
        return maps.end();
    }
    std::mutex mtx;
    std::map<T1, T2> maps;
};
template <typename T>
class safe_unordered_set
{
public:
    inline bool test_in(T t)
    {
        std::lock_guard<std::mutex> l(mtx);
        return sets.find(t) != sets.end();
    }
    inline void add(T t)
    {
        std::lock_guard<std::mutex> l(mtx);
        if (sets.find(t) != sets.end())
        {
            printf("unordered_set add err\n");
        }
        sets.insert(t);
    }
    void remove(T t)
    {
        std::lock_guard<std::mutex> l(mtx);
        sets.erase(t);
    }

private:
    std::unordered_set<T> sets;
    std::mutex mtx;
};