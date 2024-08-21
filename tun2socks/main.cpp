#include"tun2socks.h"
int main()
{
    tun2socks* client=new tun2socks;
    client->init();
    client->loop();
    return 0;
}