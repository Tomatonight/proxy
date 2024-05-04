#include "server.h"
#include <getopt.h>
char *server_ip;
char *server_port;
int main(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "i:p:")) != -1)
    {
        switch (c)
        {
        case 'i':
            server_ip = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        default:
            printf("err input %s\n", optarg);
            exit(-1);
        }
    }
    server *ser = new server;
    ser->init();
    ser->loop();
    return 0;
};