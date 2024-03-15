#include "server.h"
char *server_ip;
char *server_port;
int main(int argc, char **argv)
{
    int ch;
    while ((ch = getopt(argc, argv, "i:p:")) != -1)
    {
        switch (ch)
        {
        case 'i':
            server_ip = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        default:
            printf("fault options\n");
            exit(-1);
            break;
        }
    }
    server *ser = new server;
    ser->server_init();
    ser->loop();
    return 0;
}