#pragma once
#include<iostream>
#define SOCK5_WAIT_NEGOTIATE_REQUEST 0x1
#define SOCK5_WAIT_BUILD_REQUEST 0x2
#define SOCK5_TRANSMIT_DATA 0x3

#define SOCK5_KINDS_TCP 0x1
#define SOCK5_KINDS_UDP 0x2
#define SOCK5_KINDS_BIND 0x3
struct scok5_negotiate_request
{
    char version;
    char methodNum;
    char method[];
} __attribute__((packed));
struct sock5_negotiate_response
{
    char version;
    char method;
} __attribute__((packed));
struct sock5_build_request
{
    char version;
    char cmd;
    char rsv;
    char atyp;
    char addrLength; // 地址长度
    char *dstAddr;
    unsigned short dstPort;
} __attribute__((packed));
struct sock5_build_response
{
    char version;
    char rep;
    char rsv;
    char atyp;
 //   char addrLength; // 地址长度
    unsigned int bind_addr;
    unsigned short bndPort;
} __attribute__((packed));
struct sock5_udp_packet
{
char rsv[2];
char frag;
char atype;
uint32_t addr;
uint16_t dport;
char data[];
}__attribute__((packed));
