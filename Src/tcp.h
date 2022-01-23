#ifndef TCP_H
#define TCP_H
#include <stdint.h>

enum Protocol{
    ICMP = 1,
    TCP = 6 ,
    UDP = 17
};

struct ethernet_header {
    uint8_t len;
    char dest_mac[6];
    char src_mac[6];
    uint16_t type;
};

struct ip_header {
    uint8_t len;
    uint8_t protocol;
    char src_ip[4];
    char dest_ip[4];
    uint16_t total_length;
};

struct tcp_header {
    uint8_t len;
    uint16_t src_port;
    uint16_t dest_port;
};

struct tcp_struct {
    struct ethernet_header teth;
    struct ip_header tip;
    struct tcp_header ttcp;
    uint16_t tdata_len;
    char tdata[8];
};

class Tcp
{
public:
    struct tcp_struct tcps;
    unsigned char * packet_data;
    //tcp();
    Tcp(unsigned char * packet);

    void print();
    void print_ethernet();
    void print_ip_port();
    void print_data();

private:
    void get();
    void get_ethernet();
    void get_ip();
    void get_tcp();
    int get_data();
};

#endif // TCP_H
