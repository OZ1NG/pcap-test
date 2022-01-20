#include <stdio.h>
#include <cstring>
#include <netinet/in.h>
#include "tcp.h"

Tcp::Tcp(unsigned char * packet){
    this->packet_data = packet;
    this->get();
}

void Tcp::get(){
    this->get_ethernet();
    this->get_ip();
    this->get_tcp();
    // Data length
    this->tcps.tdata_len = this->tcps.tip.total_length - this->tcps.tip.len - this->tcps.ttcp.len;
    this->get_data();
}

void Tcp::print(){
    this->print_ethernet();
    this->print_ip_port();
    this->print_data();
    puts("");
}

void Tcp::get_ethernet(){
    // len
    this->tcps.teth.len = 14; // static
    // dest_mac
    memcpy(this->tcps.teth.dest_mac, this->packet_data, 6);
    // src_mac
    memcpy(this->tcps.teth.src_mac, this->packet_data+6, 6);
    // type
    memcpy(this->tcps.teth.type, this->packet_data+12, 2);
}

void Tcp::get_ip(){
    unsigned char * header_addr = this->packet_data+this->tcps.teth.len;
    // len // offset = +0.5 (nibble)
    this->tcps.tip.len = ((*header_addr << 4) >> 4) * 4;
    // protocol // offset = +9 // UDP : 17 , TCP : 6
    this->tcps.tip.protocol = *(header_addr + 9);
    // src_ip // offset = +12
    memcpy(this->tcps.tip.src_ip, header_addr + 12, 4);
    // dest_ip // offset = +16
    memcpy(this->tcps.tip.dest_ip, header_addr + 16, 4);
    // Total length // offset = +2
    memcpy(&this->tcps.tip.total_length, header_addr+2, 2);
    this->tcps.tip.total_length = ntohs(this->tcps.tip.total_length); // change byte order
}

void Tcp::get_tcp(){
    unsigned char * header_addr = this->packet_data+this->tcps.teth.len+this->tcps.tip.len;
    // len // offset = +12 (nibble)
    this->tcps.ttcp.len = (*(header_addr+12) >> 4) * 4;
    // src_port // offset = +1
    memcpy(&this->tcps.ttcp.src_port, header_addr, 2);
    this->tcps.ttcp.src_port = ntohs(this->tcps.ttcp.src_port);  // change byte order
    // dest_port  // offset = +3
    memcpy(&this->tcps.ttcp.dest_port, header_addr+2, 2);
    this->tcps.ttcp.dest_port = ntohs(this->tcps.ttcp.dest_port); // change byte order
}

int Tcp::get_data(){
    if(!this->tcps.tdata_len){
        memset(this->tcps.tdata, 0, 8);
        return 0;
    }
    unsigned char * header_addr = this->packet_data+this->tcps.teth.len+this->tcps.tip.len+this->tcps.ttcp.len;
    memcpy(this->tcps.tdata, header_addr, (this->tcps.tdata_len > 8)? 8 : this->tcps.tdata_len);

    return 0;
}

void Tcp::print_ethernet(){

    //puts("[Ethernet]");
    printf("[Source MAC -> Destination MAC] = %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx -> %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
           this->tcps.teth.src_mac[0],
           this->tcps.teth.src_mac[1],
           this->tcps.teth.src_mac[2],
           this->tcps.teth.src_mac[3],
           this->tcps.teth.src_mac[4],
           this->tcps.teth.src_mac[5],
           this->tcps.teth.dest_mac[0],
           this->tcps.teth.dest_mac[1],
           this->tcps.teth.dest_mac[2],
           this->tcps.teth.dest_mac[3],
           this->tcps.teth.dest_mac[4],
           this->tcps.teth.dest_mac[5]);
}

void Tcp::print_ip_port(){

    //puts("[IP:Port]");
    printf("[Source IP:Port -> Destination IP:Port] = %hhu.%hhu.%hhu.%hhu:%u -> %hhu.%hhu.%hhu.%hhu:%u\n",
           this->tcps.tip.src_ip[0],
           this->tcps.tip.src_ip[1],
           this->tcps.tip.src_ip[2],
           this->tcps.tip.src_ip[3],
           this->tcps.ttcp.src_port,
           this->tcps.tip.dest_ip[0],
           this->tcps.tip.dest_ip[1],
           this->tcps.tip.dest_ip[2],
           this->tcps.tip.dest_ip[3],
           this->tcps.ttcp.dest_port);
}


void Tcp::print_data(){

    printf("[Data] ");
    int max = (this->tcps.tdata_len > 8)? 8 : this->tcps.tdata_len;
    for(int i = 0; i < max ; i++){
        printf("%02hhx ", this->tcps.tdata[i]);
    }
    puts("");
}

