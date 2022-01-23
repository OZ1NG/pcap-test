#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "tcp.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        printf("%u bytes captured\n", header->caplen);
        // my code start
        /*
        puts("[TEST Code]");
        for(unsigned int i = 0; i < header->caplen; i++){
            if((i % 0x10) == 0){
                puts("");
            }
            printf("%x ", packet[i]);
        }
        puts("\n");
        */
        Tcp tcp((unsigned char *)packet);
        if(tcp.tcps.teth.type == 0x0800){     // IPv4
            if(tcp.tcps.tip.protocol == TCP){ // TCP
                tcp.print();
            }
        }
	}

	pcap_close(pcap);
}
