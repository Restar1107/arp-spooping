#include "cap_mac.h"
#define MAC_ADDR_LEN 6
extern pcap_t * handle;

void show_packet(char * packet){
    for (int i = 0; i < 60; i++){
        printf("%02x", (uint8_t)packet[i]);
        if (i%16 == 15){
            printf("\n");
        }
        else if(i%8 == 7){
            printf("-");
        }
        else {
            printf(" ");
        }
    }
}

void cap_mac(char * sender_ip, uint8_t cap_sender_mac[6]){
    const uint8_t * text;
    while(1) {
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, (const u_char**)(&text)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
        // ------- DEBUG ------------------
        show_packet((char*)text);
        // ------- DEBUG ------------------

        // ------- MY_CODE ----------------
        unsigned char cap_sender_ip[INET_ADDRSTRLEN] = {0,};
        sprintf((char*)cap_sender_ip, "%u.%u.%u.%u",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
        printf("\n%02x.%02x.%02x.%02x\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
        printf("%u.%u.%u.%u\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
        if (memcmp(cap_sender_ip, sender_ip, strlen((char*)cap_sender_ip))){printf("\nother packet \n");continue;}
        else{printf(" --------------- you did it !!! ------------- \n"); break;}
        // ------- MY_CODE ----------------
        memcpy(cap_sender_mac, text+0x16, MAC_ADDR_LEN);
        printf("sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", cap_sender_mac[0], cap_sender_mac[1], cap_sender_mac[2], cap_sender_mac[3], cap_sender_mac[4], cap_sender_mac[5]);
        printf("yes it's working\n");
    }
}