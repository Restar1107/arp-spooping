#include "ethhdr.h"
#include "arphdr.h"
#include <pcap.h>

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
void send_arp_packet(EthArpPacket& packet, char sender_ip[INET_ADDRSTRLEN], char target_ip[INET_ADDRSTRLEN], uint8_t src_mac[6]);
void send_arp_packet(EthArpPacket& packet, char sender_ip[INET_ADDRSTRLEN]);