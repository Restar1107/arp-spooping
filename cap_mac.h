#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void show_packet(char * packet);
void cap_mac(char * sender_ip, uint8_t cap_sender_mac[6]);