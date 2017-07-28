#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>

int get_mac_address(u_char mac[6], const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0){
		printf("can't get MAC Address\n");
		close(fd);
		return 0;	
	}	

	for (int i = 0; i < 6; ++i){
		mac[i] = ifr.ifr_addr.sa_data[i];
		//printf("%02x", (unsigned char)mac[i]);			
	}

	close(fd);
	return 1;
}

int get_ip_address(u_char **ip, const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in *sin;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

	if(ioctl(fd, SIOCGIFADDR, &ifr) != 0){
		printf("can't get IP Address\n");
		close(fd);
		return 0;
	}
	 
	close(fd);
	
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	inet_ntop(AF_INET, &(sin->sin_addr), *ip, 10);
	
	return 1;
}

int main(int argc, char *argv[]){
	pcap_t *handle;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct pcap_pkthdr *header;	

	struct ether_header eth;
	struct ether_arp arp;
	u_char packet[1000];
	int length = 0;

	u_char s_mac[6];
	u_char d_mac[6];
	u_char* s_ip_addr;
	u_char* d_ip_addr;
	
	struct in_addr my_addr;
	struct in_addr v_addr;	
	struct in_addr t_addr;

	if(argc < 4){
		printf("Nop!!\n");
		return -1;	
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return -2;
	}	
	
	s_ip_addr = (u_char*)malloc(sizeof(u_char) * 16);

	get_mac_address(s_mac, argv[1]);
	get_ip_address(&s_ip_addr, argv[1]);
	
		for (int i = 0; i < 6; ++i){
		printf("%02x", (unsigned char)s_mac[i]);			
	}

	inet_pton(AF_INET, s_ip_addr, &my_addr);
	inet_pton(AF_INET, argv[3], &t_addr);
	inet_pton(AF_INET, argv[2], &v_addr);
	
	printf("\nmy ip : %x\n", my_addr);
	
	//fill the ethernet header
	for(int i=0; i<6; i++){
		eth.ether_shost[i] = s_mac[i];
		eth.ether_dhost[i] = 0xff;
	}
	eth.ether_type = htons(ETHERTYPE_ARP);

	memcpy(packet, &eth, sizeof(eth));
	length += sizeof(eth);

	//fill the arp request header
	arp.arp_hrd = htons(0x0001);
	arp.arp_pro = htons(0x0800);
	arp.arp_hln = 0x06;
	arp.arp_pln = 0x04;
	arp.arp_op = htons(ARPOP_REQUEST);
	
	for(int i=0; i<6; i++){
		arp.arp_sha[i] = s_mac[i];
		arp.arp_tha[i] = 0x00;
	}
	
	printf("Victime Ip of binary %02x\n", v_addr);
	printf("Target Ip of binary %02x\n", t_addr);	
	
	memcpy(arp.arp_spa, &t_addr, sizeof(t_addr));
	memcpy(arp.arp_tpa, &v_addr, sizeof(v_addr));
	
	memcpy(packet+length, &arp, sizeof(arp));
	length += sizeof(arp);
	
	for(int i=0; i<length; i++)
		printf("%02x", packet[i]);
	
	printf("\n");

	return 0;
}
