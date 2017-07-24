#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define ETHERTYPE_IP 0x0800

struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip{
	u_char vhl;
	u_char tos;
	u_short	len;
	u_short	id;
	u_short off;
	u_char ttl;
	u_char pro;
	u_short sum;
	struct in_addr ip_src, ip_dst;
	
};

struct sniff_tcp{
	u_short sport;
	u_short dport;
	u_int seq;
	u_int ack;
	u_char hlrs;	
	u_char flags;
	u_short win;
	u_short sum;
	u_short urp;
};

void get_packet(const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;
	int ip_hl;
	int tcp_hl;
	int pay_l;
	char sip[16];
	char dip[16];


	printf("Pacekt #[%d]\n", count);	
	//print Ehternet Header
	ethernet = (struct sniff_ethernet *)(packet);

	printf("Ethernet Source Addr >> ");	
	for(int i=0; i<6; i++){
		printf("%02x", (ethernet->ether_shost[i]));
		if(i != 5)
			printf(":");
			
	}
		
	printf("\nEthernet Destination Addr >> ");		
	for(int i=0; i<6; i++){
		printf("%02x", (ethernet->ether_dhost[i]));
		if(i != 5)
			printf(":");
			
	}		

	if(ntohs(ethernet->ether_type) != ETHERTYPE_IP){
		printf("\nPacket #[%d] is not include IPv4 Header This Type is [%x]\n",count++, ntohs(ethernet->ether_type));
		return;	
	}

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	
	//print IP Header
	ip_hl = (ip->vhl & 0x0f) * 4;
	printf("\n\nIP Header size : %dBytes\n", ip_hl);

	inet_ntop(AF_INET, &(ip->ip_src), sip, sizeof(sip));
	inet_ntop(AF_INET, &(ip->ip_dst), dip, sizeof(dip));

	printf("Source IP Addr : %s\n", sip);
	printf("Destination IP Addr : %s\n", dip);

	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + ip_hl);

	if(ip->pro != 0x06){
		printf("\nPacket #[%d] is not include TCP Header This Type is [%x]\n", count++, ip->pro);	
		return;
	}

	count++;	
	
	//print TCP Header
	tcp_hl = ((tcp->hlrs & 0xf0) >> 4) * 4;

	printf("\nTCP Header Length : %dBytes\n", tcp_hl);
	printf("Source TCP Port : %d\n", ntohs(tcp->sport));
	printf("Destination TCP Port : %d\n", ntohs(tcp->dport));

	//print Payload
	payload = (u_char *)(packet + SIZE_ETHERNET + ip_hl + tcp_hl);
	pay_l = ntohs(ip->len) - (ip_hl + tcp_hl);

	if(pay_l > 0){
		printf("\nPayload Size : %dBytes\n\n", pay_l);
			for(int i=0; i<pay_l; i++){
				if(isprint(payload[i]))
					printf("%c", payload[i]);
				else if(payload[i] == '\r' || payload[i] == '\n')
					printf("%c", payload[i]);
				else
					printf(".");
			}
	}
	else{
		printf("\nNo Data...\n");
	}
}


int main(int argc, char *argv[]){
		pcap_t *handle;			/* Session handle */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		if(argc < 2){
			printf("./sniffer interface_name \n");
			exit(0);
		}

		/* Open the session in promiscuous mode */
		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
			return(2);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", argv[1]);
			exit(EXIT_FAILURE);
		}

		while(1){
			if(pcap_next_ex(handle, &header, &packet)){
				get_packet(header, packet);
				printf("\n---------------------------------------------------------------------\n\n");			
			}
			else{
				printf("Can't Capture The Packets...\n");
			}
		}

		/* And close the session */
		pcap_close(handle);
		return(0);
}
