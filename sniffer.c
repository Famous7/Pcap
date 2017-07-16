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

void
get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;
	int ip_hl;
	int tcp_hl;
	int pay_l;

	printf("Pacekt #[%d]\n", count++);	
	
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

	//print IP Header
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	
	ip_hl = (ip->vhl & 0x0f) * 4;
	
	printf("\nSource Addr : %s\n", inet_ntoa(ip->ip_src));
	printf("Destination Addr : %s\n", inet_ntoa(ip->ip_dst));

	//print TCP Header

	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + ip_hl);

	printf("Source Port : %d\n", ntohs(tcp->sport));
	printf("Destination Port : %d\n", ntohs(tcp->dport));

	tcp_hl = ((tcp->hlrs & 0xf0) >> 4) * 4;
	printf("TCP Header Length : %dBytes", tcp_hl);

	payload = (u_char *)(packet + SIZE_ETHERNET + ip_hl + tcp_hl);
	pay_l = ntohs(ip->len) - (ip_hl + tcp_hl);

	if(pay_l > 0){
		printf("\nPayload Size : %dBytes\n", pay_l);
		if(strncmp(payload, "GET", 3) | strncmp(payload, "POST", 4) | strncmp(payload, "HTTP", 4) == 0){
			for(int i=0; i<pay_l; i++){
				if(isprint(payload[i]))
					printf("%c", payload[i]);
				else
					printf(".");
			}
		}
		else {
			for(int i=0; i<pay_l; i++){
				printf("%02x", payload[i]);
			}		
		}
	}

	printf("\n\n---------------------------------------------------------------------\n\n");
}


int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */
		int flag = 0;

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}


		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr	
			(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr
			(handle));
			return(2);
		}
		/* Grab a packet */
		flag = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		
		pcap_loop(handle, 0, get_packet, NULL);

	
		/* And close the session */
		pcap_close(handle);
		return(0);
	 }
