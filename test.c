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

#define SNAP_LEN 1518

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
	#define IP_RF 0x8000
	#define	IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
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
	u_char offrs;
	#define OFF(th)	(((th)->offrs & 0xf0) >> 4)	
	u_char flags;
	#define FIN	0x01
	#define SYN	0x01
	#define RST	0x01
	#define PUSH	0x01
	#define ACK	0x01
	#define URG	0x01
	#define ECE	0x01
	#define CWP	0x01
	#define FLAGS	(FIN|SYN|RST|PUSH|ACK|URG|ECE|CWP)
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
	u_char flag;
	int ip_hl;

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

	printf("\nIPv4 Header info >>>\n");	

	printf("IP version : %d\n", (ip->vhl) >> 4);
	
	ip_hl = (ip->vhl & 0x0f) * 4;
	printf("Header Length : %d\n", ip_hl);
	printf("Type of Service : %d\n", (ip->tos));
	printf("Total Length : %d\n", (ip->len));
	printf("Identification : %d\n", (ip->id));
	
	flag = (ip->off) & 0xe000;

	printf("Flag : %x\n", flag);		

	switch(flag){
		case IP_RF:
			printf("X[%d]\n", flag);
			break;
		case IP_DF:		
			printf("DF[%d]\n", flag);
			break;
		case IP_MF:		
			printf("MF[%d]\n", flag);
			break;
	}
		
	printf("\nFagement Offset : %d\n", (ip->off) & 0x1fff);
	printf("Time To Live : %d\n", ip->ttl);
	printf("Protocol : %d\n", ip->pro);
	printf("Check Sum : %d\n", ip->sum);
	printf("Source Addr : %s\n", inet_ntoa(ip->ip_src));
	printf("Destination Addr : %s\n", inet_ntoa(ip->ip_dst));

	//print TCP Header

	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + ip_hl);

	printf("Source Port : %d\n", ntohs(tcp->sport));
	printf("Destination Port : %d\n", ntohs(tcp->dport));
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
		printf("Jacked a packet with length of [%d]\n", header->len);
		
		pcap_loop(handle, 1, get_packet, NULL);

	
		/* And close the session */
		pcap_close(handle);
		return(0);
	 }
