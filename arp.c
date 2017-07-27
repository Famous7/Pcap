#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

int get_mac_address(char mac[6], const char *dev){
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
		printf("%02x", (unsigned char)mac[i]);			
	}
	
	printf("\n");	
	close(fd);
	return 1;
}

int get_ip_address(char *ip, const char *dev){
	struct ifreq ifr;
	char ip2[16];
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

	/*for(int i=2; i<6; i++){
		printf("%d", ifr.ifr_addr.sa_data[i]);
		if(i != 5)
			printf(".");
	}*/
	
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	
	//printf("%02x\n", sin->sin_addr);
	
	inet_ntop(AF_INET, &(sin->sin_addr), ip2, sizeof(ip2));
	printf("%s\n", ip2);
	
	return 1;
}

int main(int argc, char *argv[]){
	char macaddr[6];
	char ip[32];
	if(argc < 2){
		printf("Nop!!\n");
		return -1;	
	}

	get_mac_address(macaddr, argv[1]);
	get_ip_address(ip, argv[1]);

	return 0;
}
