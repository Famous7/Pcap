all: send_arp

send_arp: send_arp.o
	gcc -o send_arp send_arp.o -l pcap

send_arp.o: send_arp.c
	gcc -c -o send_arp.o send_arp.c

clean:
	rm send_arp.o send_arp
