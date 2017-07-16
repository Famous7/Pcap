all: sniffer

sniffer: sniffer.o
	gcc -o sniffer sniffer.o -l pcap

sniffer.o: sniffer.c
	gcc -c -o sniffer.o sniffer.c

clean:
	rm *.o sniffer
