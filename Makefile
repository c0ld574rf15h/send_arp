all : send_arp

send_arp : main.o arp.o
	gcc -o send_arp main.o arp.o -lpcap

arp.o : arp.c
	gcc -c -o arp.o arp.c

main.o : main.c
	gcc -c -o main.o main.c

clean : 
	rm -f send_arp *.o