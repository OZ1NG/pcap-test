#Makefile
LDLIBS += -lpcap

pcap-test: pcap-test.o tcp.o
	gcc -o pcap-test pcap-test.o tcp.o -lpcap

pcap-test.o: pcap-test.cpp
	g++ -c -o pcap-test.o pcap-test.cpp

tcp.o: tcp.cpp
	g++ -c -o tcp.o tcp.cpp

clean:
	rm -f pcap-test *.o

