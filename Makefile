all: pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.cpp