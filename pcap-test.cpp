#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <stdint.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test ens33\n");
}

struct packet_hdr{
    struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
    uint8_t* data;
};

void print_mac(uint8_t *mac){
    for(int i=0;i<5;i++)
        printf("%02x:", mac[i]);
    printf("%02x\n", mac[5]);
}

void print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n", ip >> 24, (ip & 0xff0000) >> 16, (ip & 0xff00) >> 8, ip & 0xff);
}

int analyze(const u_char* packet, unsigned int length){
    if(length < 54){
        printf("packet error\n");
        return 0;
    }

    struct packet_hdr pk_hdr;
    memcpy(&(pk_hdr.eth), packet, LIBNET_ETH_H);
    memcpy(&(pk_hdr.ip), packet+LIBNET_ETH_H, LIBNET_IPV4_H);
    memcpy(&(pk_hdr.tcp), packet+LIBNET_ETH_H+LIBNET_IPV4_H, LIBNET_TCP_H);

    if(pk_hdr.ip.ip_p != 0x06){
        printf("not tcp packet\n");
        return 0;
    }

    printf("Source mac: ");
    print_mac(pk_hdr.eth.ether_shost);
    printf("Destination mac: ");
    print_mac(pk_hdr.eth.ether_dhost);


    printf("Source IP: ");
    print_ip(ntohl(pk_hdr.ip.ip_src.s_addr));
    printf("Destination IP: ");
    print_ip(ntohl(pk_hdr.ip.ip_dst.s_addr));

    printf("Source Port: %d\n", ntohs(pk_hdr.tcp.th_sport));
    printf("Destination Port: %d\n", ntohs(pk_hdr.tcp.th_dport));

    int size = 16;
    if(size > length - (LIBNET_ETH_H+LIBNET_IPV4_H+4*pk_hdr.tcp.th_off)){
        size = length - (LIBNET_ETH_H+LIBNET_IPV4_H+4*pk_hdr.tcp.th_off);
    }
    memcpy(pk_hdr.data, packet+LIBNET_ETH_H+LIBNET_IPV4_H+4*pk_hdr.tcp.th_off, size);

    printf("Data: ");
    for(int i=0;i<size;i++){
        printf("%02x ", pk_hdr.data[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("packet %d bytes captured\n", header->caplen);
        analyze(packet, header->caplen);
        printf("\n");
    }

    pcap_close(handle);
}
