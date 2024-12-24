#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;        /* version << 4 | header length >> 2 */
	u_char ip_tos;        /* type of service */
	u_short ip_len;       /* total length */
	u_short ip_id;        /* identification */
	u_short ip_off;       /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* don't fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	u_char ip_ttl;        /* time to live */
	u_char ip_p;          /* protocol */
	u_short ip_sum;       /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)        (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;    /* source port */
	u_short th_dport;    /* destination port */
	tcp_seq th_seq;        /* sequence number */
	tcp_seq th_ack;        /* acknowledgement number */
	u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;        /* window */
	u_short th_sum;        /* checksum */
	u_short th_urp;        /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    
    // Print Ethernet addresses
    printf("\nEthernet Header:\n");
    printf("   Source MAC: ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", ethernet->ether_shost[i]);
        if(i != ETHER_ADDR_LEN - 1) printf(":");
    }

    printf("\n   Destination MAC: ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", ethernet->ether_dhost[i]);
        if(i != ETHER_ADDR_LEN - 1) printf(":");
    }

    // Print IP details
    printf("\nIP Header:\n");
    printf("   From IP: %s\n", inet_ntoa(ip->ip_src));
    printf("   To IP: %s\n", inet_ntoa(ip->ip_dst));

    // Check if the packet is using TCP
    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;

        // Print TCP details
        printf("\nTCP Header:\n");
        printf("   From Port: %d\n", ntohs(tcp->th_sport));
        printf("   To Port: %d\n", ntohs(tcp->th_dport));
        printf("   Sequence Number: %u\n", ntohl(tcp->th_seq));
        printf("   Acknowledgment Number: %u\n", ntohl(tcp->th_ack));
    }

    printf("\nPacket Length: %d bytes\n", header->len);

}


void print_help() {
    printf("Usage: ./sniffer [options]\n");
    printf("Options:\n");
    printf("  -d <device>    Specify the device to capture packets\n");
    printf("  -p <port>      Specify the port to filter\n");
    printf("  -h             Show this help message\n");
}

int main(int argc, char *argv[]) {
    char *dev = NULL;
    char filter_exp[64] = "";
    int opt;

    // get flags
    while ((opt = getopt(argc, argv, "d:p:h")) != -1) {
        switch (opt) {
            case 'd':
                dev = optarg;
                break;
            case 'p':
                snprintf(filter_exp, sizeof(filter_exp), "port %s", optarg);
                break;
            case 'h':
                print_help();
                return 0;
            default:
                print_help();
                return 1;
        }
    }

    if (!dev) {
        char errbuf[PCAP_ERRBUF_SIZE];
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 2;
        }
    }

    printf("Device: %s\n", dev);
    printf("Filter: %s\n", filter_exp[0] ? filter_exp : "None");

    // Open the device for sniffing
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return 2;
    }

    // Compile and apply the filter
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    if (filter_exp[0] && pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (filter_exp[0] && pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

