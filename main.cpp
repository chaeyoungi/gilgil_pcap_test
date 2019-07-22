#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct Ethernet{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint16_t type;
};
struct IP{
    uint8_t length;
    uint8_t Sip[4];
    uint8_t Dip[4];
    uint8_t potocol;
};
struct TCP{
  uint8_t Sport[2];
  uint8_t Dport[2];
};
void print_mac(u_char* packet){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1],
           packet[2],packet[3],
            packet[4],packet[5]);
}

void print_IP(u_char* packet){
    printf("%u.%u.%u.%u\n", packet[0], packet[1], packet[2], packet[3]);
}

void print_TCP(u_char* packet){
    printf("%d\n", ((packet[0])<<8) | packet[1]);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    uint8_t* pro;
    uint8_t* T_len;
    struct Ethernet* eth;
    struct IP* ip;
    struct TCP* tcp;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n %u bytes capture\n", header->caplen);

    eth = (struct Ethernet*) packet;
    printf("Dmac : ");
    print_mac(eth->Dmac);
    printf("Smac : ");
    print_mac(eth->Smac);

    if(eth->type == ntohs(0x0800)){
        printf("type : %04x\n", eth->type);
        ip = (struct IP*) (packet + 14);
            if((ip->length & 0x0F) == 0x05){
        ip = (struct IP*)(packet + 25);
        printf("Sip : ");
        print_IP(ip->Sip);
        printf("Dip : ");
        print_IP(ip->Dip);
            }
        pro = (uint8_t*)(packet+23);
        if((*pro & 0x0F) == 0x06){
        tcp =(TCP*)(packet+34);
               printf("Sport : ");
               print_TCP(tcp->Sport);
               printf("Dport : ");
               print_TCP(tcp->Dport);

        T_len = (uint8_t*)(packet+46);
        printf("T_Hlen : %x\n", *T_len);
        packet += (14 + (ip->length*4) + sizeof(TCP));
        for (int n=0; n <=10;n++) {
            printf("%02x", packet[n]);
        }
        }
    }
    if(eth->type == ntohs(0x0806)) {
        printf("ARP\n");
    }
  }

  pcap_close(handle);
  return 0;
}
