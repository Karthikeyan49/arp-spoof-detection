#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <net/ethernet.h>

int main()
{
    char *device_name;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pack_desc;
    const __u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;
    __u_char *hard_ptr;

    device_name = pcap_lookupdev(error);
    if (device_name == NULL)
    {
        printf("%s\n", error);
        return -1;
    }
    else
    {
        printf("Device: %s\n", device_name);
    }

    pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    if (pack_desc == NULL)
    {
        printf("%s\n", error);
        return -1;
    }

    while (1)
    {
        packet = pcap_next(pack_desc, &header);

        if (packet == NULL)
        {
            printf("error: cannot capture packet");
            return -1;
        }
        else
        {
            printf("received a packet with length %d\n", header.len);
            printf("received at %s\n", ctime((const time_t *)&header.ts.tv_sec));
            printf("Ethernet Header Length: %d\n", ETHER_HDR_LEN);
            eptr = (struct ether_header *)packet;
            if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
            {
                printf("Ethernet type hex: 0x%x; dec: %d is an IP Packet\n", ETHERTYPE_IP, ETHERTYPE_IP);
            }
            else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
            {
                printf("Ethernet type hex: 0x%x; dec: %d is an ARP Packet\n", ETHERTYPE_ARP, ETHERTYPE_ARP);
            }
            else
            {
                printf("Ethernet type hex: 0x%x; dec: %d is not an IP or ARP packet, so quitting...\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
                continue;
            }
            hard_ptr = eptr->ether_dhost;
            int i = ETHER_ADDR_LEN;
            printf("Destination Address: ");
            do
            {
                printf("%s%x", (i == ETHER_ADDR_LEN) ? "" : ":", *hard_ptr++);
            } while (--i > 0);

            printf("\n");
            hard_ptr = eptr->ether_shost;
            i = ETHER_ADDR_LEN;
            printf("Source Address: ");
            do
            {
                printf("%s%x", (i == ETHER_ADDR_LEN) ? "" : ":", *hard_ptr++);
            } while (--i > 0);
            printf("\n");
        }
    }
    return 0;
}
