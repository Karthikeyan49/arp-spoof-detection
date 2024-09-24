#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <net/ethernet.h>

#include <unistd.h>

#define ARP_REQUEST 1  // ARP Request
#define ARP_RESPONSE 2 // ARP Response

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr
{
    uint16_t htype;        // Hardware type
    uint16_t ptype;        // Protocol type
    uint8_t hlen;          // Hardware address Lenght (MAC)
    uint8_t plen;          // Protocol address length
    uint16_t opcode;       // Operation code (request or response)
    uint8_t sender_mac[6]; // Sender hardware address
    uint8_t sender_ip[4];  // Sender IP address
    uint8_t target_mac[6]; // Target MAC address
    uint8_t target_ip[4];  // Target IP address
};

char* alert_spoof(uint8_t ip[4], uint8_t mac[6])
{   
    printf("\nspoof detcted...... on mac-");
    for (int i = 0; i < 6; i++)
        {
            printf("%02X%s", mac[i], (i != 5) ? ":" : "");
        }
    printf(" and on ip-  ");
    for (int i = 0; i < 4; i++)
        {
            printf("%d%s", ip[i], (i != 3) ? ":" : "");
        }
    printf("\n");
    exit(1);
}

int print_available_interfaces()
{
        char error[PCAP_ERRBUF_SIZE]; // to get error with size 256bits
        pcap_if_t *interface, *temp;  // it's a structure contains details of iterfaces
        int i = 0;

        if (pcap_findalldevs(&interface, error) == -1)
        { // function used to findall devices and return the details in inetrface vailable
            printf("cannot acquire the device\n");
            return -1;
        }
        printf("the available devices are\n");
        for (temp = interface; temp; temp = temp->next)
        {
            printf("#%d: %s\n", ++i, temp->name);
        }
        exit(1);
}

void print_version()
{
        printf("\nARP spoofing detector v0.1\n");
        printf("\nThis tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing ARP spoofing attack. \n");
        exit(1);
}

void print_help(char *bin)
{
        printf("\n Available devices: ");
        printf("------------------------------------------");
        printf("-h or --help:\t\t Print this help text.\n");
        printf("-l or --lookup:\t\t Print the available ineterfaces.\n");
        printf("-i or --ineterface:\t\t Print this interface to sniff on.\n");
        printf("-v or --version:\t\t Print this version information.\n");
        printf("------------------------------------------");
        printf("\n Usage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", bin);
        exit(1);
}

char* print_hardware_address(uint8_t mac[6])
{
        for (int i = 0; i < 6; i++)
        {
            printf("%02X%s", mac[i], (i != 5) ? ":" : "");
        }
}
char* print_ip_address(uint8_t ip[4])
{
        for (int i = 0; i < 4; i++)
        {
            printf("%d%s", ip[i], (i != 3) ? ":" : "");
        }
}
int sniff_arp(char *device_name)
{
        char error[PCAP_ERRBUF_SIZE];
        pcap_t *pack_desc; //file discriptor -linux file interface -->wlo1-file descriptor 
        const __u_char *packet; //packet ip header arp tcp arp header specfic detail
        struct pcap_pkthdr header; //tcp ip arp
        //ts,len
        struct ether_header *eptr; // net/ethernet.h
        //shost,dhost,type
        arp_hdr *arpheader = NULL; //user definedstruct 
        // int i=0;
        __u_char *hard_ptr;

        int counter=0;

        time_t ct,lt;

        long int diff=0;

        pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
        if (pack_desc == NULL)
        {
            printf("%s\n", error);
            print_available_interfaces();
            return -1;
        }
        else
        {
            printf("Listenting On..... %s\n", device_name);
        }
        while (1)
        {
            packet = pcap_next(pack_desc, &header);

            // packet header(ethernet header)
            // ethernet header - protocol


            if (packet == NULL)
            {
                printf("error: cannot capture packet");
                return -1;
            }
            else
            {
                eptr = (struct ether_header *)packet;

                if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
                {   
                    // ct=time(NULL);
                    // diff=ct-lt;
                    // if(diff>20){
                    //     counter=0;
                    // }
                    arpheader = (arp_hdr *)(packet + 14);//packet 14 offset arp header
                    printf("received a packet with length %d\n", header.len);
                    printf("received at %s\n", ctime((const time_t *)&header.ts.tv_sec));
                    printf("Ethernet Header Length: %d\n", ETHER_HDR_LEN);
                    printf("Operation Type: %s\n", (ntohs(arpheader->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");

                    printf("Sender MAC: ");
                    print_hardware_address(arpheader->sender_mac);
                    printf("\nSender IP: ");
                    print_ip_address(arpheader->sender_ip);
                    printf("\nTarget MAC: ");
                    print_hardware_address(arpheader->target_mac);
                    printf("\nTarget IP: ");
                    print_ip_address(arpheader->target_ip);
                    printf("\n--------------------------------------------------\n");
                    // counter++;
                    // lt=time(NULL);
                    // if(counter>10 && ntohs(arpheader->opcode) == ARP_RESPONSE && arpheader->sender_mac==arpheader->target_mac){
                    //     alert_spoof(arpheader->sender_ip,arpheader->sender_mac);
                    // }
                }
            }
        }
}

int main(int arg, char *args[])
{
        // if (access("/usr/bin/notify-send", F_OK) == -1)
        // {
        //     printf("Missing dependence: libnotify-bin\n");
        //     printf("Please Run: sudo apt-get install libnotify-bin\n");
        // }

        //arp protocol sniffer
        // wlo1

        if (arg < 2 || strcmp("-h", args[1]) == 0 || strcmp("--help", args[1]) == 0)
        {
            print_version();
            print_help(args[0]);
        }
        else if (strcmp("-v", args[1]) == 0 || strcmp("--version", args[1]) == 0)
        {
            print_version();
        }
        else if (strcmp("-1", args[1]) == 0 || strcmp("--lookup", args[1]) == 0)
        {
            print_available_interfaces();
        }
        else if (strcmp("-i", args[1]) == 0 || strcmp("--interface", args[1]) == 0)
        {
            if (arg < 3)
            {
                printf("Error: Please provide an inetrface to sniff on.Selct from the following");
                print_available_interfaces();
                printf("\n Usage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", args[0]);
            }
            else
            {
                sniff_arp(args[2]);
            }
        }
        else
        {
            printf("Invalid arguments...\n");
            print_help(args[0]);
        }
        return 0;
}