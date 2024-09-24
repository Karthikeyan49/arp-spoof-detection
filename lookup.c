#include <stdio.h>
#include <stdlib.h>
// #include <sys/socket.h>
#include <errno.h>
#include <pcap.h> //packet capture
// #include <netinet/in.h>
// #include <arpa/inet.h>
#include<unistd.h>

// packet library -> pcap

int main(int argc,char *arg[]){
    
    char error[PCAP_ERRBUF_SIZE]; //to get error with size 256bits

    pcap_if_t *interface, *temp;//it's a structure contains details of iterfaces
    int i=0;

    if(pcap_findalldevs(&interface,error)== -1){ // function used to findall devices and return the details in inetrface vailable 
        printf("cannot acquire the device\n");
        printf("%s",error);
        return -1;
    }
    
    printf("the available devices are\n");
    for(temp = interface;temp!=NULL;temp=temp->next){
        printf("#%d: %s\n",++i,temp->name);
    }
    // system("/usr/bin/notify-send -t 5000 -i face-angel \"LAHTP: I am watching for ARP Spoofing. Sit back and relax!\"");

    
}


// arp -address resolution protocol
// request reponse protocol
// local area 
// arp-authencation,stateless 
// arp -ip and mac

// arp request boardcast
// laptop arp -response mac address and ip  return

// wifi- mac address-phsical 6 segment hexadecimal
// arp -arp request -devies arp table 


// mitm(man in middle attack)
// 2 computer  1 com-mac2       2com mac2           router mac2
// 1co request router and response com
// 1co request attacker and send to router and response attcker 1com
// active and passive 

// tools
// arpspoof
// netdiscover
// wireshark

// router - 3 device -attckercomputer -com -victim
// middile router and victim

// wireshark -monitor


// http - no encryption and decryption
// https- folder 

// 1 type:
// https request attcak computer and server pass
// response depcr and http site 


// 2-type:
// certicate intall https 



// wireshark -monitor -passive
// packets - interface , packets ,