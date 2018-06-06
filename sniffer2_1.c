/*
Author: Kyle Shake
Date: 3/20/18
Last Modified: 3/20/18
By: Kyle Shake

Purpose: This program is a packet sniffer ***Fill out more as we understand more**

Input: No input needed

Output: Program writes information on packets gathered from host computer into files

Code Sourced From:
http://www.tcpdump.org/sniffex.c
http://www.tcpdump.org/pcap.html
http://yuba.stanford.edu/~casado/pcap/section2.html


*/



#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define SNAP_LEN 65535   /* snap length (maximum bytes per packet to capture) */
#define SIZE_ETHERNET 14
#define SIZE_UDPHD 8

//Files to hold data
FILE *ports;
FILE *ipaddresses;
FILE *TCPvsUDP;
FILE *pktsPerSec;
FILE *dataPerSec;


/* implement your own callback function to process the data*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1; //packet counter
    static int TCPcount = 0; //TCP packet counter
    static int UDPcount = 0; //UDP packet counter

    /*Declaring pointers to packet headers*/
    const struct ether_header *ethernet;
    const struct ip *ip_hdr; //from netinet/ip.h
    const struct tcphdr *tcp; //from netinet/tcp.h 
    const struct udphdr *udp; //from netinet/udp.h

    int size_ip;

    u_int length = header->len;
    u_int hlen, off, version;

    int len;


    /*Define the ethernet header*/
    ethernet = (struct ether_header*)(packet);

/*
    if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
        printf("Ethernet type hex: %x Dec: %d is an IP Packet\n",
		ntohs(ethernet->ether_type),
                ntohs(ethernet->ether_type));

    }//For Debugging */
    
    
    /*Define/Compute the IP header offset */
    ip_hdr = (struct ip*)(packet + SIZE_ETHERNET);
    size_ip = (ip_hdr->ip_len)*4;


/*For debugging taken from 
http://yuba.stanford.edu/~casado/pcap/disect2.c

*/
    length -= sizeof(struct ether_header);
    if (length < sizeof(struct ip)){
        printf("Truncated IP %d", length);
    }

    len = ntohs(ip_hdr->ip_len);
    hlen = ip_hdr->ip_hl;
    version = ip_hdr->ip_v;

    if(version != 4){
        printf("Unknown version %d\n", version);
        return;
    }

    if(hlen < 5){
        printf("Bad Hlen %d \n", hlen);
    }

    if(length < len){
        printf("Truncated IP - %d bytes missing \n", len-length);
    }

    off = ntohs(ip_hdr->ip_off);
   /* if((off & 0x1fff) == 0){
        printf("IP: %s ", inet_ntoa(ip_hdr->ip_src));
        printf("%s %d %d %d %d \n", inet_ntoa(ip_hdr->ip_dst), hlen, version, len, off);
    }*/

 /* End debug code */


    /*Open files to hold data*/
    ipaddresses = fopen("ipaddresses.txt", "a");
    ports = fopen("ports.txt", "a");
    TCPvsUDP = fopen("TCPvsUDP.txt", "a");
    pktsPerSec = fopen("pktspersec.txt", "a");
    dataPerSec = fopen("datapersec.txt", "a");

/*
* Print to Console Code 
* For comparison to Wireshark
*/

    printf("%d | ", count);

    char timestamp[256];
    strcpy(timestamp, ctime((const time_t*)&header->ts.tv_sec));

    timestamp[strlen(timestamp)-1] = '\0';

    printf("%s |", timestamp);


    /*This code is for checking the data against Wireshark*/
    printf("%s | ", inet_ntoa(ip_hdr->ip_src));
    printf("%s | ", inet_ntoa(ip_hdr->ip_dst));
   
/* END COMPARISON CODE */




    /*Adding packet number to file */
    fprintf(pktsPerSec, "%d at %s", count, ctime((const time_t*)&header->ts.tv_sec));
    count++;


    /*Adding size of packet to file*/
    fprintf(dataPerSec, "%d at %s ", header->len, ctime((const time_t*)&header->ts.tv_sec));

    /*Adding Source Address of packet to file */
    fprintf(ipaddresses, "Source: %s\n", inet_ntoa(ip_hdr->ip_src));
  
    /*Adding Destination Address of packet to file */
    fprintf(ipaddresses, "Destination: %s\n", inet_ntoa(ip_hdr->ip_dst));




    /* Determine protocol then do something with it*/
    switch(ip_hdr->ip_p){
        case IPPROTO_TCP:
            /*Add to count of TCP packets and write to file*/
            TCPcount++;

            printf("TCP | "); //For data checking

            fprintf(TCPvsUDP, "TCP Packet #%d\n", TCPcount);

            /* Define/Compute TCP header offset */
            tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

            /* Adding TCP Destination and Src Ports to file */
            fprintf(ports, "TCP Source port: %d\n", ntohs(tcp->th_sport));
            fprintf(ports, "TCP Destination port: %d\n", ntohs(tcp->th_dport));

            printf("%d | %d | ", ntohs(tcp->th_sport), ntohs(tcp->th_dport)); //For Data Checking vs Wireshark
            break;
        case IPPROTO_UDP:
            /*Add to count of UDP packets and write to file */
            UDPcount++;

            printf("UDP | "); //For data checking
  
            fprintf(TCPvsUDP, "UDP Packet #%d\n", UDPcount);

            /* Define/Compute UDP header offset */
            udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip); //Not sure if this is correct

            printf("%d | %d | ", ntohs(udp->uh_sport), ntohs(udp->uh_dport)); //For Data Checking vs. Wireshark

            /* Add size of UDP packet to file */
            fprintf(TCPvsUDP, "UDP size: %d\n", ntohs(udp->uh_ulen));
	    break;
        default:
            printf("Unknown |"); //Debug


    }
    printf("%d \n", header->len); 

    
    /*Close files*/
    fclose(ipaddresses);
    fclose(ports);
    fclose(TCPvsUDP);
    fclose(pktsPerSec);
    fclose(dataPerSec);

}

int main(int argc, char **argv)
{
    
    char *dev = NULL;            /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */
    
    struct bpf_program fp;            /* cstruct in_addrompiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
    
    
    
    /* find device to sniff */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL){
        fprintf(stderr, "Couldn't find default device %s\n", errbuf);
        return(2);
    }
   
    /* print device name */
    printf("Device: %s\n", dev);
    
   
    /* open capture device using pcap_open_live*/
    /*
    Arguments:
    dev - device name
    SNAP_LEN - the max number of bytes to capture
    0 - non promiscuous mode *We are only concerned about the local host's traffic*
    errbuf - string used to store error message if necessary
    */
    handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    
    /* compile and apply the filter expression */
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    char filter_exp[] = "tcp || udp"; // Filter for TCP or UDP packets
    if(pcap_compile(handle, &fp, filter_exp, 0 , net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    printf("No.|Time Stamp \t| Source IP | Destination IP | Protocol | Src Port | Dest Port | Length\n");
    /* main loop */
    pcap_loop(handle, -1, got_packet, NULL);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nCapture complete.\n");
    
    return 0;
}

