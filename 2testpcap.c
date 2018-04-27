#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>


void my_packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_body);
void get_whois(char *ip , char **data);
int whois_query(char *server , char *query , char **response);
int hostname_to_ip(char * hostname , char* ip);


int main(int argc, char **argv)
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int packet_count_limit = 0;
    int timeout_limit = 10000;
    pcap_t* handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    int snapshot_length = 1024; //BUFSIZ;
    int total_packet_count = 0;
    int promisc = 1; //set promiscuous mode
    
    
    
    //get device
    device = pcap_lookupdev(error_buffer);
    if(device == NULL)
    {
        printf("%s\n",error_buffer);
        exit(1);
    }
    
    bpf_u_int32 subnet_mask, ip;
    if(pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get info from device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }
    
    
    //get packets
    handle = pcap_open_live(device, snapshot_length, promisc, timeout_limit, error_buffer);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",error_buffer);
        exit(1);
    }
    
    
    //get packets only for port 80, i.e. HTTP
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    if(pcap_compile(handle, &fp, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if(pcap_setfilter(handle, &fp) == -1) {
        printf("error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    
    
    //continuously get packets until termination
    pcap_loop(handle, total_packet_count, my_packet_handler, NULL);
    
    return 0;
}



//processes packets
void my_packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet)
{
    struct ether_header * eth_header;
    eth_header = (struct ether_header *) packet;
    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        //printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    
    //printf("Packet capture length: %d\n", packet_header->caplen);
    //printf("Packet total length: %d\n", packet_header->len);
    
    
    const u_char* ip_header;
    const u_char* tcp_header;
    const u_char* payload;
    
    
    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    
    
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
    
    
    u_char protocol = *(ip_header + 9);
    if(protocol != IPPROTO_TCP) {
        //printf("Not a TCP packet. Skipping...\n\n");
        return;
    }
    
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    //printf("TCP header length in bytes: %d\n", tcp_header_length);
    
    int total_header_size = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = packet_header->caplen - total_header_size;
    //printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_header_size;
    //printf("Memory address where payload begins: %p\n\n", payload);
    
    
    //finds the "GET / ..." http packets to get the website
    char begin[7];
    int i;
    for(i = 0; i < 6; i++)
        begin[i] = payload[i];
    begin[6] = '\0';
    if(strcmp(begin, "GET / ") == 0) { //start parsing for host
        char host[200];
        int len = 0;
        
        for(i = 0; i < strlen(host); i++) //fill with zeros because it is being overwritten
            host[i] = '0';
        
        for(i = 0; i < 200; i++) { //gets host part of http header by going until newline
            if(payload[i+21] == '\r')
                break;
            host[i] = payload[i+21];
            len += 1;
        }
        
        //writing to file
//        if(check == 1) {
        //printf("host: %s\n", host);
        FILE * websiteFile = fopen("websites.txt", "a");
        for(i = 0; i < strlen(host); i++) {
            if(host[i] != '0')
                fputc(host[i], websiteFile);
            else
                break;
        }
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        fputs(", ", websiteFile);
        fputs(asctime(timeinfo), websiteFile);
        fputs("\r\n", websiteFile);
        //fputs(host, websiteFile);
        fclose(websiteFile);
        
        
    }
        
        
        //printf("\nPAYLOAD:\n%s\n\n", payload);
    
    
    
    
    const struct ip* ip;
    ip = (struct ip*)(packet + ethernet_header_length);
    
    int len = ntohs(ip->ip_len);
    
    if(ip->ip_v != 4) {
        //printf("Unknown version %d\n", ip->ip_v);
        return;
    }
    
    if(ip->ip_hl < 5) {
        //printf("bad header length %d\n", ip->ip_hl);
        return;
    }
    
    
    return;
}

















