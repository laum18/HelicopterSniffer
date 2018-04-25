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

void my_packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_body);
void get_whois(char *ip , char **data);
int whois_query(char *server , char *query , char **response);
int hostname_to_ip(char * hostname , char* ip);



/**
 Get the whois content of an ip
 by selecting the correct server
 */
void get_whois(char *ip , char **data)
{
    char *wch = NULL, *pch , *response = NULL;
    
    if(whois_query("whois.iana.org" , ip , &response))
    {
        //printf("Whois query failed");
    }
    
    pch = strtok(response , "\n");
    
    while(pch != NULL)
    {
        //Check if whois line
        wch = strstr(pch , "whois.");
        if(wch != NULL)
        {
            break;
        }
        
        //Next line please
        pch = strtok(NULL , "\n");
    }
    
    if(wch != NULL)
    {
        printf("\nWhois server is : %s" , wch);
        //whois_query(wch , ip , data);
    }
    else
    {
        *data = malloc(100);
        strcpy(*data , "No whois data");
    }
    
    return;
}

/*
 * Perform a whois query to a server and record the response
 * */
int whois_query(char *server , char *query , char **response)
{
    char ip[32] , message[100] , buffer[1500];
    int sock , read_size , total_size = 0;
    struct sockaddr_in dest;
    
    sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
    
    //Prepare connection structures :)
    memset( &dest , 0 , sizeof(dest) );
    dest.sin_family = AF_INET;
    
    //printf("\nResolving %s..." , server);
    if(hostname_to_ip(server , ip))
    {
        printf("Failed");
        return 1;
    }
    printf("%s" , ip);
    dest.sin_addr.s_addr = inet_addr( ip );
    dest.sin_port = htons( 43 );
    
    //Now connect to remote server
    if(connect( sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0)
    {
        perror("connect failed");
    }
    
    //Now send some data or message
    //printf("\nQuerying for ... %s ..." , query);
    sprintf(message , "%s\r\n" , query);
    if( send(sock , message , strlen(message) , 0) < 0)
    {
        perror("send failed");
    }
    
    //Now receive the response
    while( (read_size = recv(sock , buffer , sizeof(buffer) , 0) ) )
    {
        *response = realloc(*response , read_size + total_size);
        if(*response == NULL)
        {
            printf("realloc failed");
        }
        memcpy(*response + total_size , buffer , read_size);
        total_size += read_size;
    }
    //printf("Done");
    fflush(stdout);
    
    *response = realloc(*response , total_size + 1);
    *(*response + total_size) = '\0';
    
    close(sock);
    return 0;
}

/*
 * @brief
 * Get the ip address of a given hostname
 *
 * */
int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    
    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    
    addr_list = (struct in_addr **) he->h_addr_list;
    
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    
    return 0;
}




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
    
    char ip[100] , *data = NULL;
    
    printf("Enter ip address to whois : ");
    scanf("%s" , ip);
    
    get_whois(ip , &data);
    printf("\n\n");
    puts(data);
    
    free(data);
    return 0;
    
    
    
    //get device
    device = pcap_lookupdev(error_buffer);
    if(device == NULL)
    {
        printf("%s\n",error_buffer);
        exit(1);
    }


    /*create device
    handle = pcap_create(*device, error_buffer);
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, snapshot_length);
    pcap_set_timeout(handle, timeout_limit);
    pcap_activate(handle);
    */
    
    
    //get packets
    handle = pcap_open_live(device, snapshot_length, promisc, timeout_limit, error_buffer);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",error_buffer);
        exit(1);
    }
    
    
    pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

    
    
    
    /*
    lookup_return_code = pcap_lookupnet(dev, &ip_raw, &subnet_mask_raw, errbuf);
    if(lookup_return_code == -1) {
        printf("%s\n", errbuf);
        return 1;
    }
    
    //get ip in readable form
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if(ip == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    
    //get subnet mask in readable form
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if(subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    
    printf("Device: %s\n", dev);
    printf("technically the network address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);
    

    
    
    
    //open device for printing
    descr = pcap_open_live(dev,BUFSIZ,1,10000,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    
    
    

    //grab packet from descr (descriptor)
    packet = pcap_next(descr,&hdr);
    if(packet == NULL)
    {
        printf("Didn't grab packet\n");
        exit(1);
    }
    printf("Grabbed packet of length %d\n",hdr.len);
    printf("Received at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec));
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
    
    
    
    
    // lets start with the ether header
    eptr = (struct ether_header *) packet;
    // Do a couple of checks to see what packet type we have
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
               ntohs(eptr->ether_type),
               ntohs(eptr->ether_type));
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
               ntohs(eptr->ether_type),
               ntohs(eptr->ether_type));
    }else {
        printf("Ethernet type %x not IP\n", ntohs(eptr->ether_type));
        exit(1);
    }
    
    
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" Destination Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");
    
    */
    
    
    
    return 0;
}


void my_packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet)
{
    struct ether_header * eth_header;
    eth_header = (struct ether_header *) packet;
    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not and IP packet. Skipping...\n\n");
        return;
    }
    
    
    printf("Packet capture length: %d\n", packet_header->caplen);
    printf("Packet total length: %d\n", packet_header->len);
    
    
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
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
    
    
    u_char protocol = *(ip_header + 9);
    if(protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }
    
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);
    
    int total_header_size = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = packet_header->caplen - total_header_size;
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_header_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    
    
    const struct ip* ip;
    ip = (struct ip*)(packet + ethernet_header_length);
    
    int len = ntohs(ip->ip_len);
    
    if(ip->ip_v != 4) {
        printf("Unknown version %d\n", ip->ip_v);
        return;
    }
    
    if(ip->ip_hl < 5) {
        printf("bad header length %d\n", ip->ip_hl);
        return;
    }
    
    printf("IP source: %s\n", inet_ntoa(ip->ip_src));
    printf("IP dest: %s\n\n\n", inet_ntoa(ip->ip_dst));
    
    
    
    
    /*
    //print contents
    if(payload_length > 0) {
        const u_char * temp_pointer = payload;
        int byte_count = 0;
        while(byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */
 
    return;
}

















