#include <pcap.h> 

#include <stdio.h>      
#include <string.h>   
#include <stdlib.h>     
#include <unistd.h>     
#include <ctype.h>      
#include <stdbool.h> 
#include <sys/time.h>  
#include <time.h>       

#include <signal.h>

#include <arpa/inet.h>          
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

// general variable - descriptor
// global due to signal function
pcap_t* pcap_descriptor;


/** @brief Prepare sniffer

    @param interface      name of selected interface
    @param filter         filter string
    
    @return descriptor
*/
pcap_t* open_pcap_socket(char* interface, const char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32  source_ip, netmask;

    struct bpf_program  bpf;

    // get network device source IP address and netmask
    if (pcap_lookupnet(interface, &source_ip, &netmask, errbuf) < 0) {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Opening the device for live capture.
    if ((pcap_descriptor = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf)) == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // convert the filter expression into a packet filter code
    if (pcap_compile(pcap_descriptor, &bpf, (char *) filter, 0, netmask)) {
        printf("pcap_compile(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

    // assign the packet filter to the given libpcap socket
    if (pcap_setfilter(pcap_descriptor, &bpf) < 0) {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pcap_descriptor));
        return NULL;
    }

    return pcap_descriptor;
}

/** @brief Print all available interfaces
*/
void printinterface()
{
    pcap_if_t* allAdapters;
    pcap_if_t* adapter;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&allAdapters, errorBuffer) < 0)
    {
        fprintf(stderr,"Error in pcap_findalldevs function:%s\n", errorBuffer);
        return;
    }
    if(allAdapters == NULL)
    {
        printf("\nNo adapters found!\n");
        return;
    }
    int crtAdapter=0;
    for(adapter = allAdapters; adapter != NULL ; adapter = adapter->next)
    {
        printf("\n%d.%s", ++crtAdapter, adapter->name);
    }
    printf("\n");
    pcap_freealldevs(allAdapters);
    return;
}

/** @brief Create a filter
    @param port       port number
    @param udp        /
    @param tcp        user 
    @param icmp       arguments
    @param arp        /
    @return filter    string with specified parameters
*/
char *create_filter(char *port, bool udp, bool tcp, bool icmp, bool arp)
{
    char *filter = malloc(128);
    filter[0] = '\0';
    if (!udp && !tcp && !icmp && !arp)
    {
        if (!strcmp(port, ""))
        {
            return filter;
        }
        strcat(filter, "port ");
        strcat(filter, port);
        return filter;
    }
    
    strcat(filter, "(");
    if (tcp)
    {
        if (filter[strlen(filter)-1] != '(')
        {
            strcat(filter, "or ");
        } 
        strcat(filter, "tcp ");
    }
    if (udp)
    {
        if (filter[strlen(filter)-1] != '(')
        {
            strcat(filter, "or ");
        } 
        strcat(filter, "udp ");
    }
    if (icmp)
    {
        if (filter[strlen(filter)-1] != '(')
        {
            strcat(filter, "or ");
        } 
        strcat(filter, "icmp ");
    }
    if (arp)
    {
        if (filter[strlen(filter)-1] != '(')
        {
            strcat(filter, "or ");
        } 
        strcat(filter, "arp ");
    }
    strcat(filter, ")");

    if (strcmp(port, ""))
    {
        strcat(filter, " and port ");
        strcat(filter, port);
    }
    return filter;
}

/** @brief clear the pcap_descriptor
    exit with 0
*/
void safe_exit()
{
    pcap_close(pcap_descriptor);
    exit(0);
}

/** @brief print packet symbols in hex and in char
    @param packet   pointer to packet
    @param len      packet length
 */
void print_data(const u_char *packet, int len)
{
    unsigned int line_num = 0x0000; 
    int linecount = 0;
    printf("0x%04X:  ", line_num); //start line
    for (int i = 0; i < len; i++)
    {
        // at the end of 16bits line we convert hex to char
        if (i % 16 == 0 && i != 0)
        {
            printf("    ");
            for (int j = i - 16; j < i; j++) {
                // print dot if char is not printable
                if ((packet[j] >= 32 && packet[j] <= 126)) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }
                // print the space between bytes
                if (j == i - 9) {
                    printf("  ");
                }
            }
            printf("\n");
            linecount++;
            printf("0x%04X:  ", line_num+= 0x0010);
        }
        // print the space between bytes
        if (i % 8 == 0 && i != 0 && i % 16 != 0)
        {
            printf("  ");
        }
        
        // special module for printing the last line,
        // because it may contain less than 16 characters
        printf("%02X ", (unsigned char) packet[i]);
        if (i == len - 1)
        {
            int spacelimit = ((len - (linecount * 16)) < 8) ? 54 : 52;
            for (int k = (len - (linecount * 16))*3; k < spacelimit; k++)
            {
                printf(" ");
            }
            
            for (int j = (linecount) * 16; j < len; j++) {
                if ((packet[j] >= 32 && packet[j] <= 126)) {
                    printf("%c", (unsigned char) packet[j]);
                }
                else {
                    printf(".");
                }
                // print the space between bytes
                if (j == ((linecount+1) * 16) - 9) {
                    printf("  ");
                }
            }
        }
        
    }
    printf("\n\n");
}


/** @brief print timestamp, source and destination addresses
    @param packethdr   packet header pointer
    @param packetptr      pointer to packet
 */
void print_packet_info(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    char buffer[26], timebuffer[128];
    time_t timer = time(NULL);
    struct tm *tm_info = localtime(&packethdr->ts.tv_sec);
    strftime(buffer, 26, "%Y-%m-%dT%T%z", tm_info);

    char tzbuf[6];

    for (int i = 0; i < 5; i++) {
        tzbuf[i] = buffer[i + 19];
    }
    tzbuf[5] = '\0';
    buffer[19] = '\0';

    char timezonebuf[7];
    timezonebuf[0] = tzbuf[0];
    timezonebuf[1] = tzbuf[1];
    timezonebuf[2] = tzbuf[2];
    timezonebuf[3] = ':';
    timezonebuf[4] = tzbuf[3];
    timezonebuf[5] = tzbuf[4];
    timezonebuf[6] = '\0';
    snprintf(timebuffer, sizeof(timebuffer), "timestamp: %s.%03d%s \n", buffer, packethdr->ts.tv_usec / 1000, timezonebuf);
    printf("%s", timebuffer); // prints the time

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char src_ip6[INET6_ADDRSTRLEN];
    char dst_ip6[INET6_ADDRSTRLEN];
    struct ether_header *eth_hdr = (struct ether_header *)packetptr;
    int src_port, dst_port;

    // uint8_t src_mac[6], dst_mac[6];
    uint8_t *ptr;
    ptr = eth_hdr->ether_dhost;
    int i = ETHER_ADDR_LEN;
    printf("dst MAC:  ");
    do{
        printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");
    
    ptr = eth_hdr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf("src MAC:  ");
    do{
        printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    struct ip *ipv4_hdr = (struct ip *)(packetptr + sizeof(struct ether_header));
    printf("frame length: %d bytes\n", packethdr->len);

    inet_ntop(AF_INET, &ipv4_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipv4_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);
    printf("src ip: %s\n", src_ip);
    printf("dst ip: %s\n", dst_ip);
    uint16_t proto = ntohs(eth_hdr->ether_type);
    
    if (proto == ETHERTYPE_IP)
    {
        struct ip *ipv4_hdr = (struct ip *)(packetptr + sizeof(struct ether_header));

        if (ipv4_hdr->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *hdr = (struct tcphdr *)(packetptr + sizeof(struct ether_header));
            src_port = ntohs(hdr->th_sport);
            dst_port = ntohs(hdr->th_dport);

            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
        }
        else if (ipv4_hdr->ip_p == IPPROTO_UDP)
        {
            struct udphdr *hdr = (struct udphdr *)(packetptr + sizeof(struct ether_header));
            src_port = ntohs(hdr->uh_sport);
            dst_port = ntohs(hdr->uh_dport);

            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
        }
    
    }
    printf("\n");
    print_data(packetptr, packethdr->len);

}

int main(int argc, char *argv[]) 
{
    char port[32] = "";        // port nubmer
    int pocetpaketu = 1;       // number of packets to scan
    bool udp = false;          //
    bool tcp = false;          // booleans for 
    bool icmp = false;         // all types of connections
    bool arp = false;          //
    char interface[256] = "";  // interface name

    int opt;
    int argctmp = argc;
    // getting args
    while (argctmp--) {
        
        if (!strcmp(argv[argctmp], "--tcp") || !strcmp(argv[argctmp], "-t")) {
            tcp = true;
            argv[argctmp] = "";
        }
        else if (!strcmp(argv[argctmp], "--udp") || !strcmp(argv[argctmp], "-u")) {
            udp = true;
            argv[argctmp] = "";
        }
        else if (!strcmp(argv[argctmp], "-i") || !strcmp(argv[argctmp], "--interface")) {
            if (argctmp+1 < argc){
            if (argv[argctmp+1][0] != '-')
                strcpy(interface, argv[argctmp+1]);
            }
        }
        else if (!strcmp(argv[argctmp], "-p")) {
            strcpy(port, argv[argctmp+1]);
        }
        else if (!strcmp(argv[argctmp], "-n")) {
            pocetpaketu = atoi(argv[argctmp+1]);
        }
        else if (!strcmp(argv[argctmp], "--icmp")) {
            icmp = true;
        }
        else if (!strcmp(argv[argctmp], "--arp")) {
            arp = true;
        }
        else if (!strcmp(argv[argctmp], "-h") || !strcmp(argv[argctmp], "--help")) {
            printf("usage: [-h] [-i ] [-n ] [-p ] [-u|--udp] [-t|--tcp] [--arp] [--icmp]\n");
            printf("\t-i [string]   nastavi rozhrani\n");
            printf("\t-n [integer]  urcuje limit paketu\n");
            printf("\t-p [integer]  nastavi konkretni port\n");
            printf("\t-u|--udp      bude zobrazovat pouze UDP pakety\n");
            printf("\t-t|--tcp      bude zobrazovat pouze TCP pakety)\n");
            printf("\t--icmp        bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)\n");
            printf("\t--arp         bude zobrazovat pouze ARP pakety)\n");
            return 0;
        }
    }
      
    // if the interface not was added, print list of available interfaces
    if (!strcmp(interface,""))
    {
        printinterface();
        return 0;
    }
    // creating filter
    char *filter = create_filter(port, udp, tcp, icmp, arp);
    //printf("filter: %s\n", filter);
    pcap_descriptor = open_pcap_socket(interface, filter);

    if (pcap_descriptor)
    {
        // connect the signals to the ending function
        signal(SIGINT, safe_exit);
        signal(SIGQUIT, safe_exit);
        signal(SIGTERM, safe_exit);

        if (pcap_datalink(pcap_descriptor) != 1) {
            printf("pcap_datalink(): %s\n", pcap_geterr(pcap_descriptor));
            return EXIT_FAILURE;
        }
        if (pcap_loop(pcap_descriptor, pocetpaketu, (pcap_handler) print_packet_info /* callback function */, NULL)) {
            return EXIT_FAILURE;
        }
    }
    
    free(filter);
    return 0;
}