/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h> 

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

    /* Function Declarations */
    void handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);
    void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);
    void ip_current_destination(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);
    void ip_another_destination(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);
    void arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);
    void arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char *interface);

    /*void send_icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface, uint8_t icmp_type, uint8_t icmp_code);
    void icmp_reply_zero(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface);
    void icmp_reply_three(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface, uint8_t icmp_code);    
    void icmp_reply_eleven(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface);*/

    struct sr_rt *lpm_routing_table(struct sr_instance *sr, uint32_t ip);
    struct sr_if* sr_get_ip_interface(struct sr_instance* sr, uint32_t ip);
    
    void set_ethernet_hdr(uint8_t * packet, uint8_t *shost, uint8_t *dhost, uint16_t type);
    void set_ip_hdr(uint8_t *packet, uint32_t src, uint32_t dst, uint8_t ttl, uint8_t p);
    void set_icmp_hdr(uint8_t * packet, uint8_t type, uint8_t code);
    void set_icmp_three_hdr(uint8_t * packet, uint8_t type, uint8_t code);
    void set_arp_hdr(uint8_t * packet, unsigned short hrd, unsigned short pro, unsigned char hln, unsigned char pln, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    
    printf("***** INCOMING PACKET HEADERS *****\n");
    printf("*** -> Received packet of length %d \n",len);
    print_hdrs(packet, len);
    printf("*************************\n");
    
    uint16_t packet_protocol = ethertype(packet);
    
    switch(packet_protocol) {
        case ethertype_arp:
            {
                printf("ARP Protocol\n");
                handle_arp_packet(sr, packet, len, interface);
                return;   
            }
        case ethertype_ip:
            {
                printf("IP Protocol\n");
                handle_ip_packet(sr, packet, len, interface);
                return;   
            }
        default :
            printf("Packet Does Not Specify Protocol\n");
            exit(0);
    }
}/* end sr_ForwardPacket */

/* IP MESSAGES */

void handle_ip_packet(struct sr_instance* sr, 
                      uint8_t * packet, 
                      unsigned int len, 
                      char *interface)
{
    
    struct sr_ip_hdr * ip_hdr = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

    struct sr_if * dest_interface = sr_get_ip_interface(sr, ip_hdr->ip_dst);

    /*check if the destination is an interface for our router
    if it is, destination != NULL  */
    
    if(dest_interface){
        ip_current_destination(sr, packet, len, interface);
        return;
    }
    else{
        ip_another_destination(sr, packet, len, interface);
        return;
    }
}

void ip_current_destination(struct sr_instance* sr, 
                            uint8_t * packet, 
                            unsigned int len, 
                            char *interface){
    printf("The IP Packet is to be delivered to the current interfaces\n");    
    
    /* We have the packet, router, and sending interface. We sperated ip header and get the protocol */

    struct sr_ip_hdr * ip_hdr = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
                                                    
    uint8_t ip_protocol = ip_hdr -> ip_p;
    
    /* We get the source of the ip address since that is who sent the message and we must reply back
    Thus we get the interface structure of the next interface we must send to, which is who sent th ip message
    to us, since we have to reply back */
    
    struct sr_rt *route = lpm_routing_table(sr, ip_hdr->ip_src);
    struct sr_if *dest_interface = sr_get_interface(sr, route->interface);
    
    int new_packet_len = 0;

    if(ip_protocol == ip_protocol_icmp){
        printf("The IP Packet is ICMP\n"); 
        
        /*create a new icmp message */
        new_packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
        
        uint8_t * icmp_packet = malloc(new_packet_len);
        
        /*set headers*/
        set_ethernet_hdr(icmp_packet, 0, 0, 2048);
        set_ip_hdr(icmp_packet, ip_hdr->ip_dst, ip_hdr->ip_src, 64, ip_protocol_icmp);
        set_icmp_hdr(icmp_packet, 0, 0);
        
        /*send message*/
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(icmp_packet, new_packet_len);
        printf("*************************\n");
        sr_send_packet(sr, icmp_packet, new_packet_len, dest_interface->name);
        
        
        return;
    }
    else if(ip_protocol == 0x0006 || ip_protocol == 0x0011){
        printf("The IP Packet is TCP or UDP\n"); 
        
        new_packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        
        uint8_t * icmp_packet = malloc(new_packet_len);
        
        set_ethernet_hdr(icmp_packet, 0, 0, 2048);
        set_ip_hdr(icmp_packet, ip_hdr->ip_dst, ip_hdr->ip_src, 64, ip_protocol_icmp);
        set_icmp_three_hdr(icmp_packet, 3, 1);
        
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(icmp_packet, new_packet_len);
        printf("*************************\n");
        
        sr_send_packet(sr, icmp_packet, new_packet_len, dest_interface->name);

        return;
    }
    else{
        printf("Invalid IP Protocol Defined\n");
        exit(1);
    }
}

void ip_another_destination(struct sr_instance* sr, 
                            uint8_t * packet, 
                            unsigned int len, 
                            char *interface){
    printf("The IP Packet will be forwarded to another destination\n");

   /* struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *) packet;*/
    
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
    
    /*Since it is not for us, we first decrement the ttl and check if it is 0. If yes, then we send
    ttl timemout message */
    
    ip_hdr->ip_ttl--;
    
    struct sr_if *ttl_interface = sr_get_interface(sr, interface);
    
    if(ip_hdr -> ip_ttl == 0){
        
        printf("TTL For Packet Is Zero\n");
         
        int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
        
        uint8_t * icmp_packet = malloc(len);
        
        set_ethernet_hdr(icmp_packet, 0, 0, 2048);
        set_ip_hdr(icmp_packet, ip_hdr->ip_dst, ip_hdr->ip_src, 64, ip_protocol_icmp);
        set_icmp_hdr(icmp_packet, 11, 0);
        
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(icmp_packet, len);
        printf("*************************\n");
        
        sr_send_packet(sr, icmp_packet, len, ttl_interface->name);
        
        return;
    }
    
    printf("Decrementing TTL Successful\n");
    
    /*if it is good, we must forward it to the destination, thus we get best matching 
    interface structure of the ip destination */
    
    struct sr_rt *route = lpm_routing_table(sr, ip_hdr->ip_dst);
    struct sr_if *dest_interface = sr_get_interface(sr, route->interface);
    
    if(route == NULL){
        
        printf("Longest Prefix Match Not Found\n");
        
        /*create message and send if no route exists*/
        
        len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        
        uint8_t * icmp_packet = malloc(len);
        
        set_ethernet_hdr(icmp_packet, 0, 0, 2048);
        set_ip_hdr(icmp_packet, ip_hdr->ip_dst, ip_hdr->ip_src, 64, ip_protocol_icmp);
        set_icmp_three_hdr(icmp_packet, 3, 0);
        
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(icmp_packet, len);
        printf("*************************\n");
        
        sr_send_packet(sr, icmp_packet, len, dest_interface->name);
        
        
        return;
    }
    
    printf("Found Longest Prefix Match\n");
    
    /*Otherwise we follow protocol as defined in arpcache.h */
    
    struct sr_if *route_interface = sr_get_interface(sr, route->interface);
    
    struct sr_arpentry *cache_entry = sr_arpcache_lookup(&sr->cache, route->gw.s_addr);
    
    printf("Initialized Cache Entry\n");
    
    if(cache_entry){
        
        printf("Found Cache Entry\n");
        
        set_ethernet_hdr(packet, route_interface->addr, cache_entry->mac, 2048);
        
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(packet, len);
        printf("*************************\n");
        
        sr_send_packet(sr, packet, len, route_interface->name);
        
	return;
 
    }
    else{
        
        printf("Did Not Find Cache Entry\n");
        
        struct sr_arpreq *arpRequest = sr_arpcache_queuereq(&sr->cache, route->gw.s_addr, packet, len, route_interface->name);
        
        printf("Successfully Created Arp Request Structure\n");
        
        handle_arpreq(sr, arpRequest);
	return;
    }
}


/* ARP MESSAGES */

void handle_arp_packet(struct sr_instance* sr, 
                       uint8_t * packet, 
                       unsigned int len, 
                       char *interface){
    
    struct sr_arp_hdr * arp_hdr = (struct sr_arp_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
    
    /*check if arp request or arp reply*/
    
    if(ntohs(arp_hdr -> ar_op) == arp_op_request){
        printf("ARP Request\n");
        arp_request(sr, packet, len, interface);
        return;
    }
    else if(ntohs(arp_hdr -> ar_op) == arp_op_reply){
        printf("ARP Reply\n");
        arp_reply(sr, packet, len, interface);
        return;
    }
    else{
        printf("Invalid ARP opcode\n");
        exit(1);
    }
}

void arp_reply(struct sr_instance* sr, 
               uint8_t * packet, 
               unsigned int len, 
               char *interface){
    /* For an ARP Reply, we first recieve sr, packet, len, and recieving interface as arguments
    We then seperate the header since it contains useful information */
    
    struct sr_arp_hdr * arp_hdr = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));  
    
    
    struct sr_if * dest_interface = sr_get_ip_interface(sr, arp_hdr->ar_tip);
    
    
    if(dest_interface){
        struct sr_arpreq * arp_entry = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if(arp_entry){
            struct sr_packet * entry_packets = arp_entry->packets;
            
            struct sr_if *packet_interface = NULL;
            
            while(entry_packets){
                
                packet_interface = sr_get_interface(sr, entry_packets->iface);
                
                if(packet_interface){
                    set_ethernet_hdr(entry_packets->buf, packet_interface->addr, arp_hdr->ar_sha, 2054);
                    
                    printf("***** OUTGOING PACKET HEADERS *****\n");
                    print_hdrs(entry_packets->buf, entry_packets->len);
                    printf("*************************\n");
                    
                    sr_send_packet(sr, entry_packets->buf, entry_packets->len, entry_packets->iface);
                    
                }
                entry_packets = entry_packets->next;  
            }
        }
        sr_arpreq_destroy(&sr->cache, arp_entry);  
    }
    else{
        printf("Function: ARP_REQUEST \nTarget IP Address Not Found in Router IP Addresses\n");
    }   
}

void arp_request(struct sr_instance* sr, 
                 uint8_t * packet, 
                 unsigned int len, 
                 char *interface){

    /*if it is an arp request, first seperate the headers of 
    the arp request since it contains useful information*/
    
    struct sr_ethernet_hdr *arp_eth_hdr = (struct sr_ethernet_hdr *) packet;
    struct sr_arp_hdr * arp_req_hdr = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
        
    struct sr_if * dest_interface = sr_get_interface(sr, interface);
    
    /*check if it is for an interface on our router, otherwise we ignore it */
    
    if(dest_interface){  
        
        printf("Sending Arp Reply After Recieving Arp Request\n"); 
        
        /*construct a new arp packet */
        
        int arp_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
        
        uint8_t *arp_packet = malloc(len);
        memcpy(arp_packet, packet, arp_len);
        
        /* set the headers*/
        set_ethernet_hdr(arp_packet, dest_interface->addr, arp_eth_hdr->ether_shost, 2054);
        
        set_arp_hdr(arp_packet, 0x01, 2048, arp_req_hdr->ar_hln, arp_req_hdr->ar_pln, arp_op_reply, dest_interface->addr, dest_interface->ip, arp_req_hdr->ar_sha, arp_req_hdr->ar_sip);  

        /* Send it to the interface, we send it to dest_interface
        since arp request was from char *interface whose corresponding sr_if is above */
        printf("***** OUTGOING PACKET HEADERS *****\n");
        print_hdrs(arp_packet, arp_len);
        printf("*************************\n");
        
        sr_send_packet(sr, arp_packet, arp_len, dest_interface->name);
        
    }
    else{
        printf("Function: ARP_REPLY \nTarget IP Address Not Found in Router IP Addresses\n");
    } 
}

/* Other Helping Functions */

struct sr_rt *lpm_routing_table(struct sr_instance *sr, uint32_t ip){
     struct sr_rt *route = sr->routing_table;
    
    struct sr_rt *longest_route = NULL;
    uint32_t len = 0;
    
    while(route){
        if ((route->dest.s_addr & route->mask.s_addr) == (ip & route->mask.s_addr)){
            if(route->mask.s_addr > len){
                longest_route = route;
                len = route->mask.s_addr;
            }
        }
        route = route-> next;
    }
    return longest_route;
}


struct sr_if* sr_get_ip_interface(struct sr_instance* sr, uint32_t ip)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    /*assert(name);*/
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
        printf("%d\n", if_walker->ip);
       if(if_walker->ip == ip)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} 

void set_ethernet_hdr(uint8_t * packet, 
                      uint8_t * shost, 
                      uint8_t * dhost,
                      uint16_t type){
    
    sr_ethernet_hdr_t* eth_hdr = (struct sr_ethernet_hdr *) packet;
    
    memcpy(eth_hdr->ether_shost, shost, sizeof(uint8_t)*ETHER_ADDR_LEN);     
    memcpy(eth_hdr->ether_dhost, dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(type);
}

void set_ip_hdr(uint8_t *packet, 
                uint32_t src, 
                uint32_t dst, 
                uint8_t ttl, 
                uint8_t p){
    
    sr_ip_hdr_t* ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
    
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;
    ip_hdr->ip_ttl = ttl;
    ip_hdr->ip_p = p;
    
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

}

void set_icmp_hdr(uint8_t * packet, 
                  uint8_t type, 
                  uint8_t code){
    
    struct sr_icmp_hdr* icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
    
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_hdr));
}

void set_icmp_three_hdr(uint8_t * packet, 
                        uint8_t type, 
                        uint8_t code){
    
    struct sr_icmp_t3_hdr* icmp_hdr = (struct sr_icmp_t3_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));  
    
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
}

void set_arp_hdr(uint8_t * packet, 
                 unsigned short hrd, 
                 unsigned short pro, 
                 unsigned char hln,
                 unsigned char pln,
                 unsigned short op,
                 unsigned char *sha,
                 uint32_t sip,
                 unsigned char *tha,
                 uint32_t tip   
                ){
    
            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
            
            printf("Hardware Type: %d\n", hrd);
            printf("Protocol Type: %d\n", pro);
            printf("Opcode: %d\n", op);
            printf("Hardware Length: %d\n", hln);
            printf("Protocol Length: %d\n", pln);
            
            
            arp_hdr->ar_hrd = (unsigned short)htons(hrd);
            arp_hdr->ar_pro = (unsigned short)htons(pro);
            arp_hdr->ar_hln = (unsigned char)hln;
            arp_hdr->ar_pln = (unsigned char)pln;
    
            arp_hdr->ar_op = (unsigned short)htons(op); 
            memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = sip;                         
            memcpy(arp_hdr->ar_tha, tha, ETHER_ADDR_LEN);  
            arp_hdr->ar_tip = tip;   
}