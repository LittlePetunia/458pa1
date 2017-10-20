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

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

  printf("*** -> Received packet of length %d \n",len);
  printf("+++++++++++++++++++++++++++++++++++\n");
  print_hdrs(packet,len); 
  printf("+++++++interface %c \n", *interface);
  /* fill in code here */
  /* fill in code here */
  struct sr_if *iface = sr_get_interface(sr, interface);
  assert (iface);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;

  /* drop if packet is too short */
  if (len < sizeof (sr_ethernet_hdr_t))
  {
    fprintf (stderr, "Dropping ethernet frame. Too short. len: %d.\n", len);
    return;
  }

  /* drop if checksum not correct */
  void * datagram = (uint8_t *)packet + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)datagram;
  uint16_t cksum = ip_hdr -> ip_sum;
  ip_hdr -> ip_sum = 0;
  if(cksum(void *) ip_hdr, sizeof(sr_ip_hdr_t)) != chksum)
  {
    fprintf(stderr, "Dropping ip packet. Corrupted checksum. %d ", chksum);
    return;
  }

  

}/* end sr_ForwardPacket */

