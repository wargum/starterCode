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

  /* TODO: FILL IN YOUR CODE HERE */
  // get the new frame header
  struct sr_ethernet_hdr *new_hdr = (struct sr_ethernet_hdr *)packet;
  struct sr_if* local_interface = sr_get_interface(sr, interface);
  if(new_hdr->ether_type == htons(ethertype_arp)) {
    // get the new arp header
    sr_arp_hdr_t* new_arp_hdr = (struct sr_arp_hdr *)packet + sizeof(struct sr_ethernet_hdr);

    if(new_arp_hdr->ar_op == htons(arp_op_request)) {
      struct sr_arpreq *new_arp_req = sr_arpcache_insert(&(sr->cache), new_arp_hdr->ar_sha, new_arp_hdr->ar_sip);
      int length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);

      char buffer[length];
      struct sr_ethernet_hdr* eth_ack = (struct sr_ethernet_hdr*)buffer;
      memcpy(eth_ack->ether_dhost, new_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_ack->ether_shost, local_interface->addr, ETHER_ADDR_LEN);
      eth_ack->ether_type = htons(ethertype_arp);
      struct sr_arp_hdr* arp_ack = (struct sr_arp_hdr*)(buffer + sizeof(struct sr_ethernet_hdr));
      arp_ack->ar_hrd = htons(arp_hrd_ethernet);
      arp_ack->ar_pro = new_arp_hdr->ar_pro;
      arp_ack->ar_hln = ETHER_ADDR_LEN;
      arp_ack->ar_pln = sizeof(uint32_t);
      arp_ack->ar_op = htons(arp_op_reply);
      memcpy(arp_ack->ar_sha, local_interface->addr, ETHER_ADDR_LEN);
      arp_ack->ar_sip = local_interface->ip;
      memcpy(arp_ack->ar_tha, new_arp_hdr->ar_sha, ETHER_ADDR_LEN);
      arp_ack->ar_tip = new_arp_hdr->ar_sip;
      sr_send_packet(sr, buffer, length, interface);
    } else if(new_arp_hdr->ar_op == htons(arp_op_reply)) {

      struct sr_arpreq *new_arp_req = sr_arpcache_insert(&(sr->cache), new_arp_hdr->ar_sha, new_arp_hdr->ar_sip);
      struct sr_packet* pkt;        
      struct sr_ethernet_hdr* eth_ack;

      for (pkt = new_arp_req->packets; pkt != NULL; pkt = pkt->next) {
          char buffer[pkt->len];
          memcpy(buffer, pkt->buf, pkt->len);
          eth_ack = (struct sr_ethernet_hdr*)buffer;
          memcpy(eth_ack->ether_dhost, new_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(eth_ack->ether_shost, local_interface->addr, ETHER_ADDR_LEN);
          eth_ack->ether_type = htons(ethertype_ip);
          sr_send_packet(sr, buffer, pkt->len, interface);
      }
      sr_arpreq_destroy(&(sr->cache), new_arp_req);

    } else {
      fprinf("error arp type\n");
    }


  } else if(new_hdr->ether_type == htons(ethertype_ip)) {
      handle_ip_packet(sr,packet,len,interface);
  } else {
      fprinf("error ethernet type\n");
  }
}/* end sr_ForwardPacket */

  void handle_ip_packet(struct sr_intance *sr,uint8_t *packet,unsigned int len,char *interface){
    assert(sr);
    assert(packet);
    assert(interface);
    
    //get ether_packet
    struct sr_ethernet_hdr *cur_eth_pkt=(struct sr_ethernet_hdr*) packet;
    //get ip_packet
    struct sr_ip_hdr *cur_ip_pkt=(struct sr_ip_hdr*)(packet+sizeof(struct sr_ethernet_hdr));
    //get interface_information
    struct sr_if *if_info=sr_get_interface(sr,interface);


    if(!is_pkt_valid(packet+sizeof(struct sr_ethernet_hdr),sizeof(struct sr_ip_hdr))){
      return;
    }else{
      //packet is for us
      if(to_us(sr,packet+sizeof(struct sr_ethernet_hdr))){
        //it is icmp_echo packet
        if(is_icmp_pkt_echo(packet+sizeof(sr_ethernet_hdr),ntohs(cur_ip_pkt->ip_len))){
          if(!is_icmp_valid(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr),ntohs(cur_eth_pkt->ip_len)-sizeof(struct sr_ip_hdr))){
            return;
          }
          uint8_t *echo_rply[len];
          set_ether_hdr(echo_rply,cur_eth_pkt->ether_shost,if_info->addr,ethertype_ip);
          set_ip_pkt(echo_rply+sizeof(struct sr_ethernet_hdr),5,4,0,ntohs(cur_ip_pkt->ip_len),
          ip_ind,0,64,ip_protocol_icmp,cur_ip_pkt->ip_dst,cur_ip_pkt->ip_src);
          ip_ind++;
          set_icmp_echo_hdr(echo_rply+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr),packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)
            htons(cur_ip_pkt->ip_len-sizeof(struct sr_icmp_hdr)));
          sr_send_packet(sr,echo_rply,len,interface);
        }
        //it is TCP /UDP packet and send back icmp3 unreachable info
        else{
          struct sr_rt * next_hop=find_next_hop(sr,cur_ip_pkt->ip_src);
          struct sr_if * src_if=sr_get_interface(sr,next_hop->interface);
          unsigned int buf_len=sizeof(sr_ethernet_hdr)+sizeof(sr_ip_hdr)+sizeof(sr_icmp_t3_hdr);
          uint8_t buf[buf_len];
          //要不要把源MAC地址修改成出口的MAC地址，还是保留原来的MAC地址
          set_ether_hdr(buf,cur_eth_pkt->ether_shost,if_info->addr,ethertype_ip);
          set_ip_pkt(buf+sizeof(struct sr_ethernet_hdr),5,4,0,buf_len-sizeof(sr_ethernet_hdr),ip_ind,0,64,ip_protocol_icmp,ntohl(src_if->ip),ntohl(cur_ip_pkt->ip_src));
          ip_ind++;
          //uint8_t *packet,uint8_t icmp_type,uint8_t icmp_code,uint16_t next_mtu,uint8_t *data
          set_icmp3_hdr(buf+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr),3,3,0/*mtu*/,packet+sizeof(struct sr_ethernet_hdr));
          sr_send_packet(sr,buf,buf_len,next_hop->interface);
          return;
        }
      }
      //pkt not for us, forward it
      else{
        struct sr_rt * next_hop=find_next_hop(sr,cur_ip_pkt->ip_src);
        //check ttl value
        if(cur_ip_pkt->ttl<=1){
          
          struct sr_if * src_if=sr_get_interface(sr,next_hop->interface);
          int buf_len=sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(sr_icmp_t3_hdr);
          uint8_t buf[buf_len];
          //set ethernet hdr
          //要不要把源MAC地址修改成出口的MAC地址，还是保留原来的MAC地址
          sr_ethernet_hdr(buf,cur_eth_pkt->ether_shost,cur_eth_pkt->ether_dhost,ethertype_ip);
          //set ip hdr
          set_ip_pkt(buf+sizeof(struct sr_ethernet_hdr),5,4,0,buf_len-sizeof(struct sr_ethernet_hdr),ip_ind,0,64,ip_protocol_icmp,ntohl(src_if->ip),ntohl(cur_ip_pkt->ip_src));
          id_ind++;
          //set icmp3 hdr
          set_icmp3_hdr(buf+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr),11,0,0/*mtu*/,packet+sizeof(struct sr_ethernet_hdr));
          sr_send_packet(sr,buf,buf_len,next_hop->interface);
          return;
        }
        //check next hop, next hop unreachable
        if(next_hop==NULL){
          
          int buf_len=sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(sr_icmp_t3_hdr);
          uint8_t buf[buf_len];
          //set ethernet hdr
          set_ether_hdr(buf,cur_eth_pkt->ether_shost,cur_eth_pkt->ether_dhost,ethertype_ip);
          //set ip hdr
          set_ip_pkt(buf+sizeof(struct sr_ethernet_hdr),5,4,0,buf_len-sizeof(struct sr_ethernet_hdr),ip_ind,0,64,ip_protocol_icmp,ntohl(src_if->ip),ntohl(cur_ip_pkt->ip_src));
          id_ind++;
          //set icmp3 hdr
          set_icmp3_hdr(buf+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr),3,0,0/*mtu*/,packet+sizeof(struct sr_ethernet_hdr));
          sr_send_packet(sr,buf,buf_len,next_hop->interface);
        }
        //next hop is available
        struct sr_if * src_if=sr_get_interface(sr,next_hop->interface);
        int buf_len=len;
        uint8_t buf[buf_len];
        memcpy(buf,packet,len);
        struct sr_ip_hdr* ip_to_send = (struct sr_ip_hdr*)(buf + sizeof(struct sr_ethernet_hdr));
        ip_to_send->ip_ttl--;
        ip_to_send->ip_sum = 0;
        ip_to_send->ip_sum = cksum(buf + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_ip_hdr));
        //老王你来写,查找arp cache
        struct sr_arpentry *next_hop_port=sr_arpcache_lookup(&sr->cache, next_hop->gw.s_addr);
        if(next_hop_port){
          set_ether_hdr(buf,next_hop_port->mac,src_if->addr,ethertype_ip);
          sr_send_packet(sr,buf,buf_len,next_hop->interface);
        }
        else {
            /* ethernet header is not changed */
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache),
                next_hop->gw.s_addr, buf, buf_len, next_hop->interface);
            //暂时定义成这个名字
            handle_arpreq(sr, req);
        }
      }
    } 
  }

  //judge that if the ip packet is valid
    bool is_pkt_valid(uint8_t *packet,unsigned int len){
      struct sr_ip_hdr *ip_tmp=(struct sr_ip_hdr*) packet;
      uint16_t pre_sum=ip_tmp->sum;
      ip_tmp->sum=0;
      if(pre_sum!=cksum(packet,len)){
        return false;
      }
      return true;
    }

    //judge that if the icmp packet is valid
    bool is_icmp_valid(uint8_t *packet,unsigned int len){
      struct sr_icmp_hdr *icmp_pkt=(struct sr_icmp_hdr*) packet;
      uint16_t pre_sum=icmp_pkt->icmp_sum;
      icmp_pkt->icmp_sum=0;
      if(pre_sum!=cksum(packet,len)){
        return false;
      }
      return true;
    }

    //judge if the packet destination is current hop
    bool to_us(struct sr_instance *sr,uint8_t *packet){
      assert(sr);
      assert(packet);

      struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)packet;
      struct sr_if* if_walker = NULL;

      for (if_walker = sr->if_list; if_walker != NULL; if_walker = if_walker->next) {
          if (if_walker->ip == ip_hdr->ip_dst) {
              return true;
          }
      }
      return false;
    }
    //judge is icmp packet or not
    bool is_icmp_pkt_echo(uint8_t *packet,unsigned int len){
       assert(packet);
       if(len<sizeof(struct sr_ip_hdr*)+sizeof(struct sr_icmp_hdr*)) return false;
       struct sr_ip_hdr *ip_tmp=(struct sr_ip_hdr*) packet;
       if(ip_tmp->ip_p!=icmp_protocol){
         return false;
       }
       return true;
    }

    //set ip_pkt
    void set_ip_pkt(uint8_t *packet,unsigned int ip_hl,unsigned int ip_v,uint8_t ip_tos,uint16_t ip_len,
    uint16_t ip_id,uint16_t ip_off,uint8_t ip_ttl,uint8_t ip_p,uint32_t ip_src,
    uint32_t ip_dst)
    {
      struct sr_ip_hdr* ip_tosend=(struct sr_ip_hdr*) packet;
      ip_tosend->ip_hl=ip_hl;
      ip_tosend->ip_v=ip_v;
      ip_tosend->ip_tos=ip_tos;
      ip_tosend->ip_len=htons(ip_len);
      ip_tosend->ip_id=htons(ip_id);
      ip_tosend->ip_off=htons(ip_off);
      ip_tosend->ip_ttl=ip_ttl;
      ip_tosend->ip_p=ip_p;
      ip_tosend->ip_sum=0;
      ip_tosend->ip_src=htonl(ip_src);
      ip_tosend->ip_dst=htonl(ip_dst);
    }
    //set icmp_echo reply hdr
    void set_icmp_echo_hdr(uint8_t *to_send,uint8_t *packet,int len){
      memcpy(to_send,packet,len);
      struct sr_icmp_hdr *icmp_echo_hdr=(struct sr_icmp_hdr*) to_send;
      icmp_echo_hdr->icmp_type=0;
      icmp_echo_hdr->icmp_code=0;
      icmp_echo_hdr->icmp_sum=0;
      icmp_echo_hdr->icmp_sum=cksum(to_send,len);
    }
    //set icmp3_hdr
    void set_icmp3_hdr(uint8_t *packet,uint8_t icmp_type,uint8_t icmp_code,uint16_t next_mtu,uint8_t *data){
      struct sr_icmp_t3_hdr *icmp3_hdr=(struct sr_icmp_t3_hdr *) packet;
      icmp3_hdr->icmp_type=icmp_type;
      icmp3_her->icmp_code=icmp_code;
      icmp3_hdr->icmp_sum=0;
      icmp3_hdr->unused=0;
      icmp3_hdr->next_mtu=htons(next_mtu);
      memcpy(icmp3_hdr->data,data,ICMP_DATA_SIZE);
    }
    //set ether hdr
    void set_ether_hdr(uint8_t *packet,uint8_t* ether_dhost,uint8_t *ether_shost,uint16_t ether_type){
      struct sr_ethernet_hdr *ether_tosend=(struct sr_ethernet_hdr *) packet;
      memcpy(ether_tosend->ether_shost,ether_shost,ETHER_ADDR_LEN);
      memcpy(ether_tosend->ether_dhost,ether_dhost?ether_dhost:0xFF,ETHER_ADDR_LEN);
      ether_tosend->ether_type=htons(ether_type);
    }

    //find next hop to forward
    struct sr_rt *find_next_hop(struct sr_intance *sr,uint32_t ip_dst){
      struct sr_rt *hop=NULL;
      uint32_t max=0;
      struct sr_rt *tar=NULL;
      for(hop=sr->routing_table;hop!=NULL;hop=hop->next){
        if(hop->dest.s_addr == (hop->mask.s_addr & ip_dst) && max<(hop->mask.s_addr)){
          tar=hop;
          max=(hop->mask.s_addr);
        }
      }
      return tar;
    }
 

