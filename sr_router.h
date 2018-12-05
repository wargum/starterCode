/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};
static uint16_t ip_ind = 0;

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/*--the function defined by us--*/
bool is_pkt_valid(uint8_t *packet,unsigned int len);
bool is_icmp_valid(uint8_t *packet,unsigned int len);
bool to_us(struct sr_instance *sr,uint8_t *packet);
bool is_icmp_pkt_echo(uint8_t *packet,unsigned int len);
void set_ip_pkt(uint8_t *packet,unsigned int ip_hl,unsigned int ip_v,uint8_t ip_tos,uint16_t ip_len,
    uint16_t ip_id,uint16_t ip_off,uint8_t ip_ttl,uint8_t ip_p,uint32_t ip_src,
    uint32_t ip_dst);
void set_icmp_echo_hdr(uint8_t *to_send,uint8_t *packet,int len);
void set_icmp3_hdr(uint8_t *packet,uint8_t icmp_type,uint8_t icmp_code,uint16_t next_mtu,uint8_t *data);
void set_ether_hdr(uint8_t *packet,uint8_t* ether_dhost,uint8_t *ether_shost,uint16_t ether_type);
void handle_ip_packet(struct sr_intance *sr,uint8_t *packet,unsigned int len,char *interface);
struct sr_rt *find_next_hop(struct sr_intance *sr,uint32_t ip_dst);
#endif /* SR_ROUTER_H */
