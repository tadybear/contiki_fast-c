/*
 * Copyright (c) 2015, SICS Swedish ICT.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/**
 * \file
 *         A RPL+TSCH node able to act as either a simple node (6ln),
 *         DAG Root (6dr) or DAG Root with security (6dr-sec)
 *         Press use button at startup to configure.
 *
 * \author Simon Duquennoy <simonduq@sics.se>
 */

#include "contiki.h"
#include "node-id.h"
#include "net/rpl/rpl.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/mac/tsch/tsch.h"
#include "net/mac/tsch/tsch-asn.h"
#include "net/ip/uip-udp-packet.h"
#if WITH_ORCHESTRA
#include "orchestra.h"
#endif /* WITH_ORCHESTRA */
#if WITH_FAST_C
#include "fast-c.h"
#endif /* WITH_FAST_C */

#include "sys/energest.h"
#include "random.h"

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

/*---------------------------------------------------------------------------*/
PROCESS(node_process, "RPL Node");
AUTOSTART_PROCESSES(&node_process);

/*---------------------------------------------------------------------------*/
static int is_coordinator = 0;

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define UDP_EXAMPLE_ID  190
static struct uip_udp_conn *server_conn;
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
static int seq_id = 0;

/*---------------------------------------------------------------------------*/
typedef struct _app_packet
{
int seq_id;
int hc;
struct asn_t asn;
}APP_PACKET;

extern int tsch_packet_memb_numfree_min;
extern int tsch_packet_memb_alloc_fail;

extern int current_hc;
extern struct asn_t current_asn;

unsigned long begin_cpu, begin_lpm, begin_transmit, begin_listen;
unsigned long end_cpu, end_lpm, end_transmit, end_listen;

int arrLastSeq[36];
int arrRecvCnt[36];

static void print_network_status(void);

#ifdef APP_RPL_HOP_COUNT_VAL
int current_hc;

void app_callback_hc_updated(const uint8_t hc)
{
	current_hc = hc;
}

#endif

uint8_t nbr_table_num_neighbors();
static void
print_last(void)
{
	int i;
	int neighbor_num;
	neighbor_num = nbr_table_num_neighbors();
	if(is_coordinator) {
		for(i=0; i<36; i++) {
			printf("#CD %d %d\n", i+2, arrRecvCnt[i]);
		}
		printf("#FM %d %d %d %d %d %d\n", 
			node_id, current_hc, neighbor_num, uip_ds6_route_num_routes(), tsch_packet_memb_numfree_min, tsch_packet_memb_alloc_fail);
		printf("#FIN\n");
	}
	else {
		end_cpu = energest_type_time(ENERGEST_TYPE_CPU);
		end_lpm = energest_type_time(ENERGEST_TYPE_LPM);
		end_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
		end_listen = energest_type_time(ENERGEST_TYPE_LISTEN);
		
		printf("#FM %d %lu %lu %lu %lu %lu %lu %lu %lu %d %d %d %d %d\n", 
			node_id, begin_cpu, begin_lpm, begin_transmit, begin_listen,
			end_cpu, end_lpm, end_transmit, end_listen, current_hc, neighbor_num, uip_ds6_route_num_routes(), tsch_packet_memb_numfree_min, tsch_packet_memb_alloc_fail);
	}
}
/*---------------------------------------------------------------------------*/

static void
tcpip_handler(void)
{
	APP_PACKET *packet;
	int sender;

	if(uip_newdata()) {
		packet = (APP_PACKET *)uip_appdata;
		sender = UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1];
		if(arrLastSeq[sender-2] != packet->seq_id) {
			arrLastSeq[sender-2] = packet->seq_id;
			arrRecvCnt[sender-2]++;
		}
		printf("#DR %d %d %d %lu\n", 
			sender, packet->seq_id, packet->hc, ASN_DIFF(current_asn, packet->asn));		
	}
}
/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
	APP_PACKET packet;
	
	packet.seq_id = seq_id++;
	packet.hc = current_hc;
	memcpy(&packet.asn, &current_asn, sizeof(struct asn_t));
	
	printf("#DS %d %d, %d %d %lu\n",
         server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], sizeof(APP_PACKET), packet.seq_id, packet.hc, packet.asn.ls4b);
	uip_udp_packet_sendto(client_conn, &packet, sizeof(APP_PACKET),
						&server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}

/*---------------------------------------------------------------------------*/
static void
net_init(uip_ipaddr_t *br_prefix)
{
  uip_ipaddr_t global_ipaddr;

  if(br_prefix) { /* We are RPL root. Will be set automatically
                     as TSCH pan coordinator via the tsch-rpl module */
    memcpy(&global_ipaddr, br_prefix, 16);
    uip_ds6_set_addr_iid(&global_ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&global_ipaddr, 0, ADDR_AUTOCONF);
    rpl_set_root(RPL_DEFAULT_INSTANCE, &global_ipaddr);
    rpl_set_prefix(rpl_get_any_dag(), br_prefix, 64);
    rpl_repair_root(RPL_DEFAULT_INSTANCE);

    printf("Coordinator address ");
    PRINT6ADDR(&global_ipaddr);
    printf("\n");  
}

  NETSTACK_MAC.on();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(node_process, ev, data)
{
  static struct etimer et;
  static struct etimer rt;
  PROCESS_BEGIN();

  random_init(node_id);
  /* 3 possible roles:
     * - role_6ln: simple node, will join any network, secured or not
     * - role_6dr: DAG root, will advertise (unsecured) beacons
     * - role_6dr_sec: DAG root, will advertise secured beacons
     * */
  static enum { role_6ln, role_6dr, role_6dr_sec } node_role;
  node_role = role_6ln;
  
  /* Set node with ID == 1 as coordinator, convenient in Cooja. */
  if(node_id == 1) {
    if(LLSEC802154_ENABLED) {
      node_role = role_6dr_sec;
    } else {
      node_role = role_6dr;
    }
  } else {
    node_role = role_6ln;
  }

  printf("Init: node starting with role %s\n",
      node_role == role_6ln ? "6ln" : (node_role == role_6dr) ? "6dr" : "6dr-sec");

  tsch_set_pan_secured(LLSEC802154_ENABLED && (node_role == role_6dr_sec));
  is_coordinator = node_role > role_6ln;

  if(is_coordinator) {
    uip_ipaddr_t prefix;
    uip_ip6addr(&prefix, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    net_init(&prefix);
  } else {
    net_init(NULL);
  }
#if WITH_FAST_C
printf("It's FAST-C\n");
  fast_c_init();
#endif /* WITH_FAST_C */
  
#if WITH_ORCHESTRA
printf("It's Orchestra\n");
  orchestra_init();
#endif /* WITH_ORCHESTRA */
  
  /* Print out routing tables every minute */
  if(!is_coordinator) {
	  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
	  if(client_conn == NULL) {
	    PRINTF("No UDP connection available, exiting the process!\n");
	    PROCESS_EXIT();
	  }
	  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

	  printf("Created a connection with the server ");
	  //PRINT6ADDR(&client_conn->ripaddr);
	  printf(" local/remote port %u/%u\n",
		UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));
			
	  // for jn516x  
	  uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x215, 0x8d00, 0x35, 1);
	  // for cooja
	  //uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 1);
	  printf("Server Address: ");
	  PRINT6ADDR(&server_ipaddr);
	  printf("\n");

	  etimer_set(&et, (CLOCK_SECOND * 60 * 15) + (random_rand() % (3 * CLOCK_SECOND)));	  
	  etimer_set(&rt, CLOCK_SECOND * 60);
	  while(1) {
		PROCESS_YIELD();

		if(etimer_expired(&et)) {
			if(seq_id == 0) {
				printf("Start send packet\n");

				begin_cpu = energest_type_time(ENERGEST_TYPE_CPU);
				begin_lpm = energest_type_time(ENERGEST_TYPE_LPM);
				begin_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
				begin_listen = energest_type_time(ENERGEST_TYPE_LISTEN);
				
				seq_id = 1;
				etimer_set(&et, CLOCK_SECOND * 3);
			}
			else {
				if(seq_id < SEND_CNT+1) {
					send_packet(NULL);
					//PROCESS_YIELD_UNTIL(etimer_expired(&et));
					etimer_reset(&et);
				}
				else {
					print_last();
					break;
				}
			}
		}
		if(etimer_expired(&rt)) {
			print_network_status();
			etimer_reset(&rt);
		}
	  }
  }
  else {
	  memset(arrLastSeq, 0, sizeof(int)*36);
	  memset(arrRecvCnt, 0, sizeof(int)*36);

	  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
	  if(server_conn == NULL) {
		PRINTF("No UDP connection available, exiting the process!\n");
		PROCESS_EXIT();
	  }
	  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

	  printf("Created a server connection with remote address ");
	  //PRINT6ADDR(&server_conn->ripaddr);
	  printf(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
			 UIP_HTONS(server_conn->rport));
		  
		  
	  etimer_set(&et, CLOCK_SECOND * ((3*SEND_CNT) + (60*16)));
	  etimer_set(&rt, CLOCK_SECOND * 60);
	  while(1) {      
		PROCESS_YIELD();
		if(ev == tcpip_event) {
		  tcpip_handler();
		}
		if(etimer_expired(&rt)) {
			print_network_status();
			etimer_reset(&rt);
		}
		if(etimer_expired(&et)) {
			print_last();
			break;
		}
	  }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/





/*---------------------------------------------------------------------------*/
static void
print_network_status(void)
{
  int i;
  uint8_t state;
  uip_ds6_defrt_t *default_route;
  uip_ds6_route_t *route;

  PRINTA("--- Network status ---\n");
  
  /* Our IPv6 addresses */
  PRINTA("- Server IPv6 addresses:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINTA("-- ");
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTA("\n");
    }
  }
  
  /* Our default route */
  PRINTA("- Default route:\n");
  default_route = uip_ds6_defrt_lookup(uip_ds6_defrt_choose());
  if(default_route != NULL) {
    PRINTA("-- ");
    uip_debug_ipaddr_print(&default_route->ipaddr);;
    PRINTA(" (lifetime: %lu seconds)\n", (unsigned long)default_route->lifetime.interval);
  } else {
    PRINTA("-- None\n");
  }

  /* Our routing entries */
  PRINTA("- Routing entries (%u in total):\n", uip_ds6_route_num_routes());
  route = uip_ds6_route_head();
  while(route != NULL) {
    PRINTA("-- ");
    uip_debug_ipaddr_print(&route->ipaddr);
    PRINTA(" via ");
    uip_debug_ipaddr_print(uip_ds6_route_nexthop(route));
    PRINTA(" (lifetime: %lu seconds)\n", (unsigned long)route->state.lifetime);
    route = uip_ds6_route_next(route); 
  }
  
  PRINTA("----------------------\n");
  //tsch_schedule_print();
}

