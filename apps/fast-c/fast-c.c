#include "contiki.h"
#include "fast-c.h"
#include "net/packetbuf.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/rpl/rpl-private.h"
#include "net/rime/rime.h"

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

static void fast_c_packet_received(void);
static void fast_c_packet_sent(int mac_status);
RIME_SNIFFER(fast_c_sniffer, fast_c_packet_received, fast_c_packet_sent);

linkaddr_t fast_c_parent_linkaddr;
int fast_c_parent_knows_us = 0;
int current_hc;

#if FAST_C_EB_SEPERATE 
const struct fast_c_rule *all_rules[] = {&ebsf, &convergecast, &common};
const struct fast_c_rule *init_rules[] = {&ebsf, &common, &convergecast};
#else
const struct fast_c_rule *all_rules[] = {&convergecast, &common};
#endif
#define NUM_RULES (sizeof(all_rules) / sizeof(struct fast_c_rule *))

/*---------------------------------------------------------------------------*/
static void
fast_c_packet_received(void)
{
}
/*---------------------------------------------------------------------------*/
static void
fast_c_packet_sent(int mac_status)
{
  /* Check if our parent just ACKed a DAO */
  if(fast_c_parent_knows_us == 0
     && mac_status == MAC_TX_OK
     && packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID) == UIP_PROTO_ICMP6
     && packetbuf_attr(PACKETBUF_ATTR_CHANNEL) == (ICMP6_RPL << 8 | RPL_CODE_DAO)) {
    if(!linkaddr_cmp(&fast_c_parent_linkaddr, &linkaddr_null)
       && linkaddr_cmp(&fast_c_parent_linkaddr, packetbuf_addr(PACKETBUF_ADDR_RECEIVER))) {
      fast_c_parent_knows_us = 1;
    }
  }
}
/*---------------------------------------------------------------------------*/
void fast_c_init(void)
{
	int i;

	rime_sniffer_add(&fast_c_sniffer);
	linkaddr_copy(&fast_c_parent_linkaddr, &linkaddr_null);

	for(i = 0; i < NUM_RULES; i++) {
		if(init_rules[i]->init != NULL) {
			PRINTF("FAST-C: initializing rule %u\n", i);
			init_rules[i]->init(i);
		}
	}
	PRINTF("FAST-C: initialization done\n");
}
/*---------------------------------------------------------------------------*/
void fast_c_callback_packet_ready(void)
{
	int i;
	const linkaddr_t *oriSrc = packetbuf_addr(PACKETBUF_ADDR_ESENDER);

	/* By default, use any slotframe, any timeslot */
	uint16_t slotframe = 9;
	uint16_t timeslot = 0xffff;

	PRINTF("FAST-C: Origin Source Addr - %d %d %d %d %d %d %d %d\n", 
		oriSrc->u8[0], oriSrc->u8[1], oriSrc->u8[2], oriSrc->u8[3]
		, oriSrc->u8[4], oriSrc->u8[5], oriSrc->u8[6], oriSrc->u8[7]);
	
	for(i = 0; i < NUM_RULES; i++) {
		if(all_rules[i]->select_packet != NULL) {
			if(all_rules[i]->select_packet(&slotframe, &timeslot)) {
				break;
			}
		}
	}

#if TSCH_WITH_LINK_SELECTOR
  packetbuf_set_attr(PACKETBUF_ATTR_TSCH_SLOTFRAME, slotframe);
  packetbuf_set_attr(PACKETBUF_ATTR_TSCH_TIMESLOT, timeslot);
#endif
}
/*---------------------------------------------------------------------------*/
void fast_c_callback_new_time_source(const struct tsch_neighbor *old, const struct tsch_neighbor *new)
{
	int i;
	if(new != old) {
		fast_c_parent_knows_us = 0;
	}
	
	for(i = 0; i < NUM_RULES; i++) {
		if(all_rules[i]->new_time_source != NULL) {
			all_rules[i]->new_time_source(old, new);
		}
	}
}
/*---------------------------------------------------------------------------*/
void fast_c_callback_route_added(const uip_ipaddr_t *ipaddr)
{
	int i;
	linkaddr_t addr;
	memcpy(&addr, ipaddr->u8 + 8, UIP_LLADDR_LEN);
    addr.u8[0] ^= 0x02;
	for(i = 0; i < NUM_RULES; i++) {
		if(all_rules[i]->route_added != NULL) {
			all_rules[i]->route_added(&addr);
		}
	}
}
/*---------------------------------------------------------------------------*/
void fast_c_callback_route_removed(const uip_ipaddr_t *ipaddr)
{
	int i;
	linkaddr_t addr;
	memcpy(&addr, ipaddr->u8 + 8, UIP_LLADDR_LEN);
    addr.u8[0] ^= 0x02;
	for(i = 0; i < NUM_RULES; i++) {
		if(all_rules[i]->route_removed != NULL) {
			all_rules[i]->route_removed(&addr);
		}
	}
}
/*---------------------------------------------------------------------------*/
void fast_c_callback_hc_updated(const uint8_t hc)
{
	int i;
	for(i = 0; i < NUM_RULES; i++) {
		if(all_rules[i]->hc_updated != NULL) {
			all_rules[i]->hc_updated(hc);
		}
	}
	current_hc = hc;
}


