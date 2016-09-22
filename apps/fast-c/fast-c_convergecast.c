#include "contiki.h"
#include "fast-c.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/packetbuf.h"

static uint16_t slotframe_handle = 0;
static uint16_t channel_offset = 0;
static struct tsch_slotframe *sf_converge;

static uint8_t get_ch_offset(uint8_t isTx, uint8_t ori_chOffset)
{
	uint8_t ret;
	if(isTx)       
		ret = ori_chOffset+(sf_converge->slide_hc-1)/2;
	else
		ret = ori_chOffset+(sf_converge->slide_hc)/2;
	return ret;
}
/*---------------------------------------------------------------------------*/
static uint16_t
get_node_id(const linkaddr_t *addr)
{
  return (addr)->u8[LINKADDR_SIZE - 1];
}
/*---------------------------------------------------------------------------*/
static void
add_conv_link(const linkaddr_t *linkaddr)
{
	if(linkaddr != NULL) {
		uint16_t timeslot = get_node_id(linkaddr);

    /* Add/update link */
		tsch_schedule_add_link(sf_converge, LINK_OPTION_RX, LINK_TYPE_NORMAL, 
				&tsch_broadcast_address, timeslot*2, channel_offset);
		if(!linkaddr_cmp(&fast_c_parent_linkaddr, &linkaddr_null))
			tsch_schedule_add_link(sf_converge, LINK_OPTION_TX, LINK_TYPE_NORMAL, 
					&tsch_broadcast_address, timeslot*2+1, channel_offset);
				//&fast_c_parent_linkaddr, timeslot*2+1, channel_offset);
	}
}
/*---------------------------------------------------------------------------*/
static void
remove_conv_link(const linkaddr_t *linkaddr)
{
	uint16_t timeslot;
	struct tsch_link *rl;
	struct tsch_link *tl;

	if(linkaddr == NULL) {
		return;
	}

	timeslot = get_node_id(linkaddr);
	rl = tsch_schedule_get_link_by_timeslot(sf_converge, timeslot*2);
	tl = tsch_schedule_get_link_by_timeslot(sf_converge, timeslot*2+1);

	if(rl != NULL)
		tsch_schedule_remove_link(sf_converge, rl);
	if(tl != NULL)
		tsch_schedule_remove_link(sf_converge, tl);
}

static void init(uint16_t sf_handle)
{
	slotframe_handle = sf_handle;
	channel_offset = 1;

	sf_converge = tsch_schedule_add_slotframe(slotframe_handle, FAST_C_CONVERGECAST_PERIOD);  
	sf_converge->slide_hc = 1;
	sf_converge->cal_ch_offset = get_ch_offset;
}

static void new_time_source(const struct tsch_neighbor *old, const struct tsch_neighbor *new)
{
	uint16_t timeslot = get_node_id(&linkaddr_node_addr);	
	struct tsch_link *tl = tsch_schedule_get_link_by_timeslot(sf_converge, timeslot*2+1);

	if(new != old) {
		const linkaddr_t *new_addr = new != NULL ? &new->addr : NULL;
		if(new_addr != NULL) {
			linkaddr_copy(&fast_c_parent_linkaddr, new_addr);
			tsch_schedule_add_link(sf_converge, LINK_OPTION_TX, LINK_TYPE_NORMAL, 
					&tsch_broadcast_address, timeslot*2+1, channel_offset);			
					//&fast_c_parent_linkaddr, timeslot*2+1, channel_offset);
		} else {
			linkaddr_copy(&fast_c_parent_linkaddr, &linkaddr_null);
			if(old != NULL)
				tsch_schedule_remove_link(sf_converge, tl);
		}
	}
}
static int  select_packet(uint16_t *slotframe, uint16_t *timeslot)
{
	const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
	const linkaddr_t *oriSrc = packetbuf_addr(PACKETBUF_ADDR_ESENDER);
	uint16_t nid;
	
	if(fast_c_parent_knows_us == 0) return 0;
	if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_DATAFRAME 
		&& linkaddr_cmp(dest, &fast_c_parent_linkaddr) && !linkaddr_cmp(oriSrc,&linkaddr_null)) {
		
		nid = get_node_id(oriSrc);	
		*slotframe = slotframe_handle;
		*timeslot = nid*2+1;
		
		return 1;
	}
	return 0;
}
static void route_added(const linkaddr_t *addr)
{
	add_conv_link(addr);
}
static void route_removed(const linkaddr_t *addr)
{
	remove_conv_link(addr);
}
static void hc_updated(const uint8_t hc)
{
	sf_converge->slide_hc = hc;
}

struct fast_c_rule convergecast = {
  init,
  new_time_source,
  select_packet,
  route_added,
  route_removed,
  hc_updated,
};
