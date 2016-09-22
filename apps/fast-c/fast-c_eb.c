#include "contiki.h"
#include "fast-c.h"

static uint16_t slotframe_handle = 0;
static uint16_t channel_offset = 0;
static struct tsch_slotframe *sf_eb;

static uint8_t get_ch_offset(uint8_t isTx, uint8_t ori_chOffset)
{
	uint8_t ret;
	if(isTx)       
		ret = ori_chOffset+(sf_eb->slide_hc)/2;
	else
		ret = ori_chOffset+(sf_eb->slide_hc-1)/2;
	return ret;
}
static uint16_t
get_node_id(const linkaddr_t *addr)
{
  return (addr)->u8[LINKADDR_SIZE - 1];
}

static int select_packet(uint16_t *slotframe, uint16_t *timeslot)
{
  /* Select EBs only */
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) == FRAME802154_BEACONFRAME) {
    if(slotframe != NULL) {
      *slotframe = slotframe_handle;
    }
    if(timeslot != NULL) {
      *timeslot = get_node_id(&linkaddr_node_addr)*2;
    }
    return 1;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void init(uint16_t sf_handle)
{
  slotframe_handle = sf_handle;
  channel_offset = 1;

  sf_eb = tsch_schedule_add_slotframe(slotframe_handle, FAST_C_EB_PERIOD);
  sf_eb->slide_hc = 1;
  sf_eb->cal_ch_offset = get_ch_offset;
  /* EB link: every neighbor uses its own to avoid contention */
  tsch_schedule_add_link(sf_eb,
                         LINK_OPTION_TX,
                         LINK_TYPE_ADVERTISING_ONLY, &tsch_broadcast_address,
                         get_node_id(&linkaddr_node_addr)*2, channel_offset);
}
/*---------------------------------------------------------------------------*/
static void new_time_source(const struct tsch_neighbor *old, const struct tsch_neighbor *new)
{
  uint16_t old_ts = old != NULL ? get_node_id(&old->addr) : 0xffff;
  uint16_t new_ts = new != NULL ? get_node_id(&new->addr) : 0xffff;

  if(new_ts == old_ts) {
    return;
  }

  if(old_ts != 0xffff) {
    tsch_schedule_remove_link_by_timeslot(sf_eb, old_ts*2+1);
  }
  if(new_ts != 0xffff) {
    tsch_schedule_add_link(sf_eb, LINK_OPTION_RX, LINK_TYPE_ADVERTISING_ONLY,
      &tsch_broadcast_address, new_ts*2+1, channel_offset);
  }
}
static void hc_updated(const uint8_t hc)
{
	sf_eb->slide_hc = hc;
}
/*---------------------------------------------------------------------------*/
struct fast_c_rule ebsf = {
  init,
  new_time_source,
  select_packet,
  NULL,
  NULL,
  hc_updated,
};
