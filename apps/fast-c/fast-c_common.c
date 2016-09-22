#include "contiki.h"
#include "fast-c.h"

static uint16_t slotframe_handle = 0;
static uint16_t channel_offset = 0;

static int select_packet(uint16_t *slotframe, uint16_t *timeslot)
{
  if(slotframe != NULL) {
    *slotframe = slotframe_handle;
  }
  if(timeslot != NULL) {
    *timeslot = 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static void init(uint16_t sf_handle)
{
  slotframe_handle = sf_handle;
  channel_offset = 0;

  struct tsch_slotframe *sf_common = tsch_schedule_add_slotframe(slotframe_handle, FAST_C_COMMON_PERIOD);
#if FAST_C_EB_SEPERATE 
  tsch_schedule_add_link(sf_common,
      LINK_OPTION_RX | LINK_OPTION_TX | LINK_OPTION_SHARED,
      LINK_TYPE_NORMAL, &tsch_broadcast_address,
      0, channel_offset);
#else      
  tsch_schedule_add_link(sf_common,
      LINK_OPTION_RX | LINK_OPTION_TX | LINK_OPTION_SHARED,
      LINK_TYPE_ADVERTISING, &tsch_broadcast_address,
      0, channel_offset);      
#endif      
}
/*---------------------------------------------------------------------------*/
struct fast_c_rule common = {
  init,
  NULL,
  select_packet,
  NULL,
  NULL,
  NULL,
};
