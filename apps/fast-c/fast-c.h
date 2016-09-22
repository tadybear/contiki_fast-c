#ifndef __FAST_C_H__
#define __FAST_C_H__

#include "net/mac/tsch/tsch.h"
#include "net/mac/tsch/tsch-conf.h"
#include "net/mac/tsch/tsch-schedule.h"
#include "fast-c_conf.h"

struct fast_c_rule {
  void (* init)(uint16_t slotframe_handle);
  void (* new_time_source)(const struct tsch_neighbor *old, const struct tsch_neighbor *new);
  int  (* select_packet)(uint16_t *slotframe, uint16_t *timeslot);
  void (* route_added)(const linkaddr_t *addr);
  void (* route_removed)(const linkaddr_t *addr);
  void (* hc_updated)(const uint8_t hc);
};

struct fast_c_rule convergecast;
struct fast_c_rule common;
struct fast_c_rule ebsf;

extern linkaddr_t fast_c_parent_linkaddr;
extern int fast_c_parent_knows_us;

void fast_c_init(void);
void fast_c_callback_packet_ready(void);
void fast_c_callback_new_time_source(const struct tsch_neighbor *old, const struct tsch_neighbor *new);
void fast_c_callback_route_added(const uip_ipaddr_t *ipaddr);
void fast_c_callback_route_removed(const uip_ipaddr_t *ipaddr);
void fast_c_callback_hc_updated(const uint8_t hc);

#endif
