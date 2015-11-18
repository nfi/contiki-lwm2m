/*
 * Copyright (c) 2015, Yanzi Networks AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      IPSO Objects and OMA LWM2M example.
 * \author
 *      Joakim Eriksson, joakime@sics.se
 *      Niclas Finne, nfi@sics.se
 */

#include "contiki.h"
#include "net/ip/uip.h"
#include "net/rpl/rpl.h"
#include "net/netstack.h"
#include "er-coap-constants.h"
#include "er-coap-engine.h"
#include "lwm2m-engine.h"

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

static const char *service_urls[] =
  { ".well-known/core", "/3/0/3", "/3/0/1" };

#define MAX_NODES 10

#define NODE_HAS_TYPE  (1 << 0)

struct node {
  uip_ipaddr_t ipaddr;
  char type[32];
  uint8_t flags;
  uint8_t retries;
};
static struct node nodes[MAX_NODES];
static uint8_t node_count;

static struct node *current_target;

PROCESS(router_process, "router process");
AUTOSTART_PROCESSES(&router_process);
/*---------------------------------------------------------------------------*/
static struct node *
add_node(const uip_ipaddr_t *addr)
{
  int i;
  for(i = 0; i < node_count; i++) {
    if(uip_ipaddr_cmp(&nodes[i].ipaddr, addr)) {
      /* Node already added */
      return &nodes[i];
    }
  }
  if(node_count < MAX_NODES) {
    uip_ipaddr_copy(&nodes[node_count].ipaddr, addr);
    return &nodes[node_count++];
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
/**
 * This function is will be passed to COAP_BLOCKING_REQUEST() to
 * handle responses.
 */
static void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;
  int len = coap_get_payload(response, &chunk);
  printf("|%.*s", len, (char *)chunk);
  if(current_target != NULL) {
    if(len > sizeof(current_target->type) - 1) {
      len = sizeof(current_target->type) - 1;
    }
    memcpy(current_target->type, chunk, len);
    current_target->type[len] = 0;
    current_target->flags |= NODE_HAS_TYPE;

    PRINTF("\nNODE ");
    PRINT6ADDR(&current_target->ipaddr);
    PRINTF(" HAS TYPE %s\n", current_target->type);
  }
}
/*---------------------------------------------------------------------------*/
static void
setup_network(void)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;
  rpl_dag_t *dag;
  int i;
  uint8_t state;

#if UIP_CONF_ROUTER
/**
 * The choice of server address determines its 6LoWPAN header compression.
 * Obviously the choice made here must also be selected in udp-client.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 * Note Wireshark's IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from link local (MAC) address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
#endif

  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
#endif /* UIP_CONF_ROUTER */

  PRINTF("IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(router_process, ev, data)
{
  /* This way the packet can be treated as pointer as usual. */
  static coap_packet_t request[1];
  static struct etimer timer;
  uip_ds6_route_t *r;
  uip_ipaddr_t *nexthop;
  int n;

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  /* receives all CoAP messages */
  coap_init_engine();

  setup_network();

  /* The data sink runs with a 100% duty cycle in order to ensure high
     packet reception rates. */
  NETSTACK_MAC.off(1);

  etimer_set(&timer, CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();

    if(ev == PROCESS_EVENT_TIMER && etimer_expired(&timer)) {
      etimer_restart(&timer);

      current_target = NULL;
      n = 0;
      for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
        current_target = add_node(&r->ipaddr);
        if(current_target == NULL ||
           (current_target->flags & NODE_HAS_TYPE) != 0 ||
           current_target->retries > 5) {
          continue;
        }
        PRINTF("  ");
        PRINT6ADDR(&r->ipaddr);
        PRINTF("  ->  ");
        nexthop = uip_ds6_route_nexthop(r);
        if(nexthop != NULL) {
          PRINT6ADDR(nexthop);
          PRINTF("\n");
        } else {
          PRINTF("-");
        }
        PRINTF("\n");
        n++;
        break;
      }
      PRINTF("Found %u new routes\n", n);

      if(current_target != NULL &&
         (current_target->flags & NODE_HAS_TYPE) == 0 &&
         current_target->retries < 6) {
        /* prepare request, TID is set by COAP_BLOCKING_REQUEST() */
        coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
        coap_set_header_uri_path(request, service_urls[2]);

        current_target->retries++;
        /* const char msg[] = "Toggle!"; */
        /* coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1); */

        PRINTF("CoAP request to ");
        PRINT6ADDR(&current_target->ipaddr);
        PRINTF(" : %u (%u tx)\n", UIP_HTONS(REMOTE_PORT),
               current_target->retries);

        COAP_BLOCKING_REQUEST(&current_target->ipaddr, REMOTE_PORT, request,
                              client_chunk_handler);

        printf("\n--Done--\n");
      }
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
