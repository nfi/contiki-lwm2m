/*
 * Copyright (c) 2015, Yanzi Networks AB.
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup ipso-objects
 * @{
 */

/**
 * \file
 *         Implementation of OMA LWM2M / IPSO Power Control for
 *          Smart Plugs, etc.
 * \author
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 */

#include "lwm2m-object.h"
#include "lwm2m-engine.h"
#include "er-coap-engine.h"
#include <stdint.h>

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/* default to one power control */
#ifdef CONF_POWER_CONTROL_NUMBER
#define POWER_CONTROL_NUMBER CONF_POWER_CONTROL_NUMBER
#else
#define POWER_CONTROL_NUMBER 1
#endif

struct power_state {
  unsigned long last_on_time;
  uint32_t total_on_time;
  uint8_t is_on;
};

static struct power_state states[POWER_CONTROL_NUMBER];
static lwm2m_instance_t power_control_instances[POWER_CONTROL_NUMBER];
/*---------------------------------------------------------------------------*/
static int
read_state(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize)
{
  uint8_t idx = ctx->object_instance_index;
  if(idx >= POWER_CONTROL_NUMBER) {
    return 0;
  }
  return ctx->writer->write_boolean(ctx, outbuf, outsize,
                                    states[idx].is_on ? 1 : 0);
}
/*---------------------------------------------------------------------------*/
static int
write_state(lwm2m_context_t *ctx, const uint8_t *inbuf, size_t insize,
            uint8_t *outbuf, size_t outsize)
{
  int value;
  size_t len;

  uint8_t idx = ctx->object_instance_index;
  if(idx >= POWER_CONTROL_NUMBER) {
    return 0;
  }

  len = ctx->reader->read_boolean(ctx, inbuf, insize, &value);
  if(len > 0) {
    if(value) {
      if(!states[idx].is_on) {
        states[idx].is_on = 1;
        states[idx].last_on_time = clock_seconds();
#ifdef PLATFORM_POWER_CONTROL
	PLATFORM_POWER_CONTROL(idx, 1);
#endif
      }
    } else if(states[idx].is_on) {
      states[idx].total_on_time += clock_seconds() - states[idx].last_on_time;
      states[idx].is_on = 0;
#ifdef PLATFORM_POWER_CONTROL
	PLATFORM_POWER_CONTROL(idx, 0);
#endif
    }
  } else {
    PRINTF("IPSO power control - ignored illegal write to on/off\n");
  }
  return len;
}
/*---------------------------------------------------------------------------*/
static int
read_on_time(lwm2m_context_t *ctx, uint8_t *outbuf, size_t outsize)
{
  unsigned long now;
  uint8_t idx = ctx->object_instance_index;
  if(idx >= POWER_CONTROL_NUMBER) {
    return 0;
  }

  if(states[idx].is_on) {
    /* Update the on time */
    now = clock_seconds();
    states[idx].total_on_time += now - states[idx].last_on_time;
    states[idx].last_on_time = now;
  }
  return ctx->writer->write_int(ctx, outbuf, outsize, (int32_t)states[idx].total_on_time);
}
/*---------------------------------------------------------------------------*/
static int
write_on_time(lwm2m_context_t *ctx,
              const uint8_t *inbuf, size_t insize,
              uint8_t *outbuf, size_t outsize)
{
  int32_t value;
  size_t len;
  uint8_t idx = ctx->object_instance_index;
  if(idx >= POWER_CONTROL_NUMBER) {
    return 0;
  }

  len = ctx->reader->read_int(ctx, inbuf, insize, &value);
  if(len > 0 && value == 0) {
    PRINTF("IPSO power control - reset On Time\n");
    states[idx].total_on_time = 0;
    if(states[idx].is_on) {
      states[idx].last_on_time = clock_seconds();
    }
  } else {
    PRINTF("IPSO power control - ignored illegal write to On Time\n");
  }
  return len;
}
/*---------------------------------------------------------------------------*/
LWM2M_RESOURCES(power_control_resources,
                LWM2M_RESOURCE_CALLBACK(5850, { read_state, write_state, NULL }),
                LWM2M_RESOURCE_CALLBACK(5852, { read_on_time, write_on_time, NULL })
                );
LWM2M_OBJECT(power_control, 3312, power_control_instances);
/*---------------------------------------------------------------------------*/
void
ipso_power_control_init(void)
{
  lwm2m_instance_t template = LWM2M_INSTANCE(0, power_control_resources);
  int i;

  /* Initialize the instances */
  for(i = 0; i < POWER_CONTROL_NUMBER; i++) {
    power_control_instances[i] = template;
    power_control_instances[i].id = i;
  }

  /* register this device and its handlers - the handlers automatically
     sends in the object to handle */
  lwm2m_engine_register_object(&power_control);
  PRINTF("IPSO power control initialized\n");
}
/*---------------------------------------------------------------------------*/
/** @} */
