#include "contiki.h"
#include "net/ip/uip.h"
#include "net/ip/uiplib.h"
#include <stdio.h>

void print_node_list(void);
void set_value(const uip_ipaddr_t *addr, char *uri, char *value);
void get_value(const uip_ipaddr_t *addr, char *uri);

int
find_next_sep(char *str, char sep, int pos)
{
  char c;
  while((c = str[pos]) != 0) {
    if(c == sep) return pos + 1;
    pos++;
  }
  return -1;
}

/*
 * l - list all discovered devices
 * s - set <IP> <URI> <value>
 * d - get <IP> <URI>
 *
 */
void
serial_protocol_input(char *data)
{
  /* We assume that we have a string here */
  char cmd = data[0];
  int pos = 0;

  switch(cmd) {
  case 'l':
    /* list devices */
    print_node_list();
    break;
  case 's': {
    uip_ip6addr_t ipaddr;
    char *uri;
    char *value;
    pos = find_next_sep(data, ' ', pos);
    if(pos > 0) {
      /* start of IP */
      int start = pos;
      pos = find_next_sep(data, ' ', pos);
      if(pos == -1) return;
      data[pos - 1] = 0;
      if(uiplib_ip6addrconv((const char *) &data[start], &ipaddr) == 0) {
        printf("* Error not valid IP\n");
      }
      uri = &data[pos];
      pos = find_next_sep(data, ' ', pos);
      if(pos == -1) return;
      data[pos - 1] = 0;
      value = &data[pos];
      /* set the value at the specified node */
      set_value(&ipaddr, uri, value);
    }
    break;
  }
  case 'g': {
    uip_ip6addr_t ipaddr;
    char *uri;
    pos = find_next_sep(data, ' ', pos);
    if(pos > 0) {
      /* start of IP */
      int start = pos;
      pos = find_next_sep(data, ' ', pos);
      if(pos == -1) return;
      data[pos - 1] = 0;
      if(uiplib_ip6addrconv((const char *) &data[start], &ipaddr) == 0) {
        printf("* Error not valid IP\n");
      }
      uri = &data[pos];
      /* get the value at the specified node */
      get_value(&ipaddr, uri);
    }
    break;
  }
  default:
    printf("Unknown command\n");
  }
}
