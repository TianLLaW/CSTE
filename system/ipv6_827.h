#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#define _IPV6_RADVD_SCRIPT_PROG "radvd.sh"
#define _IPV6_DNSMASQ_SCRIPT_PROG "dnsv6.sh"
#define _IPV6_DHCPV6S_SCRIPT_PROG "dhcp6s"
#define _IPV6_LAN_INTERFACE "br0"
#define _IPV6_WAN_INTERFACE "eth1"
#define uint16 unsigned short
#define uint8 unsigned char
#define IPV6_ROUTE_PROC "/proc/net/ipv6_route" 
#define IPV6_ADDR_PROC "/proc/net/if_inet6"
#define DNSV6_ADDR_FILE	"/var/dns6.conf"
#define DNSV6_RESOLV_FILE "/var/dnsmasq_resolv.conf"

int setIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp);
int getIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp);
int setIPv6RadvdCfg(struct mosquitto *mosq, cJSON* data, char *tp);



