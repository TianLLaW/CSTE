
#ifndef _h_cloudupdate
#define _h_cloudupdate 1
#include "../cstelib.h"
#include <cs_comm.h>
#include "sigHd.h"


#define IP_ADDR_T 			0x02
#define NET_MASK_T 			0x04
#define HW_ADDR_T 			0x08

#define IFACE_FLAG_T 		0x01

int CloudACTimeSchedual(struct mosquitto *mosq, cJSON* data, char *tp);
int CloudSrvVersionCheck(struct mosquitto *mosq, cJSON* data, char *tp);


#endif /* _h_cloudupdate */
