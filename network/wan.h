#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"


int setWanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWanDnsConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getStationMacByIp(struct mosquitto *mosq, cJSON* data, char *tp);


