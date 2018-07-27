#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"


int getUsbStorageCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int setUsbStorageCfg(struct mosquitto *mosq, cJSON* data, char *tp);
