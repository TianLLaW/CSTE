#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"
#include "mibtbl.h"

int setVlanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getVlanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setVlan8021Q_Config(struct mosquitto *mosq, cJSON* data, char *tp);
int getVlan8021Q_Config(struct mosquitto *mosq, cJSON* data, char *tp);
int getOtherConfig(struct mosquitto *mosq, cJSON* data, char *tp);
