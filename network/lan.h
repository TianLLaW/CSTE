#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"
#include "mibtbl.h"

int setLanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getLanConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getDhcpCliList(struct mosquitto *mosq, cJSON* data, char *tp);
int getArpTable(struct mosquitto *mosq, cJSON* data, char *tp);
int setStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int delStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#if defined(CONFIG_APP_IGMPPROXY)
int setIgmpConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getIgmpConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#endif
#if defined(CONFIG_SUPPORT_ETH_SPEED)
int setEthSpeedConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getEthSpeedConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#endif

