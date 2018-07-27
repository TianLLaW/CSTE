#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#define	FILE_WSCD_STATUS	"/tmp/wscd_status"

enum WPSSTAT {
	WPS_START,
	WPS_RUNNING,
	MESH_START,
	MESH_RUNNING,

	WPS_IDLE=4,	
	MESH_SUCC,
	WPS_SUCC,	
	WPS_FAIL,
	MESH_FAIL,
	WPS_TIMEOUT
};

int getWiFiWpsSetupConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiWpsSetupConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int csWps(struct mosquitto *mosq, cJSON* data, char *tp);
int getWscMeshStatus(struct mosquitto *mosq, cJSON* data, char *tp);


