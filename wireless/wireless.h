#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#if defined(SUPPORT_MESH)
typedef struct basicwifi{
	int majorMsg;
	int WiFiIdx;
	int addEffect;
	int BW;
	char SSID[64];
	char AuthMode[64];
	char EncrypType[64];
	char WEPKEY[128];
	char WPAPSK[128];
	int KeyFormat;
	int WirelessMode;
}BasicWifi_t,* BasicWifi_tp;

typedef struct advancedwifi{
	int WiFiIdx;
	int BGProtection;
	int BeaconPeriod;
	int DtimPeriod;
	int FragThreshold;
	int RTSThreshold;
	int TxPower;
	int NoForwarding;
	int WmmCapable;
	int HT_BSSCoexistence;
	int TxPreamble;
	int Beamforming;
}AdvancedWifi_t,* AdvancedWifi_tp;

static BasicWifi_t BasicWifi;
static AdvancedWifi_t AdvancedWifi;
//int setMinorDevBasicWiFi(struct mosquitto *mosq, cJSON* data, char *tp);
//int setMinorDevAdvancedWiFi(struct mosquitto *mosq, cJSON* data, char *tp);
//int getMinorDevInfo(struct mosquitto *mosq, cJSON* data, char *tp);
//int sendMinorDevInfo(struct mosquitto *mosq, cJSON* data, char *tp);
#endif

int setWebWlanIdx(struct mosquitto *mosq, cJSON* data, char *tp);
int getWebWlanIdx(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiStaInfo(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiApInfo(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiBasicConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiBasicConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiAdvancedConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiAdvancedConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#if defined (MBSSID)
int setWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int delWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#endif
int getWiFiAclAddConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiAclAddConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiAclDeleteConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiIpMacTable(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiApcliScan(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiWdsAddConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiWdsAddConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiWdsDeleteConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiRepeaterConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int setWiFiRepeaterConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getWiFiScheduleConfig(struct mosquitto * mosq,cJSON * data,char * tp);
int setWiFiScheduleConfig(struct mosquitto * mosq,cJSON * data,char * tp);

