#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#if defined(SUPPORT_MESH)
typedef struct ntpConfig{
	char time_zone[32];
	char NTPServerIP[128];
	int NTPClientEnabled;
}ntpConfig_t,* ntpConfig_tp;

static ntpConfig_t ntpConfig;
#endif

int setPasswordCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getPasswordCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getDDNSStatus(struct mosquitto *mosq, cJSON* data, char *tp);
int setDDNSCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getDDNSCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int showSyslog(struct mosquitto *mosq, cJSON* data, char *tp);
int clearSyslog(struct mosquitto *mosq, cJSON* data, char *tp);
int setSyslogCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getSyslogCfg(struct mosquitto *mosq, cJSON* data, char *tp);
#if defined(CONFIG_APP_MINI_UPNP)
int setMiniUPnPConfig(struct mosquitto *mosq, cJSON* data, char *tp);
int getMiniUPnPConfig(struct mosquitto *mosq, cJSON* data, char *tp);
#endif
int LoadDefSettings(struct mosquitto *mosq, cJSON* data, char *tp);
int RebootSystem(struct mosquitto *mosq, cJSON* data, char *tp);
int SystemSettings(struct mosquitto *mosq, cJSON* data, char *tp);
int FirmwareUpgrade(struct mosquitto *mosq, cJSON* data, char *tp);
#if defined(CONFIG_SUPPORT_SCHEDULE_REBOOT)
int setRebootScheCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getRebootScheCfg(struct mosquitto *mosq, cJSON* data, char *tp);
#endif
