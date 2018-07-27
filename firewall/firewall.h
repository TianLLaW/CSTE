#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#if defined(CONFIG_PA_ONLINE_IP)
#define FILTER_RULE_NUM		10
#define PROTO_UNKNOWN	0
#define PROTO_TCP		1
#define PROTO_UDP		2
#define PROTO_TCP_UDP	3
#define PROTO_ICMP		4
#define PROTO_NONE		5


#define RULE_MODE_DISABLE	0
#define RULE_MODE_DROP		1
#define RULE_MODE_ACCEPT	2

#define ACTION_DROP		0
#define ACTION_ACCEPT	1

#define WEB_FILTER_CHAIN				"web_filter"
#define IPPORT_FILTER_CHAIN				"ipport_filter"
#define MAC_FILTER_CHAIN				"mac_filter"
#define MALICIOUS_FILTER_CHAIN			"malicious_filter"
#define SYNFLOOD_FILTER_CHAIN			"synflood_filter"
#define MALICIOUS_INPUT_FILTER_CHAIN	"malicious_input_filter"
#define SYNFLOOD_INPUT_FILTER_CHAIN		"synflood_input_filter"
#define L7_FILTER_CHAIN					"L7_filter"


#define DMZ_CHAIN				"DMZ"
#define PORT_FORWARD_CHAIN		"port_forward"

#define MAGIC_NUM			"IPCHAINS"	
#define DEBUG   1
#define LIVE_LIST "/proc/live_list"
struct bandwidth{
	int up;
	int down;
};

enum PRIORITYMODE{
	DEFAULT_MODE = 0,
	OFFICE_MODE,
	GAME_MODE,
	DOWNLOAD_MODE,
	ADVANCED_MODE
};

#define HTML_NO_FIREWALL_UNDER_BRIDGE_MODE	\
"<img src=\"/graphics/warning.gif\"><font color=#ff0000>&nbsp; &nbsp;Warning: The current operation mode is \"Bridge mode\" and these settings may not be functional.</font>"

int setFirewallType(struct mosquitto *mosq, cJSON* data, char *tp);
int getFirewallType(struct mosquitto *mosq, cJSON* data, char *tp);
int setIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setVpnPassCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getVpnPassCfg(struct mosquitto *mosq, cJSON* data, char *tp);
#if defined(CONFIG_USER_NBOX)
int setFirewallAdvCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getFirewallAdvCfg(struct mosquitto *mosq, cJSON* data, char *tp);
#endif
int setDMZCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getDMZCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int setDosCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getDosCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int setRemoteCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getRemoteCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int setScheduleRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getScheduleRules(struct mosquitto *mosq, cJSON* data, char *tp);	
int setIpQos(struct mosquitto *mosq, cJSON* data, char *tp);
int setIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setConnLimitRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delConnLimitRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getConnLimitRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setL7FilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int delL7FilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int getL7FilterRules(struct mosquitto *mosq, cJSON* data, char *tp);
int setQosPolicy(struct mosquitto *mosq, cJSON* data, char *tp);
int getQosPolicy(struct mosquitto *mosq, cJSON* data, char *tp);

int setAppById(struct mosquitto *mosq, cJSON* data, char *tp);
int getAppTypeList(struct mosquitto *mosq, cJSON* data, char *tp);
int getAppListById(struct mosquitto *mosq, cJSON* data, char *tp);
int setAppCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getAppCfg(struct mosquitto *mosq, cJSON* data, char *tp);

#endif



