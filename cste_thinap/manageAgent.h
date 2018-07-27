#ifndef __MANAGEAGENT__
#define __MANAGEAGENT__

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/socket.h>
#include "cJSON.h"
#include "jobqueen.h"
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include "apmib.h"
#include "mibtbl.h"
#include "apmib.h"
#include "sigHd.h"


#define CSTE_BIND_SIG 40

#define SMALL_BUF_SIZE  8

#define TEMP_BUF_SIZE 128

#define CMD_BUF_SIZE 256

#define MAX_BUF_SIZE 4096

#define FW_CREATE   0

#define HEART_BEAT_INTERVAL  30

#define AUTO_BROADCAST_INTERVAL  120

#define MAX_HEART_BEAT_INTERVAL 300

#define MAX_HEART_BEAT_COUNT    9

#define DEFAULT_HTTP_PORT   80

#define DEFAULT_GATEWAY_PORT 8080

#define SESSIONOVER "SessionOver"

#define ACVERSION "1.0"

#define CSTE_MAC_LEN    6

#define CSTE_IP_LEN    4

#define CSTE_MAC_STR_LEN    18

#define CSTE_IP_STR_LEN     16

#define ACTION_GET          "get"
#define ACTION_BROADCASTAP "broadcastAp"
#define ACTION_SETAPIP     "setIp"
#define ACTION_SCANAP      "scanAp"

#define UDP_HEART_BEAT_PORT 42999

#define BROADCAST_SPORT 42998

#define BROADCAST_DPORT 42997
 
#define BROADCAST_IP "255.255.255.255"

#define CHECK_HEART_INTERVAL 15

#define HANDER_DELAY_TIME 5

#define MAX_WLAN_NUM 3

#define RADIO_FIFO "/tmp/RadioFifo"

#define WLAN_FIFO "/tmp/WlanFifo"

#if defined (FOR_DUAL_BAND)
//2.4G and 5G
#define W24G_DE "wlan1"
#define W24G_DE_VAP1 "wlan1-va0"
#define W24G_DE_VAP2 "wlan1-va1"
#define W24G_DE_VAP3 "wlan1-va2"
#define W24G_DE_VAP4 "wlan1-va3"
						
#define W58G_DE "wlan0"
#define W58G_DE_VAP1 "wlan0-va0"
#define W58G_DE_VAP2 "wlan0-va1"
#define W58G_DE_VAP3 "wlan0-va2"
#define W58G_DE_VAP4 "wlan0-va3"
#else
//only 2.4G
#define W24G_DE "wlan0"
#define W24G_DE_VAP1 "wlan0-va0"
#define W24G_DE_VAP2 "wlan0-va1"
#define W24G_DE_VAP3 "wlan0-va2"
#define W24G_DE_VAP4 "wlan0-va3"
//only 5G
#define W58G_DE "wlan0"
#define W58G_DE_VAP1 "wlan0-va0"
#define W58G_DE_VAP2 "wlan0-va1"
#define W58G_DE_VAP3 "wlan0-va2"
#define W58G_DE_VAP4 "wlan0-va3"
#endif

#if defined (FOR_DUAL_BAND)
#define MAX_RADIO_NUM 2
#else
#define MAX_RADIO_NUM 1
#endif

pthread_mutex_t thd_mutex;

typedef int (* HANDLERFUN)(char *action, char *http_data, cJSON *data);

typedef struct
{
    char action[32];
    HANDLERFUN fun;
} MSG_HANDLER_FUN;

typedef enum
{
    AUTH_SUCCESS=0,
    AUTH_FAIL,
} AUTH_STATE;

typedef enum
{
    HB_FALSE = 0,
    HB_TRUE = 1
} HB_BOOL;

struct heartbeat_agent
{
    int socket;
    struct sockaddr_in address;
    struct sockaddr_in RecvAddr;
    char ap_mac_str[CSTE_MAC_STR_LEN];
    char ap_mac[CSTE_MAC_LEN];
    int heart_fail_count;
    HB_BOOL heart_rece;
};


typedef enum
{
    QUICKSETTING=0,
    HARDWARE_AC = 1,
    GATEWAY_AC = 2,
    CLOUDAC
} AC_TYPE;


struct RadioConfigContent
{	
	char country[SMALL_BUF_SIZE];		
	char wirelessmode[SMALL_BUF_SIZE];
	char htmode[SMALL_BUF_SIZE];	
	char channel[SMALL_BUF_SIZE];		
	char txpower[SMALL_BUF_SIZE];		
	char beacon[SMALL_BUF_SIZE];	
};

struct WlanConfigContent
{
	char ssid[TEMP_BUF_SIZE];
	char hide[SMALL_BUF_SIZE];
	char stanum[SMALL_BUF_SIZE];
	char vlanid[SMALL_BUF_SIZE];	
	char isolate[SMALL_BUF_SIZE];	
	char usefor[SMALL_BUF_SIZE];	
	char encryption[TEMP_BUF_SIZE];
	char passphrass[TEMP_BUF_SIZE];
};

typedef struct
{
	char mode[TEMP_BUF_SIZE];	
	char week[TEMP_BUF_SIZE];	
	char hour[TEMP_BUF_SIZE];
	char minute[SMALL_BUF_SIZE];
	char recHour[SMALL_BUF_SIZE];
}RebooSchedule;

struct SystemConfigContent
{
	char apName[TEMP_BUF_SIZE];	
	char HbInterval[TEMP_BUF_SIZE];
	char rebooSchedule[SMALL_BUF_SIZE];
	char ledState[SMALL_BUF_SIZE];
};


struct WirelessConfigContent
{
	struct RadioConfigContent RadioConfigTable[MAX_RADIO_NUM];
	struct WlanConfigContent WlanConfigTable[MAX_WLAN_NUM*MAX_RADIO_NUM];
};

struct gwAcAction
{
    unsigned SetWireless	:1;
    unsigned SetSystem		:1;
	unsigned SetUpgrade		:1;
	unsigned SetReboot		:1;
	unsigned SetReset		:1;
};

struct gwAcAction gwAc;

#define GWAC_SET_WIRELESS(val) \
				do{\
					  gwAc.SetWireless = val; \
				}while(0)

#define GWAC_SET_SYSTEM(val) \
				do{\
					  gwAc.SetSystem = val; \
				}while(0)

#define GWAC_SET_UPG(val) \
				do{\
					  gwAc.SetUpgrade = val; \
				}while(0)

#define GWAC_SET_REBOOT(val) \
				do{\
					  gwAc.SetReboot = val; \
				}while(0)

#define GWAC_SET_RESET(val) \
				do{\
					  gwAc.SetReset = val; \
				}while(0)


void send_mqtt_heart_beat(void);
void send_http_heart_beat(void);
void gatewayac_handler(void);
void assemble_heart_json_data(char *action,char *http_data);
void assemble_fwupdate_json_data(char *action,char *http_data);
void assemble_no_permission_json_data(char *action,char *http_data);
void assemble_action_response_json_data(char *action,char *http_data,AUTH_STATE result);

int SetUpgrade(char *action, char *http_data, cJSON *data);
int SetCheckTime(char *action, char *http_data, cJSON *data);
int SetRadioConfig(char *action, char *http_data, cJSON *data);
int SetWlanConfig(char *action, char *http_data, cJSON *data);
int SetSysConfig(char *action, char *http_data, cJSON *data);
int SetReset(char *action, char *http_data, cJSON *data);
int SetReboot(char *action, char *http_data, cJSON *data);
void *HanderThread(void *arg);

#endif
