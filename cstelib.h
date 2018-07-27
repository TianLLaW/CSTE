#ifndef CSTE_UTIL_H
#define CSTE_UTIL_H
#include <sys/time.h>
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"
#include <stdint.h>
#include <mystdlib.h> 

#define FILE_DIR_LEN 256

#if 1  //def CONFIG_APP_CSTE_DEBUG
#define CSTE_DEBUG(FMT, ARGS...) printf("%s:%s:%d | "FMT, __FILE__, __FUNCTION__, __LINE__, ##ARGS)
#define __FUNC_IN__     CSTE_DEBUG("######IN:######\n");
#define __FUNC_OUT__    CSTE_DEBUG("######OUT:######\n");
#define CSTE_PRINT_CMD  1
#else
#define CSTE_DEBUG(FMT, ARGS...)
#define __FUNC_IN__ 
#define __FUNC_OUT__ 
#define CSTE_PRINT_CMD  0
#endif

#if defined (ONLY_5G_SUPPORT)
#define W58G_IF "wlan0"
#define W58G_IF_VA1 "wlan0-va0"
#define W58G_IF_VA2 "wlan0-va1"
#define W58G_IF_VA3 "wlan0-va2"
#define W58G_IF_VA4 "wlan0-va3"
#else
#if defined (FOR_DUAL_BAND)
#define W24G_IF "wlan1"
#define W24G_IF_VA1 "wlan1-va0"
#define W24G_IF_VA2 "wlan1-va1"
#define W24G_IF_VA3 "wlan1-va2"
#define W24G_IF_VA4 "wlan1-va3"

#define W58G_IF "wlan0"
#define W58G_IF_VA1 "wlan0-va0"
#define W58G_IF_VA2 "wlan0-va1"
#define W58G_IF_VA3 "wlan0-va2"
#define W58G_IF_VA4 "wlan0-va3"
#else
#define W24G_IF "wlan0"
#define W24G_IF_VA1 "wlan0-va0"
#define W24G_IF_VA2 "wlan0-va1"
#define W24G_IF_VA3 "wlan0-va2"
#define W24G_IF_VA4 "wlan0-va3"
#endif
#endif


#ifdef WIFI_SIMPLE_CONFIG
enum {	CALLED_FROM_WLANHANDLER=1, CALLED_FROM_WEPHANDLER=2, CALLED_FROM_WPAHANDLER=3, CALLED_FROM_ADVANCEHANDLER=4};
struct wps_config_info_struct {
	int caller_id;
	int wlan_mode;
	int auth;
	int shared_type;
	int wep_enc;
	int wpa_enc;
	int wpa2_enc;
	unsigned char ssid[MAX_SSID_LEN];
	int KeyId;
	unsigned char wep64Key1[WEP64_KEY_LEN];
	unsigned char wep64Key2[WEP64_KEY_LEN];
	unsigned char wep64Key3[WEP64_KEY_LEN];
	unsigned char wep64Key4[WEP64_KEY_LEN];
	unsigned char wep128Key1[WEP128_KEY_LEN];
	unsigned char wep128Key2[WEP128_KEY_LEN];
	unsigned char wep128Key3[WEP128_KEY_LEN];
	unsigned char wep128Key4[WEP128_KEY_LEN];
	unsigned char wpaPSK[MAX_PSK_LEN+1];
};
struct wps_config_info_struct wps_config_info;
struct wps_config_info_struct wps_config_info_tmp;
void update_wps_configured(int reset_flag);
#define _WSC_DAEMON_PROG 	"wscd"
#endif

typedef struct _tag_mqtt_func_list{
    struct _tag_mqtt_func_list *next;
    char *name;
    int(*func)();
}tag_mqtt_func_list;

extern tag_mqtt_func_list *first_cste_hook;

typedef enum _wlan_mac_state {
    STATE_DISABLED=0, STATE_IDLE, STATE_SCANNING, STATE_STARTED, STATE_CONNECTED, STATE_WAITFORKEY
} wlan_mac_state;

/* type define */
struct user_net_device_stats {
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
	unsigned long tx_multicast;	/* multicast packets transmitted   */
	unsigned long rx_unicast;	/* unicast packets received   */
	unsigned long tx_unicast;	/* unicast packets transmitted   */
	unsigned long rx_broadcast;	/* broadcast packets received   */
	unsigned long tx_broadcast;	/* broadcast packets transmitted   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;

    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
};

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[32+1];
} bss_info;

typedef struct _OCTET_STRING {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING;

typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;

typedef	struct _IbssParms {
    unsigned short	atimWin;
} IbssParms;

typedef enum _Capability {
    cESS 		= 0x01,
    cIBSS		= 0x02,
    cPollable		= 0x04,
    cPollReq		= 0x01,
    cPrivacy		= 0x10,
    cShortPreamble	= 0x20,
} Capability;

//#define MAX_NAME_LEN 32
#define MAX_BSS_DESC 64	
#define SSID_LEN	 32
#define MESHID_LEN	 32
typedef struct _BssDscr {
    unsigned char bdBssId[6];
    unsigned char bdSsIdBuf[SSID_LEN];
    OCTET_STRING  bdSsId;

#if defined(SUPPORT_MESH) || defined(CONFIG_RTL_819X) 
	//by GANTOE for site survey 2008/12/26
	unsigned char bdMeshIdBuf[MESHID_LEN]; 
	OCTET_STRING bdMeshId; 
#endif 
    BssType bdType;
    unsigned short bdBcnPer;			// beacon period in Time Units
    unsigned char bdDtimPer;			// DTIM period in beacon periods
    unsigned long bdTstamp[2];			// 8 Octets from ProbeRsp/Beacon
    IbssParms bdIbssParms;			// empty if infrastructure BSS
    unsigned short bdCap;				// capability information
    unsigned char ChannelNumber;			// channel number
    unsigned long bdBrates;
    unsigned long bdSupportRates;		
    unsigned char bdsa[6];			// SA address
    unsigned char rssi, sq;			// RSSI and signal strength
    unsigned char network;			// 1: 11B, 2: 11G, 4:11G
	// P2P_SUPPORT
	unsigned char	p2pdevname[33];		
	unsigned char	p2prole;	
	unsigned short	p2pwscconfig;		
	unsigned char	p2paddress[6];	
	unsigned char	stage;	    
} BssDscr, *pBssDscr;
	// P2P_SUPPORT
enum p2p_role_s {
	R_P2P_GO =1	,
	R_P2P_DEVICE = 2,
	R_P2P_CLIENT =3  

};

typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} SS_STATUS_T, *SS_STATUS_Tp;

typedef enum _wlan_wds_state {
    STATE_WDS_EMPTY=0, STATE_WDS_DISABLED, STATE_WDS_ACTIVE
} wlan_wds_state;

typedef struct _WDS_INFO {
	unsigned char	state;
	unsigned char	addr[6];
	unsigned long	tx_packets;
	unsigned long	rx_packets;
	unsigned long	tx_errors;
	unsigned char	txOperaRate;
} WDS_INFO_T, *WDS_INFO_Tp;

typedef struct custom_header {
	uint32_t    ih_size;    /* Image Data Size      */
	uint8_t     ih_md5[40];  /* md5       */
    uint8_t     ih_name[32];  /* Image Name       */
} custom_header_t;


/*-- Local constant definition --*/
#define _PATH_PROCNET_ROUTE	"/proc/net/route"
#define _PATH_PROCNET_DEV	"/proc/net/dev"
#define _PATH_RESOLV_CONF	"/etc/resolv.conf"

/* -- Below define MUST same as /linux2.4.18/drivers/net/rtl865x/eth865x.c */
#define RTL8651_IOCTL_GETWANLINKSTATUS 2000
#define RTL8651_IOCTL_GETLANLINKSTATUS 2102
#define RTL8651_IOCTL_GET_ETHER_EEE_STATE 2105
#define RTL8651_IOCTL_GET_ETHER_BYTES_COUNT 2106

/* Keep this in sync with /usr/src/linux/include/linux/route.h */
#define RTF_UP			0x0001          /* route usable                 */
#define RTF_GATEWAY		0x0002          /* destination is a gateway     */

typedef unsigned short 		char_t;
#define	T(s) 				s
#define CSTEBUFSIZE         4096
#define CSTEMAXSIZE         4000
#define IFACE_FLAG_T        0x01
#define IP_ADDR_T           0x02
#define NET_MASK_T          0x04
#define HW_ADDR_T           0x08
#define RUN_INIT_SCRITP_FLAG_YES    1
#define RUN_INIT_SCRITP_FLAG_NO     0
#define _WAN_STATUS_FILE    "/proc/eth1/up_event"
#define _DHCPD_PROG_NAME	"udhcpd"
#define _DHCPD_PID_PATH		"/var/run"
#define _DHCPC_PROG_NAME	"udhcpc"
#define _DHCPC_PID_PATH		"/etc/udhcpc"
#define _PATH_DHCPS_LEASES	"/var/lib/misc/udhcpd.leases"

#define MAX_MSG_BUFFER_SIZE 256

#ifdef __i386__
#define _CONFIG_SCRIPT_PATH	    "."
#define _LITTLE_ENDIAN_
#else
#define _CONFIG_SCRIPT_PATH	    "/bin"
#endif
#define _CONFIG_SCRIPT_PROG	    "init.sh"
#define _WLAN_SCRIPT_PROG	    "wlan.sh"
#define _PPPOE_SCRIPT_PROG	    "pppoe.sh"
#define _PPTP_SCRIPT_PROG	    "pptp.sh"
#define _L2TP_SCRIPT_PROG	    "l2tp.sh"
#define _FIREWALL_SCRIPT_PROG	"firewall.sh"
#define _ROUTE_SCRIPT_PROG	    "route.sh"
#define _PPPOE_DC_SCRIPT_PROG	"disconnect.sh"
#define _IAPPAUTH_SCRIPT_PROG	"iappauth.sh"
#define _NTP_SCRIPT_PROG	    "ntp.sh"

/*sendMsgtoALink use these definition*/
#define SER_BUFSIZ					512
#define KEY_T                       9375182604

struct msg_st{
    int msg_type;
    char some_text[SER_BUFSIZ];
}msgData;

enum msgType{
	ALISECURITY = 1,
	URLPROTECTINFO,
	PROBEDSWITCHSTATE,
	PROBEDNUM,
	PROBERINFO = 5,
	ACCESSATTACKSWITCHSTATE,
	ACCESSATTACKNUM,
	ACCESSATTACKERINFO,
	WLANSWITCHSTATE,
	FWDOWNLOADINFO = 10,
	FWUPGRADEINFO,
	WANDLSPEED,
	WANULSPEED,
	DLBWINFO,
	ULBWINFO = 15,
	WLANPAMODE,
	SPEEDUPSETTING,
	WLANSETTING24G,
	WLANSETTING5G,
	WLANSECURITY24G = 20,
	WLANSECURITY5G,
	WLANCHANNELCONDITION24G,
	WLANCHANNELCONDITION5G,
	TPSK,
	TPSKLIST= 25,
	RESETBINGDING,
	GETLANDEVEICE};
/*-------------------------------*/
#define TCP_TMPFILE "/tmp/.tcpcheck.tmp"

int tcpcheck_net(const char *host, int port, int timeout);

int Cal_file_md5(const char *file_path, char *md5_str);
char *safe_strdup(const char *s);
char_t *websGetVar(cJSON *object, char_t *var, char_t *defaultGetValue);
void hook_list_init(void);
void websGetCfgResponse(struct mosquitto *mosq, char *tp, char *msg);
void websSetCfgResponse(struct mosquitto *mosq, char *tp, char *time, char *reserv);
void websErrorResponse(struct mosquitto *mosq, char *tp, char *JS_Num);
int getOperationMode();
int getDhcp();
void getLanIp(char *tmpbuf);
void getLanNetmask(char *tmpbuf);
void getWanConnectMode(char *tmpbuf);
void get_wan_connect_status(char *tmpbuf);
void getWanIp(char *if_addr);
char *getDns(int dnsIdx);
void arplookup(char *ip, char *arp);
void killSomeDaemon(void);
void run_init_script(char *arg);
void takeEffectWlan(char *wlan_if,int actionFlag);
static char *get_name(char *name, char *p);
char *getPortLinkStaus();
static int get_dev_fields(int type, char *bp, struct user_net_device_stats *pStats);
int getStats(char *interface, struct user_net_device_stats *pStats);
int CsteSystem(char *command, int printFlag);
int getCfgArrayInt(cJSON *root, int argc, char_t **argv, int **argvid);
int getCfgArrayStr(cJSON *root, int argc, char_t **argv, int **argvid);
int getCfgArrayIP(cJSON *root, int argc, char_t **argv, int **argvid);
int apmib_update_web(int type);
int _is_hex(char c);
int string_to_hex(char *string, unsigned char *key, int len);
int get_wan_link_status(char *interface);
int getFlashSize(void);
int getPid(char *filename);
int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime, char *hostname);
int isMacValid(char *);
int getDefaultRoute(char *interface, struct in_addr *route);
int getInAddr( char *interface, int type, char *pAddr );
int getStaAssociatedNum(char *ifname);
int SetWlan_idx(char *wlan_iface_name);
int getWlBssInfo(char *interface, bss_info *pInfo);
int getWlJoinResult(char *interface, unsigned char *res);
int write_line_to_file(char *filename, int mode, char *line_data);
int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo );
int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus );
int getWlSiteSurveyRequest(char *interface, int *pStatus);
#ifdef CONFIG_APP_EASYCWMP
int addObjectToArray(cJSON *root,int argc, char_t **argv, int **argvid);
int addObjectIntToArray(cJSON *root,int argc, char **argv, int **argvid);
int addPandValueToArray(cJSON *root, int argc, char **argp, char **argv);
int addObjectIPToArray(cJSON *root,int argc, char_t **argv, int **argvid);
int addIntValueToArray(cJSON * root,int argc,char * * argv,int ** argvid);
#endif

tag_mqtt_func_list *cste_hook_register(char *name, int(*func)());


#if defined(SUPPORT_MESH)
#define DL_IMAGE_FILE	"/var/cloudupdate.web"
#else
#define DL_IMAGE_FILE	"/tmp/cloudupdate.web"
#endif

int splitString2Arr_v2(char *src, char *desArr, unsigned int lenOf1d, unsigned int lenOf2d, char delimiter);
void get_Create_Time(char * tmpbuf);
#define XCMD( x, fmt, args... ) do {\
        sprintf( x, fmt, ##args ); \
        CsteSystem( x, CSTE_PRINT_CMD ); \
    } while( 0 )

#ifdef CONFIG_PA_ONLINE_IP
#define APP_CONFIG_PATH 		"/mnt/ibms_config"
#define APP_CONFIG_TEMP_PATH 	"/tmp/ibms_config"
#define APP_CONFIG_TEMP_LIST_PATH "/tmp/ibms_config/applist"
#endif

#endif
