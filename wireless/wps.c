/** 
* Copyright (c) 2013-2017 CARY STUDIO 
* @file wps.c 
* @author CaryStudio 
* @brief  This is a wps cste topic 
* @date 2017-11-14
* @warning Reference resources
	http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.                
	http://www.cnblogs.com/davygeek/p/5658968.html 
*/
#include <time.h>
#include <netdb.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <stdio.h>
#include <linux/wireless.h>
#include <string.h>
#include "wps.h"

#if defined(FOR_DUAL_BAND)
#define WSCD_IND_ONLY_INTERFACE0 "/var/wps_start_interface0"
#define WSCD_IND_ONLY_INTERFACE1 "/var/wps_start_interface1"
#endif

#if defined(SUPPORT_MESH)
extern int smartmesh_MID; //defined in cste.c
#endif
extern int wps_status;

/**
* @note setGeneratePin	--To update wps PIN
*
* @param  wifiIdx 	 -1 : 2.4G  ,2 : 5G
*
* @return  Return Json Data
<pre>
{
    "success":true,
    "error":null,
    "lan_ip":"192.168.0.1",
    "wtime":"0",
    "reserv":"reserv"
}
</pre>
*
* @author jarven
* @date    2017-11-7
*/
int setGeneratePIN(struct mosquitto *mosq, cJSON* data, char *tp)
{
	system("flash gen-pin");
	websSetCfgResponse(mosq, tp, "10", "reserv");
	int pid=fork();
	if(0 == pid){
		sleep(1);
		takeEffectWlan("wlan0",0);
		takeEffectWlan("wlan1",0);
		CsteSystem("sysconf wlanapp start wlan0 wlan1 br0 &",CSTE_PRINT_CMD);
	//	run_init_script("all");
		exit(1);
	}
	return 0;
}

void apmib_reset_wlan_to_default(unsigned char *wlanif_name)
{
	SetWlan_idx(wlanif_name);
	memcpy(&pMib->wlan[wlan_idx][vwlan_idx], &pMibDef->wlan[wlan_idx][vwlan_idx], sizeof(CONFIG_WLAN_SETTING_T));	
	if(strstr((char *)wlanif_name,"vxd") != 0)
	{
		if(wlan_idx == 0)
		{
			sprintf((char *)pMib->repeaterSSID1, (char *)pMib->wlan[wlan_idx][vwlan_idx].ssid);
			pMib->wlan[wlan_idx][vwlan_idx].wlanDisabled = !pMib->repeaterEnabled1;			
		}
		else
		{
			sprintf((char *)pMib->repeaterSSID2, (char *)pMib->wlan[wlan_idx][vwlan_idx].ssid);
			pMib->wlan[wlan_idx][vwlan_idx].wlanDisabled = !pMib->repeaterEnabled2;			
		}
	}
}
int  checkWscPid(void)
{
	int i=0,wsc_pid=0;
	for(i=0;i<3;i++)
	{
		wsc_pid=getCmdVal("ps | grep wsc | grep -v grep | awk '{print $1}'");
		if(wsc_pid>0)
		{
			sleep(3);
			return 1;
		}
		CsteSystem("sysconf wlanapp start wlan0 wlan1 br0 &",CSTE_PRINT_CMD);//wscd jincheng
		sleep(5);
	}
	return 0;
}

void updateVapWscDisable(int wlan_root,int value)
{
	int i=0;
	int wlanif_idx = 0;
	char ifname[20];
	
	for(i=0;i<(NUM_VWLAN_INTERFACE-1);i++) // vap0~vap3
	{
		memset(ifname,0x00,sizeof(ifname));
		sprintf(ifname,"wlan%d-va%d",wlan_root,i);
		SetWlan_idx(ifname);			
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&value);
	}
	
	memset(ifname,0x00,sizeof(ifname));
	sprintf(ifname,"wlan%d-vxd",wlan_root);
	SetWlan_idx(ifname);			
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&value);
	
	memset(ifname,0x00,sizeof(ifname));
	sprintf(ifname,"wlan%d",wlan_root);
	SetWlan_idx(ifname);
}

/**
* @note getDefaultPin	--To get wps last PIN
* @return  Return Json Data
<pre>
{
    "success":true,
    "error":null,
    "lan_ip":"192.168.0.1",
    "wtime":"0",
    "reserv":"reserv"
}
</pre>
*
* @author felix
* @date   2018-1-10
*/
int getDefaultPIN(struct mosquitto *mosq, cJSON* data, char *tp)
{
#if defined(FOR_DUAL_BAND)
	apmib_reset_wlan_to_default("wlan0");
	apmib_reset_wlan_to_default("wlan1");
#else
	apmib_reset_wlan_to_default("wlan0");
#endif

	websSetCfgResponse(mosq, tp, "30", "reserv");
	int pid=fork();
	if(0 == pid){
		sleep(1);
		run_init_script("all");
		exit(1);
	}
	return 0;
}

/**
* @note getWiFiWpsEncry - Get wireless encryption state
* @param  wifiIdx - 2.4G:0,5G:1 
* @return  Return Json Data
<pre>
{
	"wscConfigured":	"1",
	"wscSsid":	"TOTOLINK_A810R666666 ",
	"wscAuthMode":	"OPEN",
	"wscEncrypType":	"NONE",
	"wscKeyIdx":	"1",
	"wscKey":	"",
	"wscStatus":	"Not used",
	"wscResult":	"0",
	"wscStatusIdx": "-1"
}
Return parameter description:
wscConfigured	-WPS Configured
wscSsid		- wps ssid 
wscAuthMode	- wps encryption
wscEncrypType-wps encryptype
wscKeyIdx	-
wscKey		-wps key
wscStatus	-wps Status /Not used/Idle/Start WSC Process,Send M2/WSC Fail/
wscResult	-wps Result -1 fail, 0 wpsing, 1 success
wscStatusIdx	-wps Status Index
</pre>
* @author jarven
* @date   2017-11-14
*/
int getWiFiWpsConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0},tmp_str[128];
	//int configured, wscauth, encryp;
	int status, WscResult=0;
	FILE *fp;
	__FUNC_IN__
	
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

#if 0	
	//1. WPSConfigured	
	memset(tmp_str, '\0', sizeof(tmp_str));
	apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&configured);
    sprintf(tmp_str,"%d",configured);
    cJSON_AddStringToObject(root,"wscConfigured",tmp_str);
	
	//2. WPSSSID	
	memset(tmp_str, '\0', sizeof(tmp_str));
	apmib_get(MIB_WLAN_WSC_SSID, (void *)tmp_str);
    cJSON_AddStringToObject(root,"wscSsid",tmp_str);

	//3. WPSAuthMode
	memset(tmp_str, '\0', sizeof(tmp_str));
	apmib_get(MIB_WLAN_WSC_AUTH, (void *)&wscauth);
	switch(wscauth)
	{
		case WSC_AUTH_OPEN:
			sprintf(tmp_str,"%s","OPEN");break;
		case WSC_AUTH_SHARED:
			sprintf(tmp_str,"%s","SHARED");break;
		case WSC_AUTH_WPAPSK:
			sprintf(tmp_str,"%s","WPA-PSK");break;
		case WSC_AUTH_WPA2PSK:
		case WSC_AUTH_WPA2PSKMIXED:
			sprintf(tmp_str,"%s","WPA2-PSK");break;
		default:			
			sprintf(tmp_str,"%s","OPEN");
	}
	cJSON_AddStringToObject(root,"wscAuthMode",tmp_str);

	//4. EncrypType
	memset(tmp_str, '\0', sizeof(tmp_str));
	apmib_get(MIB_WLAN_WSC_ENC, (void *)&encryp);
	switch(encryp)
	{
		case WSC_ENCRYPT_NONE:
			sprintf(tmp_str,"%s","NONE");break;
		case WSC_ENCRYPT_WEP:			
			sprintf(tmp_str,"%s","WEP");break;
		case WSC_ENCRYPT_TKIP:
			sprintf(tmp_str,"%s","TKIP");break;
		case WSC_ENCRYPT_AES:
		case WSC_ENCRYPT_TKIPAES:
			sprintf(tmp_str,"%s","AES");break;
		default:			
			sprintf(tmp_str,"%s","NONE");
	}	
	cJSON_AddStringToObject(root,"wscEncrypType",tmp_str);
	
	//5. DefaultKeyIdx
	memset(tmp_str, '\0', sizeof(tmp_str));
	sprintf(tmp_str,"%d", 1);
    cJSON_AddStringToObject(root,"wscKeyIdx",tmp_str);
	
	//6. Key
	memset(tmp_str, '\0', sizeof(tmp_str));
	apmib_get(MIB_WLAN_WSC_PSK, (void *)tmp_str);
    cJSON_AddStringToObject(root,"wscKey",tmp_str);

	//7. WSC Status Index
	memset(tmp_str, '\0', sizeof(tmp_str));
    sprintf(tmp_str,"%d",status);
    cJSON_AddStringToObject(root,"wscStatusIdx",tmp_str);
#endif

	//8. WSC Status /Not used/Idle/Start WSC Process,Send M2/WSC Fail/
	fp = fopen( FILE_WSCD_STATUS, "r");
	if(fp != NULL)
	{
		fscanf(fp,"%d",&status);
		fclose(fp);
	}
	CSTE_DEBUG("status=[%d]\n", status);
	memset(tmp_str, '\0', sizeof(tmp_str));
	switch(status){
		case -1 ://NOT_USED
			WscResult=0;
			sprintf(tmp_str, "%s", "Not used");	break;
		case 0 ://PROTOCOL_START
			WscResult=0;
			sprintf(tmp_str, "%s", "Start WSC Process"); break;
		case 1 ://PBC_OVERLAPPING
			WscResult=-1;
			sprintf(tmp_str, "%s", "PBC Overlapping");	
			//system("echo -1 > /tmp/wscd_status");
			break;
		case 2 ://TIMEOUT
			WscResult=-1;
			sprintf(tmp_str, "%s", "WSC Timtout");	
			//system("echo -1 > /tmp/wscd_status");
			break;
		case 3 ://sucess
			WscResult=1;
			sprintf(tmp_str, "%s", "WSC Success");	
			//system("echo -1 > /tmp/wscd_status");
			break;
		case 28://FAIL
		case 29:
		case 30:
		case 31:
		case 32:
		case 33:
			WscResult=-1;
			sprintf(tmp_str, "%s", "WSC Fail");	
			//system("echo -1 > /tmp/wscd_status");
			break;
		default :			
			WscResult=0;
			sprintf(tmp_str, "%s", "Idle");
	}
    cJSON_AddStringToObject(root,"wscStatus",tmp_str);

	//9. WSC Result -1 fail, 0 wpsing, 1 success
	memset(tmp_str, '\0', sizeof(tmp_str));
    sprintf(tmp_str,"%d",WscResult);
    cJSON_AddStringToObject(root,"wscResult",tmp_str);
	
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note setWiFiWpsConfig - Set wireless WPS configuration
*
* @param wscMode 	 - PBC/PIN Mode. 1:PIN,2:PBC
* @param wscPinMode	 - 0:Registrant,1:Accepting Registration Agency
* @param wscPin		 - Only in pinMode is 1,pin is Accepting Registration Agency
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
* @author jarven
* @date   2017-11-14
*/
int setWiFiWpsConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0},cmd_buf[128]={0};
	int intVal=0;
	__FUNC_IN__

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);
	
	apmib_get(MIB_WLAN_WSC_DISABLE,(void *)&intVal);
	if(intVal==1){ //wps disable
		websSetCfgResponse(mosq, tp, "0", "reserv");
		__FUNC_OUT__
		return 0;
	}
	if(!checkWscPid()) 
		system("init.sh gw all");
	
	int wscmode = atoi(websGetVar(data, T("wscMode"), T("0")));//0:PBC 1:PIN
	int pinmode = atoi(websGetVar(data, T("wscPinMode"), T("0")));//0:登录者 1:受理注册机构
	setGpio(WPS_START);
	if(wscmode==1){//PIN
		if(pinmode==1){//Register Mode
			char_t *pin = websGetVar(data, T("pin"), T("0"));
			char pincodestr_b[20], pintmp[20];
			memset(pincodestr_b, '\0', sizeof(pincodestr_b));
			memset(pintmp, '\0', sizeof(pintmp));
			strncpy(pintmp, pin, strlen(pin));
			int idx=0, idx2=0;
			for(idx=0;idx<strlen(pintmp);idx++){
				if(pintmp[idx] >= '0' && pintmp[idx]<= '9'){
					pincodestr_b[idx2]=pintmp[idx];	
					idx2++;
				}
			}
			memset(cmd_buf, '\0', sizeof(cmd_buf));
#if defined(FOR_DUAL_BAND)
			if(WiFiIdx==0)
				system("echo wlan0 >"WSCD_IND_ONLY_INTERFACE0);
			else
				system("echo wlan1 >"WSCD_IND_ONLY_INTERFACE1);
#endif
			printf("pincodestr_b =%s, len =%d\n", pincodestr_b ,strlen(pincodestr_b));
			sprintf(cmd_buf, "iwpriv %s set_mib pin=%s", wlan_if, pincodestr_b);
			CsteSystem(cmd_buf, CSTE_PRINT_CMD);
		}
		else{
			CSTE_DEBUG("loginer\n");
		}
		
		websSetCfgResponse(mosq, tp, "0", "reserv");
		__FUNC_OUT__
		return 0;
	}
	else{//PBC
		memset(cmd_buf, '\0', sizeof(cmd_buf));
#if defined(FOR_DUAL_BAND)
		if(WiFiIdx==0)
			system("echo wlan0 >"WSCD_IND_ONLY_INTERFACE0);
		else
			system("echo wlan1 >"WSCD_IND_ONLY_INTERFACE1);
#endif
		printf("-------start wsc pbc---------\n");
		sprintf(cmd_buf, "%s -sig_pbc %s", _WSC_DAEMON_PROG, wlan_if);
		CsteSystem(cmd_buf, CSTE_PRINT_CMD);
	}
	CsteSystem("echo 0 > /tmp/wscd_status", CSTE_PRINT_CMD);
	CsteSystem("echo 1 > /tmp/wsc_pbc", CSTE_PRINT_CMD);
	apmib_update_web(CURRENT_SETTING);	// update to flash
	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiWpsSetupConfig - Get wireless WPS setup configuration
*
* @param Setting Json Data
<pre>
{	
	"wifiIdxIdx":""
}
Setting parameter description:
wifiIdx - 0 : 2.4G ,1 : 5G.
</pre>
*
* @return  Return Json Data
<pre>
{
	"wifiOff"		:	0,
	"wscFlag"		:	0,
	"wscDisabled"	:	1,
	"wscPin"		:	"52782992"
}
Return parameter description:
wifiOff			- 1 : Disabled Wlan, 0 : Enalbe Wlan.
wscFlag			- 1 WPS feature is not available , 0:  wps function available
wscDisabled		- 1 : Disable WPS 0: Enable WPS
wscPin			- PIN number
</pre>
* @author jarven
* @date   2017-11-14
*/
int getWiFiWpsSetupConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0}, wsc_pin[12]={0};
	int arraylen=0, hssid=0, authmode=0, encrypt=0, cipher=0;
	__FUNC_IN__
	
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

	//int type mib
	char *IntGetName[]={"wifiOff","wscDisabled"};
	int IntGetId[]={MIB_WLAN_WLAN_DISABLED,MIB_WLAN_WSC_DISABLE};
    arraylen=sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);

	apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);
	apmib_get(MIB_WLAN_MACAC_ENABLED, (void *)&authmode);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
	if(hssid==1||authmode==1||encrypt==ENCRYPT_WEP||encrypt==ENCRYPT_WPA||cipher==WPA_CIPHER_TKIP){
		cJSON_AddNumberToObject(root,"wscFlag",1);
	}else{
		cJSON_AddNumberToObject(root,"wscFlag",0);
	}
	
	apmib_get(MIB_HW_WSC_PIN, (void *)wsc_pin);
	cJSON_AddStringToObject(root,"wscPin",wsc_pin);

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note setWiFiWpsSetupConfig - Set wireless WPS configuration
*
* @param Setting Json Data
<pre>
{	
	"wscDisabled"	:	"",
	"wifiIdx"		:	""
}
Setting parameter description:
wscDisabled	- 1:Disable WPS 0:Enable WPS
wifiIdx 		- 0 : 2.4G ,1 : 5G.
</pre>
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
* @author jarven
* @date   2017-11-14
*/
int setWiFiWpsSetupConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int pid=-1;
	char wlan_if[8]={0};
	__FUNC_IN__
		
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);			
	
	int intVal = atoi(websGetVar(data, T("wscDisabled"), T("0")));
	apmib_set(MIB_WLAN_WSC_DISABLE, (char *)&intVal);
	updateVapWscDisable(WiFiIdx, intVal);
	apmib_update_web(CURRENT_SETTING);
	
    websSetCfgResponse(mosq, tp, "0", "reserv");
    pid=fork();
	if(0 == pid){
		sleep(1);
		takeEffectWlan(wlan_if, 0);
		exit(1);
	}
	__FUNC_OUT__
	return 0;
}

/**
* @note setWiFiWpsStop - Stop the WPS action
*
* @param NULL
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
* @author jarven
* @date   2017-11-14
*/
int setWiFiWpsStop(struct mosquitto *mosq, cJSON* data, char *tp)
{
	//printf("-------stop wsc pbc---------\n");
	CsteSystem("echo 1 > /tmp/wscd_cancel", CSTE_PRINT_CMD);	
	CsteSystem("rm -f /tmp/wsc_pbc", CSTE_PRINT_CMD);	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

#if 1//cary
int wpsWiFiIdx = -1;
#if !defined(CONFIG_BOARD_04336)
#if defined(CONFIG_BOARD_04339)||defined(CONFIG_BOARD_04347)||defined(CONFIG_BOARD_WX022)
#define WPS_PIN_DATABASE 0xB800350C
#define WPS_LED_PIN 15 //B7
#elif defined(CONFIG_BOARD_04308)
#define WPS_PIN_DATABASE 0xB8003528
#define WPS_LED_PIN 3 //E3
#else
#define WPS_PIN_DATABASE 0xB8003528
#define WPS_LED_PIN 25 //H1
#endif
int setGpio(int _LED_flag)
{
	char tmpCmd[128]={0};

	sprintf(tmpCmd,"csteSys reg 1 0x%x %d 3",WPS_PIN_DATABASE,WPS_LED_PIN);
	
	//printf("	test-> [%s]\n\n",tmpCmd);
	CsteSystem(tmpCmd, CSTE_PRINT_CMD);//stop blinking
	switch(_LED_flag)
	{
		case WPS_START:	//start wps
		case WPS_RUNNING:		//running  wps 			
			sprintf(tmpCmd,"csteSys reg 1 0x%x %d 0",WPS_PIN_DATABASE,WPS_LED_PIN);
			break;
		case WPS_SUCC:		//wps success		
		case WPS_FAIL:		//failed wps//timeout wps 			
		case WPS_TIMEOUT:		
			sprintf(tmpCmd,"csteSys reg 1 0x%x %d 2",WPS_PIN_DATABASE,WPS_LED_PIN);
			break;
		case MESH_START:
		case MESH_RUNNING:	//for mesh runing
 			break;	
		case MESH_FAIL:		//for mesh failed 		
 			break;
		case MESH_SUCC:		//for mesh success		
 			break;		
		default:
			sprintf(tmpCmd,"csteSys reg 1 0x%x %d 2",WPS_PIN_DATABASE,WPS_LED_PIN);
			break;

	}
	
	CsteSystem(tmpCmd, CSTE_PRINT_CMD);
	return -1;
}
#endif

int csStartWps(int _wps_status, cJSON* data )
{	
	int op_mode = 0, rpt_enable = 1,intVal=0, rpt_idx=0;
	int wlan0_disabled = 0, wlan1_disabled = 0, wsc1_disabled = 0, wsc0_disabled = 0;
	wpsWiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0"))); 
	apmib_get(MIB_OP_MODE, (void *)&op_mode);
	
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0_disabled);// wlan0 
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&wsc0_disabled);
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1_disabled);// wlan1
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&wsc1_disabled);
#if defined(SUPPORT_REPEATER)
	system("ehco 1 > /tmp/wps_action");
	if(wpsWiFiIdx==0)//5G
	{
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED1,(void *)&intVal);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED2,(void *)&intVal);
		SetWlan_idx("wlan0-vxd");
		apmib_set(MIB_WLAN_WLAN_DISABLED,(void *)&intVal);
		takeEffectWlan("wlan0-vxd",0);
	}
	else if(wpsWiFiIdx==1)//2G
	{
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED2,(void *)&intVal);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED1,(void *)&intVal);
		SetWlan_idx("wlan1-vxd");
		apmib_set(MIB_WLAN_WLAN_DISABLED,(void *)&intVal);
		takeEffectWlan("wlan1-vxd",0);
	}
	apmib_update_web(CURRENT_SETTING);
	system("killall wscd");
#endif
	if(!checkWscPid()) 
		system("init.sh gw all");
		
	if(wpsWiFiIdx == 1 || ((wlan0_disabled==1 || wsc0_disabled==1) && (wlan1_disabled==0)))//wlan0 off/ wlan1 on
	{			
		system("echo 1 > /var/wps_start_interface1");
#if defined(SUPPORT_REPEATER)
		system("wscd -sig_pbc wlan1-vxd");
#else
		system("wscd -sig_pbc wlan1");
#endif
	}
	else if(wpsWiFiIdx == 0 || ((wlan0_disabled==0) && (wlan1_disabled==1 || wsc1_disabled==1)))//wlan0 on/ wlan1 off
	{
		system("echo 1 > /var/wps_start_interface0");
#if defined(SUPPORT_REPEATER)
		system("wscd -sig_pbc wlan0-vxd");
#else
		system("wscd -sig_pbc wlan0");
#endif
	}
	else
	{
		system("wscd -sig_pbc wlan0-wlan1");
	}			
	return 0;
}

int setWpsMeshStatus(int _wps_status,cJSON* data)
{
	int opmode=-1;
	apmib_get(MIB_OP_MODE, (void *)&opmode);
#if !defined(SUPPORT_MESH)	
	setGpio(_wps_status);
#endif
	switch(_wps_status){		
		case WPS_IDLE:
			return -1;
		case WPS_START:
			if(wps_status >= WPS_IDLE)
			{				
				wps_status=WPS_RUNNING;
				return csStartWps(_wps_status, data);
			}
			else
			{
				printf("WPS Busy!\n");
				return -1;
			}
		case WPS_RUNNING:
			wps_status=WPS_RUNNING;
			return -1;
		case WPS_SUCC:					
			if(opmode == 1)
			{	
				if(_wps_status == WPS_SUCC)
				{
			#ifdef SUPPORT_REPEATER		
					//这里添加信息同步代码?
					int rpt_idx=0,wpa2Cipher=0,wpaCipher=0,pskFormat=0,wpaAuth=0,ecnrypt=0,channel=0;
					char wlan_if[8]={0},wlanvxd_if[16]={0},wlan_iftmp[8]={0};
					char ssid[MAX_SSID_LEN]={0},wpaPsk[64]={0};
					sprintf(wlan_if,"wlan%d",wpsWiFiIdx);
					sprintf(wlan_iftmp,"wlan%d",1-wpsWiFiIdx);
					sprintf(wlanvxd_if,"wlan%d-vxd",wpsWiFiIdx);

					sleep(2);
					SetWlan_idx(wlanvxd_if);
					apmib_set(MIB_WISP_WAN_ID, (void *)&wpsWiFiIdx);
					apmib_get(MIB_WLAN_SSID, (void *)ssid);
					apmib_get(MIB_WLAN_ENCRYPT, (void *)&ecnrypt);
					apmib_get(MIB_WLAN_WPA_AUTH, (void *)&wpaAuth);
					apmib_get(MIB_WLAN_PSK_FORMAT, (void *)&pskFormat);
					apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);
					apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
					apmib_get(MIB_WLAN_WPA_PSK, (void *)wpaPsk); 
					if(wpsWiFiIdx==0){
						channel=getCmdVal("iwpriv wlan0-vxd get_mib channel  | cut -f2 -d:");
					}else{
						channel=getCmdVal("iwpriv wlan1-vxd get_mib channel  | cut -f2 -d:");
					}
					//printf("ssid===[%s]==\n",ssid);
					
					SetWlan_idx(wlan_if);
					apmib_set(MIB_WLAN_SSID, (void *)ssid);
					apmib_set(MIB_WLAN_ENCRYPT, (void *)&ecnrypt);
					apmib_set(MIB_WLAN_WPA_AUTH, (void *)&wpaAuth);
					apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskFormat);
					apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);
					apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
					apmib_set(MIB_WLAN_WPA_PSK, (void *)wpaPsk);
					apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);
					
					SetWlan_idx(wlan_iftmp);
					if (wpsWiFiIdx==0){
						if(strlen(ssid)<27){
							strcat(ssid,"_2.4G");
						}
					}else{
						if(strlen(ssid)<29){
							strcat(ssid,"_5G");
						}
					}
					apmib_set(MIB_WLAN_SSID, (void *)ssid);
					apmib_set(MIB_WLAN_ENCRYPT, (void *)&ecnrypt);
					apmib_set(MIB_WLAN_WPA_AUTH, (void *)&wpaAuth);
					apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskFormat);
					apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);
					apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
					apmib_set(MIB_WLAN_WPA_PSK, (void *)wpaPsk);

					apmib_update_web(CURRENT_SETTING);
					sleep(1);
					system("reboot");
			#endif
				}
				else
				{					
					if(wps_status == MESH_SUCC)
					{
						system("ifconfig wlan0-vxd down 2> /dev/null");
				#if defined(FOR_DUAL_BAND)
						system("ifconfig wlan1-vxd down 2> /dev/null");
				#endif 				
						system("ifconfig wlan-msh down up 2> /dev/null");
						//system("killal pathsel;pathsel -i wlan-msh -P -d 2> /dev/null");
						_wps_status=wps_status;
					}
				}
			}
			wps_status = _wps_status;
			return 0;
		case WPS_TIMEOUT:	
		case WPS_FAIL:
	#ifdef SUPPORT_REPEATER	
			{
				int tmpVal=0;
				apmib_get(MIB_WISP_WAN_ID, (void *)&tmpVal);
				if(tmpVal==0)//5G
				{
					tmpVal=1;
					apmib_set(MIB_REPEATER_ENABLED1,(void *)&tmpVal);
					tmpVal=0;
					apmib_set(MIB_REPEATER_ENABLED2,(void *)&tmpVal);
					system("ifconfig wlan1-vxd down");
					SetWlan_idx("wlan0-vxd");
					apmib_set(MIB_WLAN_WLAN_DISABLED,(void *)&tmpVal);
					takeEffectWlan("wlan0-vxd",1);
				}
				else if(tmpVal==1)//2G
				{
					tmpVal=1;
					apmib_set(MIB_REPEATER_ENABLED2,(void *)&tmpVal);
					tmpVal=0;
					apmib_set(MIB_REPEATER_ENABLED1,(void *)&tmpVal);
					system("ifconfig wlan0-vxd down");
					SetWlan_idx("wlan1-vxd");
					apmib_set(MIB_WLAN_WLAN_DISABLED,(void *)&tmpVal);
					takeEffectWlan("wlan1-vxd",1);
				}
				
				system("rm -rf /tmp/wps_action");
				apmib_update_web(CURRENT_SETTING);
			}
	#endif
			wps_status = _wps_status;
			return 0;
		case MESH_START:
			wps_status = _wps_status;
			return -1;
		case MESH_RUNNING:
			return -1;			
		case MESH_SUCC:		
			wps_status=MESH_SUCC;
			if(opmode == 1)
			{		
				system("csteSys updateAddr &");
			}
			else
			{
#if defined(RTK_CAPWAP)	
				if(!f_exist("/web_cste/meshInfo.ini"))
				{
					system("sysconf updateAllMeshInfo");
					return 0;
				}	
#endif			
			}			
			return -1;
		case MESH_FAIL:
			return -1;
		default:
			return -1;
	}
}

/**
* @note csWps - WPS state machine
*
* @param Setting Json Data
<pre>
{	
	"wizardFlag":"",
	"states":""
}
Setting parameter description:
wizardFlag	- Setting wizard flag.
states	-The current state of the state machine
</pre>
* @return NULL
* @author jarven
* @date   2017-11-14
*/
int csWps(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int itmp=1;
	char_t *wizardflag = websGetVar(data, T("wizardflag"), T("0"));//from page
	if(wizardflag==1){//when wizard
		//apmib_set(MIB_WIZARD_FLAG, (void *)&itmp);
		apmib_update_web(CURRENT_SETTING);
	}
	char_t *var=NULL;
	//setState
	var = websGetVar(data, T("states"), T("0"));
	//printf("wps_status ---> [%s : %d]\n",var,wps_status);
	if(!strcmp(var,"start"))
	{
		if(wps_status >= WPS_IDLE)
		{
			wps_status = WPS_IDLE;
			setWpsMeshStatus(WPS_START,data);
		}
	}	
	else if(!strcmp(var,"wps_succ"))
	{	
	/*
		if (wps_status>=WPS_IDLE)
		{
		//	system("init.sh ap all");
			takeEffectWlan("wlan0",0);
			takeEffectWlan("wlan1",0);
		}
		else
			CsteSystem("sysconf wlanapp start wlan0 wlan1 br0 &",CSTE_PRINT_CMD);
		*/
		setWpsMeshStatus(WPS_SUCC,data);
	}
	else if(!strcmp(var,"wps_fail"))
	{	
		CsteSystem("sysconf wlanapp start wlan0 wlan1 br0 &",CSTE_PRINT_CMD);
		setWpsMeshStatus(WPS_FAIL,data);
	}
	else if(!strcmp(var,"wps_timeout"))
	{	
		setWpsMeshStatus(WPS_TIMEOUT,data);
	}
	else if(!strcmp(var,"mesh_start"))
	{	
		setWpsMeshStatus(MESH_START,data);
	}	
	else if(!strcmp(var,"mesh_succ"))
	{	
		setWpsMeshStatus(MESH_SUCC,data);
	}
	else if(!strcmp(var,"kick"))
	{	
		int sta_action=0;
		printf("wps_status:%d\n",wps_status);
		sta_action= atoi(websGetVar(data, T("test_sta"), T("0")));
		setGpio(sta_action);
	}	
	else if(!strcmp(var,"reboot"))
	{	
		system("reboot");
	}
	return 0;
}

/**
* @note getWscMeshStatus - Get WPS state
*
* @param NULL
* @return 
<pre>
{	
	"WscMeshStatus":"",
}
return parameter description:
WscMeshStatus	-The current state of the state machine
</pre>
* @author jarven
* @date   2017-11-14
*/
int getWscMeshStatus(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root;
	root=cJSON_CreateObject();		
	
	cJSON_AddNumberToObject(root, "WscMeshStatus", wps_status);
#if 0	
	switch(wps_status){ 	
		case WPS_IDLE:
			// 
			cJSON_AddNumberToObject(root, "WscMeshStatus", WPS_IDLE);
			break;
		case WPS_START:
		case WPS_RUNNING:
			// 
			cJSON_AddNumberToObject(root, "WscMeshStatus", WPS_RUNNING);
			break;
		case WPS_SUCC:	
			cJSON_AddNumberToObject(root, "WscMeshStatus", WPS_SUCC);
			break;
		case WPS_TIMEOUT:						
		case WPS_FAIL:
			cJSON_AddNumberToObject(root, "WscMeshStatus", MESH_FAIL);
			break;	
		case MESH_START:				
		case MESH_RUNNING:			
		case MESH_SUCC: 				
			getMeshInfo(&root, MESH_SUCC);
			break;
		case MESH_FAIL:
			cJSON_AddNumberToObject(root, "WscMeshStatus", MESH_FAIL);
			break;
		default:
			cJSON_AddNumberToObject(root, "WscMeshStatus", MESH_FAIL);
			break;
	}
#endif	

	output = cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}
#endif

//模块间通信接收消息
int mcWpsRx(struct mosquitto *mosq, cJSON* data, char *tp)
{
	__FUNC_IN__
	__FUNC_OUT__
	return 0;   
}

int module_init()
{
	cste_hook_register("mcWpsRx",mcWpsRx);
	
	cste_hook_register("setWiFiWpsConfig",setWiFiWpsConfig);
	cste_hook_register("getWiFiWpsConfig",getWiFiWpsConfig);
	
    cste_hook_register("getWiFiWpsSetupConfig",getWiFiWpsSetupConfig);
    cste_hook_register("setWiFiWpsSetupConfig",setWiFiWpsSetupConfig);
	
	cste_hook_register("setWiFiWpsStop",setWiFiWpsStop);
	
	cste_hook_register("setGeneratePIN",setGeneratePIN);
	cste_hook_register("getDefaultPIN",getDefaultPIN);
	
	cste_hook_register("csWps",csWps);
	cste_hook_register("getWscMeshStatus",getWscMeshStatus);

    return 0;  
}
