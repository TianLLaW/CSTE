/** 
* Copyright (c) 2013-2017 CARY STUDIO 
* @file wireless.c 
* @author CaryStudio 
* @brief  This is a wireless cste topic 
* @date 2017-11-7
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
#include <string.h>
#include <linux/wireless.h>
#include <unistd.h>

#include "wireless.h"
#include "sigHd.h"


/**
* @note setWebWlanIdx 	-- Setting "/tmp/webWlanIdx" content  
*
* @param   webWlanIdx 	-- the content of file to set
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
int setWebWlanIdx(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *webWlanIdx = websGetVar(data, T("webWlanIdx"), T("0"));
	char cmd[32];
	sprintf(cmd,"echo %s > /tmp/webWlanIdx",webWlanIdx);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note getWebWlanIdx 	-- Read "/tmp/webWlanIdx" content  
*
* @param  NULL 	
*
* @return  Return Json Data
<pre>
{
	"webWlanIdx":"x"
}
</pre>
webWlanIdx	-- The value saved in the file
*
* @author jarven
* @date    2017-11-7
*/
int getWebWlanIdx(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char output[32]={0};
	sprintf(output,"{\"webWlanIdx\":\"%d\"}",wlan_idx);
	websGetCfgResponse(mosq,tp,output);
	return 0;
}

/**
* @note getWiFiStaInfo 	--Get Wireless client information.
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
*
* @return  Return Json Data
<pre>
[{
	0.0.0.0;F4:CB:52:61:B9:FD;11n;20M;0;100;300;HRH_TEST_01;75;va2$
}]
	data structure:	ip;mac;mode;bw;rssi;rssi;time;ssid;dbm;wifiIdx$
Return parameter description:
//ip		- wifi client ip
bssid	- wifi client bssid(mac)
mode 	- wifi client mode
bw	 	- wifi client bandwidth
rssi		- wifi client signal(rssi)
//time 	- wifi client connection time
dbm		- wifi client connection signal strength
wifiIdx 	- wifi interface
</pre>
*
* @author jarven
* @date    2017-11-14
*/
int getWiFiStaInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *buff;
	char *output;
	char *root,*array;
	WLAN_STA_INFO_Tp pInfo,pInfo_va1,pInfo_va2;
	char mac[32]={0},mode[8]={0},bw[8]={0},signal[16]={0};
	char wlan_if[8]={0},wlan_va1_if[16]={0},wlan_va2_if[16]={0};
	char ssid[33]={0},dbm[8]={0},outmac[18]={0},bgn_mode[8]={0},cur_time[16]={0},rssi_out_width[8]={0};
	int wlan_disabled=0,wlan_vap1_disabled=0,wlan_vap2_disabled=0;
	int i=0,rssi_out=100,rssi_width=0;
	int encrypt,cipher1,cipher2;
	__FUNC_IN__

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va2_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	array=cJSON_CreateArray();
	//wlanX
	SetWlan_idx(wlan_if);
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
	if(wlan_disabled==0){
		//wlanX_va2
		SetWlan_idx(wlan_va2_if);
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_vap2_disabled);
		apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_get( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher1);
		apmib_get( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher2);
		
		if(wlan_vap2_disabled==0){
			buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
			if ( getWlStaInfo(wlan_va2_if,	(WLAN_STA_INFO_Tp)buff ) > -1 ){
				for (i=1; i<=MAX_STA_NUM; i++){
					
					pInfo_va2 = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
					if (pInfo_va2->aid && (pInfo_va2->flag & STA_INFO_FLAG_ASOC)){
						root=cJSON_CreateObject();
						cJSON_AddItemToArray(array,root);
						//MAC Address
						memset(mac,0,sizeof(mac));
						sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo_va2->addr[0],pInfo_va2->addr[1],pInfo_va2->addr[2],pInfo_va2->addr[3],pInfo_va2->addr[4],pInfo_va2->addr[5]);
						cJSON_AddStringToObject(root,"mac",mac);
						
						//Mode
						memset(mode, 0, sizeof(mode));
						if(pInfo_va2->network& BAND_5G_11AC)
							sprintf(mode,"%s","11ac");
						else if(pInfo_va2->network & BAND_11N){
							if(encrypt==ENCRYPT_WPA||cipher1==WPA_CIPHER_TKIP||cipher2==WPA_CIPHER_TKIP)
								sprintf(mode,"%s","11g");
							else
								sprintf(mode,"%s","11n");
						}
						else if (pInfo_va2->network & BAND_11G)
							sprintf(mode,"%s","11g");	
						else if (pInfo_va2->network & BAND_11B)
							sprintf(mode,"%s","11b");
						else if (pInfo_va2->network& BAND_11A)
							sprintf(mode,"%s","11a");
						cJSON_AddStringToObject(root,"mode",mode);
						
						//bw
						if(pInfo_va2->txOperaRates >= 0x90){
						//if((pInfo->ht_info & 0x5)==0x5){
							sprintf(bw,"%s","80M");
						}else if((pInfo_va2->ht_info & 0x1)==0){
							sprintf(bw,"%s","20M");
						}else if((pInfo_va2->ht_info & 0x1)==0x1){
							sprintf(bw,"%s","40M");
						}
						cJSON_AddStringToObject(root,"bw",bw);
						
						//RSSI
						memset(rssi_out_width, 0, sizeof(rssi_out_width));
						rssi_out = pInfo_va2->rssi;
						rssi_out +=30;
						if(rssi_out > 100)rssi_out=100;
						if (rssi_out==100) {
							rssi_width = 0;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=80) {
							rssi_width = rssi_out - 80;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=60) {
							rssi_width = rssi_out - 60;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=40) {
							rssi_width = rssi_out - 40;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=20) {
							rssi_width = rssi_out - 20;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else {
							rssi_width = rssi_out;	
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						cJSON_AddStringToObject(root,"rssi",rssi_out_width);
						
						//Connect time
						memset(cur_time,0,sizeof(cur_time));
						sprintf(cur_time,"%ld",pInfo_va2->expired_time/100);
						cJSON_AddStringToObject(root,"connectTime",cur_time);
						
						//ssid
						/*apmib_get(MIB_WLAN_SSID, (void *)ssid);
						strcat(output,ssid);
						strcat(output,";");
						
						//dBm
						rssi_out = pInfo_va2->rssi;
						sprintf(dbm,"%d",rssi_out);
						strcat(output,dbm);
						strcat(output,";");
						strcat(output,"va2");
						strcat(output,"$");
						printf("bbbb output=%s\n",output);*/
					}
				}
			}
			free(buff);
		}

		//wlanX_va1
		SetWlan_idx(wlan_va1_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_vap1_disabled);
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher1);
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher2);
		if(wlan_vap1_disabled==0){
			buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
			if ( getWlStaInfo(wlan_va1_if,	(WLAN_STA_INFO_Tp)buff ) > -1 ){
				for (i=1; i<=MAX_STA_NUM; i++){
					pInfo_va1 = (WLAN_STA_INFO_Tp) & buff[i*sizeof(WLAN_STA_INFO_T)];
				if (pInfo_va1->aid && (pInfo_va1->flag & STA_INFO_FLAG_ASOC)){
					root=cJSON_CreateObject();
					cJSON_AddItemToArray(array,root);
					//MAC Address
					memset(mac,0,sizeof(mac));
					sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo_va1->addr[0],pInfo_va1->addr[1],pInfo_va1->addr[2],pInfo_va1->addr[3],pInfo_va1->addr[4],pInfo_va1->addr[5]);
					cJSON_AddStringToObject(root,"mac",mac);
					
					//Mode
					memset(mode, 0, sizeof(mode));
					if(pInfo_va1->network& BAND_5G_11AC)
						sprintf(mode,"%s","11ac");
					else if(pInfo_va1->network & BAND_11N){
						if(encrypt==ENCRYPT_WPA||cipher1==WPA_CIPHER_TKIP||cipher2==WPA_CIPHER_TKIP)
							sprintf(mode,"%s","11g");
						else
							sprintf(mode,"%s","11n");
					}
					else if (pInfo_va1->network & BAND_11G)
						sprintf(mode,"%s","11g");	
					else if (pInfo_va1->network & BAND_11B)
						sprintf(mode,"%s","11b");
					else if (pInfo_va1->network& BAND_11A)
						sprintf(mode,"%s","11a");
					cJSON_AddStringToObject(root,"mode",mode);
					
					//bw
					if(pInfo_va1->txOperaRates >= 0x90){
					//if((pInfo->ht_info & 0x5)==0x5){
						sprintf(bw,"%s","80M");
					}else if((pInfo_va1->ht_info & 0x1)==0){
						sprintf(bw,"%s","20M");
					}else if((pInfo_va1->ht_info & 0x1)==0x1){
						sprintf(bw,"%s","40M");
					}
					
					cJSON_AddStringToObject(root,"bw",bw);
					
					//RSSI
					memset(rssi_out_width, 0, sizeof(rssi_out_width));
					rssi_out = pInfo_va1->rssi;
					rssi_out +=30;
					if(rssi_out > 100)rssi_out=100;
					if (rssi_out==100) {
						rssi_width = 0;
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					else if (rssi_out>=80) {
						rssi_width = rssi_out - 80;
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					else if (rssi_out>=60) {
						rssi_width = rssi_out - 60;
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					else if (rssi_out>=40) {
						rssi_width = rssi_out - 40;
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					else if (rssi_out>=20) {
						rssi_width = rssi_out - 20;
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					else {
						rssi_width = rssi_out;	
						sprintf(rssi_out_width,"%d", rssi_out);
					}
					cJSON_AddStringToObject(root,"rssi",rssi_out_width);
					
					//Connect time
					memset(cur_time,0,sizeof(cur_time));
					sprintf(cur_time,"%ld",pInfo_va1->expired_time/100);
					cJSON_AddStringToObject(root,"connectTime",rssi_out_width);
		
					//ssid
					/*apmib_get(MIB_WLAN_SSID, (void *)ssid);
					strcat(output,ssid);
					strcat(output,";");
					
					//dBm
					rssi_out = pInfo_va2->rssi;
					sprintf(dbm,"%d",rssi_out);
					strcat(output,dbm);
					strcat(output,";");
					strcat(output,"va2");
					strcat(output,"$");
					printf("bbbb output=%s\n",output);*/
				}
				}
			}
			free(buff);
		}

		//wlanX
		SetWlan_idx(wlan_if);
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher1);
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher2);
		buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
		if ( getWlStaInfo(wlan_if,	(WLAN_STA_INFO_Tp)buff ) > -1 ){
			for (i=1; i<=MAX_STA_NUM; i++){
				pInfo = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
				if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
						root=cJSON_CreateObject();
						cJSON_AddItemToArray(array,root);
						//MAC Address
						memset(mac,0,sizeof(mac));
						sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5]);
						cJSON_AddStringToObject(root,"mac",mac);
						
						//Mode
						memset(mode, 0, sizeof(mode));
						if(pInfo->network& BAND_5G_11AC)
							sprintf(mode,"%s","11ac");
						else if(pInfo->network & BAND_11N){
							if(encrypt==ENCRYPT_WPA||cipher1==WPA_CIPHER_TKIP||cipher2==WPA_CIPHER_TKIP)
								sprintf(mode,"%s","11g");
							else
								sprintf(mode,"%s","11n");
						}
						else if (pInfo->network & BAND_11G)
							sprintf(mode,"%s","11g");	
						else if (pInfo->network & BAND_11B)
							sprintf(mode,"%s","11b");
						else if (pInfo->network& BAND_11A)
							sprintf(mode,"%s","11a");
						cJSON_AddStringToObject(root,"mode",mode);					
						//bw
						
						if(pInfo->txOperaRates >= 0x90){
						//if((pInfo->ht_info & 0x5)==0x5){
							sprintf(bw,"%s","80M");
						}else if((pInfo->ht_info & 0x1)==0){
							sprintf(bw,"%s","20M");
						}else if((pInfo->ht_info & 0x1)==0x1){
							sprintf(bw,"%s","40M");
						}
						cJSON_AddStringToObject(root,"bw",bw);
						
						//RSSI
						memset(rssi_out_width, 0, sizeof(rssi_out_width));
						rssi_out = pInfo->rssi;
						rssi_out +=30;
						if(rssi_out > 100)rssi_out=100;
						if (rssi_out==100) {
							rssi_width = 0;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=80) {
							rssi_width = rssi_out - 80;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=60) {
							rssi_width = rssi_out - 60;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=40) {
							rssi_width = rssi_out - 40;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else if (rssi_out>=20) {
							rssi_width = rssi_out - 20;
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						else {
							rssi_width = rssi_out;	
							sprintf(rssi_out_width,"%d", rssi_out);
						}
						cJSON_AddStringToObject(root,"rssi",rssi_out_width);
						
						//Connect time
						memset(cur_time,0,sizeof(cur_time));
						sprintf(cur_time,"%ld",pInfo->expired_time/100);
						cJSON_AddStringToObject(root,"connectTime",cur_time);						
					}
			}
		}
		free(buff);   
	}
	output=cJSON_Print(array);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(array);
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiApInfo 		--Get WiFi Ap and Repeater Info
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
*
* @return  Return Json Data
<pre>
{
	"operationMode":	0,
	"channel":		149,
	"autoChannel":	149,
	"band":			14,
	"wifiOff1":		0,
	"ssid1":			"TOTOLINK_5G_BC90C0",
	"bssid1":			"F4:28:53:BC:90:C0",
	"wifiKey1":		"12345678",
	"staNum1":		0,
	"wifiOff2":		1,
	"ssid2":			"TOTOLINK VAP0",
	"bssid2":			"00:E0:4C:81:86:86",
	"wifiKey2":		"12345678",
	"staNum2":		0,
	"wifiOff3":		1,
	"ssid3":			"TOTOLINK 5G VAP2",
	"bssid3":			"00:E0:4C:81:86:86",
	"wifiKey3":		"12345678",
	"staNum3":		0,
	"authMode":		"WPA2PSK;NONE;NONE",
	"encrypType":		"AES;NONE;NONE",
	"bssidNum":		3,
	"apcliEnable":		0,
	"apcliSsid":		"Extender",
	"apcliAuthMode":	"WPAPSKWPA2PSK",
	"apcliEncrypType":	"AES",
	"apcliKey":		"12345678",
	"apcliBssid":		"00:00:00:00:00:00",
	"apcliStatus":		"fail"
}
Return parameter description:
operationMode	-operation mode. eg: 0:gateway,1:bridge 2:repeater,3:wisp
channel			-wifi channel
autoChannel		-wifi auto channel
band			-wifi band 1 : 11b, 2 : 11a, 4 : 11g, 8 : 11na, 9 : 11ng, 14 : 11ac
wifiOff1(2,3)		-wifi on/off 1 : off, 0 : on
ssid1(2,3)		-wifi ssid
bssid1(2,3)		-wifi bssid(mac)
wifiKey1(2,3)		-wifi key
staNum1(2,3)		-wifi client connections.
authMode 		-wifi encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK},
						AP/CPE {WPAPSKWPA2PSK,NONE}.
encrypType 		-wifi encryption key type {NONE,WEP,AES,TKIP,TKIPAES}.
bssidNum     		-wifi ssid num
apcliEnable 		-apcli off/on. 1 : on, 0 : off
apcliSsid			-apcli ssid
apcliBssid 		-apcli bssid(mac)
apcliAuthMode 	-apcli encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK}
apcliEncrypType 	-apcli encryption key type {NONE,WEP,AES,TKIP}
apcliKey			-apcli key
apcliStatus 		-apcli connection state success, fail
</pre>
*
* @author Jarven
* @date    2017-11-07
*/
int getWiFiApInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
    char wlanif[8]={0},wlanif_va0[16]={0},wlanif_va1[16]={0},wlanif_vxd[16]={0};
	char tmpBuf[65]={0},buff[16]={0},cmd[128]={0},ssid[33]={0},hw[18]={0};
	char authmode1[16]={0},authmode2[16]={0},authmode3[16]={0},authmode[64]={0},enc1[8]={0},enc2[8]={0},enc3[8]={0},enc[32]={0};
    int intVal=0,total_sta_num=0,total_va0_num=0,total_va1_num=0,total_mesh_num=0;
	bss_info bss;	
	__FUNC_IN__
		
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlanif,"wlan%d",WiFiIdx);
	sprintf(wlanif_va0,"wlan%d-va0",WiFiIdx);
	sprintf(wlanif_va1,"wlan%d-va1",WiFiIdx);
	sprintf(wlanif_vxd,"wlan%d-vxd",WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n",wlanif);
    SetWlan_idx(wlanif);

	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());
	
	apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
    cJSON_AddNumberToObject(root,"channel",intVal);
	cJSON_AddNumberToObject(root,"autoChannel",getWirelessChannel(wlanif));
	cJSON_AddNumberToObject(root,"band",getWirelessBand(wlanif));

	//wlan0/1
	sprintf(cmd,"ifconfig | grep -v vxd |grep wlan%d | awk 'NR==1{print $1}'",WiFiIdx);
	getCmdStr(cmd,tmpBuf,sizeof(tmpBuf));
	if(strcmp(tmpBuf,""))//enable
		intVal=0;
	else
		intVal=1;
	cJSON_AddNumberToObject(root,"wifiOff1",intVal);
	
	apmib_get(MIB_WLAN_SSID, (void *)ssid);
    cJSON_AddStringToObject(root,"ssid1",ssid);
	
	getIfMac(wlanif,hw);
    cJSON_AddStringToObject(root,"bssid1",hw);

	sprintf(authmode1,"%s",getAuthMode(wlanif));
	sprintf(enc1,"%s",getEncrypType(wlanif));
	cJSON_AddStringToObject(root,"key1",getWirelessKey(wlanif));
	
	memset(tmpBuf,0x00,sizeof(tmpBuf));
#if defined(SUPPORT_MESH)
	sprintf(tmpBuf,"cat /proc/%s/mesh_assoc_mpinfo | grep mesh_num | cut -f2 -d:",wlanif);
	total_mesh_num=getCmdVal(tmpBuf);	
#endif
	memset(tmpBuf,0x00,sizeof(tmpBuf));
	sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",wlanif);
	if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
		if(strlen(tmpBuf))
			total_sta_num=atoi(tmpBuf)-total_mesh_num; 	
		else
			total_sta_num=0;
	}	
	cJSON_AddNumberToObject(root,"staNum1",total_sta_num);	

	//wlan0/1-va0
	SetWlan_idx(wlanif_va0);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wifiOff2",intVal);

    apmib_get(MIB_WLAN_SSID, (void *)ssid);
	cJSON_AddStringToObject(root,"ssid2",ssid);

	getIfMac(wlanif_va0,hw);
	cJSON_AddStringToObject(root,"bssid2",hw);

	sprintf(authmode2,"%s",getAuthMode(wlanif_va0));
	sprintf(enc2,"%s",getEncrypType(wlanif_va0));
	cJSON_AddStringToObject(root,"key2",getWirelessKey(wlanif_va0));

	if(intVal==0){
		memset(tmpBuf,0x00,sizeof(tmpBuf));
		sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",wlanif_va0);
		if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
			if(strlen(tmpBuf))
				total_va0_num=atoi(tmpBuf);		
			else
				total_va0_num=0;
		}
		cJSON_AddNumberToObject(root,"staNum2",total_va0_num);
	}else{
		cJSON_AddNumberToObject(root,"staNum2",0);
	}

	//wlan0/1-va1
    SetWlan_idx(wlanif_va1);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wifiOff3",intVal);

	apmib_get(MIB_WLAN_SSID, (void *)ssid);
    cJSON_AddStringToObject(root,"ssid3",ssid);

	getIfMac(wlanif_va1,hw);
    cJSON_AddStringToObject(root,"bssid3",hw);

	sprintf(authmode3,"%s",getAuthMode(wlanif_va1));
	sprintf(enc3,"%s",getEncrypType(wlanif_va1));
	cJSON_AddStringToObject(root,"key3",getWirelessKey(wlanif_va1));


	if(intVal==0){
		memset(tmpBuf,0x00,sizeof(tmpBuf));
		sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",wlanif_va1);
	    if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
			if(strlen(tmpBuf))
				total_va1_num=atoi(tmpBuf);		
			else
				total_va1_num=0;
		}
	    cJSON_AddNumberToObject(root,"staNum3",total_va1_num);
	}else{
		cJSON_AddNumberToObject(root,"staNum3",0);
	}
	
	sprintf(authmode,"%s;%s;%s",authmode1,authmode2,authmode3);
	sprintf(enc,"%s;%s;%s",enc1,enc2,enc3);
    cJSON_AddStringToObject(root,"authMode",authmode);
    cJSON_AddStringToObject(root,"encrypType",enc);
	cJSON_AddNumberToObject(root,"bssidNum",3);

	//wlan0/1-vxd
	SetWlan_idx(wlanif_vxd);
	if(WiFiIdx==0){
        apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);
		apmib_get(MIB_REPEATER_SSID1, (void *)ssid);
    }else{
        apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);
		apmib_get(MIB_REPEATER_SSID2, (void *)ssid);
    }
	cJSON_AddNumberToObject(root,"apcliEnable",intVal);
	cJSON_AddStringToObject(root,"apcliSsid",ssid);
    cJSON_AddStringToObject(root,"apcliAuthMode",getAuthMode(wlanif_vxd));
    cJSON_AddStringToObject(root,"apcliEncrypType",getEncrypType(wlanif_vxd));
	cJSON_AddStringToObject(root,"apcliKey",getWirelessKey(wlanif_vxd));	
	getWlBssInfo(wlanif_vxd,&bss);				
	sprintf(hw,"%02X:%02X:%02X:%02X:%02X:%02X",
		bss.bssid[0],bss.bssid[1],bss.bssid[2],
		bss.bssid[3],bss.bssid[4],bss.bssid[5]);
	cJSON_AddStringToObject(root,"apcliBssid",hw);
	
	if(getRepeaterStatus(wlanif_vxd)==1){
		cJSON_AddStringToObject(root,"apcliStatus","success");
	}else{
		cJSON_AddStringToObject(root,"apcliStatus","fail");
	}

	SetWlan_idx(wlanif);
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

#if defined(SUPPORT_CPE)
int syncWdsWifiCfg()
{
	int wdsNum=0,i=0,band=0,channel=0,wifiBonding=0,regdomain=0;
	char slaveIp[32]={0},tmpCmd[128]={0},country_str[8]={0};
	WDS_T  entry;
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_CHANNEL,(void *)&channel);
	apmib_get(MIB_WLAN_CHANNEL_BONDING,(void *)&wifiBonding);
	apmib_get(MIB_WLAN_BAND,(void *)&band);
	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)country_str);
	apmib_get(MIB_HW_REG_DOMAIN, (void *)&regdomain);
	apmib_get(MIB_WLAN_WDS_NUM,(void *)&wdsNum);
	for (i=1; i<=wdsNum; i++) 
	{
		*((char *)&entry) = (char)i;
		if(!apmib_get(MIB_WLAN_WDS, (void *)&entry))
		{
			printf("get mib MIB_DHCPRSVDIP_TBL fail!\n");
			return -1;
		}	

		if(entry.macAddr[5] == 0)
			entry.macAddr[5]=1;
		if(entry.macAddr[5] == 255)
			entry.macAddr[5]=254;
		sprintf(slaveIp,"192.168.166.%d",entry.macAddr[5]);
		sprintf(tmpCmd,"cs_pub %s syncWdsWificonfig {\\\"country_str\\\":\\\"%s\\\",\\\"channel\\\":\\\"%d\\\",\\\"wifiBonding\\\":\\\"%d\\\",\\\"band\\\":\\\"%d\\\",\\\"regdomain\\\":\\\"%d\\\"}",
			slaveIp,country_str,channel,wifiBonding,band,regdomain);
		printf("tmpCmd [ %s ]\n", tmpCmd);
		system(tmpCmd);
	}
	return 0;
}
int syncWdsWificonfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int channel = atoi(websGetVar(data, T("channel"), T("0")));
	int band = atoi(websGetVar(data, T("band"), T("0")));
	int wifiBonding = atoi(websGetVar(data, T("wifiBonding"), T("0")));
	int regdomain = atoi(websGetVar(data, T("regdomain"), T("0")));
	int country_str = websGetVar(data, T("country_str"), T("0"));

	SetWlan_idx("wlan0");
	apmib_set(MIB_WLAN_CHANNEL,(void *)&channel);
	apmib_set(MIB_WLAN_CHANNEL_BONDING,(void *)&wifiBonding);
	apmib_set(MIB_WLAN_BAND,(void *)&band);
	apmib_set(MIB_WLAN_COUNTRY_STRING, (void *)country_str);
	apmib_set(MIB_HW_REG_DOMAIN, (void *)&regdomain);
	apmib_update(HW_SETTING);
	int pid=fork();
	if(0 == pid){
		//sleep(1);
		apmib_update_web(CURRENT_SETTING);
		takeEffectWlan("wlan0", 1);
		exit(1);
	}
	return 0;
}
int setAutoWdsCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int repeater=0,pid=0,wdsEnable=0;
	int  i=1;
	WDS_T macEntry;
	int autoWdsEnabled = atoi(websGetVar(data, T("autoWdsEnabled"), T("0")));
	apmib_set(MIB_AUTO_WDS,(void *)&autoWdsEnabled);
	if(autoWdsEnabled==0)  //repeater 
	{
		SetWlan_idx("wlan0");
		apmib_set(MIB_WLAN_WDS_ENABLED, (void *)&wdsEnable);
		SetWlan_idx("wlan0-vxd");//wlan
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&repeater);
		repeater=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&repeater);
	}
	else
	{
		system("csteSys csnl 2 -1");
		sleep(1);
		system("csteSys csnl 2 1");
	}
	apmib_update_web(CURRENT_SETTING);	

	websSetCfgResponse(mosq, tp, "60", "reserv");
	if(autoWdsEnabled==0)
	{
		pid=fork();
		if(0 == pid){
			sleep(2);
			system("reboot");
			exit(1);
		}
	}
	return 0;
}
int getAutoWdsCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	int autoWdsEnabled=0;
	apmib_get(MIB_AUTO_WDS,(void *)&autoWdsEnabled);
	
	cJSON_AddNumberToObject(root,"autoWdsEnabled",autoWdsEnabled);
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}

#endif

/**
* @note setWiFiBasicConfig Set WiFi Basic Config
*
* @param Setting Json Data
<pre>
{
	"addEffect":	"0",
	"wifiIdx":		"0",
	"wifiOff":		"0",
	"countryStr":	"CN",
	"ssid":		"TOTOLINK_A810R_5G",
	"band":		"14",
	"channel":	"149",
	"bw":		"1",	
	"hssid":		"0",
	"authMode":	"WPAPSKWPA2PSK",
	"encrypType":	"TKIPAES",
	"keyFormat":	"0",
	"wepkey":	"",
	"wpakey":	"12345678",
	"wscEnabled":	"0"
}
Setting parameter description:
addEffect 	- action
wifiIdx 		- wifi index 0 : 5G, 1 : 2.4G
wifiOff 		- wifi on/off 1 : off, 0 : on
countryStr 	- wifi country China(CN), USA(US), Europe(EU), Other(OT)
ssid 			- wifi ssid
band 		- wifi band 1 : 11b, 2 : 11a, 4 : 11g, 8 : 11na, 9 : 11ng, 14 : 11ac
channel 		- wifi channel
bw 			- wifi bandwidth 0 : 20M, 1 : 40M, 2 : 80M
hssid 		- wifi hide ssid, 1 : hide, 0 : show
authMode 	- wifi encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}, 
					  AP/CPE {NONE, WPAPSKWPA2PSK}
encrypType 	- wifi encryption key type {NONE,WEP,AES,TKIP,TKIPAES}
keyFormat 	- wifi key type  0 : ASCII, 1 : Hex
wepkey 		- wifi wep key
wpakey 		- wifi wpa key
wscEabled 	- wsc support flag
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiBasicConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0},cmd[128]={0};
	int pid,opmode,rpt_enabled,wifi_disabled;	
	__FUNC_IN__
		
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);
    
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
    if (addEffect){
		int wifiOff = atoi(websGetVar(data, T("wifiOff"), T("0"))); 
		apmib_get(MIB_OP_MODE, (void *)&opmode);
		if (opmode!=GATEWAY_MODE){//repeater & wisp
			if (wifiOff){//disable wlan
			    wifi_disabled=1;
			    rpt_enabled=0;				
	        }else{//enable wlan
	        	int wlan_id=0;
				apmib_get(MIB_WISP_WAN_ID, (char *)&wlan_id);
	            wifi_disabled=0;
				if (opmode==WISP_MODE){
					if(wlan_id==WiFiIdx){
			    		rpt_enabled=1;
			    	}else{
						rpt_enabled=0;
					}
				}else{
					rpt_enabled=0;
				}
	        }
		    apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifi_disabled);
			if (WiFiIdx==0){
		    	apmib_set(MIB_REPEATER_ENABLED1, (char *)&rpt_enabled);
			}else{
				apmib_set(MIB_REPEATER_ENABLED2, (char *)&rpt_enabled);
			}
        }else{//gw
            if (wifiOff){				
                wifi_disabled=1;
            }else{
                wifi_disabled=0;
			}
	     	apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifi_disabled);
			rpt_enabled=0;
		//	if (WiFiIdx==0)
		    apmib_set(MIB_REPEATER_ENABLED1, (char *)&rpt_enabled);
		//	else
			apmib_set(MIB_REPEATER_ENABLED2, (char *)&rpt_enabled);
        }
		memset(cmd,0,sizeof(cmd));

		if(wifi_disabled==1)
			sprintf(cmd,"ifconfig %s down",wlan_if);
		else
			sprintf(cmd,"ifconfig %s up",wlan_if);
		CsteSystem(cmd,1);
		sprintf(cmd,"csteSys setWifiLedCtrl %d %d ",WiFiIdx,wifiOff);
		CsteSystem(cmd,CSTE_PRINT_CMD);

        websSetCfgResponse(mosq, tp, "20", "reserv");

		pid=fork();
		if(0 == pid){
			//sleep(1);
			apmib_update_web(CURRENT_SETTING);
#if 0//defined(CS_MESH_SYNC)
			sleep(2);
			CsteSystem("reboot",1);
#else
			takeEffectWlan(wlan_if, 1);
#endif
			exit(1);
		}
		
		if (opmode!=GATEWAY_MODE){
			if (rpt_enabled==1){//close wifi and close wlan-vxd
				sprintf(cmd,"ifconfig %s-vxd up",wlan_if);
			}else{
				sprintf(cmd,"ifconfig %s-vxd down",wlan_if);
			}
	    	CsteSystem(cmd,CSTE_PRINT_CMD);
		}
        return 0;
	}
    else{
		char_t *ssid = websGetVar(data, T("ssid"), T(""));		
        char_t *auth_mode = websGetVar(data, T("authMode"), T(""));
        char_t *encryp_type = websGetVar(data, T("encrypType"), T(""));        
        char_t *wepkey = websGetVar(data, T("wepkey"), T(""));
        char_t *key = websGetVar(data, T("key"), T(""));
		char_t *countryCode = websGetVar(data, T("countryCode"), T(""));
		int key_format= atoi(websGetVar(data, T("keyFormat"), T("0")));
		int hssid = atoi(websGetVar(data, T("hssid"), T("0")));
		int channel = atoi(websGetVar(data, T("channel"), T("0")));
        int wsc_disable = atoi(websGetVar(data, T("wscDisabled"), T("0")));
		int band = atoi(websGetVar(data, T("band"), T("9")));		
		int bw = atoi(websGetVar(data, T("bw"), T("0")));
#if defined(SUPPORT_MESH)
		int flag= atoi(websGetVar(data, T("majorDevMsg"), T("0")));
		if(flag){
			char hssidBuf[8]={0},channelBuf[16]={0};
			apmib_get(MIB_WLAN_CHANNEL, (void *)&channel);
			apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);
			apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&wsc_disable);
		}
#endif
		int apbw=0;
		if(bw==3)
			apbw=bw=2;
		else if(bw==1)
			apbw=bw=0;
		else if(bw==2)
			apbw=bw=1;
		else if(bw==0)
		{
			bw=2;
			apbw=3;
		}
	
#if defined(SUPPORT_CPE)
		char *apname = websGetVar(data, T("apName"), T(""));
		apmib_set(MIB_APNAME, (char *)apname);
#endif

#if defined(SUPPORT_APAC)
		int itx_power = atoi(websGetVar(data, T("txPower"), T("0")));
		apmib_set(MIB_WLAN_RFPOWER_SCALE, (void *)&itx_power);
#endif

		//BAND
        int iband=11;
        switch(band){
            case 0 :
                iband = BAND_11BG; // 3
                break;
            case 1 :
                iband = BAND_11B; // 1
                break;
            case 2 :
                iband = BAND_11A; // 4
                break;
            case 4 :
                iband = BAND_11G; // 2
                break;
            case 6 :
                iband = BAND_11N; // 8
                break;
            case 8 :
                iband = BAND_5G_11AN; // 12
                break;
            case 9 :
                iband = BAND_11GBN;
                break;
            case 14 :
                iband = BAND_5G_11ANAC;
                break;
            case 75 :
                iband = 75;
                break;
            default :
                iband = BAND_11GBN;
        }
        apmib_set(MIB_WLAN_BAND, (char *)&iband);

		//BasicRate
        int basic_rates=15;
        if (band==4){ //g, gn
            basic_rates=351;
            apmib_set(MIB_WLAN_BASIC_RATES, (void *)&basic_rates);
        }else if (band==1){ //b
            basic_rates=3;
            apmib_set(MIB_WLAN_BASIC_RATES, (void *)&basic_rates);
        }else{ //bg,bgn,n
            apmib_set(MIB_WLAN_BASIC_RATES, (void *)&basic_rates);
        }
		
		//Broadcast SSID
		apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);

		//WSC		
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_disable);
		
		//Channel
		apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);
		//BW
		apmib_set(MIB_AP_BW, (void *)&apbw);
		apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&bw);
		//Country/RegDomain
		int regdomain=13;
		apmib_set(MIB_WLAN_COUNTRY_STRING, (void *)countryCode);
		if(!strcmp(countryCode,"US")){//usa
			regdomain=1;
		}else if(!strcmp(countryCode,"EU")){//europe
			regdomain=3;
		}else if(!strcmp(countryCode,"IA")){//Indonesia
			regdomain=13;
		}else if(!strcmp(countryCode,"OT")){//other
			regdomain=16;
		}else{//china
			regdomain=13;
		}

		apmib_set(MIB_HW_REG_DOMAIN, (void *)&regdomain);
		apmib_update(HW_SETTING);
		
        //SSID
        apmib_set(MIB_WLAN_SSID, (char *)ssid);
		
#ifdef WIFI_SIMPLE_CONFIG
		memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
		wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
		apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
		apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
		strncpy(wps_config_info_tmp.ssid, ssid, strlen(ssid));
		wps_config_info_tmp.wlan_mode=wps_config_info.wlan_mode;
		update_wps_configured(0);
#endif 

		ENCRYPT_T encrypt=ENCRYPT_DISABLED;
		int auth_wpa1=WPA_AUTH_PSK,enc1=ENCRYPT_WPA2_MIXED,keyFmt1=0,ciphersuite1=WPA_CIPHER_MIXED;
		if(strlen(key)){
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&enc1);
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&keyFmt1);
            apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
            apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key);
			apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa1);
#ifdef WIFI_SIMPLE_CONFIG
			wps_config_info.caller_id = CALLED_FROM_WPAHANDLER;
			apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
			apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
			wps_config_info_tmp.auth=enc1;
			wps_config_info_tmp.wpa_enc=ciphersuite1;
			wps_config_info_tmp.wpa2_enc=ciphersuite1;
			wps_config_info_tmp.shared_type=auth_wpa1;
			
			memset(wps_config_info_tmp.wpaPSK,0,sizeof(wps_config_info_tmp.wpaPSK));
			strncpy(wps_config_info_tmp.wpaPSK, key, strlen(key));
			update_wps_configured(0);
#endif
		}
		else{
			encrypt=ENCRYPT_DISABLED;
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_set(MIB_WLAN_WPA_PSK, "");
#ifdef WIFI_SIMPLE_CONFIG
			wps_config_info.caller_id=0;
			wps_config_info_tmp.auth=encrypt;
			update_wps_configured(0);
#endif 			
		}


#if defined(SUPPORT_MESH)
		system("sysconf updateAllMeshInfo");
#endif		
		//修改主AP的频段，同时需要改变多AP的频段 
		int vap0_disable,vap1_disable,vap_band;
		char ifname_24g[8]={0},ifname_24gm1[16]={0},ifname_24gm2[16]={0};
		char ifname_5g[8]={0},ifname_5gm1[16]={0},ifname_5gm2[16]={0};

#ifdef FOR_DUAL_BAND
		sprintf(ifname_5g,"%s","wlan0");//设置wlan0为5G接口
		sprintf(ifname_5gm1,"%s-va0",ifname_5g);
		sprintf(ifname_5gm2,"%s-va1",ifname_5g);
		SetWlan_idx(ifname_5g);
		apmib_get(MIB_WLAN_BAND, (void *)&vap_band);
		
		SetWlan_idx(ifname_5gm1);//设置wlan0-va0
		apmib_set(MIB_WLAN_BAND, (char *)&vap_band);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&vap0_disable);
		if (!vap0_disable){ //enable
			takeEffectWlan(ifname_5gm1, 0);
		}
				
		SetWlan_idx(ifname_5gm2);//设置wlan0-va1
		apmib_set(MIB_WLAN_BAND, (char *)&vap_band);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&vap1_disable);
		if (!vap1_disable) {//enable
			takeEffectWlan(ifname_5gm2, 0);
		}
		
		sprintf(ifname_24g,"%s","wlan1");//设置wlan1为2.4接口
#else
		sprintf(ifname_24g,"%s","wlan0");//设置wlan0为2.4接口
#endif
#if defined(SUPPORT_CPE)
		syncWdsWifiCfg();
#endif

		sprintf(ifname_24gm1,"%s-va0",ifname_24g);
		sprintf(ifname_24gm2,"%s-va1",ifname_24g);
		SetWlan_idx(ifname_24g);
		apmib_get(MIB_WLAN_BAND, (void *)&vap_band);
		
		SetWlan_idx(ifname_24gm1);//设置wlan0-va0		
		apmib_set(MIB_WLAN_BAND, (char *)&vap_band);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&vap0_disable);
		if (!vap0_disable){//enable
			takeEffectWlan(ifname_24gm1, 0);
		}
			
		SetWlan_idx(ifname_24gm2);//设置wlan0-va1
		apmib_set(MIB_WLAN_BAND, (char *)&vap_band);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&vap1_disable);
		if (!vap1_disable) {//enable
			takeEffectWlan(ifname_24gm2, 0);
		}
		
		websSetCfgResponse(mosq, tp, "10", "reserv");

		pid=fork();
		if(0 == pid){
			//sleep(1);
			apmib_update_web(CURRENT_SETTING);
			
#if 0//defined(CS_MESH_SYNC)
			sleep(2);
			CsteSystem("reboot",1);
#else
			takeEffectWlan(wlan_if, 1);
#endif
			exit(1);
		}
	}
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiBasicConfig - Get WiFi Basic Config
* 
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
{
	"channel":		149,
	"hssid":			0,
	"bw":			1,
	"ntpEnabled":		1,
	"wifiSchEnabled":	0,
	"wifiSchRule":		0,
	"wifiOff":			0,
	"ssid":			"TOTOLINK_A810R",
	"regDomain":		13,
	"countryStr":		"CN",
	"band":			14,
	"authMode":		"NONE",
	"encrypType":		"NONE",
	"keyFormat":		0,
	"wepkey":		"",
	"wpakey":		"",
	"apcliEnable":		0,
	"channelDfs":		1,
	"wifiDualband":	1,
	"countryBt":		0,
	"apAcBt":			0,
	"hardModel":		"04336"
}
Return parameter description:
channel 		- wifi channel
hssid 		- wifi hide ssid 1 : hide, 0 : show
bw 			- wifi bandwidth 0 : 20M, 1 : 40M, 2 : 80M
ntpEnabled	- ntp sync. switch
wifiSchEnabled- wifi schedul switch
wifiSchRule	- wifi schedul rules
wifiOff 		- wifi on/off 1 : off, 0 : on
ssid 			- wifi ssid
wepkey 		- wifi wep key
wpakey 		- wifi wpa key
regDomain	- wifi country(index): China(13), USA(1), Europe(3), Other(16)
countryStr 	- wifi country(string): China(CN), USA(US), Europe(EU), Other(OT)
band		- wifi band 1 : 11b, 2 : 11a, 4 : 11g, 8 : 11na, 9 : 11ng, 14 : 11ac
authMode 	- wifi encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}, 
					 AP/CPE {NONE,WPAPSKWPA2PSK}.
encrypType 	- wifi encryption key type {NONE,WEP,AES,TKIP,TKIPAES}
keyFormat 	- wifi key type, 0 : ASCII, 1 : Hex
wifiDualband 	- dualband frequency 1 : on, 0 : off
apcliEnable	- apcli interface switch 0: off, 1: on
channelDfs	- channel DFS support flag
countryBt 	- country support flag
apAcBt		- APAC support flag
hardModel	- hardware model
</pre>
* @author jarven
* @date    2017-11-14                                       
*/
int getWiFiBasicConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
	bss_info bss;
    cJSON *root=cJSON_CreateObject();
    char wlan_if[8]={0},wlanvxd_if[16]={0},tmpBuf[32]={0},tmpcmd[64]={0},buff[128]={0};
    unsigned char buff_key[65];
    int arraylen=0,wep,keytype,encrypt,pskformat,defkeyid,keyid,rpt_enabled,ntpEnabled,countrycode=0;
	int wlan_disable=0,mesh_enable=0,mesh_action=0,wiFiSchRule=0,channel=0,band=0,bw=0,apbw=0,op_mode=0;
	__FUNC_IN__
        
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

#if defined(SUPPORT_CPE)
	apmib_get(MIB_APNAME, (char *)tmpBuf);
	cJSON_AddStringToObject(root,"apName",tmpBuf);
#endif

	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());

    //int type mib
	char *IntGetName[]={"hssid","regDomain","wifiSchEnabled","wscDisabled","CountryCodeSupport"};
	int IntGetId[]={MIB_WLAN_HIDDEN_SSID,MIB_HW_REG_DOMAIN,MIB_WLAN_SCHEDULE_ENABLED,MIB_WLAN_WSC_DISABLE,MIB_COUNTRYCODE_SUPPORT};
    arraylen=sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
		
	wiFiSchRule=getCmdVal("cat /var/spool/cron/crontabs/root | grep WiFiSchedule | awk '{count++} END{print count}'");
	cJSON_AddNumberToObject(root,"wifiSchRule",wiFiSchRule);

	if(f_exist("/tmp/ntp_tmp"))
		ntpEnabled=getCmdVal("cat /tmp/ntp_tmp")==9?1:0;
	else
		apmib_get(MIB_NTP_ENABLED,(void *)&ntpEnabled);
	cJSON_AddNumberToObject(root,"ntpEnabled", ntpEnabled);

	apmib_get(MIB_WLAN_BAND, (void *)&band);
	apmib_get(MIB_WLAN_CHANNEL_BONDING, (void *)&bw);
	apmib_get(MIB_AP_BW, (void *)&apbw);
	if(apbw==3)
		bw=0;
	else
	{
		if(bw==1)
			bw=2;
		else if(bw==0)
			bw=1;
		else if(bw==2)
			bw=3;
 	}
	
	sprintf(buff,"%d",bw);
	cJSON_AddStringToObject(root, "bw",buff);
	sprintf(tmpcmd,"ifconfig | grep -v vxd | grep -v va |grep wlan%d | awk 'NR==1{print $1}'",WiFiIdx);
	getCmdStr(tmpcmd,tmpBuf,sizeof(tmpBuf));
	if(strcmp(tmpBuf,""))//enable
		wlan_disable=0;
	else
		wlan_disable=1;
	cJSON_AddNumberToObject(root,"wifiOff",wlan_disable);
	
#if defined(SUPPORT_MESH)	
	mesh_action=getCmdVal("cat /proc/kl_reg  | grep mesh_action | cut -f2 -d=");
	cJSON_AddNumberToObject(root,"meshAction",mesh_action);
#endif	

    //str type mib
	char *StrGetName[]={"ssid","key","countryCode","countryCodeList"};
	int StrGetId[]={MIB_WLAN_SSID,MIB_WLAN_WPA_PSK,MIB_WLAN_COUNTRY_STRING,MIB_COUNTRYCODE_LIST};
    arraylen=sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);
	getWlBssInfo(wlan_if, &bss);			
	memcpy(tmpBuf, bss.ssid, 32+1); 		
	if(strlen(tmpBuf)==0){				
		SetWlan_idx(wlan_if);
		apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
		cJSON_AddStringToObject(root,"ssid",tmpBuf);
	}
	band=getWirelessBand(wlan_if);
	sprintf(buff,"%d",band);
	cJSON_AddStringToObject(root,"band",buff);
      
    if(WiFiIdx==0){
        apmib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
    }else{
        apmib_get(MIB_REPEATER_ENABLED2, (void *)&rpt_enabled);
    }    
	cJSON_AddNumberToObject(root,"apcliEnable",rpt_enabled);
	
	if(rpt_enabled==1&&getRepeaterStatus(wlanvxd_if)==1)	
		channel=getWirelessChannel(wlan_if);
	else
		apmib_get(MIB_WLAN_CHANNEL,(void *)&channel);
	sprintf(buff,"%d",channel);
	cJSON_AddStringToObject(root, "channel",buff);

	
#if defined(CONFIG_RTL_DFS_SUPPORT)
	cJSON_AddNumberToObject(root,"channelDfs",1);
#else
	cJSON_AddNumberToObject(root,"channelDfs",0);
#endif

#if defined(FOR_DUAL_BAND)
	cJSON_AddNumberToObject(root,"wifiDualband",1);
#else
	cJSON_AddNumberToObject(root,"wifiDualband",0);
#endif

	apmib_get(MIB_COUNTRYCODE_SUPPORT, (void *)&countrycode);
	cJSON_AddNumberToObject(root,"countryBt",countrycode);
	

#if defined(SUPPORT_MESH)
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable);
	cJSON_AddNumberToObject(root,"meshEnable",mesh_enable);
#else
	cJSON_AddNumberToObject(root,"meshEnable",0);	
#endif

#if defined(SUPPORT_APAC)
	int itx_power=0;
	apmib_get(MIB_WLAN_RFPOWER_SCALE, (void *)&itx_power);
	cJSON_AddNumberToObject(root,"txPower",itx_power);
	cJSON_AddStringToObject(root,"apAcBt","1");
#else
	cJSON_AddStringToObject(root,"apAcBt","0");
#endif

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	apmib_get(MIB_CSID,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"csid",tmpBuf);

	SetWlan_idx(wlan_if);	
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note setWiFiAdvancedConfig - Set WiFi Advanced Config
*
* @param Setting Json Data
<pre>
{
	"wifiIdx" : 		"0",
	"bgProtection":	"1",
	"beaconPeriod":	"100",
	"dtimPeriod":		"1",
	"fragThreshold":	"2346",
	"rtsThreshold":	"2347",
	"txPower":		"100",
	"noForwarding":	"0",
	"htBSSCoexistence":	"0",
	"wmmCapable":	"1",
	"txPreamble":		"0",
	"beamforming":	"0"
}
Setting parameter description:
wifiIdx 			- wifi index 0 : 5G, 1 : 2.4G
bgProtection		- BG protection Mode. 0:Auto,1:On,2:Off
beaconPeriod		- Beacon interval. range: 20-999, default : 100
dtimPeriod		- Data beacon rate(DTIM). range:1-255, default : 1
fragThreshold		- Fragment threshold. range:256-2346, default: 2346.
rtsThreshold		- RTS threshold. range:1-2347, default:2347
txPower 			- TX Power,Two ways to display. 
					percentage:100			75			50		   35		  15	  (%)	
					distance  :100(2400)    75(1200)    50(600)    35(300)    15(150) (m)	
				   Only CPE products support distance
noForwarding		- AP Isolated. 0:Disable,1:Enable
htBSSCoexistence	- 20/40 Coexistence. 0:Disable,1:Enable
wmmCapable		- WMM Capable. 0:Disable,1:Enable
txPreamble		- Preamble Type. 0:Long Preamble,1:Short Preamble
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiAdvancedConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int pid,va0_disabled=1,va1_disabled=1;
    char wlan_if[8]={0},wlan_va0_if[16]={0},wlan_va1_if[16]={0};
    int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	__FUNC_IN__
		
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	SetWlan_idx(wlan_if);
	
    int ibg_protection  =atoi(websGetVar(data, T("bgProtection"), T("0")));
    int ibeacon         =atoi(websGetVar(data, T("beaconPeriod"), T("100")));
	int idtim           =atoi(websGetVar(data, T("dtimPeriod"), T("1")));
	int ifragment       =atoi(websGetVar(data, T("fragThreshold"), T("2346")));
	int irts            =atoi(websGetVar(data, T("rtsThreshold"), T("2347")));
	int itx_power       =atoi(websGetVar(data, T("txPower"), T("100")));
	int inoforwarding   =atoi(websGetVar(data, T("noForwarding"), T("0")));
    int iwmm_capable    =atoi(websGetVar(data, T("wmmCapable"), T("0")));
	int i2040_coexit  	=atoi(websGetVar(data, T("htBssCoexistence"), T("0")));
	int ishort_preamble =atoi(websGetVar(data, T("txPreamble"), T("0")));
	int ibeamforming 	=atoi(websGetVar(data, T("beamforming"), T("0")));
	int tdma_enable 	=atoi(websGetVar(data, T("tdmaEnable"), T("0")));
	int tdma_only 		=atoi(websGetVar(data, T("tdmaOnly"), T("0")));
	
	apmib_set(MIB_WLAN_PROTECTION_DISABLED, (void *)&ibg_protection);
	apmib_set(MIB_WLAN_BEACON_INTERVAL, (void *)&ibeacon);
	apmib_set(MIB_WLAN_DTIM_PERIOD, (void *)&idtim);
	apmib_set(MIB_WLAN_FRAG_THRESHOLD, (void *)&ifragment);
	apmib_set(MIB_WLAN_RTS_THRESHOLD, (void *)&irts);
	apmib_set(MIB_WLAN_RFPOWER_SCALE, (void *)&itx_power);
	apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&inoforwarding);
	apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&iwmm_capable);
	apmib_set(MIB_WLAN_COEXIST_ENABLED, (void *)&i2040_coexit);
	apmib_set(MIB_WLAN_PREAMBLE_TYPE, (void *)&ishort_preamble);
	apmib_set(MIB_WLAN_TX_BEAMFORMING, (void *)&ibeamforming);
	
#if defined(SUPPORT_CPE)
	int ackTimeOut =atoi(websGetVar(data, T("ackTimeOut"), T("100")));
	apmib_set(MIB_WLAN_ACK_TIMEOUT,(void *)&ackTimeOut);
#endif

#ifdef RTK_SW_TDMA
	apmib_set(MIB_WLAN_TDMA_ENABLE, (void *)&tdma_enable);
	apmib_set(MIB_WLAN_TDMA_ONLY, (void *)&tdma_only);
	SetWlan_idx("wlan0-vxd");
	apmib_set(MIB_WLAN_TDMA_ENABLE, (void *)&tdma_enable);
#endif

	SetWlan_idx(wlan_va0_if);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va0_disabled);
	apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&inoforwarding);
	
	SetWlan_idx(wlan_va1_if);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va1_disabled);
	apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&inoforwarding);
	
	SetWlan_idx(wlan_if);

	pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
	
#if defined(SUPPORT_MESH)
	system("sysconf updateAllMeshInfo");
#endif
#ifdef RTK_SW_TDMA	
    pid=fork();
	if(0 == pid)
	{
		takeEffectWlan("wlan0-vxd", 1);
		exit(1);
	}
#endif	
    pid=fork();
	if(0 == pid)
	{
		if(va0_disabled==0)	takeEffectWlan(wlan_va0_if, 1);
		exit(1);
	}

	pid=fork();
	if(0 == pid){
		if(va1_disabled==0) takeEffectWlan(wlan_va1_if, 1);
		exit(1);
	}
	
	pid=fork();
	if(0 == pid){
		takeEffectWlan(wlan_if, 1);
		exit(1);
	}
	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiAdvancedConfig - Get WiFi Advanced Config
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
{
	"bgProtection":	1,
	"beaconPeriod":	100,
	"htBssCoexistence":	0,
	"dtimPeriod":		1,
	"fragThreshold":	2346,
	"rstThreshold":	2347,
	"txPreamble":		1,
	"wmmCapable":	1,
	"beamforming":	0,
	"noForwarding":	0,
	"txPower":		0,
	"band":			14,
}
Return parameter description:
bgProtection		- BG protection Mode. 0:Auto,1:On,2:Off
beaconPeriod		- Beacon interval. range: 20-999,default : 100
htBssCoexistence	- 20/40 Coexistence. 0:Disable,1:Enable
dtimPeriod		- Data beacon rate(DTIM). range:1-255, default : 1
fragThreshold 		- Fragment threshold. range:256-2346, default: 2346.
rtsThreshold 		- RTS threshold. range:1-2347, default:2347
txPreamble 		- Preamble Type. 0:Long Preamble,1:Short Preamble
wmmCapable		- WMM Capable. 0:Disable,1:Enable
noForwarding 		- AP Isolated. 0:Disable,1:Enable
txPower 			- TX Power,Two ways to display. 
					percentage:100			75			50		   35		  15	  (%)	
					distance  :100(2400)    75(1200)    50(600)    35(300)    15(150) (m)			
				  Only CPE products support distance
band 			- Wireless mode,1:11b,2:11a,4:11g,8:11na,9:11ng,14:11ac.
</pre>
* @author Jarven
* @date    2017-11-14
*/
int getWiFiAdvancedConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
    char wlan_if[8]={0};
    int arraylen=0,tdma=0,tdma_only=0;
	__FUNC_IN__
	
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

    //int type mib
	char *IntGetName[]={"opMode","meshEnable","bgProtection","beaconPeriod","htBssCoexistence",\
	    "dtimPeriod","fragThreshold","rtsThreshold","txPreamble",\
	    "wmmCapable","beamforming","noForwarding","txPower","ackTimeOut"};
	int IntGetId[]={MIB_OP_MODE,MIB_WLAN_MESH_ENABLE,MIB_WLAN_PROTECTION_DISABLED,MIB_WLAN_BEACON_INTERVAL,MIB_WLAN_COEXIST_ENABLED,\
	    MIB_WLAN_DTIM_PERIOD,MIB_WLAN_FRAG_THRESHOLD,MIB_WLAN_RTS_THRESHOLD,MIB_WLAN_PREAMBLE_TYPE,\
	    MIB_WLAN_WMM_ENABLED,MIB_WLAN_TX_BEAMFORMING,MIB_WLAN_BLOCK_RELAY,MIB_WLAN_RFPOWER_SCALE,MIB_WLAN_ACK_TIMEOUT};
    arraylen=sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
#ifdef RTK_SW_TDMA
	apmib_get(MIB_WLAN_TDMA_ENABLE,(void *)&tdma);
	apmib_get(MIB_WLAN_TDMA_ONLY,(void *)&tdma_only);
	cJSON_AddNumberToObject(root,"tdmaEnable",tdma);	
	cJSON_AddNumberToObject(root,"tdmaOnly",tdma_only);
#endif

	cJSON_AddNumberToObject(root,"band",getWirelessBand(wlan_if));

#if defined(FOR_DUAL_BAND)
	cJSON_AddNumberToObject(root,"wifiDualband",1);
#else
	cJSON_AddNumberToObject(root,"wifiDualband",0);
#endif

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

#if defined (MBSSID)
/**
* @note setWiFiMultipleConfig -Set Multiple AP Config
*
* @param Setting Json Data
<pre>
{
	"doAction":	0,
 	"wifiIdx" : 	0,
	"ssid":		"mytest",
	"hssid":		"0",
	"authMode":	"NONE",
	"encrypType":	"NONE",
	"keyFormat":	"1",
	"wepkey":	"",
	"wpakey":	""
}
Setting parameter description:
wifiIdx 		- wifi index 0 : 5G, 1 : 2.4G
wifiOff(2/3)	- wifi on/off 1 : off, 0 : on
ssid(2/3) 	- wifi ssid
hssid 		- wifi hide ssid 1: hide , 0: show
authMode 	- wifi encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}
encrypType 	- wifi encryption key type {NONE,WEP,AES,TKIP,TKIPAES}
keyFormat 	- wifi key type  0 : ASCII, 1 : Hex
wepkey(2/3)	- wifi wep key
wpakey(2/3)   - wifi wpa key
</pre>
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
* @author jarven
* @date    2017-11-21
*/
int setWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0}, wlan_va0_if[16]={0}, wlan_va1_if[16]={0};
    char hiddenssid[2]={0},authmode[16]={0},encryptype[8]={0},keyformat[2]={0};
    int hssid=0,keyfmt=0,wep=WEP_DISABLED,auth_wpa=WPA_AUTH_AUTO,encrypt=ENCRYPT_DISABLED;
	
	__FUNC_IN__
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	CSTE_DEBUG("~~~ wlan_vap0_if=[%s] wlan_vap1_if=[%s]~~~\n", wlan_va0_if, wlan_va1_if);

	//fetch from web input
	char_t *mssid2 = websGetVar(data, T("ssid2"), T(""));
	char_t *wepkey2 = websGetVar(data, T("wepkey2"), T(""));
	char_t *key2 = websGetVar(data, T("key2"), T(""));
	char_t *key3 = websGetVar(data, T("key3"), T(""));
	char_t *mssid3 = websGetVar(data, T("ssid3"), T(""));
	char_t *wepkey3 = websGetVar(data, T("wepkey3"), T(""));	

	char_t *hidden_ssid = websGetVar(data, T("hssid"), T(""));	
	char_t *auth_mode = websGetVar(data, T("authMode"), T(""));
	char_t *encryp_type = websGetVar(data, T("encrypType"), T(""));	
	char_t *key_format= websGetVar(data, T("keyFormat"), T(""));

	int doaction = atoi(websGetVar(data, T("doAction"), T("0")));
	int wifioff2 = atoi(websGetVar(data, T("wifiOff2"), T("0")));
	int wifioff3 = atoi(websGetVar(data, T("wifiOff3"), T("0")));
	int noforwanding2 = atoi(websGetVar(data, T("noForwarding2"), T("0")));
	int noforwanding3 = atoi(websGetVar(data, T("noForwarding3"), T("0")));

	//action 1:all 2:vap0 3:vap1
	if(doaction==1||doaction==2){
		SetWlan_idx(wlan_va0_if);

		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff2);
		apmib_set(MIB_WLAN_SSID, (void *)mssid2);
		apmib_set(MIB_WLAN_ACCESS, (void *)&noforwanding2);

	    checkVar(hidden_ssid,1,hiddenssid);
	    checkVar(auth_mode,1,authmode);
	    checkVar(encryp_type,1,encryptype);
	    checkVar(key_format,1,keyformat);	
		
		keyfmt=atoi(keyformat);
		hssid=atoi(hiddenssid);
	    apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);		

		ENCRYPT_T encrypt=ENCRYPT_DISABLED;
		int auth_wpa1=WPA_AUTH_PSK,enc1=ENCRYPT_WPA2_MIXED,keyFmt1=0,ciphersuite1=WPA_CIPHER_MIXED;
		if(strlen(key2)){
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&enc1);
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&keyFmt1);
	        apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	        apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key2);
			apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa1);
			}
		else{
			encrypt=ENCRYPT_DISABLED;
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_set(MIB_WLAN_WPA_PSK, "");			
		}
	}

	//action 1:all 2:vap0 3:vap1
	if(doaction==1||doaction==3){
		SetWlan_idx(wlan_va1_if);
		
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff3);
		apmib_set(MIB_WLAN_SSID, (void *)mssid3);
		apmib_set(MIB_WLAN_ACCESS, (void *)&noforwanding3);

	    checkVar(hidden_ssid,2,hiddenssid);
	    checkVar(auth_mode,2,authmode);
	    checkVar(encryp_type,2,encryptype);
	    checkVar(key_format,2,keyformat);

		keyfmt=atoi(keyformat);
		hssid=atoi(hiddenssid);
	    apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);

		ENCRYPT_T encrypt=ENCRYPT_DISABLED;
		int auth_wpa1=WPA_AUTH_PSK,enc1=ENCRYPT_WPA2_MIXED,keyFmt1=0,ciphersuite1=WPA_CIPHER_MIXED;
		if(strlen(key3)){
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&enc1);
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&keyFmt1);
	        apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	        apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key3);
			apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa1);
			}
		else{
			encrypt=ENCRYPT_DISABLED;
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_set(MIB_WLAN_WPA_PSK, "");			
		}
	}
	//takeEffectWlan(wlan_if, 1);
	
	int pid=fork();
	if(0 == pid){
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		CsteSystem("sysconf init gw all", CSTE_PRINT_CMD);
		exit(1);
	}
	
	websSetCfgResponse(mosq, tp, "20", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiMultipleConfig - Get WiFi Multiple AP Config
*
* @param  wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
{
	"wifiOff":		0,
	"ssid1":		"TOTOLINK_A810R",
	//"noForwarding2":0,
	"wifiOff2": 	1,
	"ssid2":		"TOTOLINK 5G VAP1",
	"wepKey2":	"",
	"wpaKey2":	"",
	//"noForwarding3":0,
	"wifiOff3": 	1,
	"ssid3":		"TOTOLINK 5G VAP2",
	"wepKey3":	"",
	"wpaKey3":	"",
	"hssid": 		"0;0",
	"authMode": 	"NONE;NONE",
	"encrypType":	"NONE;NONE",
	"keyFormat":	"0;0"
}
Return parameter description:
wifiOff 		- wifi on/off 1 : off, 0 : on
wifiOff2(3) 	- wifi on/off 1 : off, 0 : on
ssid2(3) 		- wifi ssid
hssid 		- wifi hide ssid 1 : hide, 0 : show
authMode	- wifi encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}
encrypType 	- wifi encryption key type {NONE,WEP,AES,TKIP,TKIPAES}
keyFormat 	- wifi key type 0 : ASCII, 1 : Hex
wepkey2(3) 	- wifi wep key	
wpakey2(3) 	- wifi wpa key
//noForwarding2(3)	- 
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0},wlan_va0_if[16]={0},wlan_va1_if[16]={0};
	char ssid[MAX_SSID_LEN]={0};	
    unsigned char buff_key[65]={0},wepkey[32]={0},wpapsk[65]={0};
	int noforwarding=0,wifioff=0,wep=0,defkeyid=1,keyid=0;
	int keytype2=0,hssid2=0;
	int keytype3=0,hssid3=0;
	__FUNC_IN__
	
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_vap0_if=[%s] wlan_vap1_if=[%s]~~~\n", wlan_va0_if, wlan_va1_if);
    SetWlan_idx(wlan_if);

	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff);
	cJSON_AddNumberToObject(root,"wifiOff",wifioff);

	apmib_get(MIB_WLAN_SSID, (void *)ssid);
	cJSON_AddStringToObject(root,"ssid1",ssid);
		
	//VAP0
	SetWlan_idx(wlan_va0_if);
	apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&hssid2);

	apmib_get(MIB_WLAN_ACCESS, (void *)&noforwarding);
	cJSON_AddNumberToObject(root, "noForwarding2", noforwarding);	
	
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff);
	cJSON_AddNumberToObject(root,"wifiOff2",wifioff);
	
	apmib_get(MIB_WLAN_SSID, (void *)ssid);
	cJSON_AddStringToObject(root,"ssid2",ssid);
	
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wpapsk);
	cJSON_AddStringToObject(root,"key2",wpapsk);

	//VAP1
	SetWlan_idx(wlan_va1_if);	
	apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&hssid3);
	
	apmib_get(MIB_WLAN_ACCESS, (void *)&noforwarding);
	cJSON_AddNumberToObject(root, "noForwarding3", noforwarding);
	
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff);
	cJSON_AddNumberToObject(root,"wifiOff3",wifioff);
	
	apmib_get(MIB_WLAN_SSID, (void *)ssid);
	cJSON_AddStringToObject(root,"ssid3",ssid);
	
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wpapsk);
	cJSON_AddStringToObject(root,"key3",wpapsk);

	//value format: x;x
	char hssid[4]={0},keytype[4]={0};
	char authmode[64]={0},authmode2[16]={0},authmode3[16]={0};
	char encryptype[32]={0},encryptype2[8]={0},encryptype3[8]={0};

	sprintf(hssid,"%d;%d",hssid2,hssid3);
	cJSON_AddStringToObject(root,"hssid",hssid);

	sprintf(authmode2,"%s",getAuthMode(wlan_va0_if));
	sprintf(authmode3,"%s",getAuthMode(wlan_va1_if));
	sprintf(authmode,"%s;%s",authmode2,authmode3);
	cJSON_AddStringToObject(root,"authMode",authmode);

	sprintf(encryptype2,"%s",getEncrypType(wlan_va0_if));
	sprintf(encryptype3,"%s",getEncrypType(wlan_va1_if));
	sprintf(encryptype,"%s;%s",encryptype2,encryptype3);
	cJSON_AddStringToObject(root,"encrypType",encryptype);

	sprintf(keytype,"%d;%d",keytype2,keytype3);
	cJSON_AddStringToObject(root,"keyFormat",keytype);

	SetWlan_idx(wlan_if);
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}
int delWiFiMultipleConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0}, wlan_va0_if[16]={0}, wlan_va1_if[16]={0};
    char hiddenssid[2]={0},authmode[16]={0},encryptype[8]={0},keyformat[2]={0};
    int tmpInt=0,hssid=0,keyfmt=0,wep=WEP_DISABLED,auth_wpa=WPA_AUTH_AUTO,encrypt=ENCRYPT_DISABLED;
	
	__FUNC_IN__
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	CSTE_DEBUG("~~~ wlan_vap0_if=[%s] wlan_vap1_if=[%s]~~~\n", wlan_va0_if, wlan_va1_if);

	//fetch from web input
	char_t *mssid2 = websGetVar(data, T("ssid2"), T(""));
	char_t *wepkey2 = websGetVar(data, T("wepkey2"), T(""));
	char_t *key2 = websGetVar(data, T("key2"), T(""));
	char_t *key3 = websGetVar(data, T("key3"), T(""));
	char_t *mssid3 = websGetVar(data, T("ssid3"), T(""));
	char_t *wepkey3 = websGetVar(data, T("wepkey3"), T(""));	

	char_t *hidden_ssid = websGetVar(data, T("hssid"), T(""));	
	char_t *auth_mode = websGetVar(data, T("authMode"), T(""));
	char_t *encryp_type = websGetVar(data, T("encrypType"), T(""));	
	char_t *key_format= websGetVar(data, T("keyFormat"), T(""));

	int doaction = atoi(websGetVar(data, T("doAction"), T("0")));
	int wifioff2 = atoi(websGetVar(data, T("wifiOff2"), T("0")));
	int wifioff3 = atoi(websGetVar(data, T("wifiOff3"), T("0")));
	int noforwanding2 = atoi(websGetVar(data, T("noForwarding2"), T("-1")));
	int noforwanding3 = atoi(websGetVar(data, T("noForwarding3"), T("-1")));

	if(doaction==2)
	{
		SetWlan_idx(wlan_va0_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&tmpInt);
		if(tmpInt==1)
		{
			doaction=3;
			wifioff3=tmpInt;		
		}
	}

	//action 1:all 2:vap0 3:vap1
	if(doaction==1||doaction==2){
		SetWlan_idx(wlan_va0_if);

		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff2);
		apmib_set(MIB_WLAN_SSID, (void *)mssid2);
		if(noforwanding2!=-1)
			apmib_set(MIB_WLAN_ACCESS, (void *)&noforwanding2);

	    checkVar(hidden_ssid,1,hiddenssid);
	    checkVar(auth_mode,1,authmode);
	    checkVar(encryp_type,1,encryptype);
	    checkVar(key_format,1,keyformat);	
		
		keyfmt=atoi(keyformat);
		hssid=atoi(hiddenssid);
	    apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);		

		ENCRYPT_T encrypt=ENCRYPT_DISABLED;
		int auth_wpa1=WPA_AUTH_PSK,enc1=ENCRYPT_WPA2_MIXED,keyFmt1=0,ciphersuite1=WPA_CIPHER_MIXED;
		if(strlen(key2)){
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&enc1);
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&keyFmt1);
	        apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	        apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key2);
			apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa1);
			}
		else{
			encrypt=ENCRYPT_DISABLED;
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_set(MIB_WLAN_WPA_PSK, "");			
		}
	}

	//action 1:all 2:vap0 3:vap1
	if(doaction==1||doaction==3){
		SetWlan_idx(wlan_va1_if);
		
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff3);
		apmib_set(MIB_WLAN_SSID, (void *)mssid3);
		if(noforwanding3!=-1)
			apmib_set(MIB_WLAN_ACCESS, (void *)&noforwanding3);

	    checkVar(hidden_ssid,2,hiddenssid);
	    checkVar(auth_mode,2,authmode);
	    checkVar(encryp_type,2,encryptype);
	    checkVar(key_format,2,keyformat);

		keyfmt=atoi(keyformat);
		hssid=atoi(hiddenssid);
	    apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);

		ENCRYPT_T encrypt=ENCRYPT_DISABLED;
		int auth_wpa1=WPA_AUTH_PSK,enc1=ENCRYPT_WPA2_MIXED,keyFmt1=0,ciphersuite1=WPA_CIPHER_MIXED;
		if(strlen(key3)){
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&enc1);
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&keyFmt1);
	        apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	        apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key3);
			apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa1);
			}
		else{
			encrypt=ENCRYPT_DISABLED;
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_set(MIB_WLAN_WPA_PSK, "");			
		}
	}
	//takeEffectWlan(wlan_if, 1);
	
	int pid=fork();
	if(0 == pid){
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		CsteSystem("sysconf init gw all", CSTE_PRINT_CMD);
		exit(1);
	}
	
	websSetCfgResponse(mosq, tp, "20", "reserv");
	__FUNC_OUT__
	return 0;
}

#endif

/**
* @note setWiFiAclAddConfig -Add Acl Config
*
* @param Setting Json Data
<pre>
{
	  "wifiIdx": 		"0",
	  "addEffect": 		"0",
	  "comment": 		"",
	  "authMode": 		"1",
	  "macAddress": 	"54:FF:25:22:00:28"
}
Setting parameter description:
addEffect 	- action
wifiIdx 		- wifi index 0 : 5G, 1 : 2.4G
authMode 	- acl authentication mode. 0:disable,1:allow,2: deny
macAddress 	- acl rule mac address
comment 	- description
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiAclAddConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int entryNum=0,i=0,wsc_disable=0,pid,va0_disabled=1,va1_disabled=1;
	int encrypt=0,cipher=0,hssid=0;
    char wlan_if[8]={0},wlan_va0_if[16]={0},wlan_va1_if[16]={0};
    MACFILTER_T macEntry;
	__FUNC_IN__

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);
	
    int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
    if(addEffect){
        int enabled = atoi(websGetVar(data, T("authMode"), T("0")));
        apmib_set(MIB_WLAN_MACAC_ENABLED, (void *)&enabled);

		if(enabled==1){
			wsc_disable=1;
		}else{
			apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
			apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&hssid);
			if(hssid==1){
				wsc_disable=1;
			}else{
				if(encrypt==ENCRYPT_WEP){
					wsc_disable=1;
				}else{
					if(cipher==WPA_CIPHER_TKIP){
						wsc_disable=1;
					}
				}
			}
		}
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_disable);
		SetWlan_idx(wlan_va0_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va0_disabled);
		apmib_set(MIB_WLAN_MACAC_ENABLED, (void *)&enabled);
		SetWlan_idx(wlan_va1_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va1_disabled);
		apmib_set(MIB_WLAN_MACAC_ENABLED, (void *)&enabled);
		SetWlan_idx(wlan_if);
    }else{
        char *delim=":", *p=NULL;
        char buffer[32]={0}, clo_mac[32]={0};
        char_t *mac = websGetVar(data, T("macAddress"), T(""));
        char_t *comment = websGetVar(data, T("comment"), T(""));
	    apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum);
        if((entryNum + 1) > MAX_WLAN_AC_NUM){
			return 0;
        }
        if(mac!=NULL){
            p = strtok(mac, delim);
            if(p==NULL) return 0;
            strcat(buffer, p);
            while((p=strtok(NULL, delim))) {
        		strcat(buffer, p);
        	}
        	string_to_hex(buffer, macEntry.macAddr, 12);            
        }

		if(strlen(comment)>0){
           if(strlen(comment)>=(COMMENT_LEN-1))
			comment[COMMENT_LEN-1]='\0';
            strcpy((char *)macEntry.comment, comment);
        }
        else
            macEntry.comment[0] = '\0';

        // set to MIB. try to delete it first to avoid duplicate case
        apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
        apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
		SetWlan_idx(wlan_va0_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va0_disabled);
		apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
        apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
		SetWlan_idx(wlan_va1_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va1_disabled);
		apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
        apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
		SetWlan_idx(wlan_if);
    }

    pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
#if defined(SUPPORT_MESH)
	CsteSystem("sysconf updateAllMeshInfo",CSTE_PRINT_CMD);
#endif

    pid=fork();
	if(0 == pid){
		if(va0_disabled==0)	takeEffectWlan(wlan_va0_if, 1);
		exit(1);
	}

	pid=fork();
	if(0 == pid){
		if(va1_disabled==0) takeEffectWlan(wlan_va1_if, 1);
		exit(1);
	}
	
	pid=fork();
	if(0 == pid){
		takeEffectWlan(wlan_if, 1);
		exit(1);
	}
	
	if(addEffect)
		websSetCfgResponse(mosq, tp, "10", "reserv");
	else
		websSetCfgResponse(mosq, tp, "5", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiAclAddConfig - Get WiFi acl config
*
* @param  wifiIdx - 0 : 5G, 1 : 2.4G
*
* @return  Return Json Data
<pre>
{
	"authMode": 	"2",
	"authList":	"F4:28:54:00:28:02;F4:28:54:00:28:00",
	"hardModel":	"04336"
}
Return parameter description:
authMode 	- authentication mode. 0:disable, 1 : allow, 2 : deny
authList 		- auth list
hardModel 	- hardware name.
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiAclAddConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
    char wlan_if[8]={0},tmpBuf[32]={0},buff[64]={0},macList[512]={0},comment[64]={0};
    int arraylen=0,entryNum=0,i=0,enabled=0;
    MACFILTER_T macEntry;
	__FUNC_IN__
        
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s]~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

    memset(macList, '\0', sizeof(macList));
	memset(comment, '\0', sizeof(comment));
    
    apmib_get(MIB_WLAN_MACAC_ENABLED, (void *)&enabled);
    apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum);
    apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
    for (i=1; i<=entryNum; i++){
        *((char *)&macEntry) = (char)i;
        apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
        snprintf(buff, 32, "%02X:%02X:%02X:%02X:%02X:%02X",
			macEntry.macAddr[0], macEntry.macAddr[1], macEntry.macAddr[2],
			macEntry.macAddr[3], macEntry.macAddr[4], macEntry.macAddr[5]);
		strcpy(comment, macEntry.comment);
		
		if(i==1){
			strcpy(macList, buff);
			sprintf(macList, "%s%s", buff, comment);
		}else{
	    	if(strstr(macList,buff)==NULL)
			sprintf(macList, "%s;%s%s", macList, buff, comment);
	    }
    }
    
    cJSON_AddNumberToObject(root,"authMode", enabled);
    cJSON_AddStringToObject(root,"authList", macList);

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note setWiFiAclDeleteConfig -Delete Acl Config
*
* @param Setting Json Data
<pre>
{
 	"wifiIdx" : "0"
	"DR0": 0,
	"DR1": 1
	...
}
Setting parameter description:
	wifiIdx - wifi index 0 : 5G, 1 : 2.4G.
	DR-     - deleted index number
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiAclDeleteConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char_t *ret;
    char wlan_if[8]={0},wlan_va0_if[16]={0},wlan_va1_if[16]={0},name_buf[16]={0};
    int entryNum=0,i=0,pid,va0_disabled=0,va1_disabled=0;
    MACFILTER_T macEntry;
	__FUNC_IN__

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

    apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum);
    for (i=entryNum; i>0; i--){
        memset(name_buf, '\0', sizeof(name_buf));
        snprintf(name_buf, 16, "DR%d", i-1);
		ret = websGetVar(data, T(name_buf), NULL);
        if(ret!=NULL){
            *((char *)&macEntry) = (char)i;
            apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
            apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
			SetWlan_idx(wlan_va0_if);
			apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va0_disabled);
			apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
            apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
			SetWlan_idx(wlan_va1_if);
			apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&va1_disabled);
			apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
            apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
			SetWlan_idx(wlan_if);
        }
    }
	
    pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
#if defined(SUPPORT_MESH)
	CsteSystem("sysconf updateAllMeshInfo",CSTE_PRINT_CMD);
#endif	

    pid=fork();
	if(0 == pid){
		if(va0_disabled==0) takeEffectWlan(wlan_va0_if, 1);
		exit(1);
	}

	pid=fork();
	if(0 == pid){
		if(va1_disabled==0)	takeEffectWlan(wlan_va1_if, 1);
		exit(1);
	}
	
    pid=fork();
	if(0 == pid){
		takeEffectWlan(wlan_if, 1);
		exit(1);
	}	
	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
	return 0;
}
char *findIPforMac(const char mac[])
{
	int i=0;
	char tmpCmd[64]={0},tmpMac[32]={0};
	static char cmdResult[32]={0};
	strcpy(tmpMac,mac);
	while(tmpMac[i])
	{
		if(tmpMac[i]>='A'&&tmpMac[i]<='Z')
		tmpMac[i]=tmpMac[i]+32;
		i++;
	}
	sprintf(tmpCmd,"cat /proc/net/arp | grep %s | awk '{print $1}'", tmpMac);
	getCmdStr(tmpCmd,cmdResult,sizeof(cmdResult));
	if(strlen(cmdResult)==0)
		strcpy(cmdResult,"0.0.0.0");
	return cmdResult;	
}
/**
* @note getWiFiIpMacTable Get wireless clients MAC/IP list. 
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
[{
    "mac":	"a0:86:c6:37:5c:f3",
    "ip":	"0.0.0.0"
}]
Return parameter description:
mac 	- wifi clients mac
ip 	- wifi clients ip, default is 0.0.0.0.
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiIpMacTable(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char *buff,*buff_va0,*buff_va1,*outip=NULL;
    char wlan_if[8]={0},wlan_va0_if[16]={0},wlan_va1_if[16]={0};
    char  outmac[18] = {0}, output[4096] ={0};
	char responseStr[CSTEMAXSIZE]={0};
	int len=0, i;	
    WLAN_STA_INFO_Tp pInfo,pInfo_va0,pInfo_va1;
	__FUNC_IN__
    int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_va0_if, "wlan%d-va0", WiFiIdx);
	sprintf(wlan_va1_if, "wlan%d-va1", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

    buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
    if (buff == 0) {
        return 0;
    }
    if (getWlStaInfo(wlan_if,  (WLAN_STA_INFO_Tp)buff ) < 0){
        return 0;
    }

	SetWlan_idx(wlan_va0_if);
	buff_va0 = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
	getWlStaInfo(wlan_va0_if,  (WLAN_STA_INFO_Tp)buff_va0 );

	SetWlan_idx(wlan_va1_if);
	buff_va1 = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
	getWlStaInfo(wlan_va1_if,  (WLAN_STA_INFO_Tp)buff_va1 );
	
	SetWlan_idx(wlan_if);

    memset(output,0,4096);
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),\ 
		"[\n");
	len = strlen(responseStr);

    for (i=1; i<=MAX_STA_NUM; i++) {
        pInfo = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
        if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)){
            //IP Address
            //MAC Address
            sprintf(outmac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5]);            
			outip=findIPforMac(outmac);
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
    			"{\"mac\":\"%s\",\"ip\":\"%s\"},\n",outmac,outip);
    		len = strlen(responseStr);
    		if(len>CSTEMAXSIZE)break;
        }

		pInfo_va0 = (WLAN_STA_INFO_Tp)&buff_va0[i*sizeof(WLAN_STA_INFO_T)];
        if (pInfo_va0->aid && (pInfo_va0->flag & STA_INFO_FLAG_ASOC)) {
            //IP Address
            //MAC Address
            sprintf(outmac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo_va0->addr[0],pInfo_va0->addr[1],pInfo_va0->addr[2],pInfo_va0->addr[3],pInfo_va0->addr[4],pInfo_va0->addr[5]);            
			outip=findIPforMac(outmac);
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
    			"{\"mac\":\"%s\",\"ip\":\"%s\"},\n",outmac,outip);
    		len = strlen(responseStr);
    		if(len>CSTEMAXSIZE)break;
        }
		
		pInfo_va1 = (WLAN_STA_INFO_Tp)&buff_va1[i*sizeof(WLAN_STA_INFO_T)];
        if (pInfo_va1->aid && (pInfo_va1->flag & STA_INFO_FLAG_ASOC)){
            //IP Address
            //MAC Address
            sprintf(outmac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo_va1->addr[0],pInfo_va1->addr[1],pInfo_va1->addr[2],pInfo_va1->addr[3],pInfo_va1->addr[4],pInfo_va1->addr[5]);            
			outip=findIPforMac(outmac);
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
    			"{\"mac\":\"%s\",\"ip\":\"%s\"},\n",outmac,outip);
    		len = strlen(responseStr);
    		if(len>CSTEMAXSIZE)break;
        }
		
    }

	if(len>2)
		responseStr[len-2]='\0';
	len = strlen(responseStr);
    snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
   
    websGetCfgResponse(mosq,tp,responseStr);
	free(buff_va0);
	free(buff_va1);
    free(buff);
	__FUNC_OUT__
    return 0;
}

/**
* @note getWiFiApcliScan - apcli scan results
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
[{
   149;m1t7k|TOTOLINK_A3100R_5G;m1t7k|f4:28:54:00:43:56;m1t7k|None;m1t7k|100;m1t7k|(A+N+AC);m1t7k|;m1t7k|5G\#m1t7k|
   149;m1t7k|welcome to carystudio;m1t7k|f4:28:54:00:34:90;m1t7k|WPA-PSK/WPA2-PSK;m1t7k|100;m1t7k|(A+N+AC);m1t7k|aes/tkip;m1t7k|5G\#m1t7k|
}]
format:channel;m1t7k|ssid;m1t7k|bssid;m1t7k|encryp;m1t7k|rssi;m1t7k|wirelessMode;m1t7k|wpa_tkip_aes;m1t7k|wirelessIdx\#m1t7k|
Return parameter description:
channel 	- ap channel
ssid 		- ap ssid
bssid 	- ap bssid(mac)
encrypt 	- ap encryption {NONE,WEP,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}
cipher	- ap encryption key type {TKIP,AES,TKIPAES}
signal 	- ap signal(rssi)
band 	- ap band(B, A, N, AC)
wifimode - ap mode 5g, 2g
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiApcliScan(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	char *root,*array;
	char result[1024*6]={0},result2[1024*6]={0};
	char cmd[128]={0};
	FILE *fd=NULL,*fp=NULL;
	array=cJSON_CreateArray();

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	if(WiFiIdx == 2){//5G and 2G
		memcpy(cmd,"sysconf scan wlan0",sizeof("sysconf scan wlan0"));
		system(cmd);
		if ((fd = fopen("/tmp/.scanResult", "r")) != NULL){
			while (fgets(result, sizeof(result), fd)){
				;
			}
			fclose(fd);
		}

		memset(cmd,0,sizeof(cmd));
		memcpy(cmd,"sysconf scan wlan1",sizeof("sysconf scan wlan1"));
		system(cmd);
			if ((fp = fopen("/tmp/.scanResult", "r")) != NULL){
			while (fgets(result2, sizeof(result2), fp)){
				;
			}
			strcat(result,result2);
			fclose(fp);
		}

		if(result==NULL){
			strcpy(result,"{}");
		}	
	}
	else{
		sprintf(cmd, "sysconf scan wlan%d", WiFiIdx);	
		system(cmd);
		if ((fd = fopen("/tmp/.scanResult", "r")) != NULL){
			while (fgets(result, sizeof(result), fd)){
				;
			}
			fclose(fd);
		}

		if(result==NULL){
			strcpy(result,"{}");
		}		
	}
	//printf("\n==[%s]==\n", result);	
	int i=0;
	char rec[256]={0};
	char channel[4]={0};
	char ssid[33]={0};
	char bssid[20]={0};
	char encrypt[16]={0};
	char cipher[8]={0};
	char band[16]={0};
	char signal[4]={0};
	char wifimode[4]={0};
	while(getNthValueSafe(i++, result, ';', rec, sizeof(rec)) != -1){
		if(getNthValueSafe(0, rec, ',', channel, sizeof(channel)) == -1)continue;
		if(getNthValueSafe(1, rec, ',', ssid, sizeof(ssid)) == -1)continue;
		if(getNthValueSafe(2, rec, ',', bssid, sizeof(bssid)) == -1)continue;
		if(getNthValueSafe(3, rec, ',', encrypt, sizeof(encrypt)) == -1)continue;
		if(getNthValueSafe(4, rec, ',', cipher, sizeof(cipher)) == -1)continue;
		if(getNthValueSafe(5, rec, ',', band, sizeof(band)) == -1)continue;
		if(getNthValueSafe(6, rec, ',', signal, sizeof(signal)) == -1)continue;
#if 0
		if(getNthValueSafe(7, rec, ',', wifimode, sizeof(wifimode)) == -1)continue;
#endif
		root=cJSON_CreateObject();
		cJSON_AddItemToArray(array,root);
		cJSON_AddStringToObject(root,"ssid",ssid);
		cJSON_AddStringToObject(root,"bssid",bssid);
		cJSON_AddNumberToObject(root,"channel",atoi(channel));
		cJSON_AddStringToObject(root,"encrypt",encrypt);
		if(strlen(cipher)>0){
			cJSON_AddStringToObject(root,"cipher",cipher);
		}
		else{
			cJSON_AddStringToObject(root,"cipher","");
		}
		cJSON_AddStringToObject(root,"band",band);
		cJSON_AddNumberToObject(root,"signal",atoi(signal));
#if 0
		cJSON_AddStringToObject(root,"wifimode",wifimode);
#endif
	}
    output=cJSON_Print(array);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(array);
	__FUNC_OUT__
    return 0;
}

/**
* @note getWiFiWdsAddConfig - Get WiFi Wds Config
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
{
	"wifiOff":		0,
	"wdsEnable":	0,
	"wdsList":	""
}
Return parameter description:
wifiOff 		- wifi on/off 1 : off, 0 : on
wdsEnable 	- wifi wds switch 1 : enabled , 0: disable
wdsList 		- wifi wds list
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiWdsAddConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	int i=0,enabled=0,entryNum=0;
	char wlan_if[8]={0}, tmpBuf[32]={0}, wdslist[256]={0};
	WDS_T entry;
	
	__FUNC_IN__
    int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);	
	
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&enabled);
	cJSON_AddNumberToObject(root,"wifiOff", enabled);
	
	apmib_get(MIB_WLAN_WDS_ENABLED, (void *)&enabled);
	cJSON_AddNumberToObject(root,"wdsEnable", enabled);

	apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum);
	memset(wdslist, '\0', sizeof(wdslist));
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		apmib_get(MIB_WLAN_WDS, (void *)&entry);
		memset(tmpBuf, '\0', sizeof(tmpBuf));
		snprintf(tmpBuf, sizeof(tmpBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
		if(i==1){
			strcpy(wdslist, tmpBuf);
		}else{
			sprintf(wdslist, "%s;%s", wdslist, tmpBuf);
		}
	}
	if(strlen(wdslist)==0){
		strcpy(wdslist,"");
	}
	cJSON_AddStringToObject(root,"wdsList",wdslist);
	
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note setWiFiWdsConfig -Add Wds Config
*
* @param Setting Json Data
<pre>
{
	"addEffect":	"0",
	"wifiIdx":		"1",	
	"wdsEnable": 	"",
	"wdsList":	"22:33:66:55:44:77"
}
Setting parameter description:
addEffect		- action
wifiIdx 		- wifi index 0 : 5G, 1 : 2.4G
wdsEnable 	- wifi wds switch 1 : enabled , 0: disable
wdsList 		- wifi wds list
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiWdsAddConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int pid,entryNum;
	char wlan_if[8]={0},wds_list_tmp[32]={0};
	WDS_T macEntry;
	
	__FUNC_IN__
    int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	if (addEffect) {
		int enabled = atoi(websGetVar(data, T("wdsEnable"), T("0")));
        apmib_set(MIB_WLAN_WDS_ENABLED, (char *)&enabled);
    }
    else {
		char *delim=":", *p=NULL;
        char buffer[32]={0};
		char_t *wds_list = websGetVar(data, T("wdsList"), T(""));
		char_t *comment = websGetVar(data, T("comment"), T(""));
		
		apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum);
        if((entryNum + 1) > MAX_WDS_NUM){
			return 0;
        }
        if(wds_list!=NULL){
			checkVar(wds_list,entryNum+1,wds_list_tmp);
            p = strtok(wds_list_tmp, delim);
            if(p==NULL) return 0;
            strcat(buffer, p);
            while((p=strtok(NULL, delim))) {
        		strcat(buffer, p);
        	}
			if(strlen(buffer)!=12||!string_to_hex(buffer, macEntry.macAddr, 12)){
				return 0;
			}
        }

		if(strlen(comment)>0){
           if(strlen(comment)>=(COMMENT_LEN-1))
			comment[COMMENT_LEN-1]='\0';
            strcpy((char *)macEntry.comment, comment);
        }
        else
            macEntry.comment[0] = '\0';

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
		apmib_set(MIB_WLAN_WDS_ADD, (void *)&macEntry);			
    }

	pid=fork();
	if(0 == pid){
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		run_init_script("all");
		exit(1);
	} 
	
	websSetCfgResponse(mosq, tp, "20", "reserv");

	__FUNC_OUT__
	return 0;
}

/**
* @note setWiFiWdsDeleteConfig -Delete WDS Config
*
* @param Setting Json Data
<pre>
{
 	"wifiIdx" : 	"0",
	"DR0": 		"0",
	"DR1": 		"1"
	...
}
Setting parameter description:
	wifiIdx - wifi index 0 : 5G, 1 : 2.4G
	DR-     - deleted index number
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiWdsDeleteConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	char_t *ret;
    char wlan_if[8]={0}, name_buf[16]={0};
    int entryNum=0, i=0, pid;
    WDS_T macEntry;
	
	__FUNC_IN__
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

    apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum);
    for (i=entryNum; i>0; i--){
        memset(name_buf, '\0', sizeof(name_buf));
        snprintf(name_buf, 16, "DR%d", i-1);
		ret = websGetVar(data, T(name_buf), NULL);
        if(ret!=NULL){
            *((char *)&macEntry) = (char)i;
            apmib_get(MIB_WLAN_WDS, (void *)&macEntry);
            apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
        }
    }
	
    pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		takeEffectWlan(wlan_if, 1);
		exit(1);
	}
	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note getWiFiRepeaterConfig - Get WiFi Repeater Config
*
* @param   wifiIdx - 0 : 5G, 1 : 2.4G
* @return  Return Json Data
<pre>
{
	"apcliEnable":		1,
	"apcliChannel":	11,
	"apcliSsid":		"welcome to carystudio",
	"apcliBssid":		"F4:28:54:00:34:94",
	"apcliAuthMode":	"WPA2PSK",
	"apcliEncrypType":	"AES",
	"apcliKey":		"12345678",
	"apcliStatus":		"fail"
}
Return parameter description:
apcliEnable		- apcli switch 1: on, 0: off
apcliChannel 		- apcli channel
apcliSsid 			- apcli ssid
apcliBssid 		- apcli bssid(mac)
apcliAuthMode 	- apcli encryption. - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK}
apcliEncrypType 	- apcli encryption key type {NONE,WEP,AES,TKIP}
apcliKey 			- apcli key 
apcliStatus 		- apcli connection state. success, fail
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiRepeaterConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0},wlanvxd_if[16]={0};
	char tmpBuff[128]={0};
	unsigned char buff_key[32]={0};
	int intVal,keyid,wep,keytype,defkeyid,encrypt,pskformat;
	__FUNC_IN__
		
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

	apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
	cJSON_AddNumberToObject(root,"apcliChannel",intVal);

	CSTE_DEBUG("~~~ wlanvxd_if=[%s]~~~\n", wlanvxd_if);
    SetWlan_idx(wlanvxd_if);
	
	apmib_get(MIB_ROOTAP_MAC, (void *)tmpBuff);
	cJSON_AddStringToObject(root,"apcliBssid",tmpBuff);
	
	if(WiFiIdx==0){
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);
		apmib_get(MIB_REPEATER_SSID1, (void *)tmpBuff);
	}else{
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);
		apmib_get(MIB_REPEATER_SSID2, (void *)tmpBuff);
	}
	cJSON_AddNumberToObject(root,"apcliEnable",intVal);	
	cJSON_AddStringToObject(root,"apcliSsid",tmpBuff);	
	cJSON_AddStringToObject(root,"apcliAuthMode",getRptAuthMode(wlanvxd_if));
	cJSON_AddStringToObject(root,"apcliEncrypType",getRptEncrypType(wlanvxd_if));

	apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	if (encrypt>1){
		apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpBuff);
		cJSON_AddStringToObject(root,"apcliKey",tmpBuff);
	}else if (encrypt==1){
		apmib_get(MIB_WLAN_WEP, (void *)&wep);
	    apmib_get(MIB_WLAN_WEP_KEY_TYPE, (void *)&keytype);    
	    apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&defkeyid);
	    apmib_get(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);		
		if(wep == WEP64){
	        if(defkeyid==0)
	            keyid = MIB_WLAN_WEP64_KEY1;
	        else if(defkeyid==1)
	            keyid = MIB_WLAN_WEP64_KEY2;
	        else if(defkeyid==2)
	            keyid = MIB_WLAN_WEP64_KEY3;
	        else if(defkeyid==3)
	            keyid = MIB_WLAN_WEP64_KEY4;
	        apmib_get(keyid, (void *)buff_key);

			if(keytype==1){//Hex
	            convert_bin_to_str(buff_key, 5, tmpBuff);
	        }else{
	            snprintf(tmpBuff, 6, "%s", buff_key);
	        }
	    }else if(wep == WEP128){
	        if(defkeyid==0)
	            keyid = MIB_WLAN_WEP128_KEY1;
	        else if(defkeyid==1)
	            keyid = MIB_WLAN_WEP128_KEY2;
	        else if(defkeyid==2)
	            keyid = MIB_WLAN_WEP128_KEY3;
	        else if(defkeyid==3)
	            keyid = MIB_WLAN_WEP128_KEY4;
	        apmib_get(keyid, (void *)buff_key);

			if(keytype==1){//Hex
	            convert_bin_to_str(buff_key, 13, tmpBuff);
	        }else{
	            snprintf(tmpBuff, 14, "%s", buff_key);
	        }
	    }
		cJSON_AddStringToObject(root,"apcliKey",tmpBuff);
	}else{
		cJSON_AddStringToObject(root,"apcliKey","");
	}	

	if(1==getRepeaterStatus(wlanvxd_if)){
		cJSON_AddStringToObject(root,"apcliStatus","success");
	}else{
		cJSON_AddStringToObject(root,"apcliStatus","fail");
	}
	
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

#ifdef SUPPORT_REPEATER
int getWiFiExtenderConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	bss_info bss;
	cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0},tmpBuf[33]={0};
	int arraylen=0;
	__FUNC_IN__

	int WiFiIdx = 1;
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	SetWlan_idx(wlan_if);

	//str type mib
	char *StrGetName[]={"ssid","wpakey"}; 
	int StrGetId[]={MIB_WLAN_SSID,MIB_WLAN_WPA_PSK};
	arraylen=sizeof(StrGetName)/sizeof(char *);
	getCfgArrayStr(root, arraylen, StrGetName, StrGetId);
	
	getWlBssInfo(wlan_if, &bss);			
	memcpy(tmpBuf, bss.ssid, 32+1); 		
	if(strlen(tmpBuf)==0){				
		SetWlan_idx(wlan_if);
		apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
		cJSON_AddStringToObject(root,"ssid",tmpBuf);
	}

	SetWlan_idx(wlan_if);	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	__FUNC_OUT__
	return 0;
}


int setRpeaterFail(int val1, int val2)
{
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&val1);
	if(val1==0){
		system("ifconfig wlan0-vxd down");
	}

	apmib_set(MIB_REPEATER_ENABLED2, (void *)&val2);
	if(val2==0){
		system("ifconfig wlan1-vxd down");
	}
	return 0;
}

int setWiFiExtenderConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0},wlan_iftmp[8]={0};
	char wlanvxd_if[16]={0},wlanvxd_iftmp[16]={0};
	char new_root_ssid[33]={0};
	char new_rpt_ssid[33]={0};
	int intVal=0, tmpRptEnable1=0,tmpRptEnable2=0;	

	int actionFlag = atoi(websGetVar(data, T("actionFlag"), T("0")));
	char_t *ssid  = websGetVar(data, T("apcliSsid"), T(""));
	char_t *bssid = websGetVar(data, T("apcliBssid"), T(""));	 
	char_t *auth_mode = websGetVar(data, T("apcliAuthMode"), T(""));
	char_t *encryp_type = websGetVar(data, T("apcliEncrypType"), T(""));	
	char_t *key = websGetVar(data, T("apcliKey"), T("")); 
	int channel = atoi(websGetVar(data, T("apcliChannel"), T("0")));
	int key_format = atoi(websGetVar(data, T("apcliKeyFormat"), T("0")));
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	int rebootFlag = atoi(websGetVar(data, T("rebootFlag"), T("0")));

	int rootFlag = atoi(websGetVar(data, T("rootFlag"), T("0")));
	char_t *rootSsid  = websGetVar(data, T("rootSsid"), T(""));
	char_t *rootKey = websGetVar(data, T("rootKey"), T("")); 

	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlan_iftmp, "wlan%d", 1-WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	sprintf(wlanvxd_iftmp, "wlan%d-vxd", (1-WiFiIdx));

//	printf("\nssid=[%s]\nbssid=[%s]\nchannel=[%d]\nauthMode=[%s]\nencrypType=[%s]\nkey=[%s]\nkeyFormat=[%d]\n",ssid,bssid,channel,auth_mode,encryp_type,key,key_format);
//	printf("\nrootFlag=[%d]\nrootSsid=[%s]\nrootKey=[%s]\n",rootFlag,rootSsid,rootKey);

	SetWlan_idx(wlan_if);//wlan

	//get last repeater info
	char old_rpt_ssid[33]={0};
	char old_rpt_pass[65]={0};
	apmib_get(MIB_WLAN_SSID, (void *)old_rpt_ssid); 
	apmib_get(MIB_WLAN_WPA_PSK, (void *)old_rpt_pass); 

	//repeater
	apmib_set(MIB_ROOTAP_MAC, (void *)bssid);
	apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);
	if (WiFiIdx == 0 && channel == 165) {
		int bw = 0;
		apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&bw);
	}

	apmib_get(MIB_REPEATER_ENABLED1, (void *)&tmpRptEnable1);
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&tmpRptEnable2);
	
	if(WiFiIdx==0){
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);//5g
		apmib_set(MIB_REPEATER_SSID1, (void *)ssid);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);
	}else{
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);//2.4g
		apmib_set(MIB_REPEATER_SSID2, (void *)ssid);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
	}
	apmib_set(MIB_WISP_WAN_ID, (void *)&WiFiIdx);

	SetWlan_idx(wlanvxd_if);//wlan vxd
	intVal=0;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	apmib_set(MIB_WLAN_SSID, (void *)ssid); 
	
	int encrypt=ENCRYPT_DISABLED;
	int auth_wpa=WPA_AUTH_PSK;
	int cipher=WPA_CIPHER_AES;
	int pskformat=KEY_ASCII;
	if(!strncmp(auth_mode,"NONE",5)){
		encrypt=ENCRYPT_DISABLED;
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);				
	}
	else{
		if(!strncmp(auth_mode,"WPAPSK",7)){
			encrypt=ENCRYPT_WPA;
		}else{
			encrypt=ENCRYPT_WPA2;
		}
		if(!strncmp(encryp_type,"TKIP",5)){
			cipher=WPA_CIPHER_TKIP;
		}else{
			cipher=WPA_CIPHER_AES;
		}
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&key_format);
		apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
		apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
		apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
		apmib_set(MIB_WLAN_WPA_PSK, (void *)key);		
	}

	if (actionFlag==1){//save & reboot	
rebootAction:	
		SetWlan_idx(wlan_if);
		if(rootFlag==1){//change
			apmib_set(MIB_WLAN_SSID,(void *)rootSsid);
			if(strlen(rootKey)>0){
				encrypt=ENCRYPT_WPA2_MIXED;					
				apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
				apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
				apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
				cipher=WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
				apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
				apmib_set(MIB_WLAN_WPA_PSK, (void *)rootKey); 	
			}else{
				encrypt=ENCRYPT_DISABLED;					
				apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			}
		}else{//keep
			apmib_set(MIB_WLAN_SSID, (void *)ssid);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key);
			if(!strcmp(auth_mode,"NONE")){
				encrypt=ENCRYPT_DISABLED;
			}else{
				encrypt=ENCRYPT_WPA2_MIXED;
			}			
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			cipher=WPA_CIPHER_AES;
			apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
			apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);		
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);	
		}

		if (WiFiIdx==0){
			if(strlen(rootSsid)<27){
				sprintf(new_root_ssid,"%s_2.4G",rootSsid);	
			}
			if(strlen(ssid)<27){
				sprintf(new_rpt_ssid,"%s_2.4G",ssid);
			}
		}
		else{
			if(strlen(rootSsid)<29){
				sprintf(new_root_ssid,"%s_5G",rootSsid);	
			}
			if(strlen(ssid)<29){
				sprintf(new_rpt_ssid,"%s_5G",ssid);
			}
		}

		SetWlan_idx(wlan_iftmp);
		if(rootFlag==1){//change
			apmib_set(MIB_WLAN_SSID,(void *)new_root_ssid);
			if(strlen(rootKey)>0){
				encrypt=ENCRYPT_WPA2_MIXED;					
				apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
				apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
				apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
				cipher=WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
				apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
				apmib_set(MIB_WLAN_WPA_PSK, (void *)rootKey); 	
			}else{
				encrypt=ENCRYPT_DISABLED;					
				apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			}
		}else{//keep
			apmib_set(MIB_WLAN_SSID, (void *)new_rpt_ssid);
			apmib_set(MIB_WLAN_WPA_PSK, (void *)key);
			if(!strcmp(auth_mode,"NONE")){
				encrypt=ENCRYPT_DISABLED;
			}else{
				encrypt=ENCRYPT_WPA2_MIXED;
			}			
			apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
			cipher=WPA_CIPHER_AES;
			apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
			apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);		
			apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);	
		}

		//wlan vxd反接口清空数据
		int tmpIntVal=0;
		char tmpStrVal[65]={0};
		SetWlan_idx(wlanvxd_iftmp);
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&tmpIntVal);
		apmib_set(MIB_WLAN_WPA_AUTH, (void *)&tmpIntVal);
		apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&tmpIntVal);
		apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&tmpIntVal);
		apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&tmpIntVal);
		strcpy(tmpStrVal,"");
		apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpStrVal); 	

		strcpy(tmpStrVal,"Extender");
		apmib_set(MIB_WLAN_SSID, (void *)tmpStrVal);	
		if(WiFiIdx==0){
			apmib_set(MIB_REPEATER_SSID2, (void *)tmpStrVal);
			CsteSystem("ifconfig wlan1-vxd down",CSTE_PRINT_CMD);
		}else{
			apmib_set(MIB_REPEATER_SSID1, (void *)tmpStrVal);
			CsteSystem("ifconfig wlan0-vxd down",CSTE_PRINT_CMD);
		}		
		
		apmib_update_web(CURRENT_SETTING);
		websSetCfgResponse(mosq, tp, "60", "reserv");
		int pid=fork();
		if(0 == pid){
			sleep(1);
			CsteSystem("reboot",CSTE_PRINT_CMD);
			exit(1);
		}
		return 0;
	}
	else{//repeater	
		takeEffectWlan(wlanvxd_if, 1);
		CsteSystem("echo 1  > /tmp/setWifiExtend",0);
		int i=0;
		while(1){
			int ret=getRepeaterStatus(wlanvxd_if);
			//printf("ret==[%d]==[i]==%d\n",ret,i);
			if(ret==1){//success
				websSetCfgResponse(mosq, tp, "15", "1");	
				sleep(1);
				if(rebootFlag==1)
					goto rebootAction;
				break;
			}else if(ret==0){
				setRpeaterFail(tmpRptEnable1,tmpRptEnable2);
				websSetCfgResponse(mosq, tp, "3", "0");
				break;
			}else if((ret==-1) && (i<=25)){//connecting
				i++;
				sleep(1);
			}else if((ret==-1) && (i>25)){
				setRpeaterFail(tmpRptEnable1,tmpRptEnable2);
				CsteSystem("rm -rf /tmp/setWifiExtend",0);
				websSetCfgResponse(mosq, tp, "3", "-1");
				break;
			}
		}
	}
	return 0;
}
#endif

/**
* @note setWiFiRepeaterConfig Set WiFi Repeater Config
*
* @param data
<pre>
{
	"wifiIdx":			"1",
	"apcliSsid":		"welcome to carystudio",
	"apcliBssid":		"F4:28:54:00:34:94",
	"apcliChannel":	"11",
	"apcliAuthMode":	"WPA2PSK",
	"apcliEncrypType":	"AES",
	"apcliKeyFormat":	"0",
	"apcliKey":		"333333333",
	"operationMode":	"2"
}
Setting parameter description:
wifiIdx 			- wifi index  0 : 5G, 1 : 2.4G
apcliSsid 			- apcli ssid
apcliBssid 		- apcli bssid(mac)
apcliChannel 		- apcli channel
apcliAuthMode 	- apcli encryption - {NONE,OPEN,SHARED,WPAPSK,WPA2PSK,WPAPSKWPA2PSK}
apcliEncrypType 	- apcli encryptype key type{NONE,WEP,AES,TKIP,TKIPAES}
apcliKeyFormat	- apcli key type 0 : ASCII, 1 : Hex
apcliKey			- apcli password
operationMode 	- operation mode 2: Repeater, 3: WISP
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiRepeaterConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0},wlanvxd_if[16]={0},wlanvxd_iftmp[16]={0};
	int pid,intVal, opmodeTmp;	
	__FUNC_IN__
		
    char_t *ssid  = websGetVar(data, T("apcliSsid"), T(""));
    char_t *bssid = websGetVar(data, T("apcliBssid"), T(""));    
    char_t *auth_mode = websGetVar(data, T("apcliAuthMode"), T(""));
    char_t *encryp_type = websGetVar(data, T("apcliEncrypType"), T(""));	
    char_t *key = websGetVar(data, T("apcliKey"), T("")); 
	int channel = atoi(websGetVar(data, T("apcliChannel"), T("0")));
	int key_format = atoi(websGetVar(data, T("apcliKeyFormat"), T("0")));
	int opmode = atoi(websGetVar(data, T("operationMode"), T("2")));
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	int lan_mode = 0;

	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	sprintf(wlanvxd_iftmp, "wlan%d-vxd", (1-WiFiIdx));
	CSTE_DEBUG("\nssid=[%s]\nbssid=[%s]\nchannel=[%d]\nauthMode=[%s]\nencrypType=[%s]\nkey=[%s]\nkeyFormat=[%d]\n",ssid,bssid,channel,auth_mode,encryp_type,key,key_format);
    SetWlan_idx(wlan_if);//wlan

	apmib_get(MIB_OP_MODE,(void *)&opmodeTmp);
	if(opmodeTmp == 0 && opmode == 3){  //网关模式切到wisp
		intVal=0;
		apmib_set(MIB_DNS_MODE, (void *)&intVal);
	}

	apmib_set(MIB_ROOTAP_MAC, (void *)bssid);
	apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);
	if (WiFiIdx == 0 && channel == 165) {
		int bw = 0;
		apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&bw);
	}
	opmode=opmode-1;
	apmib_set(MIB_OP_MODE, (void *)&opmode);

	intVal=0;
	SetWlan_idx("wlan0");
	apmib_set(MIB_WLAN_SCHEDULE_ENABLED, (void *)&intVal); 

	SetWlan_idx("wlan1");
	apmib_set(MIB_WLAN_SCHEDULE_ENABLED, (void *)&intVal); 

#if defined(FOR_DUAL_BAND)
	if(WiFiIdx==0){
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);//5g
		apmib_set(MIB_REPEATER_SSID1, (void *)ssid);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);
	}else{
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);//2.4g
		apmib_set(MIB_REPEATER_SSID2, (void *)ssid);
		intVal=0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
	}
	apmib_set(MIB_WISP_WAN_ID, (void *)&WiFiIdx);
#else
	intVal=1;
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);//2.4g
	apmib_set(MIB_REPEATER_SSID1, (void *)ssid);
	apmib_set(MIB_WISP_WAN_ID, (void *)&WiFiIdx);
#endif

	char buffer[32]={0},mac[32]={0};
	char cmdBuf[128]={0},orig_ip[32]={0},orig_mask[32]={0};

	SetWlan_idx(wlanvxd_if);//wlan vxd
#if !defined(SUPPORT_APAC)		
	if(opmode==2){
		intVal=CLIENT_MODE;
		apmib_set(MIB_WLAN_MODE, (void *)&intVal);		
		
		intVal=DHCP_SERVER;
		apmib_set(MIB_DHCP, (void *)&intVal);

		intVal=DHCP_CLIENT;
		apmib_set(MIB_WAN_DHCP, (void *)&intVal);

		//切换到wisp模式，原来克隆的wanmac恢复到设备本身的mac
		apmib_get(MIB_HW_NIC1_ADDR, (void *)buffer);
		sprintf(mac, "%02X%02X%02X%02X%02X%02X", 
			(unsigned char)buffer[0], (unsigned char)buffer[1], (unsigned char)buffer[2], 
			(unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);
		string_to_hex(mac, buffer, 12);
		apmib_set(MIB_WAN_MAC_ADDR, (void *)buffer);
	}else{		
		intVal=DHCP_DISABLED;
		apmib_set(MIB_DHCP, (void *)&intVal);
		
		CsteSystem("killall -9 udhcpd 2> /dev/null", CSTE_PRINT_CMD);
		
		apmib_get(MIB_IP_ADDR, (void *)buffer); //get orig lan ip
		sprintf(orig_ip,"%s",inet_ntoa(*((struct in_addr *)buffer)));
		apmib_get(MIB_SUBNET_MASK, (void *)buffer); //get orig lan subnet
		sprintf(orig_mask,"%s",inet_ntoa(*((struct in_addr *)buffer)));
		sprintf(cmdBuf, "ifconfig br0 down;ifconfig br0 %s netmask %s up",orig_ip,orig_mask);
		CsteSystem(cmdBuf, CSTE_PRINT_CMD);
		lan_mode = 1;
	}
	apmib_set(MIB_LAN_MODE, (void *)&lan_mode);
#endif

	intVal=0;
#if defined(CONFIG_SUPPORT_NOTICE)
	apmib_set(MIB_NOTICE_ENABLED, (void *)&intVal);
	system("killall  notice");
	sleep(2);
	system("killall -9 stunnel");
#endif
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);	
	
#if 0//defined(RTL_MULTI_CLONE_SUPPORT)
	intVal=1;
	apmib_set(MIB_WLAN_MACCLONE_ENABLED, (void *)&intVal);
#endif

	int encrypt=ENCRYPT_WEP;
	if(!strncmp(auth_mode,"NONE",5)){
		encrypt=ENCRYPT_DISABLED;
        apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);				
	}else if(!strncmp(auth_mode,"WEP",4)){
		int wep=WEP_DISABLED;
		int authtype=AUTH_BOTH;
		int key_id=0;
		int wepkey_len=strlen(key);
		char key_hex[32]={0};
		encrypt=ENCRYPT_WEP;
        if(!strncmp(encryp_type,"OPEN",5)){
			authtype=AUTH_OPEN;
		}else{ 
            authtype=AUTH_SHARED;            
		}
		if(key_format==1){//Hex
            if(wepkey_len==10){
                wep=WEP64;
                wepkey_len=WEP64_KEY_LEN*2;
            }else if(wepkey_len==26){
                wep=WEP128;
		        wepkey_len=WEP128_KEY_LEN*2;
            }
		    string_to_hex(key,key_hex,wepkey_len);
        }else{//ASCII
            if(wepkey_len==5){
                wep=WEP64;
            }else if(wepkey_len==13){
                wep=WEP128;
            }
		    strcpy(key_hex,key);
        }
        apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);		
        apmib_set(MIB_WLAN_AUTH_TYPE, (void *)&authtype);
	    apmib_set(MIB_WLAN_WEP, (void *)&wep);
        apmib_set(MIB_WLAN_WEP_KEY_TYPE, (void *)&key_format);
        apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&key_id);		
	   	if(wep==WEP64){
            apmib_set(MIB_WLAN_WEP64_KEY1, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP64_KEY2, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP64_KEY3, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP64_KEY4, (void *)key_hex);
        }else if(wep==WEP128){
            apmib_set(MIB_WLAN_WEP128_KEY1, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP128_KEY2, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP128_KEY3, (void *)key_hex);
            apmib_set(MIB_WLAN_WEP128_KEY4, (void *)key_hex);
        }
	}
	else{
		int auth_wpa=WPA_AUTH_PSK;
		int cipher=WPA_CIPHER_AES;
	    int wpakey_len=strlen(key);
        char key_hex[65]={0};
		if(!strncmp(auth_mode,"WPAPSK",7)){
			encrypt=ENCRYPT_WPA;
		}else{
            encrypt=ENCRYPT_WPA2;
        }
		if(!strncmp(encryp_type,"TKIP",5)){
			cipher=WPA_CIPHER_TKIP;
        }else{
			cipher=WPA_CIPHER_AES;
        }
		if(key_format==1){//Hex
            if(wpakey_len!=MAX_PSK_LEN && !string_to_hex(key, key_hex, MAX_PSK_LEN)){
		        return 0;
            }
        }
        apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
        apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&key_format);
        apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
        apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
        apmib_set(MIB_WLAN_WPA_PSK, (void *)key);		
		apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	}
	
#if defined(FOR_DUAL_BAND)
	//中继/WISP模式时
	int tmpIntVal=0;
	char tmpStrVal[65]={0},def_key64[30]={0},def_key128[30]={0};
	SetWlan_idx(wlanvxd_iftmp);
	//wlan vxd反接口清空数据
	apmib_set(MIB_WLAN_ENCRYPT, (void *)&tmpIntVal);
	apmib_set(MIB_WLAN_AUTH_TYPE, (void *)&tmpIntVal);
    apmib_set(MIB_WLAN_WEP, (void *)&tmpIntVal);
    apmib_set(MIB_WLAN_WEP_KEY_TYPE, (void *)&tmpIntVal);
	apmib_set(MIB_WLAN_WPA_AUTH, (void *)&tmpIntVal);
    apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&tmpIntVal);
    apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&tmpIntVal);
    apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&tmpIntVal);
	
	int idx=0,i=0,j=0;				
	for (idx=0; idx<5; idx++) {
		def_key64[i++] = (unsigned char) strtol("00", (char**)NULL, 16);
	}
	for (idx=0; idx<13; idx++) {
		def_key128[j++] = (unsigned char) strtol("00", (char**)NULL, 16);
	}
    apmib_set(MIB_WLAN_WEP64_KEY1, (void *)def_key64);
    apmib_set(MIB_WLAN_WEP64_KEY2, (void *)def_key64);
    apmib_set(MIB_WLAN_WEP64_KEY3, (void *)def_key64);
    apmib_set(MIB_WLAN_WEP64_KEY4, (void *)def_key64);
    apmib_set(MIB_WLAN_WEP128_KEY1, (void *)def_key128);
    apmib_set(MIB_WLAN_WEP128_KEY2, (void *)def_key128);
    apmib_set(MIB_WLAN_WEP128_KEY3, (void *)def_key128);
    apmib_set(MIB_WLAN_WEP128_KEY4, (void *)def_key128);

	strcpy(tmpStrVal,"");
	apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpStrVal);		

	strcpy(tmpStrVal,"Extender");
	apmib_set(MIB_WLAN_SSID, (void *)tmpStrVal);	
	if(WiFiIdx==0){
		apmib_set(MIB_REPEATER_SSID2, (void *)tmpStrVal);
		CsteSystem("ifconfig wlan1-vxd down",CSTE_PRINT_CMD);
	}else{
		apmib_set(MIB_REPEATER_SSID1, (void *)tmpStrVal);
		CsteSystem("ifconfig wlan0-vxd down",CSTE_PRINT_CMD);
	}		
#endif
#if defined(SUPPORT_MESH)
	intVal=0;
	SetWlan_idx("wlan0");
	apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&intVal);
	SetWlan_idx("wlan1");
	apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&intVal);
	intVal=1;
	apmib_set(MIB_MESH_SYNC_FLAG,(void *)&intVal);
	
	CsteSystem("csteSys csnl 2 -1",CSTE_PRINT_CMD);
	CsteSystem("csteSys csnl 1 1",CSTE_PRINT_CMD);
	sleep(1);
	CsteSystem("csteSys csnl 2 2",CSTE_PRINT_CMD);
	CsteSystem("rm /tmp/meshSlave -f",CSTE_PRINT_CMD);
#else
	CsteSystem("csteSys csnl 2 -1",CSTE_PRINT_CMD);
	if(opmode==2){
		CsteSystem("csteSys csnl 1 2",CSTE_PRINT_CMD);
		sleep(1);
		CsteSystem("csteSys csnl 2 2",CSTE_PRINT_CMD);
	}else{
		CsteSystem("csteSys csnl 1 1",CSTE_PRINT_CMD);
		sleep(1);
		CsteSystem("csteSys csnl 2 1",CSTE_PRINT_CMD);
	}
#endif

#if defined(CONFIG_SUPPORT_CS_IPTV)
		apmib_get(MIB_IPTV_ENABLED,(void *)&intVal);
		if(intVal==1){
			intVal=0;
			apmib_set(MIB_IPTV_ENABLED,(void *)&intVal);
	
			apmib_update_web(CURRENT_SETTING);
			websSetCfgResponse(mosq, tp, "70", "reserv");	
			pid=fork();
			if(0 == pid)
			{
				sleep(1);
				CsteSystem("reboot",CSTE_PRINT_CMD);
				exit(1);
			}
			return 0;
		}
#endif

	apmib_update_web(CURRENT_SETTING);
	run_init_script("all");
	websSetCfgResponse(mosq, tp, "30", "reserv");
	__FUNC_OUT__
	return 0;
}

/**
* @note setWiFiScheduleConfig -Set WiFi Schedule Config
*
* @param Setting Json Data
<pre>
{
	"addEffect" : 		"",
	"wifiScheduleEn":	"",
	"enableX":		"1",
	"weekX":			"6",
	"startHourX":		"4",
	"startMinuteX":	"0",
	"endHourX":		"17",
	"endMinuteX":		"0"
}
Setting parameter description:
addEffect 	 - action
wifiScheduleEn - wifi schedule on/off 1 : on, 0 : off
enableX 		 - wifi rule X switch 1 : Enbale, 0 : Disabled
weekX 		 - wifi rule X week days, range value : {255,128,64,32,16,8,4,2}, default 255.
startHourX	 - wifi rule X start time hour, range value: 0 - 23, default 0.
startMinuteX 	 - wifi rule X start time minute, range value: 0 - 60, default 0.
endHourX 	 - wifi rule X end time hour, range value: 0 - 23, default 0.
endMinuteX 	 - wifi rule X end time minute, range value: 0 - 60, default 0.
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int setWiFiScheduleConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char wlan_if[8]={0};
	SCHEDULE_T entry;
	int i;
	char *strTmp,*strTmp2;
	char tmpBuf[MAX_MSG_BUFFER_SIZE]={0};
	int pid;

	int WiFiIdx=0;
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);
	
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));	
	int wlsch_onoff= atoi(websGetVar(data, T("wifiScheduleEn"), T("0")));
	
	if(addEffect){		
		apmib_set(MIB_WLAN_SCHEDULE_ENABLED, (void *)&wlsch_onoff);
	}
	else {//add 
		apmib_set(MIB_WLAN_SCHEDULE_DELALL, (void *)&entry);

		for(i=1; i<=MAX_SCHEDULE_NUM ; i++){
			int index;
			memset(&entry, '\0', sizeof(entry));
			
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);			

			index = i-1;
				
			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"enable%d",index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			if(strTmp[0]){
				entry.eco = atoi(strTmp);
			}
			
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "week%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			if(strTmp[0]){
				entry.day = atoi(strTmp);
			}

			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "startHour%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "startMinute%d", index);
			strTmp2 = websGetVar(data, tmpBuf, T(""));
			entry.fTime = atoi(strTmp)*60 + atoi(strTmp2);	
			
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "endHour%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "endMinute%d", index);
			strTmp2 = websGetVar(data, tmpBuf, T(""));
			entry.tTime = atoi(strTmp)*60 + atoi(strTmp2);	
			
			apmib_set(MIB_WLAN_SCHEDULE_ADD, (void *)&entry);
		}	
	}

#if defined(FOR_DUAL_BAND)
	WiFiIdx=1;
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);
	
	if(addEffect){		
		apmib_set(MIB_WLAN_SCHEDULE_ENABLED, (void *)&wlsch_onoff);
	}
	else {//add 
		apmib_set(MIB_WLAN_SCHEDULE_DELALL, (void *)&entry);
		for(i=1; i<=MAX_SCHEDULE_NUM ; i++){
			int index;
			memset(&entry, '\0', sizeof(entry));
			
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);			

			index = i-1;
				
			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"enable%d",index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			if(strTmp[0]){
				entry.eco = atoi(strTmp);
			}
			
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "week%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			if(strTmp[0]){
				entry.day = atoi(strTmp);
			}

			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "startHour%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "startMinute%d", index);
			strTmp2 = websGetVar(data, tmpBuf, T(""));
			entry.fTime = atoi(strTmp)*60 + atoi(strTmp2);	
			
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "endHour%d", index);
			strTmp = websGetVar(data, tmpBuf, T(""));
			memset(tmpBuf, 0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf, "endMinute%d", index);
			strTmp2 = websGetVar(data, tmpBuf, T(""));
			entry.tTime = atoi(strTmp)*60 + atoi(strTmp2);	
			
			apmib_set(MIB_WLAN_SCHEDULE_ADD, (void *)&entry);
		}	
	}
#endif

	pid=fork();
	if(0 == pid){
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	} 

#ifdef CONFIG_CROND
	CsteSystem("csteSys wifiSch", CSTE_PRINT_CMD);
	CsteSystem("csteSys updateCrond", CSTE_PRINT_CMD);
#endif

	//system("sysconf wlan_schedule");//setWiFiSchedule effect
	websSetCfgResponse(mosq, tp, "5", "reserv");

	__FUNC_OUT__
    return 0;
}

/**
* @note getWiFiScheduleConfig - Get WiFi Schedule Config
*
* @param   none
* @return  Return Json Data
<pre>
{
	"wifiIdx": 	"0",
	"wifiScheduleEn":	"0",
	"wifiScheduleNum":	"10",
	"wifiScheduleRule0":	"0,255,0,0,0,0",
	"wifiScheduleRule1":	"0,255,0,0,0,0",
	"wifiScheduleRule2":	"0,255,0,0,0,0",
	"wifiScheduleRule3":	"0,255,0,0,0,0",
	"wifiScheduleRule4":	"0,255,0,0,0,0",
	"wifiScheduleRule5":	"0,255,0,0,0,0",
	"wifiScheduleRule6":	"0,255,0,0,0,0",
	"wifiScheduleRule7":	"0,255,0,0,0,0",
	"wifiScheduleRule8":	"0,255,0,0,0,0",
	"wifiScheduleRule9":	"0,255,0,0,0,0"
}
Return parameter description:
wifiScheduleEn 	- wifi schedule on/off 1 : on, 0 : off
wifiScheduleNum 	- wifi schedule max rules, default : 10
wifiScheduleRuleX 	- wifi schedule rules, "Enable,Week,StartHour,StartMinute,EndHour,EndMinute"
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiScheduleConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char wlan_if[8]={0};

    int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
    SetWlan_idx(wlan_if);

	SCHEDULE_T entry;
	char* linker = ",";
	char strTmp[32], entryName[32];
	int	i, entryNum = 0, wlsch_onoff;
	int startHour, startMin, endHour, endMin;
	
	char msgBuf[MAX_MSG_BUFFER_SIZE]={0};
	char entryBuf[MAX_MSG_BUFFER_SIZE]={0};
	__FUNC_IN__ ;
	
	apmib_get(MIB_WLAN_SCHEDULE_ENABLED, (void *)&wlsch_onoff);
	cJSON_AddNumberToObject(root, "wifiScheduleEn", wlsch_onoff);

	apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);
	cJSON_AddNumberToObject(root, "wifiScheduleNum", entryNum);
	
	if(wlsch_onoff == 1){		
		for(i=1; i<=MAX_SCHEDULE_NUM ; i++){
			int index;

			memset(&entry, '\0', sizeof(entry));
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);			

			index = i-1;

			memset(entryBuf, 0x00, sizeof(entryBuf));
			sprintf(entryBuf, "%d", entry.eco);

			memset(strTmp, 0x00, sizeof(strTmp));
			sprintf(strTmp, "%d", entry.day);
			strcat(entryBuf, linker);
			strcat(entryBuf, strTmp);

			startHour= floor(entry.fTime/60.0);
			startMin = entry.fTime %60;	
			endHour= floor(entry.tTime/60.0);
			endMin = entry.tTime%60;
			
			memset(strTmp, 0x00, sizeof(strTmp));
			sprintf(strTmp, "%d", startHour);
			strcat(entryBuf, linker);
			strcat(entryBuf, strTmp);

			memset(strTmp, 0x00, sizeof(strTmp));
			sprintf(strTmp, "%d", startMin);
			strcat(entryBuf, linker);
			strcat(entryBuf, strTmp);

			memset(strTmp, 0x00, sizeof(strTmp));
			sprintf(strTmp, "%d", endHour);
			strcat(entryBuf, linker);
			strcat(entryBuf, strTmp);

			memset(strTmp, 0x00, sizeof(strTmp));
			sprintf(strTmp, "%d", endMin);
			strcat(entryBuf, linker);
			strcat(entryBuf, strTmp);

			sprintf(entryName, "wifiScheduleRule%d", i-1);
			cJSON_AddStringToObject(root, entryName, entryBuf);
		}	
	}

	output=cJSON_Print(root);
    websGetCfgResponse(mosq, tp, output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__ ;
    return 0;
}

#if defined(SUPPORT_MESH)
int formatMac(char *mac,char out_mac[])
{
    char *delim=":", *p=NULL;
    char buffer[32]={0},tmp_mac[32]={0}; 
	strcpy(tmp_mac,mac);
    if(tmp_mac!=NULL){
        p = strtok(tmp_mac, delim);
        if(p==NULL) return 0;
        strcat(buffer, p);
        while((p=strtok(NULL, delim))) {
    		strcat(buffer, p);
    	}
		strcpy(out_mac,buffer);
    }
	
	return 0;
}
static int checkSameIpAndMac(struct in_addr *IpAddr, char *macAddr, int entryNum)
{
	if(IpAddr==NULL || macAddr==NULL || entryNum<1)
		return 0;
	int i;
	DHCPRSVDIP_T entry;
	
	for (i=1; i<=entryNum; i++) 
	{
		*((char *)&entry) = (char)i;
		if(!apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry))
		{
			printf("get mib MIB_DHCPRSVDIP_TBL fail!\n");
			return -1;
		}
		if((memcmp(IpAddr, entry.ipAddr, 4)==0))
			return 1;
		
		if((memcmp(macAddr, entry.macAddr, 6)==0))
			return 2;
	}
	return 0;
}

/**
* @note meshInfoKick -Master-slave information synchronization
*
* @param NULL
* @return NULL
* @author jarven
* @date    2017-11-14
*/
int meshInfoKick(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int opmode=0;	
	int i,filesize;
	int mesh_enable=0,mesh_enable0=0,mesh_enable1=0;
	
	cJSON* subObj, *root;
	char *devInfo=NULL,*ipaddr=NULL;
	char myMd5val[64]={0},lanAddr[32]={0},cmd[128]={0};
	
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable0);
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable1);
	mesh_enable = mesh_enable0 | mesh_enable1;
	
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	
	getCmdStr("md5sum /web_cste/meshInfo.ini  | awk '{print $1}'", myMd5val ,sizeof(myMd5val));
	getInAddr("br0", IP_ADDR_T, (void *)lanAddr);
	if(opmode==0&&mesh_enable==1){

		if(f_exist("/tmp/MinorDevInfoList"))
		{
			filesize = f_size("/tmp/MinorDevInfoList");
			devInfo = (char *)malloc(filesize); 
			f_read("/tmp/MinorDevInfoList", devInfo, 0, filesize);

			root = cJSON_Parse(devInfo);
			free(devInfo);
			for(i=0; i<cJSON_GetArraySize(root); i++)
			{
				subObj = cJSON_GetArrayItem(root, i);
				ipaddr = websGetVar(subObj, T("IpAddr"), T("0"));
				sprintf(cmd,
					"cs_pub %s UpdateWifiInfo {\\\"NewMd5\\\":\\\"%s\\\",\\\"serverIp\\\":\\\"%s\\\"}",
					ipaddr,myMd5val,lanAddr);
				
				CsteSystem(cmd, CSTE_PRINT_CMD);
			}
			cJSON_Delete(root);
		}
	}
	return 0;
}

/**
* @note keepAlive -Check whether the mesh network is connected
*
* @param NULL
* @return NULL
* @author jarven
* @date    2017-11-14
*/
int keepAlive(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char root[2048]={0},dateStr[32]={0},mibBr0Ip[16]={0};
	char lanAddr[16]={0},lanMac[32]={0},fwVersion[32]={0},devName[32]={0},md5Val[64]={0},server_ip[16]={0}, *output=NULL;
	int opmode=0,mesh_succ_num=0;
	char cmd[2048]={0};

	apmib_get(MIB_OP_MODE, &opmode);
	if(opmode!=1)
		return 0;
	if(f_exist("/tmp/udhcpcinfo"))	
	{
		getCmdStr("cat /tmp/udhcpcinfo | grep server_ip | cut -f2 -d=",server_ip,sizeof(server_ip));
	}
	else
	{
		mesh_succ_num=getCmdVal("cat /proc/kl_reg | grep meshSuccNum | cut -f2 -d=");
		if(mesh_succ_num<1)
		{
			CsteSystem("csteSys csnl 2 -1",CSTE_PRINT_CMD);
			CsteSystem("csteSys takeEffectSync 1",CSTE_PRINT_CMD);
		}
		else
		{
			CsteSystem("echo '' > /tmp/meshKeepAlive0",CSTE_PRINT_CMD);
			CsteSystem("csteSys updateAddr 2> /dev/null",CSTE_PRINT_CMD);
		}
		CsteSystem("csteSys reg 2 0 0 1 0",CSTE_PRINT_CMD);
		return 0;
	}
	getIfMac("br0",lanMac);
	if(!f_exist("/web_cste/meshInfo.ini"))
	{
		CsteSystem("sysconf updateAllMeshInfo",CSTE_PRINT_CMD);
	}
	getCmdStr("md5sum /web_cste/meshInfo.ini  | awk '{print $1}'", md5Val ,sizeof(md5Val));
	if(!getInAddr("br0", IP_ADDR_T, (void *)lanAddr))
	{
		sprintf(lanAddr,"0.0.0.0");
	}
	if(!f_exist("/tmp/meshKeepAlive0")){
		CsteSystem("echo '' > /tmp/meshKeepAlive0",CSTE_PRINT_CMD);
	}
	else if(!f_exist("/tmp/meshKeepAlive1")){
		if(!f_exist("/tmp/meshSyncInfo"))
			CsteSystem("csteSys reg 2 0 0 1 0",CSTE_PRINT_CMD);
		CsteSystem("echo '' > /tmp/meshKeepAlive1",CSTE_PRINT_CMD);
	}
	else if(!f_exist("/tmp/meshKeepAlive2")){
		CsteSystem("echo '' > /tmp/meshKeepAlive2",CSTE_PRINT_CMD);
	}
	else{		
		CsteSystem("rm -f /tmp/meshKeepAlive1",CSTE_PRINT_CMD);
		CsteSystem("rm -f /tmp/meshKeepAlive2",CSTE_PRINT_CMD);
		CsteSystem("csteSys updateAddr 2> /dev/null",CSTE_PRINT_CMD);
		return 0;
	}
	system("echo '' > /var/log/ping.txt");
	
	getLanIp(mibBr0Ip);
	if(!strcmp(lanAddr,mibBr0Ip))
	{
		return 0;
	}
	apmib_get(MIB_HARDWARE_MODEL, (void *)devName);	
	sprintf(fwVersion, "%s.%d", PRODUCT_VER,PRODUCT_SVN);
	addInfoToroot(root, "Name", devName);
	addInfoToroot(root, "IpAddr", lanAddr);
	addInfoToroot(root, "MacAddr", lanMac);
	addInfoToroot(root, "Md5Val", md5Val);
	addInfoToroot(root, "FwVersion", fwVersion);
//	getCmdStr(" date +\"%D:%H:%M:%S\"",dateStr,sizeof(dateStr));
//	addInfoToroot(root, "Date", dateStr);
	sprintf(cmd,"cs_pub %s checkKeepAlive %s",server_ip,root);
//	printf("Cary Debug:%s\n",cmd);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	return 0;
}

int saveToMeshListFile(const char *NewMacAddr, cJSON* data)
{
	FILE *fp=NULL;
	int i=0, filesize=0, op_mode=0,mesh_client_num=0,isMacExist=0,j=0,DevListNum=0;
	char *output=NULL,*devInfo=NULL,*devMac=NULL;
	cJSON *rootObj, *subObj, *dataObj;

	char mac[32]={0},tmpMac[16]={0},cmd[128]={0},dateStr[32]={0};
	apmib_get(MIB_OP_MODE,(void *)&op_mode);
	if(op_mode==1) 
	{
		return 0;
	}
	if(!f_exist("/tmp/MinorDevInfoList"))
		system("echo [] > /tmp/MinorDevInfoList");

	//data copy.
	output =cJSON_Print(data);
	dataObj = cJSON_Parse(output);
	free(output);
	
	filesize = f_size("/tmp/MinorDevInfoList");
	if(filesize > 0)
	{
		fp=fopen("/tmp/MinorDevInfoList","r+");
		devInfo = (char *)malloc(filesize);
		fseek(fp,0,SEEK_SET);
		fread(devInfo, 1, filesize,fp);
		fclose(fp);
	}

	rootObj = cJSON_Parse(devInfo);

	DevListNum=cJSON_GetArraySize(rootObj);
	
	getCmdStr(" date +\"%D:%H:%M:%S\"",dateStr,sizeof(dateStr));
	cJSON_AddStringToObject(dataObj, "Date", dateStr); 
	
	if(strstr(devInfo,NewMacAddr))
	{
		//Replace
		for(i=0; i<DevListNum; i++)
		{
			subObj = cJSON_GetArrayItem(rootObj, i);
			devMac = websGetVar(subObj, T("MacAddr"), T("0"));
			if(!strcmp(NewMacAddr,devMac))
			{
				cJSON_ReplaceItemInArray(rootObj, i ,dataObj);
				break;
			}
		}
	}
	else
	{
		cJSON_AddItemToArray(rootObj, dataObj);
	}
		
	output =cJSON_Print(rootObj);

	fp=fopen("/tmp/MinorDevInfoList","w");
	fwrite(output,strlen(output),1,fp);
	fclose(fp); 
	free(output);
	cJSON_Delete(rootObj);
	free(devInfo);
	return 0;
}

/**
* @note CheckKeepAlive -Used to receive heartbeat packets from  slave
*
* @param Setting Json Data
<pre>
{
	"macAddr" : "",
	"ipAddr":"",
	"md5Val":"",
}
Setting parameter description:
macAddr 	-the slave MAC address
ipAddr	-the slave IP address 
md5Val	-the slave MD5 value
</pre>
* @return NULL
* @author jarven
* @date    2017-11-14
*/
int checkKeepAlive(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *NewMacAddr = websGetVar(data, T("macAddr"), T("0"));
	char *NewIpAddr = websGetVar(data, T("ipAddr"), T("0"));
	char *md5Val = websGetVar(data, T("md5Val"), T("0"));
	char myMd5val[64]={0},tmpCmd[128]={0},lanAddr[32]={0};
	int op_mode=0;
	
	int entryNum=0,ret=0,brip[3],mesh_action=0,static_lease=0;
	unsigned char macAddr[6]={0};
	char buffer[32]={0},ip_address[32]={0},mac_address[32]={0};
	DHCPRSVDIP_T staticIPEntry;
	struct in_addr inIp, inLanaddr_orig, inLanmask_orig;
	
	apmib_get(MIB_OP_MODE,(void *)&op_mode);
	if(op_mode!=0)
		return 0;
	
	if(!f_exist("/web_cste/meshInfo.ini"))
	{
		system("sysconf updateAllMeshInfo");
		return 0;
	}
#if 1	
	apmib_get(MIB_DHCPRSVDIP_TBL_NUM,(void *)&entryNum);
	if ( (entryNum + 1) > MAX_DHCP_RSVD_IP_NUM ){
		return 0;
	}
	
	inet_aton(NewIpAddr, &inIp);

	formatMac(NewMacAddr,mac_address);
	string_to_hex(mac_address,  macAddr, 12);	
	if(macAddr[0]==0x00&&macAddr[1]==0x00&&macAddr[2]==0x00)
		return 0;
	
	ret=checkSameIpAndMac(&inIp, macAddr, entryNum);

//	mesh_action=getCmdVal("cat /proc/kl_reg | grep mesh_action | cut -f2 -d=");
//	if(mesh_action==1)
//		ret=1;
#endif	
	if(ret==1)//static ip exist 
	{
		saveToMeshListFile(NewMacAddr, data);
		system("echo \"/10.000/\" > /var/log/ping.txt");
		getCmdStr("md5sum /web_cste/meshInfo.ini  | awk '{print $1}'", myMd5val ,sizeof(myMd5val));
		getInAddr("br0", IP_ADDR_T, (void *)lanAddr);

		if(strcmp(md5Val,myMd5val))
		{
			sprintf(tmpCmd,
				"cs_pub %s updateWifiInfo {\\\"NewMd5\\\":\\\"%s\\\",\\\"serverIp\\\":\\\"%s\\\"}",
				NewIpAddr,myMd5val,lanAddr);
		}
		else
			sprintf(tmpCmd,
				"cs_pub %s updateWifiInfo {\\\"NewMd5\\\":\\\"%d\\\",\\\"serverIp\\\":\\\"%s\\\"}",
				NewIpAddr,0,lanAddr);
		
	//	CsteSystem(tmpCmd,CSTE_PRINT_CMD);
	}
	else if(ret == 2)//static ip  mac is not corresponding 
	{
		static_lease=getCmdVal("cat /var/udhcpd.conf | grep static | awk '{count++} END{print count}'");
		if(static_lease!=entryNum)
		{
			system("sysconf reservedIP");
			return 0;
		}
		else
			sprintf(tmpCmd,"cs_pub %s updateLanIp {}",NewIpAddr);
	}
	else //the slave is not in static 
	{
		int staticdhcp_enabled=0;
		apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&staticdhcp_enabled);
		if(staticdhcp_enabled==0)
		{
			staticdhcp_enabled=1;
			apmib_set(MIB_DHCPRSVDIP_ENABLED, (void *)&staticdhcp_enabled);
		}
		sscanf(NewIpAddr,"%d.%d.%d.%*d",&brip[0],&brip[1],&brip[2]);
		sprintf(ip_address,"%d.%d.%d.%d",brip[0],brip[1],brip[2],entryNum+200);
		
		if(inet_aton(ip_address, &inIp))
			memcpy(staticIPEntry.ipAddr, &inIp, 4);
		
		strcpy((char *)staticIPEntry.hostName, "mesh slave");
			
		string_to_hex(mac_address, staticIPEntry.macAddr, 12);
		memset(buffer, '\0', sizeof(buffer));
			
		apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
		memcpy((void *)&inLanaddr_orig, buffer, 4); 	
		apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
		memcpy((void *)&inLanmask_orig, buffer, 4);
		if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inIp.s_addr & inLanmask_orig.s_addr)){
			return 0;
		}
		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&staticIPEntry);
		if ( apmib_set(MIB_DHCPRSVDIP_ADD, (void *)&staticIPEntry) == 0) {
			return 0;
		}
		
		system("sysconf reservedIP");
		apmib_update(CURRENT_SETTING);
		sprintf(tmpCmd,"cs_pub %s updateLanIp {}", NewIpAddr);
	}
	CsteSystem(tmpCmd,CSTE_PRINT_CMD);

	//need check roaming
	CsteSystem("sysconf roaming_cfg", CSTE_PRINT_CMD);
	CsteSystem("sysconf roaming_app", CSTE_PRINT_CMD);	
	
	return 0;
}
void setWifiAclCfg(int aclNum,const char *macList)
{
	MACFILTER_T macEntry;
	int entryNum=0,i=0;
	char *buffer=NULL, tmpMacList[256]={0};
	apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum);

	if(aclNum==entryNum) return;
	
	//del
    for (i=1; i<=entryNum; i++)
	{		
       *((char *)&macEntry) = (char)1;
        apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
        apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
    }
	
	//add
	if(aclNum>0)
	{
		strcpy(tmpMacList,macList);
		buffer=strtok(tmpMacList, ";");
        if(buffer==NULL) return 0;	
		
		sscanf(buffer,"%02x:%02x:%02x:%02x:%02x:%02x",		
			&macEntry.macAddr[0], &macEntry.macAddr[1], &macEntry.macAddr[2],
			&macEntry.macAddr[3], &macEntry.macAddr[4], &macEntry.macAddr[5]);
		
		apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
		while(buffer=strtok(NULL, ";"))
		{
			if(buffer==NULL) break;	
			sscanf(buffer,"%02x:%02x:%02x:%02x:%02x:%02x",		
				&macEntry.macAddr[0], &macEntry.macAddr[1], &macEntry.macAddr[2],
				&macEntry.macAddr[3], &macEntry.macAddr[4], &macEntry.macAddr[5]);
			
			apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
		}
	}
	return;
}
int sync_wifi_info()
{
	FILE *fp=NULL;

	int mib_str=0,tmp_val=0,type=0,setWifiAclCfgFalg=0;
	char line_str[256] = {0},value_str[256]={0};
	char wifiIdx[8]={0},set_cmd[128]={0};
	char *p=NULL;
	
	fp=fopen("/web_cste/meshInfo.ini","r+");
	if(fp==NULL)
	{
		perror("fopen");
		return 0;
	}
	CsteSystem("echo 1 > /tmp/meshSyncInfo",CSTE_PRINT_CMD);
	while(NULL!=fgets(line_str,sizeof(line_str),fp))
	{
		if(NULL!=strstr(line_str,"["))
		{
			sscanf(line_str,"[%5s]",wifiIdx);
			
			line_str[strlen(line_str)-1]='\0';
			
			if((!strcmp(wifiIdx,"wlan0"))||(!strcmp(wifiIdx,"wlan1")))
			{
				SetWlan_idx(wifiIdx);
			}
			else if(!strcmp(wifiIdx,"AclCf"))
			{
				setWifiAclCfgFalg=1;
			}
			
			continue ;
		}
		if(NULL==strstr(line_str,"="))
			continue;
		line_str[strlen(line_str)-1]='\0';
		
		p=line_str;
		while((*p)!='=')
			p++;
		*p='\0';
		strcpy(value_str,p+1);

		sscanf(line_str,"%*[^(](%d:%d)",&mib_str,&type);
		if(strlen(value_str)==0&&setWifiAclCfgFalg==0)
		{
			continue ;
		}
	//	if(type==1)
	//		printf("\n[HRH]	setWifiAclCfgFalg:%d,	type:%d, value_str:%s\n",setWifiAclCfgFalg,type,value_str);
	//	if(mib_str==451||mib_str==1|| mib_str==30||\
	//		mib_str==182||mib_str==183|| mib_str==153||mib_str==7002)
		if(type==1)	
		{
			if(setWifiAclCfgFalg==1)
			{
				setWifiAclCfg(mib_str,value_str);
				setWifiAclCfgFalg=0;
			}
			else
				apmib_set(mib_str,(void *)value_str);
		}
		else
		{
			tmp_val=atoi(value_str);
			apmib_set(mib_str,(void *)&tmp_val);
		}
		memset(value_str,0,sizeof(value_str));
	}
	
	apmib_update_web(CURRENT_SETTING);
	
	CsteSystem("rm /tmp/mesh_action_flag 2> /dev/null",CSTE_PRINT_CMD);
	CsteSystem("rm /tmp/udhcpcinfo 2> /dev/null",CSTE_PRINT_CMD);
	CsteSystem("csteSys csnl 6 0", CSTE_PRINT_CMD);//close led blink
	CsteSystem("csteSys csnl 1 1", CSTE_PRINT_CMD);//kick linux opmode
	CsteSystem("csteSys csnl 2 -1", CSTE_PRINT_CMD);
	CsteSystem("ifconfig br0 0.0.0.0", CSTE_PRINT_CMD);
	
	sleep(2);
	CsteSystem("init.sh ap all",CSTE_PRINT_CMD);

	CsteSystem("csteSys csnl 2 0",CSTE_PRINT_CMD);

	return 0;
}

/**
* @note updateLanIp -Retrieve the IP address
*
* @param NULL
* @return NULL
* @author jarven
* @date    2017-11-14
*/
int updateLanIp(struct mosquitto *mosq, cJSON* data, char *tp)
{
	CsteSystem("echo '' > /tmp/meshKeepAlive0",CSTE_PRINT_CMD);
	CsteSystem("rm -f /tmp/udhcpcinfo 2> /dev/null",CSTE_PRINT_CMD);
	CsteSystem("csteSys updateAddr 2> /dev/null",CSTE_PRINT_CMD);
}
/**
* @note UpdateWifiInfo -Master-slave information synchronization
*
* @param Setting Json Data
<pre>
{
	"serverIp":"",
	"newMd5":"",
}
Setting parameter description:
ipAddr	-the master IP address 
newMd5	-the master MD5 value
</pre>
* @return NULL
* @author jarven
* @date    2017-11-14
*/
int updateWifiInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	
	char *serverIp = websGetVar(data, T("serverIp"), T("0"));
	char *NewMd5 = websGetVar(data, T("newMd5"), T("0"));
	char Mymd5[64] = {0},tmpCmd[128]={0};
	
	if(!strcmp(NewMd5,"0"))
	{		
		//need check roaming
	#if 0
		printf("Debug by cary:%s[%d]\n",__FUNCTION__,__LINE__);
	#else
		system("echo \"/10.000/\" > /var/log/ping.txt");
		
		if(f_exist("/tmp/meshKeepAlive0"))
			CsteSystem("rm -f /tmp/meshKeepAlive0",CSTE_PRINT_CMD);
		if(f_exist("/tmp/meshKeepAlive1"))
			CsteSystem("rm -f /tmp/meshKeepAlive1",CSTE_PRINT_CMD);
		if(f_exist("/tmp/meshKeepAlive2"))
			CsteSystem("rm -f /tmp/meshKeepAlive2",CSTE_PRINT_CMD);
		if(f_exist("/tmp/meshSyncInfo"))
			CsteSystem("rm -f /tmp/meshSyncInfo",CSTE_PRINT_CMD);
		if(getCmdVal("cat /proc/kl_reg | grep LedCtrl | cut -f2 -d="))
			CsteSystem("csteSys reg 2 0 0 0 0",CSTE_PRINT_CMD);
		
		CsteSystem("sysconf roaming_cfg", CSTE_PRINT_CMD);
		CsteSystem("sysconf roaming_app", CSTE_PRINT_CMD);	
	#endif
		return 0;
	}
	else
	{
		CsteSystem("killall WTP", CSTE_PRINT_CMD);
		CsteSystem("rm /web_cste/meshInfo.ini 2> /dev/null",CSTE_PRINT_CMD);	

		sprintf(tmpCmd,"cd /web_cste/; wget http://%s/meshInfo.ini",serverIp);
		CsteSystem(tmpCmd,CSTE_PRINT_CMD);
		sleep(5);
		getCmdStr("md5sum /web_cste/meshInfo.ini  | awk '{print $1}'", Mymd5 ,sizeof(Mymd5));

		if(!strcmp(Mymd5,NewMd5))//下载成功
		{
			sync_wifi_info();
		}
	}
	return 0;
}
typedef struct cmpDate{
	char day[16];
	int hour;
	int min;
}DATE_T;

/**
* @note getWiFiMeshConfig - Get mesh connected status
*
* @param   none
* @return  Return Json Data
<pre>
{
	"meshInfo": "T10,192.168.15.202,F428530001B0;",
	"meshState":	1
}
Return parameter description:
meshInfo		-mesh slave list.
meshState	-mesh connent status. 1 connected, 0  disconnected
</pre>
* @author jarven
* @date    2017-11-14
*/
int getWiFiMeshConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int  len=0,opmode=0,mesh_enable1=0,mesh_enable2,i=0,filesize=0,conn_num=0;
    char *ipAddr=NULL,*tmpMac=NULL,*Name=NULL,*output=NULL,*devInfo=NULL;
    char responseStr[CSTEBUFSIZE]={0},mac[32]={0};
	char *date=NULL,dateStr[32]={0};
	DATE_T masterDate, slaveDate;

	cJSON* subObj;
    cJSON *root=cJSON_CreateObject();
	cJSON *tmproot=cJSON_CreateObject();
	__FUNC_IN__
		
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable1);
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable2);
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	
	getCmdStr(" date +\"%D:%H:%M:%S\"",dateStr,sizeof(dateStr));
	sscanf(dateStr,"%[^:]:%d:%d:%*d",masterDate.day,&masterDate.hour,&masterDate.min);
	
	if(opmode==0&&(mesh_enable1||mesh_enable2))
	{
		if(f_exist("/tmp/MinorDevInfoList"))
		{
			filesize = f_size("/tmp/MinorDevInfoList");
			devInfo = (char *)malloc(filesize); 
			f_read("/tmp/MinorDevInfoList", devInfo, 0, filesize);
			tmproot = cJSON_Parse(devInfo);
			free(devInfo);
			for(i=0; i<cJSON_GetArraySize(tmproot); i++)
			{
				subObj = cJSON_GetArrayItem(tmproot, i);
				ipAddr = websGetVar(subObj, T("ipAddr"), T("0"));
				tmpMac = websGetVar(subObj, T("macAddr"), T("0"));
				Name = websGetVar(subObj, T("name"), T("0"));
				date = websGetVar(subObj, T("date"), T("0"));
				sscanf(date,"%[^:]:%d:%d:%*d",slaveDate.day,&slaveDate.hour,&slaveDate.min);
				
				if(strcmp(slaveDate.day,masterDate.day))
					continue;

				if(((masterDate.hour)*60+masterDate.min-((slaveDate.hour)*60+slaveDate.min))>4)
					continue;

				conn_num++;
				formatMac(tmpMac,mac);
				if(len==0)
					snprintf((responseStr + len), (sizeof(responseStr) - len),"%s,%s,%s",Name,ipAddr,mac);
				else
					snprintf((responseStr + len), (sizeof(responseStr) - len),";%s,%s,%s",Name,ipAddr,mac);
				
				len = strlen(responseStr);
				
			}
			cJSON_Delete(tmproot);
		}
	}
	cJSON_AddStringToObject(root,"meshInfo",responseStr);
	if(conn_num>1) conn_num=1;
	cJSON_AddNumberToObject(root,"meshState",conn_num);
    __FUNC_OUT__
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
    return 0; 
}
void cleanStaticDhcp(void)
{
	int i,entryNum;
	char name_buf[32];
	char *value;
	DHCPRSVDIP_T delEntry;
	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		*((char *)(void *)&delEntry) = (char)i;
		apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&delEntry);
		apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&delEntry);			
	}
	CsteSystem("sysconf reservedIP", CSTE_PRINT_CMD);
	return 0;
}
/**
* @note setWiFiMeshConfig - set  mesh connected config
*
* @param Json Data
<pre>
{
	"meshEnabled": "1",
}
Return parameter description:
meshEnabled	-mesh interface status. 1 enable, 0  disable
</pre>
* @author jarven
* @date    2017-11-14
*/
int setWiFiMeshConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	__FUNC_IN__
    int pid;
	int tmpVal=0, opmode=0,wlan_mode=0,mesh_sync=0,channel=0;
	char wifiIdx[16]={0};
    int enabled=atoi(websGetVar(data, T("meshEnabled"), T("0")));
	if(enabled==0)
	{
		SetWlan_idx("wlan0");
		apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&enabled);
		SetWlan_idx("wlan1");
		apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&enabled);

		pid=fork();
		if(0 == pid)
		{
			apmib_update_web(CURRENT_SETTING);
			system("csteSys csnl 2 -1");
			sleep(1);
			system("csteSys csnl 2 0");
			exit(1);
		}
		
		pid=fork();
		if(0 == pid)
		{
			//sleep(2);
			takeEffectWlan("wlan0", 1);
			takeEffectWlan("wlan1", 1);
			exit(1);
		}	
		websSetCfgResponse(mosq, tp, "15","reserv");
		return 0;
	}

	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&tmpVal);
	if(tmpVal==1)
	{
		system("csteSys csnl 6 0"); 
		return 0;
	}
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&tmpVal);
	if(tmpVal==0)
	{
		tmpVal=0;
		apmib_set(MIB_REPEATER_ENABLED1,(void *)&tmpVal);
		apmib_set(MIB_REPEATER_ENABLED2,(void *)&tmpVal);
		apmib_set(MIB_OP_MODE,(void *)&tmpVal);
		tmpVal=DHCP_SERVER;
		apmib_set(MIB_DHCP,(void *)&tmpVal);

		cleanStaticDhcp();
		system("brctl delif br0 eth1 2> /dev/null"); 
		system("brctl delif br0 wlan0-vxd 2> /dev/null"); 
		system("brctl delif br0 wlan1-vxd 2> /dev/null"); 
		wlan_mode=4;
		SetWlan_idx("wlan0");
		apmib_set(MIB_WLAN_MODE,(void *)&wlan_mode);
		apmib_get(MIB_WLAN_CHANNEL,(void *)&channel);
		tmpVal=0;
		apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&tmpVal);
		if(channel==0){
			channel=getWirelessChannel("wlan0");
			apmib_set(MIB_WLAN_CHANNEL,(void *)&channel);
		}
		
		tmpVal=1;
		apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&tmpVal);
#if defined(FOR_DUAL_BAND)	
	SetWlan_idx("wlan1");
	apmib_set(MIB_WLAN_MODE,(void *)&wlan_mode);
	apmib_get(MIB_WLAN_CHANNEL,(void *)&channel);
	tmpVal=0;
	apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&tmpVal);
	if(channel==0){
		channel=getWirelessChannel("wlan1");
		apmib_set(MIB_WLAN_CHANNEL,(void *)&channel);
	}
		tmpVal=1;
		apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&tmpVal);
#endif	
		system("ifconfig wlan0-vxd down 2> /dev/null"); 
		system("ifconfig wlan1-vxd down 2> /dev/null"); 
//		tmpVal=3;
//		apmib_set(MIB_CAPWAP_MODE,(void *)&tmpVal);
		
		system("sysconf updateAllMeshInfo");
	}
		
	tmpVal=0;
	SetWlan_idx("wlan0-va2");
	apmib_set(MIB_WLAN_WLAN_DISABLED,(void *)&tmpVal);
	
	system("csteSys csnl 1 0");
	system("csteSys csnl 2 0");

#if defined(CONFIG_8021Q_VLAN_SUPPORTED)
	int vlanEnabled = 0;
	apmib_set(MIB_VLAN_ENABLED, (void *)&vlanEnabled);
#endif
	
   	pid=fork();
	if(0 == pid)
	{
		//sleep(1);
		apmib_update_web(CURRENT_SETTING);
		sleep(1);
		system("csteSys csnl 6 1"); 
		exit(1);
	}

	pid=fork();
	if(0 == pid)
	{
		sleep(5);
		system("init.sh gw all"); 
		exit(1);
	}	
	websSetCfgResponse(mosq, tp, "120","reserv");

return 0;
}
#endif

/*******************************
wlan_disabled : 1 disable wlan 
                     : 0 enable wlan
*******************************/
static void Ctrl_wlan(int wlan_enable, int index) 
{
	int wlan_disabled=0;
	int mesh_enabled=0;
	int wlan_wds_enabled=0;
	int wlan_wds_num=0;
	int i;
	char cmdBuffer[128];
	int repeader_enabled=0;
	int guest0_disabled=0;
	int guest1_disabled=0;
	int guest2_disabled=0;
	int guest3_disabled=0;
	
	sprintf(cmdBuffer,"wlan%d",index);
	
	SetWlan_idx(cmdBuffer);

#if 0 //SUPPORT_MESH
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh_enabled);
#endif
	apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_disabled);
	sprintf(cmdBuffer,"wlan%d-va0",index);
	SetWlan_idx(cmdBuffer);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&guest0_disabled);
	sprintf(cmdBuffer,"wlan%d-va1",index);
	SetWlan_idx(cmdBuffer);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&guest1_disabled);
	sprintf(cmdBuffer,"wlan%d-va2",index);
	SetWlan_idx(cmdBuffer);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&guest2_disabled);
	sprintf(cmdBuffer,"wlan%d-va3",index);
	SetWlan_idx(cmdBuffer);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&guest3_disabled);
	
	if(index == 0)	
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&repeader_enabled);
	else
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&repeader_enabled);

	if (wlan_enable)// enable wlan
	{
		if(!wlan_disabled)
		{
			sprintf(cmdBuffer,"ifconfig wlan%d up",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			if (!guest0_disabled){
				sprintf(cmdBuffer,"ifconfig wlan%d-va0 up",index);
				CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			}
			if (!guest1_disabled){
				sprintf(cmdBuffer,"ifconfig wlan%d-va1 up",index);
				CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			}
			if (!guest2_disabled){
				sprintf(cmdBuffer,"ifconfig wlan%d-va2 up",index);
				CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			}
			if (!guest3_disabled){
				sprintf(cmdBuffer,"ifconfig wlan%d-va3 up",index);
				CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			}
			if (repeader_enabled){
				sprintf(cmdBuffer,"ifconfig wlan%d-vxd up",index);
				CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
			}
			sprintf(cmdBuffer,"csteSys setWifiLedCtrl %d %d",index,(wlan_enable?0:1));
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
#if 0 //SUPPORT_MESH
		if (mesh_enabled){
			CsteSystem("ifconfig wlan-msh up", CSTE_PRINT_CMD);
		}
#endif
	CsteSystem("csteSys csnl 7 0", CSTE_PRINT_CMD);//wifiSch_ctrl

	}
	else 
	{
		if(!wlan_disabled)
		{
			sprintf(cmdBuffer,"ifconfig wlan%d down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}	
		if (!guest0_disabled) {
			sprintf(cmdBuffer,"ifconfig wlan%d-va0 down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
	
		if (!guest1_disabled) {
			sprintf(cmdBuffer,"ifconfig wlan%d-va1 down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
	
		if (!guest2_disabled) {
			sprintf(cmdBuffer,"ifconfig wlan%d-va2 down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
	
		if (!guest3_disabled) {
			sprintf(cmdBuffer,"ifconfig wlan%d-va3 down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
	
		if (repeader_enabled) {
			sprintf(cmdBuffer,"ifconfig wlan%d-vxd down",index);
			CsteSystem(cmdBuffer, CSTE_PRINT_CMD);
		}
		sprintf(cmdBuffer,"csteSys setWifiLedCtrl %d %d",index,(wlan_enable?0:1));
		CsteSystem(cmdBuffer,CSTE_PRINT_CMD);
#if 0 //SUPPORT_MESH
		if (mesh_enabled){
			CsteSystem("ifconfig wlan-msh down", CSTE_PRINT_CMD);
		}
#endif
	
	CsteSystem("csteSys csnl 7 2", CSTE_PRINT_CMD);//wifiSch_ctrl
	
	}
	return ;
}

static int ctrl_time = 0;		
/**
* @note wifiSchedule -WiFi scheduling effective function
*
* @param Setting Json Data
<pre>
{
	"wifiSchedule" : ""
}
Setting parameter description:
wifiSchedule 	: 
	end	: 	End time of wireless scheduling
	start	:	Start time of wireless scheduling
	disableWifiSch	:	Disable wireless scheduling
	checkSch	:	Detecting current time and rule matching
</pre>
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
* @author jarven
* @date    2017-11-14
*/
int WiFiSchedule(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int NtpEnabled = 0;
	NtpEnabled = getCmdVal("cat /tmp/ntp_tmp");	
	
	if(NtpEnabled == 9)//时间同步成功
	{
		int hour = 0,min=0;
		
		char_t *var=NULL;
		//setState
		var = websGetVar(data, T("wifiSchedule"), T("0"));
		if(!strcmp(var,"end"))
		{	
			if(ctrl_time > 0)
				ctrl_time--;
			if(ctrl_time==0){
				Ctrl_wlan(0,0);//disable wlan0
				Ctrl_wlan(0,1);//disable wlan1
			}
		}
		else if(!strcmp(var,"start"))
		{
			if(ctrl_time==0)
			{
				Ctrl_wlan(1,0);//enable wlan
				Ctrl_wlan(1,1);//enable wlan1
			}
			ctrl_time++;
		}
		else if(!strcmp(var,"disableWifiSch"))
		{
			Ctrl_wlan(1,0);//enable wlan0
			Ctrl_wlan(1,1);//enable wlan1
			ctrl_time=0;	
		}
		else if(!strcmp(var,"checkSch"))
		{
			int Enable = 0, entryNum = 0, i = 0, flag=0,implementation=0;
			SCHEDULE_T entry;
			time_t tm;
			struct tm tm_time;
			time(&tm);
			memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
			ctrl_time = 0;
			
			SetWlan_idx("wlan0");
			apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);
			apmib_get(MIB_WLAN_SCHEDULE_ENABLED, (void *)&Enable);
			for (i=1; i<=entryNum; i++) {
				*((char *)&entry) = (char)i;
				SetWlan_idx("wlan0");
				apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);
				if(entry.eco==0)
				{	
					continue;
				}
				implementation++;
				if((entry.day==7)||(entry.day == tm_time.tm_wday))
				{
					if((tm_time.tm_hour*60+tm_time.tm_min>entry.fTime)&&(tm_time.tm_hour*60+tm_time.tm_min<entry.tTime))
					{
						flag=1;
						ctrl_time++;
					}
					else
					{
						if(ctrl_time > 0)
							ctrl_time--;
						if(ctrl_time==0)
						{
							flag=0;
							Ctrl_wlan(0,0);//disable wlan0
							Ctrl_wlan(0,1);//disable wlan1
						}
					}
				}
			}
			
			if(flag==1||implementation==0)
			{
				Ctrl_wlan(1,0);
				Ctrl_wlan(1,1);
			}
			else if(Enable==1)
			{
				Ctrl_wlan(0,0);
				Ctrl_wlan(0,1);
			}
		}			
	}
	return 0;
}

int module_init()
{
	cste_hook_register("setWebWlanIdx",setWebWlanIdx);
	cste_hook_register("getWebWlanIdx",getWebWlanIdx);
	
	cste_hook_register("getWiFiStaInfo",getWiFiStaInfo);
    cste_hook_register("getWiFiApInfo",getWiFiApInfo);
	
    cste_hook_register("setWiFiBasicConfig",setWiFiBasicConfig);
	cste_hook_register("getWiFiBasicConfig",getWiFiBasicConfig);
	
    cste_hook_register("setWiFiAdvancedConfig",setWiFiAdvancedConfig);
	cste_hook_register("getWiFiAdvancedConfig",getWiFiAdvancedConfig);
	
#if defined (MBSSID)
    cste_hook_register("setWiFiMultipleConfig",setWiFiMultipleConfig);
	cste_hook_register("getWiFiMultipleConfig",getWiFiMultipleConfig);
	cste_hook_register("delWiFiMultipleConfig",delWiFiMultipleConfig);
#endif
	cste_hook_register("getWiFiAclAddConfig",getWiFiAclAddConfig);
    cste_hook_register("setWiFiAclAddConfig",setWiFiAclAddConfig);
    cste_hook_register("setWiFiAclDeleteConfig",setWiFiAclDeleteConfig);
	
    cste_hook_register("getWiFiIpMacTable",getWiFiIpMacTable);
    cste_hook_register("getWiFiApcliScan",getWiFiApcliScan);
	
    cste_hook_register("getWiFiWdsAddConfig",getWiFiWdsAddConfig);
    cste_hook_register("setWiFiWdsAddConfig",setWiFiWdsAddConfig);
    cste_hook_register("setWiFiWdsDeleteConfig",setWiFiWdsDeleteConfig);
	
    cste_hook_register("getWiFiRepeaterConfig",getWiFiRepeaterConfig);
    cste_hook_register("setWiFiRepeaterConfig",setWiFiRepeaterConfig);
	
	cste_hook_register("getWiFiScheduleConfig",getWiFiScheduleConfig);
	cste_hook_register("setWiFiScheduleConfig",setWiFiScheduleConfig);
	
#if defined(SUPPORT_MESH)
	cste_hook_register("getWiFiMeshConfig",getWiFiMeshConfig);	
	cste_hook_register("setWiFiMeshConfig",setWiFiMeshConfig);	
	
	cste_hook_register("keepAlive",keepAlive);
	cste_hook_register("checkKeepAlive",checkKeepAlive);
	cste_hook_register("updateWifiInfo",updateWifiInfo);
	
	cste_hook_register("meshInfoKick",meshInfoKick);	
	cste_hook_register("updateLanIp",updateLanIp);
#endif	
#ifdef SUPPORT_REPEATER
	cste_hook_register("getWiFiExtenderConfig",getWiFiExtenderConfig);
	cste_hook_register("setWiFiExtenderConfig",setWiFiExtenderConfig);
#endif
#if defined(CONFIG_SUPPORT_SCHEDULE_WIFI)			//rancho
	cste_hook_register("WiFiSchedule",WiFiSchedule);
#endif
#if defined(SUPPORT_CPE)
	cste_hook_register("syncWdsWificonfig",syncWdsWificonfig);
	cste_hook_register("setAutoWdsCfg",setAutoWdsCfg);
	cste_hook_register("getAutoWdsCfg",getAutoWdsCfg);
#endif	

    return 0;  
}
