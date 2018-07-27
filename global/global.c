/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file global.c
* @author CaryStudio
* @brief  This is a global cste topic
* @date 2017-11-13
* @warning http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.
			http://www.cnblogs.com/davygeek/p/5658968.html
* @bug
*/

#include <stdio.h>
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
#include <sys/time.h>
#include <sys/sysinfo.h>

#include "global.h"
#include "../cstelib.h"

#include "apmib.h"
#include "mibtbl.h"
#include "sigHd.h"

#define IF_SCAN_PATTERN \
	" %[^ :]:%u %*d" \
	" %*d %*d %*d %*d %*d %*d" \
	" %u %*d"
#define TRAP_SCAN_PATTERN " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s "

#define BUFSIZE 32
#define LIVE_LIST "/proc/net/live_list"

int loginflag=0;

#if defined(SUPPORT_CPE)
int getOpMode(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int intVal=0,rpt_enabled=0;
	char tmpBuf[64]={0},ssid[MAX_SSID_LEN]={0};
	__FUNC_IN__
	
	cJSON_AddNumberToObject(root,"wifiDualband",0);
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);

	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_SSID, (void *)ssid);	
	cJSON_AddStringToObject(root,"ssid",ssid);

	cJSON_AddNumberToObject(root,"channel",getWirelessChannel("wlan0"));
    cJSON_AddStringToObject(root,"authMode",getAuthMode("wlan0"));
	
	apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"wpakey",tmpBuf);
	
	apmib_get(MIB_OP_MODE, (void *)&intVal);
	if(intVal==2){
		intVal=3;
	}else if(intVal==1&&rpt_enabled==1){
		intVal=2;
	}

	cJSON_AddNumberToObject(root,"operationMode",intVal);
	memset(tmpBuf,0x00,sizeof(tmpBuf));
	apmib_get(MIB_WLAN_COUNTRY_STRING,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"countryCode",tmpBuf);
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);	
	cJSON_Delete(root);
	__FUNC_OUT__
	return 0;
}

int setOpMode(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int rptEnabled=0,opMode=0,encrypt=0,dhcp_enabled=0;
	char *ssid = websGetVar(data, T("ssid"), T("0"));
	char *wpakey = websGetVar(data, T("wpakey"), T("0"));
	char *authMode = websGetVar(data, T("authMode"), T("0"));
	int channel = atoi(websGetVar(data, T("channel"), T("0")));

	opMode=1;
	apmib_set(MIB_OP_MODE, (void *)&opMode);
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&rptEnabled);

	SetWlan_idx("wlan0");
	apmib_set(MIB_WLAN_SSID, (void *)ssid);
	apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);

	dhcp_enabled=0;
	apmib_set(MIB_DHCP, (void *)&dhcp_enabled);
	
	if(!strcmp(authMode,"WPAPSKWPA2PSK")){
		encrypt=ENCRYPT_WPA2_MIXED;   
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);		
	}
	else{
		encrypt=ENCRYPT_DISABLED;
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&authMode);	
	}
	
	websSetCfgResponse(mosq, tp, "10", "reserv");
	int	pid=fork();
	if(0 == pid){
		system("csteSys csnl 2 -1");
		sleep(1);
		system("csteSys csnl 2 1");
		sleep(3);
		apmib_update_web(CURRENT_SETTING);
		run_init_script("all");
		exit(1);
	}        
	return 0;
}
#else
int getOpMode(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int intVal=0,rpt_enabled=0;
	int mesh0_enabled=0,mesh1_enabled=0;
	int wlan0_enabled=0,wlan1_enabled=0;
	char tmpBuf[32]={0};
	__FUNC_IN__
	
#if defined(FOR_DUAL_BAND)	
	cJSON_AddNumberToObject(root,"wifiDualband",1);

	apmib_get(MIB_WISP_WAN_ID, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wispInterface",intVal);

	if(intVal==0){
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
	}else{
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&rpt_enabled);
	}
	
	cJSON_AddNumberToObject(root,"apCliEnable",rpt_enabled);

	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh1_enabled);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1_enabled);
#else
	cJSON_AddNumberToObject(root,"wifiDualband",0);
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
#endif	

	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh0_enabled);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0_enabled);
	apmib_get(MIB_OP_MODE, (void *)&intVal);
	if(intVal==2){
		intVal=3;
	}else if(intVal==1&&rpt_enabled==1){
		intVal=2;
	}
	if(mesh0_enabled==1||mesh1_enabled==1){
		cJSON_AddStringToObject(root,"operationMode","4");
		cJSON_AddNumberToObject(root,"meshEnabled",1);
	}else{
		memset(tmpBuf,0x00,sizeof(tmpBuf));
		sprintf(tmpBuf,"%d",intVal);
		cJSON_AddStringToObject(root,"operationMode",tmpBuf);
		cJSON_AddNumberToObject(root,"meshEnabled",0);
	}

#if defined(FOR_DUAL_BAND)
	cJSON_AddNumberToObject(root,"wifiOff",wlan1_enabled);
	cJSON_AddNumberToObject(root,"wifiOff5g",wlan0_enabled);
#else
	cJSON_AddNumberToObject(root,"wifiOff",wlan0_enabled);
#endif

#if defined(SUPPORT_APAC)
	cJSON_AddNumberToObject(root,"apAcBt",1);
#else
	cJSON_AddNumberToObject(root,"apAcBt",0);
#endif	

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
#if defined (CONFIG_KL_C7187R_1200)
	strcpy(tmpBuf, "1200");
#endif
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	apmib_get(MIB_CSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"csid",tmpBuf);
	
	cJSON_AddStringToObject(root,"cpeMode","0");

#if defined(CONFIG_KL_C7180R_04339)||defined(CONFIG_KL_C7181R_04336)
	cJSON_AddNumberToObject(root,"repeaterBt",0);
#else
	cJSON_AddNumberToObject(root,"repeaterBt",1);
#endif

	apmib_get(MIB_OPMODE_LIST, tmpBuf);
	cJSON_AddStringToObject(root,"OpModeSupport",tmpBuf);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);	
	cJSON_Delete(root);
	__FUNC_OUT__
	return 0;
}

int setOpMode(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal=0,opmode=0,rpt_flag=0,rpt_disabled=0,wan_type=DHCP_CLIENT,pid=0;
	char wlan_if[16]={0},domain_name[33]={0};
	char buffer[32]={0},mac[32]={0};
	__FUNC_IN__	
		
 	int operationMode = atoi(websGetVar(data, T("operationMode"), T("1")));
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	if(opmode==2&&operationMode==0)
	{
		intVal=0;
		apmib_set(MIB_DNS_MODE, (void *)&intVal);
	}
	
	if(operationMode==3){//WISP
		opmode=WISP_MODE;
		rpt_flag=2;
		apmib_save_wlanIdx();		
		int wanid = atoi(websGetVar(data, T("wispInface"), T("0")));
#if defined(FOR_DUAL_BAND)
		if(wanid==0){//5g
			intVal=1;
			apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
			
			intVal=0;
			apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);
		}else{
			intVal=0;
			apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
			
			intVal=1;
			apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);
		}
#else
		intVal=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
		wanid=0;
#endif
		apmib_set(MIB_WISP_WAN_ID, (void *)&wanid);

		sprintf(wlan_if, "wlan%d", wanid);		
		SetWlan_idx(wlan_if);
		intVal=AP_WDS_MODE;
		apmib_set(MIB_WLAN_MODE, (void *)&intVal);

		sprintf(wlan_if, "wlan%d-vxd", wanid);		
		SetWlan_idx(wlan_if);
		intVal=CLIENT_MODE;
		apmib_set(MIB_WLAN_MODE, (void *)&intVal);		
		
		intVal=0;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		apmib_recov_wlanIdx();
		
		intVal=DHCP_SERVER;
		apmib_set(MIB_DHCP, (void *)&intVal);

		//切换到wisp模式，原来克隆的wanmac恢复到设备本身的mac
		apmib_get(MIB_HW_NIC1_ADDR,  (void *)buffer);
		sprintf(mac, "%02x%02x%02x%02x%02x%02x", (unsigned char)buffer[0], (unsigned char)buffer[1], 
			(unsigned char)buffer[2], (unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);
		string_to_hex(mac, buffer, 12);
		apmib_set(MIB_WAN_MAC_ADDR, (void *)buffer);
	}
	else{
		char cmdBuf[128]={0}, orig_ip[32]={0}, orig_mask[32]={0};

		apmib_get(MIB_IP_ADDR, (void *)buffer); //get orig lan ip
		sprintf(orig_ip,"%s",inet_ntoa(*((struct in_addr *)buffer)));

		apmib_get(MIB_SUBNET_MASK, (void *)buffer); //get orig lan subnet
		sprintf(orig_mask,"%s",inet_ntoa(*((struct in_addr *)buffer)));

		sprintf(cmdBuf, "ifconfig br0 down;ifconfig br0 %s netmask %s up",orig_ip,orig_mask);
		CsteSystem(cmdBuf, CSTE_PRINT_CMD);

		if(operationMode==0){//gw
			opmode=GATEWAY_MODE;
			rpt_flag=0;
			intVal=DHCP_SERVER;
			apmib_set(MIB_DHCP, (void *)&intVal);
		}
		else{//bridge or repeater
			opmode=BRIDGE_MODE;	
			if(operationMode==2) rpt_flag=1;//repeater	
#if defined(CONFIG_ELINK_SUPPORT) || defined(CONFIG_KL_C8184R_04376)
			intVal=DHCP_CLIENT;
#else							
			intVal=DHCP_DISABLED;
#endif	
			intVal=DHCP_CLIENT;
			apmib_set(MIB_DHCP, (void *)&intVal);
		}
	}
	apmib_set(MIB_WAN_DHCP, (void *)&wan_type);//切换模式后，wan模式设置为dhcp
	
	apmib_set(MIB_OP_MODE, (void *)&opmode);
	
#if defined(CONFIG_SUPPORT_IPTV)
	int vlanEnabled = 0, repeater_enabled1 = 0, repeater_enabled2 = 0;
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&repeater_enabled1);
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&repeater_enabled2);
	if(!((opmode == BRIDGE_MODE)&&(repeater_enabled1 == 0)&&(repeater_enabled2 == 0))){
		apmib_set(MIB_IPTV_ENABLED, (void *)&vlanEnabled);
	}
#endif

	if(rpt_flag!=2){//gw or bridge or repeater
		if(rpt_flag==0){ 
			rpt_disabled=1;//gw or bridge 	
		}
		intVal=0;
		SetWlan_idx("wlan0-vxd");
		apmib_set(MIB_WLAN_WSC_DISABLE,(void *)&intVal);
		SetWlan_idx("wlan1-vxd");
		apmib_set(MIB_WLAN_WSC_DISABLE,(void *)&intVal);
	
		apmib_save_wlanIdx();
		wlan_idx=0;
		vwlan_idx=5;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&rpt_disabled);
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&rpt_flag);
#if defined (FOR_DUAL_BAND)
		wlan_idx=1;
		vwlan_idx=5;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&rpt_disabled);
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&rpt_flag);
#endif
		apmib_recov_wlanIdx();
	}

	if(operationMode<2){//gw	
		intVal=0;
		SetWlan_idx("wlan0-vxd");
		apmib_set(MIB_WLAN_WSC_DISABLE,(void *)&intVal);
		SetWlan_idx("wlan1-vxd");
		apmib_set(MIB_WLAN_WSC_DISABLE,(void *)&intVal);
#if defined (FOR_DUAL_BAND)
		system("ifconfig wlan0-vxd down;ifconfig wlan1-vxd down");
#else
		system("ifconfig wlan0-vxd down");
#endif
	}
#if defined(SUPPORT_MESH)
	intVal=0;
	SetWlan_idx("wlan0");
	apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&intVal);
	SetWlan_idx("wlan1");
	apmib_set(MIB_WLAN_MESH_ENABLE,(void *)&intVal);
	CsteSystem("rm /tmp/meshSlave -f",CSTE_PRINT_CMD);
#endif 
#if 1
#if defined(CONFIG_ELINK_SUPPORT)
	CsteSystem("csteSys watchdogCfgUpdate",CSTE_PRINT_CMD);
#endif	
	CsteSystem("csteSys csnl 2 -1",CSTE_PRINT_CMD);
	if(opmode==1)
	{
		CsteSystem("csteSys csnl 1 1",CSTE_PRINT_CMD);
	}
	else
	{
		CsteSystem("csteSys csnl 1 0",CSTE_PRINT_CMD);
	}
	sleep(1);
	CsteSystem("csteSys csnl 2 2",CSTE_PRINT_CMD);
#endif
	websSetCfgResponse(mosq, tp, "35", "reserv");

	pid=fork();
	if(0 == pid)
	{
		sleep(5);
		apmib_update_web(CURRENT_SETTING);
		run_init_script("all");
		exit(1);
	}
	
	__FUNC_OUT__
	return 0;
}
#endif

int getCmdResult(char *cmd, char *resultbuf, size_t buf_size)
{
	char *pchar = NULL;
	FILE *fp = popen(cmd, "r");
	if(!fp) 
		return -1;
	fgets(resultbuf, buf_size, fp);
	pclose(fp); 
	if(pchar = strstr(resultbuf, "\n"))
		*pchar = '\0';

	resultbuf[buf_size-1] = '\0';
	return 0;
}


int getSysStatusCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	cJSON *root=cJSON_CreateObject();
	bss_info bss;
	char buff[32]={0},tmpBuf[65]={0},cmd[128]={0};
	char authmode1[16]={0},authmode2[16]={0},authmode3[16]={0},enc1[8]={0},enc2[8]={0},enc3[8]={0};
	char ifname2g[8]={0},ifname2g_m1[16]={0},ifname2g_m2[16]={0},ifname2g_vxd[16]={0};
	char ifname5g[8]={0},ifname5g_m1[16]={0},ifname5g_m2[16]={0},ifname5g_vxd[16]={0};
	char br0addr[16]={0},br0mask[16]={0},hw[18]={0};
	int intVal=0,wifioff_24g=0,wifioff_5g=0;	
	int dbm=0,total_sta_num=0,total_va0_num=0,total_va1_num=0,total_mesh_num=0;
	int wlan_va0_off5g=0,wlan_va1_off5g=0;
	int wlan_va0_off24g=0,wlan_va1_off24g=0;
	int mesh5g_enabled=0,mesh2g_enabled=0,tmpMesh=0;
	int csteDevicePid=0;
	char buf[64]={0};
	FILE *fp;
	char filename[64]={0}, line_buffer[256], connect[32], cmdBuf[128] = {0}, tmpCount[128] = {0};
	char *pchar, *token;
	int cpuRate, memoryUseRate, memtotal, memfree, lanUserNum;
	unsigned int curConnectNum = 0;
	unsigned int maxconnectNum = 0;
	__FUNC_IN__
	
	sprintf(ifname5g,"%s","wlan0");
	sprintf(ifname5g_m1,"%s-va0",ifname5g);
	sprintf(ifname5g_m2,"%s-va1",ifname5g);
	sprintf(ifname5g_vxd,"%s-vxd",ifname5g);

#if defined (FOR_DUAL_BAND)	
	sprintf(ifname2g,"%s","wlan1");
#else
	sprintf(ifname2g,"%s","wlan0");
#endif
	sprintf(ifname2g_m1,"%s-va0",ifname2g);
	sprintf(ifname2g_m2,"%s-va1",ifname2g);
	sprintf(ifname2g_vxd,"%s-vxd",ifname2g);	

	//PortLinkStatus Info
#if defined(CONFIG_SUPPORT_PORTLINK_STATUS)
	cJSON_AddNumberToObject(root,"portlinkBt",1);
#else
	cJSON_AddNumberToObject(root,"portlinkBt",0);
#endif	

    //cpurate
    snprintf(filename, sizeof(filename), "/proc/cpuinfo");
    if((fp=fopen(filename, "r")) == NULL){
		cpuRate = 10;
    }
    while(fgets(line_buffer, sizeof(line_buffer), fp))
    {
        line_buffer[strlen(line_buffer)-1]='\0';
        if((pchar=strstr(line_buffer, "BogoMIPS"))!=NULL){
            pchar = strchr(line_buffer, ':');
            pchar+=1;
            cpuRate = atoi(pchar);
        }
    }
    fclose(fp);
	
	cJSON_AddNumberToObject(root,"cpuRatio",cpuRate);

	//memoryuserate
    snprintf(filename, sizeof(filename), "/proc/meminfo");
    if((fp=fopen(filename, "r")) == NULL){
        memoryUseRate = 10;
    }
    while(fgets(line_buffer, sizeof(line_buffer), fp))
    {
        line_buffer[strlen(line_buffer)-1]='\0';
        if((pchar=strstr(line_buffer, "MemTotal:"))!=NULL){
            pchar+=strlen("MemTotal:");
		    token = strtok(pchar, " ");
		    memtotal = atoi(token);
        }
        if((pchar=strstr(line_buffer, "MemFree:"))!=NULL){
            pchar+=strlen("MemFree:");
		    token = strtok(pchar, " ");
		    memfree = atoi(token);
		    break;
        }
    }
    memoryUseRate= 100-(memfree*100/memtotal);
    fclose(fp);
	cJSON_AddNumberToObject(root,"memRatio",memoryUseRate);

	if(fp = fopen("/proc/live_list", "r"))
	{
		fgets(line_buffer,sizeof(line_buffer),fp);
		fgets(line_buffer,sizeof(line_buffer),fp);
		while(fgets(line_buffer,sizeof(line_buffer),fp))
		{
			sscanf(line_buffer, "%*s %*s %*s %*s %s %*s %*lu %*lu %*s %*s %*s",connect);
			if(atoi(connect)!=0)
			{
				lanUserNum++;
			}
		}		
	}	
	else
	{
		lanUserNum = 1;
	}
	fclose(fp);
	cJSON_AddNumberToObject(root,"lanUserNum",lanUserNum);

	strcpy(cmdBuf,"cat /proc/sys/net/ipv4/netfilter/ip_conntrack_count");
	getCmdResult(cmdBuf, tmpCount, sizeof(tmpCount));
	curConnectNum += atoi(tmpCount);

	strcpy(cmdBuf,"cat /proc/sys/net/nf_conntrack_max");
	getCmdResult(cmdBuf, tmpCount, sizeof(tmpCount));
	maxconnectNum += atoi(tmpCount);
	cJSON_AddNumberToObject(root,"curConnectNum",curConnectNum);
	cJSON_AddNumberToObject(root,"maxconnectNum",maxconnectNum);
	cJSON_AddStringToObject(root,"portLinkStatus",getPortLinkStaus());

	//sysInfo
	cJSON_AddStringToObject(root,"upTime",getSysUptime());
	memset(tmpBuf, 0, sizeof(tmpBuf));
#if defined(SUPPORT_APAC)
	char SoftVer[32]={0};
	apmib_get(MIB_SOFTWARE_VERSION,(void *)SoftVer);
	sprintf(tmpBuf,"%s.%d",SoftVer,PRODUCT_SVN);
#else
	sprintf(tmpBuf,"%s.%d",PRODUCT_VER,PRODUCT_SVN);
#endif
	cJSON_AddStringToObject(root,"fmVersion",tmpBuf);

	apmib_get(MIB_CSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"productName",tmpBuf);	

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
#if defined (CONFIG_KL_C7187R_1200)
	memset(tmpBuf, 0, sizeof(tmpBuf));
	strcpy(tmpBuf, "1200");
#endif
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	//apmib_get(MIB_HW_PRODUCT_SN, (void *)tmpBuf);
	//cJSON_AddStringToObject(root,"snNumber",tmpBuf);

	sprintf(tmpBuf,"%s %s",PRODUCT_DATE,PRODUCT_TIME);
	cJSON_AddStringToObject(root,"buildTime",tmpBuf);
	
#if defined(SUPPORT_APAC)
	apmib_get(MIB_MULTI_LANGUAGE, (void *)tmpBuf);
	if(strlen(tmpBuf)==0)
		cJSON_AddStringToObject(root,"multiLangBt","cn;en");
	else
		cJSON_AddStringToObject(root,"multiLangBt",tmpBuf);
#else
#ifdef CONFIG_MULTI_LANG
	cJSON_AddNumberToObject(root,"multiLangBt",1);
#else
	cJSON_AddNumberToObject(root,"multiLangBt",0);
#endif		
#endif	

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"languageType",tmpBuf);

#if 1
	apmib_get(MIB_CUSTOMERURL,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"customerUrl",tmpBuf);
#else
	cJSON_AddStringToObject(root,"customerUrl","");
#endif

#if  defined(SUPPORT_APAC)
	apmib_get( MIB_APNAME,	(void *)tmpBuf);
	cJSON_AddStringToObject(root,"apName",tmpBuf);
	cJSON_AddStringToObject(root,"apAcBt","1");
#else
	cJSON_AddStringToObject(root,"apAcBt","0");
#endif

	//lanInfo
	getLanIp(tmpBuf);
	if(!getInAddr("br0", IP_ADDR_T, (void *)br0addr)){
		sprintf(br0addr,"0.0.0.0");
	}
	if(br0addr != "0.0.0.0" && br0addr != tmpBuf){
		cJSON_AddStringToObject(root,"lanIp",br0addr);
	}else{
		cJSON_AddStringToObject(root,"lanIp",tmpBuf);
	}
	
	getLanNetmask(tmpBuf);
	if(!getInAddr("br0", NET_MASK_T, (void *)&br0mask)){
		sprintf(br0mask,"0.0.0.0");
	}
	if(br0mask != "0.0.0.0" && br0mask != tmpBuf){
		cJSON_AddStringToObject(root,"lanMask",br0mask);
	}else{
		cJSON_AddStringToObject(root,"lanMask",tmpBuf);
	}
	cJSON_AddStringToObject(root,"lanMac",getLanMac());
	cJSON_AddNumberToObject(root,"dhcpServer",getDhcp());
		
	//wanInfo 
	get_wan_connect_status(tmpBuf);
	cJSON_AddStringToObject(root,"wanConnStatus",tmpBuf);
	
	apmib_get(MIB_WAN_DHCP, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wanMode",intVal);	
	if (intVal==DHCP_DISABLED){
		apmib_get(MIB_WAN_IP_ADDR,(void *)tmpBuf);
		cJSON_AddStringToObject(root,"wanIp",inet_ntoa(*((struct in_addr *)tmpBuf)));	

		apmib_get(MIB_WAN_SUBNET_MASK,(void *)tmpBuf);
		cJSON_AddStringToObject(root,"wanMask",inet_ntoa(*((struct in_addr *)tmpBuf)));
	
		apmib_get(MIB_WAN_DEFAULT_GATEWAY,(void *)tmpBuf);		
		cJSON_AddStringToObject(root,"wanGw",inet_ntoa(*((struct in_addr *)tmpBuf)));
	}
	else{
		getWanIp(tmpBuf);
		cJSON_AddStringToObject(root,"wanIp",tmpBuf);
		cJSON_AddStringToObject(root,"wanMask",getWanNetmask());
		cJSON_AddStringToObject(root,"wanGw",getWanGateway());
	}
	cJSON_AddStringToObject(root,"wanMac",getWanMac());
	
	apmib_get(MIB_DNS_MODE, (void *)&intVal);	
	if (intVal==DNS_MANUAL) {//Manual
		char *IPGetName2[]={"priDns","secDns"};
        int IPGetId2[]={MIB_DNS1,MIB_DNS2};
	    int arraylen=sizeof(IPGetName2)/sizeof(char *);
        getCfgArrayIP(root, arraylen, IPGetName2, IPGetId2);
	}else{
		cJSON_AddStringToObject(root,"priDns",getDns(1));
		cJSON_AddStringToObject(root,"secDns",getDns(2));
	}

	getWanLinktime(tmpBuf);
	cJSON_AddStringToObject(root,"wanConnTime",tmpBuf);

#if defined(FOR_DUAL_BAND)
	//5g wifi
	cJSON_AddNumberToObject(root,"wifiDualband",1);	//5G : 1 
	
	SetWlan_idx(ifname5g);
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh5g_enabled);

	getCmdStr("ifconfig | grep -v vxd |grep wlan0 | awk 'NR==1{print $1}'",tmpBuf,sizeof(tmpBuf));
	if(strcmp(tmpBuf,""))//enable
		wifioff_5g=0;
	else
		wifioff_5g=1;

	cJSON_AddNumberToObject(root,"wifiOff5g",wifioff_5g);

	if (wifioff_5g==0){	   
		cJSON_AddNumberToObject(root,"band5g",getWirelessBand(ifname5g));
		apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
		cJSON_AddNumberToObject(root,"channel5g",intVal);
		cJSON_AddNumberToObject(root,"autoChannel5g",getWirelessChannel(ifname5g));

		//5g wifi1
		getWlBssInfo(ifname5g, &bss);			
		memcpy(tmpBuf, bss.ssid, 32+1);	
		if(strlen(tmpBuf)==0){				
        	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf); 
		}
		cJSON_AddStringToObject(root,"ssid5g1",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey5g1",getWirelessKey(ifname5g));

		memset(hw,0,sizeof(hw));		
		getIfMac(ifname5g,hw);
	    cJSON_AddStringToObject(root,"bssid5g1",hw);
				
		sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname5g);
		if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
			if(strlen(tmpBuf))
				total_sta_num=atoi(tmpBuf);		
			else
				total_sta_num=0;
		}
		cJSON_AddNumberToObject(root,"staNum5g1",total_sta_num);
		
		//5g wifi2
		SetWlan_idx(ifname5g_m1);
		apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va0_off5g);
		cJSON_AddNumberToObject(root,"wifiOff5g2",wlan_va0_off5g);
		
		getWlBssInfo(ifname5g_m1, &bss);
		memcpy(tmpBuf, bss.ssid, 32+1);
		if(strlen(tmpBuf)==0){
        	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
		}			
		cJSON_AddStringToObject(root,"ssid5g2",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey5g2",getWirelessKey(ifname5g_m1));
	
		memset(hw,0,sizeof(hw));			
		getIfMac(ifname5g_m1,hw);
    	cJSON_AddStringToObject(root,"bssid5g2",hw);

		if(wlan_va0_off5g==0){
			sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname5g_m1);
			if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
				if(strlen(tmpBuf))
					total_va0_num=atoi(tmpBuf);		
				else
					total_va0_num=0;
			}
		}
		cJSON_AddNumberToObject(root,"staNum5g2",total_va0_num);
		
		//5g wifi3
		SetWlan_idx(ifname5g_m2);
		apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va1_off5g);
		cJSON_AddNumberToObject(root,"wifiOff5g3",wlan_va1_off5g);
		
		//5g wifi3
		getWlBssInfo(ifname5g_m2, &bss);
		memcpy(tmpBuf, bss.ssid, 32+1);
		if(strlen(tmpBuf)==0){
        	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
		}			
		cJSON_AddStringToObject(root,"ssid5g3",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey5g3",getWirelessKey(ifname5g_m2));
	
		memset(hw,0,sizeof(hw));
		getIfMac(ifname5g_m2,hw);
    	cJSON_AddStringToObject(root,"bssid5g3",hw);

		if(wlan_va1_off5g==0){
			sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname5g_m2);
			if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
				if(strlen(tmpBuf))
					total_va1_num=atoi(tmpBuf);		
				else
					total_va1_num=0;
			}
		}
		cJSON_AddNumberToObject(root,"staNum5g3",total_va1_num);
		cJSON_AddNumberToObject(root,"staNum5g",(total_sta_num+total_va0_num+total_va1_num));	

		//Security
		sprintf(authmode1,"%s",getAuthMode(ifname5g));
		sprintf(authmode2,"%s",getAuthMode(ifname5g_m1));
		sprintf(authmode3,"%s",getAuthMode(ifname5g_m2)); 	
		sprintf(tmpBuf,"%s;%s;%s",authmode1,authmode2,authmode3);
		cJSON_AddStringToObject(root,"authMode5g",tmpBuf);		
			
		sprintf(enc1,"%s",getEncrypType(ifname5g));
		sprintf(enc2,"%s",getEncrypType(ifname5g_m1));
		sprintf(enc3,"%s",getEncrypType(ifname5g_m2)); 
		sprintf(tmpBuf,"%s;%s;%s",enc1,enc2,enc3); 
		cJSON_AddStringToObject(root,"encrypType5g",tmpBuf);
		
		//RepeaterInfo
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);			
		cJSON_AddNumberToObject(root,"apcliEnable5g",intVal);
		
		if(intVal==1){
			getWlBssInfo(ifname5g_vxd, &bss);
			memcpy(tmpBuf, bss.ssid, 32+1);
			if(strlen(tmpBuf)==0){
        		SetWlan_idx(ifname5g_vxd);
        		apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
			}
			cJSON_AddStringToObject(root,"apcliSsid5g",tmpBuf);				
			getWlBssInfo(ifname5g_vxd,&bss);				
			sprintf(tmpBuf,"%02X:%02X:%02X:%02X:%02X:%02X",
				bss.bssid[0],bss.bssid[1],bss.bssid[2],
				bss.bssid[3],bss.bssid[4],bss.bssid[5]);
			cJSON_AddStringToObject(root,"apcliBssid5g",tmpBuf);				
			cJSON_AddStringToObject(root,"apcliAuthMode5g",getAuthMode(ifname5g_vxd));
			cJSON_AddStringToObject(root,"apcliEncrypType5g",getEncrypType(ifname5g_vxd));
			cJSON_AddStringToObject(root,"apcliKey5g",getWirelessKey(ifname5g_vxd));

			if(1==getRepeaterStatus(ifname5g_vxd))
				cJSON_AddStringToObject(root,"apcliStatus5g","success");
			else
				cJSON_AddStringToObject(root,"apcliStatus5g","fail");

			dbm=getRptStaAndRssi(ifname5g_vxd)-100;
			if(dbm>=-60)
				strcpy(tmpBuf,"high");
			else if(dbm>=-70)
				strcpy(tmpBuf,"medium");
			else if(dbm>=-80)
				strcpy(tmpBuf,"low");
			else
				strcpy(tmpBuf,"null");
			cJSON_AddStringToObject(root,"apcliSignal5g",tmpBuf);
		}
		else{
			cJSON_AddStringToObject(root,"apcliSsid5g","Extender");				
			cJSON_AddStringToObject(root,"apcliBssid5g","00:00:00:00:00:00");				
			cJSON_AddStringToObject(root,"apcliAuthMode5g","NONE");
			cJSON_AddStringToObject(root,"apcliEncrypType5g","NONE");
			cJSON_AddStringToObject(root,"apcliKey5g","");
			cJSON_AddStringToObject(root,"apcliStatus5g","fail");
			cJSON_AddStringToObject(root,"apcliSignal5g","null");
		}
	}
#else
	cJSON_AddNumberToObject(root,"wifiDualband",0);	//2.4G : 0 
#endif

	//2.4g wifi 
	SetWlan_idx(ifname2g);
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh2g_enabled);

	sprintf(cmd,"ifconfig | grep -v vxd |grep %s | awk 'NR==1{print $1}'",ifname2g);
	getCmdStr(cmd,tmpBuf,sizeof(tmpBuf));
	if(strcmp(tmpBuf,""))//enable
		wifioff_24g=0;
	else
		wifioff_24g=1;

	cJSON_AddNumberToObject(root,"wifiOff",wifioff_24g);

	if (wifioff_24g==0){	   
		cJSON_AddNumberToObject(root,"band",getWirelessBand(ifname2g));
		apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
		cJSON_AddNumberToObject(root,"channel",intVal);
		cJSON_AddNumberToObject(root,"autoChannel",getWirelessChannel(ifname2g));

		//2.4g wifi1
		getWlBssInfo(ifname2g, &bss);			
		memcpy(tmpBuf, bss.ssid, 32+1);			
		if(strlen(tmpBuf)==0){				
        	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
		}
		cJSON_AddStringToObject(root,"ssid1",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey1",getWirelessKey(ifname2g));
		
		memset(hw,0,sizeof(hw));		
		getIfMac(ifname2g,hw);
	    cJSON_AddStringToObject(root,"bssid1",hw);

		sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname2g);
		if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
			if(strlen(tmpBuf))
				total_sta_num=atoi(tmpBuf);		
			else
				total_sta_num=0;
		}
		cJSON_AddNumberToObject(root,"staNum1",total_sta_num);
		
		//2.4g wifi2
		SetWlan_idx(ifname2g_m1);
		apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va0_off24g);
		cJSON_AddNumberToObject(root,"wifiOff2",wlan_va0_off24g);
		
		getWlBssInfo(ifname2g_m1, &bss);
		memcpy(tmpBuf, bss.ssid, 32+1);
		if(strlen(tmpBuf)==0){
        	apmib_get(MIB_WLAN_SSID,(void *)tmpBuf);      
		}			
		cJSON_AddStringToObject(root,"ssid2",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey2",getWirelessKey(ifname2g_m1));
	
		memset(hw,0,sizeof(hw));			
		getIfMac(ifname2g_m1,hw);
    	cJSON_AddStringToObject(root,"bssid2",hw);

		if(wlan_va0_off24g==0){
			sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname2g_m1);
			if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
				if(strlen(tmpBuf))
					total_va0_num=atoi(tmpBuf);		
				else
					total_va0_num=0;
			}
		}
		cJSON_AddNumberToObject(root,"staNum2",total_va0_num);

		//2.4g wifi3		
		SetWlan_idx(ifname2g_m2);
		apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va1_off24g);
		cJSON_AddNumberToObject(root,"wifiOff3",wlan_va1_off24g);
		
		getWlBssInfo(ifname2g_m2, &bss);
		memcpy(tmpBuf, bss.ssid, 32+1);
		if(strlen(tmpBuf)==0){
        	apmib_get(MIB_WLAN_SSID,(void *)tmpBuf);      
		}			
		cJSON_AddStringToObject(root,"ssid3",tmpBuf);
		cJSON_AddStringToObject(root,"wifiKey3",getWirelessKey(ifname2g_m2));
	
		memset(hw,0,sizeof(hw));
		getIfMac(ifname2g_m2,hw);
    	cJSON_AddStringToObject(root,"bssid3",hw);

		if(wlan_va1_off24g==0){
			sprintf(cmd,"cat /proc/%s/sta_info | grep hwaddr | awk '{count++} END{print count}'",ifname2g_m2);
			if(!getCmdStr(cmd, tmpBuf, sizeof(tmpBuf))){
				if(strlen(tmpBuf))
					total_va1_num=atoi(tmpBuf);		
				else
					total_va1_num=0;
			}
		}
		cJSON_AddNumberToObject(root,"staNum3",total_va1_num);
		cJSON_AddNumberToObject(root,"staNum",(total_sta_num+total_va0_num+total_va1_num));		

		sprintf(authmode1,"%s",getAuthMode(ifname2g));
		sprintf(authmode2,"%s",getAuthMode(ifname2g_m1));
		sprintf(authmode3,"%s",getAuthMode(ifname2g_m2));
		sprintf(tmpBuf,"%s;%s;%s",authmode1,authmode2,authmode3);
		cJSON_AddStringToObject(root,"authMode",tmpBuf);
		
		sprintf(enc1,"%s",getEncrypType(ifname2g));
		sprintf(enc2,"%s",getEncrypType(ifname2g_m1));
		sprintf(enc3,"%s",getEncrypType(ifname2g_m2));
		sprintf(tmpBuf,"%s;%s;%s",enc1,enc2,enc3);			
		cJSON_AddStringToObject(root,"encrypType",tmpBuf);
		
		//RepeaterInfo
#if defined(FOR_DUAL_BAND)		
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);
#else
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);
#endif
		cJSON_AddNumberToObject(root,"apcliEnable",intVal);	
		if(intVal==1){
			getWlBssInfo(ifname2g_vxd, &bss);
			memcpy(tmpBuf, bss.ssid, 32+1);
			if(strlen(tmpBuf)==0){
        		SetWlan_idx(ifname2g_vxd);
        		apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
			}
			cJSON_AddStringToObject(root,"apcliSsid",tmpBuf);		
		
			getWlBssInfo(ifname2g_vxd, &bss);				
			sprintf(tmpBuf,"%02X:%02X:%02X:%02X:%02X:%02X",
				bss.bssid[0],bss.bssid[1],bss.bssid[2],
				bss.bssid[3],bss.bssid[4],bss.bssid[5]);
			cJSON_AddStringToObject(root,"apcliBssid",tmpBuf);
			cJSON_AddStringToObject(root,"apcliAuthMode",getAuthMode(ifname2g_vxd));
			cJSON_AddStringToObject(root,"apcliEncrypType",getEncrypType(ifname2g_vxd));
			cJSON_AddStringToObject(root,"apcliKey",getWirelessKey(ifname2g_vxd));

			if(1==getRepeaterStatus(ifname2g_vxd))
				cJSON_AddStringToObject(root,"apcliStatus","success");
			else
				cJSON_AddStringToObject(root,"apcliStatus","fail");

			dbm=getRptStaAndRssi(ifname2g_vxd)-100;
			if(dbm>=-60)
				strcpy(tmpBuf,"high");
			else if(dbm>=-70)
				strcpy(tmpBuf,"medium");
			else if(dbm>=-80)
				strcpy(tmpBuf,"low");
			else
				strcpy(tmpBuf,"null");
			cJSON_AddStringToObject(root,"apcliSignal",tmpBuf);
		}
		else{
			cJSON_AddStringToObject(root,"apcliSsid","Extender");				
			cJSON_AddStringToObject(root,"apcliBssid","00:00:00:00:00:00");				
			cJSON_AddStringToObject(root,"apcliAuthMode","NONE");
			cJSON_AddStringToObject(root,"apcliEncrypType","NONE");
			cJSON_AddStringToObject(root,"apcliKey","");
			cJSON_AddStringToObject(root,"apcliStatus","fail");
			cJSON_AddStringToObject(root,"apcliSignal","null");
		}
	}
	apmib_get(MIB_OP_MODE, (void *)&intVal);
#if defined(CONFIG_ELINK_SUPPORT)
	apmib_get(MIB_MESH_STYLE, (void *)&tmpMesh);
#endif
	if(mesh5g_enabled==1||mesh2g_enabled==1){//mesh mode
#if defined(SUPPORT_MESH)
#if defined(CONFIG_ELINK_SUPPORT)
		cJSON_AddNumberToObject(root,"meshStyle",tmpMesh);
		if(tmpMesh==2)
#else
		if(intVal==1)		
#endif		
			cJSON_AddNumberToObject(root,"operationMode",5);
		else	
#endif
		cJSON_AddNumberToObject(root,"operationMode",4);
	}else{
		if(intVal==2)
			intVal=3;
		cJSON_AddNumberToObject(root,"operationMode",intVal);
	}
	
	//StatisticsInfo
	char if_wan[16]={0};
	struct user_net_device_stats stats;

	//WAN statistics
	getWanIfNameCs(if_wan);
	if (getStats(if_wan, &stats) < 0){
		stats.tx_packets = 0;
		stats.rx_packets = 0;
	}
	cJSON_AddNumberToObject(root,"wanTx",(int)stats.tx_packets);
	cJSON_AddNumberToObject(root,"wanRx",(int)stats.rx_packets);

	//LAN statistics
	if (getStats("eth0", &stats) < 0){
		stats.tx_packets = 0;
		stats.rx_packets = 0;
	}
	cJSON_AddNumberToObject(root,"lanTx",(int)stats.tx_packets);
	cJSON_AddNumberToObject(root,"lanRx",(int)stats.rx_packets);	

	//WLAN statistics
#if defined(FOR_DUAL_BAND)
	if (getStats(ifname5g, &stats) < 0){
		stats.tx_packets = 0;
		stats.rx_packets = 0;
	}
	cJSON_AddNumberToObject(root,"wlanTx5g",stats.tx_packets);
	cJSON_AddNumberToObject(root,"wlanRx5g",stats.rx_packets);
	
	if (getStats(ifname2g, &stats) < 0){
		stats.tx_packets = 0;
		stats.rx_packets = 0;
	}
	cJSON_AddNumberToObject(root,"wlanTx",stats.tx_packets);
	cJSON_AddNumberToObject(root,"wlanRx",stats.rx_packets);
#else
	if (getStats(ifname2g, &stats) < 0){
		stats.tx_packets = 0;
		stats.rx_packets = 0;
	}
	cJSON_AddNumberToObject(root,"wlanTx",(int)stats.tx_packets);
	cJSON_AddNumberToObject(root,"wlanRx",(int)stats.rx_packets);
#endif		

	csteDevicePid=getCmdVal("cat /var/run/csteDrvierConnMachine.pid");
	sprintf(buf,"kill -SIGUSR1 %d &",csteDevicePid);
	system(buf);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
	return 0;
}

int getIfStat(const char *ifname, unsigned int *rxb, unsigned int *txb)
{
	FILE *info;
	char line[1024] = {0};
	char ifname_tmp[16] = {0};
	unsigned int rxb_tmp, txb_tmp;

	if ((info = fopen("/proc/net/dev", "r")) != NULL)
	{
		while (fgets(line, sizeof(line), info))
		{
			if (strchr(line, '|'))
				continue;

			if (sscanf(line, IF_SCAN_PATTERN, ifname_tmp, &rxb_tmp,&txb_tmp))
			{
				if (0 == strncmp(ifname_tmp, ifname, strlen(ifname)))
				{
					*rxb = rxb_tmp;
					*txb = txb_tmp;
					break;
				}
			}
		}

			fclose(info);
	}

}

int getNetInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	char *output;
	cJSON *root=cJSON_CreateObject();

	char br0addr[16]={0},tmpBuf[32]={0};
	int intVal;
	char  time_buf[32]={0};
	char if_wan[32]={0};
	char  up[32]={0};
	char  down[32]={0};	
	unsigned int rxb = 0;
	unsigned int txb = 0;
	unsigned int rxb1 = 0;
	unsigned int txb1 = 0;
	struct timeval tv;
	__FUNC_IN__
		
	apmib_get(MIB_WAN_DHCP, (void *)&intVal);
	cJSON_AddNumberToObject(root,"type",intVal);

	get_wan_connect_status(tmpBuf);
	if(strncmp("connected",tmpBuf,9)==0)
		cJSON_AddNumberToObject(root,"status",1);
	else if(strncmp("disconnected",tmpBuf,12)==0)
		cJSON_AddNumberToObject(root,"status",0);
	getWanIp(tmpBuf);
	cJSON_AddStringToObject(root,"ip",tmpBuf);
	
	cJSON_AddStringToObject(root,"gateway",getWanGateway());
	gettimeofday(&tv,NULL);
	sprintf(time_buf,"%u",tv.tv_sec);
	cJSON_AddStringToObject(root,"timestamp", time_buf);

    getWanIfNameCs(if_wan);
	getIfStat(if_wan, &rxb, &txb);
	sleep(1);
	getIfStat(if_wan, &rxb1, &txb1);
	sprintf(down,"%u",(rxb1-rxb)/1024);
	sprintf(up,"%u",(txb1 -txb)/1024);
	cJSON_AddStringToObject(root,"up",up);
	cJSON_AddStringToObject(root,"down",down);

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	
	__FUNC_OUT__
	return 0;
}

int getProtocolDataSta(unsigned int *tcp, unsigned int *udp)
{

	char cmdbuf[128] = {0},tmpcount[128] = {0};
	struct stat s;
	const char *ipc = stat("/proc/net/nf_conntrack", &s)
		? "/proc/net/ip_conntrack" : "/proc/net/nf_conntrack";

	sprintf(cmdbuf,"cat %s | grep -v TIME_WAIT | grep -v src=127.0.0.1 | grep -v dst=127.0.0.1 | grep bytes= | grep udp | wc -l ",ipc);
    getCmdResult(cmdbuf, tmpcount, sizeof(tmpcount));
	(*udp) += atoi(tmpcount);
	
	sprintf(cmdbuf,"cat %s | grep -v TIME_WAIT | grep -v src=127.0.0.1 | grep -v dst=127.0.0.1 | grep bytes= | grep tcp | wc -l ",ipc);
    getCmdResult(cmdbuf, tmpcount, sizeof(tmpcount));
	(*tcp) += atoi(tmpcount);

	return 0;
}

int getLinksData(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *fp = NULL;
	char line[512]={0},srcip[32]={0},upBytes_buf[32]={0},downBytes_buf[32]={0},uprate[32]={0},downrate[32]={0};
	unsigned long upBytes,downBytes;
	unsigned int tcp=0,udp=0;
	char tcp_buf[8]={0},udp_buf[8]={0};
	
	char *output = NULL;
	cJSON *root, *connEntry, *connArray, *connstatisc;
	root = cJSON_CreateObject();
	connArray = cJSON_CreateArray();
	
	if ((fp = fopen(LIVE_LIST, "r")) != NULL){
		fgets(line, sizeof(line), fp);
		fgets(line, sizeof(line), fp);
		while (fgets(line, sizeof(line), fp)){
			sscanf(line, "%s %*s %*s %*s %*s %*s %lu %lu %s %s %*s",srcip,&upBytes,&downBytes,uprate,downrate);
			connEntry = cJSON_CreateObject();
			cJSON_AddStringToObject(connEntry, "src", srcip);
			sprintf(downBytes_buf, "%.2lf", (double)downBytes);
			cJSON_AddStringToObject(connEntry, "count_download", downBytes_buf);
			sprintf(upBytes_buf, "%.2lf", (double)upBytes);
			cJSON_AddStringToObject(connEntry, "count_upload", upBytes_buf);
			cJSON_AddStringToObject(connEntry, "download", downrate);
			cJSON_AddStringToObject(connEntry, "upload", uprate);			
			getProtocolDataSta(&tcp, &udp);
			cJSON_AddItemToArray(connArray,connEntry);
		}
		fclose(fp);
	}
	cJSON_AddItemToObject(root,"connections",connArray);

	sprintf(tcp_buf, "%u", tcp);
	sprintf(udp_buf, "%u", udp);
	connstatisc=cJSON_CreateObject();
	cJSON_AddStringToObject(connstatisc,"tcp", tcp_buf);
	cJSON_AddStringToObject(connstatisc,"udp", udp_buf);
	cJSON_AddItemToObject(root,"statistics",connstatisc);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int setLanguageCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char cmd_buf[256]={0},buff[24];
	int pid=-1;
	__FUNC_IN__
	char *langAutoFlag = websGetVar(data, T("langAutoFlag"), T(""));
	apmib_set(MIB_LANG_FLAG,(void *)langAutoFlag);
	char *lang = websGetVar(data, T("lang"), T(""));

	apmib_get(MIB_LANGUAGE_TYPE, (void *)buff);
	if(strcmp(lang,"") && strcmp(lang,buff)){
		apmib_set(MIB_LANGUAGE_TYPE,(void *)lang);
#if defined(SUPPORT_CUSTOMIZATION)
		if(0 != f_exist("/mnt/custom/product.ini"))
		{
			memset(buff,0,sizeof(buff));
			sprintf(cmd_buf,"HelpUrl_%s",lang);
			inifile_get_string("/mnt/custom/product.ini","PRODUCT",cmd_buf,buff);
			apmib_set(MIB_CUSTOMERURL, buff);
		}
#endif
		pid=fork();
		if(pid==0){
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			exit(1);
		}
	}

	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
    return 0;
}

int getLanguageCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
    int intVal;
	char tmpBuf[32]={0};  
	__FUNC_IN__
	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());
	cJSON_AddNumberToObject(root,"loginFlag",loginflag);	
	loginflag=0;
#ifdef CONFIG_MULTI_LANG
	cJSON_AddNumberToObject(root,"multiLangBt",1);
#else
	cJSON_AddNumberToObject(root,"multiLangBt",0);
#endif

#ifdef CONFIG_SUPPORT_HELP
	cJSON_AddNumberToObject(root,"helpBt",1);
#else
	cJSON_AddNumberToObject(root,"helpBt",0);
#endif

	memset(tmpBuf, '\0', sizeof(tmpBuf));
#if defined(SUPPORT_APAC)
	char SoftVer[32]={0};
	apmib_get(MIB_SOFTWARE_VERSION,(void *)SoftVer);
	sprintf(tmpBuf,"%s.%d",SoftVer,PRODUCT_SVN);
#else
	sprintf(tmpBuf,"%s.%d",PRODUCT_VER,PRODUCT_SVN);
#endif
	cJSON_AddStringToObject(root,"fmVersion",tmpBuf);

	apmib_get(MIB_WEB_TITLE,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"title",tmpBuf);

	memset(tmpBuf, '\0', sizeof(tmpBuf));
	apmib_getDef(MIB_USER_NAME, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"defaultName",tmpBuf);

	apmib_getDef(MIB_USER_PASSWORD, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"defaultPassword",tmpBuf);
	
	memset(tmpBuf, '\0', sizeof(tmpBuf));

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"languageType",tmpBuf);
#if defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)
	sprintf(tmpBuf,"%s","www.szeasycore.com");
#else
	if (!strcmp(tmpBuf,"cn")){
		sprintf(tmpBuf,"%s","www.totolink.cn");
	}else if(!strcmp(tmpBuf,"ct")){
		sprintf(tmpBuf,"%s","www.totolink.tw");
	}else{
		sprintf(tmpBuf,"%s","www.totolink.net");	
	}
#endif
	cJSON_AddStringToObject(root,"helpUrl",tmpBuf);

#if defined(CONFIG_APP_STORAGE)
	cJSON_AddNumberToObject(root,"usbFlag",getCmdVal("cat /tmp/usbFlag")); 
#else
	cJSON_AddNumberToObject(root,"usbFlag",0);	
#endif
	
	apmib_get(MIB_HARDWARE_MODEL, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"productName",tmpBuf);

	if(getIfIp("br0",tmpBuf) == -1){
		getLanIp(tmpBuf);
	}
	cJSON_AddStringToObject(root,"lanIp",tmpBuf);

	get_wan_connect_status(tmpBuf);
	cJSON_AddStringToObject(root,"wanConnStatus",tmpBuf);

#if defined(SUPPORT_APAC)	
	if(f_exist("/tmp/cloudFwStatus")){
		getCmdStr("cat /tmp/cloudFwStatus",tmpBuf,sizeof(tmpBuf));
		cJSON_AddStringToObject(root,"cloudFwStatus",tmpBuf);		
	}
	
	if(f_exist("/tmp/NewVersion")){
		getCmdStr("cat /tmp/NewVersion",tmpBuf,sizeof(tmpBuf));
		cJSON_AddStringToObject(root,"new_version",tmpBuf);		
	}
#endif	

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
#if defined (CONFIG_KL_C7187R_1200)
	memset(tmpBuf, 0, sizeof(tmpBuf));
	strcpy(tmpBuf, "1200");
#endif
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	apmib_get(MIB_USER_NAME,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"loginUser",tmpBuf);
	
	apmib_get(MIB_USER_PASSWORD,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"loginPass",tmpBuf);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
	__FUNC_OUT__
    return 0;
}

char hextochar( char ch1, char ch2 )//只针对两位情形
{
	int tmp = 0;
	if(ch1 == 'A') tmp += 16*10;
	if(ch1 == 'B') tmp += 16*11;
	if(ch1 == 'C') tmp += 16*12;
	if(ch1 == 'D') tmp += 16*13;
	if(ch1 == 'E') tmp += 16*14; 
	if(ch1 == 'F') tmp += 16*15; 
	if(48 <= ch1 && ch1 <= 57) tmp += (ch1 - 48)*16;
	
	if(ch2 == 'A') tmp += 10;
	if(ch2 == 'B') tmp += 11;
	if(ch2 == 'C') tmp += 12;
	if(ch2 == 'D') tmp += 13; 
	if(ch2 == 'E') tmp += 14;
	if(ch2 == 'F') tmp += 15;
	if(48 <= ch2 && ch2 <= 57) tmp += (ch2 - 48);
	
	return (char)tmp;
}

int passwordTrans(char* oldPassword, char* newPassword)
{
	int i = 0, j = 0;
	char ch;
	while(oldPassword[i] != '\0'){
		if(oldPassword[i] == '%'){
			ch = hextochar(oldPassword[i+1], oldPassword[i+2]);
			newPassword[j] = ch;
			i += 3;
			++j;
		}else{
			newPassword[j++] = oldPassword[i++];
		}
	}
	newPassword[j] = '\0';
	return 0;
}
#if defined(CONFIG_APP_CLOUDSRVUP)
int getCloudCheckTime()
{
	unsigned long sec, sec2;
	struct sysinfo info ;
	FILE *f;
	char buf[256];

	sysinfo(&info);
	sec = (unsigned long) info.uptime ;  //current  time
	//day -= 10957; // day counted from 1970-2000

	f = fopen("/var/CloudCheckTime", "r");
	if (f == NULL ){
		printf("open file error\n");
		return 0;
	}

	fread(buf, 1,  255, f);	
	if (buf[0] != '0'){
		sec2 = atoi(strtok(buf, " "));			
		sec = sec-sec2;			
	}
	else{
		sec = 0; 
	}
	fclose(f);
	return sec;
}
#endif
int loginAuth(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int m=0, len=0;
	int passwordLen=0;
	int wzd_flag=0;
	int opmode=0, authCode=0,intVal=0;
	char  goURL[128]={0};
    char recs[1024]={0},authKey[128]={0},authKeyVal[256]={0};
    char mib_user[33]={0}, mib_pass[33]={0};
    char serIp[256]={0},wanIp[16]={0};
    char responseStr[CSTEBUFSIZE]={0};
	char tmpBuf[32]={0};
    cJSON *loginAuthData;
    char *loginAuthURL = websGetVar(data, T("loginAuthUrl"), T(""));
	char newPassword[33];
	
    loginAuthData=cJSON_CreateObject();
    while(getNthValueSafe(m++, loginAuthURL, '&', recs, sizeof(recs)) != -1){
		if((getNthValueSafe(0, recs, '=', authKey, sizeof(authKey)) == -1)){
			continue;
		}
		if((getNthValueSafe(1, recs, '=', authKeyVal, sizeof(authKeyVal)) == -1)){
			continue;
		}	
		cJSON_AddStringToObject(loginAuthData,authKey,authKeyVal);
	}
    
    char *username = websGetVar(loginAuthData, T("username"), T(""));
	char *password = websGetVar(loginAuthData, T("password"), T(""));
	char *http_host= websGetVar(loginAuthData, T("http_host"), T(""));
	char *flag = websGetVar(loginAuthData, T("flag"), T(""));
    apmib_get(MIB_USER_NAME, (void *)mib_user);
    apmib_get(MIB_USER_PASSWORD, (void *)mib_pass);    
    apmib_get(MIB_OP_MODE, (void *)&opmode);
	//apmib_get(MIB_WIZARD_FLAG, (void *)&wzd_flag);
	if(strlen(http_host)>0){
		strcpy(serIp,http_host);
	}else{
		getLanIp(serIp);
	}

	if ( strlen(username)==0 || strlen(password)==0 ) {
		loginflag=1;
	}
	else{
		if (strcmp(username, mib_user)) {
			loginflag=1;
		}
		passwordTrans(password, newPassword);
		if (strcmp(newPassword, mib_pass)) {
			loginflag=1;
		}
	}
	
    if((!strcmp(username, mib_user) && !strcmp(newPassword, mib_pass))) {	
		loginflag=0;
		if(opmode==GATEWAY_MODE){
			if (atoi(flag)==1){
				strcpy(goURL,"mobile/home.html");
			}else{
				strcpy(goURL,"home.html");
			}
		}else if(opmode==WISP_MODE){
			strcpy(goURL,"home.html");
		}else{
			if (atoi(flag)==1){
				strcpy(goURL,"mobile/home.html");
			}else{
				strcpy(goURL,"home.html");
			}
		}

#if defined(CONFIG_APP_CLOUDSRVUP)
		int Timeout=getCloudCheckTime();
		if(Timeout==0 || Timeout > 3600){
			CsteSystem("killall cs_cloudfwcheck 1>/dev/null 2>&1", CSTE_PRINT_CMD);
			CsteSystem("/bin/cs_cloudfwcheck 1 &", CSTE_PRINT_CMD);
		}
#endif	
		authCode=1;
    }
    else{//login faild
		if (atoi(flag)==1){
        	strcpy(goURL,"mobile/login.html");
		}
		else{	
			strcpy(goURL,"login.html");
        }
		authCode=0;
    }

    snprintf((responseStr + len), (sizeof(responseStr) - len), "{\"httpStatus\":\"%s\",\"host\":\"%s\"","302",serIp);
	len = strlen(responseStr);
	if (atoi(flag)==1){
	    snprintf((responseStr + len),(sizeof(responseStr) - len),\
			",\"redirectURL\":\"http://%s/formLoginAuth.htm?authCode=%d&userName=%s&password=%s&goURL=%s&action=login&flag=1\"}"\
			,serIp,authCode,username,newPassword,goURL);	
	}
	else{
		snprintf((responseStr + len),(sizeof(responseStr) - len),\
			",\"redirectURL\":\"http://%s/formLoginAuth.htm?authCode=%d&userName=%s&password=%s&goURL=%s&action=login\"}"\
			,serIp,authCode,username,newPassword,goURL);
	}
	len = strlen(responseStr);
	
	websGetCfgResponse(mosq,tp,responseStr);
	return 0;
}

int getWanAutoDetect(struct mosquitto *mosq, cJSON* data, char *tp)	
{
	int ret,intVal=0;
	char tmpbuf[16]={0},retBuf[256]={0};
	char ip[16]={0},mask[16]={0},gw[16]={0},dns1[16]={0},dns2[16]={0};
	char wanStatus[16]={0};

	get_wan_connect_status(wanStatus);

	CsteSystem("disconnect.sh all",CSTE_PRINT_CMD);
	//1.get eth1 link status
	ret=get_wan_link_status("eth1");
	if (ret < 0) {//link down
		intVal = 0;
	}else{//2.discovery PPP mode
		CsteSystem("pppoe-discovery -I eth1", CSTE_PRINT_CMD);
		f_read("/tmp/pppoedetect", tmpbuf, 0, sizeof(tmpbuf));
		if ( strstr(tmpbuf, "success") ){
			printf("Is ppp mode!!\n");
			intVal = 1;
		}else{//3.discovery Dhcp mode
			CsteSystem("udhcpc-discovery -i eth1", CSTE_PRINT_CMD);
			f_read("/tmp/udhcpcdetect", tmpbuf, 0, sizeof(tmpbuf));
			if ( strstr(tmpbuf, "success") ){
				printf("Is dhcp mode!!\n");			
				intVal = 2;
				getCmdStr("cat /tmp/udhcpcinfo | grep client_ip | cut -f2 -d \"=\"", ip, sizeof(ip));	
				getCmdStr("cat /tmp/udhcpcinfo | grep server_ip | cut -f2 -d \"=\"", gw, sizeof(gw));	
				getCmdStr("cat /tmp/udhcpcinfo | grep server_subnet | cut -f2 -d \"=\"", mask, sizeof(mask));	
				//getCmdStr("cat /tmp/udhcpcinfo | grep server_dns1 | cut -f2 -d \"=\"", dns1, sizeof(dns1));
				//getCmdStr("cat /tmp/udhcpcinfo | grep server_dns2 | cut -f2 -d \"=\"", dns2, sizeof(dns2));
			}else{
				intVal = 3;
				printf("Is static mode!!\n");
			}
		}
	}
	if(intVal==2){
		sprintf(retBuf, "{\"wanDetectResult\":\"%d\",\"wanConnStatus\":\"%s\",\"newWanIp\":\"%s\",\"newWanMask\":\"%s\",\"newWanGW\":\"%s\",\"newWanDns1\":\"%s\",\"newWanDns2\":\"%s\"}", 
			intVal,wanStatus,ip,mask,gw,gw,gw);
	}else{
		sprintf(retBuf, "{\"wanDetectResult\":\"%d\",\"wanConnStatus\":\"%s\"}",intVal,wanStatus);
	}
	websGetCfgResponse(mosq,tp,retBuf);
	return 0;
}

int getLedStatus(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	char tmpbuf[32]={0};
	__FUNC_IN__
		
	static time_t old_time = 0;
	time_t now_time = time(NULL);

	//it is better to use file lock, but now, I let it in this way.
	//lighttpd will read this file to check IP_Login_Limit, see cookie.c in lighttpd
	sprintf(tmpbuf, "echo \"%ld\" > /tmp/getLedTime", now_time);
	system(tmpbuf);
	
	cJSON_AddStringToObject(root,"ethLinkStatus",getPortLinkStaus());

#if defined(CONFIG_APP_STORAGE)	
	cJSON_AddNumberToObject(root,"usbFlag",getCmdVal("cat /tmp/usbFlag"));
#else
	cJSON_AddNumberToObject(root,"usbFlag",0);
#endif

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	__FUNC_OUT__
	return 0;
}

int setWanDnsConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char_t  *dns_mode,*pd, *sd;
	struct in_addr dns1, dns2;
	struct in_addr dns1_old, dns2_old;
	int ret=0, curDnsMode=0, iDnsMode=0;

    apmib_get(MIB_DNS_MODE,  (void *)&iDnsMode);
    apmib_get(MIB_DNS1, (void *)&dns1_old);
    apmib_get(MIB_DNS2, (void *)&dns2_old);
	dns_mode = websGetVar(data, T("dnsMode"), T("0"));
	curDnsMode = atoi(dns_mode);
	if(iDnsMode != curDnsMode)
	    ret=1;
	    
	apmib_set(MIB_DNS_MODE,  (void *)&curDnsMode);
	if (!strcmp(dns_mode, "1")) {
		pd = websGetVar(data, T("priDns"), T("0.0.0.0"));
		sd = websGetVar(data, T("secDns"), T("0.0.0.0"));
		if( !inet_aton(pd, &dns1) ) {
            return -1;
		}
        apmib_set(MIB_DNS1, (void *)&dns1);
        
        if( !inet_aton(sd, &dns2) ){
            return -1;
        }
        apmib_set(MIB_DNS2, (void *)&dns2);
        if ( *((long *)&dns1) != *((long *)&dns1_old) ||*((long *)&dns2) != *((long *)&dns2_old))
            ret = 1;
	}
	return ret;
}

#if defined(SUPPORT_CPE)
#define GUEST_SSID "TOTOLINK-manage"
#define GUEST_KEY  "totolinkos"

int switchToGuestSsid(char *apcli_name,char *apclibssid)
{
	int  tmp_mac[6] = {0};
	unsigned char  mac_str[32] = {0};
	char manage_ssid[64] = {0};
	unsigned char tmp_mac0 = 0;
	char buf[128] = {0};
	
	if(NULL == apcli_name || NULL == apclibssid)
	{
		return -1;
	}
	sscanf(apclibssid,"%2x:%2x:%2x:%2x:%2x:%2x",&tmp_mac[0],&tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
	
	/*guest bssid*/
	tmp_mac0 = tmp_mac[0] + 6;
	sprintf(mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",tmp_mac[0],tmp_mac[1],tmp_mac[2],tmp_mac[3],tmp_mac[4],tmp_mac[5]);

	sprintf(manage_ssid,"%s_%02x%02x",GUEST_SSID,tmp_mac[4],tmp_mac[5]);
	/*first backup wireless config*/

	SetWlan_idx(apcli_name);
	if(!strcmp(apcli_name, "wlan0-vxd")){
		apmib_set(MIB_REPEATER_SSID1,(void *)manage_ssid);
	}else if(!strcmp(apcli_name, "wlan1-vxd")){
		apmib_set(MIB_REPEATER_SSID2,(void *)manage_ssid);
	}
	apmib_set(MIB_WLAN_SSID, (void *)manage_ssid); 
	apmib_set(MIB_WLAN_WSC_SSID, (void *)manage_ssid);
	apmib_set(MIB_ROOTAP_MAC, (void *)mac_str);

	int wep=WEP_DISABLED;
	int auth_wpa=WPA_AUTH_PSK;
	int encrypt=ENCRYPT_WPA2;
	int ciphersuite2 = WPA_CIPHER_AES,ciphersuite1=WPA_CIPHER_AES;
	int pskformat=1;
	sprintf(buf,"%s",GUEST_KEY);
	apmib_set( MIB_WLAN_WEP, (void *)&wep);
	apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
	apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
	apmib_set( MIB_WLAN_WPA_PSK, (void *)buf);		
	apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	apmib_set( MIB_WLAN_WSC_ENC, (void *)&encrypt);	
	apmib_set( MIB_WLAN_WSC_AUTH, (void *)&auth_wpa);
	apmib_set( MIB_WLAN_WSC_PSK, (void *)buf);

	CsteSystem("killall onekey_conn;onekey_conn &", CSTE_PRINT_CMD);
		
}
#endif

#if defined(SUPPORT_CPE)
int sys_opmode(int mode)
{
	int opmode=0,tmpint=0,dhcp_enabled=0,countryflag=0,iReg;
	char tmpStr[32] = {0},wlan_if[16]={0},wlanvxd_if[16]={0};
	if(mode==3)
	{
		opmode=WISP_MODE;
		dhcp_enabled=2;
		countryflag=1;
		
		apmib_save_wlanIdx();
		tmpint=0;
		apmib_set(MIB_WISP_WAN_ID, (void *)&tmpint);
		
		tmpint=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&tmpint);
		tmpint=0;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&tmpint);
		SetWlan_idx("wlan0");
		tmpint = AP_MODE;
		apmib_set( MIB_WLAN_MODE, (void *)&tmpint);
		
		SetWlan_idx("wlan0-vxd");
		tmpint = CLIENT_MODE;
		apmib_set( MIB_WLAN_MODE, (void *)&tmpint);
		tmpint=0;
		apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&tmpint);

		apmib_recov_wlanIdx();
	}
	//Repeater Mode
	else if(mode==2)
	{
		opmode=BRIDGE_MODE;
		dhcp_enabled=0;
		countryflag=1;
		tmpint=0;
		apmib_set(MIB_WISP_WAN_ID, (void *)&tmpint);
			
		apmib_save_wlanIdx();
		wlan_idx=0;
		vwlan_idx=5;
		tmpint=0;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&tmpint);
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&tmpint);

		tmpint=1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&tmpint);
		SetWlan_idx("wlan0");
		tmpint = AP_MODE;
		apmib_set( MIB_WLAN_MODE, (void *)&tmpint);
		
		SetWlan_idx("wlan0-vxd");
		tmpint = CLIENT_MODE;
		apmib_set( MIB_WLAN_MODE, (void *)&tmpint); 
		apmib_recov_wlanIdx();		
	}
	//Bridge Mode
	else// if(ui_opmode==0)
	{
		opmode=BRIDGE_MODE;
		dhcp_enabled=0;
		countryflag=0;
		
		apmib_save_wlanIdx();
		wlan_idx=0;
		vwlan_idx=5;
		tmpint=0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&tmpint);
		tmpint=1;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&tmpint);
		SetWlan_idx("wlan0");
		tmpint = AP_MODE;
		apmib_set( MIB_WLAN_MODE, (void *)&tmpint);
		
		apmib_recov_wlanIdx();	
	}	

	apmib_set(MIB_OP_MODE, (void *)&opmode);
	apmib_set(MIB_DHCP, (void *)&dhcp_enabled);
	
	SetWlan_idx("wlan0");
	if(countryflag==1){
	//	apmib_set(MIB_WLAN_COUNTRY_STRING, "OT");
		iReg=16;
	}else{
		char tmpbuf[10]="IN";
	//	apmib_get(MIB_WLAN_ASSIST_COUNTRY_STRING,(void *)tmpbuf);
		apmib_get(MIB_WLAN_COUNTRY_STRING,(void *)tmpbuf);
		if(!strcmp("US",tmpbuf)){
			iReg=FCC;
		}else if(!strcmp("EU",tmpbuf)){
			iReg=ETSI;
		}else if(!strcmp("OT",tmpbuf)){
			iReg=16;
		}else if(!strcmp("IN",tmpbuf)){
			iReg=CN;
		}else{
			iReg=CN;
		}
	}
	if ( apmib_set(MIB_HW_REG_DOMAIN, (void *)&iReg) == 0) {
		CSTE_DEBUG("Set wlan regdomain error!\n");
	}
	
	sprintf(tmpStr,"csteSys csnl 1 %d",opmode);
	system(tmpStr);
	
	system("csteSys csnl 2 -1");
	sleep(1);
	
	if(mode==2||mode==3)	
		system("csteSys csnl 2 1");
	else	
		system("csteSys csnl 2 2");
	return 0;
}

int setSysModeCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int OperationMode,WiFiIdx,iReg,pid;
	int encrypt=0,auth_wpa=0,wep=WEP_DISABLED,pskformat;
	int ciphersuite1=WPA_CIPHER_AES,ciphersuite2=WPA_CIPHER_AES;
	char wlan_if[32]={0},wlanvxd_if[32]={0},tmpBuf[64]={0},buff[64]={0},ApCliwpakey[64]={0};
	char *ssid,*channel,*authmode,*encryptype,*wpakey,*countryCode,*keytype;
	char *ssid5g,*channel5g,*authmode5g,*encryptype5g,*wpakey5g,*keytype5g;
	int channelTmp=0;
	OperationMode=atoi(websGetVar(data,T("operationMode"),T("0")));
	WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	sys_opmode(OperationMode);

	char *apcli_ssid,*apcli_bssid,*apcli_channel,*apcli_authmode;
	char *apcli_encryptype,*apcli_keytype,*apcli_wepkey,*apcli_wpakey;
	int iChannel;
	apcli_ssid = websGetVar(data, T("apcliSsid"), T(""));
	apcli_bssid = websGetVar(data, T("apcliBssid"), T(""));
	apcli_channel = websGetVar(data, T("apcliChannel"), T(""));
	apcli_authmode = websGetVar(data, T("apcliAuthMode"), T("NONE"));
	apcli_encryptype = websGetVar(data, T("apcliEncrypType"), T(""));
	apcli_keytype = websGetVar(data, T("apcliKeyType"), T("1"));
	apcli_wepkey = websGetVar(data, T("apcliKeyStr"), T(""));  
	apcli_wpakey = websGetVar(data, T("apcliKey"), T(""));

	SetWlan_idx(wlan_if);//wlan
	iChannel=atoi(apcli_channel);
	apmib_set(MIB_WLAN_CHANNEL,(void *)&iChannel);

	SetWlan_idx(wlanvxd_if);//wlan
	apmib_set(MIB_WLAN_SSID, (void *)apcli_ssid); 
	apmib_set(MIB_WLAN_WSC_SSID, (void *)apcli_ssid);
	apmib_set(MIB_REPEATER_SSID1, (void *)apcli_ssid);
	
	apmib_set(MIB_ROOTAP_MAC, (void *)apcli_bssid);

	checkVar(apcli_wpakey,1,ApCliwpakey);

	if(!strncmp(apcli_authmode, "WPAPSK", 7)||!strncmp(apcli_authmode, "WPA2PSK", 8)||!strncmp(apcli_authmode, "WPAPSKWPA2PSK", 14)){//WPA-PSK
		int ciphersuite1 = WPA_CIPHER_AES, ciphersuite2 = WPA_CIPHER_AES;
	    int pskformat    = atoi(apcli_keytype)==0?1:0;//RTL 0:ASCII 1:HEX MTK 0:Hex 1:ASCII
	    int wpakey_len   = strlen(ApCliwpakey);
        char key_hex[65] = {0};
		auth_wpa=WPA_AUTH_PSK;	

		if(!strncmp(apcli_authmode, "WPAPSK", 7)){
			encrypt = ENCRYPT_WPA;
            if(!strncmp(apcli_encryptype, "TKIP", 5))
                ciphersuite1 = WPA_CIPHER_TKIP;
            else
                ciphersuite1 = WPA_CIPHER_AES;
		}else if(!strncmp(apcli_authmode, "WPA2PSK", 8)){
            encrypt=ENCRYPT_WPA2;
            if(!strncmp(apcli_encryptype, "TKIP", 5))
                ciphersuite2 = WPA_CIPHER_TKIP;
            else if(!strncmp(apcli_encryptype, "AES", 4))
                ciphersuite2 = WPA_CIPHER_AES;
            else
                ciphersuite2 = WPA_CIPHER_MIXED;
        }else if(!strncmp(apcli_authmode, "WPAPSKWPA2PSK", 14)){
            encrypt=ENCRYPT_WPA2_MIXED;
            if(!strncmp(apcli_encryptype, "TKIP", 5)){
				ciphersuite1 = WPA_CIPHER_TKIP;
                ciphersuite2 = WPA_CIPHER_TKIP;
            }else if(!strncmp(apcli_encryptype, "AES", 4)){
				ciphersuite1 = WPA_CIPHER_AES;
                ciphersuite2 = WPA_CIPHER_AES;
            }else{
				ciphersuite1 = WPA_CIPHER_MIXED;
                ciphersuite2 = WPA_CIPHER_MIXED;
            }
        }else{
            encrypt=ENCRYPT_WPA2;
        }
		
		if(pskformat==1){//Hex
			if(wpakey_len != MAX_PSK_LEN && !string_to_hex(wpakey, key_hex, MAX_PSK_LEN)){
				websErrorResponse(mosq, tp,"JS_msg25");
				return 0;
			}
		}else{
			if(wpakey_len==0 || wpakey_len > (MAX_PSK_LEN-1)|| wpakey_len < MIN_PSK_LEN){
				websErrorResponse(mosq, tp,"JS_msg24");
				return 0;
			}
		}

        apmib_set( MIB_WLAN_WEP, (void *)&wep);
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
        apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
        apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
        apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
        apmib_set( MIB_WLAN_WPA_PSK, (void *)ApCliwpakey);		
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
		apmib_set( MIB_WLAN_WSC_ENC, (void *)&encrypt);	
		apmib_set( MIB_WLAN_WSC_AUTH, (void *)&auth_wpa);
		apmib_set( MIB_WLAN_WSC_PSK, (void *)ApCliwpakey);	
	}
	else{//NONE
		encrypt=ENCRYPT_DISABLED;
		auth_wpa=WPA_AUTH_AUTO;
        apmib_set( MIB_WLAN_WEP, (void *)&wep);
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);		
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
		apmib_set( MIB_WLAN_WSC_ENC, (void *)&encrypt);	
		apmib_set( MIB_WLAN_WSC_AUTH, (void *)&auth_wpa);
	}

	pid=fork();
	if(0==pid){
		sleep(5);
		apmib_update_web(CURRENT_SETTING);
		 //生效配置
	    sprintf(buff, "echo conneting > /tmp/.%s_flag", wlanvxd_if);
	    CsteSystem(buff, CSTE_PRINT_CMD);
	//    CsteSystem("init.sh gw all", CSTE_PRINT_CMD);
		run_init_script("all");
		exit(1);
	}
	
    websSetCfgResponse(mosq, tp, "50", "reserv");

	return 0;							
}

int setEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{		
	char wlanvxd_if[16]={0}, buff[64]={0};
	int encrypt, auth_wpa=WPA_AUTH_PSK, ciphersuite=WPA_CIPHER_MIXED, pskformat=KEY_ASCII;

	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sys_opmode(2);//repeater mode
	apmib_set( MIB_WISP_WAN_ID, (void *)&WiFiIdx);	

	//wifi
	char_t	*ssid = websGetVar(data, T("ssid"), T(""));
	char_t	*authmode = websGetVar(data, T("authMode"), T("NONE"));
	char_t	*wpakey = websGetVar(data, T("wpakey"), T("")); 	

	SetWlan_idx("wlan0");//wlan0
	apmib_set(MIB_WLAN_SSID,(void *)ssid);	
	if(!strcmp(authmode,"NONE")){
		encrypt = ENCRYPT_DISABLED;
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);		
	}else{
		encrypt = ENCRYPT_WPA2_MIXED;
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);		
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
        apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
        apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite);
        apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite);
        apmib_set( MIB_WLAN_WPA_PSK, (void *)wpakey);
	}

	//repeater
	int apcli_channel = atoi(websGetVar(data, T("apcliChannel"), T("")));
	char_t	*apcli_ssid = websGetVar(data, T("apcliSsid"), T(""));
	char_t	*apcli_bssid = websGetVar(data, T("apcliBssid"), T(""));	
	char_t	*apcli_authmode = websGetVar(data, T("apcliAuthMode"), T("NONE"));
	char_t	*apcli_encryptype = websGetVar(data, T("apcliEncrypType"), T(""));
	char_t	*apcli_wpakey = websGetVar(data, T("apcliKey"), T(""));
	int val = 0;

	SetWlan_idx("wlan0");//wlan0
	apmib_set( MIB_WLAN_CHANNEL,  (void *)&apcli_channel);
	apmib_set(MIB_REPEATER_SSID1, (void *)apcli_ssid);
	val = 1;
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&val);
	val = 0;
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&val);

	sprintf(wlanvxd_if,"wlan0-vxd");
	SetWlan_idx(wlanvxd_if);
	apmib_set(MIB_WLAN_SSID, (void *)apcli_ssid); 
	
	apmib_set(MIB_ROOTAP_MAC, (void *)apcli_bssid);

	if(!strcmp(apcli_authmode, "NONE")){
		encrypt=ENCRYPT_DISABLED;
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);		
	}
	else{
		if(!strcmp(apcli_authmode, "WPAPSK")){
			encrypt = ENCRYPT_WPA;
		}else{
            encrypt = ENCRYPT_WPA2;
        }

		if(!strcmp(apcli_encryptype, "TKIP")){
       		ciphersuite = WPA_CIPHER_TKIP;
       	}else{
        	ciphersuite = WPA_CIPHER_AES;
       	}
		
        apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
        apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
        apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite);
        apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite);
        apmib_set( MIB_WLAN_WPA_PSK, (void *)apcli_wpakey);		

		switchToGuestSsid(wlanvxd_if,apcli_bssid);
	}

	int pid=fork();
	if(0 == pid)
	{
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		 //生效配置
	    sprintf(buff, "echo conneting > /tmp/.%s_flag", wlanvxd_if);
	    CsteSystem(buff, CSTE_PRINT_CMD);
		run_init_script("all");
		exit(1);
	} 

    websSetCfgResponse(mosq, tp, "60", "reserv");

	return 0;						
}

int getEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root;
	int arraylen,dnsMode=0,intVal=0,rtp_enabled=0,chan=0;
	char ssid[33]={0},wpaKey[65]={0};
	char wlan_if[32]={0},tmpBuf[65]={0},wlanvxd_if[32]={0},rpt_ssid[33]={0},rtp_bssid[32]={0};
	char wanMode[32]={0},opmode[8]={0}, Country[10]={0},wlan_disabled=0;
	char lan_ip[64]={0},poe_user[32]={0},poe_pass[64]={0};
	char lang[8]={0},countryCode[8]={0};

	__FUNC_IN__
	root=cJSON_CreateObject();
	int WiFiIdx = atoi(websGetVar(data, T("wifiIdx"), T("0")));
	sprintf(wlan_if, "wlan%d", WiFiIdx);
	sprintf(wlanvxd_if, "wlan%d-vxd", WiFiIdx);
	CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
	
	//wlan1
    SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_CHANNEL, (void *)&chan);
	cJSON_AddNumberToObject(root,"channel",chan);
	apmib_get(MIB_WLAN_SSID,(void *)ssid);
	cJSON_AddStringToObject(root,"ssid",ssid);
	cJSON_AddStringToObject(root,"authMode", getAuthMode("wlan0"));
	cJSON_AddStringToObject(root,"encrypType",getEncrypType("wlan0"));
	apmib_get(MIB_WLAN_WPA_PSK,(void *)wpaKey);
	cJSON_AddStringToObject(root,"wpakey",wpaKey);
	
 //   SetWlan_idx(wlan_if);
	//opmode
	int op_mode=0;
    apmib_get(MIB_OP_MODE, (void *)&op_mode);
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rtp_enabled);

	
	switch(op_mode){
		case BRIDGE_MODE:
			op_mode=0;
			break;
		case WISP_MODE:
			op_mode=3;
			break;
		default:// GATEWAY_MODE
			op_mode=1;
	}

	if(op_mode==0 && rtp_enabled==1){
		cJSON_AddNumberToObject(root,"operationMode",2);
	}else{
		cJSON_AddNumberToObject(root,"operationMode",op_mode);
	}
	
	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)countryCode);
	cJSON_AddStringToObject(root,"countryCode",countryCode);
	//RPT 
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
	cJSON_AddNumberToObject(root,"wifiOff",wlan_disabled);
	apmib_get(MIB_ROOTAP_MAC, (void *)rtp_bssid);

	apmib_get(MIB_REPEATER_SSID1, (void *)rpt_ssid);
	
//	cJSON_AddNumberToObject(root,"apcliEnable5g",rtp_enabled1);
	cJSON_AddNumberToObject(root,"apcliEnable",rtp_enabled);
	cJSON_AddStringToObject(root,"apcliBssid",rtp_bssid);
	cJSON_AddStringToObject(root,"apcliSsid",rpt_ssid);


	strcpy(wlanvxd_if,"wlan0-vxd");
	
	SetWlan_idx(wlanvxd_if);
	
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
	if (wlan_disabled)
		sprintf(tmpBuf, "%s", "wifiRadioOff");
	else if(1==getRepeaterStatus(wlanvxd_if))
		sprintf(tmpBuf, "%s", "success");
	else {
		if(WiFiIdx==0){
			if (!strcmp(rpt_ssid,"RepeaterSSID0")&& strlen(rtp_bssid)==0)
				sprintf(tmpBuf, "%s", "notConnection");
			else
				sprintf(tmpBuf, "%s", "fail");
		}else{
			if (!strcmp(rpt_ssid,"RepeaterSSID1")&& strlen(rtp_bssid)==0)
				sprintf(tmpBuf, "%s", "notConnection");
			else
				sprintf(tmpBuf, "%s", "fail");
		}
	}
	cJSON_AddStringToObject(root,"apcliStatus",tmpBuf);

	char ApCliwpaKey[65]={0}, buff_key[32]={0}, ApCli_wepkey[32]={0};
	int rtl_keyid=0;
	int rtl_wep, rtl_keytype, rtl_defkeyid, rtl_encrypt, pskformat;
	apmib_get( MIB_WLAN_WEP, (void *)&rtl_wep);
	apmib_get( MIB_WLAN_WEP_KEY_TYPE,  (void *)&rtl_keytype);	 
	apmib_get( MIB_WLAN_WEP_DEFAULT_KEY,  (void *)&rtl_defkeyid);
	apmib_get( MIB_WLAN_ENCRYPT, (void *)&rtl_encrypt);
	apmib_get( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
	apmib_get(MIB_WLAN_WPA_PSK,(void *)ApCliwpaKey);

	if(rtl_wep == WEP64){
        if(rtl_defkeyid==0)
            rtl_keyid = MIB_WLAN_WEP64_KEY1;
        else if(rtl_defkeyid==1)
            rtl_keyid = MIB_WLAN_WEP64_KEY2;
        else if(rtl_defkeyid==2)
            rtl_keyid = MIB_WLAN_WEP64_KEY3;
        else if(rtl_defkeyid==3)
            rtl_keyid = MIB_WLAN_WEP64_KEY4;
        apmib_get(rtl_keyid, (void *)buff_key);
        if(rtl_keytype==1){//Hex
            convert_bin_to_str(buff_key, 5, ApCli_wepkey);
        }else{
            snprintf(ApCli_wepkey, 6, "%s", buff_key);
        }
    }else if(rtl_wep == WEP128){
        if(rtl_defkeyid==0)
            rtl_keyid = MIB_WLAN_WEP128_KEY1;
        else if(rtl_defkeyid==1)
            rtl_keyid = MIB_WLAN_WEP128_KEY2;
        else if(rtl_defkeyid==2)
            rtl_keyid = MIB_WLAN_WEP128_KEY3;
        else if(rtl_defkeyid==3)
            rtl_keyid = MIB_WLAN_WEP128_KEY4;
        apmib_get(rtl_keyid, (void *)buff_key);
        if(rtl_keytype==1){//Hex
            convert_bin_to_str(buff_key, 13, ApCli_wepkey);
        }else{
            snprintf(ApCli_wepkey, 14, "%s", buff_key);
        }
    }
	
	cJSON_AddStringToObject(root,"apcliAuthMode", getAuthMode(wlanvxd_if));
	cJSON_AddStringToObject(root,"apcliEncrypType",getEncrypType(wlanvxd_if));
	cJSON_AddStringToObject(root,"apcliKeyStr",ApCli_wepkey);
	cJSON_AddStringToObject(root,"apcliWPAPSK",ApCliwpaKey);

	if(!getInAddr("br0", IP_ADDR_T, (void *)lan_ip))
		sprintf(lan_ip,"0.0.0.0");
	cJSON_AddStringToObject(root,"lanIp",lan_ip);
	
	getWanConnectMode(wanMode);
	cJSON_AddStringToObject(root,"wanConnectionMode",wanMode);
	apmib_get(MIB_PPP_USER_NAME,(void *)poe_user);
	cJSON_AddStringToObject(root,"wanPppoeUser",poe_user);
	apmib_get(MIB_PPP_PASSWORD,(void *)poe_pass);
	cJSON_AddStringToObject(root,"wanPppoePass",poe_pass);
	 char * IPGetName[]={"wanIpaddr","wanNetmask","wanGateway"};
    int IPGetId[]={MIB_WAN_IP_ADDR,MIB_WAN_SUBNET_MASK,MIB_WAN_DEFAULT_GATEWAY};
    arraylen = sizeof(IPGetName)/sizeof(char *);
    getCfgArrayIP(root, arraylen, IPGetName, IPGetId);
	
	apmib_get(MIB_DNS_MODE,  (void *)&dnsMode);
	if(dnsMode==1){//manual
		char * IPGetName2[]={"wanDns1", "wanDns2"};
		int IPGetId2[]={MIB_DNS1, MIB_DNS2};
		arraylen = sizeof(IPGetName2)/sizeof(char *);
		getCfgArrayIP(root, arraylen, IPGetName2, IPGetId2);
	}else{//auto
		cJSON_AddStringToObject(root,"dns1",getDns(1));
		cJSON_AddStringToObject(root,"dns2",getDns(2));
	}

	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	__FUNC_OUT__
	return 0;
}
#else
int setEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int dnschg=0,tmpVal=0,opmode=0,optime=0,mesh_enable=0,filesize=0,i=0,spectype=0;
	struct in_addr wanip,wannm,wangw;
	struct in_addr pptpip,pptpnm,pptpgw,pptpsip,l2tpip,l2tpnm,l2tpgw,l2tpsip;
	cJSON* subObj,*root,cmd[256]={0};
	char *devInfo=NULL,*ipaddr=NULL;
	char wlan_if[8]={0};
	__FUNC_IN__

	int ctype=atoi(websGetVar(data, T("wanMode"), T("0")));
	apmib_set(MIB_WAN_DHCP, (void *)&ctype);
	if(ctype==DHCP_DISABLED){
		char_t *ip = websGetVar(data, T("staticIp"), T(""));
		char_t *nm = websGetVar(data, T("staticMask"), T(""));
		char_t *gw = websGetVar(data, T("staticGw"), T(""));		
		if (!inet_aton(ip, &wanip)) return 0;
        apmib_set(MIB_WAN_IP_ADDR, (void *)&wanip);		
		if (!inet_aton(nm, &wannm)) return 0;
        apmib_set(MIB_WAN_SUBNET_MASK, (void *)&wannm);		
		if (!inet_aton(gw, &wangw)) return 0;
        apmib_set(MIB_WAN_DEFAULT_GATEWAY, (void *)&wangw);			
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	else if (ctype==DHCP_CLIENT) {
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	else if (ctype==PPPOE) {
		char_t *pppoe_user = websGetVar(data, T("pppoeUser"), T(""));
		char_t *pppoe_pass = websGetVar(data, T("pppoePass"), T(""));
		opmode = CONTINUOUS;
		optime = 300;		
		apmib_set(MIB_PPP_USER_NAME, (void *)pppoe_user);
    	apmib_set(MIB_PPP_PASSWORD, (void *)pppoe_pass);
		//apmib_set(MIB_PPP_SPEC_TYPE, (void *)&spectype);
		apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&opmode);			
    	apmib_set(MIB_PPP_IDLE_TIME, (void *)&optime);
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	else if (ctype==PPTP) {
		char_t *pptp_ip = websGetVar(data, T("pptpIp"), T(""));
		char_t *pptp_nm = websGetVar(data, T("pptpMask"), T(""));
		char_t *pptp_gw = websGetVar(data, T("pptpGw"), T(""));
		char_t *pptp_server= websGetVar(data, T("pptpServerIp"), T(""));
		char_t *pptp_user = websGetVar(data, T("pptpUser"), T(""));
		char_t *pptp_pass = websGetVar(data, T("pptpPass"), T(""));
		int mppe = atoi(websGetVar(data, T("pptpMppe"), T("0"))); 
		int mppc = atoi(websGetVar(data, T("pptpMppc"), T("0"))); 
		int pptp_mode = atoi(websGetVar(data, T("pptpMode"), T("0")));
		opmode = 0;
		optime = 60;		
		apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&pptp_mode); 		
		if (!inet_aton(pptp_ip, &pptpip)) return 0;
		apmib_set(MIB_PPTP_IP_ADDR, (void *)&pptpip);
		if (!inet_aton(pptp_nm, &pptpnm)) return 0;
		apmib_set(MIB_PPTP_SUBNET_MASK, (void *)&pptpnm);
		if (!inet_aton(pptp_gw, &pptpgw)) return 0;
		apmib_set(MIB_PPTP_DEFAULT_GW, (void *)&pptpgw);
		if (!inet_aton(pptp_server, &pptpsip)) return 0;
		apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&pptpsip);		
		apmib_set(MIB_PPTP_USER_NAME, (void *)pptp_user);
		apmib_set(MIB_PPTP_PASSWORD, (void *)pptp_pass);
		apmib_set(MIB_PPTP_CONNECTION_TYPE, (void *)&opmode);
		apmib_set(MIB_PPTP_IDLE_TIME, (void *)&optime);
		apmib_set(MIB_PPTP_SECURITY_ENABLED, (void *)&mppe);
		apmib_set(MIB_PPTP_MPPC_ENABLED, (void *)&mppc);
		dnschg=setWanDnsConfig(mosq,data,tp);		
	}
	else if (ctype==L2TP) {
		char_t *l2tp_ip = websGetVar(data, T("l2tpIp"), T(""));
		char_t *l2tp_nm = websGetVar(data, T("l2tpMask"), T(""));
		char_t *l2tp_gw = websGetVar(data, T("l2tpGw"), T(""));
		char_t *l2tp_server= websGetVar(data, T("l2tpServerIp"), T(""));
		char_t *l2tp_user = websGetVar(data, T("l2tpUser"), T(""));
		char_t *l2tp_pass = websGetVar(data, T("l2tpPass"), T(""));
		int l2tp_mode = atoi(websGetVar(data, T("l2tpMode"), T("0")));
		opmode = 0;
		optime = 60;
		apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&l2tp_mode);			
		if (!inet_aton(l2tp_ip, &l2tpip)) return 0;
        apmib_set(MIB_L2TP_IP_ADDR, (void *)&l2tpip);
		if (!inet_aton(l2tp_nm, &l2tpnm)) return 0;
        apmib_set(MIB_L2TP_SUBNET_MASK, (void *)&l2tpnm);
		if (!inet_aton(l2tp_gw, &l2tpgw)) return 0;
        apmib_set(MIB_L2TP_DEFAULT_GW, (void *)&l2tpgw);
		if (!inet_aton(l2tp_server, &l2tpsip)) return 0;
	    apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&l2tpsip);		
		apmib_set(MIB_L2TP_USER_NAME, (void *)l2tp_user);
		apmib_set(MIB_L2TP_PASSWORD, (void *)l2tp_pass);
		apmib_set(MIB_L2TP_CONNECTION_TYPE, (void *)&opmode);
		apmib_set(MIB_L2TP_IDLE_TIME, (void *)&optime);
		dnschg=setWanDnsConfig(mosq,data,tp);	
    }
	
	//WIFI Set
	char_t *ssid,*wpakey;
	int wifioff=0,wsc_enable=0;
	int encrypt=ENCRYPT_WPA2_MIXED,auth_wpa=WPA_AUTH_PSK,cipher=WPA_CIPHER_MIXED,pskfmt=KEY_ASCII;

#if defined(CONFIG_KL_CS18NR_04336)
	cipher=WPA_CIPHER_AES;
#endif

#if defined(FOR_DUAL_BAND)
	strcpy(wlan_if,"wlan0");
	SetWlan_idx(wlan_if);	
	ssid = websGetVar(data, T("ssid5g"), T(""));
	wpakey = websGetVar(data, T("wpakey5g"), T(""));

	apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifioff);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
	apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
	strncpy(wps_config_info_tmp.ssid, ssid, strlen(ssid));
	wps_config_info_tmp.wlan_mode=wps_config_info.wlan_mode;
	update_wps_configured(0);
#endif	

	apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskfmt);
    apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);		
	apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	
#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
	wps_config_info_tmp.auth=encrypt;
	wps_config_info_tmp.wpa_enc=cipher;
	wps_config_info_tmp.wpa2_enc=cipher;
	wps_config_info_tmp.shared_type=auth_wpa;
	strncpy(wps_config_info_tmp.wpaPSK,wpakey,strlen(wpakey));
	update_wps_configured(0);
#endif		
	
	//WSC		
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_enable);
	tmpVal=34;
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&tmpVal);//34
	tmpVal=12;
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&tmpVal);//12
	strcpy(wlan_if,"wlan1");
#else
	strcpy(wlan_if,"wlan0");
#endif
	SetWlan_idx(wlan_if);
	ssid = websGetVar(data, T("ssid"), T(""));
	wpakey = websGetVar(data, T("wpakey"), T(""));

	apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifioff);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
	apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
	strncpy(wps_config_info_tmp.ssid, ssid, strlen(ssid));
	wps_config_info_tmp.wlan_mode=wps_config_info.wlan_mode;
	update_wps_configured(0);
#endif

	apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskfmt);
    apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);		
	apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	
#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
	wps_config_info_tmp.auth=encrypt;
	wps_config_info_tmp.wpa_enc=cipher;
	wps_config_info_tmp.wpa2_enc=cipher;
	wps_config_info_tmp.shared_type=auth_wpa;
	strncpy(wps_config_info_tmp.wpaPSK,wpakey,strlen(wpakey));
	update_wps_configured(0);
#endif
	
	tmpVal=34;
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&tmpVal);//34
	tmpVal=12;
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&tmpVal);//12
	//WSC		
#if !defined(SUPPORT_MESH)
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_enable);
#else
	tmpVal=0;
	apmib_set(MIB_REPEATER_ENABLED1,(void *)&tmpVal);
#if defined(FOR_DUAL_BAND)
	apmib_set(MIB_REPEATER_ENABLED2,(void *)&tmpVal);
#endif
#endif

	int pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		sleep(1);
#if defined (CS_MESH_SYNC)
		system("sysconf updateAllMeshInfo");
#endif
		takeEffectWlan("wlan0", 1);
#if defined(FOR_DUAL_BAND)
		takeEffectWlan("wlan1", 1);
#endif
		system("sysconf init gw wan");
		exit(1);
	}

	if(ctype == 4){
		websSetCfgResponse(mosq, tp, "70", "reserv");	
	}else if(ctype == 3 || ctype == 6){
		websSetCfgResponse(mosq, tp, "65", "reserv");
	}else{
		websSetCfgResponse(mosq, tp, "50", "reserv");
	}	
	__FUNC_OUT__
    return 0;
}

int getEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int arraylen,intVal;
	char wlan_if[8]={0},tmpBuf[33]={0};
	__FUNC_IN__

	//int type mib
    char *IntGetName[]={"l2tpMode","l2tpFlag","pptpMode","pptpFlag","pptpMppe","pptpMppc"};
    int IntGetId[]={MIB_L2TP_WAN_IP_DYNAMIC,MIB_L2TP_GET_SERV_BY_DOMAIN,MIB_PPTP_WAN_IP_DYNAMIC,MIB_PPTP_GET_SERV_BY_DOMAIN,MIB_PPTP_SECURITY_ENABLED,MIB_PPTP_MPPC_ENABLED};
    arraylen = sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
	
	//ip type mib
    char *IPGetName[]={"lanIp","staticIp","staticMask","staticGw","l2tpServerIp","l2tpIp","l2tpMask","l2tpGw","pptpServerIp","pptpIp","pptpMask","pptpGw"};
    int IPGetId[]={MIB_IP_ADDR,MIB_WAN_IP_ADDR,MIB_WAN_SUBNET_MASK,MIB_WAN_DEFAULT_GATEWAY,\
				MIB_L2TP_SERVER_IP_ADDR,MIB_L2TP_IP_ADDR,MIB_L2TP_SUBNET_MASK,MIB_L2TP_DEFAULT_GW,\
				MIB_PPTP_SERVER_IP_ADDR,MIB_PPTP_IP_ADDR,MIB_PPTP_SUBNET_MASK,MIB_PPTP_DEFAULT_GW};
    arraylen = sizeof(IPGetName)/sizeof(char *);
    getCfgArrayIP(root, arraylen, IPGetName, IPGetId);

	//str type mib
    char *StrGetName[]={"pppoeUser","pppoePass","l2tpUser","l2tpPass","l2tpServer","pptpUser","pptpPass","pptpServer"};
	int StrGetId[]={MIB_PPP_USER_NAME,MIB_PPP_PASSWORD,\
					MIB_L2TP_USER_NAME,MIB_L2TP_PASSWORD,MIB_L2TP_SERVER_DOMAIN,\
					MIB_PPTP_USER_NAME,MIB_PPTP_PASSWORD,MIB_PPTP_SERVER_DOMAIN};
    arraylen = sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);	
	
#ifdef CONFIG_MULTI_LANG
	cJSON_AddNumberToObject(root,"multiLangBt",1);
#else
	cJSON_AddNumberToObject(root,"multiLangBt",0);
#endif

#ifdef CONFIG_SUPPORT_HELP
	cJSON_AddNumberToObject(root,"helpBt",1);
#else
	cJSON_AddNumberToObject(root,"helpBt",0);
#endif
	
	apmib_get(MIB_HARDWARE_MODEL, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"productName",tmpBuf);

#if defined(SUPPORT_APAC)
	char SoftVer[32]={0};
	apmib_get(MIB_SOFTWARE_VERSION,(void *)SoftVer);
	sprintf(tmpBuf,"%s.%d",SoftVer,PRODUCT_SVN);
#else
	sprintf(tmpBuf, "%s.%d", PRODUCT_VER, PRODUCT_SVN);
#endif	
	cJSON_AddStringToObject(root,"fmVersion",tmpBuf);	
#if defined(CONFIG_SUPPORT_TOTOLINK)
	cJSON_AddStringToObject(root,"title","TOTOLINK");
#elif defined(CONFIG_KL_C7182R_04325)||defined(CONFIG_KL_C7188R_04325)
	cJSON_AddStringToObject(root,"title","GWTT");
#elif defined(CONFIG_KL_C7185R_04336)
	cJSON_AddStringToObject(root,"title","JX-IMAP1200");
#else
	cJSON_AddStringToObject(root,"title","");
#endif

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"languageType", tmpBuf);
#if defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)
	sprintf(tmpBuf,"%s","www.szeasycore.com");
#else
	if (!strcmp(tmpBuf,"cn")){
		sprintf(tmpBuf,"%s","www.totolink.cn");
	}else if(!strcmp(tmpBuf,"ct")){
		sprintf(tmpBuf,"%s","www.totolink.tw");
	}else{
		sprintf(tmpBuf,"%s","www.totolink.net");	
	}
#endif
	cJSON_AddStringToObject(root,"helpUrl",tmpBuf);

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

	//WAN
	apmib_get(MIB_DNS_MODE, (void *)&intVal);
	if(intVal==DNS_MANUAL){//manual
	    char *IPGetName2[]={"priDns","secDns"};
        int IPGetId2[]={MIB_DNS1,MIB_DNS2};
	    arraylen=sizeof(IPGetName2)/sizeof(char *);
        getCfgArrayIP(root, arraylen, IPGetName2, IPGetId2);
	}else{//auto
        cJSON_AddStringToObject(root,"priDns",getDns(1));
		cJSON_AddStringToObject(root,"secDns",getDns(2));
    }
	
	get_wan_connect_status(tmpBuf);
	cJSON_AddStringToObject(root,"wanConnStatus",tmpBuf);
	
	apmib_get(MIB_WAN_DHCP, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wanMode",intVal);	
	if (intVal!=DHCP_DISABLED){
		if(!strcmp(tmpBuf,"connected")){
			getWanIp(tmpBuf);
			cJSON_AddStringToObject(root,"wanIp",tmpBuf);
			cJSON_AddStringToObject(root,"wanMask",getWanNetmask());
			cJSON_AddStringToObject(root,"wanGw",getWanGateway());
		}
		else{
			cJSON_AddStringToObject(root,"wanIp","0.0.0.0");
			cJSON_AddStringToObject(root,"wanMask","0.0.0.0");
			cJSON_AddStringToObject(root,"wanGw","0.0.0.0");
		}		
	}

#ifdef CONFIG_SUPPORT_WAN_AUTODETECT
	cJSON_AddNumberToObject(root,"wanAutoDetectBt",1);
#else
	cJSON_AddNumberToObject(root,"wanAutoDetectBt",0);
#endif

#ifdef CONFIG_APP_PPTP
	cJSON_AddNumberToObject(root,"pptpBt",1);
#else
	cJSON_AddNumberToObject(root,"pptpBt",0);
#endif

#ifdef CONFIG_APP_L2TPD
	cJSON_AddNumberToObject(root,"l2tpBt",1);
#else
	cJSON_AddNumberToObject(root,"l2tpBt",0);
#endif

	//WIFI
#if defined(FOR_DUAL_BAND)
	cJSON_AddNumberToObject(root,"wifiDualband",1);	//5G : 1 

	strcpy(wlan_if,"wlan0");
	SetWlan_idx(wlan_if);	
	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ssid5g",tmpBuf);
	
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intVal);
	if(intVal>1){
		cJSON_AddStringToObject(root,"wpakey5g",getWirelessKey(wlan_if));	
	}else{
		cJSON_AddStringToObject(root,"wpakey5g","");
	}
	strcpy(wlan_if,"wlan1");	
#else
	cJSON_AddNumberToObject(root,"wifiDualband",0);	//2.4G : 0 

	strcpy(wlan_if,"wlan0");
#endif
	SetWlan_idx(wlan_if);
	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ssid",tmpBuf);
	
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intVal);
	if(intVal>1){
		cJSON_AddStringToObject(root,"wpakey",getWirelessKey(wlan_if));	
	}else{
		cJSON_AddStringToObject(root,"wpakey","");
	}

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	__FUNC_OUT__
	return 0;
}
#endif
int getSaveConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char responseStr[CSTEBUFSIZE]={0};
	char serIp[32]={0},modelName[32]={0},dateStr[16]={0},tmpCmd[64]={0};
	unsigned char csid[16]={0};
	int len=0;
	FILE *fp=NULL;
	__FUNC_IN__

	save_cs_to_file();

	char *http_host= websGetVar(data, T("http_host"), T(""));
	if(strlen(http_host)>0){
		strcpy(serIp,http_host);
	}else{
		getLanIp(serIp);
	}

	snprintf((responseStr + len), (sizeof(responseStr) - len), "{\"httpStatus\":\"%s\",\"host\":\"%s\"","302",serIp);
	len = strlen(responseStr);
	apmib_get(MIB_HARDWARE_MODEL,(void *)modelName);

	apmib_get(MIB_CSID,(void *)csid);
	fp=fopen("/web_cste/config.dat","ab");
	if(fp==NULL)
	{
		perror("fopen");
		return 0;
	}
	
	fwrite(" ", 1, 1, fp);
	fwrite(csid, strlen(csid), 1, fp); 
	fclose(fp);

	getCmdStr("date  '+%Y%m%d'",dateStr,sizeof(dateStr));
	
	sprintf(tmpCmd,"cp /web_cste/config.dat /web_cste/Config-%s-%s.dat", modelName,dateStr);
	system(tmpCmd);

	snprintf((responseStr + len),(sizeof(responseStr) - len), ",\"redirectURL\":\"http://%s/Config-%s-%s.dat\"}",serIp,modelName,dateStr);
	len = strlen(responseStr);
	websGetCfgResponse(mosq,tp,responseStr);
	__FUNC_OUT__
}


int autoDhcp(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	int opmode=0,apmode=0,meshSuccNum=0;
	char cmd[64]={0},tmpBuf[16]={0};
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	
	if (opmode==1){
		char_t *status = websGetVar(data, T("status"), T("0"));
		//printf("status=%s,%d,%s\n",status,__LINE__,__FUNCTION__);
		system("killall -9 udhcpd 2> /dev/null");
		system("killall -9 udhcpc 2> /dev/null");
		if(!strcmp(status,"succ")){
#if defined(SUPPORT_REPEATER)
			CsteSystem("ifconfig br0 169.254.0.254",CSTE_PRINT_CMD);
			CsteSystem("udhcpc -i br0 -p /etc/udhcpc/udhcpc-br0.pid -s /usr/share/udhcpc/br0.sh &",CSTE_PRINT_CMD);
			CsteSystem("echo '' > /tmp/DhcpSucc",CSTE_PRINT_CMD);
			CsteSystem("ifconfig br0:1 192.168.0.254 up",CSTE_PRINT_CMD);
			apmib_get(MIB_AP_MODE_ENABLED, (void *)&apmode);
			if(apmode==0){//ap mode
				int dhcp_type=0;
				apmib_set(MIB_DHCP, (void *)&dhcp_type);
				apmib_update_web(CURRENT_SETTING);
			}
#else			
#ifdef SUPPORT_APAC
			system("ifconfig br0 192.169.253.254;ifconfig br0:1 192.168.0.254 up");
#endif
			system("udhcpc -i br0 -p /etc/udhcpc/udhcpc-br0.pid -s /usr/share/udhcpc/br0.sh &");
			//取到地址，通知主设备，同步mesh信息
#ifdef SUPPORT_MESH		
			meshSuccNum=getCmdVal("cat /proc/kl_reg | grep meshSuccNum | cut -f2 -d=");
			if(meshSuccNum>0)
				system("csteSys syncWifi");
#endif
#endif
		}
#if !(defined(SUPPORT_APAC)||defined(SUPPORT_REPEATER))
		else{			
			system("udhcpd /var/udhcpd.conf &");
		}
#endif
	}
	return 0;
}

#ifdef SUPPORT_REPEATER
int getExtendConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	cJSON *root=cJSON_CreateObject();
	bss_info bss;
	int arraylen,intVal=0,wlanid=0,dbm=0;
	char wlanvxd_if[16]={0},buff[32],buff2[4]={0},buff3[128]={0};

#ifdef CONFIG_MULTI_LANG
	cJSON_AddNumberToObject(root,"multiLangBt",1);
#else
	cJSON_AddNumberToObject(root,"multiLangBt",0);
#endif

#ifdef CONFIG_SUPPORT_HELP
	cJSON_AddNumberToObject(root,"helpBt",1);
#else	
	cJSON_AddNumberToObject(root,"helpBt",0);
#endif

	apmib_get(MIB_LANGUAGE_TYPE, (void *)buff2);	
	cJSON_AddStringToObject(root,"languageType",buff2);
	if (!strcmp(buff2,"cn")){
		sprintf(buff,"%s","www.totolink.cn");
	}else if(!strcmp(buff2,"ct")){
		sprintf(buff,"%s","www.totolink.tw");
	}else{
		sprintf(buff,"%s","www.totolink.net");	
	}
	cJSON_AddStringToObject(root,"helpUrl",buff);
	cJSON_AddStringToObject(root,"customerUrl",buff);
	
#ifdef CONFIG_SUPPORT_PROMODEL
	apmib_get(MIB_HARDWARE_MODEL, (void *)buff);
	cJSON_AddStringToObject(root,"productName",buff);
#else
	cJSON_AddStringToObject(root,"productName","");
#endif

	sprintf(buff,"%s.%d",PRODUCT_VER,PRODUCT_SVN);
    cJSON_AddStringToObject(root,"fmVersion",buff);

	sprintf(buff,"%s %s",PRODUCT_DATE,PRODUCT_TIME);
	cJSON_AddStringToObject(root,"buildTime",buff);

	char ipaddr[18]={0}, ipnetmask[18]={0};
    getInAddr("br0", IP_ADDR_T, ipaddr);
    getInAddr("br0", NET_MASK_T, ipnetmask);
	cJSON_AddStringToObject(root,"lanIp",ipaddr);
	cJSON_AddStringToObject(root,"lanMask",ipnetmask);

#ifdef CONFIG_SUPPORT_SCHEDULE_REBOOT
	char * IntGetName[]={"scheEn","scheWeek","scheHour","scheMin"};
	int IntGetId[]={MIB_REBOOTSCH_ENABLED,MIB_REBOOTSCH_WEEK,MIB_REBOOTSCH_HOUR,MIB_REBOOTSCH_MINUTE};
    arraylen = sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
#endif

	//wifi
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_SSID, (void *)buff3);		
	cJSON_AddStringToObject(root,"ssid5g",buff3);
	
	apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
	if(intVal==0)intVal=149;//解决wps
	cJSON_AddNumberToObject(root,"channel5g",intVal);

	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)buff3);
	cJSON_AddStringToObject(root,"countryCode5g",buff3);

	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_SSID, (void *)buff3);		
	cJSON_AddStringToObject(root,"ssid",buff3);
	
	apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
	if(intVal==0) intVal=11;//解决wps
	cJSON_AddNumberToObject(root,"channel",intVal);

	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)buff3);
	cJSON_AddStringToObject(root,"countryCode",buff3);

	apmib_get(MIB_WLAN_WPA_PSK, (void *)buff3);
	cJSON_AddStringToObject(root,"wpakey",buff3);

	apmib_get(MIB_WISP_WAN_ID, (void *)&wlanid);
	if(wlanid==0){
		strcpy(wlanvxd_if,"wlan0-vxd");	
	}else{
		strcpy(wlanvxd_if,"wlan1-vxd");
	}

	apmib_get(MIB_AP_MODE_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"apcliEnable",intVal);
	SetWlan_idx(wlanvxd_if);
	if (intVal==1){//connected	
		getWlBssInfo(wlanvxd_if, &bss);
		memcpy(buff3, bss.ssid, 32+1);
		if(strlen(buff3)==0){
			apmib_get(MIB_WLAN_SSID, (void *)buff3);		
		}
		cJSON_AddStringToObject(root,"apcliSsid",buff3);
		
		getWlBssInfo(wlanvxd_if,&bss);				
		sprintf(buff,"%02X:%02X:%02X:%02X:%02X:%02X",
			bss.bssid[0],bss.bssid[1],bss.bssid[2],
			bss.bssid[3],bss.bssid[4],bss.bssid[5]);
		cJSON_AddStringToObject(root,"apcliBssid",buff);			

		if(1==getRepeaterStatus(wlanvxd_if))
			cJSON_AddStringToObject(root,"apcliStatus","success");
		else 
			cJSON_AddStringToObject(root,"apcliStatus","fail");

		intVal=getRptStaAndRssi(wlanvxd_if);
		dbm=intVal-100;
		if(dbm > -50)
			strcpy(buff,"high");
		else if(dbm <= -50 && dbm > -60)
			strcpy(buff,"medium");
		else if(dbm <= -60 && dbm > -70)
			strcpy(buff,"low");
		else
			strcpy(buff,"null");
		cJSON_AddStringToObject(root,"apcliSignal",buff);
	}
	else{
		cJSON_AddStringToObject(root,"apcliSsid","Extender");
		cJSON_AddStringToObject(root,"apcliBssid","00:00:00:00:00:00");	
		cJSON_AddStringToObject(root,"apcliStatus","fail");
		cJSON_AddStringToObject(root,"apcliSignal","null");
	}

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}

int setExtendConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char tmpBuff[128]={0},orig_ssid[33]={0},orig_wpakey[65]={0};
	int intVal=0,flag=0,orig_channel=0;
	__FUNC_IN__

	char_t *ssid = websGetVar(data, T("ssid"), T(""));
	char_t *ssid5g = websGetVar(data, T("ssid5g"), T(""));
	char_t *wpakey = websGetVar(data, T("wpakey"), T(""));
	int channel = atoi(websGetVar(data, T("channel"), T("")));
	int channel5g = atoi(websGetVar(data, T("channel5g"), T("")));

	//5G wifi
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_SSID, (void *)orig_ssid);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)orig_wpakey);
	apmib_get(MIB_WLAN_CHANNEL, (void *)&orig_channel);
	apmib_set(MIB_WLAN_SSID, (void *)ssid5g);	
	intVal=76;
	apmib_set(MIB_WLAN_BAND, (void *)&intVal);
	apmib_set(MIB_WLAN_CHANNEL, (void *)&channel5g);

	if(strlen(wpakey)==0){
		intVal=0;//none
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);	
		strcpy(tmpBuff,"");
		apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpBuff);
	}
	else{	
		intVal=6;//wpa/wpa2-psk
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);	
		intVal=2;//aes	
		apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal);
		apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal);
		intVal=0;//ascii
		apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&intVal);
		apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);
	}

	if(strcmp(orig_ssid,ssid5g)) flag=1;
	if(strcmp(orig_wpakey,wpakey)) flag=1;
	if(orig_channel!=channel5g) flag=1;

	//2.4G wifi
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_SSID, (void *)orig_ssid);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)orig_wpakey);
	apmib_get(MIB_WLAN_CHANNEL, (void *)&orig_channel);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);
	intVal=11;//bgn
	apmib_set(MIB_WLAN_BAND, (void *)&intVal);	
	apmib_set(MIB_WLAN_CHANNEL, (void *)&channel);

	if(strcmp(orig_ssid,ssid)) flag=1;
	if(strcmp(orig_wpakey,wpakey)) flag=1;
	if(orig_channel!=channel) flag=1;		

	if(strlen(wpakey)==0){
		intVal=0;//none
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);
		strcpy(tmpBuff,"");
		apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpBuff);
	}
	else{
		intVal=6;//wpa/wpa2-psk
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);	
		intVal=2;//aes	
		apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal);
		apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal);
		intVal=0;//ascii
		apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&intVal);
		apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);	
	}

	strcpy(tmpBuff,"Extender");
	intVal=0;
	SetWlan_idx("wlan0-vxd");//vxd
	apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);
	apmib_set(MIB_WLAN_SSID, (void *)tmpBuff);
	apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpBuff);
	intVal=1;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

	intVal=0;
	SetWlan_idx("wlan1-vxd");//vxd
	apmib_set(MIB_WLAN_ENCRYPT, (void *)&intVal);
	apmib_set(MIB_WLAN_SSID, (void *)tmpBuff);
	apmib_set(MIB_WLAN_WPA_PSK, (void *)tmpBuff);
	intVal=1;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	
	strcpy(tmpBuff,"");
	apmib_set(MIB_ROOTAP_MAC, (void *)tmpBuff);

	//wifi vxd
	intVal=0;
	apmib_set(MIB_AP_MODE_ENABLED, (void *)&intVal);//ap mode	
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&intVal);
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&intVal);
	CsteSystem("ifconfig wlan0-vxd down",CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-vxd down",CSTE_PRINT_CMD);
	CsteSystem("brctl delif br0 wlan0-vxd",CSTE_PRINT_CMD);
	CsteSystem("brctl delif br0 wlan1-vxd",CSTE_PRINT_CMD);
	intVal=2;
	apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&intVal);//80m
	
	//printf("flag=[%d]\n",flag);
	if(flag){
		CsteSystem("killall -9 udhcpd 2> /dev/null",CSTE_PRINT_CMD);
		intVal=0;
		apmib_set(MIB_DHCP, (void *)&intVal);
	}
	SetWlan_idx("wlan0");
	int pid=fork();
	if(0 == pid){
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	} 
    //生效配置
    takeEffectWlan("wlan0-vxd", 1);
	takeEffectWlan("wlan1-vxd", 1);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	__FUNC_OUT__
    return 0;
}
#endif

#if defined(CONFIG_KL_C7180R_04339)||defined(CONFIG_KL_C7181R_04336)
int setQuickWanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int dnschg=0,opmode=0,optime=0,spectype=0;
	struct in_addr wanip,wannm,wangw;
	__FUNC_IN__

	apmib_set(MIB_OP_MODE, (void *)&opmode);//gateway
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&opmode);
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&opmode);

	int ctype=atoi(websGetVar(data, T("wanMode"), T("0")));
	apmib_set(MIB_WAN_DHCP, (void *)&ctype);
	if(ctype==DHCP_DISABLED){
		char_t *ip = websGetVar(data, T("staticIp"), T(""));
		char_t *nm = websGetVar(data, T("staticMask"), T(""));
		char_t *gw = websGetVar(data, T("staticGw"), T(""));		
		if (!inet_aton(ip, &wanip)) return 0;
		apmib_set(MIB_WAN_IP_ADDR, (void *)&wanip); 	
		if (!inet_aton(nm, &wannm)) return 0;
		apmib_set(MIB_WAN_SUBNET_MASK, (void *)&wannm); 	
		if (!inet_aton(gw, &wangw)) return 0;
		apmib_set(MIB_WAN_DEFAULT_GATEWAY, (void *)&wangw); 		
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	else if (ctype==DHCP_CLIENT) {
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	else if (ctype==PPPOE) {
		char_t *pppoe_user = websGetVar(data, T("pppoeUser"), T(""));
		char_t *pppoe_pass = websGetVar(data, T("pppoePass"), T(""));
		opmode = CONTINUOUS;
		optime = 300;		
		apmib_set(MIB_PPP_USER_NAME, (void *)pppoe_user);
		apmib_set(MIB_PPP_PASSWORD, (void *)pppoe_pass);
		//apmib_set(MIB_PPP_SPEC_TYPE, (void *)&spectype);
		apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&opmode);			
		apmib_set(MIB_PPP_IDLE_TIME, (void *)&optime);
		dnschg=setWanDnsConfig(mosq, data, tp);
	}
	
	int pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		sleep(1);
		system("sysconf init gw wan");
		exit(1);
	}

	websSetCfgResponse(mosq, tp, "50", "reserv");
	__FUNC_OUT__
	return 0;
}

int setQuickWiFiConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int tmpVal=0;
	char wlan_if[8]={0};
	__FUNC_IN__

	//WIFI Set
	char_t *ssid,*wpakey;
	int wifioff=0,wsc_enable=0;
	int encrypt=ENCRYPT_WPA2_MIXED,auth_wpa=WPA_AUTH_PSK,cipher=WPA_CIPHER_MIXED,pskfmt=KEY_ASCII;
		
#if defined(FOR_DUAL_BAND)
	strcpy(wlan_if,"wlan0");
	SetWlan_idx(wlan_if);	
	ssid = websGetVar(data, T("ssid5g"), T(""));
	wpakey = websGetVar(data, T("wpakey5g"), T(""));

	apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifioff);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
	apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
	strncpy(wps_config_info_tmp.ssid, ssid, strlen(ssid));
	wps_config_info_tmp.wlan_mode=wps_config_info.wlan_mode;
	update_wps_configured(0);
#endif	

	apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskfmt);
    apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);		
	apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	
#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
	wps_config_info_tmp.auth=encrypt;
	wps_config_info_tmp.wpa_enc=cipher;
	wps_config_info_tmp.wpa2_enc=cipher;
	wps_config_info_tmp.shared_type=auth_wpa;
	strncpy(wps_config_info_tmp.wpaPSK,wpakey,strlen(wpakey));
	update_wps_configured(0);
#endif		
	
	//WSC		
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_enable);
	tmpVal=34;
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&tmpVal);//34
	tmpVal=12;
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&tmpVal);//12
	strcpy(wlan_if,"wlan1");
#else
	strcpy(wlan_if,"wlan0");
#endif
	SetWlan_idx(wlan_if);
	ssid = websGetVar(data, T("ssid"), T(""));
	wpakey = websGetVar(data, T("wpakey"), T(""));

	apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&wifioff);
	apmib_set(MIB_WLAN_SSID, (void *)ssid);

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
	apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
	strncpy(wps_config_info_tmp.ssid, ssid, strlen(ssid));
	wps_config_info_tmp.wlan_mode=wps_config_info.wlan_mode;
	update_wps_configured(0);
#endif

	apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
	apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&pskfmt);
    apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&cipher);
    apmib_set(MIB_WLAN_WPA_PSK, (void *)wpakey);		
	apmib_set(MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	
#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
	wps_config_info_tmp.auth=encrypt;
	wps_config_info_tmp.wpa_enc=cipher;
	wps_config_info_tmp.wpa2_enc=cipher;
	wps_config_info_tmp.shared_type=auth_wpa;
	strncpy(wps_config_info_tmp.wpaPSK,wpakey,strlen(wpakey));
	update_wps_configured(0);
#endif
	
	//WSC		
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&wsc_enable);
	tmpVal=34;
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&tmpVal);//34
	tmpVal=12;
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&tmpVal);//12

	int pid=fork();
	if(0 == pid){
		apmib_update_web(CURRENT_SETTING);
		sleep(1);
		takeEffectWlan("wlan0", 1);
#if defined(FOR_DUAL_BAND)
		takeEffectWlan("wlan1", 1);
#endif
		exit(1);
	}

	websSetCfgResponse(mosq, tp, "30", "reserv");	
	__FUNC_OUT__
    return 0;
}

int getQuickConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int arraylen,intVal;
	char wlan_if[16]={0},tmpBuf[33]={0};
	bss_info bss;
	int wisp_wan_id=0;
	__FUNC_IN__

	//int type mib
	char *IntGetName[]={"wanMode","dhcpLease"};
	int IntGetId[]={MIB_WAN_DHCP,MIB_DHCP_LEASE_TIME};
	arraylen = sizeof(IntGetName)/sizeof(char *);
	getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
	
	//ip type mib
	char *IPGetName[]={"lanIp","lanNetmask","dhcpStart","dhcpEnd",\
						"staticIp","staticMask","staticGw","priDns","secDns"};
	int IPGetId[]={MIB_IP_ADDR,MIB_SUBNET_MASK,MIB_DHCP_CLIENT_START,MIB_DHCP_CLIENT_END,\
					MIB_WAN_IP_ADDR,MIB_WAN_SUBNET_MASK,MIB_WAN_DEFAULT_GATEWAY,MIB_DNS1,MIB_DNS2};
	arraylen = sizeof(IPGetName)/sizeof(char *);
	getCfgArrayIP(root, arraylen, IPGetName, IPGetId);

	//str type mib
	char *StrGetName[]={"pppoeUser","pppoePass"};
	int StrGetId[]={MIB_PPP_USER_NAME,MIB_PPP_PASSWORD};
	arraylen = sizeof(StrGetName)/sizeof(char *);
	getCfgArrayStr(root, arraylen, StrGetName, StrGetId);	
	
	cJSON_AddStringToObject(root,"title","");
	cJSON_AddNumberToObject(root,"dhcpServer",getDhcp());

	//WIFI
	SetWlan_idx("wlan0");	
	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ssid5g",tmpBuf);

	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ssid",tmpBuf);
	
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intVal);
	if(intVal>1){
		cJSON_AddStringToObject(root,"wpakey",getWirelessKey("wlan1")); 
	}else{
		cJSON_AddStringToObject(root,"wpakey","");
	}

	//RepeaterInfo	
	apmib_get(MIB_WISP_WAN_ID, (void *)&wisp_wan_id);		
	if (wisp_wan_id==0){
		strcpy(wlan_if,"wlan0-vxd");
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);			
	}else{
		strcpy(wlan_if,"wlan1-vxd");
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);			
	}
	
	if(intVal==1){
		getWlBssInfo(wlan_if, &bss);
		memcpy(tmpBuf, bss.ssid, 32+1);
		if(strlen(tmpBuf)==0){
    		SetWlan_idx(wlan_if);
    		apmib_get(MIB_WLAN_SSID, (void *)tmpBuf);      
		}
		cJSON_AddStringToObject(root,"apcliSsid",tmpBuf);				
		cJSON_AddStringToObject(root,"apcliKey",getWirelessKey(wlan_if));

		if(1==getRepeaterStatus(wlan_if))
			cJSON_AddStringToObject(root,"apcliStatus","success");
		else
			cJSON_AddStringToObject(root,"apcliStatus","fail");
	}
	else{
		cJSON_AddStringToObject(root,"apcliSsid","Extender");				
		cJSON_AddStringToObject(root,"apcliKey","");
		cJSON_AddStringToObject(root,"apcliStatus","fail");
	}

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	__FUNC_OUT__
	return 0;
}
#endif
//-----------------------------------------------------
#if defined(SUPPORT_WECHATQR)
/**
* @note getCrpcConfig  get Crpc Configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"status":		0,
	"url":		""
}
return parameter description:
"status":		crp status - 0 :fail, 1 : success
"url":		crp address
</pre>
*@author	Hayden
*@date	2018-6-15
*/
void url_encode(char *url)
{
    unsigned char const *from, *end;
	unsigned char *start, *to;
	unsigned char c;

	char res[256];
	int len = strlen(url);
    from = url;
    end = url + len;
    start = to = res;

    unsigned char hexchars[] = "0123456789abcdef";//"0123456789ABCDEF";

    while (from < end) {
        c = *from++;

        if (c == ' ') {
            *to++ = '+';
        } else if ((c < '0' && c != '-' && c != '.')
                   ||(c < 'A' && c > '9')
                   ||(c > 'Z' && c < 'a' && c != '_')
                   ||(c > 'z')) {
            to[0] = '%';
            to[1] = hexchars[c >> 4];
            to[2] = hexchars[c & 15];
            to += 3;
        } else {
            *to++ = c;
        }
    }
    *to++ = 0;

    strcpy(url, res);
    return;
}

#define WECHAR_URL_HEAD "http://www.carystudio.com/router/wechatmanage/routerurl?url="
int getCrpcConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	char wechatHead[128],weChatUrl[256]={0},url[256]={0};
	int enable=0,intVal=0;
	int countmax=50; //1sec
	
	apmib_get(MIB_CRPC_ENABLED, (void *)&enable);
	if (enable==0 ||( !tcpcheck_net( "114.114.114.114", 53, 2) && !tcpcheck_net( "www.qq.com", 80, 2)))
	{
		cJSON_AddNumberToObject(root,"status",0);
		cJSON_AddStringToObject(root,"url","");
	}
	else{
		cJSON_AddNumberToObject(root,"status",1);	
		CsteSystem("crpc", CSTE_PRINT_CMD);
		while ( countmax-- )
		{
			if (f_exist("/tmp/crpc_url"))
				break;

			usleep(20);
		}
		f_read("/tmp/crpc_url",url,0,sizeof(url));
		url_encode(url);
		apmib_get(MIB_CRPC_URLHEAD, wechatHead);
		if(strlen(wechatHead)<10){
			strcpy(wechatHead,WECHAR_URL_HEAD);
		}
		sprintf(weChatUrl, "%s%s", wechatHead, url);
		cJSON_AddStringToObject(root,"url",weChatUrl);
	}
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}
#endif

int getInitConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output,*showhelp,*helpurl;
	cJSON *root,*custom;
	
	char tmpBuf[64] = {0}, lstr[256] = {0},langflag[8]={0};
	int  tmpInt=0;

	root=cJSON_CreateObject();
	
	apmib_get(MIB_HARDWARE_MODEL, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"model", tmpBuf);

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"defaultLang", tmpBuf);

	apmib_get(MIB_VENDOR, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"cs", tmpBuf);

	apmib_get(MIB_LANG_FLAG, (void *)langflag);
	cJSON_AddStringToObject(root,"langAutoFlag",langflag);
	cJSON_AddStringToObject(root,"showAutoLang", "1");
	int opmode=1;
	if(opmode == 0)
		cJSON_AddStringToObject(root,"currentMode", "BR");
	else if(opmode == 1)
		cJSON_AddStringToObject(root,"currentMode", "GW");
	else if(opmode == 2)
		cJSON_AddStringToObject(root,"currentMode", "RPT");
	else if(opmode == 3)
		cJSON_AddStringToObject(root,"currentMode", "WISP");
	else if(opmode == 4)
		cJSON_AddStringToObject(root,"currentMode", "MESH");
	else if(opmode == 5)
		cJSON_AddStringToObject(root,"currentMode", "CLI");

	apmib_get(MIB_MULTIPLE_LANGUAGE, (void *)tmpBuf);
	cJSON_AddStringToObject(root, "showLanguage", tmpBuf);

	apmib_get(MIB_COPYRIGHT, (void *)tmpBuf);
	sprintf(lstr,"Copyright &copy; [date] %s",tmpBuf);
	cJSON_AddStringToObject(root, "copyRight", lstr);

	apmib_get(MIB_WEB_TITLE, (void *)tmpBuf);
	cJSON_AddStringToObject(root, "webTitle", tmpBuf);

	apmib_get(MIB_CUSTOMERURL, (void *)tmpBuf);
	if(strlen(tmpBuf)>1){
		sprintf(lstr,"http://%s",tmpBuf);
		cJSON_AddStringToObject(root, "helpUrl", lstr);
		cJSON_AddBoolToObject(root, "showHelp", 1);
	}
	else{
		cJSON_AddStringToObject(root, "helpUrl", "");
		cJSON_AddBoolToObject(root, "showHelp", 0);
	}

	cJSON_AddBoolToObject(root, "hasMobile", 0);

	custom=cJSON_CreateObject();
	apmib_get(MIB_IPTV_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "IptvSupport", tmpInt);
	
	apmib_get(MIB_IPV6_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "Ipv6Support", tmpInt);
	
	apmib_get(MIB_PPPOE_SPEC_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "PppoeSpecSupport", tmpInt);

	apmib_get(MIB_PPPOE_RUSSIA_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "PppoeSpecRussia", tmpInt);

	apmib_get(MIB_WAN_LIST, (void *)tmpBuf);
	cJSON_AddStringToObject(custom, "WanTypeList",tmpBuf);

	apmib_get(MIB_WECHATQR_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "showWechatQR", tmpInt);

	apmib_get(MIB_LTE4G_SUPPORT, (void *)&tmpInt);
	cJSON_AddBoolToObject(root, "show4gFlag", tmpInt);

	cJSON_AddItemToObject(root,"custom",custom);
	
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);

	cJSON_Delete(root);
	free(output);

	return 0;
}

int getLoginCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root;
	char tmpBuf[48]={0},username[40],password[40];

	apmib_get(MIB_USER_NAME, (void *)username);
    apmib_get(MIB_USER_PASSWORD, (void *)password);
    
    root=cJSON_CreateObject();	
	getLanIp(tmpBuf);
	cJSON_AddStringToObject(root,"lanIp",tmpBuf);
	cJSON_AddStringToObject(root,"loginIp",tmpBuf);
	cJSON_AddStringToObject(root,"loginUser",username);
	cJSON_AddStringToObject(root,"loginPass",password);
	f_read("/tmp/login_flag", tmpBuf, 0, sizeof(tmpBuf));
	cJSON_AddStringToObject(root,"loginFlag",tmpBuf);

    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);

    cJSON_Delete(root);
	free(output);
    return 0;
}

//-----------------------------------------------------
int module_init()
{
	cste_hook_register("getInitConfig",getInitConfig);
	cste_hook_register("getLoginCfg",getLoginCfg);
	cste_hook_register("getCrpcConfig",getCrpcConfig);

	cste_hook_register("getOpMode",getOpMode);
	cste_hook_register("setOpMode",setOpMode);
	
	cste_hook_register("getSysStatusCfg",getSysStatusCfg);
	cste_hook_register("getNetInfo",getNetInfo);
	
	cste_hook_register("getLanguageCfg",getLanguageCfg);
	cste_hook_register("setLanguageCfg",setLanguageCfg);
	
	cste_hook_register("loginAuth",loginAuth);
	cste_hook_register("getSaveConfig",getSaveConfig);
	cste_hook_register("getLedStatus",getLedStatus);//for eth port status and usb status
	
	cste_hook_register("getWanAutoDetect",getWanAutoDetect);
	cste_hook_register("setEasyWizardCfg",setEasyWizardCfg);
	cste_hook_register("getEasyWizardCfg",getEasyWizardCfg);
#ifdef SUPPORT_REPEATER	
	cste_hook_register("getExtendConfig",getExtendConfig);
	cste_hook_register("setExtendConfig",setExtendConfig);
#endif
#if defined(SUPPORT_CPE)
	cste_hook_register("setSysModeCfg",setSysModeCfg);
#endif
	cste_hook_register("autoDhcp",autoDhcp);

#if defined(CONFIG_KL_C7180R_04339)||defined(CONFIG_KL_C7181R_04336)
	cste_hook_register("setQuickWanConfig",setQuickWanConfig);
	cste_hook_register("setQuickWiFiConfig",setQuickWiFiConfig);
	cste_hook_register("getQuickConfig",getQuickConfig);
#endif

	return 0;  
}
