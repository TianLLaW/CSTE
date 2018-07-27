/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file system.c
* @author CaryStudio
* @brief  This is a system cste topic
* @date 2017-11-10
* @warning http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.
			http://www.cnblogs.com/davygeek/p/5658968.html
* @bug
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

#include "../cstelib.h"
#include "system.h"
#include "sigHd.h"

#define LOG_MAX         16384
#define LOG_MAX_LINE    256
#define LOG_MAX_NUM     64

#if defined(CONFIG_APP_TR069)
#define strACSURLWrong  "ACS's URL can't be empty!"
#define strSSLWrong "CPE does not support SSL! URL should not start with 'https://'!"
#define strSetACSURLerror "Set ACS's URL error!"
#define strSetUserNameerror "Set User Name error!"
#define strSetPasserror "Set Password error!"
#define strSetInformEnableerror "Set Inform Enable error!"
#define strSetInformIntererror "Set Inform Interval error!"
#define strSetConReqUsererror "Set Connection Request UserName error!"
#define strSetConReqPasserror "Set Connection Request Password error!"
#define strSetCWMPFlagerror "Set CWMP_FLAG error!"
#define strGetCWMPFlagerror "Get CWMP_FLAG error!"
#define strUploaderror "Upload error!"
#define strMallocFail "malloc failure!"
#define strArgerror "Insufficient args\n"
#define strSetCerPasserror  "Set CPE Certificat's Password error!"
#endif
int GetDomainName(char *url,char domain[128])
{
    memset(domain,0,sizeof(domain));
    if(!strlen(url))
	return 0;
    if(!strncmp(url, "http://", 7))
	sscanf(url+7, "%s", domain);
    else if(!strncmp(url, "https://", 8))
	sscanf(url+8, "%s", domain);
    else
	strcpy(domain,url);
    return 1;
} 
int setNoticeCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int len,last_poit;
	char *split;
	char lan_ip_buf[30];
	char lan_ip[30], ip_range[64];
	char command[512];
	char notice_url[128], tmp2[512];
	char tmp_url1[128],tmp_url2[128],tmp_url3[128];
	int notice_enable;
	int Enabled = atoi(websGetVar(data, T("NoticeEnabled"), T("0")));
	int ret1,ret2,ret3;
	apmib_get( MIB_NOTICE_ENABLED,  (void *)&notice_enable);
	
	apmib_set(MIB_NOTICE_ENABLED, (void *)&Enabled);
	printf("[debug:notice_enable=%d]\n",notice_enable);
	if(notice_enable == 1){
		system("killall  notice");
		sleep(2);
		system("killall -9 stunnel");
		if(Enabled == 0)
			goto END;
	}    
	char *noticeURL = websGetVar(data, T("NoticeUrl"), T(""));
	GetDomainName(noticeURL,notice_url);
	apmib_set(MIB_NOTICE_URL, (void *)notice_url);
	
	char *btnName = websGetVar(data, T("BtnName"), T("Click here to continue"));
	apmib_set(MIB_NOTICE_BTN_VAL, (void *)btnName);

	char *whitelistURL1 = websGetVar(data, T("WhiteListUrl1"), T(""));
	//ret1 = GetDomainName(whitelistURL1,tmp_url1);
	/*if(strlen(whitelistURL1))
	    apmib_set(MIB_NOTICE_WHITELIST_URL1, (void *)tmp_url1);
	else
*/
	apmib_set(MIB_NOTICE_WHITELIST_URL1, (void *)whitelistURL1);
	    
	char *whitelistURL2 = websGetVar(data, T("WhiteListUrl2"), T(""));
	//ret2 = GetDomainName(whitelistURL2,tmp_url2);
	/*if(strlen(whitelistURL2))
	    apmib_set(MIB_NOTICE_WHITELIST_URL2, (void *)tmp_url2);
	else*/
	apmib_set(MIB_NOTICE_WHITELIST_URL2, (void *)whitelistURL2);

	char *whitelistURL3 = websGetVar(data, T("WhiteListUrl3"), T(""));
	//ret3 = GetDomainName(whitelistURL3,tmp_url3);
	/*if(strlen(whitelistURL3))
            apmib_set(MIB_NOTICE_WHITELIST_URL3, (void *)tmp_url3);
        else*/
	apmib_set(MIB_NOTICE_WHITELIST_URL3, (void *)whitelistURL3);

	char *ipFrom = websGetVar(data, T("IpFrom"), T(""));
	apmib_set(MIB_NOTICE_WHITELIST_SIP_START, (void *)ipFrom);

	char  *ipTo = websGetVar(data, T("IpTo"), T(""));
	apmib_set(MIB_NOTICE_WHITELIST_SIP_END, (void *)ipTo);

	int timeoutVal = atoi(websGetVar(data, T("NoticeTimeoutVal"), T("120")));
	apmib_set(MIB_NOTICE_TIMEOUT, (void *)&timeoutVal);
	

	if(strlen(ipFrom)&&strlen(ipTo))
	{
		//printf("### FUN:%s,LINE:%d\n",__FUNCTION__,__LINE__);
		memset(ip_range,0,sizeof(ip_range));
		memset(lan_ip,0,sizeof(lan_ip));
		memset(lan_ip_buf,0,sizeof(lan_ip_buf));
		apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf);
		sprintf(lan_ip,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
		for(split=lan_ip,last_poit=0;split;last_poit++,split++){
			if(last_poit==3)
				break;
			split=strchr(split,'.');
		}
		//printf("### FUN:%s,LINE:%d\n",__FUNCTION__,__LINE__);
		len=split-lan_ip;//len=strlen("192.168.1");
		//strncpy(lan_ip+len,ipFrom,strlen(ipFrom));
		lan_ip[len]='\0';
		strncpy(ip_range,lan_ip,len);
                strncpy(ip_range+len,ipFrom,strlen(ipFrom));
                len=len+strlen(ipFrom);
                ip_range[len]='-';
		strcat(lan_ip,ipTo);
		strncpy(ip_range+len+1,lan_ip,strlen(lan_ip));
	}
	
	//printf("%d\n%s\n%s\n%s\n%s\n%s\n%d\n",Enabled, noticeURL, btnName, whitelistURL1, ipFrom, ipTo, timeoutVal);
	if(strlen(whitelistURL1)||strlen(whitelistURL2)||strlen(whitelistURL3))
	{
		memset(command,0x00,sizeof(command));
		/*memset(tmp2,0x00,sizeof(tmp2));
		
		if(ret1>0)
		    strcat(tmp2,tmp_url1);
		if(ret2>0)
		{
		    strcat(tmp2,",");
		    strcat(tmp2,tmp_url2);
		}
		if(ret3>0)
                {
                    strcat(tmp2,",");
                    strcat(tmp2,tmp_url3);
                }*/	
		if(strlen(ipFrom)&&strlen(ipTo))
		{
			sprintf(command,"notice %s 3 %s %d",notice_url,ip_range,timeoutVal);
			system(command);
			printf("##################\n%s\n",command);
		}
		else
		{
			sprintf(command,"notice %s 1 %d",notice_url,timeoutVal);
			system(command);
			printf("##################\n%s\n",command);
		}
	}
	else
	{
		memset(command,0x00,sizeof(command));
		if(strlen(ipFrom)&&strlen(ipTo))
		{
			sprintf(command,"notice %s 2 %s %d",notice_url,ip_range,timeoutVal);
			system(command);
			printf("##################\n%s\n",command);
		}	
		else
		{
			sprintf(command,"notice %s %d",notice_url,timeoutVal);
			system(command);
			printf("##################\n%s\n",command);
		}
		
	} 
	goto END;

END:	
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "0", "reserv"); 
}

int getNoticeCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output, tmpBuf[65]={0}, br0addr[16]={0}, buf1[16]={0}, buf2[16]={0};
	cJSON *root=cJSON_CreateObject();
	int arraylen;
	char sip0[4],sip1[4],sip2[4],sip3[4];

	char *IntGetName[]={"NoticeEnabled", "NoticeTimeoutVal"};
	int IntGetId[]={MIB_NOTICE_ENABLED, MIB_NOTICE_TIMEOUT};
	arraylen=sizeof(IntGetName)/sizeof(char *);
	getCfgArrayInt(root, arraylen, IntGetName, IntGetId);

	char *StrGetName[]={"NoticeUrl", "BtnName", "WhiteListUrl1", "WhiteListUrl2", "WhiteListUrl3", "IpFrom", "IpTo"};
	int StrGetId[]={MIB_NOTICE_URL, MIB_NOTICE_BTN_VAL, MIB_NOTICE_WHITELIST_URL1, MIB_NOTICE_WHITELIST_URL2, MIB_NOTICE_WHITELIST_URL3, MIB_NOTICE_WHITELIST_SIP_START, MIB_NOTICE_WHITELIST_SIP_END};
	arraylen=sizeof(StrGetName)/sizeof(char *);
	getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

	getLanIp(tmpBuf);
	if(!getInAddr("br0", IP_ADDR_T, (void *)br0addr))
		sprintf(br0addr,"0.0.0.0");
	if(br0addr != "0.0.0.0" && br0addr != tmpBuf){
		sscanf(br0addr, "%[^.].%[^.].%[^.].%[^.]", sip0,sip1,sip2,sip3);
		sprintf(buf1,"%s.%s.%s", sip0,sip1,sip2);
		cJSON_AddStringToObject(root,"lanIp",buf1);
		
		sprintf(buf2,"%s", sip3);
		cJSON_AddStringToObject(root,"lanSubnet",buf2);
	}
	else{
		sscanf(tmpBuf, "%[^.].%[^.].%[^.].%[^.]", sip0,sip1,sip2,sip3);
		sprintf(buf1,"%s.%s.%s.", sip0,sip1,sip2);
		cJSON_AddStringToObject(root,"lanIp",buf1);
		
		sprintf(buf2,"%s", sip3);
		cJSON_AddStringToObject(root,"lanSubnet",buf2);

	}
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);	
	free(output);
	cJSON_Delete(root);
	return 0;
}

/**
* @note setPasswordCfg  set password configuration
* @param Setting Json Data
<pre>
{
	"admuser":	""
	"admpass":	""
}
setting parameter description
admuser:		username of admin
admpass:	password of admin
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setPasswordCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char_t *username = websGetVar(data, T("admuser"), T("admin"));
	char_t *password = websGetVar(data, T("admpass"), T(""));
	apmib_set(MIB_USER_NAME, (void *)username);
	apmib_set(MIB_USER_PASSWORD, (void *)password);
    apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "10", "reserv");    
	
#if defined(SUPPORT_MESH)
	system("sysconf updateAllMeshInfo");
#endif
	return 0;		
}

/**
* @note getPasswordCfg  get password configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"admuser":	"admin"
	"admpass":	"admin"
}
return parameter description:
admuser:		username
admpass:	password
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getPasswordCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
    int arraylen;

    char *StrGetName[]={"admuser","admpass"};
	int StrGetId[]={MIB_USER_NAME,MIB_USER_PASSWORD};
    arraylen=sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
    return 0;
}

void getCurrentTime(char *tmpbuf)
{
	char *p,buf[64]={0};
	FILE *fp = popen("date", "r");
	if(!fp) return;    
    while(fgets(buf, sizeof(buf), fp) != NULL){
        if(p=strstr(buf, "\n"))
            p[0]='\0';
    }
    pclose(fp);	
  	strcpy(tmpbuf,buf);
	return ;
}

/**
* @note NTPSyncWithHost  Synchronization  NTP with Host
* @param Setting Json Data
<pre>
{
	"hostTime":	""
}
setting parameter description
host_time:	time of host
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int NTPSyncWithHost(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char cmd[256];
	int enabled=0;	
    char_t *host_time = websGetVar(data, T("host_time"), T(""));
	
	struct timeval	new;
	char connTime[100] = {0};
	unsigned long sec;
	FILE *f;
	char buf[256];
	gettimeofday(&new, NULL);	
	
	f = fopen("/tmp/wanranchocontime", "r");
	if (f != NULL )
	{			
		fscanf(f, "%s", buf);		
		sec = atoi(buf);
		fclose(f);			
		sec = new.tv_sec - sec;			
		sprintf(connTime, "echo '%d' > tmp/preNtpConnectTime", sec);				
		system(connTime);
	}
	
    sprintf(cmd,"date -s \"%s\"", host_time);
    CsteSystem(cmd, CSTE_PRINT_CMD);
	apmib_set(MIB_NTP_ENABLED, (void *)&enabled);
	apmib_update_web(CURRENT_SETTING);
	system("echo 9 > /tmp/ntp_tmp");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	system("sysconf recordWanConnTime 1");
#ifdef CONFIG_CROND
	CsteSystem("csteSys wifiSch", CSTE_PRINT_CMD);
	CsteSystem("csteSys updateCrond", CSTE_PRINT_CMD);
#endif
}

/**
* @note setNTPCfg  set NTP configuration
* @param Setting Json Data
<pre>
{
	"tz":	""
	"ntpServerIp":		""
	"ntpClientEnabled"		""
}
setting parameter description
tz:	zone of Country
ntpServerIp:	IP of NTP server
ntpClientEnabled:	switch of NTP client
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setNTPCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char_t *tz = websGetVar(data, T("tz"), T(""));
	char_t *ntpServer = websGetVar(data, T("ntpServerIp"), T(""));
	char_t *ntpClientEnbl = websGetVar(data, T("ntpClientEnabled"), T(""));
	int enabled=0;

    if (!strcmp(ntpClientEnbl, "1")){
		apmib_set(MIB_NTP_HOSTFLAG,(void *) &enabled);//set MIB_NTP_HOSTFLAG 0
		apmib_set(MIB_NTP_SERVER_URL,(void *) ntpServer);
		enabled=1;
	}else{
		enabled=0;
	}

	apmib_set(MIB_NTP_ENABLED, (void *)&enabled);
	apmib_set(MIB_NTP_TIMEZONE, (void *)tz);

#if defined(SUPPORT_MESH)
	system("sysconf updateAllMeshInfo");
#endif	

	apmib_update_web(CURRENT_SETTING);
	set_timeZone();
	system("sysconf ntp");	
    websSetCfgResponse(mosq, tp, "0", "reserv");
}

/**
* @note getNTPCfg  get NTP configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"tz":	"UCT-8"
	"ntpServerIp":	"time.nist.gov"
	"ntpClientEnabled":	1
	"ntpHostFlag":	0
	"currentTime":	"Tue Nov  7 12:57:24 GMT 2017"
	"languageType":	"cn"
	"operationMode":	0
	"apAcBt":	"0"
}
return parameter description:
"tz":	Zone of Country
"ntpServerIp":	Server IP of NTP
"ntpClientEnabled":	Switch of NTP,0 is OFF,1 is ON
"ntpHostFlag":	NTP host flag
"currentTime":	Current time
"languageType":	Type of language
"operationMode":	Systerm mode,0:Gateway,1:Bridge,2:Repeater,3:Wisp
"apAcBt":	If support APAC or not,1 is support,0 is not support
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getNTPCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output,tmpbuf[64]={0};
    cJSON *root=cJSON_CreateObject();
    int arraylen;

	char *StrGetName[]={"tz","ntpServerIp"};
	int StrGetId[]={MIB_NTP_TIMEZONE,MIB_NTP_SERVER_URL};
    arraylen=sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

    char *ParaSetZero[]={"ntpClientEnabled","ntpHostFlag"};
	int IntGetId[]={MIB_NTP_ENABLED,MIB_NTP_HOSTFLAG};
    arraylen=sizeof(ParaSetZero)/sizeof(char *);
    getCfgArrayInt(root, arraylen, ParaSetZero,IntGetId );

	getCurrentTime(tmpbuf);
	cJSON_AddStringToObject(root,"currentTime",tmpbuf);

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpbuf);
	cJSON_AddStringToObject(root,"languageType", tmpbuf);

	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());
#if  defined(SUPPORT_APAC)
	cJSON_AddStringToObject(root,"apAcBt","1");
#else
	cJSON_AddStringToObject(root,"apAcBt","0");
#endif
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);	
	free(output);
    cJSON_Delete(root);
    return 0;
}

/**
* @note getDDNSStatus  get DDNS Status
*
* @param NULL
* @return return Json Data
<pre>
{
	"ddnsStatus":	"fail"
	"ddnsIp":	""
}
return parameter description:
"ddnsStatus":	The connection state of DDNS,success or fail
"ddnsIp":	The public address by DDNS		
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getDDNSStatus(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal, opmode,tmpBuff=0;
    char* output, tmpBuf[128],wanip[16],ddnsType[128];
    cJSON *root=cJSON_CreateObject();
	struct stat st;
	
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	apmib_get(MIB_DDNS_ENABLED, (void *)&intVal);
	if (intVal == 0){
		tmpBuff=0;
	}else {	
		if (opmode == GATEWAY_MODE) {			
			int isWanPhy_Link = get_wan_link_status("eth1");
			if(isWanPhy_Link < 0)
				tmpBuff=0;
			else {
				if (!stat("/var/ddns_ok", &st))
					tmpBuff=1;
				else
					tmpBuff=0;
			}
		}else if (opmode == WISP_MODE){
			if (!stat("/var/ddns_ok", &st))
				tmpBuff=1;
			else
				tmpBuff=0;
		}else {
			tmpBuff=0;
		}
	}
	sprintf(tmpBuf,"%d",tmpBuff);
    cJSON_AddStringToObject(root,"ddnsStatus",tmpBuf);
	apmib_get(MIB_DDNS_TYPE, (void *)ddnsType);
	if((0!=strcmp(ddnsType,"no-ip.com")) && (0!=strcmp(ddnsType,"dyndns.org"))){
		if(0==strcmp(tmpBuf,"1")){
			getWanIp(wanip);
			cJSON_AddStringToObject(root,"ddnsIPAddr",wanip);
		}else{
			cJSON_AddStringToObject(root,"ddnsIPAddr","");
		}
	}else{
		if(0==strcmp(tmpBuf,"1")){
			f_read("/var/ddns_ok", tmpBuf, 0, sizeof(tmpBuf));
			cJSON_AddStringToObject(root,"ddnsIPAddr",strstr(tmpBuf,"IP="));
		}else{
			cJSON_AddStringToObject(root,"ddnsIPAddr","");
		}
	}
	
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);				
	free(output);
    cJSON_Delete(root);
    return 0;
}

/**
* @note getDDNSCfg  get DDNS configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"ddnsEnabled":	1
	"ddnsProvider":	2
	"ddnsDomain":	""
	"ddnsAccount":	""
	"ddnsPassword":	""
}
return parameter description:
"ddnsEnabled":	Switch of DDNS
"ddnsProvider":	Provider of DDNS	0 is DynDNS, 1 is noip, 2 is 3322.org
"ddnsDomain":	Domain of DDNS
"ddnsAccount":	Username of DDNS
"ddnsPassword":	Password of DDNS
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getDDNSCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output,tmpBuf[128]={0};
    cJSON *root=cJSON_CreateObject();
    int intVal;

	apmib_get(MIB_DDNS_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"ddnsEnabled",intVal);

	apmib_get(MIB_DDNS_TYPE, (void *)tmpBuf);
    cJSON_AddStringToObject(root,"ddnsProvider",tmpBuf);

	apmib_get(MIB_DDNS_DOMAIN_NAME, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ddnsDomain", tmpBuf);

	apmib_get(MIB_CSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"csid", tmpBuf);

	apmib_get(MIB_DDNS_USER, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ddnsAccount", tmpBuf);

	apmib_get(MIB_DDNS_PASSWORD, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"ddnsPassword", tmpBuf);

	cJSON_AddNumberToObject(root,"flag",1);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);	
	free(output);
    cJSON_Delete(root);
    return 0;
}

/**
* @note setDDNSCfg  set DDNS configuration
* @param Setting Json Data
<pre>
{
	"ddnsEnabled":	"0"
	"ddnsProvider":	"0"
	"ddnsDomain":	""
	"ddnsAccount":	""
	"ddnsPassword":	""
}
setting parameter description
ddnsEnabled:		Switch of DDNS,0 is OFF,1 is ON
ddnsProvider:		Provider of DDNS,0 is DynDNS, 1 is noip, 2 is 3322.org
ddnsDomain:		Domain of DDNS
ddnsAccount:		Username of DDNS
ddnsPassword:	Password of DDNS
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"15",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setDDNSCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int ddns_enabled = atoi(websGetVar(data, T("ddnsEnabled"), T("0")));
    char *ddns_provider = websGetVar(data, T("ddnsProvider"), T(""));
    char *ddns_domain = websGetVar(data, T("ddnsDomain"), T(""));
    char *ddns_acc = websGetVar(data, T("ddnsAccount"), T(""));
    char *ddns_pass = websGetVar(data, T("ddnsPassword"), T(""));
	
	apmib_set(MIB_DDNS_ENABLED, (void *)&ddns_enabled);	
	apmib_set(MIB_DDNS_TYPE, (void *)ddns_provider);				
	apmib_set(MIB_DDNS_DOMAIN_NAME, (void *)ddns_domain);
	apmib_set(MIB_DDNS_USER, (void *)ddns_acc);				
	apmib_set(MIB_DDNS_PASSWORD, (void *)ddns_pass);

	apmib_update_web(CURRENT_SETTING);	
    system("sysconf ddns");	
    websSetCfgResponse(mosq, tp, "20", "reserv");
}

/**
* @note getSyslog  get system log
*
* @param NULL
* @return return Json Data
<pre>
{
	"syslogEnabled":	0
	"syslog":	""
}
return parameter description:
"syslogEnabled":	0 is OFF(default),1 is ON
"syslog":	Content of log
</pre>
*@author		Kris
*@date	2017-11-9
*/
void getSyslog(char *responseStr)
{
	char buf[LOG_MAX+1];

	memset(buf,0,LOG_MAX+1);
	f_read("/var/log/messages", buf, 0, sizeof(buf));
	
	if (strlen(buf) < 4)
		goto fun_end;
	strcpy(responseStr,buf);

fun_end:
	return;
}

/**
* @note getSyslogCfg  get Syslog configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"syslogEnabled":	0
	"syslog":	""
}
return parameter description:
"syslogEnabled":	Switch of syslog
"syslog":	Content of log
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getSyslogCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output,responseStr[LOG_MAX+1]={0};
	cJSON *root=cJSON_CreateObject();
	int intVal=0;

	apmib_get(MIB_SCRLOG_ENABLED, (void *)&intVal);
	if(intVal==31) intVal=1;
	cJSON_AddNumberToObject(root,"syslogEnabled",intVal);
	if(intVal==1){
		getSyslog(responseStr);
	}
	cJSON_AddStringToObject(root,"syslog",responseStr);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}

/**
* @note clearSyslog  clear Systerm log
* @param NULL
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int clearSyslog(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char tmpBuf[100];
	snprintf(tmpBuf, 100, "echo \" \" > %s", "/var/log/messages");
	system(tmpBuf);
	//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to	SDKv2.5 from kernel 2.4
#ifdef RINGLOG
	system("rm /var/log/messages.* >/dev/null 2>&1");
#endif
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note setSyslogCfg  set Systerm log configuration
* @param Setting Json Data
<pre>
{
	"syslogEnabled":	"0"
}
setting parameter description
syslogEnabled:	Switch of syslog
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setSyslogCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal = atoi(websGetVar(data, T("syslogEnabled"), T("0")));
	if (intVal==1) intVal=31;
	apmib_set(MIB_SCRLOG_ENABLED, (void *)&intVal);
	apmib_update_web(CURRENT_SETTING);
	system("sysconf syslogd");
	websSetCfgResponse(mosq, tp, "0", "reserv");
}

#if defined(CONFIG_APP_MINI_UPNP)
/**
* @note getMiniUPnPConfig  get MiniUPnP configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"upnpEnabled":	"0"
	"getUpnpTable":	""
}
return parameter description:
"upnpEnabled":	Switch of upnp,0 is OFF,1 is ON
"getUpnpTable":	Table of Upnp

</pre>
*@author		Kris
*@date	2017-11-9
*/
int getMiniUPnPConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output,responseStr[CSTEBUFSIZE]={0};
    cJSON *root=cJSON_CreateObject();
    int tmpint;
    
	apmib_get(MIB_UPNP_ENABLED, (void *)&tmpint);
	cJSON_AddNumberToObject(root,"upnpEnabled",tmpint);

	memset(responseStr, 0, sizeof(responseStr));
	FILE *fp = fopen("/tmp/upnp_info", "r");
	if(fp != NULL) {    
        fgets(responseStr, sizeof(responseStr), fp);
        fclose(fp);
    }
    cJSON_AddStringToObject(root,"getUpnpTable",responseStr);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
    return 0;
}

/**
* @note setMiniUPnPConfig  set MiniUPnP configuration
* @param Setting Json Data
<pre>
{
	"upnpEnabled":	""
}
setting parameter description
upnpEnabled:	Switch of upnp,0 is OFF,1 is ON
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setMiniUPnPConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal = atoi(websGetVar(data, T("upnpEnabled"),  T("0")));
	apmib_set(MIB_UPNP_ENABLED, (void *)&intVal);

  	if(intVal == 0)
		unlink("tmp/upnp_info");
	
	apmib_update_web(CURRENT_SETTING);
	CsteSystem("sysconf upnpd_igd", CSTE_PRINT_CMD);
    websSetCfgResponse(mosq, tp, "0", "reserv");
}
#endif

/**
* @note LoadDefSettings  load default configuration
*
* @param NULL
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"60",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int LoadDefSettings(struct mosquitto *mosq, cJSON* data, char *tp)
{
	websSetCfgResponse(mosq, tp, "60", "reserv");
#if defined(SUPPORT_MESH)
	system("csteSys reg 1 0xb8003528 24 3");//πÿ±’¬Ãµ∆¬˝…¡
	system("csteSys reg 1 0xb8003528 24 1");//πÿ±’¬Ãµ∆≥£¡¡
	system("csteSys reg 1 0xb8003528 25 2");//∫Ïµ∆øÏ…¡
#elif defined(SUPPORT_APAC)
#if defined(CONFIG_KL_C8B180A_AP0167)||defined(CONFIG_KL_CSB180A_AP0167)||defined(CONFIG_KL_C8B181A_AP0169)
	system("csteSys reg 1 0xb8003528 25 1");//πÿ±’∫Ï…´µ∆H1
#elif defined(CONFIG_KL_C8B182A_AP0170)
	system("csteSys reg 1 0xb800350c 15 1");//πÿ±’∫Ï…´µ∆
#endif	
	system("csteSys reg 1 0xb800350c 31 2");//¬Ãµ∆øÏ…¡
#endif

	CsteSystem("csteSys csnl 1 -2", CSTE_PRINT_CMD);
	int pid=fork();
	if(0 == pid)
	{
		apmib_updateDef();//…˙≥…DEF≈‰÷√
		apmib_reinit();//≥ı ºªØ≈‰÷√
		if(0 != f_exist("/mnt/custom/product.ini")){
			CsteSystem("convertIniToCfg", CSTE_PRINT_CMD);
		}
		apmib_update_web(CURRENT_SETTING);//÷––‘∞Ê∏¸–¬≈‰÷√÷¡flash
		sleep(1);
		CsteSystem("reboot", CSTE_PRINT_CMD);
		exit(1);
	}
	return 0;
}

/**
* @note RebootSystem  Reboot system
* @param NULL
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"60",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int RebootSystem(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int pid;		
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		CsteSystem("reboot", CSTE_PRINT_CMD);
		exit(1);
	}

	websSetCfgResponse(mosq, tp, "60", "reserv");
	return 0;
}


#ifdef CONFIG_SUPPORT_SCHEDULE_REBOOT
int setRebootSchd(int sche)
{   
	unsigned long cfg_sec,sec;	
	struct sysinfo info;
	char cmd[128];
	apmib_set(MIB_SCHE_DAY,(void *)&sche);
	if(sche>0){
		sysinfo(&info);
		sec = (unsigned long) info.uptime;
		cfg_sec = sche *3600-sec;
		if(cfg_sec>0){
			CsteSystem("killall sche_reboot 2>/dev/null", CSTE_PRINT_CMD);
			sprintf(cmd,"sche_reboot %ld &",(cfg_sec-sec));
			CsteSystem(cmd, CSTE_PRINT_CMD);
		}else{
			CsteSystem("reboot", CSTE_PRINT_CMD);
		}
	}else{
		CsteSystem("killall sche_reboot 2>/dev/null",CSTE_PRINT_CMD);
	}
	return 0;	
}

/**
* @note setRebootScheCfg  set Reboot schedul configuration
* @param Setting Json Data
<pre>
{
	"scheEn":		""
	"scheWeek":	""
	"scheHour":	""
	"scheMin":	""
}
setting parameter description
scheEn:		Switch of reboot schedul,0 is OFF,1 is ON
scheWeek:	Week of schedul
scheHour:	Hour of schedul
scheMin:		Minuter of schedul
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-9
*/
int setRebootScheCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	unsigned long cfgSec,sec;	 
	char buff[128];
	
	int mode = atoi(websGetVar(data,T("mode"),T("0")));
	apmib_set(MIB_REBOOTSCH_ENABLED, (void *)&mode);//0:disenable; 1:spec_time 2:count down
	CsteSystem("killall sche_reboot", CSTE_PRINT_CMD);
	if(mode==1){
		int week=atoi(websGetVar(data, T("week"), T("0")));
		int time_h=atoi(websGetVar(data, T("hour"), T("0")));
		apmib_set(MIB_REBOOTSCH_HOUR, (void *)&time_h);
		int time_m=atoi(websGetVar(data, T("minute"), T("0")));
		apmib_set(MIB_REBOOTSCH_MINUTE, (void *)&time_m);

	apmib_set(MIB_REBOOTSCH_WEEK, (void *)&week);
	}else if(mode==2){
		int hour = atoi(websGetVar(data,T("recHour"),T("0")));
		setRebootSchd(hour);
	}
	apmib_update_web(CURRENT_SETTING);	

	CsteSystem("csteSys rebootSch", CSTE_PRINT_CMD);
	CsteSystem("csteSys updateCrond", CSTE_PRINT_CMD);

    websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note getRebootScheCfg  get Reboot schedul configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"scheHour":	0
	"scheWeek":	0
	"scheMin":	0
	"scheEn":		0
	"ntpEnabled":	1
}
return parameter description:
"scheHour":	Hour of schedul
"scheWeek":	Week of schedul
"scheMin":	Minuter of schedul
"scheEn":		Switch of reboot schedul,1 is ON,0 is OFF
"ntpEnabled":	Switch of NTP,1 is ON,0 is OFF
</pre>
*@author		Kris
*@date	2017-11-9
*/
int getRebootScheCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL, buff[8],reboot_mode[16]={0};
	cJSON *root = cJSON_CreateObject();
	int intVal,mode;
	int arraylen,ntp_enable,NtpEnabled;
	apmib_get(MIB_REBOOTSCH_ENABLED,(void *)&mode);
	sprintf(reboot_mode,"%d",mode);
	cJSON_AddStringToObject(root,"mode",reboot_mode);
	//if(mode==1){
		char *IntGetName[]={ "week","hour","minute"};
		int IntGetId[]={MIB_REBOOTSCH_WEEK,MIB_REBOOTSCH_HOUR,MIB_REBOOTSCH_MINUTE};
		arraylen=sizeof(IntGetName)/sizeof(char *);
		getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
	//}else if(mode==2){
		apmib_get(MIB_SCHE_DAY,(void *)&intVal);
		cJSON_AddNumberToObject(root,"recHour",intVal);
		if(intVal>0){	
			unsigned long sec, mn, hr, day;
			struct sysinfo info;
			
			sysinfo(&info);
			sec = (unsigned long) info.uptime ;
			sec= intVal*3600-sec;
			day = sec / 86400;
			sec %= 86400;
			hr = sec / 3600;
			sec %= 3600;
			mn = sec / 60;
			sec %= 60;
			sprintf(buff,"%d;%d;%d;%d",day,hr,mn,sec);
		}else{
			sprintf(buff,"%d;%d;%d;%d",0,0,0,0);
		}
		cJSON_AddStringToObject(root,"recTime",buff);
	//}
	
	cJSON_AddStringToObject(root,"sysTime",getSysUptime());
	apmib_get(MIB_NTP_ENABLED,(void *)&ntp_enable);
	if(ntp_enable==0){
		NtpEnabled = getCmdVal("cat /tmp/ntp_tmp");	
		if(NtpEnabled==9)
			ntp_enable=1;
		else
			ntp_enable=0;
	}
	cJSON_AddNumberToObject(root,"NTPValid",ntp_enable);	
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
    return 0;
}
#endif

#if defined(CONFIG_APP_EASYCWMP)
int getTr069Cfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	cJSON *root=cJSON_CreateObject();

	char *StrGetName[]={"easycwmp_acsurl","easycwmp_acsname","easycwmp_acskey"};
	int StrGetId[]={MIB_EASYCWMP_ACSURL,MIB_EASYCWMP_ACSNAME,MIB_EASYCWMP_ACSKEY};
	int arraylen=sizeof(StrGetName)/sizeof(char *);
	getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

	char *ParaSetZero[]={"easycwmp_enable","easycwmp_cpeprot"};
	int IntGetId[]={MIB_EASYCWMP_ENABLE,MIB_EASYCWMP_PORT};
    arraylen=sizeof(ParaSetZero)/sizeof(char *);
    getCfgArrayInt(root, arraylen, ParaSetZero,IntGetId );

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	return 0;
}

int setTr069Cfg(struct mosquitto *mosq, cJSON* data, char *tp){
	char * easycwmp_enable = websGetVar(data, T("easycwmp_enable"), T(""));
	char * addEffect = websGetVar(data, T("addEffect"), T(""));
	int acs_enable=atoi(easycwmp_enable);
	apmib_set(MIB_EASYCWMP_ENABLE,(void *)&acs_enable);
	if(1 == atoi(addEffect)){
		apmib_update_web(CURRENT_SETTING);
		goto end;
	}
	
	char * easycwmp_acsurl = websGetVar(data, T("easycwmp_acsurl"), T(""));
	char * easycwmp_acsname = websGetVar(data, T("easycwmp_acsname"), T(""));
	char * easycwmp_acskey = websGetVar(data, T("easycwmp_acskey"), T(""));
	char * easycwmp_periodenable = websGetVar(data, T("easycwmp_periodenable"), T(""));
	char * easycwmp_periodupdate = websGetVar(data, T("easycwmp_periodupdate"), T(""));
	char * easycwmp_cpeport = websGetVar(data, T("easycwmp_cpeprot"), T(""));
	
	if(strlen(easycwmp_acsurl)>0)
		apmib_set(MIB_EASYCWMP_ACSURL,(void *)easycwmp_acsurl);
	if(strlen(easycwmp_acsname)>0)
		apmib_set(MIB_EASYCWMP_ACSNAME,(void *)easycwmp_acsname);
	if(strlen(easycwmp_acskey)>0)
		apmib_set(MIB_EASYCWMP_ACSKEY,(void *)easycwmp_acskey);

	if(strlen(easycwmp_cpeport)>0){
		int port = atoi(easycwmp_cpeport);
		apmib_set(MIB_EASYCWMP_PORT,(void *)&port);
	}
	apmib_update_web(CURRENT_SETTING);

	system("killall easycwmpd");
	if(!strcmp(easycwmp_enable, "1")){
		sleep(1);
		system("/bin/easycwmpd -b -f &");
	}

end:
	websSetCfgResponse(mosq, tp, "0", "reserv");
}
#endif

/**
* @note setTelnetCfg  set Telnet configuration
* @param Setting Json Data
<pre>
{
	"telnet_enabled":		"0"
}
setting parameter description
telnet_enabled:	Switch of telnet,0 is OFF(default),1 is ON
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date		2017-11-9
*/
int setTelnetCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal=atoi(websGetVar(data, T("telnet_enabled"), T("0")));
	apmib_set(MIB_TELNET_ENABLED,(void *)&intVal);
	if(intVal==1){
		system("killall telnetd 2> /dev/null");
		system("telnetd &");
	}else{
		system("killall telnetd 2> /dev/null");
	}
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note getTelnetCfg  get Telnet configuration
*
* @param NULL
* @return	return Json Data
<pre>
{
	"telnet_enabled":	0
}
return parameter description:
"telnet_enabled":	Switch of telnet,0 is OFF,1 is ON,0 is default
</pre>
*@author		Kris
*@date		2017-11-9
*/
int getTelnetCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root=cJSON_CreateObject();
	int intVal;

	apmib_get(MIB_TELNET_ENABLED,(void *)&intVal);
	cJSON_AddNumberToObject(root,"telnet_enabled",intVal);
	
	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);	
	free(output);
    cJSON_Delete(root);		
	return 0;
}

#if defined(CONFIG_APP_TR069)
extern int needReboot;
int getTR069Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int arraylen;
	
	//Int MIB data
	char *IntGetName[]={"autoexec","enable","interval","conreqport"};	
	int IntGetId[]={MIB_CWMP_ENABLED,MIB_CWMP_INFORM_ENABLE,MIB_CWMP_INFORM_INTERVAL,MIB_CWMP_CONREQ_PORT};
	arraylen=sizeof(IntGetName)/sizeof(char *);
	getCfgArrayInt(root, arraylen, IntGetName, IntGetId);

	//String MIB data
	char *StrGetName[]={"url","username","password","conreqname","conreqpw","conreqpath"};
	int StrGetId[]={MIB_CWMP_ACS_URL,MIB_CWMP_ACS_USERNAME,MIB_CWMP_ACS_PASSWORD,MIB_CWMP_CONREQ_USERNAME,MIB_CWMP_CONREQ_PASSWORD,MIB_CWMP_CONREQ_PATH};	
	arraylen=sizeof(StrGetName)/sizeof(char *);
	getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
}

void setTR069Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *strData;
	int vInt,cur_port;
	unsigned char vChar,acsurlchangeflag=0;
	unsigned int cwmp_flag,informEnble,informInterv;
	char tmpBuf[100],changeflag=0,cwmp_flag_value=1,tmpStr[256+1],origACSURL[256+1],NewACSURL[256+1],isDisConReqAuth=0;
	char orig_acsUserName[64]={0},orig_acsPassword[64]={0},new_acsUserName[64]={0},new_acsPassword[64]={0};
	char orig_ConReqUserName[64]={0},orig_ConReqPassword[64]={0},new_ConReqUserName[64]={0},new_ConReqPassword[64]={0};
	
	apmib_get( MIB_CWMP_ACS_URL, (void *)origACSURL);
#ifdef _CWMP_WITH_SSL_
	//CPE Certificat Password
	strData = websGetVar(data, T("CPE_Cert"), T(""));
	if( strData[0] )
	{
		strData = websGetVar(data, T("certpw"), T(""));
		changeflag = 1;
		if ( !apmib_set( MIB_CWMP_CERT_PASSWORD, (void *)strData))
		{
			strcpy(tmpBuf, strSetCerPasserror);
			goto setErr_tr069;
		}
		else
			goto end_tr069;
	}
#endif
	strData = websGetVar(data, T("url"), T(""));
	if ( strlen(strData)==0 )
	{
		strcpy(tmpBuf, (strACSURLWrong));
		goto setErr_tr069;
	}
#ifndef _CWMP_WITH_SSL_
	if ( strstr(strData, "https://") )
	{
		strcpy(tmpBuf, (strSSLWrong));
		goto setErr_tr069;
	}
#endif
	if ( !apmib_set( MIB_CWMP_ACS_URL, (void *)strData))
	{
		strcpy(tmpBuf, (strSetACSURLerror));
		goto setErr_tr069;
	}

	apmib_get( MIB_CWMP_ACS_URL, (void *)NewACSURL);
	if(strcmp(origACSURL, NewACSURL)){
		changeflag=1;
		acsurlchangeflag=1;
	}

	apmib_get( MIB_CWMP_ACS_PASSWORD, (void *)orig_acsUserName);
	apmib_get( MIB_CWMP_ACS_USERNAME, (void *)orig_acsPassword);

	apmib_get( MIB_CWMP_CONREQ_USERNAME, (void *)orig_ConReqUserName);
	apmib_get( MIB_CWMP_CONREQ_PASSWORD, (void *)orig_ConReqPassword);
	
	strData = websGetVar(data, T("username"), T(""));
	if ( !apmib_set( MIB_CWMP_ACS_USERNAME, (void *)strData)) {
		strcpy(tmpBuf, (strSetUserNameerror));
		goto setErr_tr069;
	}
	
	strData = websGetVar(data, T("password"), T(""));
	if ( !apmib_set( MIB_CWMP_ACS_PASSWORD, (void *)strData)) {
		strcpy(tmpBuf, (strSetPasserror));
		goto setErr_tr069;
	}
	
	strData = websGetVar(data, T("enable"), T(""));
	if ( strData[0] ) {
		informEnble = (strData[0]=='0')? 0:1;
		apmib_get( MIB_CWMP_INFORM_ENABLE, (void*)&vInt);
		if(vInt != informEnble){
			changeflag = 1;
			if ( !apmib_set( MIB_CWMP_INFORM_ENABLE, (void *)&informEnble)) {
				strcpy(tmpBuf, (strSetInformEnableerror));
				goto setErr_tr069;
			}
		}
	}
	
	strData = websGetVar(data, T("interval"), T(""));
	if ( strData[0] ) {
		informInterv = atoi(strData);
		
		if(informEnble == 1){
			apmib_get( MIB_CWMP_INFORM_INTERVAL, (void*)&vInt);

			if(vInt != informInterv){
				changeflag = 1;
				if ( !apmib_set( MIB_CWMP_INFORM_INTERVAL, (void *)&informInterv)) {
					strcpy(tmpBuf, (strSetInformIntererror));
					goto setErr_tr069;
				}
			}
		}
	}

#ifdef _TR069_CONREQ_AUTH_SELECT_
	strData = websGetVar(data, T("disconreqauth"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG2, (void *)&cwmp_flag ) )
		{
			changeflag = 1;

			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG2_DIS_CONREQ_AUTH);
			else{
				cwmp_flag = cwmp_flag | CWMP_FLAG2_DIS_CONREQ_AUTH;
				isDisConReqAuth = 1;
			}

			if ( !apmib_set( MIB_CWMP_FLAG2, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
#endif

	//if connection reuqest auth is enabled, don't handle conreqname & conreqpw to keep the old values
	if(!isDisConReqAuth)
	{
		strData = websGetVar(data, T("conreqname"), T(""));
		if ( !apmib_set( MIB_CWMP_CONREQ_USERNAME, (void *)strData)) {
			strcpy(tmpBuf, (strSetConReqUsererror));
			goto setErr_tr069;
		}
		
		strData = websGetVar(data, T("conreqpw"), T(""));
		if ( !apmib_set( MIB_CWMP_CONREQ_PASSWORD, (void *)strData)) {
			strcpy(tmpBuf, (strSetConReqPasserror));
			goto setErr_tr069;
		}
		
	}//if(isDisConReqAuth)
	
	strData = websGetVar(data, T("conreqpath"), T(""));
	apmib_get( MIB_CWMP_CONREQ_PATH, (void *)tmpStr);
	if (strcmp(tmpStr,strData)!=0){
		changeflag = 1;
		if ( !apmib_set( MIB_CWMP_CONREQ_PATH, (void *)strData)) {
			strcpy(tmpBuf, ("Set Connection Request Path error!"));
			goto setErr_tr069;
		}
	}
	
	strData = websGetVar(data, T("conreqport"), T(""));
	if ( strData[0] ) {
		cur_port = atoi(strData);
		apmib_get( MIB_CWMP_CONREQ_PORT, (void *)&vInt);
		if ( vInt != cur_port ) {
			changeflag = 1;
			if ( !apmib_set( MIB_CWMP_CONREQ_PORT, (void *)&cur_port)) {
				strcpy(tmpBuf, ("Set Connection Request Port error!"));
				goto setErr_tr069;
			}
		}
	}

/*for debug*/
	strData = websGetVar(data, T("dbgmsg"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_DEBUG_MSG);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_DEBUG_MSG;

			if ( !apmib_set( MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}

#ifdef _CWMP_WITH_SSL_
	strData = websGetVar(data, T("certauth"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_CERT_AUTH);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_CERT_AUTH;

			changeflag = 1;
			if ( !apmib_set( MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
#endif
	strData = websGetVar(data, T("sendgetrpc"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_SENDGETRPC);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_SENDGETRPC;

			if ( !apmib_set(MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
	strData = websGetVar(data, T("skipmreboot"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_SKIPMREBOOT);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_SKIPMREBOOT;

			if ( !apmib_set( MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
	strData = websGetVar(data, T("delay"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_DELAY);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_DELAY;

			if ( !apmib_set( MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
	strData = websGetVar(data, T("autoexec"), T(""));
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			int onoff_tr069 = 0;
			if(strData[0]=='0') {
				if ( cwmp_flag & CWMP_FLAG_AUTORUN )
					changeflag = 1;

				cwmp_flag = cwmp_flag & (~CWMP_FLAG_AUTORUN);
				cwmp_flag_value = 0;
			}else {
				if ( !(cwmp_flag & CWMP_FLAG_AUTORUN) )
					changeflag = 1;

				cwmp_flag = cwmp_flag | CWMP_FLAG_AUTORUN;
				cwmp_flag_value = 1;
			}

			if ( !apmib_set( MIB_CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, (strSetCWMPFlagerror));
				goto setErr_tr069;
			}
			
			onoff_tr069 = (cwmp_flag & CWMP_FLAG_AUTORUN)==0?0:1;
			apmib_set( MIB_CWMP_ENABLED, (void *)&onoff_tr069);
			
		}else{
			strcpy(tmpBuf, (strGetCWMPFlagerror));
			goto setErr_tr069;
		}
	}
/*end for debug*/
end_tr069:

	apmib_get( MIB_CWMP_ACS_PASSWORD, (void *)new_acsUserName);
	apmib_get( MIB_CWMP_ACS_USERNAME, (void *)new_acsPassword);
	
	if(orig_acsUserName[0] && orig_acsPassword[0] && new_acsUserName[0] && new_acsPassword[0]) {
		if((strcmp(orig_acsUserName, new_acsUserName)) || (strcmp(orig_acsPassword, new_acsPassword)))
			changeflag=1;
	}

	apmib_get( MIB_CWMP_CONREQ_USERNAME, (void *)new_ConReqUserName);
	apmib_get( MIB_CWMP_CONREQ_PASSWORD, (void *)new_ConReqPassword);
	if(orig_ConReqUserName[0] && orig_ConReqPassword[0] && new_ConReqUserName[0] && new_ConReqPassword[0]) {
		if((strcmp(orig_ConReqUserName, new_ConReqUserName)) || (strcmp(orig_ConReqPassword, new_ConReqPassword)))
			changeflag=1;
	}
	

	if ( changeflag ) {
		if ( cwmp_flag_value == 0 ) {  // disable TR069
			off_tr069();
			printf("disable TR069 !\n");
		} else {                       // enable TR069
			off_tr069();
			if (-1==startCWMP(acsurlchangeflag)){
				strcpy(tmpBuf, ("Start tr069 Fail *****"));
				printf("Start tr069 Fail *****\n");
				goto setErr_tr069;
			}
		}
	}


// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	apmib_update_web(CURRENT_SETTING);
	
#if defined(REBOOT_CHECK) && defined(APPLY_CHANGE_DIRECT_SUPPORT)
	if(needReboot == 1)
	{
		int pid;		
		pid=fork();
		if(0 == pid)
		{
			sleep(1);
			CsteSystem("reboot", CSTE_PRINT_CMD);
			exit(1);
		}
		return;
	}
#endif
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return;

setErr_tr069:
	websGetCfgResponse(mosq,tp,tmpBuf);
}
#endif 

int module_init()
{
	cste_hook_register("getNoticeCfg",getNoticeCfg);
	cste_hook_register("setNoticeCfg",setNoticeCfg);

	cste_hook_register("getPasswordCfg",getPasswordCfg);
	cste_hook_register("setPasswordCfg",setPasswordCfg);
	
	cste_hook_register("NTPSyncWithHost",NTPSyncWithHost);	
	cste_hook_register("getNTPCfg",getNTPCfg);
	cste_hook_register("setNTPCfg",setNTPCfg);

	cste_hook_register("getDDNSStatus",getDDNSStatus);	
	cste_hook_register("getDDNSCfg",getDDNSCfg);
	cste_hook_register("setDDNSCfg",setDDNSCfg);

	cste_hook_register("getSyslogCfg",getSyslogCfg);
	cste_hook_register("clearSyslog",clearSyslog);
	cste_hook_register("setSyslogCfg",setSyslogCfg);	
	
#if defined(CONFIG_APP_MINI_UPNP)
	cste_hook_register("getMiniUPnPConfig",getMiniUPnPConfig);
	cste_hook_register("setMiniUPnPConfig",setMiniUPnPConfig);
#endif

	cste_hook_register("LoadDefSettings",LoadDefSettings);	
	cste_hook_register("RebootSystem",RebootSystem);
	

#ifdef CONFIG_SUPPORT_SCHEDULE_REBOOT	
	cste_hook_register("getRebootScheCfg",getRebootScheCfg);
	cste_hook_register("setRebootScheCfg",setRebootScheCfg);
#endif

#if defined(CONFIG_APP_EASYCWMP)
	cste_hook_register("getTr069Cfg",getTr069Cfg);
	cste_hook_register("setTr069Cfg",setTr069Cfg);
#endif
	
	cste_hook_register("getTelnetCfg",getTelnetCfg);
	cste_hook_register("setTelnetCfg",setTelnetCfg);
	
#if defined(CONFIG_APP_TR069)
	cste_hook_register("getTR069Config",getTR069Config);
	cste_hook_register("setTR069Config",setTR069Config);
#endif

	return 0;
}
