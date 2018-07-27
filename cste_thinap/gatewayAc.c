#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <linux/kernel.h> 
#include "manageAgent.h"
#include "../cstelib.h"
#include "sigHd.h"


static sigjmp_buf jmpbuf;

char *vap0_attr[]={W24G_IF,W24G_IF_VA1,W24G_IF_VA2,W24G_IF_VA3,W24G_IF_VA4};
#if defined (ONLY_5G_SUPPORT) || defined (FOR_DUAL_BAND)
char *vap1_attr[]={W58G_IF,W58G_IF_VA1,W58G_IF_VA2,W58G_IF_VA3,W58G_IF_VA4};
#endif

MSG_HANDLER_FUN handerList[]={
	{ "SetUpgrade",			SetUpgrade		},
	{ "SetCheckTime",		SetCheckTime	},
	{ "SetRadioConfig",		SetRadioConfig	},
	{ "SetWlanConfig",		SetWlanConfig	},
	{ "SetSysConfig",		SetSysConfig	},
	{ "SetReset",			SetReset		},
	{ "SetReboot",			SetReboot		}
};

static void alarm_func()
{
     siglongjmp(jmpbuf, 1);
}
struct hostent *gngethostbyname(char *HostName, int timeout)
{
     struct hostent *lpHostEnt;
 
     signal(SIGALRM, alarm_func);
     if(sigsetjmp(jmpbuf, 1) != 0)
     {
           alarm(0);
           signal(SIGALRM, SIG_IGN);
           return NULL;
     }
	 
     alarm(timeout);
     lpHostEnt = gethostbyname(HostName);
     signal(SIGALRM, SIG_IGN);
 
     return lpHostEnt;
}

//buildDate Handle for gatewayAc,format : 20171117
void DateHandle(char *tmpbuf,char D_buf[32])
{
	int month;
	char *token,*year,*day;
	char *Jan = "Jan",*Feb = "Feb",*Mar = "Mar",*Apr = "Apr",*May = "May",*Jun = "Jun";
	char *Jul = "Jul",*Aug = "Aug",*Sep = "Sep",*Oct = "Oct",*Nov = "Nov",*Dec = "Dec";
	token= strtok(tmpbuf, " ");
	if(strcmp(token,Jan)==0){month=1;}
	else if(strcmp(token,Feb)==0){month=2;}
	else if(strcmp(token,Mar)==0){month=3;}
	else if(strcmp(token,Apr)==0){month=4;}
	else if(strcmp(token,May)==0){month=5;}
	else if(strcmp(token,Jun)==0){month=6;}
	else if(strcmp(token,Jul)==0){month=7;}
	else if(strcmp(token,Aug)==0){month=8;}
	else if(strcmp(token,Sep)==0){month=9;}
	else if(strcmp(token,Oct)==0){month=10;}
	else if(strcmp(token,Nov)==0){month=11;}
	else if(strcmp(token,Dec)==0){month=12;}
	else {month=0;return;}
	token = strtok(NULL," ");
	day = token;
	
	token = strtok(NULL," ");
	year = token;
	
	memset(D_buf,'\0',sizeof(D_buf));
	sprintf(D_buf,"%s%d%s",year,month,day);
	return ;
}

int init_tcp_client(void)
{
	int sock;
    struct sockaddr_in addr;
	struct hostent *host;
	char acaddr[TEMP_BUF_SIZE] = {0};
	char ac_port[TEMP_BUF_SIZE] = {0};
	int acport = 0;

	apmib_get(MIB_GATEWAYAC_HOSTPATH, (void *)acaddr);
	host = gngethostbyname(acaddr,1);
	if(host == NULL)
	{
		//printf("gngethostbyname fail!\n");
		return -1;		
	}
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        perror("socket");
		return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));
	apmib_get(MIB_GATEWAYAC_PORT, (void *)ac_port);
	acport=atoi(ac_port);
	if(acport == DEFAULT_HTTP_PORT || acport == 0)
	{
		acport = DEFAULT_GATEWAY_PORT;
	}
    addr.sin_port = htons(acport);

    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        perror("connect");
        close(sock);
		return -1;  
    }

	return sock;	
}

int add_wlan_config(cJSON *root, char *wlan_interface)
{
	cJSON *Wlan = NULL, *SSIDS = NULL, *SSID = NULL;
	char wlan_if[32]={0}, tmpBuf[128]={0};
	int i, tmpInt, wlan_disabled=0,StaNum=0;

	if(strcmp(wlan_interface,"APS2G")==0){
		strcpy(wlan_if, W24G_IF);
	}
#if defined (ONLY_5G_SUPPORT) || defined (FOR_DUAL_BAND)
	else
	{
		strcpy(wlan_if, W58G_IF);
	}
#endif
	SetWlan_idx(wlan_if);
	Wlan = cJSON_CreateObject();
	
	apmib_get("WiFiOff",  (void *)&wlan_disabled);
	sprintf(tmpBuf,"%d",wlan_disabled);
	cJSON_AddStringToObject(Wlan,"WlanStatus",tmpBuf);

	apmib_get(MIB_WLAN_CHANNEL,(void *)&tmpInt);
	sprintf(tmpBuf,"%d",tmpInt);
	cJSON_AddStringToObject(Wlan,"Channel", tmpBuf);

	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)tmpBuf);
	cJSON_AddStringToObject(Wlan,"CountryCode", tmpBuf);

	apmib_get(MIB_WLAN_RFPOWER_SCALE,(void *)&tmpInt);
	if(0 == tmpInt) sprintf(tmpBuf,"%d",100);
	else if(1 == tmpInt) sprintf(tmpBuf,"%d",75);
	else if(2 == tmpInt) sprintf(tmpBuf,"%d",50);
	else if(3 == tmpInt) sprintf(tmpBuf,"%d",35);
	else if(4 == tmpInt) sprintf(tmpBuf,"%d",15);
	else sprintf(tmpBuf,"%d",100);
	cJSON_AddStringToObject(Wlan,"TxPower", tmpBuf);

	cJSON_AddStringToObject(Wlan,"SSIDNUM", "1");
	
	apmib_get(MIB_WLAN_CHANNEL_BONDING,(void *)&tmpInt);
	sprintf(tmpBuf,"%d",tmpInt==2?1:tmpInt);
	cJSON_AddStringToObject(Wlan,"HT_BW", tmpBuf);

	SSIDS = cJSON_CreateArray();
	for(i=0;i<3;i++){
		SSID = cJSON_CreateObject();
		if(0==strcmp(wlan_interface,"APS2G")){
			strcpy(wlan_if,vap0_attr[i]);
		}
#if defined (ONLY_5G_SUPPORT) || defined (FOR_DUAL_BAND)
		else if(0==strcmp(wlan_interface,"APS5G"))
		{
			strcpy(wlan_if,vap1_attr[i]);
		}
#endif
		SetWlan_idx(wlan_if);
		
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		sprintf(tmpBuf,"%d",wlan_disabled);
		cJSON_AddStringToObject(SSID,"SsidStatus",tmpBuf);
		if(strcmp(tmpBuf,"1")==0){
			strcpy(tmpBuf,"");
		}else{
			apmib_get( MIB_WLAN_SSID, (void *)tmpBuf);
			tmpInt=getStaAssociatedNum(wlan_if);
			StaNum+=tmpInt==-1?0:tmpInt;
		}
		
		cJSON_AddStringToObject(SSID,"SSID",tmpBuf);

		apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&tmpInt);
		sprintf(tmpBuf,"%d",tmpInt);
		cJSON_AddStringToObject(SSID,"HideSSID",tmpBuf);

		apmib_get(MIB_WLAN_BLOCK_RELAY,(void *)&tmpInt);
		sprintf(tmpBuf,"%d",tmpInt);
		cJSON_AddStringToObject(SSID,"NoForward", tmpBuf);

		apmib_get(MIB_MAXSTANUM,(void *)&tmpInt);
		sprintf(tmpBuf,"%d",tmpInt);
		cJSON_AddStringToObject(SSID,"MaxStaNum", tmpBuf);
		
		cJSON_AddStringToObject(SSID,"VlanID", "0");

		apmib_get( MIB_WLAN_ENCRYPT, (void *)&tmpInt);
		if(tmpInt==ENCRYPT_DISABLED){
			cJSON_AddStringToObject(SSID,"EncrypType","0");
			cJSON_AddStringToObject(SSID,"WlanKey","");
		}else{
			apmib_get( MIB_WLAN_WPA_PSK, (void *)tmpBuf);
			cJSON_AddStringToObject(SSID,"EncrypType","1");
			cJSON_AddStringToObject(SSID,"WlanKey",tmpBuf);
		}
		
		cJSON_AddItemToArray(SSIDS,SSID);
	}
	sprintf(tmpBuf, "%d", StaNum);
	cJSON_AddStringToObject(Wlan, "StaNum", tmpBuf);
	
	cJSON_AddItemToObject(Wlan,"SSIDS",SSIDS);
	cJSON_AddItemToObject(root,wlan_interface,Wlan);
	
	return 0;
}

void assemble_heart_json_data(char *action,char *http_data)
{
	char buf[32]={0};
	char T_buf[32]={0};
	char time[TEMP_BUF_SIZE] = {0};
	char apmac[CSTE_MAC_STR_LEN] = {0};
	char apip[CSTE_IP_STR_LEN] = {0};
	char tmpBuf[TEMP_BUF_SIZE] = {0};
	cJSON *root = cJSON_CreateObject();
	char *http_b = NULL;
	struct sysinfo info;
	
	sprintf(apmac,"%s",getLanMac());
	cJSON_AddStringToObject(root, "apMac", apmac);

	if(!getInAddr("br0", IP_ADDR_T, (void *)apip))
		sprintf(apip,"0.0.0.0");
	cJSON_AddStringToObject(root, "apIp", apip);

	getCmdStr("date +\"%Y-%m-%d %H:%M:%S\"", time, sizeof(time));
	cJSON_AddStringToObject(root, "timeStamp", time);

	cJSON_AddStringToObject(root, "upTime", getSysUptime());
	
	cJSON_AddStringToObject(root, "action", action);
	
	cJSON_AddStringToObject(root, "version", ACVERSION);

#if defined(FOR_DUAL_BAND)
	cJSON_AddStringToObject(root, "apType", "3");
	add_wlan_config(root, "APS2G");
	add_wlan_config(root, "APS5G");
#else
#if defined(ONLY_5G_SUPPORT)
	cJSON_AddStringToObject(root, "apType", "2");
	add_wlan_config(root, "APS5G");
#else
	cJSON_AddStringToObject(root, "apType", "1");
	add_wlan_config(root, "APS2G");
#endif
#endif

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_CSID, (void *)buf);
	cJSON_AddStringToObject(root,"csid",buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_SOFTWARE_VERSION, (void *)buf);
	cJSON_AddStringToObject(root,"softVer",buf);
	
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%d",PRODUCT_SVN);
	cJSON_AddStringToObject(root,"svnNum",buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_HARDWARE_VERSION, (void *)buf);
	cJSON_AddStringToObject(root,"softModel",buf);

	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%s",__DATE__);
	DateHandle(buf,T_buf);
	cJSON_AddStringToObject(root,"buildDate",T_buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_USER_NAME, (void *)buf);
	cJSON_AddStringToObject(root,"userName",buf);
	
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_USER_PASSWORD, (void *)buf);
	cJSON_AddStringToObject(root,"password",buf);
	
	//sche reboot
	cJSON *schJson = cJSON_CreateObject();
	int iMode=0,ischeWeek=0,ischeHour=0,ischeMn,count_down=0;
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_REBOOTSCH_ENABLED,(void *)&iMode);
	sprintf(buf,"%d",iMode);
	cJSON_AddStringToObject(schJson,"mode",buf);
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_REBOOTSCH_WEEK,(void *)&ischeWeek);
	switch(ischeWeek){
		case 7:
			ischeWeek=128;
			break;
		case 6:
			ischeWeek=64;
			break;
		case 5:
			ischeWeek=32;
			break;
		case 4:
			ischeWeek=16;
			break;
		case 3:
			ischeWeek=8;
			break;
		case 2:
			ischeWeek=4;
			break;
		case 1:
			ischeWeek=2;
			break;
		case 0:
			ischeWeek=256;
			break;
	}
	sprintf(buf,"%d",ischeWeek);
	cJSON_AddStringToObject(schJson,"week",buf);
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_REBOOTSCH_HOUR,(void *)&ischeHour);
	sprintf(buf,"%d",ischeHour);
	cJSON_AddStringToObject(schJson,"hour",buf);	
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_REBOOTSCH_MINUTE,(void *)&ischeMn);
	sprintf(buf,"%d",ischeMn);
	cJSON_AddStringToObject(schJson,"minute",buf);
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_SCHE_DAY,(void *)&count_down);
	sprintf(buf,"%d",count_down);
	cJSON_AddStringToObject(schJson,"recHour",buf);
	cJSON_AddItemToObject(root,"rebooSchedule",schJson);
	
	memset(buf,'0',sizeof(buf));
	getLanIp(buf);
	cJSON_AddStringToObject(root,"ipAddr",buf);

	memset(buf,'0',sizeof(buf));
	getLanNetmask(buf);
	cJSON_AddStringToObject(root,"netMask",buf);

	memset(buf,'0',sizeof(buf));
	getRealGateway(buf);
	cJSON_AddStringToObject(root,"gateway",buf);
	
	memset(buf,'0',sizeof(buf));
	strcpy(buf,getDns(1));
	cJSON_AddStringToObject(root,"lan_dns",buf);
	cJSON_AddStringToObject(root,"pridns",buf);
	
	memset(buf,'0',sizeof(buf));
	strcpy(buf,getDns(2));
	cJSON_AddStringToObject(root,"secdns",buf);
	
	http_b=cJSON_Print(root);
	cJSON_Delete(root);

	strcpy(http_data,http_b);
	//printf("http_data===%s\n",http_data);

	free(http_b);
}

void assemble_action_response_json_data(char *action,char *http_data,AUTH_STATE result)
{
	char apmac[CSTE_MAC_STR_LEN] = {0};
	char apip[CSTE_IP_STR_LEN] = {0};
	cJSON *root = cJSON_CreateObject();
	char *http_b = NULL;
	
	sprintf(apmac,"%s",getLanMac());

	cJSON_AddStringToObject(root, "apMac", apmac);
	
	cJSON_AddStringToObject(root, "action", action);
	
	cJSON_AddNumberToObject(root, "status", result);

	http_b=cJSON_Print(root);
	
	cJSON_Delete(root);

	strcpy(http_data,http_b);

	free(http_b);
}



int server_send(int sock, char *w_buff, fd_set *rdfds, int timeout)
{
	int ret = 0;
	struct timeval tv;

	FD_ZERO(rdfds);
	FD_SET(sock, rdfds);
	tv.tv_sec = timeout;
	tv.tv_usec = 500000;

	if(send(sock, w_buff, strlen(w_buff), 0) < 0){
		perror("send");
		goto end;
	}
	ret = select(sock + 1, rdfds, NULL, NULL, &tv);

end:
	return ret;
}

int connect_gatewayac(int sock,char *action, char *http_data,char *r_buff)
{
	fd_set rdfds;
	int ret = 0, recvLen = 0;
	char http_buff[MAX_BUF_SIZE]={0};
	char acPort[SMALL_BUF_SIZE] = {0};
	char actpath[TEMP_BUF_SIZE] = {0};
	char hostpath[TEMP_BUF_SIZE] = {0};
	
	memset(r_buff, 0, MAX_BUF_SIZE);

	apmib_get(MIB_GATEWAYAC_PORT, (void *)acPort);
	apmib_get(MIB_GATEWAYAC_ACTPATH, (void *)actpath);
	apmib_get(MIB_GATEWAYAC_HOSTPATH, (void *)hostpath);
	
	snprintf(http_buff,MAX_BUF_SIZE,"POST %s HTTP/1.1\r\nHost: %s:%s\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", 
				actpath, hostpath, acPort, strlen(http_data),http_data);

	//printf("connect_gatewayAc:http_buff:%s\n", http_buff);

	ret =  server_send(sock, http_buff, &rdfds, 1);

	if(ret < 0) 
		perror("select");
	else if(ret == 0) 
		printf("tcp sock timeout\n");
	else{
		if(FD_ISSET(sock, &rdfds)){
			recvLen = recv(sock, r_buff, MAX_BUF_SIZE, 0); 
			//printf("r_buff=%s, len=%d.\n",r_buff, recvLen);
		}
	}
end:
	return recvLen;  
}

int gatewayac_msg_process(char *http_data,char *r_buff, int recvLen,char *action)
{
	int i,arraylen;
	
	int code;
	sscanf(r_buff,"%*s %d %*s", &code);
	if(200==code)
	{  
		char *r_data = NULL;
		if( !(r_data = strstr(r_buff, "{")) )
		{
			snprintf(action,TEMP_BUF_SIZE,SESSIONOVER);
			printf("No Recv Data\n");
		}
		else
		{
			cJSON *root = NULL;
			char *output = (char *)malloc(recvLen); 		
			char *pAction = NULL,*key=NULL;

			memset(output,0x00, recvLen);
			strcpy(output, r_data);
			root = cJSON_Parse(output);
			free( output );
			if(root==NULL)
			{
				printf("Recv Error Data!\n");
				snprintf(action,TEMP_BUF_SIZE,SESSIONOVER);
				return -1;
			}

			key = websGetVar(root, T("key"), T(""));
			pAction = websGetVar(root, T("action"), T(SESSIONOVER));

			if( 0 == strcmp( pAction, "SessionOver") )
			{
				snprintf(action,TEMP_BUF_SIZE,SESSIONOVER);
				goto end;
			}
			
			if( strcmp(key, "csapkey2017") == 0)
			{
				arraylen = sizeof(handerList)/sizeof(MSG_HANDLER_FUN);
				for(i=0; i<arraylen; i++)
				{
					if( 0 == strcmp( pAction, handerList[i].action) )
					{
						handerList[i].fun(pAction, http_data, root);
						assemble_action_response_json_data(pAction,http_data,AUTH_SUCCESS);
					}
				}
			}else
			{
				assemble_action_response_json_data(pAction,http_data,AUTH_FAIL);
			}
end:
			cJSON_Delete(root);
		}
	}
	else
	{
		printf("Recv Error Data!\n");
		strcpy(action, SESSIONOVER);
	}
}

void gatewayac_handler(void)
{
	int sock = init_tcp_client();
	char rec_buff[MAX_BUF_SIZE] = {0};
	char action[TEMP_BUF_SIZE] = {0};
	char http_data[MAX_BUF_SIZE] ={0};
	int buff_len = 0;

	if (sock < 0)
	{
		printf("gatewayac_handler:init_tcp_client error!\n");
		return;
	}

	snprintf(action,TEMP_BUF_SIZE,ACTION_GET);

	assemble_heart_json_data(action,http_data);
	while(strcmp(action, SESSIONOVER))
	{
		buff_len = connect_gatewayac(sock,action,http_data,rec_buff);
		if (buff_len > 0)
		{
			gatewayac_msg_process(http_data,rec_buff,buff_len,action);
		}else{
			snprintf(action,TEMP_BUF_SIZE,SESSIONOVER);
		}
	}
	close(sock);
}


