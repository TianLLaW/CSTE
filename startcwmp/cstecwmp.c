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
#include "cstecwmp.h"
#include "sigHd.h"


int cwmp_config_local(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL,local_port[128]={0};
	int arraylen,port;

	char if_wan[32]={0};
	getWanIfNameCs(if_wan);
	
	cJSON *root=cJSON_CreateObject(); 
	cJSON_AddStringToObject(root,"logging_level", LOCAL_logging_level);
	cJSON_AddStringToObject(root,"interface", if_wan);

	apmib_get(MIB_EASYCWMP_PORT, (void *)&port);
	sprintf(local_port,"%d",port);
	cJSON_AddStringToObject(root,"port", local_port);
	
	 //str type mib
    char *StrGetName[]={"username", "password"};
	int  StrGetId[]={ MIB_EASYCWMP_CPE_NAME,  MIB_EASYCWMP_CPE_KEY};
    arraylen = sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);
	
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int cwmp_config_acs(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL;
	cJSON *root=cJSON_CreateObject();
	int arraylen;
 
	//str type mib
    char *StrGetName[]={"url","username","password","periodic_time"};
	int  StrGetId[]={ MIB_EASYCWMP_ACSURL,MIB_EASYCWMP_ACSNAME,MIB_EASYCWMP_ACSKEY,MIB_EASYCWMP_PERIODTIME};
    arraylen = sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

	//int type mib
	char * IntGetName[]={"periodic_enable","periodic_interval"};
	int IntGetId[]={MIB_EASYCWMP_PERIODENABLE,MIB_EASYCWMP_PERIODINT};
    arraylen = sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);
	
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int easycwmp(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL;
	cJSON *root;
	char PeriodicInformInterval[8] = "100";
	char tmpBuf[256] = {0},buf[256]={0},wanip[16];	
	
	char *cmd = websGetVar(data, T("command"), T(""));
	char *class = websGetVar(data, T("class"), T(""));
	char *parameter = websGetVar(data, T("parameter"), T(""));
	char *argument = websGetVar(data, T("argument"), T(""));

	CSTE_DEBUG("cmd=%s, class=%s, parameter=%s, argument=%s\n", cmd, class, parameter,argument);

	if ( 0 == strcmp( cmd, "inform" ) ){
		if (0 == strcmp( class, "device_id" )){
			CSTE_DEBUG("begin get the parameter value*****\n");
			root = cJSON_CreateObject(); 
			int arraylen;

			char * StrGetName[]={"manufacturer"};
			int StrGetId[]={MIB_HOST_NAME};
			arraylen = sizeof(StrGetName)/sizeof(char *);
			getCfgArrayStr(root, arraylen, StrGetName, StrGetId);
			
			cJSON_AddStringToObject(root,"product_class", PRODUCT_CLASS);
			cJSON_AddStringToObject(root,"serial_number", SERIAL_NUMBER);
			if(getIfMac6("br0", tmpBuf)<0)
				strcpy(tmpBuf,"F42853");
			cJSON_AddStringToObject(root,"oui", tmpBuf);
		}
		else if(0 == strcmp( class, "parameter" )){
			root = cJSON_CreateArray();
			cJSON *p1,*p2,*p3,*p4,*p5,*p6,*p7,*p8,*p9,*p10,*p11;
			cJSON_AddItemToArray(root,p1=cJSON_CreateObject());
			memset(tmpBuf,0x00,sizeof(tmpBuf));
			apmib_get(MIB_HARDWARE_VERSION, (char *)tmpBuf);
			cJSON_AddStringToObject(p1,"parameter", "Device.DeviceInfo.HardwareVersion");
			cJSON_AddStringToObject(p1,"value", tmpBuf);
			cJSON_AddStringToObject(p1,"type", "xsd:string");
			cJSON_AddStringToObject(p1,"fault_code", "");
			
			cJSON_AddItemToArray(root,p2=cJSON_CreateObject());
			cJSON_AddStringToObject(p2,"parameter", "Device.DeviceInfo.Manufacturer");
			cJSON_AddStringToObject(p2,"value", "HUMAX");
			cJSON_AddStringToObject(p2,"type", "xsd:string");
			cJSON_AddStringToObject(p2,"fault_code", "");

			cJSON_AddItemToArray(root,p3=cJSON_CreateObject());
			cJSON_AddStringToObject(p3,"parameter", "Device.DeviceInfo.ManufacturerOUI");
			if(getIfMac6("br0", tmpBuf)<0)
				strcpy(tmpBuf,"F42853");
			cJSON_AddStringToObject(p3,"value", tmpBuf);
			cJSON_AddStringToObject(p3,"type", "xsd:string");
			cJSON_AddStringToObject(p3,"fault_code", "");

			cJSON_AddItemToArray(root,p4=cJSON_CreateObject());
			cJSON_AddStringToObject(p4,"parameter", "Device.DeviceInfo.ProductClass");
			cJSON_AddStringToObject(p4,"value", PRODUCT_CLASS);
			cJSON_AddStringToObject(p4,"type", "xsd:string");
			cJSON_AddStringToObject(p4,"fault_code", "");
			
			cJSON_AddItemToArray(root,p6=cJSON_CreateObject());
			cJSON_AddStringToObject(p6,"parameter", "Device.DeviceInfo.SerialNumber");
			cJSON_AddStringToObject(p6,"value", SERIAL_NUMBER);
			cJSON_AddStringToObject(p6,"type", "xsd:string");
			cJSON_AddStringToObject(p6,"fault_code", "");
			
			cJSON_AddItemToArray(root,p7=cJSON_CreateObject());
			memset(tmpBuf,0x00,sizeof(tmpBuf));
			sprintf(tmpBuf, "%s.%d", PRODUCT_VER, PRODUCT_SVN);
			cJSON_AddStringToObject(p7,"parameter", "Device.DeviceInfo.SoftwareVersion");
			cJSON_AddStringToObject(p7,"value", tmpBuf);
			cJSON_AddStringToObject(p7,"type", "xsd:string");
			cJSON_AddStringToObject(p7,"fault_code", "");

			cJSON_AddItemToArray(root,p9=cJSON_CreateObject());
			memset(tmpBuf,0x00,sizeof(tmpBuf));
			apmib_get(MIB_EASYCWMP_PORT,(void *)&tmpBuf);
			getWanIp(wanip);
			sprintf(buf,"http://%s:%s",wanip,tmpBuf);
			cJSON_AddStringToObject(p9,"parameter", "Device.ManagementServer.ConnectionRequestURL");
			cJSON_AddStringToObject(p9,"value", buf);
			cJSON_AddStringToObject(p9,"type", "xsd:string");
			cJSON_AddStringToObject(p9,"fault_code", "");

			apmib_get(MIB_EASYCWMP_PARAMETERKEY,(void *)&tmpBuf);
			cJSON_AddItemToArray(root,p10=cJSON_CreateObject());
			cJSON_AddStringToObject(p10,"parameter", "Device.ManagementServer.ParameterKey");
			cJSON_AddStringToObject(p10,"value", tmpBuf);
			cJSON_AddStringToObject(p10,"type", "xsd:string");
			cJSON_AddStringToObject(p10,"fault_code", "");

		}
	}
	
	else if (0 == strcmp( cmd, "add" )){
		
	}
	else if (0 == strcmp( cmd, "delete" )){
		
	}
	else if (0 == strcmp( cmd, "update_value_change" )){
		root = cJSON_CreateObject();
		CSTE_DEBUG("the cmd =[update_value_change]\n");
	}
	else if (0 == strcmp( cmd, "check_value_change" )){
		
	}else if (0 == strcmp( cmd, "apply")){
		root = cJSON_CreateObject();//after inform the cmd==apply
	}
	
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int cwmp_DeviceInfo(struct mosquitto *mosq, cJSON* data, char *tp){
	struct sysinfo s_sysram;
	int error;
	unsigned long freeram,totalram,uptime;
	char ramFree[256]={0}, ramtotal[256]={0}, inittime[256]={0}, syslg[16]={0}, version[32] = {0};
	char *action = websGetVar(data, T("action"), T(""));

	if(strcmp(action,"get")==0){//获取DeviceInfo
		char *output = NULL,cpu[32]={0};
		cJSON *root=cJSON_CreateArray();
		int arraylen,addlen;
		
		char * StrGetName[]={DINFO_HD"HardwareVersion"};
		
		int StrGetId[]={MIB_HARDWARE_VERSION};
		
		arraylen = sizeof(StrGetName)/sizeof(char *);		
		addObjectToArray(root,arraylen, StrGetName, StrGetId);

		error = sysinfo(&s_sysram);//获取时间和RAM值
		if(error){
			dprintf("%s get system information failure \n","cwmp_DeviceInfo()");
		}
		freeram = (unsigned long) s_sysram.freeram/1024;
		totalram = (unsigned long) s_sysram.totalram/1024;
		uptime = (unsigned long) s_sysram.uptime;
		sprintf(ramFree, "%d KB", freeram);
		sprintf(ramtotal, "%d KB", totalram);
		sprintf(inittime, "%d s", uptime);;

		apmib_get_bool(MIB_SCRLOG_ENABLED,syslg);
		getCurrentCPU(cpu);
		sprintf(version, "%s.%d", PRODUCT_VER, PRODUCT_SVN);
		
		char * StrAddParameter[]={DINFO_HD"ManufacturerOUI",\
								DINFO_HD"ProductClass",\
								DINFO_HD"SerialNumber",\
								DINFO_HD"UpTime",\
								DINFO_HD"MemoryStatus.Total",\
								DINFO_HD"MemoryStatus.Free",\
								DINFO_HD"X_HUMAX_SystemLogEnable",\
								DINFO_HD"ProcessStatus.CPUUsage",\
								DINFO_HD"SoftwareVersion",\
								DINFO_HD"AdditionalSoftwareVersion",\
								DINFO_HD"VendorLogFile.1.Name",\
								DINFO_HD"ModelName",\
								DINFO_HD"Manufacturer"};

		char * StrAddValue[]={"000378",\
							PRODUCT_CLASS,\
							SERIAL_NUMBER,\
							inittime,\
							ramtotal,\
							ramFree,\
							syslg,\
							cpu,\
							version,\
							PRODUCT_DATE,\
							"/var/log/messages",\
							MODEL_NAME,\
							"HUMAX"};
		
		addlen = sizeof(StrAddParameter)/sizeof(char *);
		addPandValueToArray(root,addlen,StrAddParameter,StrAddValue);
		
		output =cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{//DeviceInfo设置syslog开关
		int enable;
		char *output = NULL;
		
		char * Enable = websGetVar(data, T(DINFO_HD"X_HUMAX_SystemLogEnable"), T(""));
		
		apmib_get(MIB_SCRLOG_ENABLED, (void *)&enable);
		if(!strcmp(Enable,"TRUE")){
			enable |=(1|2|4|8|16);
		}else{
			enable &= ~1;
			
		}
		apmib_set(MIB_SCRLOG_ENABLED,(void *)&enable);
			
		apmib_update_web(CURRENT_SETTING);
		system("sysconf syslogd");

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_ManagementServer(struct mosquitto *mosq, cJSON* data, char *tp)
{
 	char *output = NULL;
	char *action = websGetVar(data, T("action"), T(""));

	if(strcmp(action,"get")==0){//获取acs参数
		cJSON *root=cJSON_CreateArray();
		int arraylen,cpe_port;
		char wanip[16],enablecwmp[16]={0},periodicinformenable[16]={0},tmpBuf[256]={0},buf[256]={0};
		char * StrGetName[] = {MANAG_HD"URL",\
							MANAG_HD"Username",\
							MANAG_HD"PeriodicInformTime", \
							MANAG_HD"ParameterKey", \
							MANAG_HD"ConnectionRequestUsername",\
							MANAG_HD"ConnectionRequestPassword"};//获取字符型MIB添加到JSON数组
							
		int StrGetId[] = {MIB_EASYCWMP_ACSURL,\
						MIB_EASYCWMP_ACSNAME,\
						MIB_EASYCWMP_PERIODTIME,\
						MIB_EASYCWMP_PARAMETERKEY,\
						MIB_EASYCWMP_CPE_NAME,\
						MIB_EASYCWMP_CPE_KEY};
		
		arraylen = sizeof(StrGetName)/sizeof(char *);
		addObjectToArray(root, arraylen, StrGetName, StrGetId);	
	
		apmib_get_bool(MIB_EASYCWMP_ENABLE,enablecwmp);
		apmib_get_bool(MIB_EASYCWMP_PERIODENABLE,periodicinformenable);

		apmib_get(MIB_EASYCWMP_PORT,(void *)&cpe_port);
		getWanIp(wanip);
		sprintf(buf,"http://%s:%d",wanip,cpe_port);

		char * StrName[]={MANAG_HD"EnableCWMP",\
						MANAG_HD"PeriodicInformEnable",\
						MANAG_HD"UpgradesManaged",\
						MANAG_HD"ConnectionRequestURL", \
						MANAG_HD"Password"};

		char * GetId[] = { enablecwmp,\
						periodicinformenable,\
						"FALSE",\
						buf, \
						""};

		int leng = sizeof(StrName)/sizeof(char *);
		addPandValueToArray(root,leng,StrName,GetId);
		
		char *IntGetName[]={MANAG_HD"PeriodicInformInterval",\
							MANAG_HD"CWMPRetryMinimumWaitInterval",\
							MANAG_HD"CWMPRetryIntervalMultiplier"};//批量添加整数型MIB到JSON数组

		int IntGetId[]={MIB_EASYCWMP_PERIODINT,\
					MIB_EASYCWMP_RETRYMINU,\
					MIB_EASYCWMP_RETRYINTMUL};
		
	    arraylen = sizeof(IntGetName)/sizeof(char *); 
		addObjectIntToArray(root, arraylen, IntGetName, IntGetId);
			
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{//设置acs参数

		char * EnableCWMP = websGetVar(data, T(MANAG_HD"EnableCWMP"), T(""));
		char * URL = websGetVar(data, T(MANAG_HD"URL"), T(""));
		char * Username = websGetVar(data, T(MANAG_HD"Username"), T(""));
		char * Password = websGetVar(data, T(MANAG_HD"Password"), T(""));
		char * Time = websGetVar(data, T(MANAG_HD"PeriodicInformTime"), T(""));
		char * ReqUsername = websGetVar(data, T(MANAG_HD"ConnectionRequestUsername"), T(""));
		char * ReqPassword = websGetVar(data, T(MANAG_HD"ConnectionRequestPassword"), T(""));
		char * InformEnable = websGetVar(data, T(MANAG_HD"PeriodicInformEnable"), T(""));
		char * InformInterval = websGetVar(data, T(MANAG_HD"PeriodicInformInterval"), T(""));
		char * UpManaged = websGetVar(data, T(MANAG_HD"UpgradesManaged"), T(""));
		char * WaitInterval = websGetVar(data, T(MANAG_HD"CWMPRetryMinimumWaitInterval"), T(""));
		char * IntMultiplier = websGetVar(data, T(MANAG_HD"CWMPRetryIntervalMultiplier"), T(""));
		char *ParameterKey = websGetVar(data, T(MANAG_HD"ParameterKey"), T(""));
	
		int enable=!strcmp(EnableCWMP,"TRUE")?1:0;
		int informenable=!strcmp(InformEnable,"TRUE")?1:0;
		int upmanaged=!strcmp(UpManaged,"TRUE")?1:0;
		
		apmib_set(MIB_EASYCWMP_ENABLE,(void *)&enable);
		apmib_set(MIB_EASYCWMP_ACSURL,(void *)URL);
		apmib_set(MIB_EASYCWMP_ACSNAME,(void *)Username);
		if(strcmp(Password, ""))
			apmib_set(MIB_EASYCWMP_ACSKEY,(void *)Password);
		apmib_set(MIB_EASYCWMP_PERIODTIME,(void *)Time);
		apmib_set(MIB_EASYCWMP_CPE_NAME,(void *)ReqUsername);
		apmib_set(MIB_EASYCWMP_CPE_KEY,(void *)ReqPassword);
		apmib_set(MIB_EASYCWMP_PERIODENABLE,(void *)&informenable);
		int intvalue = atoi(InformInterval);
		apmib_set(MIB_EASYCWMP_PERIODINT,(void *)&intvalue);
		apmib_set(MIB_EASYCWMP_UPGRADEMANAG,(void *)&upmanaged);
		intvalue = atoi(WaitInterval);
		apmib_set(MIB_EASYCWMP_RETRYMINU,(void *)&intvalue);
		intvalue = atoi(IntMultiplier);
		apmib_set(MIB_EASYCWMP_RETRYINTMUL,(void *)&intvalue);
		apmib_set(MIB_EASYCWMP_PARAMETERKEY,(void *)ParameterKey);
        
		apmib_update_web(CURRENT_SETTING);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);

		if(enable){
			;
		}else{
			CsteSystem("killall -9 easycwmpd",1);
		}
	}
	return 0;	
 }


int cwmp_Timing(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		cJSON *root=cJSON_CreateArray();
		int arraylen,intlen,addlen,iplen;
		char tmpbuf[64]={0},ntpstatus[64]={0},ntpen[16]={0},NTPServer[128]={0},NTPServer1[32]={0},NTPServer2[32]={0},NTPServer3[32]={0};
		FILE *fp=NULL;	
		unsigned char ntptmp_str[100];
		char *StrGetName[]={TIME_HD"LocalTimeZone"};
		int  StrGetId[]={MIB_NTP_TIMEZONE};	
		
		arraylen = sizeof(StrGetName)/sizeof(char *);
		addObjectToArray(root, arraylen, StrGetName, StrGetId);

		apmib_get(MIB_NTP_SERVER_URL,(void *)NTPServer);
		sscanf(NTPServer,"%[^;];%[^;];%[^;]",NTPServer1,NTPServer2,NTPServer3);

		char *ipGetName[]={TIME_HD"NTPServer1",TIME_HD"NTPServer2",TIME_HD"NTPServer3"};
		int ipGetMib[]={NTPServer1,NTPServer2,NTPServer3};
		
		iplen = sizeof(ipGetName)/sizeof(char *);
		addPandValueToArray(root,iplen,ipGetName,ipGetMib);

		apmib_get_bool(MIB_NTP_ENABLED,ntpen);
		memset(ntptmp_str,0x00,sizeof(ntptmp_str));
		if(0 != f_exist("/tmp/ntp_tmp")){
				strcpy(ntpstatus,"Synchronized");
		}
		else{
				strcpy(ntpstatus,"Unsynchronized");
		}
		
		getCurrentTime(tmpbuf);
		char * StrAddParameter[]={TIME_HD"Enable",\
								  TIME_HD"CurrentLocalTime",\
								  TIME_HD"Status"};
		
		char * StrAddValue[]={ntpen,\
							  tmpbuf,\
							  ntpstatus};
		
		addlen = sizeof(StrAddParameter)/sizeof(char *);
		addPandValueToArray(root,addlen,StrAddParameter,StrAddValue);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
		
	}
	else{
		char * Enable = websGetVar(data, T(TIME_HD"Enable"), T(""));
		char * NTPServer1 = websGetVar(data, T(TIME_HD"NTPServer1"), T(""));
		char * NTPServer2 = websGetVar(data, T(TIME_HD"NTPServer2"), T(""));		//没有用到
		char * NTPServer3 = websGetVar(data, T(TIME_HD"NTPServer3"), T(""));
		char * LocalTimeZone = websGetVar(data, T(TIME_HD"LocalTimeZone"), T(""));

		char NTPServer[128]={0};
		int enabled=!strcmp(Enable,"TRUE")?1:0;
		apmib_set(MIB_NTP_ENABLED,(void *)&enabled);
		apmib_set( MIB_NTP_TIMEZONE, (void *)LocalTimeZone);

		if(strlen(NTPServer1)>0 && strlen(NTPServer2)>0)
			sprintf(NTPServer,"%s;%s",NTPServer1,NTPServer2);
		if(strlen(NTPServer1)>0 && strlen(NTPServer2)>0 && strlen(NTPServer3)>0)
			sprintf(NTPServer,"%s;%s;%s",NTPServer1,NTPServer2,NTPServer3);

		apmib_set(MIB_NTP_SERVER_URL,(void *)NTPServer);
		
		apmib_update_web(CURRENT_SETTING);
		set_timeZone();
		system("sysconf ntp");	

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	return 0;
}

int cwmp_UserInterface(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL,remoteaccess[16]={0},language[24]={0},*CurrentLanguage=NULL;
		cJSON *root=cJSON_CreateArray();
		int arraylen,intlen;

		apmib_get(MIB_LANGUAGE_TYPE,(void *)language);
		if(!strcmp(language,"cn"))
			CurrentLanguage="Chinese";
		if(!strcmp(language,"en"))
			CurrentLanguage="English";
		if(!strcmp(language,"thai"))
			CurrentLanguage="Thai";

		apmib_get_bool(MIB_WEB_WAN_ACCESS_ENABLED,remoteaccess);	
		char * StrName[]={USER_HD"RemoteAccess.Enable",\
						USER_HD"CurrentLanguage"};
		
		char * GetId[] = {remoteaccess,\
						CurrentLanguage};
		
		int leng = sizeof(StrName)/sizeof(char *);
		addPandValueToArray(root,leng,StrName,GetId);
		
		char * ParaSetZero[]={USER_HD"RemoteAccess.Port"};
		int IntGetId[]={MIB_WEB_WAN_ACCESS_PORT};
		
		intlen = sizeof(ParaSetZero)/sizeof(char *);
		addObjectIntToArray(root,intlen,ParaSetZero,IntGetId);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		char * Enable = websGetVar(data, T(USER_HD"RemoteAccess.Enable"), T(""));
		char * Port = websGetVar(data, T(USER_HD"RemoteAccess.Port"), T(""));
		
		int enabled=!strcmp(Enable,"TRUE")?1:0;
		apmib_set(MIB_WEB_WAN_ACCESS_ENABLED,(void *)&enabled);
		enabled = atoi(Port);
		apmib_set( MIB_WEB_WAN_ACCESS_PORT, (void *)&enabled);

		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_Ethernet(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL, *portlink;
		char wanlinkresult[16]={0};
		cJSON *root=cJSON_CreateArray();
		//ETHN接口数量
		char * intstr[]={"Device.Ethernet.InterfaceNumberOfEntries",\
						ETHERNET_HD1"WAN",\
						ETHERNET_HD1"LAN"};
		
		int intvl[]={INTERFACE_NB,11,1};
		int intlen = sizeof(intstr)/sizeof(char *);
		addIntValueToArray(root,intlen,intstr,intvl);
		//wan信息
		if(getOperationMode()==0){//网关
			char * wan_name[]={ETHERNET_HD2"Enable",ETHERNET_HD2"Upstream"};
			char * wan_value[]={"TRUE","TRUE"};
			int wan_len = sizeof(wan_name)/sizeof(char *);
			addPandValueToArray(root, wan_len, wan_name, wan_value);
		}else{
			char * wan_name[]={ETHERNET_HD2"Enable", ETHERNET_HD2"Upstream"};
			char * wan_value[]={"FALSE","FALSE"};
			int wan_len = sizeof(wan_name)/sizeof(char *);
			addPandValueToArray(root, wan_len, wan_name, wan_value);
		}
		
		portlink = getPortLinkStaus();
		char delims[] = ",";
		char *result = NULL;
		result = strtok( portlink, delims );
		if(!strcmp(result,"1")){
			strcpy(wanlinkresult,"Up");
		}
		else{
			strcpy(wanlinkresult,"Down");
		}
		char * wanlink[]={ETHERNET_HD2"Status", ETHERNET_HD2"MACAddress"};
		char * Strwanlink[]={wanlinkresult, getWanMac()};
		int statuslen = sizeof(wanlink)/sizeof(char *);
		addPandValueToArray(root,statuslen,wanlink,Strwanlink);

		//WAN statistics
		char if_wan[32]={0};
		struct user_net_device_stats stats;
		getWanIfNameCs(if_wan);	
		getStats(if_wan, &stats);
		
		char * wanstate[]={ETHERNET_HD3"BytesSent",\
						ETHERNET_HD3"BytesReceived",\
						ETHERNET_HD3"PacketsSent",\
						ETHERNET_HD3"PacketsReceived",\
						ETHERNET_HD3"ErrorsSent",\
						ETHERNET_HD3"ErrorsReceived",\
						ETHERNET_HD3"UnicastPacketsSent",\
						ETHERNET_HD3"UnicastPacketsReceived",\
						ETHERNET_HD3"MulticastPacketsSent",\
						ETHERNET_HD3"MulticastPacketsReceived",\
						ETHERNET_HD3"BroadcastPacketsSent",\
						ETHERNET_HD3"BroadcastPacketsReceived"};
		
		int intstat[]={stats.tx_bytes,\
					stats.rx_bytes,\
					stats.tx_packets,\
					stats.rx_packets,\
					stats.tx_errors,\
					stats.rx_errors,\
					stats.tx_unicast,\
					stats.rx_unicast,\
					stats.tx_multicast,\
					stats.rx_multicast,\
					stats.tx_broadcast,\
					stats.rx_broadcast};
		
		int statlen = sizeof(wanstate)/sizeof(char *);
		addIntValueToArray(root, statlen, wanstate, intstat);


		//--------------------------  lan info  ------------------------------
		char * lan_name[]={ETHERNET_HD4"Enable",ETHERNET_HD4"Upstream"};
		char * lan_value[]={"TRUE","FALSE"};
		int lan_len = sizeof(lan_name)/sizeof(char *);
		addPandValueToArray(root, lan_len, lan_name, lan_value);

		char lanlinkresult[16]={0};
		strcpy(lanlinkresult, "Donw");

		//获取的结果有7  个位,  需截断后两位
		portlink = getPortLinkStaus();
		*(portlink+10) = '\0';

		while( *(++portlink) != '\0'){
			if(*portlink == '1'){
				strcpy(lanlinkresult, "Up");
				break;
			}
		}

		char * lanlink[]={ETHERNET_HD4"Status", ETHERNET_HD4"MACAddress"};
		char * Strlanlink[]={lanlinkresult, getLanMac()};
		int lan_statuslen = sizeof(lanlink)/sizeof(char *);
		addPandValueToArray(root, lan_statuslen, lanlink, Strlanlink);

		//LAN statistics
		struct user_net_device_stats lan_stats;	
		getStats("br0", &lan_stats);
		char * lanstate[]={ETHERNET_HD5"BytesSent",\
				ETHERNET_HD5"BytesReceived",\
				ETHERNET_HD5"PacketsSent",\
				ETHERNET_HD5"PacketsReceived",\
				ETHERNET_HD5"ErrorsSent",\
				ETHERNET_HD5"ErrorsReceived",\
				ETHERNET_HD5"UnicastPacketsSent",\
				ETHERNET_HD5"UnicastPacketsReceived",\
				ETHERNET_HD5"MulticastPacketsSent",\
				ETHERNET_HD5"MulticastPacketsReceived",\
				ETHERNET_HD5"BroadcastPacketsSent",\
				ETHERNET_HD5"BroadcastPacketsReceived"};
		
		int lan_intstat[]={lan_stats.tx_bytes,\
					lan_stats.rx_bytes,\
					lan_stats.tx_packets,\
					lan_stats.rx_packets,\
					lan_stats.tx_errors,\
					lan_stats.rx_errors,\
					lan_stats.tx_unicast,\
					lan_stats.rx_unicast,\
					lan_stats.tx_multicast,\
					lan_stats.rx_multicast,\
					lan_stats.tx_broadcast,\
					lan_stats.rx_broadcast};

		int lan_statlen = sizeof(lanstate)/sizeof(char *);
		addIntValueToArray(root, lan_statlen, lanstate, lan_intstat);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		
		//char * WAN = websGetVar(data, T(ETHERNET_HD1"WAN"), T(""));
		//char * LAN = websGetVar(data, T(ETHERNET_HD1"LAN"), T(""));
		//char * Enable = websGetVar(data, T(ETHERNET_HD2"Enable"), T(""));

		//没有对应MIB	项

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

#ifdef CONFIG_APP_STORAGE
int cwmp_USB(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){

		char enable[16] = {0}, host_usbVer[16] = {0}, device_num[16] = {0};
		
		char dev_num[16] = {0}, 		dev_usbVer[16] = {0}, 	dev_class[16] = {0};
		char dev_subclass[16] = {0},	dev_proto[16] = {0}, 	dev_ver[16] = {0};
		char dev_productID[16] = {0},	dev_vendorID[16] = {0},	dev_Manufac[32] = {0};
		char dev_productCls[16] = {0},	dev_rate[16] = {0};

		char buff[32] = {0};
		
		char *output=NULL;
		cJSON *root=cJSON_CreateArray();

		//HostNumberOfEntries 实际是: cat /proc/bus/usb/devices | grep \"Host Controller\" | wc -l
		//这里写死为1
		//同样，为简洁只考虑Host Controller 的Bus=01，DeviceNumberOfEntries 写死为1。
		//如果Host Controller的Bus 会变化, 可使用以下命令获取Bus 号:
		//awk 'BEGIN{ FS="\n"; RS=""} /Host Controller/ {print $1}' /proc/bus/usb/devices | awk -F '[ =]+' '{print $3}'
		//然后grep Prnt=Bus 号| grep Cls=08 | wc -l，获得该Host 下DeviceNumberOfEntries。


		//USB_HD1"Enable"
		apmib_get_bool(MIB_USB_ENABLE, enable);

		//USB_HD1"USBVersion
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Host Controller/ {print $3}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $3}'", host_usbVer, sizeof(host_usbVer)))
			goto out;

		//USB_HD1"DeviceNumberOfEntries"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Cls=08/ {print $2}' /proc/bus/usb/devices | grep Prnt=01 | wc -l", device_num, sizeof(device_num)))
			goto out;

		/* ------------Device-------------*/
		//USB_HD2"DeviceNumber"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $1}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $8}'", dev_num, sizeof(dev_num)))
			goto out;

		//USB_HD2"USBVersion"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $2}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $3}'", dev_usbVer, sizeof(dev_usbVer)))
			goto out;

		//USB_HD2"DeviceClass"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $8}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $8}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_class, buff+4);
		

		//USB_HD2"DeviceSubClass"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $8}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $9}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_subclass, buff+4);

		//USB_HD2"DeviceProtocol"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $8}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $10}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_proto, buff+5);

		//USB_HD2"DeviceVersion"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $3}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $5}'", dev_ver, sizeof(dev_ver)))
			goto out;

		//USB_HD2"ProductID"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $3}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $3}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_productID, buff+7);
		
		//USB_HD2"VendorID",
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $3}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $2}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_vendorID, buff+7);

		//USB_HD2"Manufacturer"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $4}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $2}'", buff, sizeof(buff)))
			goto out;
		strcpy(dev_Manufac, buff+13);

		//USB_HD2"ProductClass"
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $2}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $4}'", buff, sizeof(buff)))
			goto out;
		strncpy(dev_productCls, buff+4, 2);

		//USB_HD2"Rate"
		//只测试过480 的
		if(getCmdStr("awk 'BEGIN{ FS=\"\\n\"; RS=\"\"} /Driver=usb/ {print $1}' /proc/bus/usb/devices | awk -F '[ ]+' '{print $9}'", dev_rate, sizeof(dev_rate)))
			goto out;
		if(strstr(dev_rate, "1.5"))
			strcpy(dev_rate, "Low");
		else if(strstr(dev_rate, "12"))
			strcpy(dev_rate, "Full");
		else if(strstr(dev_rate, "480"))
			strcpy(dev_rate, "High");
		else if(strstr(dev_rate, "5.0"))
			strcpy(dev_rate, "Super");	

		char *name[]={"Device.USB.USBHosts.HostNumberOfEntries",
					  USB_HD1"Enable",
					  USB_HD1"USBVersion", //这是控制器的
					  USB_HD1"DeviceNumberOfEntries",
					  
					  USB_HD2"DeviceNumber",
					  USB_HD2"USBVersion", //这是读取到的USB 设备的
					  USB_HD2"DeviceClass",
					  USB_HD2"DeviceSubClass",
					  USB_HD2"DeviceProtocol",
					  USB_HD2"DeviceVersion",
					  USB_HD2"ProductID",
					  USB_HD2"VendorID",
					  USB_HD2"Manufacturer",
					  USB_HD2"ProductClass",
					  USB_HD2"Rate"
					};

		char *value[] = {"1", 
						 enable,
						 host_usbVer,
						 device_num, 
						 
						 dev_num,
						 dev_usbVer,
						 dev_class,
						 dev_subclass,
						 dev_proto,
						 dev_ver,
						 dev_productID,
						 dev_vendorID,
						 dev_Manufac,
						 dev_productCls,
						 dev_rate
						 }; 

		int len = sizeof(value)/sizeof(char *);
		addPandValueToArray(root, len, name, value);

out:
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		char *enable = websGetVar(data, USB_HD1"Enable", "");
		int onoff=!strcmp(enable, "TRUE")? 1 : 0;
		apmib_set(MIB_USB_ENABLE, (void *)&onoff);

		if(onoff){
			system("insmod /lib/modules/2.6.30.9/kernel/drivers/usb/storage/usb-storage.ko");
		}
		else{//禁用的时候需禁用USB 相关功能
			apmib_set(MIB_DLNA_ENABLED,(void *)&onoff);
			apmib_set(MIB_SAMBA_ENABLED,(void *)&onoff);
			apmib_set(MIB_FTP_ENABLED,(void *)&onoff);

			system("sysconf minidlna");
			system("sysconf samba");
			system("sysconf vsftpd");
			
			system("umount /var/tmp/usb/sda1");
			system("rmmod usb-storage");
		}

		apmib_update_web(CURRENT_SETTING);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}
#endif

int cwmp_DynamicDNS(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL,ddnsType[128];
		char ddnsen[16]={0},ddnst[128]={0},if_wan[32]={0},ddnserver[128]={0},serv1[64]={0};
		char serv1host[64]={0},serv2[64]={0},serv2host[64]={0},serv3[64]={0},serv3host[64]={0};
		int arraylen,tmpBuf=0;
		cJSON *root=cJSON_CreateArray();
		
		if(getOperationMode()!=1){			
			if(getOperationMode()==1){
				strcpy(ddnsen,"FALSE");
			}else{
				apmib_get_bool(MIB_DDNS_ENABLED,ddnsen);
			}
			ddnsStatus(tmpBuf);
			if(tmpBuf==1)){
				strcpy(ddnst,"Updated");
			}
			else{
				strcpy(ddnst,"Disabled");
			}
			
			apmib_get(MIB_DDNS_TYPE, (void *)ddnsType);

			sprintf(ddnserver,"%s",ddnsType);

			//getWanIfNameCs(if_wan);
			sprintf(if_wan,"eth0");
			strcpy(serv1,"dyndns.org");
			strcpy(serv1host,"www.dyndns.org");
			strcpy(serv2,"no-ip.com");
			strcpy(serv2host,"www.no-ip.com");
			strcpy(serv3,"3322.org");
			strcpy(serv3host,"www.3322.org");
			char * server[]={DYDNS_HD1"ClientNumberOfEntries",\
							DYDNS_HD1"ServerNumberOfEntries",\
							DYDNS_HD2"Enable",\
							DYDNS_HD2"Status",\
							DYDNS_HD2"Server",\
							DYDNS_HD2"Interface",\
							DYDNS_HD2"HostnameNumberOfEntries",\
							DYDNS_HD2"Hostname.1.Enable",\
							DYDNS_HD3"1.Name",\
							DYDNS_HD3"1.ServerAddress",\
							DYDNS_HD3"2.Name",\
							DYDNS_HD3"2.ServerAddress",\
							DYDNS_HD3"3.Name",\
							DYDNS_HD3"3.ServerAddress",};
			
			char * svalue[]={"1",\
							"3",\
							ddnsen,\
							ddnst,\
							ddnserver,\
							if_wan,\
							"1",\
							ddnsen,\
							serv1,\
							serv1host,\
							serv2,\
							serv2host,\
							serv3,\
							serv3host};
			
			int servelen = sizeof(server)/sizeof(char *);
			addPandValueToArray(root,servelen,server,svalue);

			char *StrGetName[]={DYDNS_HD2"Username",\
								DYDNS_HD2"Password",\
								DYDNS_HD2"Hostname.1.Name"};
			
			int  StrGetId[]={MIB_DDNS_USER,\
							MIB_DDNS_PASSWORD,\
							MIB_DOMAIN_NAME};
			
			arraylen = sizeof(StrGetName)/sizeof(char *);
			addObjectToArray(root, arraylen, StrGetName, StrGetId);
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		if(getOperationMode()==1){
			CSTE_DEBUG("Error:DDDNS Bridge mode can not be set!\n");
			//模式是桥不能设置
		}else{
			char * ClientEnable = websGetVar(data, T(DYDNS_HD2"Enable"), T(""));
			char * ClientServer = websGetVar(data, T(DYDNS_HD2"Server"), T(""));
			char * ClientInterface = websGetVar(data, T(DYDNS_HD2"Interface"), T(""));	//Unknow the MIB in RTL;This param Writable
			char * ClientUsername = websGetVar(data, T(DYDNS_HD2"Username"), T(""));
			char * ClientPassword = websGetVar(data, T(DYDNS_HD2"Password"), T(""));
			char * ClientHostEnable = websGetVar(data, T(DYDNS_HD2"Hostname.1.Enable"), T("")); //Set cwmp_DynamicDNS;What is this mean
			char * ClientHostName = websGetVar(data, T(DYDNS_HD2"Hostname.1.Name"), T(""));
			
			char * ServerName1 = websGetVar(data, T(DYDNS_HD3"1.Name"), T(""));	//unknow
			char * ServerAddress1 = websGetVar(data, T(DYDNS_HD3"1.ServerAddress"), T(""));
			char * ServerName2 = websGetVar(data, T(DYDNS_HD3"2.Name"), T(""));
			char * ServerAddress2 = websGetVar(data, T(DYDNS_HD3"2.ServerAddress"), T(""));
			char * ServerName3 = websGetVar(data, T(DYDNS_HD3"3.Name"), T(""));
			char * ServerAddress3 = websGetVar(data, T(DYDNS_HD3"3.ServerAddress"), T(""));

			int enabl = !strcmp(ClientEnable,"TRUE")?1:0;
			apmib_set(MIB_DDNS_ENABLED,(void *)&enabl);
				
			apmib_set(MIB_DDNS_TYPE, (void *)ClientServer);
			apmib_set(MIB_DDNS_USER,(void *)ClientUsername);
			apmib_set(MIB_DDNS_PASSWORD,(void *)ClientPassword);
			apmib_set(MIB_DDNS_DOMAIN_NAME,(void *)ClientHostName);
			
		}
		apmib_update_web(CURRENT_SETTING);
		system("sysconf ddns");

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);		
		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	return 0;
}

int cwmp_DHCPv4(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char tmpBuf[128],wanip[16],wanMode[32]={0},dhcpen[32]={0},cnectst[32]={0};
		cJSON *root=cJSON_CreateArray();
		getWanIp(wanip);
		//DHCP CLIENT部分
		if(getOperationMode()!=1){
			getWanConnectMode(wanMode);
			if(!strcmp(wanMode,"DHCP")){
				strcpy(dhcpen,"TRUE");
			}
			else{
				strcpy(dhcpen,"FALSE");
			}
			get_wan_connect_status(tmpBuf);
			if(!strcmp(tmpBuf,"connected")){
				strcpy(cnectst,"Enabled");
			}else{
				strcpy(cnectst,"Disabled");
			}

			char * wanifo[]={"Device.DHCPv4.ClientNumberOfEntries",\
							DHCP_HD1"Enable",\
							DHCP_HD1"Status",\
							DHCP_HD1"IPAddress",\
							DHCP_HD1"SubnetMask",\
							DHCP_HD1"IPRouters",\
							DHCP_HD1"DHCPServer"};
			
			char * wanifoValue[]={"1",\
								dhcpen,\
								cnectst,\
								wanip,\
								getWanNetmask(),\
								getWanGateway(),\
								getWanGateway()};
			
			int wanifolen = sizeof(wanifo)/sizeof(char *);
			addPandValueToArray(root,wanifolen,wanifo,wanifoValue);
			
			DNS_TYPE_T dnsMode;
			apmib_get( MIB_DNS_MODE, (void *)&dnsMode);
			if (dnsMode==DNS_MANUAL) {//Manual
				char * IPGetName2[]={DHCP_HD1"DNSServers"};
				int IPGetId2[]={MIB_DNS1};
				int arraylen = sizeof(IPGetName2)/sizeof(char *);
				addObjectIPToArray(root, arraylen, IPGetName2, IPGetId2);
			}
			else {
					char * dns1[]={DHCP_HD1"DNSServers"};
					char * dns1Value[]={getDns(1)};
					int dns1len = sizeof(dns1)/sizeof(char *);
					addPandValueToArray(root,dns1len,dns1,dns1Value);
				}
			
			//DHCP SERVER部分
			char dhcp[8]={0},poolst[64]={0},sten[8]={0},serveren[16]={0};
			char macaddr[30]={0},ipAddr[32]={0},macAddr[32]={0},liveTime[32]={0},hostName[64]={0},servnb[16]={0};
			int stacnb=0,i=0,count=0,pid,ret;
			unsigned long fileSize=0;
			char *buf = NULL,*ptr = NULL;
			FILE *fp;
			struct stat status;
			DHCPRSVDIP_T entry;
			getDhcp();
			if(getDhcp()==2){
				strcpy(serveren,"TRUE");
				strcpy(poolst,"Enabled");
			}else{
				strcpy(serveren,"FALSE");
				strcpy(poolst,"Disabled");
			}
			
			apmib_get_bool(MIB_DHCPRSVDIP_ENABLED, sten);//静态DHCP
			char * dhcps[] = {"Device.DHCPv4.Server.Enable",\
							  "Device.DHCPv4.Server.PoolNumberOfEntries",\
							  DHCP_HD2"Enable",\
							  DHCP_HD2"Status",\
							  DHCP_HD2"X_HUMAX_StaticAddressEnable",\
							  DHCP_HD2"StaticAddressNumberOfEntries",\
							  DHCP_HD2"ReservedAddresses"};
			
			char * dhcpsValue[]={serveren,\
								 "1",\
								 serveren,\
								 poolst,\
								 sten,\
								 NUM_DHCPv4_StaticAddress,\
								 ""};
			
			int dhcpslen = sizeof(dhcps)/sizeof(char *);
			addPandValueToArray(root,dhcpslen,dhcps,dhcpsValue);

			char * dhcppl[] = {DHCP_HD2"DNSServers",\
							   DHCP_HD2"MinAddress",\
				               DHCP_HD2"MaxAddress", \
				               DHCP_HD2"SubnetMask"};	
			
			int dhcpplId[] = {MIB_IP_ADDR, \
							  MIB_DHCP_CLIENT_START, \
				              MIB_DHCP_CLIENT_END, \
				              MIB_SUBNET_MASK};
			
			int dhcppllen = sizeof(dhcppl)/sizeof(char *);
			addObjectIPToArray(root, dhcppllen, dhcppl, dhcpplId);

			char * IntGetName[]={DHCP_HD2"LeaseTime"};
			
			int IntGetId[]={MIB_DHCP_LEASE_TIME};
			
	   		int intlen = sizeof(IntGetName)/sizeof(char *);
			addObjectIntToArray(root,intlen,IntGetName,IntGetId);
			apmib_get(MIB_DHCPRSVDIP_TBL_NUM,(void *)&stacnb);
			cJSON * arry = cJSON_CreateArray();
			for(i=1; i<=stacnb; i++)
			{
		    	cJSON * item = cJSON_CreateObject();
				cJSON_AddItemToArray(arry,item);	
		        *((char *)&entry) = (char)i;
		        apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
		        if (!memcmp(entry.macAddr, "\x0\x0\x0\x0\x0\x0", 6))
					macaddr[0]='\0';
				else			
					sprintf(macaddr,"%02x:%02x:%02x:%02x:%02x:%02x",entry.macAddr[0],entry.macAddr[1],\
					entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
				cJSON_AddStringToObject(item, "Enable", sten);
				cJSON_AddStringToObject(item, "Chaddr", macaddr);
				cJSON_AddStringToObject(item, "Yiaddr", inet_ntoa(*((struct in_addr*)entry.ipAddr)));
			}
			
			char *stsvl = cJSON_Print(arry);
			char * scps[]={"StaticAddress"};
			char * sValue[]={stsvl};
			int slen = sizeof(scps)/sizeof(char *);
			addPandValueToArray(root,slen,scps,sValue);
			cJSON_Delete(arry);
			free(stsvl);

			// siganl DHCP server to update lease file
			cJSON * dparry = cJSON_CreateArray();
			memset(tmpBuf,0x00,sizeof(tmpBuf));
		    snprintf(tmpBuf, 128, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
		    pid = getPid(tmpBuf);
		    if( pid > 0)
		    {
		        snprintf(tmpBuf, 128, "kill -SIGUSR1 %d\n", pid);
		        system(tmpBuf);
		    }
		    usleep(1000);
		    if ( stat(_PATH_DHCPS_LEASES, &status) < 0 ){
		    	return 0;
		    }
		    fileSize=status.st_size;
		    buf = malloc(fileSize);
		    if ( buf != NULL )
		    {
		        if( (fp=fopen(_PATH_DHCPS_LEASES, "r"))==NULL )
		        {
		        	free(buf);
		    		return 0;
		        }
		        fread(buf, 1, fileSize, fp);
		        fclose(fp);
		        ptr = buf;
		        while(1)
		        {
		        	cJSON * dptem = cJSON_CreateObject();
		            ret = getOneDhcpClient(&ptr, &fileSize, ipAddr, macAddr, liveTime, hostName);
		            if(ret<0){
						cJSON_Delete(dptem);
						break;
					}
		            if(ret==0){
						cJSON_Delete(dptem);
						continue;
					}
		            if(!strcmp(macAddr,"00:00:00:00:00:00")){
						cJSON_Delete(dptem);
						continue;
					}
					
					cJSON_AddStringToObject(dptem, "Chaddr", macAddr);
					cJSON_AddStringToObject(dptem, "Active", "TRUE");
					cJSON_AddStringToObject(dptem, "IPv4AddressNumberOfEntries", "1");
					cJSON_AddStringToObject(dptem, "IPv4Address.1.IPAddress", ipAddr);
					cJSON_AddStringToObject(dptem, "IPv4Address.1.LeaseTimeRemaining", liveTime);
					cJSON_AddItemToArray(dparry, dptem);
					//count++;
		        }
		    }
			//sprintf(servnb,"%d",count);
			char * dpvl = cJSON_Print(dparry);
			char * dps[]={DHCP_HD2"ClientNumberOfEntries","Client"};
			char * dsValue[]={NUM_DHCPv4_Client, dpvl};
			int dslen = sizeof(dps)/sizeof(char *);
			addPandValueToArray(root, dslen, dps, dsValue);
			cJSON_Delete(dparry);
			free(dpvl);
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		int i=0,enable=0,entryNum=0;
		DHCPRSVDIP_T delEntry;
		char *output = NULL;
		struct in_addr  ip_addr;
		cJSON *root,*subObj,*StaticAddressMap;
		root = cJSON_CreateObject();
		char buffer[32]={0};
		char * ClientEnalble = websGetVar(data, T(DHCP_HD1"Enable"), T(""));
		char * ServerEnalble = websGetVar(data, T("Device.DHCPv4.Server.Enable"), T(""));
		char * StaticAddressEnable = websGetVar(data, T(DHCP_HD2"X_HUMAX_StaticAddressEnable"), T(""));
		char * MinAddress = websGetVar(data, T(DHCP_HD2"MinAddress"), T(""));
		char * MaxAddress = websGetVar(data, T(DHCP_HD2"MaxAddress"), T(""));
		//char * ReservedAddresses = websGetVar(data, T(DHCP_HD2"ReservedAddresses"), T(""));
		char * SubnetMask = websGetVar(data, T(DHCP_HD2"SubnetMask"), T(""));
		char * LeaseTime = websGetVar(data, T(DHCP_HD2"LeaseTime"), T(""));
		
		if(!strcmp(ClientEnalble,"TRUE")) {
			enable= 1;
			apmib_set(MIB_WAN_DHCP,(void *)&enable);
			char *dhcp_mtu = "1500";
			int iDhcp_mtu = atoi(dhcp_mtu);
				apmib_set(MIB_DHCP_MTU_SIZE,  (void *)&iDhcp_mtu); 
		}
		else{
		//disable dhcp ???
			;			
		}	

		enable = !strcmp(ServerEnalble,"TRUE")?2:0;
		apmib_set(MIB_DHCP,(void *)&enable);

		enable = !strcmp(StaticAddressEnable,"TRUE")?1:0;
		apmib_set(MIB_DHCPRSVDIP_ENABLED,(void *)&enable);
		
		 if ( inet_aton(MinAddress, &ip_addr) ){
        			apmib_set( MIB_DHCP_CLIENT_START, (void *)&ip_addr);
    		} 
		
		 if ( inet_aton(MaxAddress, &ip_addr) ){
        			apmib_set( MIB_DHCP_CLIENT_END, (void *)&ip_addr);
    		}
		 if ( inet_aton(SubnetMask, &ip_addr) ){	//lan mask
        			apmib_set( MIB_SUBNET_MASK, (void *)&ip_addr);
    		} 
	 
		int dhcp_l_time = atoi(LeaseTime);
		apmib_set(MIB_DHCP_LEASE_TIME, (void *)&dhcp_l_time);

		//删除原有规则，写入ACS	  下发的规则
		apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
		for(i=entryNum; i>0; i--)
		{
			*((char *)&delEntry) = (char)i;
			apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&delEntry);
			apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&delEntry);
		}
		StaticAddressMap = cJSON_Parse(websGetVar(data, T(DHCP_HD2"StaticAddress."), ""));
		for(i=0;i<cJSON_GetArraySize(StaticAddressMap);i++){	
			subObj = cJSON_GetArrayItem(StaticAddressMap, i);
			char * enabled = websGetVar(subObj, T("Enable"), T(""));
			char * mac_address = websGetVar(subObj, T("Chaddr"), T(""));
			char * ip_address = websGetVar(subObj, T("Yiaddr"), T(""));
			//------set  static  dhcp-------------
			int  entryNum=0;
			DHCPRSVDIP_T staticIPEntry;
			struct in_addr inIp, inLanaddr_orig, inLanmask_orig;
			char *delim=":", *p=NULL;
			if(!strcmp(enabled,"TRUE")) enable= 1;
			 	else enable = 0;
			apmib_set(MIB_DHCPRSVDIP_ENABLED,(void *)&enable);
		     	memset(&staticIPEntry, '\0', sizeof(staticIPEntry));
			if(inet_aton(ip_address, &inIp))
				memcpy(staticIPEntry.ipAddr, &inIp, 4);
		    	if(!isMacValid(mac_address)){
				goto end;
			}
			else{
				if(mac_address!=NULL){
					p = strtok(mac_address, delim);
					memset(buffer, '\0', sizeof(buffer));
					if(p==NULL) goto end;
					    strcat(buffer, p);
					while((p=strtok(NULL, delim))) {
							strcat(buffer, p);
					}
					string_to_hex(buffer, staticIPEntry.macAddr, 12);	
				}
		        }
			apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
			if ( (entryNum + 1) > MAX_DHCP_RSVD_IP_NUM ){
				goto end;
			}
			apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
			memcpy((void *)&inLanaddr_orig, buffer, 4);    	
			apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
			memcpy((void *)&inLanmask_orig, buffer, 4);
			if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inIp.s_addr & inLanmask_orig.s_addr)){
				goto end;
			}
			int ret=checkSameIpOrMac(&inIp, staticIPEntry.macAddr, entryNum);
			if(ret>0){
				goto end;
			}
			// set to MIB. try to delete it first to avoid duplicate case
			apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&staticIPEntry);
			if ( apmib_set(MIB_DHCPRSVDIP_ADD, (void *)&staticIPEntry) == 0) {
				goto end;
			}
		
		}
		cJSON_Delete(StaticAddressMap);
end:
		apmib_update_web(CURRENT_SETTING);

		//延迟可能导致网络断开的操作，以避免多项数据相继下发时
		//在部分数据尚未完成设置之前就断开网络
		int pid=fork();
		if(0 == pid)
		{
			sleep(5);
			run_init_script("all");
			CsteSystem("sysconf reservedIP", CSTE_PRINT_CMD);
			exit(0);
		}

		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output); 
	}
	return 0;
}

int cwmp_DHCPv6(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		cJSON *root=cJSON_CreateArray();

		char cmd_output[64] = {0};
		char *dhcpv6_en = NULL, *dhcpv6_num = NULL, *prefix = NULL;

		//不使用MIB 项判断，因为目前如果没有配置地址池，即是开启进程也没起来
		getCmdStr("ps | grep dhcp6s", cmd_output, sizeof(cmd_output));
		if(strlen(cmd_output)){
			dhcpv6_en = "TRUE";
			dhcpv6_num = "1";
			prefix = "Device.IP.Interface.1.IPv6Prefix.1";
		}else{
			dhcpv6_en = "FALSE";
			dhcpv6_num = "0";
			prefix = "";
		}

		char * dhcps[] = {DHCPV6_HD1"Enable",\
						  DHCPV6_HD1"PoolNumberOfEntries",\
						  DHCPV6_HD1"pool.1.Enable",\
						  DHCPV6_HD1"pool.1.IAPDManualPrefixes"};
		
		char * dhcpsValue[]={dhcpv6_en,\
							 dhcpv6_num,\
							 dhcpv6_en,\
							 prefix};
		
		int dhcpslen = sizeof(dhcps)/sizeof(char *);
		addPandValueToArray(root,dhcpslen,dhcps,dhcpsValue);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		char *server_on = websGetVar(data, DHCPV6_HD1"Enable", "");
		dhcp6sCfgParam_t dhcp6sCfgParam;

		if(strcmp(server_on, "TRUE"))
			dhcp6sCfgParam.enabled = 0;
		else
			dhcp6sCfgParam.enabled = 1;
		
		apmib_set(MIB_IPV6_DHCPV6S_PARAM, &dhcp6sCfgParam);

		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			sleep(4);
			run_init_script("all");
		}
		
		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root, "status", 0);
		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output); 
	}
	return 0;
}

int cwmp_Users(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		cJSON *root=cJSON_CreateArray();

		char * strName[]={"Device.Users.UserNumberOfEntries",\
						  USERS_HD"Enable",\
						  USERS_HD"Password"};
		
		char * strValue[]={"1","TRUE",""};
		
		int strlen = sizeof(strName)/sizeof(char *);
		addPandValueToArray(root,strlen,strName,strValue);

		char *StrGetName[]={USERS_HD"Username"};
		int  StrGetId[]={MIB_USER_NAME};
		int arraylen = sizeof(StrGetName)/sizeof(char *);
		addObjectToArray(root, arraylen, StrGetName, StrGetId);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		char *output = NULL;
		
		//char * Enable = websGetVar(data, T(USERS_HD"Enable"), T(""));	//没有对应MIB   项
		char * Username = websGetVar(data, T(USERS_HD"Username"), T(""));
		char * Password = websGetVar(data, T(USERS_HD"Password"), T(""));
		
		apmib_set(MIB_USER_NAME,(void *)Username);
		if(strcmp(Password, ""))
			apmib_set(MIB_USER_PASSWORD,(void *)Password);
		apmib_update_web(CURRENT_SETTING);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_UPnP(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){

		char *output=NULL,tmpStr[16]={0};
		cJSON *root=cJSON_CreateArray();
		
		apmib_get_bool(MIB_UPNP_ENABLED,tmpStr);
		//UPnPArchitecture,UPnPArchitectureMinorVer,UPnPIGD value is ??? 
		char * Upnp[]={UPNP_HD"Enable",
					   UPNP_HD"UPnPIGD",
					   UPNP_HD"Capabilities.UPnPArchitecture",
					   UPNP_HD"Capabilities.UPnPArchitectureMinorVer",
					   UPNP_HD"Capabilities.UPnPIGD"};
		
		char * UpnpValue[]={tmpStr,\
							tmpStr,\
							"1",\
							"2",\
							"1"};
		
		int len = sizeof(Upnp)/sizeof(char *);
		addPandValueToArray(root,len,Upnp,UpnpValue);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		
		char * Enable = websGetVar(data, T(UPNP_HD"Enable"), T(""));
		char * UPnPIGD = websGetVar(data, T(UPNP_HD"UPnPIGD"), T(""));
		
		int enable=!strcmp(Enable,"TRUE") ?1:0;
		apmib_set(MIB_UPNP_ENABLED,(void *)&enable);
		enable=!strcmp(UPnPIGD,"TRUE") ?1:0;
		apmib_set(MIB_UPNP_ENABLED,(void *)&enable);
		apmib_update_web(CURRENT_SETTING);
		system("sysconf upnpd_igd");

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_Firewall(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	cJSON *root=cJSON_CreateArray();
	
	if(strcmp(action,"get")==0){
		
		char *output=NULL;
		URLFILTER_T url_entry;
		int fw_mode, entryNum=0, i=0; 
		char fw_enable[16]={0}, *policy=NULL;
		char block_en[8]={0},ipsec_en[8]={0},pptp_en[8]={0},l2tp_en[8]={0};
		
		if(getOperationMode()!=1){
			strcpy(fw_enable, "TRUE");
			apmib_get(MIB_FIREWALL_MODE, (void *)&fw_mode);
			policy=fw_mode?"Drop":"Accept";
			
			apmib_get_bool(MIB_PING_WAN_ACCESS_ENABLED,block_en);
			apmib_get_bool(MIB_VPN_PASSTHRU_IPSEC_ENABLED,ipsec_en);
			apmib_get_bool(MIB_VPN_PASSTHRU_PPTP_ENABLED,pptp_en);
			apmib_get_bool(MIB_VPN_PASSTHRU_L2TP_ENABLED,l2tp_en);
			
			char *frName[]={"Device.Firewall.Enable", \
							"Device.Firewall.ChainNumberOfEntries", \ 
							FW_HD"IPFilter.Chain",  \
							FW_HD"IPFilter.DefaultPolicy", \
							FW_HD"MACFilter.Chain", \
							FW_HD"MACFilter.DefaultPolicy", \
							FW_HD"URLFilter.Chain", \
							FW_HD"URLFilter.DefaultPolicy",\
							FW_HD"ICMPBlocking", \
							FW_HD"IPsecPassthrough", \
							FW_HD"PPTPPassthrough", \
							FW_HD"L2TPPassthrough", \
							FW_HD"IPFilter.Enable", \
							FW_HD"MACFilter.Enable", \
							FW_HD"URLFilter.Enable"};		

			char *frValue[]={fw_enable,
							 "3",
							 FW_HD2"1",		//ip chain
							 policy,
							 FW_HD2"2",		//mac chain
							 policy,
							 FW_HD2"3",		//url chain
							 policy,
							 block_en,
							 ipsec_en,
							 pptp_en,
							 l2tp_en,
							 "TRUE",
							 "TRUE",
							 "TRUE"};
			int frlen = sizeof(frName)/sizeof(char *);
			addPandValueToArray(root, frlen, frName, frValue);

			char * firewallDes[] = {FW_HD"IPFilter.Description", \ 
							   FW_HD"MACFilter.Description", \
				               FW_HD"URLFilter.Description"};	
			
			int desId[] = {MIB_EASYCWMP_IP_DES, \
							MIB_EASYCWMP_MAC_DES, \
							MIB_EASYCWMP_URL_DES};
			
			int desLen = sizeof(firewallDes)/sizeof(char *);
			addObjectToArray(root, desLen, firewallDes, desId);
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		char * Enable = websGetVar(data, T("Device.Firewall.Enable"), T(""));
		char * ICMPBlocking = websGetVar(data, T( FW_HD"ICMPBlocking"), T(""));
		char * IPsecPassthrough = websGetVar(data, T(FW_HD"IPsecPassthrough"), T(""));
		char * PPTPPassthrough = websGetVar(data, T(FW_HD"PPTPPassthrough"), T(""));
		char * L2TPPassthrough = websGetVar(data, T( FW_HD"L2TPPassthrough"), T(""));
		char * IPFilterDescription = websGetVar(data, T(FW_HD"IPFilter.Description"), T(""));
		char * IPFilterChain = websGetVar(data, T(FW_HD"IPFilter.Chain"), T(""));
		char * IPFilterDefaultPolicy = websGetVar(data, T(FW_HD"IPFilter.DefaultPolicy"), T(""));
		char * MACFilterDescription = websGetVar(data, T(FW_HD"MACFilter.Description"), T(""));
		char * URLFilterDescription = websGetVar(data, T(FW_HD"URLFilter.Description"), T(""));
		char * URLFilterChain = websGetVar(data, T(FW_HD"URLFilter.Chain"), T(""));
		char * URLFilterDefaultPolicy = websGetVar(data, T(FW_HD"URLFilter.DefaultPolicy"), T(""));

		if(strlen(IPFilterDescription)>0){
			apmib_set(MIB_EASYCWMP_IP_DES,(void *)IPFilterDescription);
		}

		if(strlen(MACFilterDescription)>0){
			apmib_set(MIB_EASYCWMP_MAC_DES,(void *)MACFilterDescription);
		}

		if(strlen(URLFilterDescription)>0){
			apmib_set(MIB_EASYCWMP_URL_DES,(void *)URLFilterDescription);
		}

		if(strlen(ICMPBlocking)>0){//允许从WAN口PING
			int iICMPBlocking=!strcmp(ICMPBlocking,"TRUE")?1:0;
			apmib_set(MIB_PING_WAN_ACCESS_ENABLED,(void *)&iICMPBlocking);
		}
		
		if(strlen(IPsecPassthrough)>0){//IPSec穿透
			int iIPsecPassthrough=!strcmp(IPsecPassthrough,"TRUE")?1:0;
			apmib_set(MIB_VPN_PASSTHRU_IPSEC_ENABLED,(void *)&iIPsecPassthrough);
		}

		if(strlen(PPTPPassthrough)>0){//PPTP穿透	
			int iPPTPPassthrough=!strcmp(PPTPPassthrough,"TRUE")?1:0;
			apmib_set(MIB_VPN_PASSTHRU_PPTP_ENABLED,(void *)&iPPTPPassthrough);
		}

		if(strlen(L2TPPassthrough)>0){//L2TP穿透	
			int iL2TPPassthrough=!strcmp(L2TPPassthrough,"TRUE")?1:0;
			apmib_set(MIB_VPN_PASSTHRU_L2TP_ENABLED,(void *)&iL2TPPassthrough);
		}

		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");
		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_Firewall_IP(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		int i=0,entryNum=0;
		char *type=NULL, *ip_rule=NULL, ip[32]={0}, port_buf[16] = {0},ip_en[8]={0};
		IPFILTER_T ip_entry;
		
		cJSON *root=cJSON_CreateArray();
		apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
		cJSON *ip_arry = cJSON_CreateArray();
		for (i=1; i<=entryNum; i++){
			cJSON *ip_item= cJSON_CreateObject();
			cJSON_AddItemToArray(ip_arry,ip_item);
			
			*((char *)&ip_entry) = (char)i;
			if ( !apmib_get(MIB_IPFILTER_TBL, (void *)&ip_entry))
				return -1;
			sprintf(ip,"%s",inet_ntoa(*((struct in_addr *)ip_entry.ipAddr)));
			if ( !strcmp(ip, "0.0.0.0"))
				strcpy(ip,"----");
			
			if ( ip_entry.protoType == PROTO_BOTH )
				type = "TCP+UDP";
			else if ( ip_entry.protoType == PROTO_TCP )
				type = "TCP";
			else
				type = "UDP";

			sprintf(port_buf, "%d-%d", ip_entry.fromPort, ip_entry.toPort);
			
			cJSON_AddStringToObject(ip_item,"Enable","TRUE");
			cJSON_AddStringToObject(ip_item,"Description", ip_entry.comment);
			cJSON_AddStringToObject(ip_item,"CreationDate", ip_entry.creTime);
			cJSON_AddStringToObject(ip_item,"ExpiryDate", "9999-12-31T23:59:59Z");
			cJSON_AddStringToObject(ip_item,"DestIP", "");
			cJSON_AddStringToObject(ip_item,"SourceIP", ip);
			cJSON_AddStringToObject(ip_item,"Protocol", type);
			cJSON_AddStringToObject(ip_item,"DestPort", port_buf);
			cJSON_AddStringToObject(ip_item,"DestPortRangeMax", "65535");
			cJSON_AddStringToObject(ip_item,"X_HUMAX_SourceMACAddress", "");
			cJSON_AddStringToObject(ip_item,"X_HUMAX_URL", "");
		}
		ip_rule = cJSON_Print(ip_arry);

		apmib_get_bool(MIB_IPFILTER_ENABLED,ip_en);
		
		char *frName[]={"Device.Firewall.Chain.1.Enable", \
						"Device.Firewall.Chain.1.Name",\
						"Device.Firewall.Chain.1.RuleNumberOfEntries",\
						"Rule"};		

		char *frValue[]={ip_en,\
						"IP Firewall",\
						NUM_FIREWARLL1,\
						ip_rule};
		
		int frlen = sizeof(frName)/sizeof(char *);
		addPandValueToArray(root, frlen, frName, frValue);

		cJSON_Delete(ip_arry);
		free(ip_rule);

		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		cJSON *chain,*subObj;	
		int entryNum=0,i=0,j=0;
		IPFILTER_T ipEntry;
		SCHEFILTER_T scheEntry;
		char port_f[8] = {0}, port_t[8] = {0}, cur_time[32]={0};
		char * Enable=websGetVar(data, T("Device.Firewall.Chain.1.Enable"), "");//IP过滤总开关
		//char * Name=websGetVar(data, T("Device.Firewall.Chain.1.Name"), ""); //	未做处理

		chain = cJSON_Parse(websGetVar(data, T("Device.Firewall.Chain.1.Rule."), ""));

		if(strlen(Enable)>0){//IP/端口过滤
			int iIPFilterEnable=!strcmp(Enable,"TRUE")?1:0;
			apmib_set(MIB_IPFILTER_ENABLED,(void *)&iIPFilterEnable);
		}
		
		//删除原有规则
		if(cJSON_GetArraySize(chain)>0){
			apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
			for (j=entryNum; j>0;j--) {
				*((char *)(void *)&ipEntry) = (char)j;
				apmib_get(MIB_IPFILTER_TBL, (void *)&ipEntry);
				apmib_set(MIB_IPFILTER_DEL, (void *)&ipEntry);
			}
		}
		
		for(i=0;i<cJSON_GetArraySize(chain);i++){	
			subObj = cJSON_GetArrayItem(chain,i);
			//char * enable = websGetVar(chain, T("Enable"), T("")); //已改为只读。
			char * description = websGetVar(subObj, T("Description"), T("")); 
			//char * creationDate = websGetVar(chain, T("CreationDate"), T("")); //已改为只读。
			char * expiryDate = websGetVar(subObj, T("ExpiryDate"), T("")); 
			char * destIp= websGetVar(subObj, T("DestIP"), T("")); 
			char * sourceIp = websGetVar(subObj, T("SourceIP"), T("")); 
			char * protocol = websGetVar(subObj, T("Protocol"), T("")); 
			char * destport = websGetVar(subObj, T("DestPort"), T("")); 
			char * destportrangeMax = websGetVar(subObj, T("DestPortRangeMax"), T("")); 
			char * sourceMacAddress = websGetVar(subObj, T("X_HUMAX_SourceMACAddress"), T(""));
			
			if(strlen(sourceIp)>4){
				//写入ACS设置的规则
				memset(&ipEntry, '\0', sizeof(ipEntry));
				memset(&scheEntry, '\0', sizeof(scheEntry));
				inet_aton(sourceIp, (struct in_addr *)&ipEntry.ipAddr);
				if(! strcmp(protocol, T("TCP"))){
					ipEntry.protoType = PROTO_TCP;
				}else if( !strcmp(protocol, T("UDP"))){
					ipEntry.protoType = PROTO_UDP;
				}else if( !strcmp(protocol, T("TCP+UDP"))){
					ipEntry.protoType = PROTO_BOTH;
				}else
					return -1;

				strcpy((char *)ipEntry.comment, description);
			
				sscanf(destport, "%[^-]-%[^-]", port_f, port_t);

				ipEntry.fromPort = atoi(port_f);
				if ( !port_t[0] )
					ipEntry.toPort = ipEntry.fromPort;
				else
					ipEntry.toPort = atoi(port_t);

				//创建规则时间
				get_Create_Time(cur_time);
				strcpy((char *)ipEntry.creTime, cur_time);
			
				apmib_set(MIB_IPFILTER_DEL, (void *)&ipEntry);
				apmib_set(MIB_IPFILTER_ADD, (void *)&ipEntry);

				//for fwschedual
				inet_aton(sourceIp, (struct in_addr *)&scheEntry.ipAddr);
				scheEntry.protoType = ipEntry.protoType;
				string_to_hex("000000000000", scheEntry.macAddr,12);
				strcpy((char *)scheEntry.day,"1,2,3,4,5,6,7");
				strcpy((char *)scheEntry.stime,"00:00");
				strcpy((char *)scheEntry.ttime,"23:59");
				apmib_set(MIB_SCHEFILTER_DEL, (void *)&scheEntry);
				apmib_set(MIB_SCHEFILTER_ADD, (void *)&scheEntry);
			}
		}
		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");
		cJSON_Delete(chain);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;

}


int cwmp_Firewall_Mac(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		int i=0,entryNum=0;
		char *type=NULL,*mac_rule=NULL,mac_buf[32]={0},mac_en[8]={0};
		MACFILTER_T mac_entry;
		
		cJSON *root=cJSON_CreateArray();
		apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
		cJSON *mac_arry	= cJSON_CreateArray();
		for (i=1; i<=entryNum; i++){
			cJSON *mac_item	= cJSON_CreateObject();
			cJSON_AddItemToArray(mac_arry,mac_item);
			
			*((char *)&mac_entry) = (char)i;
			if ( !apmib_get(MIB_MACFILTER_TBL, (void *)&mac_entry))
				return -1;

			snprintf(mac_buf, 32, ("%02x:%02x:%02x:%02x:%02x:%02x"),
			mac_entry.macAddr[0], mac_entry.macAddr[1], mac_entry.macAddr[2],
			mac_entry.macAddr[3], mac_entry.macAddr[4], mac_entry.macAddr[5]);
			
			cJSON_AddStringToObject(mac_item, "Enable","TRUE");
			cJSON_AddStringToObject(mac_item, "Description",mac_entry.comment);
			cJSON_AddStringToObject(mac_item, "CreationDate",mac_entry.creTime);
			cJSON_AddStringToObject(mac_item, "ExpiryDate","9999-12-31T23:59:59Z");
			cJSON_AddStringToObject(mac_item, "DestIP","");
			cJSON_AddStringToObject(mac_item, "SourceIP","");
			cJSON_AddStringToObject(mac_item, "Protocol","");
			cJSON_AddStringToObject(mac_item, "DestPort","");
			cJSON_AddStringToObject(mac_item, "DestPortRangeMax","65535");
			cJSON_AddStringToObject(mac_item, "X_HUMAX_SourceMACAddress",mac_buf);
			cJSON_AddStringToObject(mac_item, "X_HUMAX_URL", "");
		}
		mac_rule = cJSON_Print(mac_arry);

		apmib_get_bool(MIB_MACFILTER_ENABLED,mac_en);
	
		char *frName[]={"Device.Firewall.Chain.2.Enable", \
						"Device.Firewall.Chain.2.Name",\
						"Device.Firewall.Chain.2.RuleNumberOfEntries",\
						"Rule"};		

		char *frValue[]={mac_en,\
						"MAC Firewall",\
						NUM_FIREWARLL2,\
						mac_rule};
		
		int frlen = sizeof(frName)/sizeof(char *);
		addPandValueToArray(root, frlen, frName, frValue);

		cJSON_Delete(mac_arry);
		free(mac_rule);

		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		cJSON *chain,*subObj;	
		int entryNum=0,i=0;
		char macbuf[32]={0},macaddr[32]={0},*q=NULL,cre_time[32]={0};
		
		MACFILTER_T macEntry;
		SCHEFILTER_T scheEntry;
		
		char * Enable=websGetVar(data, T("Device.Firewall.Chain.2.Enable"), "");//	MAC过滤总开关
		//char * Name=websGetVar(data, T("Device.Firewall.Chain.2.Name"), ""); //	未做处理
		chain = cJSON_Parse(websGetVar(data, T("Device.Firewall.Chain.2.Rule."), ""));

		if(strlen(Enable)>0){//MAC过滤
			int iMACFilterEnable=!strcmp(Enable,"TRUE")?1:0;
			apmib_set(MIB_MACFILTER_ENABLED,(void *)&iMACFilterEnable);
		}
		
		//删除原有规则
		if(cJSON_GetArraySize(chain)>0){
			apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
			for (i=entryNum; i>0; i--) {
				*((char *)(void *)&macEntry) = (char)i;
				apmib_get(MIB_MACFILTER_TBL, (void *)&macEntry);
				apmib_set(MIB_MACFILTER_DEL, (void *)&macEntry);
			}
		}
		
		for(i=0;i<cJSON_GetArraySize(chain);i++){	
			subObj = cJSON_GetArrayItem(chain,i);
			//char * enable = websGetVar(chain, T("Enable"), T("")); //模板已经改变它的属性为只读。
			char * description = websGetVar(subObj, T("Description"), T("")); 
			//char * creationDate = websGetVar(chain, T("CreationDate"), T("")); //模板已经改变它的属性为只读。
			char * expiryDate = websGetVar(subObj, T("ExpiryDate"), T("")); 
			char * destIp= websGetVar(subObj, T("DestIP"), T("")); 
			char * sourceIp = websGetVar(subObj, T("SourceIP"), T("")); 
			char * protocol = websGetVar(subObj, T("Protocol"), T("")); 
			char * destport = websGetVar(subObj, T("DestPort"), T("")); 
			char * destportrangeMax = websGetVar(subObj, T("DestPortRangeMax"), T("")); 
			char * sourceMacAddress = websGetVar(subObj, T("X_HUMAX_SourceMACAddress"), T(""));
			
			if(strlen(sourceMacAddress)>0){
				//去掉MAC 地址中的":"符号
				memset(macbuf, 0x00, sizeof(macbuf));
				memset(macaddr, 0x00, sizeof(macaddr));
				sprintf(macbuf,"%s",sourceMacAddress);
				strcat(macaddr,strtok(macbuf,":"));
				while(q=strtok(NULL,":")){
					strcat(macaddr,q);
				}

				strcpy((char *)macEntry.comment, description);

				//创建规则时间
				get_Create_Time(cre_time);
				strcpy((char *)macEntry.creTime, cre_time);
			
				string_to_hex(macaddr, macEntry.macAddr,strlen(macaddr));
				strcpy((char *)macEntry.comment, description);					
				apmib_set(MIB_MACFILTER_DEL, (void *)&macEntry);
				apmib_set(MIB_MACFILTER_ADD, (void *)&macEntry);

				//for fwschedual
				string_to_hex(macaddr, scheEntry.macAddr,strlen(macaddr));
				inet_aton("0.0.0.0", (struct in_addr *)&scheEntry.ipAddr);
				scheEntry.protoType = 0;
				scheEntry.fromPort = 0;
				scheEntry.toPort = 0;
				strcpy((char *)scheEntry.day,"1,2,3,4,5,6,7");
				strcpy((char *)scheEntry.stime,"00:00");
				strcpy((char *)scheEntry.ttime,"23:59");
				apmib_set(MIB_SCHEFILTER_DEL, (void *)&scheEntry);
				apmib_set(MIB_SCHEFILTER_ADD, (void *)&scheEntry);
			}
		}
		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");
		cJSON_Delete(chain);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_Firewall_Url(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	cJSON * root=cJSON_CreateArray();
	if(strcmp(action,"get")==0){
		int i=0,entryNum=0;
		char *url_rule=NULL, url_buf[64] = {0}, mac_buf[32] = {0},url_en[8]={0};
		URLFILTER_T url_entry;
		
		cJSON *root=cJSON_CreateArray();
		apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
			cJSON *url_arry = cJSON_CreateArray();
			for (i=1; i<=entryNum; i++){
				cJSON *url_item	= cJSON_CreateObject();
				cJSON_AddItemToArray(url_arry,url_item);
				
				*((char *)&url_entry) = (char)i;
				if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&url_entry))
					return -1;

				strcpy(url_buf, url_entry.urlAddr);
				strncpy(mac_buf, url_buf + strlen(url_buf) - 17, 17);
				*(url_buf + strlen(url_buf) - 17) = '\0';

				if(!strncmp(mac_buf, "xx:xx", strlen("xx:xx")-1))
					strcpy(mac_buf, "All Device");

				cJSON_AddStringToObject(url_item,"Enable","TRUE");
				cJSON_AddStringToObject(url_item,"Description",url_entry.comment);
				cJSON_AddStringToObject(url_item,"CreationDate",url_entry.creTime);
				cJSON_AddStringToObject(url_item,"ExpiryDate","9999-12-31T23:59:59Z");
				cJSON_AddStringToObject(url_item,"DestIP","");
				cJSON_AddStringToObject(url_item,"SourceIP","");
				cJSON_AddStringToObject(url_item,"Protocol","");
				cJSON_AddStringToObject(url_item,"DestPort","");
				cJSON_AddStringToObject(url_item,"DestPortRangeMax","65535");
				cJSON_AddStringToObject(url_item,"X_HUMAX_SourceMACAddress", mac_buf);	
				cJSON_AddStringToObject(url_item,"X_HUMAX_URL", url_buf);
					
			}
			url_rule = cJSON_Print(url_arry);

		apmib_get_bool(MIB_URLFILTER_ENABLED,url_en);

		char *frName[]={"Device.Firewall.Chain.3.Enable", \
						"Device.Firewall.Chain.3.Name",\
						"Device.Firewall.Chain.3.RuleNumberOfEntries",\
						"Rule"};		

		char *frValue[]={url_en,\
						"URL Firewall",\
						NUM_FIREWARLL3,\
						url_rule};
		
		int frlen = sizeof(frName)/sizeof(char *);
		addPandValueToArray(root, frlen, frName, frValue);

		cJSON_Delete(url_arry);
		free(url_rule);
		
		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		cJSON *chain,*subObj;	
		int entryNum=0,i=0;
		URLFILTER_T urlEntry;
		char mac_buf[32] = {0}, url[64] = {0}, cur_time[32]={0};
		
		char * Enable=websGetVar(data, T("Device.Firewall.Chain.2.Enable"), "");//	URL总开关
		//char * Name=websGetVar(data, T("Device.Firewall.Chain.2.Name"), ""); //	未做处理
		chain = cJSON_Parse(websGetVar(data, T("Device.Firewall.Chain.3.Rule."), ""));

		if(strlen(Enable)>0){//URL过滤
			int iURLFilterEnable=!strcmp(Enable,"TRUE")?1:0;
			apmib_set(MIB_URLFILTER_ENABLED,(void *)&iURLFilterEnable);
		}
		
		//删除原有规则
		if(cJSON_GetArraySize(chain)>0){
			apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
			for (i=entryNum; i>0; i--) {
				*((char *)(void *)&urlEntry) = (char)i;
				apmib_get(MIB_URLFILTER_TBL, (void *)&urlEntry);
				apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);	
			}
		}
		
		for(i=0;i<cJSON_GetArraySize(chain);i++){	
			subObj = cJSON_GetArrayItem(chain,i);
			//char * enable = websGetVar(chain, T("Enable"), T("")); //已改为只读。
			char * description = websGetVar(subObj, T("Description"), T("")); 
			//char * creationDate = websGetVar(chain, T("CreationDate"), T("")); //已经改为只读。
			char * expiryDate = websGetVar(subObj, T("ExpiryDate"), T("")); 
			char * destIp= websGetVar(subObj, T("DestIP"), T("")); 
			char * sourceIp = websGetVar(subObj, T("SourceIP"), T("")); 
			char * protocol = websGetVar(subObj, T("Protocol"), T("")); 
			char * destport = websGetVar(subObj, T("DestPort"), T("")); 
			char * destportrangeMax = websGetVar(subObj, T("DestPortRangeMax"), T("")); 
			char * sourceMacAddress = websGetVar(subObj, T("X_HUMAX_SourceMACAddress"), T(""));
			memset(url, 0, sizeof(url));
			strncpy(url, websGetVar(subObj, "X_HUMAX_URL", ""), 63-17);

			if(strlen(url)){
				if(!strcmp(sourceMacAddress, "All Device"))
					strcpy(mac_buf, "xx:xx:xx:xx:xx:xx");
				else
					strcpy(mac_buf, sourceMacAddress);

				strcat(url, mac_buf);

				strcpy((char *)urlEntry.comment, description);

				//创建规则时间
				get_Create_Time(cur_time);
				strcpy((char *)urlEntry.creTime, cur_time);
				
				strcpy((char *)urlEntry.urlAddr, url);	
				apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);
				apmib_set(MIB_URLFILTER_ADD, (void *)&urlEntry);
			}

		}
		
		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");
		cJSON_Delete(chain);

		cJSON *root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		char * output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_NAT(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	cJSON * root=cJSON_CreateArray();
	if(strcmp(action,"get")==0){

		char *output=NULL;
		char dmzen[16]={0},ptfor[16]={0},DMZAddress[32]={0},type[16]={0};
		int entryNum,i;
		PORTFW_T entry;

		apmib_get_bool(MIB_DMZ_ENABLED,dmzen);
		apmib_get_bool(MIB_PORTFW_ENABLED,ptfor);
		apmib_get( MIB_DMZ_HOST,  (void *)DMZAddress);
		apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
		
		char * frName[]={NAT_HD1"PortMappingNumberOfEntries",
						 NAT_HD1"X_HUMAX_PortForwardingEnable",
						 NAT_HD1"X_HUMAX_DMZEnable",
						 NAT_HD1"X_HUMAX_DMZDestIPAddress"};
		
		char * frValue[]={NUM_NAT, \
						  ptfor, \
						  dmzen,\
						  inet_ntoa(*((struct in_addr *)DMZAddress))};
		
		int frlen = sizeof(frName)/sizeof(char *);
		addPandValueToArray(root,frlen,frName,frValue);

		cJSON *arry	= cJSON_CreateArray();
		for (i=1; i<=entryNum; i++){
			cJSON *item	= cJSON_CreateObject();
			cJSON_AddItemToArray(arry,item);
			*((char *)&entry) = (char)i;
			if ( !apmib_get(MIB_PORTFW_TBL, (void *)&entry))
				return -1;
			//ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));

			if ( entry.protoType == PROTO_BOTH )
				strcpy(type,"TCP+UDP");
			else if ( entry.protoType == PROTO_TCP )
				strcpy(type,"TCP");
			else
				strcpy(type,"UDP");	
			
			cJSON_AddStringToObject(item, "Enable", 		"TRUE");
			cJSON_AddStringToObject(item, "Status",			"Enabled");
			cJSON_AddNumberToObject(item, "ExternalPort",	entry.toPort);
			cJSON_AddNumberToObject(item, "ExternalPortEndRange", 65535);
			cJSON_AddNumberToObject(item, "InternalPort",	entry.fromPort);
			cJSON_AddStringToObject(item, "Protocol",		type);
			cJSON_AddStringToObject(item, "InternalClient", inet_ntoa(*((struct in_addr *)entry.ipAddr)));
			cJSON_AddStringToObject(item, "Description", 	entry.comment);
		}
		char *arry_str = cJSON_Print(arry);
		char *maName[]={"PortMapping"};
		char *maValue[]={arry_str};
		int malen = sizeof(maName)/sizeof(char *);
		addPandValueToArray(root,malen,maName,maValue);

		cJSON_Delete(arry);
		free(arry_str);	
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		CSTE_DEBUG("-----NAT   action   set --------\n");
		int i=0,enable=0;
		int entryNum;
		char *output = NULL;
		struct in_addr  ip_addr;
		PORTFW_T entry;
		cJSON *subObj,*PortMapping;
		cJSON *root=cJSON_CreateObject();
		
		char * DMZEnable = websGetVar(data, T(NAT_HD1"X_HUMAX_DMZEnable"), T(""));
		char * DMZDestIPAddress = websGetVar(data, T(NAT_HD1"X_HUMAX_DMZDestIPAddress"), T(""));
		char * PortForwardingEnable = websGetVar(data, T(NAT_HD1"X_HUMAX_PortForwardingEnable"), T(""));

		if(strlen(DMZEnable)>0){ //DMZ Enable
			int iDMZEnable=!strcmp(DMZEnable,"TRUE")?1:0;
			apmib_set(MIB_DMZ_ENABLED,(void *)&iDMZEnable);
		}

		if (inet_aton(DMZDestIPAddress, &ip_addr))
			apmib_set( MIB_DMZ_HOST, (void *)&ip_addr);
			
		if(strlen(PortForwardingEnable)>0){
			int iPortForwardingEnable=!strcmp(PortForwardingEnable,"TRUE")?1:0;
			apmib_set(MIB_PORTFW_ENABLED,(void *)&iPortForwardingEnable);
		}

		//先删除原来的TABLE ,再写入ACS	下发的数据
		apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
		for (i=entryNum; i>0; i--) {
			*((char *)(void *)&entry) = (char)i;
			apmib_get(MIB_PORTFW_TBL, (void *)&entry);
			apmib_set(MIB_PORTFW_DEL, (void *)&entry);			
		}
		
		//不能直接PortMapping = cJSON_GetObjectItem(data,"Device.NAT.PortMapping.");
		//为方便，目前动态参数名最后带有一个点
		PortMapping = cJSON_Parse(websGetVar(data, T("Device.NAT.PortMapping."), ""));
		for(i=0;i<cJSON_GetArraySize(PortMapping);i++){	
			subObj = cJSON_GetArrayItem(PortMapping, i);
			char * enabled=websGetVar(subObj, T("Enable"), T(""));
			char * wprf=websGetVar(subObj, T("ExternalPort"), T(""));
			 //没有对应MIB项。
			//char * range=websGetVar(subObj, T("ExternalPortEndRange"), T(""));
			char * prf=websGetVar(subObj, T("InternalPort"), T(""));
			char * protocol=websGetVar(subObj, T("Protocol"), T(""));
			char * ip_address=websGetVar(subObj, T("InternalClient"), T(""));
			char * comment=websGetVar(subObj, T("Description"), T(""));
			//ACS没有传这个参数IP  地址
			inet_aton(ip_address, (struct in_addr *)&entry.ipAddr);	
			entry.fromPort = (unsigned short)atoi(prf);
			entry.toPort   = (unsigned short)atoi(wprf);

			if(! strcmp(protocol, T("TCP"))){
				entry.protoType = PROTO_TCP;
			}else if( !strcmp(protocol, T("UDP"))){
				entry.protoType = PROTO_UDP;
			}else if( !strcmp(protocol, T("TCP+UDP"))){
				entry.protoType = PROTO_BOTH;
			}else{
				goto OUT;
			}
			
			strcpy((char *)entry.comment, comment);					
			apmib_set(MIB_PORTFW_DEL, (void *)&entry);
			apmib_set(MIB_PORTFW_ADD, (void *)&entry);
		}
		apmib_update_web(CURRENT_SETTING);
		system("sysconf firewall");
		//注意释放内存
		cJSON_Delete(PortMapping);

OUT:
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_DNS(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	char dns1_buf[128]={0},dns2_buf[128]={0},buf1[128]={0},buf2[128]={0};
	int dns_num=0,idns_mode;
	apmib_get(MIB_DNS_MODE,  (void *)&idns_mode);
	if(strcmp(action,"get")==0){
		char *output=NULL;
		cJSON *root=cJSON_CreateArray();		
		if(getOperationMode()!=1){
			if(idns_mode==1){//manual
				apmib_get(MIB_DNS1,(void *)buf1);
				apmib_get(MIB_DNS2,(void *)buf2);
				sprintf(dns1_buf,"%s",inet_ntoa(*((struct in_addr *)buf1)));
				sprintf(dns2_buf,"%s",inet_ntoa(*((struct in_addr *)buf2)));
			}else{//auto
				strcpy(dns1_buf,getDns(1));
				strcpy(dns2_buf,getDns(2));
			}
			if(strlen(dns1_buf)>0 && strcmp(dns1_buf,"0.0.0.0"))
				dns_num++;
			if(strlen(dns2_buf)>0 && strcmp(dns2_buf,"0.0.0.0"))
				dns_num++;
			char * cName[]={DNS_HD1"Enable",
						    DNS_HD1"Status"};
			
			char * cValue[]={"TRUE", \
							 "Enabled"};
			int clen = sizeof(cName)/sizeof(char *);
			addPandValueToArray(root,clen,cName,cValue);
			
			char * iName[]={DNS_HD1"ServerNumberOfEntries"};
			char * iValue[]={dns_num};
			int ilen = sizeof(iName)/sizeof(char *);
			addIntValueToArray(root,ilen,iName,iValue);

			if(dns_num>0)
			{
				char * s1Name[]={DNS_HD2"Enable", \
						    	DNS_HD2"Status", \
						    	DNS_HD2"DNSServer"};
			
				char * s1Value[]={"TRUE", \
							 	 "Enabled", \
							 	 dns1_buf};
				int s1len = sizeof(s1Name)/sizeof(char *);
				addPandValueToArray(root,s1len,s1Name,s1Value);
				if(dns_num==2)
				{
					char * s2Name[]={DNS_HD3"Enable", \
									DNS_HD3"Status", \
									DNS_HD3"DNSServer"};
					
					char * s2Value[]={"TRUE", \
									 "Enabled", \
									 dns2_buf};
					int s2len = sizeof(s2Name)/sizeof(char *);
					addPandValueToArray(root,s2len,s2Name,s2Value);
				}
			}

		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		if(getOperationMode()!=1){
			int ret=0;
			char *arg=NULL;
			struct in_addr dns1, dns2;
			struct in_addr dns1_old, dns2_old;
			apmib_get(MIB_DNS1, (void *)&dns1_old);
    		apmib_get(MIB_DNS2, (void *)&dns2_old);
	
			char *DNSServer1 = websGetVar(data, T(DNS_HD2"DNSServer"), T(""));
			char *DNSServer2 = websGetVar(data, T(DNS_HD3"DNSServer"), T(""));
			
	
			if (idns_mode==1) {
				if( !inet_aton(DNSServer1, &dns1) ) {
		            goto end;
				}
		        apmib_set(MIB_DNS1, (void *)&dns1);
		        
		        if( !inet_aton(DNSServer2, &dns2) ){
		            goto end;
		        }
		        apmib_set(MIB_DNS2, (void *)&dns2);
		        if ( *((long *)&dns1) != *((long *)&dns1_old) ||*((long *)&dns2) != *((long *)&dns2_old))
		            ret = 1;
			}
			if(ret == 1)
		        arg = "all";
		    else
		        arg = "wan";

			//延迟可能导致网络断开的操作，以避免多项数据相继下发时
			//在部分数据尚未完成设置之前就断开网络
			int pid=fork();
			if(0 == pid)
			{
				sleep(5);
				run_init_script(arg);	
				exit(0);
			}
    		
		}
		cJSON *root=cJSON_CreateObject();
end:
		cJSON_AddNumberToObject(root,"status", 0);		
		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	return 0;
}

int cwmp_Hosts(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL, *buf = NULL, *ptr = NULL;
		char macaddr[32]={0}, infv[64]={0}, tmpBuf[128] = {0};
		char ipAddr[32]={0}, macAddr[32]={0}, liveTime[32]={0}, hostName[64]={0},inittime[64]={0};
		char dhcp_hosts[NUM_Hosts*20] = {0};
		char static_hosts[NUM_Hosts*20] = {0};
		
		int enable, static_num, pid, ret;
		int i = 0, j = 0, count = 0, error;
		unsigned long fileSize=0, size_bak,uptime;
		FILE * fp;
		struct stat status;
		struct sysinfo s_sysram;
		DHCPRSVDIP_T entry;
		
		strcpy(infv, "Device.Ethernet.Interface.1");
		cJSON *root=cJSON_CreateArray();
		cJSON *starry=cJSON_CreateArray();

	    snprintf(tmpBuf, 128, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	    pid = getPid(tmpBuf);
	    if( pid > 0)
	    {
	        snprintf(tmpBuf, 128, "kill -SIGUSR1 %d\n", pid);
	        system(tmpBuf);
	    }
	    usleep(1000);
	    if ( stat(_PATH_DHCPS_LEASES, &status) < 0 ){
	    	goto out;
	    }

		//fileSize will be modified by getOneDhcpClient, so bak it.
	    size_bak = fileSize = status.st_size;
	    buf = malloc(fileSize);
	    if ( buf != NULL )
	    {
	        if( (fp=fopen(_PATH_DHCPS_LEASES, "r"))==NULL )
	        {
	        	free(buf);
	    		return 0;
	        }
	        fread(buf, 1, fileSize, fp);
	        ptr = buf;
	        while(count <NUM_Hosts)
	        {
	            ret = getOneDhcpClient(&ptr, &fileSize, ipAddr, macAddr, liveTime, hostName);
	            if(ret<0)   break;
	            if(ret==0)  continue;
	            if(!strcmp(macAddr,"00:00:00:00:00:00"))    continue;

				strcat(dhcp_hosts, macAddr);
				strcat(dhcp_hosts, ";");
				count++;
	        }
			
			free(buf);
	    }

		CSTE_DEBUG("the result of count=[%d]\n", count);

		apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&enable);//静态DHCP
		apmib_get(MIB_DHCPRSVDIP_TBL_NUM,(void *)&static_num);

		error = sysinfo(&s_sysram);//获取时间和RAM值
		if(error){
			dprintf("%s get system information failure\n","cwmp_Hosts()");
		}
		uptime = (unsigned long) s_sysram.uptime;
		sprintf(inittime, "%d s", uptime);;
		
		if(static_num!=0 && count < NUM_Hosts){
			//note: the index MUST start from 1, not 0.
			for(i = 1; (i<=static_num) && (i<= NUM_Hosts-count); ++i)
		    {
		    	cJSON *stitem=cJSON_CreateObject();
				
		        *((char *)&entry) = (char)i;
				
		        apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
		        if (!memcmp(entry.macAddr, "\x0\x0\x0\x0\x0\x0", 6))
					macaddr[0]='\0';
				else			
					sprintf(macaddr,"%02x:%02x:%02x:%02x:%02x:%02x",entry.macAddr[0],entry.macAddr[1],\
					entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

				//在dhcp 列表中的项是Active 的
				if(strstr(dhcp_hosts, macaddr)){
					cJSON_AddStringToObject(stitem,"Active","TRUE");
				}else{
					cJSON_AddStringToObject(stitem,"Active","FALSE");
				}

				cJSON_AddStringToObject(stitem,"PhysAddress",macaddr);
				cJSON_AddStringToObject(stitem,"IPAddress",inet_ntoa(*((struct in_addr*)entry.ipAddr)));
				cJSON_AddStringToObject(stitem,"AddressSource", "Static");
				cJSON_AddStringToObject(stitem,"Layer1Interface",infv);
				cJSON_AddStringToObject(stitem,"HostName","Unknow");
				cJSON_AddStringToObject(stitem,"ActiveLastChange",inittime);
				cJSON_AddStringToObject(stitem,"IPv4AddressNumberOfEntries", "1");
				cJSON_AddStringToObject(stitem,"IPv6AddressNumberOfEntries", "1");
				cJSON_AddStringToObject(stitem,"IPv4Address.1.IPAddress",inet_ntoa(*((struct in_addr*)entry.ipAddr)));	

				cJSON_AddItemToArray(starry, stitem);
				strcat(static_hosts, macaddr);
				strcat(static_hosts, ";");
			}
		}

		CSTE_DEBUG("the result of i=[%d]\n", i);

	    //buf has been modified. so re -read it.
        fread(buf, 1, size_bak, fp);
        fclose(fp);
		
		ptr = buf;	//this is necessary
		
        while(1)
        {
        	cJSON *apitem=cJSON_CreateObject();
			
            ret = getOneDhcpClient(&ptr, &size_bak, ipAddr, macAddr, liveTime, hostName);
            if(ret<0)   break;
            if(ret==0)  continue;
            if(!strcmp(macAddr,"00:00:00:00:00:00"))    continue;

			//跳过已在静态列表中的项
			if(strstr(static_hosts, macAddr)){
					continue;
			}

			cJSON_AddStringToObject(apitem,"PhysAddress",macAddr);
			cJSON_AddStringToObject(apitem,"IPAddress",ipAddr);
			cJSON_AddStringToObject(apitem,"AddressSource", "DHCP");
			cJSON_AddStringToObject(apitem,"Layer1Interface", infv);
			cJSON_AddStringToObject(apitem,"HostName", hostName);
			cJSON_AddStringToObject(apitem,"Active","TRUE");
			cJSON_AddStringToObject(apitem,"ActiveLastChange",inittime);
			cJSON_AddStringToObject(apitem,"IPv4AddressNumberOfEntries", "1");
			cJSON_AddStringToObject(apitem,"IPv6AddressNumberOfEntries", "1");
			cJSON_AddStringToObject(apitem,"IPv4Address.1.IPAddress", ipAddr);

			cJSON_AddItemToArray(starry, apitem);
        }
		
		free(buf);
		
		char * intstate[]={"Device.Hosts.HostNumberOfEntries"};
		int intvl[]={ NUM_Hosts };
		int intlen = sizeof(intstate)/sizeof(char *);
		addIntValueToArray(root,intlen,intstate,intvl);

		char *stvl = cJSON_Print(starry);
		char * dhcps[]={"Host"};
		char * dhcpsValue[]={stvl};
		int dhcpslen = sizeof(dhcps)/sizeof(char *);
		addPandValueToArray(root,dhcpslen,dhcps,dhcpsValue);

		cJSON_Delete(starry);
		free(stvl);
out:		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		//无设值
	}
	return 0;
}

int cwmp_PPP(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char wanMode[32]={0},wanSt[32]={0};
		char pppen[32]={0},pppst[32]={0},ppptrig[64]={0};
		int arraylen,pppconntype=0;
		cJSON *root=cJSON_CreateArray();
			
		//wan mode
		getWanConnectMode(wanMode);
		if(getOperationMode()!=1){
			get_wan_connect_status(wanSt);
			if(!strcmp(wanMode,"PPPOE")){
				strcpy(pppen,"TRUE");
				if(!strcmp(wanSt,"connected")){
					strcpy(pppst,"Up");
				}else{
					strcpy(pppst,"Down");
				}
			}else{
				strcpy(pppen,"FALSE");
				strcpy(pppst,"Down");
			}
			apmib_get(MIB_PPP_CONNECT_TYPE,  (void *)&pppconntype);
			if(pppconntype==0){//auto:0 ondemand:1 manual:2
		        	strcpy(ppptrig,"AlwaysOn");
			}else if(pppconntype==2){
		        	strcpy(ppptrig,"Manual");
			}
			char * ppps[]={"Device.PPP.InterfaceNumberOfEntries",\
						   PPP_HD"Enable", \
						   PPP_HD"Status", \
						   PPP_HD"ConnectionTrigger", \
						   PPP_HD"PPPoE.ServiceName",\
						   PPP_HD"PPPoE.ACName"};
			
			char * pppValue[]={"1",\
							   pppen,\
							   pppst,\
							   ppptrig,\
							   "HUMAX",\
							   ""};
			
			int ppplen = sizeof(ppps)/sizeof(char *);
			addPandValueToArray(root,ppplen,ppps,pppValue);
		    
			char *StrGetName[]={PPP_HD"Username", \
								PPP_HD"Password"};
			
			int  StrGetId[]={MIB_PPP_USER_NAME, \
							 MIB_PPP_PASSWORD};
			
			arraylen = sizeof(StrGetName)/sizeof(char *);
			addObjectToArray(root, arraylen, StrGetName, StrGetId);

			char * IntGetName[]={PPP_HD"PPPoE.SessionID"};
			int IntGetId[]={MIB_PPP_SESSION_NUM};
	   		int intlen = sizeof(IntGetName)/sizeof(char *);
			addObjectIntToArray(root,intlen,IntGetName,IntGetId);
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);	
	}
	else{
		cJSON *root = cJSON_CreateObject();
		char *output = NULL;
		
		char *Enable = websGetVar(data, T(PPP_HD"Enable"), T(""));  //Writable?
		char *Username = websGetVar(data, T(PPP_HD"Username"), T(""));
		char *Password = websGetVar(data, T(PPP_HD"Password"), T(""));
		char *ConnectionTrigger = websGetVar(data, T(PPP_HD"ConnectionTrigger"), T(""));
		//char *ACName = websGetVar(data, T(PPP_HD"PPPoE.ACName"), T(""));		//No MIB to wirte

		if(strlen(ConnectionTrigger)>0){
			int pppconntype;
			if(!strcmp(ConnectionTrigger, "AlwaysOn"))
				pppconntype = 0;
			else
				pppconntype = 2;
			apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&pppconntype);
		}
		
		if(strlen(Username)>0){
			apmib_set(MIB_PPP_USER_NAME,(void *)Username);
		}
		
		if(strlen(Password)>0){
			apmib_set(MIB_PPP_PASSWORD,(void *)Password);
		}
		
		apmib_update_web(CURRENT_SETTING);
		
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);

		//延迟可能导致网络断开的操作，以避免多项数据相继下发时
		//在部分数据尚未完成设置之前就断开网络
		int pid=fork();
		if(0 == pid)
		{
			sleep(5);
			run_init_script("all");	
			exit(0);
		}
	}
	return 0;
}

int cwmp_wifi(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	cJSON *root=cJSON_CreateArray();

	char *wifinfo[]={WIFI_HD1"RadioNumberOfEntries",\
					 WIFI_HD1"SSIDNumberOfEntries",\
					 WIFI_HD1"AccessPointNumberOfEntries"};
	int infovalue[]={RADIO_NUM,SSID_NUM,ACCESS_POINT_NUM};
	int infolen = sizeof(wifinfo)/sizeof(char *);
	addIntValueToArray(root,infolen,wifinfo,infovalue);
	
	char *output=NULL;
	output = cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int cwmp_wifi_basic(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	int wifiIdx=0;
	char wlan_if[32]={0};
	WDS_T entry;
	sprintf(wlan_if, "wlan%d", wifiIdx);
	SetWlan_idx(wlan_if);
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char wifien[32]={0},wifist[32]={0},opstand[32]={0},freband[32]={0},autochal[32]={0},bandwidth[32]={0};
		char extensc[32]={0},pream[32]={0},tmpower[32]={0},country[10]={0},chnnelUse[8]={0},ieehen[32]={0};
		char gudint[32]={0},pmode[32]={0};
		int wifiof,arraylen,channel,bgn,channel_bonding=1,contside,guard,premable,tmp,i,bgpt,entryNum=0;
		cJSON *root=cJSON_CreateArray();
		
		apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wifiof);
		if(wifiof==0){
			strcpy(wifien,"TRUE");
			strcpy(wifist,"Up");
		}else{
			strcpy(wifien,"FALSE");
			strcpy(wifist,"Down");
		}
		
		apmib_get(MIB_WLAN_CHANNEL_BONDING,(void *)&channel_bonding);
		if(channel_bonding==1){
			strcpy(bandwidth,"20/40MHz");
			apmib_get(MIB_WLAN_CONTROL_SIDEBAND,(void *)&contside);
			if(contside==0){
				strcpy(extensc,"BelowControlChannel");
			}else{
				strcpy(extensc,"AboveControlChannel");
			}
		}else{
			strcpy(bandwidth,"20MHz");
			strcpy(extensc,"Auto");
		}

		apmib_get(MIB_WLAN_SHORT_GI, (void *)&guard);
		if(guard==1){
			strcpy(gudint,"400nsec");
		}else{
			strcpy(gudint,"800nsec");
		}
	
		apmib_get(MIB_WLAN_CHANNEL,(void *)&channel);
		if(channel==0){
			strcpy(autochal,"TRUE");
		}else{
			strcpy(autochal,"FALSE");
		}
		
		apmib_get( MIB_WLAN_COUNTRY_STRING, (void *)country);
		if(strcmp(country,"")==0){	
			strcpy(country,"CN");	
		}
		if(!strcmp(country,"FR") || !strcmp(country,"BR") || !strcmp(country,"CN")|| !strcmp(country,"EU")){
			strcpy(chnnelUse,"1-13");
		}else if(!strcmp(country,"JP")){
			if(getWirelessBand(wlan_if)==1){
				strcpy(chnnelUse,"1-14");
			}else{
				strcpy(chnnelUse,"1-13");
			}
		}else{
			strcpy(chnnelUse,"1-11");
		}

		if(wifiIdx==0){
			strcpy(freband,"2.4GHz");
		}else{
			strcpy(freband,"5GHz");
		}
		apmib_set(MIB_WLAN_REGULATORY_DOMAIN, (char *)country);
		
		apmib_get(MIB_WLAN_BAND, (void *)&bgn);
		switch(bgn){
			case 1:
				strcpy(opstand,"B");break;
			case 2:
				strcpy(opstand,"G");break;
			case 3:
				strcpy(opstand,"B+G");break;	
			case 8:
				strcpy(opstand,"N");break;
			case 11:
				strcpy(opstand,"B+G+N");
			case 75:
				strcpy(opstand,"B+G+N+AC");//HUMAC
			default:
				CSTE_DEBUG("Unknow The WLAN0_BAND->%d\n",bgn);
		}
		
		apmib_get(MIB_WLAN_PREAMBLE_TYPE, (void *)&premable);
		if(premable){
			strcpy(pream,"short");
		}else{
			strcpy(pream,"long");
		}
		
		apmib_get(MIB_WLAN_RFPOWER_SCALE,(void *)&tmp);
		switch(tmp){
			case 0:
				sprintf(tmpower,"%d%%",100);break;
			case 1:
				sprintf(tmpower,"%d%%",75);break;
			case 2:
				sprintf(tmpower,"%d%%",50);break;
			case 3:
				sprintf(tmpower,"%d%%",35);break;	
			case 4:
				sprintf(tmpower,"%d%%",15);break;	
			default:
				sprintf(tmpower,"%d%%",100);break;
		}

#if HUMAX_WDS
		char humaxWDS[8]={0}
		apmib_get_bool(MIB_WLAN_WDS_ENABLED, humaxWDS);
#endif

		if (wifiIdx == 0) //2.4G为0,5G为1
			{
				strcpy(ieehen,"FALSE");
			}
		else
			{
				strcpy(ieehen,"TRUE");
			}
		apmib_get(MIB_WLAN_PROTECTION_DISABLED,(void *)&bgpt);
		if(bgpt==1){
			strcpy(pmode,"FALSE");
		}else{
			strcpy(pmode,"TRUE");
		}
		
		char * wifi[]={WIFI_HD2"Enable", \
					   WIFI_HD2"Status", \
					   WIFI_HD2"Upstream", \
					   WIFI_HD2"OperatingChannelBandwidth", \
					   WIFI_HD2"ExtensionChannel", \
					   WIFI_HD2"GuardInterval", \
					   WIFI_HD2"AutoChannelEnable", \
					   WIFI_HD2"ChannelsInUse", \
					   WIFI_HD2"OperatingFrequencyBand", \
					   WIFI_HD2"OperatingStandards",\
					   WIFI_HD2"PreambleType", \
					   WIFI_HD2"Name",\
					   WIFI_HD2"TransmitPower", \
					   WIFI_HD2"IEEE80211hEnabled",\
					   WIFI_HD2"X_HUMAX_ProtectionMode"
#if HUMAX_WDS
					   ,
					   WIFI_HD3"Enable",\
					   WIFI_HD3"Mode", \
					   WIFI_HD3"SlaveAPNumberOfEntries"
#endif
					   };
		char * wifiValue[]={wifien, \
							wifist,\
							"FALSE", \
							bandwidth,\
							extensc, \
							gudint,\
							autochal, \
							chnnelUse,\
							freband, \
							opstand,\
							pream, \
							wlan_if,\
							tmpower, \
							ieehen,\
							pmode
#if HUMAX_WDS
							,
							humaxWDS,\
							"Slave", \
							NUM_WiFi_Radio
#endif
							};
		int wifilen = sizeof(wifi)/sizeof(char *);
		addPandValueToArray(root,wifilen,wifi,wifiValue);

		char *strGetName[]={WIFI_HD2"RegulatoryDomain"};
		int strGetId[]={MIB_WLAN_REGULATORY_DOMAIN};
		int strlen = sizeof(strGetName)/sizeof(char *);
		addObjectToArray(root,strlen,strGetName,strGetId);
		
		char * IntGetName[]={WIFI_HD2"Channel", \
							 WIFI_HD2"FragmentationThreshold",\
							 WIFI_HD2"RTSThreshold", \
							 WIFI_HD2"BeaconPeriod",\
							 WIFI_HD2"DTIMPeriod"};
		int IntGetId[]={MIB_WLAN_CHANNEL, \
						MIB_WLAN_FRAG_THRESHOLD,
						MIB_WLAN_RTS_THRESHOLD, \
						MIB_WLAN_BEACON_INTERVAL,\
						MIB_WLAN_DTIM_PERIOD};
   		int intlen = sizeof(IntGetName)/sizeof(char *);
    	addObjectIntToArray(root,intlen,IntGetName,IntGetId);
		
#if HUMAX_WDS
		cJSON * wdsArry = cJSON_CreateArray();
		char wdsmac[32] = {0}, wdscommment[32] = {0};
		apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum);
		for (i=1; i<=entryNum; i++) {
			cJSON * wdsPramt = cJSON_CreateObject(); 
			memset(wdsmac, 0x00, sizeof(wdsmac));
			memset(wdscommment, 0x00, sizeof(wdscommment));
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_WDS, (void *)&entry);
			snprintf(wdsmac, sizeof(wdsmac), ("%02x:%02x:%02x:%02x:%02x:%02x"),
				entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
				entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
			strcpy(wdscommment, entry.comment);
			cJSON_AddItemToArray(wdsArry,wdsPramt);	
			cJSON_AddStringToObject(wdsPramt, "Description", wdscommment);
			cJSON_AddStringToObject(wdsPramt, "MACAddress",  wdsmac);	
		}
		char * arryVl = cJSON_Print(wdsArry);
		char * slave[]={"SlaveAP"};
		char * slaveValue[]={arryVl};
		int slavelen = sizeof(slave)/sizeof(char *);
		addPandValueToArray(root,slavelen,slave,slaveValue);

		cJSON_Delete(wdsArry);
		free(arryVl);
#endif

		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{	
		int i,entryNum;
		char *output = NULL;
		cJSON *pArrayItem, *JsonSlaveAP, *root = cJSON_CreateObject();
		char WDSMacBuff[128] = {0};
		char tmp[8] = {0};
		WDS_T macEntry;
		char *WiFiRadio1Enable = websGetVar(data, T(WIFI_HD2"Enable"), T(""));
		char *WiFiRadio1OpChBw = websGetVar(data, T(WIFI_HD2"OperatingChannelBandwidth"), T(""));
		char *WiFiRadio1ExChan = websGetVar(data, T(WIFI_HD2"ExtensionChannel"), T(""));
		char *WiFiRadio1GuaInt = websGetVar(data, T(WIFI_HD2"GuardInterval"), T(""));
		char *WiFiRadio1AutoCh = websGetVar(data, T(WIFI_HD2"AutoChannelEnable"), T(""));
		char *WiFiRadio1OpFreB = websGetVar(data, T(WIFI_HD2"OperatingFrequencyBand"), T(""));
		char *WiFiRadio1OpStan = websGetVar(data, T(WIFI_HD2"OperatingStandards"), T(""));
		char *WiFiRadio1PreBle = websGetVar(data, T(WIFI_HD2"PreambleType"), T(""));
		char *WiFiRadio1TraPow = websGetVar(data, T(WIFI_HD2"TransmitPower"), T(""));
		char *WiFiRadio1IEEEEN = websGetVar(data, T(WIFI_HD2"IEEE80211hEnabled"), T(""));
		char *WiFiRadio1RegDom = websGetVar(data, T(WIFI_HD2"RegulatoryDomain"), T(""));
		char *WiFiRadio1Channel= websGetVar(data, T(WIFI_HD2"Channel"), T(""));
		char *WiFiRadio1FragTh = websGetVar(data, T(WIFI_HD2"FragmentationThreshold"), T(""));
		char *WiFiRadio1RTSThd = websGetVar(data, T(WIFI_HD2"RTSThreshold"), T(""));
		char *WiFiRadio1Beacon = websGetVar(data, T(WIFI_HD2"BeaconPeriod"), T(""));
		char *WiFiRadio1DTIMPd = websGetVar(data, T(WIFI_HD2"DTIMPeriod"), T(""));

#if HUMAX_WDS
		char *WiFiRadio1WDSEnb = websGetVar(data, T(WIFI_HD3"Enable"), T(""));
		char *WiFiRadio1WDSMode= websGetVar(data, T(WIFI_HD3"Mode"), T(""));
		char *WiFiRadio1SlaveAPNum= websGetVar(data, T(WIFI_HD3"SlaveAPNumberOfEntries"), T(""));
#endif
		char *WiFiRadio1X_HUMAX_PreMode = websGetVar(data, T(WIFI_HD2"X_HUMAX_ProtectionMode"), T(""));
		
		if(strlen(WiFiRadio1Enable)>0){
			int wlan_disabled=strcmp(WiFiRadio1Enable,"TRUE")?1:0;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		}
		
		if(strlen(WiFiRadio1OpChBw)>0){
			int bandwidth = 0;
			if(!strcmp("20MHz",WiFiRadio1OpChBw))
				bandwidth = 0;
			else if(!strcmp("40MHz",WiFiRadio1OpChBw))
				bandwidth = 1;
			apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&bandwidth);
		}

		if(strlen(WiFiRadio1ExChan)>0){
			int isideband;
			if(!strcmp(WiFiRadio1ExChan,"BelowControlChannel"))		//BelowControlChannel
				isideband=1;
			else			//auto & AboveControlChannel
				isideband=0;
			apmib_set(MIB_WLAN_CONTROL_SIDEBAND, (void *)&isideband);
		}

		if(strlen(WiFiRadio1GuaInt)>0){
			int iguard = 0;		//800nsec
			if(!strcmp("800nsec",WiFiRadio1GuaInt)){
				iguard = 0;
			}
			else			//400nsec & auto
				iguard = 1;
			apmib_set(MIB_WLAN_CHANNEL, (void *)&iguard);
		}
		
		if(!strcmp("TRUE",WiFiRadio1AutoCh)){
			int auto_channel = 0;
			apmib_set(MIB_WLAN_CHANNEL, (void *)&auto_channel);
		}

		if(strlen(WiFiRadio1Channel)>0){
			int ichannel = atoi(WiFiRadio1Channel);
			apmib_set(MIB_WLAN_CHANNEL, (void *)&ichannel);
		}

		if(strlen(WiFiRadio1OpStan)>0){
			int iband = 11;
			if(!strcmp("B",WiFiRadio1OpStan))
				iband=BAND_11B;
			else if(!strcmp("G",WiFiRadio1OpStan))
				iband=BAND_11G;
			else if(!strcmp("B+G",WiFiRadio1OpStan))
				iband=BAND_11BG;
			else if(!strcmp("N",WiFiRadio1OpStan))
				iband=BAND_11N;
			else if(!strcmp("B+G+N",WiFiRadio1OpStan))
				iband=11;
			else if(!strcmp("B+G+N+AC",WiFiRadio1OpStan))//HUMAC
				iband=75;
			else
				CSTE_DEBUG("Unknow The bgn value\n");
			apmib_set(MIB_WLAN_BAND, (void *)&iband);
		}

		if(strlen(WiFiRadio1PreBle)>0){
			int ishort_preamble=!strcmp(WiFiRadio1PreBle,"short")?1:0;
			apmib_set(MIB_WLAN_PREAMBLE_TYPE, (void *)&ishort_preamble);
		}

		if(strlen(WiFiRadio1TraPow)>0){
			int itx_power=atoi(WiFiRadio1TraPow);
			if(itx_power < 1 || itx_power > 100){
				CSTE_DEBUG("The tx_power value out of range. Error\n");
			}else{
				apmib_set(MIB_WLAN_RFPOWER_SCALE, (void *)&itx_power);
			}
		}

		if(strlen(WiFiRadio1RegDom)>0){
			apmib_set(MIB_WLAN_REGULATORY_DOMAIN, (void *)WiFiRadio1RegDom);
			strncpy(tmp,WiFiRadio1RegDom,2);
			apmib_set(MIB_WLAN_COUNTRY_STRING, (void *)tmp);
		}

		if(strlen(WiFiRadio1X_HUMAX_PreMode)>0){
			int ibg_protection = !strcmp("TRUE",WiFiRadio1X_HUMAX_PreMode)?1:0;
			apmib_set(MIB_WLAN_PROTECTION_DISABLED, (void *)&ibg_protection);
		}

		if(strlen(WiFiRadio1FragTh)>0){
			int ifragment=atoi(WiFiRadio1FragTh);
			if(ifragment > 2346 || ifragment < 256){
				CSTE_DEBUG("The ifragment value out of range. Error\n");
			}else{
				apmib_set(MIB_WLAN_FRAG_THRESHOLD, (void *)&ifragment);
			}
		}

		if(strlen(WiFiRadio1RTSThd)>0){
			int irts=atoi(WiFiRadio1RTSThd);
			if(irts > 2347 || irts < 1){
				CSTE_DEBUG("The irts value out of range. Error\n");
			}else{
				apmib_set(MIB_WLAN_RTS_THRESHOLD, (void *)&irts);
			}
		}
		
		if(strlen(WiFiRadio1Beacon)>0){
			int ibeacon=atoi(WiFiRadio1Beacon);
			if(ibeacon > 999 || ibeacon < 20){
				CSTE_DEBUG("The ibeacon value out of range. Error\n");
			}else{
				apmib_set(MIB_WLAN_BEACON_INTERVAL, (void *)&ibeacon);
			}
		}

		if(strlen(WiFiRadio1DTIMPd)>0){
			int idtim=atoi(WiFiRadio1DTIMPd);
			if(idtim > 255 || idtim < 1){
				CSTE_DEBUG("The idtim value out of range. Error\n");
			}else{
				apmib_set(MIB_WLAN_DTIM_PERIOD, (void *)&idtim);
			}
		}

#if HUMAX_WDS
		if(strlen(WiFiRadio1WDSEnb)>0){
			int wds_enabled = 0;
			if(!strcmp("TRUE",WiFiRadio1WDSEnb))
				wds_enabled = 1;
			apmib_set(MIB_WLAN_WDS_ENABLED, (void *)&wds_enabled);
		}

		if(strlen(WiFiRadio1SlaveAPNum)>0){
			int WDSRuleNum=atoi(WiFiRadio1SlaveAPNum);
			apmib_set(MIB_WLAN_WDS_NUM, (void *)&WDSRuleNum);
		}
		//删除原有规则，写入ACS		下发的规则
		 apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum);
		for (i=entryNum; i>0; i--){
			*((char *)&macEntry) = (char)i;
			apmib_get(MIB_WLAN_WDS, (void *)&macEntry);
			apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
		}
		JsonSlaveAP = cJSON_Parse(websGetVar(data, T(WIFI_HD3"SlaveAP."), ""));
		for(i=0;i<cJSON_GetArraySize(JsonSlaveAP);i++)
		{
			pArrayItem = cJSON_GetArrayItem(JsonSlaveAP, i);
			char *WDSDescription = websGetVar(pArrayItem, T("Description"), T(""));
			char *WDSMACAddress = websGetVar(pArrayItem, T("MACAddress"), T(""));
		
			char *delim=":", *p=NULL;
			char buffer[32]={0},wds_list_tmp[32]={0};
			
			memset(buffer, '\0', sizeof(buffer));
			p = strtok(WDSMACAddress, delim);
			if(p==NULL){
				CSTE_DEBUG("WDS MAC strtok Error\n");
			}
			strcat(buffer, p);
			while((p=strtok(NULL, delim))) {
				strcat(buffer, p);
			}
			if(strlen(buffer)!=12||!string_to_hex(buffer, entry.macAddr, 12)){
				CSTE_DEBUG("WDS MAC Error\n");
			}
			
			apmib_set(MIB_WLAN_WDS_DEL, (void *)&entry.macAddr);
			if ( apmib_set(MIB_WLAN_WDS_ADD, (void *)&entry.macAddr) == 0) {
				CSTE_DEBUG("MIB_WLAN_WDS_ADD MAC Error\n");
			}
		}
#endif

		//生效配置
		takeEffectWlan(wlan_if, 1);
		cJSON_Delete(JsonSlaveAP);

		//update mib
		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			exit(1);
		}
		cJSON_AddNumberToObject(root,"status", 0);		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_wifi_scan(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char scanstate[32]={0},wlan_if[32]={0},bssid[64]={0},ssid[64]={0},bgn_mode[32]={0},opfband[32]={0};
		unsigned char res;
		SS_STATUS_Tp result=NULL;
		BssDscr *pBss;
		int i=0, ret=0, status, wait_time,num,enable=0;
			
		cJSON *root=cJSON_CreateArray();
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&enable);
		if(enable == 0){
			int WiFiIdx = 0;
			sprintf(wlan_if, "wlan%d", WiFiIdx);
			CSTE_DEBUG("~~~ wlan_if=[%s] ~~~\n", wlan_if);
			SetWlan_idx(wlan_if);

			memset(scanstate,0x00,sizeof(scanstate));
			//热点扫描
			wait_time = 0;
			while(1){
				switch(getWlSiteSurveyRequest(wlan_if, &status)){
					case -2:
						strcpy(scanstate,"Requested");
						websErrorResponse(mosq, tp,"Auto scan running!!please wait...");
						return -2;
					case -1:
						if(wait_time++>5){
						strcpy(scanstate,"Error");	
						websErrorResponse(mosq, tp,"Site-survey request failed!");
						wait_time = 0;
						return -1;
						}
						CSTE_DEBUG("~~~ wait_time=[%d] ~~~\n", wait_time);
						sleep(2);
						continue;
					default:
						strcpy(scanstate,"Complete");
						break; 
				}
				if(status!=0){
					if (wait_time++ > 5){
						strcpy(scanstate,"Canceled");
						websErrorResponse(mosq, tp,"scan request timeout!");
						return -1;
					}
					sleep(1);
				}else{
					strcpy(scanstate,"Completed");
					break;
				}
			}
			CSTE_DEBUG("complete scan ****\n");
			//获取扫描状态
			wait_time = 0;
			while(1){
				res=1;
				if(getWlSiteSurveyResult(wlan_if, (SS_STATUS_Tp)&res) < 0){
					strcpy(scanstate,"Error");
					//websErrorResponse(mosq, tp,"Read site-survey status failed!"); 
					return -1;
				}
				if (res == 0xff){// in progress
					if (wait_time++ > 30){
						strcpy(scanstate,"Canceled");
						//websErrorResponse(mosq, tp,"scan timeout!"); 
						return -1;
					}
					sleep(1);
				}else{
					strcpy(scanstate,"Completed");
					break;
				}
			}

			result=calloc(1, sizeof(SS_STATUS_T));
			if ( result == NULL ){
			    printf("Allocate buffer failed!\n");
			    return 0;
			}
			//获取扫描结果
			result->number=0;
			if(getWlSiteSurveyResult(wlan_if, result) < 0){
				free(result);
				result = NULL;
				websErrorResponse(mosq, tp,"get scan Result failed!"); 
				return 0;
			}

			char * scanPa[]={SCAN_HD1"DiagnosticsState", \
							 SCAN_HD1"ResultNumberOfEntries"};
			char * scanValue[]={scanstate, \
								NUM_WiFiDiagnostic};
			int scanlen = sizeof(scanPa)/sizeof(char *);
			addPandValueToArray(root,scanlen,scanPa,scanValue);
			
			CSTE_DEBUG("~~~ i=[%d] result->number=[%d]~~~\n", i, result->number);
			cJSON *scanArry = cJSON_CreateArray();
			num=atoi(NUM_WiFiDiagnostic);
			//遍历扫描结果
			for(i=0; i<num && result->number!=0xff; i++)
			{
				pBss = &result->bssdb[i];
				cJSON *rltstr = cJSON_CreateObject();
				cJSON_AddItemToArray(scanArry,rltstr);	
				//BSSID
				snprintf(bssid, 30, ("%02x:%02x:%02x:%02x:%02x:%02x"),
				pBss->bdBssId[0], pBss->bdBssId[1], pBss->bdBssId[2],
				pBss->bdBssId[3], pBss->bdBssId[4], pBss->bdBssId[5]);

				//SSID
				memcpy(ssid, pBss->bdSsIdBuf, strlen(pBss->bdSsIdBuf));
				ssid[pBss->bdSsId.Length] = '\0';
				
				//Radio
				cJSON_AddStringToObject(rltstr,"Radio",WIFI_HD2);
				char mode_tmp[32]={0};
				if(pBss->bdIbssParms.atimWin){
					strcpy(mode_tmp,"AdHoc");
				}else{
					strcpy(mode_tmp,"Infrastructure");
				}
				//channel
				char chan_tmp[32]={0};
				sprintf(chan_tmp, "%d", pBss->ChannelNumber);
				//SignalStrength
				char sig_tmp[32]={0};
				sprintf(sig_tmp, "%d", pBss->sq);
				//SecurityModeEnabled,EncryptionMode
				char scmode[32]={0}, encmode[32]={0};//, wpa2_tkip_aes[32]={0};
				if ((pBss->bdCap & cPrivacy) == 0){
					sprintf(scmode, "None");
					sprintf(encmode, "None");
				}else {
						if (pBss->bdTstamp[0] == 0){
							sprintf(scmode, "WEP");
							sprintf(encmode, "None");
						}
						else{
							int wpa_exist = 0, idx = 0;
							if (pBss->bdTstamp[0] & 0x0000ffff) {
								idx = sprintf(scmode, "WPA");
								if(((pBss->bdTstamp[0] & 0x0000f000) >> 12) == 0x2){
									idx += sprintf(scmode+idx, "-1X");
								}
								wpa_exist = 1;	
								
								if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x5)
									sprintf(encmode,"%s","aes/tkip");
								else if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x4)
									sprintf(encmode,"%s","aes");
								else if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x1)
									sprintf(encmode,"%s","tkip");
							}
							if (pBss->bdTstamp[0] & 0xffff0000) {
								if (wpa_exist){
									idx += sprintf(scmode+idx, "-");
									}	
								idx += sprintf(scmode+idx, "WPA2");
								if (((pBss->bdTstamp[0] & 0xf0000000) >> 28) == 0x2)
									idx += sprintf(scmode+idx, "-1X");

								if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x5)
									sprintf(encmode,"%s","aes/tkip");
								else if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x4)
									sprintf(encmode,"%s","aes");
								else if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x1)
									sprintf(encmode,"%s","tkip");
							}
						} 
				}
				//OperatingFrequencyBand 2.4G/5G
				memset(opfband,0x00,sizeof(opfband));
				strcpy(opfband,"2.4GHz");
				//OperatingStandards
				memset(bgn_mode, 0x00, sizeof(bgn_mode));
				if (pBss->network==BAND_11B)
					strcpy(bgn_mode, "b");
				else if (pBss->network==BAND_11G)
					strcpy(bgn_mode, "g");	
				else if (pBss->network==(BAND_11G|BAND_11B))
					strcpy(bgn_mode, "b,g");
				else if (pBss->network==(BAND_11N))
					strcpy(bgn_mode, "n");		
				else if (pBss->network==(BAND_11G|BAND_11N))
					strcpy(bgn_mode, "g,n");	
				else if (pBss->network==(BAND_11G|BAND_11B | BAND_11N))
					strcpy(bgn_mode, "b,g,n");	
				else if(pBss->network== BAND_11A)
					strcpy(bgn_mode, "a");
				else if(pBss->network== (BAND_11A | BAND_11N))
					strcpy(bgn_mode, "a,n");	
				else if(pBss->network== (BAND_5G_11AC | BAND_11N))
					strcpy(bgn_mode, "ac,n");	
				else if(pBss->network== (BAND_11A | BAND_5G_11AC))
					strcpy(bgn_mode, "a,ac");							
				else if(pBss->network== (BAND_11A |BAND_11N | BAND_5G_11AC))
					strcpy(bgn_mode, "a,n,ac");				
				else
					strcpy(bgn_mode, "b,g,n");
				//OperatingChannelBandwidth

				cJSON_AddStringToObject(rltstr, "SSID",		ssid);
				cJSON_AddStringToObject(rltstr, "BSSID",	bssid);
				cJSON_AddStringToObject(rltstr, "Mode",		mode_tmp);
				cJSON_AddStringToObject(rltstr,	"Channel",	chan_tmp);
				cJSON_AddStringToObject(rltstr, "SignalStrength",		sig_tmp);
				cJSON_AddStringToObject(rltstr, "SecurityModeEnabled",	scmode);
				cJSON_AddStringToObject(rltstr, "EncryptionMode",		encmode);
				cJSON_AddStringToObject(rltstr, "OperatingFrequencyBand",opfband);
				cJSON_AddStringToObject(rltstr,	"OperatingStandards",	bgn_mode);
			}
			free(result);
			char * rlt = cJSON_Print(scanArry);
			char * resultPa[]={"Result"};
			char * resultValue[]={rlt};
			int resultlen = sizeof(resultPa)/sizeof(char *);
			addPandValueToArray(root,resultlen,resultPa,resultValue);

			cJSON_Delete(scanArry);
			free(rlt);
			
		}
		else{//禁止无线时，上传空json数组，保证动态数据显示正常。
			char * scansta[]={SCAN_HD1"DiagnosticsState", \
							 SCAN_HD1"ResultNumberOfEntries"};
			char * Value[]={"Error", \
							NUM_WiFiDiagnostic};
			int len = sizeof(scansta)/sizeof(char *);
			addPandValueToArray(root,len,scansta,Value);
			
			cJSON *EmptyArry = cJSON_CreateArray();
			char * arry = cJSON_Print(EmptyArry);
			char * name[]={"Result"};
			char * value[]={arry};
			int leng = sizeof(name)/sizeof(char *);
			addPandValueToArray(root,leng,name,value);

			cJSON_Delete(EmptyArry);
			free(arry);
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		CSTE_DEBUG("Error! Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState? unknow the MIB in RTL\n");
	}
	return 0;
}

int cwmp_wifi_multilssid(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	char wlan_if[32]={0},wlan_vap0_if[32]={0},wlan_vap1_if[32]={0},wlan_name[32]={0},enm[128]={0};
	int wifiIdx=0;
	sprintf(wlan_if,"wlan%d",wifiIdx);
	sprintf(wlan_vap0_if, "wlan%d-va0", wifiIdx);
	sprintf(wlan_vap1_if, "wlan%d-va1", wifiIdx);
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char wfif1ien[32]={0},wifi1status[32]={0},wlan1_hw[32]={0};
		char wlan_ssid1[32]={0},Layers_val[64]={0};
		char stanm[64]={0},nanm[64]={0},bsdnm[64]={0},ssdnm[64]={0},btstnm[64]={0},btrnm[64]={0},Layers[64]={0};
		char pcstnm[64]={0},pcrcnm[64]={0},erstnm[64]={0},tanm[64]={0},frcnm[64]={0},rcnm[64]={0},mrcnm[64]={0};
		char acknm[64]={0},aggnm[64]={0},errcnm[64]={0},ucpstn[64]={0},ucprcn[64]={0},dpstn[64]={0},dprcn[64]={0};
		char mpstn[64]={0},mprcn[64]={0},bpstn[64]={0},bprcn[64]={0},upprcn[64]={0};
		int wifioff1,j=1;
		cJSON *root=cJSON_CreateArray();
		
		
		for(j=1;j<=3;j++){
			if(j==1){
				strcpy(wlan_name,wlan_if);
			}else if(j==2){
				strcpy(wlan_name,wlan_vap0_if);
			}else{
				strcpy(wlan_name,wlan_vap1_if);
			}
			sprintf(enm,	"%s%d.Enable",	SSID_HD1,j);
			sprintf(stanm,	"%s%d.Status",	SSID_HD1,j);
			sprintf(nanm,	"%s%d.Name",	SSID_HD1,j);
			sprintf(bsdnm,	"%s%d.BSSID",	SSID_HD1,j);
			sprintf(ssdnm,	"%s%d.SSID",	SSID_HD1,j);
			sprintf(Layers,	"%s%d.LowerLayers",	SSID_HD1,j);
			sprintf(btstnm,	"%s%d.Stats.%s",SSID_HD1,j,"BytesSent");
			sprintf(btrnm,	"%s%d.Stats.%s",SSID_HD1,j,"BytesReceived");
			sprintf(pcstnm,	"%s%d.Stats.%s",SSID_HD1,j,"PacketsSent");
			sprintf(pcrcnm,	"%s%d.Stats.%s",SSID_HD1,j,"PacketsReceived");
			sprintf(erstnm,	"%s%d.Stats.%s",SSID_HD1,j,"ErrorsSent");
			sprintf(errcnm,	"%s%d.Stats.%s",SSID_HD1,j,"ErrorsReceived");
			sprintf(ucpstn,	"%s%d.Stats.%s",SSID_HD1,j,"UnicastPacketsSent");
			sprintf(ucprcn,	"%s%d.Stats.%s",SSID_HD1,j,"UnicastPacketsReceived");
			sprintf(mpstn,	"%s%d.Stats.%s",SSID_HD1,j,"MulticastPacketsSent");
			sprintf(mprcn,	"%s%d.Stats.%s",SSID_HD1,j,"MulticastPacketsReceived");
			sprintf(bpstn,	"%s%d.Stats.%s",SSID_HD1,j,"BroadcastPacketsSent");
			sprintf(bprcn,	"%s%d.Stats.%s",SSID_HD1,j,"BroadcastPacketsReceived");

			SetWlan_idx(wlan_name);
			apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wifioff1);
			if(wifioff1){
				strcpy(wfif1ien,"FALSE");
				strcpy(wifi1status,"Down");
			}else{
				strcpy(wfif1ien,"TRUE");
				strcpy(wifi1status,"Up");
			}
			getIfMac(wlan_name, wlan1_hw);
			apmib_get( MIB_WLAN_SSID, (char *)wlan_ssid1);

			memset(Layers_val, 0x00, sizeof(Layers_val));
			sprintf(Layers_val,"Device.WIFI.Radio.1");
			
			char * ssid1[]={enm,stanm,nanm,bsdnm,ssdnm,Layers};
			if(wifioff1){//禁用时赋空值
				char * ssid1Value[]={"","","","","",""};
				int ssid1len = sizeof(ssid1)/sizeof(char *);
				addPandValueToArray(root,ssid1len,ssid1,ssid1Value);
			}else{
				char * ssid1Value[]={wfif1ien,wifi1status,wlan_name,wlan1_hw,wlan_ssid1,Layers_val};
				int ssid1len = sizeof(ssid1)/sizeof(char *);
				addPandValueToArray(root,ssid1len,ssid1,ssid1Value);
			}
			

			struct user_net_device_stats stats;	
			getStats(wlan_name, &stats);
			char * wanstate[]={btstnm,btrnm,pcstnm,pcrcnm,erstnm,errcnm,ucpstn,ucprcn,mpstn,mprcn,\
				bpstn,bprcn};
			if(wifioff1){//禁用时赋空值
				char* intstat[]={"","","","","","","","","","","",""};
		    	int statlen = sizeof(wanstate)/sizeof(char *);
				addPandValueToArray(root,statlen,wanstate,intstat);
			}
			else{
				int intstat[]={stats.tx_bytes,stats.rx_bytes,stats.tx_packets,stats.rx_packets,stats.tx_errors,stats.rx_errors,\
					stats.tx_unicast,stats.rx_unicast,stats.tx_multicast,stats.rx_multicast,stats.tx_broadcast,\
					stats.rx_broadcast};
		    	int statlen = sizeof(wanstate)/sizeof(char *);
				addIntValueToArray(root,statlen,wanstate,intstat);
			}
			
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		char *output = NULL,ifname[32]={0}; 
		cJSON *root=cJSON_CreateObject();

		char *wlan_disabled1 = websGetVar(data, T("Device.WiFi.SSID.1.Enable"), T(""));
		char *wlan_disabled2 = websGetVar(data, T("Device.WiFi.SSID.2.Enable"), T(""));
		char *wlan_disabled3 = websGetVar(data, T("Device.WiFi.SSID.3.Enable"), T(""));
		char *wlan_ssid1 = websGetVar(data, T("Device.WiFi.SSID.1.SSID"), T(""));
		char *wlan_ssid2 = websGetVar(data, T("Device.WiFi.SSID.2.SSID"), T(""));
		char *wlan_ssid3 = websGetVar(data, T("Device.WiFi.SSID.3.SSID"), T(""));
		
		if(strlen(wlan_disabled1)>0){
			SetWlan_idx(wlan_if);
			int iwlan_disabled1=!strcmp(wlan_disabled1,"TRUE")?0:1;
			apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&iwlan_disabled1);
		}
		
		if(strlen(wlan_ssid1)>0){
			apmib_set( MIB_WLAN_SSID, (void *)wlan_ssid1);
		}
		
		if(strlen(wlan_disabled2)>0){
			SetWlan_idx(wlan_vap0_if);
			int iwlan_disabled2=!strcmp(wlan_disabled2,"TRUE")?0:1;
			apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&iwlan_disabled2);
		}

		if(strlen(wlan_ssid2)>0){
			apmib_set( MIB_WLAN_SSID, (void *)wlan_ssid2);
		}
		
		if(strlen(wlan_disabled3)>0){
			SetWlan_idx(wlan_vap1_if);
			int iwlan_disabled3=!strcmp(wlan_disabled3,"TRUE")?0:1;
			apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&iwlan_disabled3);
		}

		if(strlen(wlan_ssid3)>0){
			apmib_set( MIB_WLAN_SSID, (void *)wlan_ssid3);
		}
		
		sprintf(ifname,"%s","wlan0-va0");
		takeEffectWlan(ifname, 0);

		sprintf(ifname,"%s","wlan0-va1");
		takeEffectWlan(ifname, 0);
		
		sprintf(ifname,"%s","wlan0");
		takeEffectWlan(ifname, 1);
		
		apmib_update_web(CURRENT_SETTING);
		cJSON_AddNumberToObject(root,"status", 0);		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_wifi_accsspoint(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	int wifiIdx=0;
	char wlan_name[32]={0},wlan_if[32]={0},wlan_vap0_if[32]={0},wlan_vap1_if[32]={0};
	sprintf(wlan_if,"wlan%d",wifiIdx);
	sprintf(wlan_vap0_if, "wlan%d-va0", wifiIdx);
	sprintf(wlan_vap1_if, "wlan%d-va1", wifiIdx);
	if(strcmp(action,"get")==0){
		char *output=NULL,*pbuff,*wpamode;
		WLAN_STA_INFO_Tp pInfo;
		int vChar,func_off;
		char referssid[32]={0};
		char wpst[32]={0},wsc_pin[12]={0};
		char acen[8]={0}, macenabled[8]={0}, buff[32]={0}, macList[512]={0}, macallowmode[8]={0},outmac[32]={0},bgn_mode[16]={0};
		char dbm[32]={0},keytype[64]={0},wepkey[64]={0},keypass[64]={0},wpsen[64]={0},wpsmod[64]={0};
		char enm[64]={0},refnm[64]={0},advnm[64]={0},wmmnm[64]={0},assnbnm[64]={0},maxanm[64]={0},isonm[64]={0},maxstanum[32]={0};
		char maconm[64]={0},allnm[64]={0},mamnm[64]={0},aunm[64]={0},wknm[64]={0},psspnm[64]={0},enpnm[64]={0};
		char ktpnm[64]={0},wpsenm[64]={0},wpscnm[64]={0},wpstnm[64]={0},wpslcn[64]={0};
		int assnb=0, macen=0, entryNum=0, rssi_out=100, weptype=0, configured=0, i=0, j=1;
		unsigned char buff_key[65];
		int rtl_wep=0, rtl_keytype=0, rtl_defkeyid=0,rtl_keyid=0,maxsta=0,num=0;
		MACFILTER_T macEntry;
		cJSON *root=cJSON_CreateArray();

		char modes_supp[64] = {0};
		char *modes_supp_val = "WPA-PSK, WPA2-PSK, WPA/WPA2-PSK, WEP-Open System, WEP-Shared Key";
		
		//wlan0
		for(j=1;j<=3;j++){
			if(j==1){
				strcpy(wlan_name,wlan_if);
			}else if(j==2){
				strcpy(wlan_name,wlan_vap0_if);
			}else{
				strcpy(wlan_name,wlan_vap1_if);
			}
			
			sprintf(enm,	"%s%d.Enable",						ACESS_HD1,j);
			sprintf(refnm,	"%s%d.SSIDReference",				ACESS_HD1,j);
			sprintf(advnm,	"%s%d.SSIDAdvertisementEnabled",	ACESS_HD1,j);
			sprintf(wmmnm,	"%s%d.WMMEnable",					ACESS_HD1,j);
			sprintf(assnbnm,"%s%d.AssociatedDeviceNumberOfEntries", 	ACESS_HD1,j);
			sprintf(maxanm,	"%s%d.MaxAssociatedDevices",		ACESS_HD1,j);
			sprintf(isonm,	"%s%d.IsolationEnable",				ACESS_HD1,j);
			sprintf(maconm,	"%s%d.MACAddressControlEnabled",	ACESS_HD1,j);
			sprintf(allnm,	"%s%d.AllowedMACAddress",			ACESS_HD1,j);
			sprintf(mamnm,	"%s%d.X_HUMAX_MACAddressControlAllowMode",  ACESS_HD1,j);
			sprintf(modes_supp,  "%s%d.Security.ModesSupported",		ACESS_HD1,j);
			sprintf(aunm,	"%s%d.Security.ModeEnabled",		ACESS_HD1,j);
			sprintf(wknm,	"%s%d.Security.WEPKey",				ACESS_HD1,j);
			sprintf(psspnm,	"%s%d.Security.KeyPassphrase",		ACESS_HD1,j);
			sprintf(enpnm,	"%s%d.Security.X_HUMAX_EncryptionType",		ACESS_HD1,j);
			sprintf(ktpnm,	"%s%d.Security.X_HUMAX_KeyType",	ACESS_HD1,j);
			sprintf(wpsenm,	"%s%d.WPS.Enable",					ACESS_HD1,j);
			sprintf(wpscnm,	"%s%d.WPS.ConfigMethodsEnabled", 	ACESS_HD1,j);
			sprintf(wpstnm,	"%s%d.WPS.X_HUMAX_Status",			ACESS_HD1,j);
			sprintf(wpslcn,	"%s%d.WPS.X_HUMAX_LocalPinCode",	ACESS_HD1,j);
			sprintf(referssid,"%s%d.",SSID_HD1,j);
			
			getMaxstanum(maxstanum);
			maxsta=atoi(maxstanum);
				
			SetWlan_idx(wlan_name);
			apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&vChar);
			if(vChar==0)
				strcpy(acen,"TRUE");
			else
				strcpy(acen,"FALSE");

			apmib_get(MIB_WLAN_MACAC_ENABLED, (void *)&macen);
			if(macen==0){
				strcpy(macenabled,"FALSE");
				strcpy(macallowmode,"FALSE");
			}else if(macen==1){
				strcpy(macenabled,"TRUE");
				strcpy(macallowmode,"TRUE");
			}else{
				strcpy(macenabled,"TRUE");
				strcpy(macallowmode,"FALSE");
			}

			if(i==1){
				num=atoi(NUM_WiFi_AccessPoint1);
			}else if(i==2){
				num=atoi(NUM_WiFi_AccessPoint2);
			}else{
				num=atoi(NUM_WiFi_AccessPoint3);
			}
			
			memset(macList, '\0', sizeof(macList));
			apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum);
		    apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
		    for (i=1; i<=entryNum; i++){
		        *((char *)&macEntry) = (char)i;
		        apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry);
		        snprintf(buff, 32, ("%02x:%02x:%02x:%02x:%02x:%02x"),
					macEntry.macAddr[0], macEntry.macAddr[1], macEntry.macAddr[2],
					macEntry.macAddr[3], macEntry.macAddr[4], macEntry.macAddr[5]);
			    if(i==1){
		            sprintf(macList, "%s", buff);
			    }else{
		            sprintf(macList, "%s,%s", macList, buff);
			    }
		    }	
			//Security
			wpamode = getModeEnabled(wlan_name);
			if(!strcmp(wpamode,"WEP-64")||!strcmp(wpamode,"WEP-128")){
				apmib_get(MIB_WLAN_WEP_KEY_TYPE,  (void *)&weptype);
				if(weptype==1){
					strcpy(keytype,"Hexadecimal");
				}else{
					strcpy(keytype,"CharaterString");
				}
			}else{
				strcpy(keytype,"");
			}

			{
				if(j == 1)
					SetWlan_idx(wlan_if);
				else if(j == 2)
					SetWlan_idx(wlan_vap0_if);
				else if(j == 3)
					SetWlan_idx(wlan_vap1_if);
				
				apmib_get( MIB_WLAN_WPA_PSK, (void *)keypass);
				apmib_get( MIB_WLAN_WEP, (void *)&rtl_wep);
				apmib_get( MIB_WLAN_WEP_KEY_TYPE,  (void *)&rtl_keytype);
				apmib_get( MIB_WLAN_WEP_DEFAULT_KEY,  (void *)&rtl_defkeyid);
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
						convert_bin_to_str(buff_key, 5, wepkey);
					}else{
						snprintf(wepkey, 6, "%s", buff_key);
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
						convert_bin_to_str(buff_key, 13, wepkey);
					}else{
						snprintf(wepkey, 14, "%s", buff_key);
					}
				}
			}

			//当为WEP加密时，ACS不能显示WPA密码，同理，为WPA加密时ACS不能显示WEP密码
			if(0 == strcmp(getEncrypType(wlan_name),"WEP"))
			{
				 memset(keypass, 0,sizeof(keypass));
			}
			else
			{
				memset(wepkey, 0,sizeof(wepkey));
			}
				
			
			//wps
			apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&configured);
			if(configured==0){
				strcpy(wpsen,"TRUE");
			}else{
				strcpy(wpsen,"FALSE");
			}
			strcpy(wpsmod,"PBC");
			getWpsTates(wpst);
			apmib_get(MIB_HW_WSC_PIN,(void *)wsc_pin);
			char * acName[]={enm,refnm,maconm,allnm,mamnm,aunm,enpnm,ktpnm,wknm,psspnm,wpsenm,wpscnm,wpstnm,wpslcn, modes_supp};
			char * acValue[]={acen,referssid,macenabled,macList,macallowmode,getAuthMode(wlan_name),getEncrypType(wlan_name),\
				keytype,wepkey,keypass,wpsen,wpsmod,wpst,wsc_pin, modes_supp_val};
			int aclen = sizeof(acName)/sizeof(char *);
			addPandValueToArray(root,aclen,acName,acValue);

			char * IntGetName[]={advnm,wmmnm,isonm};
			int IntGetId[]={MIB_WLAN_HIDDEN_SSID,MIB_WLAN_WMM_ENABLED,MIB_WLAN_BLOCK_RELAY};
	   		int intlen = sizeof(IntGetName)/sizeof(char *);
	    	addBooleanToArray(root,intlen,IntGetName,IntGetId);
			
			assnb=getStaAssociatedNum(wlan_name);
			char *acIntName[]={assnbnm,maxanm};
			int acIntValue[]={num,maxsta};
			int jklen = sizeof(acIntName)/sizeof(char *);
			addIntValueToArray(root,jklen,acIntName,acIntValue);

			// AssociatedDevice信息
			if(vChar==0){
				cJSON *arry	= cJSON_CreateArray();	
				pbuff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
			    if ( getWlStaInfo(wlan_name,  (WLAN_STA_INFO_Tp)pbuff ) > -1 ){
				    for (i=1; i<=MAX_STA_NUM; i++)
				    {
				        pInfo = (WLAN_STA_INFO_Tp)&pbuff[i*sizeof(WLAN_STA_INFO_T)];
				        if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC))
				        {
				        	cJSON *item = cJSON_CreateObject();
							cJSON_AddItemToArray(arry,item);
				            memset(outmac, 0, sizeof(outmac));
				            sprintf(outmac,"%02X:%02X:%02X:%02X:%02X:%02X", pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5]);
				            //OperatingStandard
				            memset(bgn_mode, 0, sizeof(bgn_mode));
				            if(pInfo->network& BAND_5G_11AC)
				    			sprintf(bgn_mode, "%s", "ac");
				    		else if(pInfo->network & BAND_11N)
				    			sprintf(bgn_mode, "%s", "n");
				    		else if (pInfo->network & BAND_11G)
				    			sprintf(bgn_mode,"%s",  "g");	
				    		else if (pInfo->network & BAND_11B)
				    			sprintf(bgn_mode, "%s", "b");
				    		else if (pInfo->network& BAND_11A)
				    			sprintf(bgn_mode, "%s", "a");	            
							//dBm
							memset(dbm,0x00,sizeof(dbm));
							rssi_out = pInfo->rssi;
							sprintf(dbm, "%d", rssi_out);

							cJSON_AddStringToObject(item, "MACAddress",outmac);
							cJSON_AddStringToObject(item,"OperatingStandard",bgn_mode);
							cJSON_AddStringToObject(item, "SignalStrength", dbm);				
				        }
				    }
			    }
		    	free(pbuff);
				char * asstfm = cJSON_Print(arry);
				char * cltName[]={"AssociatedDevice"};
				char * cltValue[]={asstfm};
				int cltlen = sizeof(cltName)/sizeof(char *);
				addPandValueToArray(root,cltlen,cltName,cltValue);

				cJSON_Delete(arry);
				free(asstfm);
			}
			else{//vChar=0表示该无线未开启，则必须上传空的json数组，否则动态显示不正确
				cJSON *empty= cJSON_CreateArray();
				char * str = cJSON_Print(empty);
				char * Name[]={"AssociatedDevice"};
				char * Value[]={str};
				int len = sizeof(Name)/sizeof(char *);
				addPandValueToArray(root,len,Name,Value);

				cJSON_Delete(empty);
				free(str);
			}
		}
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}else{
		int i;
		char EnableBuff[64]={0}, MACConEnableBuff[64]={0},SSIDAdEnableBuff[64]={0},WMMEnableBuff[64]={0},
			 IsoEnable[64]={0},WPS_EnabledBuff[64]={0},Sec_ModeEnabledBuff[64]={0},Sec_HUMAX_EncTypeBuff[64]={0},
			 Sec_HUMAX_KeyTypeBuff[64]={0},MaxAssDevBuff[64]={0},SSIDRBuff[64]={0},HUMAX_MACConBuff[64]={0},
			 Sec_WEPKeyBuff[64]={0},Sec_KeyPaPhBuff[64]={0},WPS_ConfigBuff[64]={0},AllowedMACBuff[64]={0},ifname[32]={0};

		for(i=1;i<4;i++)
		{
			if(i==1){
				strcpy(wlan_name,wlan_if);
			}else if(i==2){
				strcpy(wlan_name,wlan_vap0_if);
			}else{
				strcpy(wlan_name,wlan_vap1_if);
			}
			SetWlan_idx(wlan_name);			
			sprintf(EnableBuff,		  	"%s%d.Enable",					ACESS_HD1,i);
			sprintf(SSIDRBuff,		  	"%s%d.SSIDReference", 			ACESS_HD1,i);
			sprintf(MACConEnableBuff, 	"%s%d.MACAddressControlEnabled",ACESS_HD1,i);
			sprintf(AllowedMACBuff,   	"%s%d.AllowedMACAddress", 		ACESS_HD1,i);
			sprintf(HUMAX_MACConBuff,	"%s%d.X_HUMAX_MACAddressControlAllowMode",	ACESS_HD1,i);
			sprintf(SSIDAdEnableBuff,	"%s%d.SSIDAdvertisementEnabled",	ACESS_HD1,i);
			sprintf(WMMEnableBuff,		"%s%d.WMMEnable",				ACESS_HD1,i);
			sprintf(IsoEnable,			"%s%d.IsolationEnable",			ACESS_HD1,i);
			sprintf(MaxAssDevBuff,		"%s%d.MaxAssociatedDevices", 	ACESS_HD1, i);
			sprintf(Sec_ModeEnabledBuff,	"%s%d.Security.ModeEnabled",ACESS_HD1,i);	//加密方式
			sprintf(Sec_HUMAX_EncTypeBuff,	"%s%d.Security.X_HUMAX_EncryptionType", ACESS_HD1,i);//加密类型 AES/TKIP 用于WPA加密方式
			sprintf(Sec_HUMAX_KeyTypeBuff,	"%s%d.Security.X_HUMAX_KeyType",		ACESS_HD1,i);//密码类型 CharaterString/Hexadecimal 用于WEP加密方式
			sprintf(Sec_WEPKeyBuff,		"%s%d.Security.WEPKey", 		ACESS_HD1,i);	//WEP加密方式密码
			sprintf(Sec_KeyPaPhBuff,	"%s%d.Security.KeyPassphrase", 	ACESS_HD1,i);	//WPA加密方式密码
			sprintf(WPS_EnabledBuff,	"%s%d.WPS.Enable",				ACESS_HD1,i);
			sprintf(WPS_ConfigBuff,		"%s%d.WPS.ConfigMethodsEnabled",ACESS_HD1,i);
			//sprintf(WPS_HUMAX_RemoteBuff,"%s%d.WPS.X_HUMAX_RemotePinCode",ACESS_HD1,i);	//Writable?

			char *EnableValue = websGetVar(data, T(EnableBuff), T(""));
			char *SSIDRValue = websGetVar(data, T(SSIDRBuff), T(""));
			char *MACConEnableValue = websGetVar(data, T(MACConEnableBuff), T(""));
			char *AllowedMACValue = websGetVar(data, T(AllowedMACBuff), T(""));
			char *HUMAX_MACConValue = websGetVar(data, T(HUMAX_MACConBuff), T(""));
			char *SSIDAdEnableValue = websGetVar(data, T(SSIDAdEnableBuff), T(""));
			char *WMMEnableValue = websGetVar(data, T(WMMEnableBuff), T(""));
			char *IsoValue = websGetVar(data, T(IsoEnable), T(""));
			char *MaxAssDevValue = websGetVar(data, T(MaxAssDevBuff), T(""));	
			char *Sec_ModeEnabledValue = websGetVar(data, T(Sec_ModeEnabledBuff), T(""));
			char *Sec_HUMAX_EncTypeValue = websGetVar(data, T(Sec_HUMAX_EncTypeBuff), T(""));
			char *Sec_HUMAX_KeyTypeValue = websGetVar(data, T(Sec_HUMAX_KeyTypeBuff), T(""));
			char *Sec_WEPKeyValue = websGetVar(data, T(Sec_WEPKeyBuff), T(""));
			char *Sec_KeyPaPhValue = websGetVar(data, T(Sec_KeyPaPhBuff), T(""));
			char *WPS_EnabledValue = websGetVar(data, T(WPS_EnabledBuff), T(""));
			char *WPS_ConfigValue = websGetVar(data, T(WPS_ConfigBuff), T(""));
			//char *WPS_HUMAX_RemoteValue = websGetVar(data, T(WPS_HUMAX_RemoteBuff), T(""));
			
			if(strlen(EnableValue)>0)
			{
				int rtl_enabled,rtl_rpt_enabled;
				if(getOperationMode()==3) {
					if(!strcmp(EnableValue, "FALSE")){ //disable wlan
					    rtl_enabled=0;
					    rtl_rpt_enabled=1;
			        }
			        else{ 							   //enable wlan
			            rtl_enabled=1;
					    rtl_rpt_enabled=0;
			        }
					apmib_set(MIB_REPEATER_ENABLED1, (char *)&rtl_rpt_enabled);
		        }
				else{
		            if (!strcmp(EnableValue, "FALSE"))
		                rtl_enabled=1;
		            else
		                rtl_enabled=0;  
				}
				apmib_set(MIB_WLAN_WLAN_DISABLED, (char *)&rtl_enabled);
			}

			if(strlen(MACConEnableValue)>0)
			{
				int iMACConEnable=!strcmp(MACConEnableValue,"TRUE")?1:0;
				apmib_set(MIB_WLAN_MACAC_ENABLED, (void *)&iMACConEnable);
			}

			if(strlen(HUMAX_MACConValue)>0)
			{//MAC认证模式，FALSE为黑名单，TRUE为白名单
				int iMacEnabled;
				apmib_get(MIB_WLAN_MACAC_ENABLED, (void *)&iMacEnabled);
				if(iMacEnabled==1)
				{
					int iMAConEable = !strcmp(HUMAX_MACConValue,"TRUE")?1:2;
					apmib_set(MIB_WLAN_MACAC_ENABLED, (void *)&iMAConEable);
				}
			}

			if(strlen(AllowedMACValue)>0)
			{//MAC认证下的MAC地址以逗号分隔						
				MACFILTER_T macEntry;
				char *delim=":", *p=NULL;
				char buffer[32]={0};
				if(AllowedMACValue!=NULL){
		            p = strtok(AllowedMACValue, delim);
		            if(p==NULL) return 0;
		            	strcat(buffer, p);
		            while((p=strtok(NULL, delim))) {
		        		strcat(buffer, p);
		        	}
		        	string_to_hex(buffer, macEntry.macAddr, 12);            
		        }	
		        macEntry.comment[0] = '\0';
		        apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
		        apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry);
			}

			if(strlen(SSIDAdEnableValue)>0)
			{//HideSSID 启用 0 禁用 1
				int hiddenssid=!strcmp(SSIDAdEnableValue,"TRUE")?0:1;
				apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&hiddenssid);
			}
			
			if(strlen(WMMEnableValue)>0)
			{//Wi-Fi多媒体(WMM)
				int iwmm_capable=!strcmp(WMMEnableValue,"TRUE")?1:0;
				apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&iwmm_capable);
			}

			if(strlen(IsoValue)>0 && i==1)		
			{//AP 隔离,针对主SSID有效
				int inoforwarding=!strcmp(IsoValue,"TRUE")?1:0;
				apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&inoforwarding);
			}

			if(i==1)
			{//最大连接数,只有主SSID可以设置该值。最大设置为64个。当设置为0时表示无限个。
				char cmd_buf[64]={0};
				int Maxstanum= atoi(MaxAssDevValue);
				if(Maxstanum > 64) Maxstanum=64;
				sprintf(cmd_buf,"iwpriv wlan0 set_mib stanum=%d",Maxstanum);
				CsteSystem(cmd_buf,CSTE_PRINT_CMD);
			}
			
			if(strlen(Sec_ModeEnabledValue)>0 && !strcmp(EnableValue, "TRUE"))
			{//加密方式, 加密类型, 密码类型, 密码
			
				char authmode[32]={0},encryptype[32]={0};
				char *security_mode=Sec_ModeEnabledValue;	//加密方式
				strcpy(authmode,Sec_ModeEnabledValue);	//加密方式
				int wep=WEP_DISABLED,auth_wpa=WPA_AUTH_AUTO;
        		ENCRYPT_T encrypt=ENCRYPT_DISABLED;	
				
				if((!strncmp(security_mode, "OPEN", 5)||!strncmp(security_mode, "SHARED", 7))&& !strncmp(Sec_HUMAX_EncTypeValue, "WEP", 4))//WEP
				{
					int auth_type	= AUTH_BOTH;
					int key_type	= !strcmp(Sec_HUMAX_KeyTypeValue,"CharaterString")?0:1;//密码类型 //RTL 0:ASCII 1:HEX MTK 0:Hex 1:ASCII
					int key_id		= 0;
					char *wepkey=Sec_WEPKeyValue;				//WEP类型密码
					int wepkey_len	= strlen(wepkey);
					char key_hex[32]={0};
					
					if(key_type==1){//Hex
						if(wepkey_len==10){
							wep=WEP64;
							wepkey_len=WEP64_KEY_LEN*2;
						}else if(wepkey_len==26){
							wep=WEP128;
							wepkey_len=WEP128_KEY_LEN*2;
						}else{
							CSTE_DEBUG("Error!The wepkey_len->%d\n",wepkey_len);
						}	
						string_to_hex(wepkey, key_hex, wepkey_len);
					}else{//ASCII
						if(wepkey_len==5){
							wep=WEP64;
						}else if(wepkey_len==13){
							wep=WEP128;
						}else{
							CSTE_DEBUG("Error!The wepkey_len->%d\n",wepkey_len);
						}
						strcpy(key_hex, wepkey);
					}
					encrypt=ENCRYPT_WEP;
					auth_wpa=WPA_AUTH_AUTO;
					if(!strncmp(authmode, "OPEN", 5))
						auth_type=AUTH_OPEN;
					else if(!strncmp(authmode, "SHARED", 7))
						auth_type=AUTH_SHARED;
		
#ifdef WIFI_SIMPLE_CONFIG
					wps_config_info.caller_id = CALLED_FROM_ADVANCEHANDLER;
					apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&wps_config_info.shared_type);
					wps_config_info_tmp.shared_type=auth_type;
					update_wps_configured(0);
					wps_config_info.caller_id = CALLED_FROM_WEPHANDLER;
					apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
					apmib_get(MIB_WLAN_WEP, (void *)&wps_config_info.wep_enc);
					apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wps_config_info.KeyId);
					apmib_get(MIB_WLAN_WEP64_KEY1, (void *)wps_config_info.wep64Key1);
					apmib_get(MIB_WLAN_WEP64_KEY2, (void *)wps_config_info.wep64Key2);
					apmib_get(MIB_WLAN_WEP64_KEY3, (void *)wps_config_info.wep64Key3);
					apmib_get(MIB_WLAN_WEP64_KEY4, (void *)wps_config_info.wep64Key4);
					apmib_get(MIB_WLAN_WEP128_KEY1, (void *)wps_config_info.wep128Key1);
					apmib_get(MIB_WLAN_WEP128_KEY2, (void *)wps_config_info.wep128Key2);
					apmib_get(MIB_WLAN_WEP128_KEY3, (void *)wps_config_info.wep128Key3);
					apmib_get(MIB_WLAN_WEP128_KEY4, (void *)wps_config_info.wep128Key4);
					wps_config_info_tmp.auth = encrypt;
					wps_config_info_tmp.wep_enc = wep;
					wps_config_info_tmp.KeyId = key_id;
					wps_config_info_tmp.wpa_enc = auth_wpa;
					if(wep==WEP64){
						strncpy(wps_config_info_tmp.wep64Key1, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep64Key2, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep64Key3, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep64Key4, key_hex, strlen(key_hex));
					}else{
						strncpy(wps_config_info_tmp.wep128Key1, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep128Key2, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep128Key3, key_hex, strlen(key_hex));
						strncpy(wps_config_info_tmp.wep128Key4, key_hex, strlen(key_hex));
					}
					update_wps_configured(0);
#endif
					apmib_set( MIB_WLAN_WEP, (void *)&wep);
					apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt); 	
					apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
					apmib_set( MIB_WLAN_AUTH_TYPE, (void *)&auth_type);
					apmib_set( MIB_WLAN_WEP_KEY_TYPE, (void *)&key_type);
					apmib_get( MIB_WLAN_WEP_DEFAULT_KEY,  (void *)&key_id);
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
				else if(!strncmp(security_mode, "WPAPSK", 7)||!strncmp(security_mode, "WPA2PSK", 8)||!strncmp(security_mode, "WPAPSKWPA2PSK", 14))
				{
					strcpy(encryptype,Sec_HUMAX_EncTypeValue);	//加密类型 
					int ciphersuite1 = WPA_CIPHER_AES, ciphersuite2 = WPA_CIPHER_AES;
					int pskformat	 = 0;//RTL 0:ASCII 1:HEX MTK 0:Hex 1:ASCII  X_HUMAX_KeyType只适用于WEP加密方式
					char *wpakey=Sec_KeyPaPhValue;	//WPA类型密码
					int wpakey_len	 = strlen(wpakey);
					char key_hex[65] = {0};
					auth_wpa=WPA_AUTH_PSK;
					if(!strncmp(security_mode, "WPAPSK", 7)){
						encrypt = ENCRYPT_WPA;
						if(!strncmp(encryptype, "TKIP", 5))
							ciphersuite1 = WPA_CIPHER_TKIP;
						else
							ciphersuite1 = WPA_CIPHER_AES;
					}else if(!strncmp(security_mode, "WPA2PSK", 8)){
						encrypt=ENCRYPT_WPA2;
						if(!strncmp(encryptype, "TKIP", 5))
							ciphersuite2 = WPA_CIPHER_TKIP;
						else if(!strncmp(encryptype, "AES", 4))
							ciphersuite2 = WPA_CIPHER_AES;
						else
							ciphersuite2 = WPA_CIPHER_MIXED;
					}else if(!strncmp(security_mode, "WPAPSKWPA2PSK", 14)){
						encrypt=ENCRYPT_WPA2_MIXED;
						if(!strncmp(encryptype, "TKIP", 5)){
							ciphersuite1 = WPA_CIPHER_TKIP;
							ciphersuite2 = WPA_CIPHER_TKIP;
						}else if(!strncmp(encryptype, "AES", 4)){
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
#ifdef WIFI_SIMPLE_CONFIG
					wps_config_info.caller_id = CALLED_FROM_WPAHANDLER;
					apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
					apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
					apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
					apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
					wps_config_info_tmp.auth=encrypt;
					wps_config_info_tmp.wpa_enc=ciphersuite1;
					wps_config_info_tmp.wpa2_enc=ciphersuite2;
					wps_config_info_tmp.shared_type=auth_wpa;
					strncpy(wps_config_info_tmp.wpaPSK, wpakey, strlen(wpakey));
					update_wps_configured(0);
#endif
					apmib_set( MIB_WLAN_WEP, (void *)&wep);
					apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
					apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
					apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
					apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
					apmib_set( MIB_WLAN_WPA_PSK, (void *)wpakey);		
					apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
				}
				else	//NONE
				{
					encrypt=ENCRYPT_DISABLED;
					auth_wpa=WPA_AUTH_AUTO;
#ifdef WIFI_SIMPLE_CONFIG
					wps_config_info.caller_id = 0;
					wps_config_info_tmp.auth=encrypt;
					wps_config_info_tmp.shared_type=auth_wpa;
					update_wps_configured(0);
#endif
					apmib_set( MIB_WLAN_WEP, (void *)&wep);
					apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt); 	
					apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
				}	
			}

			if(strlen(WPS_EnabledValue)>0)
			{//WPS enabled
				int wsc_enable = !strcmp(WPS_EnabledValue,"TRUE")?1:0;
				apmib_set(MIB_WLAN_WSC_DISABLE, (char *)&wsc_enable);
			}

			{//WPS配置模式

			}
			
			{//X_HUMAX_RemotePinCode Writable?

			}
			
		}
		
		sprintf(ifname,"%s","wlan0-va0");
		takeEffectWlan(ifname, 0);

		sprintf(ifname,"%s","wlan0-va1");
		takeEffectWlan(ifname, 0);
		
		sprintf(ifname,"%s","wlan0");
		takeEffectWlan(ifname, 1);

		//update mib
		char *output = NULL;
		cJSON *root = cJSON_CreateObject();
		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			exit(1);
		}
		cJSON_AddNumberToObject(root,"status", 0);		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_IP(struct mosquitto *mosq, cJSON* data, char *tp)
{

	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL, ipv6_enable[8]={0};
		char lanst[16]={0},lanface[16]={0},br0addr[64]={0},br0mask[64]={0},addrtype[16]={0},opmode[32]={0},wanmode[32]={0};
		char wanip[16]={0},wanen[16]={0},wanst[16]={0},stas[32]={0},waname[16]={0},wanmtu[16]={0},LowerLayers[64]={0};
		int mtu;
		cJSON *root = cJSON_CreateArray();
		
		//lan  ==============================================================
		if(!strcmp(IP_INTER_EN,"TRUE")){
			strcpy(lanst,"Up");
		}else{
			strcpy(lanst,"Down");
		}
		strcpy(lanface,"br0");
		if(!getInAddr("br0", IP_ADDR_T, br0addr))
			sprintf(br0addr, "0.0.0.0");
		if(!getInAddr("br0", NET_MASK_T, br0mask ))
			sprintf(br0mask, "0.0.0.0");
		
		getWanIp(wanip);
		strcpy(addrtype, "DHCP");
		strcpy(LowerLayers,"Device.Ethernet.Interface.1");
		
		char * lanName[]={IP_HD1"IPv6Enable", \
						  IP_HD2"Enable", \
						  IP_HD2"IPv6Enable", \
						  IP_HD2"Status", \
						  IP_HD2"Name", \
						  IP_HD2"LowerLayers", \
						  IP_HD2"IPv4Address.1.Enable", \
						  IP_HD2"IPv4Address.1.IPAddress", \
						  IP_HD2"IPv4Address.1.SubnetMask", \
						  IP_HD2"IPv4Address.1.AddressingType"};

		apmib_get_bool(MIB_IPV6_WAN_ENABLE,ipv6_enable);
		
		char * lanValue[]={ipv6_enable,
						   IP_INTER_EN,
						   "FALSE",	//目前LAN 口尚未设置IPv6 地址!!
						   lanst,
						   lanface,
						   LowerLayers,
						   IPV4_ADDR_EN,
						   br0addr,
						   br0mask,
						   addrtype};
		
		int lanlen = sizeof(lanName)/sizeof(char *);
		addPandValueToArray(root,lanlen,lanName,lanValue);

		int lan_mtu;
		apmib_get(MIB_DHCP_MTU_SIZE,(void *)&lan_mtu);
		char *lanIntName[] ={IP_HD2"MaxMTUSize", \
							 IP_HD2"IPv4AddressNumberOfEntries"};
		int lanIntValue[] = {lan_mtu, \
							 IPADDR_V4_NUMBER};
		lanlen = sizeof(lanIntName)/sizeof(char *);
		addIntValueToArray(root, lanlen, lanIntName, lanIntValue);
	
		//wan ===============================================================
		int wanlen, wantype,ipv6_addr_num=0;
		char ipv6_prefix[128+8] = {0}, ipv6_addr[128+8] = {0};
		char *pchar = "", *ipv6_addr_enable = "",  *ipv6_origin = "";
		char *prefix_origin = "", *ipv6_life = "", *prefix_index = "";
			
		if(getOperationMode()!=1){
			get_wan_connect_status(stas);
			getWanConnectMode(wanmode);
			if(getOperationMode()==3){
				strcpy(wanen,"TRUE");
				strcpy(waname,"wlan0-vxd");
				if(!strcmp(stas,"connected")){
					strcpy(wanst,"Up");
				}else{
					strcpy(wanst,"Down");
				}
			}else{
				strcpy(wanen,"TRUE");
				strcpy(waname,"eth1");
				if(!strcmp(stas,"connected")){
					strcpy(wanst,"Up");
				}else{
					strcpy(wanst,"Down");
				}
			}
			if(!strcmp(wanmode,"DHCP")){
				apmib_get(MIB_DHCP_MTU_SIZE,(void *)&mtu);
			}else if(!strcmp(wanmode,"STATIC")){
				apmib_get(MIB_FIXED_IP_MTU_SIZE,(void *)&mtu);
			}else if(!strcmp(wanmode,"PPPOE")){
				apmib_get(MIB_PPP_MTU_SIZE,(void *)&mtu);
			}
			sprintf(wanmtu,"%d",mtu);
			memset(LowerLayers,0x00,sizeof(LowerLayers));
			strcpy(LowerLayers,"Device.Ethernet.Interface.11");
			
			getCmdStr("ifconfig | awk 'BEGIN{FS=\"\\n\";RS=\"\"} /tun/ {print}' | grep \"Scope:Global\" | awk '{print $3}'", ipv6_prefix, sizeof(ipv6_prefix));
			if(!strlen(ipv6_prefix))
				getCmdStr("ifconfig | awk 'BEGIN{FS=\"\\n\";RS=\"\"} /peth0/ {print}' | grep \"Scope:Global\" | awk '{print $3}'", ipv6_prefix, sizeof(ipv6_prefix));

			if(!strlen(ipv6_prefix))
				getCmdStr("ifconfig | awk 'BEGIN{FS=\"\\n\";RS=\"\"} /eth1/ {print}' | grep \"Scope:Global\" | awk '{print $3}'", ipv6_prefix, sizeof(ipv6_prefix));

			if(strlen(ipv6_prefix)){
				ipv6_addr_enable = "TRUE";
				ipv6_addr_num = 1;
				
				strcpy(ipv6_addr, ipv6_prefix);
				prefix_index = "Device.IP.Interface.11.IPv6Prefix.1";
				
				if(pchar = strstr(ipv6_addr, "/"))
					*pchar = '\0';

				apmib_get(MIB_IPV6_ORIGIN_TYPE,(void *)&wantype);
				if(wantype == 0){
					ipv6_origin = "DHCPv6";
					prefix_origin = "Child";
					ipv6_life = "0001-01-01T00:00:00Z"; //表示不知道
				}else if(wantype == 1){
					ipv6_origin = "Static";
					prefix_origin = "Static";
					ipv6_life = "9999-12-31T23:59:59Z";
				}else{
					ipv6_origin = "UnKonw"; //tun 和ip 穿透不知道写什么
					prefix_origin = "Child";
					ipv6_life = "0001-01-01T00:00:00Z";
				}
			}
	
			char * wanName[]={IP_HD3"Enable",
							  IP_HD3"IPv6Enable",
							  IP_HD3"Status",
							  IP_HD3"Name",
							  IP_HD3"LowerLayers", \
							  IP_HD3"MaxMTUSize",
							  IP_HD3"IPv4Address.1.Enable",
							  IP_HD3"IPv4Address.1.IPAddress",
							  IP_HD3"IPv4Address.1.SubnetMask",
							  IP_HD3"IPv4Address.1.AddressingType",
							  IP_HD3"IPv6Address.1.Enable",	//目前只取一个Internet 地址, 下标只取1
							  IP_HD3"IPv6Address.1.IPAddress",
							  IP_HD3"IPv6Address.1.Origin",
							  IP_HD3"IPv6Address.1.Prefix",
							  IP_HD3"IPv6Prefix.1.Enable",
							  IP_HD3"IPv6Prefix.1.Prefix",
							  IP_HD3"IPv6Prefix.1.Origin",
							  IP_HD3"IPv6Prefix.1.PreferredLifetime"};
							  //IP_HD3"IPv6Prefix.1.ChildPrefixBits",  //不知道怎么做
			
			char * wanValue[]={wanen, \
							   ipv6_enable, \
							   wanst,
							   waname, \
							   LowerLayers, \
							   wanmtu, \
							   wanen, \
							   wanip, \
							   getWanNetmask(), \
							   wanmode, \
							   ipv6_addr_enable, \
							   ipv6_addr, \
							   ipv6_origin, \
							   "Device.IP.Interface.11.IPv6Prefix.1", \
							   ipv6_addr_enable, \
							   ipv6_prefix, \
							   prefix_origin, \
							   ipv6_life};
			
			wanlen = sizeof(wanName)/sizeof(char *);
			addPandValueToArray(root, wanlen, wanName, wanValue);
		}
		char *wanIntName[]={IP_HD1"InterfaceNumberOfEntries",\
							IP_HD1"X_HUMAX_IndexRules.WAN", \
							IP_HD1"X_HUMAX_IndexRules.LAN", \
							IP_HD3"IPv4AddressNumberOfEntries", \
							IP_HD3"IPv6AddressNumberOfEntries"};
		int wanIntValue[]={IP_INTERFACE_NUMBER, \
						   WAN_INDEX, \
						   LAN_INDEX, \
						   IPADDR_V4_NUMBER, \
						   ipv6_addr_num};	// ipv6 开启则写为1, 关闭则认为是0.  实际情况较复杂
		wanlen = sizeof(lanIntName)/sizeof(char *);
		addIntValueToArray(root, wanlen, wanIntName, wanIntValue);

		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		int i=0;
		char *output = NULL;
		struct in_addr  ip_addr;
		cJSON *root=cJSON_CreateObject();
		char LanMaxMTU[64]={0},LanIPv4IPAddr[64]={0},LanIPv4Subnet[64]={0};
		char WanMaxMTU[64]={0},WanIPv4IPAddr[64]={0},WanIPv4Subnet[64]={0};

		char *HUMAX_WAN = websGetVar(data, T(IP_HD1"X_HUMAX_IndexRules.WAN"), T(""));//为下方i索引
		char *HUMAX_LAN = websGetVar(data, T(IP_HD1"X_HUMAX_IndexRules.LAN"), T(""));//为下方i索引

		sprintf(LanMaxMTU,"%s%s.%s",IP_HD4,HUMAX_LAN,"MaxMTUSize");
		sprintf(LanIPv4IPAddr,"%s%s.%s",IP_HD4,HUMAX_LAN,"IPv4Address.1.IPAddress");
		sprintf(LanIPv4Subnet,"%s%s.%s",IP_HD4,HUMAX_LAN,"IPv4Address.1.SubnetMask");
		
		sprintf(WanMaxMTU,"%s%s.%s",IP_HD4,HUMAX_WAN,"MaxMTUSize");
		sprintf(WanIPv4IPAddr,"%s%s.%s",IP_HD4,HUMAX_WAN,"IPv4Address.1.IPAddress");
		sprintf(WanIPv4Subnet,"%s%s.%s",IP_HD4,HUMAX_WAN,"IPv4Address.1.SubnetMask");

		char *cLanMaxMTU = websGetVar(data, T(LanMaxMTU), T(""));
		char *cLanIPv4IPAddr = websGetVar(data, T(LanIPv4IPAddr), T(""));
		char *cLanIPv4Subnet = websGetVar(data, T(LanIPv4Subnet), T(""));
		char *cWanMaxMTU = websGetVar(data, T(WanMaxMTU), T(""));
		char *cWanIPv4IPAddr = websGetVar(data, T(WanIPv4IPAddr), T(""));
		char *cWanIPv4Subnet = websGetVar(data, T(WanIPv4Subnet), T(""));
		char *ipv6Enable = websGetVar(data, IP_HD1"IPv6Enable", "");
		
		int ipv6 = strcmp(ipv6Enable, "TRUE") ? 0 : 1;
		apmib_set(MIB_IPV6_WAN_ENABLE, (void*)&ipv6);

		//  wan =========================================
		char wanmode[16]={0};
		int iWanMaxMTU = atoi(cWanMaxMTU);
		getWanConnectMode(wanmode);
		if(!strcmp(wanmode,"DHCP")){
			apmib_set(MIB_DHCP_MTU_SIZE,(void *)&iWanMaxMTU);
		}else if(!strcmp(wanmode,"STATIC")){
			apmib_set(MIB_FIXED_IP_MTU_SIZE,(void *)&iWanMaxMTU);
			//仅在静态时写
			if(inet_aton(cWanIPv4IPAddr, &ip_addr))
				apmib_set(MIB_WAN_IP_ADDR, (void *)&ip_addr);
			if(inet_aton(cWanIPv4Subnet, &ip_addr))
				apmib_set(MIB_WAN_SUBNET_MASK, (void *)&ip_addr);
		}else if(!strcmp(wanmode,"PPPOE")){
			apmib_set(MIB_PPP_MTU_SIZE,(void *)&iWanMaxMTU);
		}

		//  lan =========================================
		if(inet_aton(cLanIPv4IPAddr, &ip_addr))
			apmib_set(MIB_IP_ADDR, (void *)&ip_addr);
		if(inet_aton(cLanIPv4Subnet, &ip_addr))
			apmib_set(MIB_SUBNET_MASK, (void *)&ip_addr);
		
		apmib_update_web(CURRENT_SETTING);
		
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
		//延迟可能导致网络断开的操作，以避免多项数据相继下发时
		//在部分数据尚未完成设置之前就断开网络
		int pid=fork();
		if(0 == pid)
		{
			sleep(5);
			run_init_script("all");	
			exit(0);
		}		
	}
	return 0;
}

//cwmp_Routing: not supported, see the DateModle of HUMAX
int cwmp_Routing(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		cJSON *root;
		root=cJSON_CreateObject();
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
		
	}
	else{
		
	}
	return 0;
}

int cwmp_X_HUMAX_CurrentNetwork(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char *output=NULL;
		char routmode[32]={0},wanMode[16]={0},wanipmode[32]={0},if_wan[32]={0};
		cJSON *root;
		root=cJSON_CreateArray();

		getWanConnectMode(wanMode);
		if(getOperationMode()==1){
			strcpy(routmode,"Extender");
			strcpy(wanipmode,"Bridge");
		}else{
			strcpy(routmode,"Router");
			strcpy(wanipmode,wanMode);
		}
		getWanIfNameCs(if_wan);
		char * strarr[]={CURR_HD1"RouterMode", \
						 CURR_HD1"WanIPType", \
						 CURR_HD1"WanIPInterface"};
		char * strarrValue[]={routmode, \
							  wanipmode, \
							  if_wan};
		int strlen = sizeof(strarr)/sizeof(char *);
		addPandValueToArray(root,strlen,strarr,strarrValue);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq,tp,output);
		cJSON_Delete(root);
		free(output);
	}
	else{

		char *RouteMode = websGetVar(data, T(CURR_HD1"RouterMode"), T(""));
		char *WanIPType = websGetVar(data, T(CURR_HD1"WanIPType"), T(""));
		char *WanIPInterface = websGetVar(data, T(CURR_HD1"WanIPInterface"), T(""));
		
		int iopmode = !strcmp(RouteMode, "Extender")?0:1;
		apmib_set(MIB_OP_MODE, (void *)&iopmode);

		int wan_type;
		if(!strcmp(WanIPType, "DynamicIP")){
			wan_type = 1;
		}else if(!strcmp(WanIPType, "StaticIP")){
			wan_type = 0;
		}else if(!strcmp(WanIPType, "PPPoE")){
			wan_type = 3;
		}else if(!strcmp(WanIPType, "L2TP")){
			wan_type = 6;
		}else if(!strcmp(WanIPType, "PPTP")){
			wan_type = 4;
		}
		// else if   PPPoA / Brige, not support now.
		apmib_set(MIB_WAN_DHCP, (void *)&wan_type);

		char *output = NULL;
		cJSON *root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
		
		//延迟可能导致网络断开的操作，以避免多项数据相继下发时
		//在部分数据尚未完成设置之前就断开网络
		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			sleep(4);
			run_init_script("all");	
			exit(0);
		}
	}
	return 0;
}

int cwmp_System(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *command =   websGetVar(data, T("command"), T(""));
	static int UpFlag=1;
	static char file_size[16] = {0};
	static char file_type[64] = {0};
	cJSON *root=cJSON_CreateObject();

	if(!strcmp(command, "reboot")){
		safe_cs_pub("127.0.0.1", "RebootSystem","{}");	
	}
	else if(!strcmp(command, "factory_reset")){
		safe_cs_pub("127.0.0.1", "LoadDefSettings","{}");	
	}
	else if(!strcmp(command, "download")){
		char *url =websGetVar(data, T("url"), T(""));
		strcpy(file_size, websGetVar(data, T("file_size"), T("")));
		strcpy(file_type, websGetVar(data, T("file_type"), T("")));

		if(UpFlag == 1){
			char cmd[256]={0};
			sprintf(cmd, "wget -O %s  %s", "/var/cwmp_download", url);
			int ret=CsteSystem(cmd, CSTE_PRINT_CMD);
			if(ret == 0 )
				cJSON_AddStringToObject(root, "status", "0");
			else
				cJSON_AddStringToObject(root, "status", ""); // FAULT_9002
		}
		else{
			cJSON_AddStringToObject(root, "status", "0");
		}		
	}
	else if(!strcmp(command, "apply")){
		char *class =	 websGetVar(data, T("class"), T(""));
		char *argument = websGetVar(data, T("argument"), T(""));
		
		if(!strcmp(argument, "1 Firmware Upgrade Image ") && !strcmp(argument, file_type)){
			if(f_exist("/var/cwmp_download")){
				printf("Warning: The system is upgrading... \n");
				if(UpFlag == 1){
					safe_cs_pub("127.0.0.1", "AcsUpdate","{}");	
					cJSON_AddStringToObject(root, "status", "1");
					UpFlag = 0;
				}
				else{
					cJSON_AddStringToObject(root, "status", "0");
				}
			}
		}
	}
	
	char *output = cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	
	return 0;
}

int cwmp_IPPingDiagnostics(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	char *output = NULL,diastate[16] = "None",buf[16] = {0};
	if(strcmp(action,"get")==0){
		cJSON *root=cJSON_CreateArray();

		if(0 == access("/tmp/easycwmp_ping_status",0)){
			FILE *fp = popen("cat /tmp/easycwmp_ping_status", "r");
			if(!fp) {
				CSTE_DEBUG("popen Error\n");
			}else{
				fgets(buf, sizeof(buf), fp);
				strcpy(diastate,buf);
				pclose(fp);
			}
			
		}
		
		char *Name[]={IPPING_HD"DiagnosticsState", \
					  IPPING_HD"ProtocolVersion"};
		
		char *Value[]={diastate, "IPv4"};
		int strlen = sizeof(Name)/sizeof(char *);
		addPandValueToArray(root, strlen, Name, Value);

		char *CharGetName[]={IPPING_HD"Host"};
		int CharGetId[]={MIB_EASYCWMP_PINGHOST};
	    int arraylen = sizeof(CharGetName)/sizeof(char *); 
		addObjectToArray(root, arraylen, CharGetName, CharGetId);

		char * IntGetName[]={IPPING_HD"NumberOfRepetitions", \
							 IPPING_HD"SuccessCount", \
							 IPPING_HD"FailureCount", \
							 IPPING_HD"AverageResponseTime"};
		int IntGetId[]={MIB_EASYCWMP_PINGNUM, \
						MIB_EASYCWMP_PINGSUCCESSNUM, \
						MIB_EASYCWMP_PINGFAILURENUM, \
						MIB_EASYCWMP_PINGAVG};
   		int intlen = sizeof(IntGetName)/sizeof(char *);
    	addObjectIntToArray(root,intlen,IntGetName,IntGetId);

		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}else{
		cJSON *root=cJSON_CreateObject();
		char *cDiaState = websGetVar(data, T(IPPING_HD"DiagnosticsState"), T(""));
		char *cPingHost = websGetVar(data, T(IPPING_HD"Host"), T(""));
		char *cPingNum = websGetVar(data, T(IPPING_HD"NumberOfRepetitions"), T(""));
		if(!strcmp(cDiaState,"Requested"))
		{
			char cmd[256]={0};
			int pid;
			pid=fork();
			if(pid==0){
				sprintf(cmd,"/bin/easycwmpping.sh %s %s &",cPingHost,cPingNum);
				CsteSystem(cmd,CSTE_PRINT_CMD);
				exit(1);
			}
		}

		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}

}

int cwmp_IPTraceDiagnostics(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	char *output = NULL,diastate[16]="None",status_buf[16]={0};
	int rows=0,i=0,num=atoi(NUM_IP);
	char str[128];
	if(strcmp(action,"get")==0){
		cJSON *root=cJSON_CreateArray();
		
		if(0 == access("/tmp/easycwmp_trace_status",0)){
			FILE *fp2 = popen("cat /tmp/easycwmp_trace_status", "r");
			if(!fp2) {
				CSTE_DEBUG("popen Error\n");
			}else{
				fgets(status_buf, sizeof(status_buf), fp2);
				strcpy(diastate,status_buf);
				pclose(fp2);
			}
			
		}

		
		char *Name[]={IPTRACE_HD"DiagnosticsState"};
		char *Value[]={diastate};
		int strlen = sizeof(Name)/sizeof(char *);
		addPandValueToArray(root, strlen, Name, Value);

		char *CharGetName[]={IPTRACE_HD"Host"};
		int CharGetId[]={MIB_EASYCWMP_TRACEHOST};
	    int arraylen = sizeof(CharGetName)/sizeof(char *); 
		addObjectToArray(root, arraylen, CharGetName, CharGetId);
			
		char * IntGetName[]={IPTRACE_HD"NumberOfTries", \
							 IPTRACE_HD"Timeout", \
							 IPTRACE_HD"MaxHopCount"};
		int IntGetId[]={MIB_EASYCWMP_TRACENUM, \
						MIB_EASYCWMP_TRACETIMEOUT, \
						MIB_EASYCWMP_TRACEMAXCOUNT};
		int intlen = sizeof(IntGetName)/sizeof(char *);
		addObjectIntToArray(root,intlen,IntGetName,IntGetId);

		//read /tmp/easycwmp_trace 
		if(0 == access(EASYCWMP_TRACE,0)){
			struct stat st;
			stat(EASYCWMP_TRACE, &st);
			if(st.st_size<=0)
				goto end;
			FILE *fp = fopen(EASYCWMP_TRACE, "r");
			while (fgets(str, 128, fp) != NULL)
				++rows;

			//取最后一次路由的最后一次时间
			char buf[8]={0}, cmd[256]={0},line_buf[512]={0},*time_list[20]={NULL};
			char host_addr[32]={0},addr[32]={0},host_name[32]={0},time[512]={0},RTTimes[512]={0};
			int numiftri=0,respinsetime,time_num=0,j=0;
			apmib_get(MIB_EASYCWMP_TRACENUM,(void *)&numiftri);
			sprintf(cmd,"tail -n 1 /tmp/easycwmp_trace | grep \" \" | cut -d \" \" -f%d | cut -d \".\" -f1",7+3*(numiftri-1));

			FILE *fp1 = popen(cmd, "r");
			if(!fp1) CSTE_DEBUG("popen Error\n");
	    	fgets(buf, sizeof(buf), fp1);
			respinsetime=atoi(buf);
			if(!strcmp(buf,"*"))
				respinsetime=0;
			pclose(fp);
			pclose(fp1);

			char *IntName[]={IPTRACE_HD"ResponseTime",\
							 IPTRACE_HD"RouteHopsNumberOfEntries"};
			int IntValue[]={respinsetime,num};
			int jklen = sizeof(IntName)/sizeof(char *);
			addIntValueToArray(root,jklen,IntName,IntValue);
			//动态数据
			cJSON *arry	= cJSON_CreateArray();
			FILE * fd=fopen(EASYCWMP_TRACE,"r");
			if ( NULL == fd){
		      printf("open /tmp/easycwmp_trace failed.\n");
		      return 0;
		    }
			
			while(fgets(line_buf, 512, fd) != NULL){
				cJSON *item	= cJSON_CreateObject();
				sscanf(line_buf,"%*s%*[ ]%s%*[ ]%s%*[ ]%[0-9, ,.,(,)]",host_name,addr,time);
				sscanf(addr,"(%[^)]",host_addr);
				cJSON_AddStringToObject(item,"Host",host_name);
				cJSON_AddStringToObject(item,"HostAddress",host_addr);
				time_list[time_num]=strtok(time,") (");
				while(time_list[time_num+1]=strtok(NULL,") (")){
						time_num++;
				}

				for(j=0;j< time_num;j++){
					int ret=isIPValid(time_list[j]);  //判断数据是不是IP  地址
					if(ret != 1){
						strcat(RTTimes,time_list[j]);
						strcat(RTTimes,",");
					}
				}
				
				cJSON_AddStringToObject(item,"RTTimes",RTTimes);
				output = cJSON_Print(item);
				cJSON_AddItemToArray(arry,item);

				time_num=0;
				memset(time,0x00,sizeof(time));
				memset(RTTimes,0x00,sizeof(RTTimes));
				memset(line_buf,0x00,sizeof(line_buf));
				memset(host_name,0x00,sizeof(host_name));
				memset(host_addr,0x00,sizeof(host_addr));
			}	
			

			char * trace = cJSON_Print(arry);
			char * maName[]={"RouteHops"};
			char * maValue[]={trace};
			int malen = sizeof(maName)/sizeof(char *);
			addPandValueToArray(root,malen,maName,maValue);

			cJSON_Delete(arry);
			free(trace);
			fclose(fd);
		}
		else{
			char *Intval[]={IPTRACE_HD"ResponseTime",\
							IPTRACE_HD"RouteHopsNumberOfEntries"};
			int Value[]={0,num};
			int leng = sizeof(Intval)/sizeof(char *);
			addIntValueToArray(root,leng,Intval,Value);

			cJSON *arry	= cJSON_CreateArray();
			char * trace = cJSON_Print(arry);
			char * maName[]={"RouteHops"};
			char * maValue[]={trace};
			int malen = sizeof(maName)/sizeof(char *);
			addPandValueToArray(root,malen,maName,maValue);
			cJSON_Delete(arry);
			free(trace);	
		}
end:
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}else{
		cJSON *root=cJSON_CreateObject();
		char *cDiaState = websGetVar(data, T(IPTRACE_HD"DiagnosticsState"), T(""));
		char *cTraceHost = websGetVar(data, T(IPTRACE_HD"Host"), T(""));
		char *cTraceNum = websGetVar(data, T(IPTRACE_HD"NumberOfTries"), T(""));
		char *cTraceTimeout = websGetVar(data, T(IPTRACE_HD"Timeout"), T(""));
		char *cTraceMaxHopCount = websGetVar(data, T(IPTRACE_HD"MaxHopCount"), T(""));

		if(!strcmp(cDiaState,"Requested"))
		{
			char cmd[256]={0};
			int pid=fork();
			if(0 == pid)
			{
				sprintf(cmd,"/bin/easycwmptrace.sh %s %s %s %s &",
							cTraceMaxHopCount,cTraceNum,cTraceTimeout,cTraceHost);
				CsteSystem(cmd,CSTE_PRINT_CMD);
				exit(1);
			}
			int iTraceNum=atoi(cTraceNum);
			int iTraceTimeout=atoi(cTraceTimeout);
			int iTraceMaxHopCount=atoi(cTraceMaxHopCount);
			apmib_set(MIB_EASYCWMP_TRACEHOST, (void *)cTraceHost);
			apmib_set(MIB_EASYCWMP_TRACENUM, (void *)&iTraceNum);
			apmib_set(MIB_EASYCWMP_TRACETIMEOUT, (void *)&iTraceTimeout);
			apmib_set(MIB_EASYCWMP_TRACEMAXCOUNT, (void *)&iTraceMaxHopCount);
			int pid1=fork();
			if(0 == pid1)
			{
				sleep(1);
				apmib_update_web(CURRENT_SETTING);
				exit(1);
			}
			
		}
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
}

int cwmp_X_HUMAX_WirelessSchedule(struct mosquitto *mosq, cJSON* data, char *tp)
{

	char *action = websGetVar(data, T("action"), T(""));
	char *output;
	if(strcmp(action,"get")==0){
		cJSON *root=cJSON_CreateArray();

		int enabled = 0, entryNum = 0, i = 0;
		int startHour, startMin,DurationHour,DurationMin;
		char ch_enabled[8]={0};
		SCHEDULE_T entry;
		char buff[64]={0}, schList[512]={0};

		SetWlan_idx("wlan0");
		apmib_get_bool(MIB_WLAN_SCHEDULE_ENABLED, ch_enabled);

		char *Name[]={WIFISCH_HD1"Enable", \
					  WIFISCH_HD1"RuleNumberOfEntries"};
		char *Value[]={ch_enabled, \
					   NUM_WiFi_Schedule};
		
		int strlen = sizeof(Name)/sizeof(char *);
		addPandValueToArray(root, strlen, Name, Value);

		//-----schedule item-----
		cJSON *schedule_arry = cJSON_CreateArray();
		apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);
		for (i=1; i<=entryNum; i++) {
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);

			cJSON *schedule_item= cJSON_CreateObject();
			char StartTime[16] = {0}, EndTime[16] = {0}, time_buf[8] = {0},Duration[8]={0};
			char *weekday = NULL;

			cJSON_AddItemToArray(schedule_arry, schedule_item);

			startHour= entry.fTime/60;
			startMin = entry.fTime%60;

			if(startHour<10)
				sprintf(time_buf, "0%d", startHour);
			else
				sprintf(time_buf, "%d", startHour);
			if(startMin<10)
				sprintf(StartTime,	"%s:0%d", time_buf, startMin);
			else
				sprintf(StartTime,	"%s:%d", time_buf, startMin);
			
			DurationHour= (entry.tTime - entry.fTime)/60;
			DurationMin = (entry.tTime - entry.fTime)%60;

			if(DurationHour<10)
				sprintf(time_buf, "0%d", DurationHour);
			else
				sprintf(time_buf, "%d", DurationHour);
			if(DurationMin<10)
				sprintf(Duration,	"%s:0%d", time_buf, DurationMin);
			else
				sprintf(Duration,	"%s:%d", time_buf, DurationMin);
			
			switch(entry.day){
				case 0:	weekday = "Sun"; break;
				case 1:	weekday = "Mon"; break;
				case 2:	weekday = "Tue"; break;
				case 3:	weekday = "Wed"; break;
				case 4:	weekday = "Thr"; break;
				case 5:	weekday = "Fri"; break;
				case 6:	weekday = "Sat"; break;
				case 7:	weekday = "Everyday"; break;
			}

			//单独的开关应该是entry.eco, 但是页面没有开关，为统一不使用
			cJSON_AddStringToObject(schedule_item, "Enable", "TRUE");
			cJSON_AddStringToObject(schedule_item, "DayOfWeek", weekday);
			cJSON_AddStringToObject(schedule_item, "StartTime", StartTime);
			cJSON_AddStringToObject(schedule_item, "Duration", Duration);
			
		}

		char *schedule_rule = cJSON_Print(schedule_arry);
		char *frName[]={"Rule"};		
		char *frValue[]={schedule_rule};
		strlen = sizeof(frName)/sizeof(char *);
		addPandValueToArray(root, strlen, frName, frValue);

		cJSON_Delete(schedule_arry);
		free(schedule_rule);

		output =cJSON_Print(root);
		
		char *output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		int i = 0, entryNum = 0;
		char time1[8] = {0}, time2[8] = {0},time3[8] = {0}, time4[8] = {0};
		SCHEDULE_T entry;
		//char *Enable = websGetVar(data, WIFISCH_HD1"Enable", "");
		cJSON *WifiSchedure = cJSON_Parse(websGetVar(data, WIFISCH_HD1"Rule.", ""));
		cJSON *root=cJSON_CreateObject();
		cJSON *subObj = NULL;

		SetWlan_idx("wlan0");
		apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);
		for (i=entryNum; i>0; --i){
			*((char *)&entry) = (char)i;
			apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);
			apmib_set(MIB_WLAN_SCHEDULE_DEL, (void *)&entry);
		}

		for(i=0; i<cJSON_GetArraySize(WifiSchedure); ++i){ 
			subObj = cJSON_GetArrayItem(WifiSchedure, i);
			//char * enabled=websGetVar(subObj, Enable, "");
			char *DayOfWeek = websGetVar(subObj, "DayOfWeek", "");
			char *Start_Time = websGetVar(subObj, "StartTime", "");
			char *Duration_Time	= websGetVar(subObj, "Duration", "");

			// 与reboot 调度可能不同
			if(!strcmp(DayOfWeek, "Sun"))
				entry.day=0;
			if(!strcmp(DayOfWeek, "Sat"))
				entry.day=6;
			if(!strcmp(DayOfWeek, "Fri"))
				entry.day=5;
			if(!strcmp(DayOfWeek, "Thr"))
				entry.day=4;
			if(!strcmp(DayOfWeek, "Wed"))
				entry.day=3;
			if(!strcmp(DayOfWeek, "Tue"))
				entry.day=2;
			if(!strcmp(DayOfWeek, "Mon"))
				entry.day=1;
			if(!strcmp(DayOfWeek, "Everyday")){
				entry.day=7;
			}

			entry.eco = 1;	//Humax 页面未使用该开关，总设置为开
			sscanf(Start_Time, "%[^:]:%[^:]", time1, time2);
			entry.fTime = atoi(time1)*60 + atoi(time2);
			sscanf(Duration_Time, "%[^:]:%[^:]", time3, time4);
			entry.tTime = atoi(time3)*60 + atoi(time4) + entry.fTime;
			if(entry.tTime >= 1439)entry.tTime = 1439;

			apmib_set(MIB_WLAN_SCHEDULE_DEL, (void *)&entry);
			if ( apmib_set(MIB_WLAN_SCHEDULE_ADD, (void *)&entry) == 0) {
				printf("set wifi_schedule error!");
				goto OUT;
			}
		}

		apmib_update_web(CURRENT_SETTING);
		system("sysconf wlan_schedule");
		cJSON_Delete(WifiSchedure);

OUT:
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

int cwmp_X_HUMAX_RebootSchedule(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *action = websGetVar(data, T("action"), T(""));
	if(strcmp(action,"get")==0){
		char weeks[128]={0},time[64]={0},Enable[16]={0},*output=NULL;
		int date=0,hour=0,minute=0;
		cJSON *root=cJSON_CreateArray();
		
		apmib_get(MIB_REBOOTSCH_HOUR, (void *)&hour);
		apmib_get(MIB_REBOOTSCH_MINUTE, (void *)&minute);
		apmib_get_bool(MIB_REBOOTSCH_ENABLED, Enable);
		apmib_get(MIB_REBOOTSCH_WEEK,  (void *)&date);

		sprintf(time,"%d:%d",hour,minute);
		
		switch(date){
			case 7:
				sprintf(weeks,"%s","Sun");break;
			case 6:
				sprintf(weeks,"%s","Sat");break;
			case 5:
				sprintf(weeks,"%s","Fri");break;
			case 4:
				sprintf(weeks,"%s","Thr");break;
			case 3:
				sprintf(weeks,"%s","Wed");break;
			case 2:
				sprintf(weeks,"%s","Tue");break;
			case 1:
				sprintf(weeks,"%s","Mon");break;
			case 0:
				sprintf(weeks,"%s","Everyday");break;
			default:
				sprintf(weeks,"%s","Sun");break;
		}

		char *Name[]={REBOOT_HD1"Enable", \
				  	REBOOT_HD1"Time",\
				  	REBOOT_HD1"DayOfWeek"};
		
		char *Value[]={Enable, time, weeks};
		int strlen = sizeof(Name)/sizeof(char *);
		addPandValueToArray(root, strlen, Name, Value);
		
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	else{
		char time1[32]={0},time2[32]={0},*output=NULL;
		int date=0,enable=0,hour=0,minute=0;
		cJSON *root=cJSON_CreateObject();

		char *Enable = websGetVar(data, T(REBOOT_HD1"Enable"), T(""));
		char *Time = websGetVar(data, T(REBOOT_HD1"Time"), T(""));
		char *DayOfWeek = websGetVar(data, T(REBOOT_HD1"DayOfWeek"), T(""));

		sscanf(Time,"%[0-9]:%[0-9]",time1,time2);
		hour=atoi(time1);
		minute=atoi(time2);
		
		enable = !strcmp(Enable,"TRUE")?1:0;
		if(enable){
			if(!strcmp(DayOfWeek,"Sun"))
				date=7;
			if(!strcmp(DayOfWeek,"Sat"))
				date=6;
			if(!strcmp(DayOfWeek,"Fri"))
				date=5;
			if(!strcmp(DayOfWeek,"Thr"))
				date=4;
			if(!strcmp(DayOfWeek,"Wed"))
				date=3;
			if(!strcmp(DayOfWeek,"Tue"))
				date=2;
			if(!strcmp(DayOfWeek,"Mon"))
				date=1;
			if(!strcmp(DayOfWeek,"Everyday"))
				date=0;

			apmib_set(MIB_REBOOTSCH_WEEK, (void *)&date);
			apmib_set(MIB_REBOOTSCH_HOUR, (void *)&hour);
			apmib_set(MIB_REBOOTSCH_MINUTE, (void *)&minute);
		}
		
		apmib_set(MIB_REBOOTSCH_ENABLED, (void *)&enable);
		apmib_update_web(CURRENT_SETTING);
		
		cJSON_AddNumberToObject(root,"status", 0);
		output = cJSON_Print(root);
		websGetCfgResponse(mosq, tp, output);
		cJSON_Delete(root);
		free(output);
	}
	return 0;
}

static int init_cpe_acsname( void )
{
	char acsName[32]={0};
	char acsDefName[32]={0};

	apmib_get(MIB_EASYCWMP_ACSNAME,(void *)acsName);
	if ( acsName && !strcmp(acsName, "AcsName") )
	{
		getDefaultAcsName(acsDefName);
		apmib_set(MIB_EASYCWMP_ACSNAME,(void *)acsDefName);
	}
	
	return 0;

	
		// temp code, for EASYCWMP
#if defined(CONFIG_APP_EASYCWMP)
		int easycwmp_onoff = 0;
		apmib_get(MIB_EASYCWMP_ENABLE, (void *)&easycwmp_onoff);
		
		if(easycwmp_onoff){
			system("killall easycwmpd");
			sleep(1);
			system("/bin/easycwmpd -b -f &");
		}
#endif
}

int preparedm(void)
{
	int ret = 0;
	FILE *fp;

    fp = fopen(DM_FILE, "w");
	if (fp!=NULL)
    {
    	ret = fwrite(XMLDATAMODEL, 1, strlen(XMLDATAMODEL), fp);
        fclose(fp);
    }
	CSTE_DEBUG("len=%d.\n", ret);

	fp = fopen(UNVAULED_JSONS_FILE, "w");
	if (fp!=NULL)
    {
    	ret = fwrite(UNVALUED_JSONS, 1, strlen(UNVALUED_JSONS), fp);
        fclose(fp);
    }

    return ret;
}

int module_init()
{
	init_cpe_acsname();
	preparedm();
	cste_hook_register("easycwmp",easycwmp);
	cste_hook_register("cwmp_config_local",cwmp_config_local);	
	cste_hook_register("cwmp_config_acs",cwmp_config_acs);
	cste_hook_register("cwmp_DeviceInfo",cwmp_DeviceInfo);
	cste_hook_register("cwmp_ManagementServer",cwmp_ManagementServer);
	cste_hook_register("cwmp_Timing",cwmp_Timing);
	cste_hook_register("cwmp_UserInterface",cwmp_UserInterface);
	cste_hook_register("cwmp_Ethernet",cwmp_Ethernet);
	cste_hook_register("cwmp_USB",cwmp_USB);
	cste_hook_register("cwmp_DynamicDNS",cwmp_DynamicDNS);
	cste_hook_register("cwmp_DHCPv4",cwmp_DHCPv4);
	cste_hook_register("cwmp_DHCPv6",cwmp_DHCPv6);
	cste_hook_register("cwmp_Users",cwmp_Users);
	cste_hook_register("cwmp_UPnP",cwmp_UPnP);
	cste_hook_register("cwmp_Firewall",cwmp_Firewall);
	cste_hook_register("cwmp_Firewall_IP",cwmp_Firewall_IP);
	cste_hook_register("cwmp_Firewall_Mac",cwmp_Firewall_Mac);
	cste_hook_register("cwmp_Firewall_Url",cwmp_Firewall_Url);
	cste_hook_register("cwmp_NAT",cwmp_NAT);
	cste_hook_register("cwmp_DNS",cwmp_DNS);
	cste_hook_register("cwmp_Hosts",cwmp_Hosts);
	cste_hook_register("cwmp_PPP",cwmp_PPP);
	cste_hook_register("cwmp_wifi",cwmp_wifi);
	cste_hook_register("cwmp_wifi_basic",cwmp_wifi_basic);
	cste_hook_register("cwmp_wifi_scan",cwmp_wifi_scan);
	cste_hook_register("cwmp_wifi_multilssid",cwmp_wifi_multilssid);
	cste_hook_register("cwmp_wifi_accsspoint",cwmp_wifi_accsspoint);
	cste_hook_register("cwmp_IP",cwmp_IP);
	cste_hook_register("cwmp_Routing",cwmp_Routing);
	cste_hook_register("cwmp_X_HUMAX_CurrentNetwork",cwmp_X_HUMAX_CurrentNetwork);
	cste_hook_register("cwmp_System", cwmp_System);
	cste_hook_register("cwmp_IPPingDiagnostics", cwmp_IPPingDiagnostics);
	cste_hook_register("cwmp_IPTraceDiagnostics", cwmp_IPTraceDiagnostics);
	cste_hook_register("cwmp_X_HUMAX_WirelessSchedule", cwmp_X_HUMAX_WirelessSchedule);
	cste_hook_register("cwmp_X_HUMAX_RebootSchedule", cwmp_X_HUMAX_RebootSchedule);
    return 0;  
}

