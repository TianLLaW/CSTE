#include "managementAc.h"

int mysqltest(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;
	int ret=-1;
	
	cJSON *root =NULL;

	char query[1024] ={0}, *output =NULL, *cmd;

	cmd= websGetVar(data, T("cmd"), T(""));

	if(strlen(cmd)==0)
	{
		sprintf(query,"select * from %s;",MYSQL_APLIST_TABLE_NAME);
	}
	else
	{
		strcpy(query,cmd);
	}
	root=cJSON_CreateArray();

	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;

	cste_mysqlgetarray(my_con, query, root);
	cste_mysqlclose(my_con);

end_lable:

	output=cJSON_Print(root);

	cJSON_Delete(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);

	return 0;
}

int ScanAp(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char tmpbuf[128] = {0};
	sprintf(tmpbuf,"killall -%d cste_heartbeat",SIG_BROADCAST);
	CsteSystem(tmpbuf,CSTE_PRINT_CMD);

	websSetCfgResponse(mosq, tp, "0", "reserv");

	return 0;
}


/*---------------get--------------------------------------*/
int addApInfoToList(sqlite3 *my_con,cJSON *root, char *id)
{
	char query[MAX_MYSQL_QUERY_LEN] ={0},*aptype;
	cJSON *jsonAp,*jsonSch,*radio0,*radio1,*wlans;
	int iRet=0;

	jsonAp = cJSON_CreateObject();
	cJSON_AddItemToArray(root,jsonAp);
		
	snprintf(query,MAX_MYSQL_QUERY_LEN,"select id,apname,apmac,ipaddr,netmask,gateway,pridns,"
				   "apstate,apstatus,csid,model,svnnum,uptime,softver,aptype,password,ledstate from %s where id='%s';",
				   TBL_ID_TONAME(MYSQL_APLIST_TABLE),id);
	cste_mysqlonerowtojson(my_con,jsonAp,query);

	//rebooSchedule	
	jsonSch = cJSON_CreateObject();
	snprintf(query,MAX_MYSQL_QUERY_LEN,"select schMode,schWeek,schHour,schMinute,recHour from %s where id='%s';",
				   TBL_ID_TONAME(MYSQL_APLIST_TABLE),id);
	cste_mysqlonerowtojson(my_con,jsonSch,query);
	cJSON_AddItemToObject(jsonAp,"rebooSchedule",jsonSch);

	aptype=websGetVar(jsonAp, T("aptype"), T("1"));

	wlans = cJSON_CreateObject();
	snprintf(query,MAX_MYSQL_QUERY_LEN,"select ssid,hide,isolate,encryption,passphrase,stanum,vlanid from %s where apid='%s' and usefor=1;",
				   TBL_ID_TONAME(MYSQL_WLAN_STATUS),id);

	iRet=cste_mysqlonerowtojson(my_con,wlans,query);
	if(iRet<0){
		cJSON_Delete(wlans);
	}else{
		cJSON_AddItemToObject(jsonAp,SSIDS_STR,wlans);
	}

	radio0 = cJSON_CreateObject();
	snprintf(query,MAX_MYSQL_QUERY_LEN,"select htmode,channel,txpower,clientnum from %s where apid='%s';",
		           TBL_ID_TONAME(MYSQL_APSTATUS_WIFI0),id);
	iRet=cste_mysqlonerowtojson(my_con,radio0,query);
	if(iRet<0){
		cJSON_Delete(radio0);
	}else{
		cJSON_AddItemToObject(jsonAp,RADIO0,radio0);
	}

	if(!strcmp(aptype,"3")){
		wlans = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select ssid,hide,isolate,encryption,passphrase,stanum,vlanid from %s where apid='%s' and usefor=2;",
			           TBL_ID_TONAME(MYSQL_WLAN_STATUS),id);

		iRet=cste_mysqlonerowtojson(my_con,wlans,query);
		if(iRet<0){
			cJSON_Delete(wlans);
		}else{
			cJSON_AddItemToObject(jsonAp,SSIDS1_STR,wlans);
		}
		
		radio1 = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select htmode,channel,txpower,clientnum from %s where apid='%s';",
			           TBL_ID_TONAME(MYSQL_APSTATUS_WIFI1),id);

		iRet=cste_mysqlonerowtojson(my_con,radio1,query);
		if(iRet<0){
			cJSON_Delete(radio1);
		}else{
			cJSON_AddItemToObject(jsonAp,RADIO1,radio1);
		}
	}

	return 0;
}
int getGroupApList(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	cJSON *root =NULL,*id_arry,*tmpjs;

	char *output =NULL,*APID;

	char query[1024] ={0};

	int i,id_num=0,ret=-1;

	root=cJSON_CreateArray();

	id_arry=cJSON_CreateArray();

	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;

	sprintf(query,"select id from %s;",TBL_ID_TONAME(MYSQL_APLIST_TABLE));
	cste_mysqlgetarray(my_con, query, id_arry);

	id_num=cJSON_GetArraySize(id_arry);

	for(i=0;i<id_num;i++){
		tmpjs = cJSON_GetArrayItem(id_arry,i);
		APID=websGetVar(tmpjs, T("id"), T(""));
		addApInfoToList(my_con,root, APID);
	}
	
	cste_mysqlclose(my_con);
end_lable:

	output=cJSON_Print(root);
	cJSON_Delete(root);
	cJSON_Delete(id_arry);
	websGetCfgResponse(mosq,tp,output);
	free(output);

	return 0;
}

int getApCsidList(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	cJSON *root =NULL;

	char *output =NULL;
	char query[1024] ={0};
	int ret=-1;

	root=cJSON_CreateArray();
	
	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;
	
	snprintf(query,sizeof(query),"select distinct %s from %s;",MYSQL_CSID_KEY_NAME,TBL_ID_TONAME(MYSQL_APLIST_TABLE));
	
	cste_mysqlgetarray(my_con, query, root);

	cste_mysqlclose(my_con);

end_lable:

	output=cJSON_Print(root);
	
	cJSON_Delete(root);
	
	websGetCfgResponse(mosq,tp,output);
	free(output);

	return 0;
}

int getApListByCsid(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	cJSON *root =NULL;

	char *output =NULL, *CSID = NULL;
	char query[1024] ={0};
	int ret=-1;

	CSID= websGetVar(data, T("csid"), T(""));

	root=cJSON_CreateArray();

	if(strlen(CSID))
	{
		ret=cste_mysqlopen(&my_con,SQLPATH);
		if(ret==-1)
			goto end_lable;
	
		snprintf(query,sizeof(query),"select * from %s where %s='%s';",TBL_ID_TONAME(MYSQL_APLIST_TABLE),MYSQL_CSID_KEY_NAME,CSID);
		
		cste_mysqlgetarray(my_con, query, root);

		cste_mysqlclose(my_con);

		
	}
end_lable:

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);

	return 0;
}

int getApStatusConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	int APID = 0;

	char *output =NULL;
	char query[MAX_MYSQL_QUERY_LEN] ={0};
	int ret=-1;

	cJSON *root = cJSON_CreateObject();

	APID= atoi(websGetVar(data, T("apid"), T("")));
	
	if(APID)
	{
		ret=cste_mysqlopen(&my_con,SQLPATH);
		if(ret==-1)
			goto end_lable;

		cJSON *radio0 = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select country,wirelessmode,htmode,channel,txpower,clientnum,beacon from %s where apid=%d;",TBL_ID_TONAME(MYSQL_APSTATUS_WIFI0),APID);
		cste_mysqlonerowtojson(my_con,radio0,query);
		cJSON_AddItemToObject(root,RADIO0,radio0);
		
		cJSON *radio1 = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select country,wirelessmode,htmode,channel,txpower,clientnum,beacon from %s where apid=%d;",TBL_ID_TONAME(MYSQL_APSTATUS_WIFI1),APID);
		cste_mysqlonerowtojson(my_con,radio1,query);
		cJSON_AddItemToObject(root,RADIO1,radio1);

		cJSON *wlans = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select * from %s where apid=%d and usefor='1';",TBL_ID_TONAME(MYSQL_WLAN_STATUS),APID);
		cste_mysqlonerowtojson(my_con,wlans,query);
		cJSON_AddItemToObject(root,SSIDS_STR,wlans);

		wlans = cJSON_CreateObject();
		snprintf(query,MAX_MYSQL_QUERY_LEN,"select * from %s where apid=%d and usefor='2';",TBL_ID_TONAME(MYSQL_WLAN_STATUS),APID);
		cste_mysqlonerowtojson(my_con,wlans,query);
		cJSON_AddItemToObject(root,SSIDS1_STR,wlans);

		cste_mysqlclose(my_con);
		
	}

end_lable:
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}


/*--------------------set----------------------------*/

int setApName(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	char *APID = NULL, *APNAME = NULL;

	int config_value = AP_CONFIG_OK_VALUE;
	int ret=-1;

	APID= websGetVar(data, T("apid"), T("1"));
	APNAME = websGetVar(data, T("apname"), T(""));

	if((APID)&&(strlen(APNAME)))
	{
		ret=cste_mysqlopen(&my_con,SQLPATH);
		if(ret==-1)
			goto end_lable;

		MyClearField32(config_value,SYSTEM_CONFIG);

		cste_mysqlexec(my_con,"update %s set %s=%d, %s='%s', %s=%s&%d where %s='%s';",MYSQL_APLIST_TABLE_NAME,MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,MYSQL_APNAME_KEY_NAME,APNAME,
						MSYQL_APSTATE_KEY_NAME,MSYQL_APSTATE_KEY_NAME,config_value,MYSQL_APID_KEY_NAME,APID);

		backupDb(my_con, SQLPATH_BAK, xProgress);
		cste_mysqlclose(my_con);
	}
end_lable:

	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setApLedState(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	char *aparr,*ledState = NULL;
	char APID[8] ={0},APID_ARR[1024]={0};

	int ret=-1,i=0;
	int config_value = AP_CONFIG_OK_VALUE;

	aparr = websGetVar(data, T("id"), T("1"));
	ledState = websGetVar(data, T("ledState"), T(""));
	strcpy(APID_ARR,aparr);
	
	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;

	MyClearField32(config_value,SYSTEM_CONFIG);

	while(getNthValueSafe(i++, APID_ARR, ',', APID, sizeof(APID)) != -1)
	{
		if(strlen(APID))
		{
			cste_mysqlexec(my_con,"update APLIST set ledstate='%s' where id='%s';",ledState,APID);
			cste_mysqlexec(my_con,"update APLIST set %s=%d, apstate=apstate&%d where id='%s';",MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,config_value,APID);
		}
	}

	cste_mysqlclose(my_con);

end_lable:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setApReboot(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;
	
	char *aparr = websGetVar(data, T("id"), T(""));
	char APID[8] ={0},APID_ARR[1024]={0};
	
	int config_value = AP_CONFIG_OK_VALUE;
	int i=0,ret=-1;

	strcpy(APID_ARR,aparr);

	MyClearField32(config_value,REBOOT_COMMAND);

	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;

	while(getNthValueSafe(i++, APID_ARR, ',', APID, sizeof(APID)) != -1)
	{
		if(strlen(APID))
		{
			cste_mysqlexec(my_con,"update APLIST set %s=%d, apstate=apstate&%d where id='%s';",MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,config_value,APID);
		}
	}
	cste_mysqlclose(my_con);
end_lable:

	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setApReset(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	char *aparr = websGetVar(data, T("id"), T(""));
	char APID[8] ={0},APID_ARR[1024]={0};
	
	int config_value =AP_CONFIG_OK_VALUE;
	int i=0,ret=-1;
	
	MyClearField32(config_value,RESET_COMMAND);

	strcpy(APID_ARR,aparr);
	
	ret=cste_mysqlopen(&my_con,SQLPATH);
	if(ret==-1)
		goto end_lable;

	while(getNthValueSafe(i++, APID_ARR, ',', APID, sizeof(APID)) != -1)
	{
		if(strlen(APID))
		{
			cste_mysqlexec(my_con,"update APLIST set %s=%d, apstate=apstate&%d where id='%s';",MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,config_value,APID);
		}
	}

	cste_mysqlclose(my_con);
end_lable:

	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setQuickSetting(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;

	int  config_value = AP_CONFIG_OK_VALUE, i = 0,iRet;
	char APID[5] = {0};
	int wifi_td=MYSQL_APSTATUS_WIFI0;
	char *apid = websGetVar(data, T("apid"), T("0"));
	char *usefor = websGetVar(data, T("usefor"), T("1"));
	char *apname = websGetVar(data, T("apname"), T(""));

	char *ssid = websGetVar(data, T("ssid"), T(""));
	char *hedden = websGetVar(data, T("hedden"), T("0"));
	char *noforward = websGetVar(data, T("noforward"), T("0"));
	char *encryption = websGetVar(data, T("encryption"), T("0"));
	char *wlanKey = websGetVar(data, T("wlanKey"), T(""));
	char *maxstanum = websGetVar(data, T("maxstanum"), T("32"));
	char *vlanid = websGetVar(data, T("vlanid"), T("0"));
	
	char *channel = websGetVar(data, T("channel"), T("0"));
	char *htbw = websGetVar(data, T("htbw"), T("0"));
	char *txpower = websGetVar(data, T("txpower"), T("100"));

	cJSON *schdReboot  = NULL;
	schdReboot =  cJSON_GetObjectItem(data,"rebooSchedule");
	
	char *schMode = websGetVar(schdReboot,"schMode",  T("0"));
	char *schWeek = websGetVar(schdReboot,"schWeek",  T("0"));
	char *schHour = websGetVar(schdReboot,"schHour",  T("0"));
	char *schMinute = websGetVar(schdReboot,"schMinute",T("0"));
	char *recHour = websGetVar(schdReboot,"recHour",  T("0"));

	if(!strcmp(usefor,"2"))
		wifi_td=MYSQL_APSTATUS_WIFI1;

	iRet=cste_mysqlopen(&my_con,SQLPATH);
	if(iRet<0){
		goto err;
	}
	if(strlen(apid)>0)
	{

		while((getNthValueSafe(i++, apid, ',', APID, sizeof(APID)) != -1))
		{
			cste_mysqlexec(my_con,"update %s set ssid='%s',hide='%s',isolate='%s',encryption='%s',passphrase='%s',"
												"stanum='%s',vlanid='%s' where %s='%s' and usefor='%s';",
							TBL_ID_TONAME(MYSQL_WLAN_STATUS),ssid,hedden,noforward,encryption,wlanKey,maxstanum,vlanid,MYSQL_STATUS_APID,APID,usefor);

			cste_mysqlexec(my_con,"update %s set channel='%s', htmode='%s',txpower='%s' where %s='%s';",
							TBL_ID_TONAME(wifi_td),channel,htbw,txpower,MYSQL_STATUS_APID,APID);

			if(strlen(apname)>0)
			{
				cste_mysqlexec(my_con,"update %s set %s='%s' where %s='%s';",
					          TBL_ID_TONAME(MYSQL_APLIST_TABLE),MYSQL_APNAME_KEY_NAME,apname,MYSQL_APID_KEY_NAME,APID);
			}
			
			cste_mysqlexec(my_con,"update %s set schMode='%s',schWeek='%s',schHour='%s',schMinute='%s',recHour='%s' where %s='%s';",
							  TBL_ID_TONAME(MYSQL_APLIST_TABLE),schMode,schWeek,schHour,schMinute,recHour,MYSQL_APID_KEY_NAME,APID);
			
		}
		
	}

	MyClearField32(config_value,SYSTEM_CONFIG);
	MyClearField32(config_value,RADIO_CONFIG);
	MyClearField32(config_value,WLAN_CONFIG);

	i = 0;
	if(strlen(apid)>0)
	{
		while((getNthValueSafe(i++, apid, ',', APID, sizeof(APID)) != -1))
		{
			if(strlen(APID))
			{
				cste_mysqlexec(my_con,"update %s set %s=%d, %s=%s&%d where %s='%s';",TBL_ID_TONAME(MYSQL_APLIST_TABLE),MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,
									MSYQL_APSTATE_KEY_NAME,MSYQL_APSTATE_KEY_NAME,config_value,MYSQL_APID_KEY_NAME,APID);												
			}
		}
	}

	backupDb(my_con, SQLPATH_BAK, xProgress);
	cste_mysqlclose(my_con);

err:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setApIp(struct mosquitto *mosq, cJSON* data, char *tp)
{

	char cmd[4096],tmpbuf[128] = {0},*output;

	output=cJSON_Print(data);
	sprintf(cmd,"echo '%s' > /tmp/apipsetting",output);
	system(cmd);
	sprintf(tmpbuf,"killall -%d cste_heartbeat",SIG_SETAPIP);
	CsteSystem(tmpbuf,CSTE_PRINT_CMD);

	free(output);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}


int getApFwInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char query[1024] ={0};
	sqlite3 *my_con;
	cJSON *root =NULL;
	char *output =NULL;
	char *CSID = NULL;
	int iRet=0;

	CSID= websGetVar(data, T("csid"), T(""));

	root=cJSON_CreateArray();

	if(strlen(CSID))
	{

		iRet=cste_mysqlopen(&my_con,SQLPATH);
		if(iRet<0){
			goto err;
		}

		snprintf(query,sizeof(query),"select * from %s where %s='%s';",TBL_ID_TONAME(MYSQL_AP_UPGRADE),MYSQL_CSID_KEY_NAME,CSID);

		cste_mysqlgetarray(my_con, query, root);

		cste_mysqlclose(my_con);
	}
err:
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	
	return 0;

}

int getFwList(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char query[1024] ={0};
	sqlite3 *my_con;
	cJSON *root =NULL;
	char *output =NULL;
	int iRet=0;
	
	root=cJSON_CreateArray();

	iRet=cste_mysqlopen(&my_con,SQLPATH);
	if(iRet<0){
		goto err;
	}

	snprintf(query,sizeof(query),"select * from %s ;",TBL_ID_TONAME(MYSQL_AP_UPGRADE));
	cste_mysqlgetarray(my_con, query, root);
	cste_mysqlclose(my_con);

err:
	output=cJSON_Print(root);
	
	cJSON_Delete(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	
	return 0;
}

int uploadApFw(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	char buf[64]= {0};
	char cmd[256]= {0};
	char time_buf[3][8]={0};
	char csid[16];
	char svnnum[8];
	char builddate[24];
	char filepath[256];
	char old_file[256];
	
	long inLen=0;
	
	cJSON *root;
	int iRet = 0;
	sqlite3 *my_con;

	char *FileName = websGetVar(data, T("FullName"), T(""));
	char *ContentLength= websGetVar(data, T("ContentLength"), T("0"));

	sprintf(filepath,"/ACFirmware/%s",FileName);

	inLen= strtol(ContentLength, NULL, 10);

	root=cJSON_CreateObject();

	if(!d_exist("/web_cste/ACFirmware")){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}

	if(strlen(FileName)<10 || inLen < 1024*1024){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}
	//TOTOLINK_C8B810A_AP0155_AP0155_QCA9531_SPI_16M128M_V6.2c.847_B20180408_ALL.web
	getNthValueSafe(1,FileName,'_',csid,sizeof(csid));
	if(strlen(csid)<1){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}

	getNthValueSafe(7,FileName,'_',buf,sizeof(buf));
	if(strlen(buf)<4){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}
	getNthValueSafe(2,buf,'.',svnnum,sizeof(svnnum));
	if(strlen(svnnum)<1){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}

	getNthValueSafe(8,FileName,'_',builddate,sizeof(builddate));
	sscanf((builddate+1),"%4s",&time_buf[0]);
	sscanf((builddate+5),"%2s",&time_buf[1]);
	sscanf((builddate+7),"%2s",&time_buf[2]);
	sprintf(builddate,"%s,%s,%s",time_buf[0],time_buf[1],time_buf[2]);

	iRet=cste_mysqlopen(&my_con,SQLPATH);
	if(iRet<0){
		cJSON_AddStringToObject(root, "upgradeERR1","MM_fwupload_error");
		goto err;
	}

	if(cste_mysqlgetstr(my_con,old_file,"select filepath from AP_UPGRADE where csid='%s';",csid))
	{
		if(strcmp(old_file,filepath)){//remove old fw
			sprintf(cmd,"rm -f /web_cste%s",old_file);
			CsteSystem(cmd,CSTE_PRINT_CMD);
		}

		cste_mysqlexec(my_con,"update AP_UPGRADE set svnnum='%s',builddate='%s',filepath='%s' where csid='%s';",
			           svnnum,builddate,filepath,csid);
		
	}else
	{
		cste_mysqlexec(my_con,"insert into AP_UPGRADE (csid,svnnum,builddate,filepath) values('%s','%s','%s','%s');",
					  csid,svnnum,builddate,filepath);
	}

	sprintf(cmd,"cp /tmp/firmware.img /web_cste%s",filepath);
	CsteSystem(cmd,CSTE_PRINT_CMD);
	CsteSystem("rm -f /tmp/firmware.img",CSTE_PRINT_CMD);

	backupDb(my_con, SQLPATH_BAK, xProgress);

	cste_mysqlclose(my_con);

	cJSON_AddStringToObject(root, "upgradeStatus","1");
	output =cJSON_Print(root);

	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);

	return 0;

err:

	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);

	free(output);
	return 0;
}

int delApFWInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *CSID= websGetVar(data, T("csid"), T(""));
	sqlite3 *my_con;
	
	char filepath[MAX_MYSQL_VALUE_LEN] = {0};
	char cmd[MAX_MYSQL_QUERY_LEN] ={0};
	int iRet=0;

	if(strlen(CSID))
	{
		iRet=cste_mysqlopen(&my_con,SQLPATH);
		if(iRet<0){
			goto err;
		}
		
		if(cste_mysqlgetstr(my_con,filepath,"select %s from %s where %s='%s';",MSYQL_FILE_PATH_KEY_NAME,TBL_ID_TONAME(MYSQL_AP_UPGRADE),MYSQL_CSID_KEY_NAME,CSID))
		{
			snprintf(cmd,MAX_MYSQL_QUERY_LEN,"rm -f /web_cste%s",filepath);
			CsteSystem(cmd,CSTE_PRINT_CMD);
			cste_mysqlexec(my_con,"delete from %s where %s='%s';",TBL_ID_TONAME(MYSQL_AP_UPGRADE),MYSQL_CSID_KEY_NAME,CSID);
		}

		backupDb(my_con, SQLPATH_BAK, xProgress);
		cste_mysqlclose(my_con);
	}
err:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int setApUpgrade(struct mosquitto *mosq, cJSON* data, char *tp)
{
	sqlite3 *my_con;
	int i = 0, iRet=0, config_value =AP_CONFIG_OK_VALUE;
	char APID[8] ={0},csid[MYSQL_APKEY_LEN] = {0};
	int svnCur = 0,svnUp = 0;
	
	char *APID_ARR = websGetVar(data, T("id"), T("0"));
	
	MyClearField32(config_value,UPGRADE_COMMAND);

	iRet=cste_mysqlopen(&my_con,SQLPATH);
	if(iRet<0){
		goto err;
	}

	while((getNthValueSafe(i++, APID_ARR, ',', APID, sizeof(APID)) != -1))
	{
		cste_mysqlgetstr(my_con, csid, "select %s from %s where %s='%s';",
							MYSQL_CSID_KEY_NAME,TBL_ID_TONAME(MYSQL_APLIST_TABLE),MYSQL_APID_KEY_NAME, APID);
		
			cste_mysqlgetint(my_con,&svnCur, "select %s from %s where %s='%s';",
							MYSQL_SVNNUM_KEY_NAME,TBL_ID_TONAME(MYSQL_APLIST_TABLE),MYSQL_APID_KEY_NAME, APID);
			
			cste_mysqlgetint(my_con,&svnUp, "select %s from %s where %s='%s';",
							MYSQL_SVNNUM_KEY_NAME,TBL_ID_TONAME(MYSQL_AP_UPGRADE),MYSQL_CSID_KEY_NAME,csid);
		
			if(svnCur==svnUp || svnUp==0)
			{
				continue ;
			}
			cste_mysqlexec(my_con,"update %s set %s=%d, %s=%s&%d where %s='%s';",TBL_ID_TONAME(MYSQL_APLIST_TABLE),MSYQL_APSTATUS_KEY_NAME,STATUS_CONFIGING,
								MSYQL_APSTATE_KEY_NAME,MSYQL_APSTATE_KEY_NAME,config_value,MYSQL_APID_KEY_NAME,APID);
	}
	cste_mysqlclose(my_con);
err:

	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int AcRestore(struct mosquitto *mosq, cJSON* data, char *tp)
{
	system("echo 0 > /proc/udwrite 2>/dev/null");
	system("killall cste_heartbeat");
	system("rm -f /mnt/meac/*");
	system("rm -f /tmp/meac/*");

	int pid;        
    pid=fork();
    if(0==pid)
    {
        sleep(2);
        CsteSystem("reboot", CSTE_PRINT_CMD);
        exit(1);
    }

	websSetCfgResponse(mosq, tp, "60", "reserv");
	return 0;
}

int UploadSqlConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	cJSON *root;
	char *FileName = websGetVar(data, T("FileName"), T(""));
	char *ContentLength= websGetVar(data, T("ContentLength"), T(""));
	long inLen;
	char cmd[256] = {0};
	
	root=cJSON_CreateObject();
	inLen = strtol(ContentLength, NULL, 10) + 1;		
	if(inLen < 10){
		cJSON_AddStringToObject(root, "settingERR","MSG_config_error");
		goto err;;
	}

	system("echo 0 > /proc/udwrite 2>/dev/null");
	system("rm -f /mnt/meac/*");
	snprintf(cmd,256,"cp -f %s /mnt/meac/meac.sqlite3",FileName);
	system(cmd);
	
	cJSON_AddStringToObject(root, "settingERR","1");
	output =cJSON_Print(root);	
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	unlink(FileName);

	int pid;        
    pid=fork();
    if(0==pid)
    {
        sleep(3);
        CsteSystem("reboot", CSTE_PRINT_CMD);
        exit(1);
    }

	return 0;
	
err:
	unlink(FileName);
	output =cJSON_Print(root);	
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);

	return 0;
}

int status_mount()
{
	int iRet=0;
	FILE *fp = popen("cat /proc/mounts | grep usb", "r");
	char dir[13];

	while(EOF != fscanf(fp, "%*s %s %*s %*s %*s %*s\n", dir)){
		if (strstr(dir, "/usb/sd")!=NULL){
			iRet=1;
		}
	}
	pclose(fp);

	return iRet;
}

void getUsbState(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char *output;
    cJSON *root=cJSON_CreateObject();	
    int iRet=0;
	
	iRet=status_mount();
    if(iRet == 1){
		cJSON_AddStringToObject(root,"usbState","1");
    }else{
    	cJSON_AddStringToObject(root,"usbState","0");
    }

    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return ;
}

int getSaveSqlite3Topic(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output, csid[16]={0},modelName[32]={0},fileName[128]={0};
	char dateStr[16]={0},tmpCmd[128]={0};

	cJSON *root=cJSON_CreateObject();

	apmib_get(MIB_HARDWARE_MODEL,(void *)modelName);
	apmib_get(MIB_CSID,(void *)csid);

	getCmdStr("date  '+%Y%m%d'",dateStr,sizeof(dateStr));

	sprintf(fileName,"/Config-%s-%s.sqlite3", modelName,dateStr);

	if(f_exist("/mnt/meac/meac.sqlite3")){
		sprintf(tmpCmd,"cp -f /mnt/meac/meac.sqlite3 /web_cste%s",fileName);
	}else{
		sprintf(tmpCmd,"cp -f /tmp/meac/meac.sqlite3 /web_cste%s",fileName);
	}
	system(tmpCmd);

	cJSON_AddStringToObject(root,"Action",fileName);

	output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
	return 0;
}

int module_init()
{
	cste_hook_register("mysqltest",mysqltest);

	cste_hook_register("ScanAp",ScanAp);
	
	cste_hook_register("getGroupApList",   getGroupApList);
	cste_hook_register("getApCsidList",    getApCsidList);
	cste_hook_register("getApListByCsid",  getApListByCsid);
	cste_hook_register("getApStatusConfig",getApStatusConfig);

	cste_hook_register("setApName",        setApName);
	cste_hook_register("setApLedState",    setApLedState);
	cste_hook_register("setApReboot",      setApReboot);
	cste_hook_register("setApReset",       setApReset);
	cste_hook_register("setQuickSetting",  setQuickSetting);
	cste_hook_register("setApIp",setApIp);

	cste_hook_register("getApFwInfo",getApFwInfo);
	cste_hook_register("getFwList",getFwList);
	cste_hook_register("uploadApFw",uploadApFw);
	cste_hook_register("delApFWInfo",delApFWInfo);
	cste_hook_register("setApUpgrade",setApUpgrade);

	cste_hook_register("getSaveSqlite3Topic",getSaveSqlite3Topic);
	cste_hook_register("AcRestore",AcRestore);
	cste_hook_register("UploadSqlConfig",UploadSqlConfig);
	cste_hook_register("getUsbState",getUsbState);

	return 0;  
}

