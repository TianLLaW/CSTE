#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>

#include <cstelib.h>



#if defined(CONFIG_USER_PPTPD)
int setPptpdConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *Enabled = websGetVar(data, T("Enabled"),	T(""));
	char *startip = websGetVar(data, T("startip"),  T(""));
	char *endip = websGetVar(data, T("endip"),  T(""));
	char *localip = websGetVar(data, T("localip"),  T(""));
	char *wanpridns = websGetVar(data, T("wanpridns"),  T(""));
	char *wansecdns = websGetVar(data, T("wansecdns"),  T(""));
	char *servermtu = websGetVar(data, T("servermtu"),	T(""));
	char *servermru = websGetVar(data, T("servermru"),	T(""));
	char *mppeencrypt = websGetVar(data, T("mppeencrypt"),	T(""));

	if(atoi(Enabled) == 0){
		nvram_bufset(RT2860_NVRAM, "pptpdEnable", "0");
	}else
	{
		nvram_bufset(RT2860_NVRAM, "pptpdEnable", "1");
		nvram_bufset(RT2860_NVRAM, "pptpdStartip", startip);
		nvram_bufset(RT2860_NVRAM, "pptpdEndip", endip);
		nvram_bufset(RT2860_NVRAM, "pptpdLocalip",localip);
		nvram_bufset(RT2860_NVRAM, "pptpdPridns", wanpridns);
		nvram_bufset(RT2860_NVRAM, "pptpdSecdns", wansecdns);
		nvram_bufset(RT2860_NVRAM, "pptpdMtu", servermtu);
		nvram_bufset(RT2860_NVRAM, "pptpdMru", servermru);
		nvram_bufset(RT2860_NVRAM, "pptpdMppeEncrypt", mppeencrypt);
	}
		
	nvram_commit(RT2860_NVRAM);

	setNetworkLktos("initpptpd");
	
	websSetCfgResponse(mosq, tp, "1", "reserv");
	return 0;
}

int getPptpdConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	cJSON *root;
	root=cJSON_CreateObject();

	cJSON_AddStringToObject(root,"Enabled", nvram_bufget(RT2860_NVRAM, "pptpdEnable"));
	cJSON_AddStringToObject(root,"startip", nvram_bufget(RT2860_NVRAM, "pptpdStartip"));
	cJSON_AddStringToObject(root,"endip", nvram_bufget(RT2860_NVRAM, "pptpdEndip"));
	cJSON_AddStringToObject(root,"localip", nvram_bufget(RT2860_NVRAM, "pptpdLocalip"));
	cJSON_AddStringToObject(root,"wanpridns", nvram_bufget(RT2860_NVRAM, "pptpdPridns"));
	cJSON_AddStringToObject(root,"wansecdns", nvram_bufget(RT2860_NVRAM, "pptpdSecdns"));
	cJSON_AddStringToObject(root,"servermtu", nvram_bufget(RT2860_NVRAM, "pptpdMtu"));
	cJSON_AddStringToObject(root,"servermru", nvram_bufget(RT2860_NVRAM, "pptpdMru"));
	cJSON_AddStringToObject(root,"mppeencrypt", nvram_bufget(RT2860_NVRAM, "pptpdMppeEncrypt"));

	char *output =cJSON_Print(root);
	
	websGetCfgResponse(mosq,tp,output);
	
	cJSON_Delete(root);
	
	free(output);

	return 0;
}
#endif

#if defined(CONFIG_USER_L2TPD)
int setL2tpdConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *Enabled = websGetVar(data, T("Enabled"),	T(""));
	char *startip = websGetVar(data, T("startip"),	T(""));
	char *endip = websGetVar(data, T("endip"),	T(""));
	char *localip = websGetVar(data, T("localip"),	T(""));
	char *wanpridns = websGetVar(data, T("wanpridns"),	T(""));
	char *wansecdns = websGetVar(data, T("wansecdns"),	T(""));
	char *servermtu = websGetVar(data, T("servermtu"),	T(""));
	char *servermru = websGetVar(data, T("servermru"),	T(""));

	if(atoi(Enabled) == 0){
		nvram_bufset(RT2860_NVRAM, "l2tpdEnable", "0");
	}else
	{
		nvram_bufset(RT2860_NVRAM, "l2tpdEnable", "1");
		nvram_bufset(RT2860_NVRAM, "l2tpdStartip", startip);
		nvram_bufset(RT2860_NVRAM, "l2tpdEndip", endip);
		nvram_bufset(RT2860_NVRAM, "l2tpdLocalip",localip);
		nvram_bufset(RT2860_NVRAM, "l2tpdPridns", wanpridns);
		nvram_bufset(RT2860_NVRAM, "l2tpdSecdns", wansecdns);
		nvram_bufset(RT2860_NVRAM, "l2tpdMtu", servermtu);
		nvram_bufset(RT2860_NVRAM, "l2tpdMru", servermru);
	}
		
	nvram_commit(RT2860_NVRAM);

	setNetworkLktos("initl2tpd");
	
	websSetCfgResponse(mosq, tp, "1", "reserv");
	return 0;
}

int getL2tpdConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	cJSON *root;
	root=cJSON_CreateObject();

	cJSON_AddStringToObject(root,"Enabled", nvram_bufget(RT2860_NVRAM, "l2tpdEnable"));
	cJSON_AddStringToObject(root,"startip", nvram_bufget(RT2860_NVRAM, "l2tpdStartip"));
	cJSON_AddStringToObject(root,"endip", nvram_bufget(RT2860_NVRAM, "l2tpdEndip"));
	cJSON_AddStringToObject(root,"localip", nvram_bufget(RT2860_NVRAM, "l2tpdLocalip"));
	cJSON_AddStringToObject(root,"wanpridns", nvram_bufget(RT2860_NVRAM, "l2tpdPridns"));
	cJSON_AddStringToObject(root,"wansecdns", nvram_bufget(RT2860_NVRAM, "l2tpdSecdns"));
	cJSON_AddStringToObject(root,"servermtu", nvram_bufget(RT2860_NVRAM, "l2tpdMtu"));
	cJSON_AddStringToObject(root,"servermru", nvram_bufget(RT2860_NVRAM, "l2tpdMru"));

	char *output =cJSON_Print(root);
	
	websGetCfgResponse(mosq,tp,output);
	
	cJSON_Delete(root);
	
	free(output);

	return 0;
}
#endif

#if defined(CONFIG_USER_PPTPD)||defined(CONFIG_USER_L2TPD)
int getVpnUser(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL,*protocol=NULL;
	char index[8]={0},username[128]={0},password[128]={0},authenticate[63]={0},comment[64]={0},upbandwidth[64],downbandwidth[64],buf[256]={0};
	int num=0,i=0; 
	cJSON *item,*item_des,*root;
	
	const char *entries = (char *)nvram_bufget(RT2860_NVRAM, "ppp_users");

	if(strlen(entries)==0)
		num = 0;
	else	
		num = getRuleNums((char *)entries);

	root= cJSON_CreateArray();

	for(i=0;i<num;i++){
		
		getNthValueSafe(i, entries, ';', buf, sizeof(buf));
		
		item = cJSON_CreateObject();
		
		snprintf(index,8,"%d",i);
		
		cJSON_AddStringToObject(item, "idx", index);
		
		getNthValueSafe(0, buf, ',', username, sizeof(username));
		cJSON_AddStringToObject(item, "username", username);

		getNthValueSafe(1, buf, ',', password, sizeof(password));
		cJSON_AddStringToObject(item, "password", password);

		getNthValueSafe(2, buf, ',', authenticate, sizeof(authenticate));
		if(!strcmp(authenticate,"*"))
		protocol="0";
		else if(!strcmp(authenticate,"pppoe-server"))
		protocol="1";
		else if(!strcmp(authenticate,"pptp-server"))
		protocol="2";
		else if(!strcmp(authenticate,"l2tp-server"))
		protocol="3";
		else if(!strcmp(authenticate,"openvpn-server"))
		protocol="4";
		cJSON_AddStringToObject(item, "authenticate", protocol);

		getNthValueSafe(3, buf, ',', upbandwidth, sizeof(upbandwidth));
		cJSON_AddStringToObject(item, "upbandwidth", upbandwidth);

		getNthValueSafe(4, buf, ',', downbandwidth, sizeof(downbandwidth));
		cJSON_AddStringToObject(item, "downbandwidth", downbandwidth);
		
		getNthValueSafe(5, buf, ',', comment, sizeof(comment));
		cJSON_AddStringToObject(item, "comment", comment);

		cJSON_AddItemToArray(root,item);
	}
	
	item_des = cJSON_CreateObject();
	
	cJSON_AddStringToObject(item_des, "upband", "125000");

	cJSON_AddStringToObject(item_des, "downband", "125000");

    cJSON_AddItemToArray(root,item_des);
	
	output =cJSON_Print(root);
	
	websGetCfgResponse(mosq,tp,output);
	
	cJSON_Delete(root);
	
	free(output);
	
	return 0;

}

int setVpnUser(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int num=0;
	char *p=NULL,buf[128]={0},name[64]={0},pass[64]={0},descrip[64]={0},attest[64]={0},upwidth[64],downwidth[64],*protocol=NULL;
	char *username = websGetVar(data, T("username"),  T(""));
	char *password = websGetVar(data, T("password"),  T(""));
	char *authenticate = websGetVar(data, T("authenticate"),  T(""));
	char *upbandwidth = websGetVar(data, T("upbandwidth"),  T(""));
	char *downbandwidth = websGetVar(data, T("downbandwidth"),  T(""));
	char *comment = websGetVar(data, T("comment"),  T(""));

	char value[4096] ={0};
	
	if(!strcmp(authenticate,"0"))
		protocol="*";
	else if(!strcmp(authenticate,"1"))
		protocol="pppoe-server";
	else if(!strcmp(authenticate,"2"))
		protocol="pptp-server";
	else if(!strcmp(authenticate,"3"))
		protocol="l2tp-server";
	else if(!strcmp(authenticate,"4"))
		protocol="openvpn-server";

	const char *entries = (char *)nvram_bufget(RT2860_NVRAM, "ppp_users");

	if(strlen(entries)==0)
	{
		snprintf(value, sizeof(value), "%s,%s,%s,%s,%s,%s",  
			username, password, protocol, upbandwidth, downbandwidth, comment);
	}else	
	{

		snprintf(value, sizeof(value), "%s;%s,%s,%s,%s,%s,%s",entries,  
			username, password, protocol, upbandwidth, downbandwidth, comment);
		
	}

	nvram_bufset(RT2860_NVRAM, "ppp_users", value);
	
	nvram_commit(RT2860_NVRAM);

	setNetworkLktos("initpppuser");
	
	websSetCfgResponse(mosq, tp, "0", "reserv");

	return 0;
}

static int disconnec_vpn(char *username)
{	
	FILE *f_info;

	char info[256]={0},linkuser[64]={0},pid[8]={0};

	if ((f_info = fopen("/tmp/vpnd_connected", "r")) != NULL) {
		while (fgets(info, sizeof(info), f_info)){//遍历在线用户
			if(strlen(info) > 0){
				sscanf(info,"%*s %s %*s %s",pid,linkuser);
				if(strcmp(linkuser,username)== 0)
				{
					sprintf(info,"kill %s",pid);
					CsteSystem(info, CSTE_PRINT_CMD);
				}
			}
			memset(pid,0,sizeof(pid));
			memset(info,0,sizeof(info));
			memset(linkuser,0,sizeof(linkuser));
		}			
		fclose(f_info);
	}
	
	return 0;
}

int deleteVpnUser(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int index_num,user_num,i,j,k;
	char index[4];
	char username[64],buf[256]={0};
	char *delIndex = websGetVar(data, T("idx"), T(""));
	int *deleArray;
	char value[4096] ={0};
	char *new_value;
	index_num = getNums((char *)delIndex,',');
	
	const char *entries = (char *)nvram_bufget(RT2860_NVRAM, "ppp_users");
	
	if(strlen(entries)==0)
		user_num = 0;
	else	
		user_num = getRuleNums((char *)entries);
	
	if((!index_num)||(index_num > user_num))
	{
		websErrorResponse(mosq, tp,"delete vpn user error!\n");
    	return 0;
	}
	
	deleArray = (int *)malloc(user_num * sizeof(int));
	if(!deleArray)
	{
		websErrorResponse(mosq, tp,"delete vpn user error!\n");
		return 0;
	}		

	new_value = strdup(entries);
	if(!new_value){
		free(deleArray);
		websErrorResponse(mosq, tp,"delete vpn user error!\n");
		return 0;
	}

	for(i=0;i<index_num;i++)
	{
		getNthValueSafe(i, delIndex, ',', index, sizeof(index));
		printf("index is %s\n",index);
		if(atoi(index) < user_num)
		{
			deleArray[i] = atoi(index);
		}
	}
	
	for(j=0, k=0; j< user_num; j++)
	{
    	if(deleArray[k] == j)
    	{
    		k++;
    		getNthValueSafe(j, entries, ';', buf, sizeof(buf));
			getNthValueSafe(0, buf, ',', username, sizeof(username));
			disconnec_vpn(username);
    	}
	}
	
	deleteNthValueMulti(deleArray, i, new_value, ';');
	nvram_bufset(RT2860_NVRAM, "ppp_users", new_value);	
	nvram_commit(RT2860_NVRAM);
	free(deleArray);
	free(new_value);

	setNetworkLktos("initpppuser");
	
	websSetCfgResponse(mosq, tp, "0", "reserv");

	return 0;
}

int getUserInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *f;
	int num=0,i=0;
	char nod[128]={0},info[128]={0},value[64]={0},username[64]={0};
	char buf[4096] = {0};
	char authenticate[16]={0},ip[32]={0},device_ip[32]={0},name[64]={0},time[32]={0},comment[64]={0},pid[32]={0},interfac[32]={0};
	cJSON *root	= cJSON_CreateArray();

	const char *entries = (char *)nvram_bufget(RT2860_NVRAM, "ppp_users");

	if(strlen(entries)==0)
		num = 0;
	else	
		num = getRuleNums((char *)entries);

	if ((f = fopen("/tmp/pptpd_connected", "r")) != NULL) {
		while (fgets(info, sizeof(info), f)){
			if(strlen(info) > 0){
				cJSON *item	= cJSON_CreateObject();
				
				sscanf(info,"%s %s %s %s %s %s %s",authenticate,pid,interfac,ip,device_ip,name,time);
				cJSON_AddStringToObject(item,"ip",ip);
				cJSON_AddStringToObject(item,"pid",pid);
				cJSON_AddStringToObject(item,"name",name);
				cJSON_AddStringToObject(item,"time",time);
				cJSON_AddStringToObject(item,"device_ip",device_ip);
				cJSON_AddStringToObject(item,"authenticate",authenticate);

				if(num == 0)
				{
					cJSON_AddStringToObject(item,"comment","");
				}else
				{
					for(i=0;i<num;i++)
					{
						getNthValueSafe(i, entries, ';', buf, sizeof(buf));
						getNthValueSafe(0, buf, ',', username, sizeof(username));
						if(strcmp(username,name)==0)
						{
							getNthValueSafe(5, buf, ',', comment, sizeof(comment));
							cJSON_AddStringToObject(item,"comment",comment);	
						}else
						{
							continue;
						}
					}
				}
				
				cJSON_AddItemToArray(root,item);
			}
			
			memset(nod,0,sizeof(nod));
			memset(ip,0,sizeof(ip));
			memset(pid,0,sizeof(pid));
			memset(info,0,sizeof(info));
			memset(name,0,sizeof(name));
			memset(time,0,sizeof(time));
			memset(username,0,sizeof(username));
			memset(comment,0,sizeof(comment));
			memset(interfac,0,sizeof(interfac));
			memset(device_ip,0,sizeof(device_ip));
			memset(authenticate,0,sizeof(authenticate));
		}
		fclose(f);
	}
	
	char *output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}


int disconnectVPN(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *pid = websGetVar(data, T("pid"),  T(""));
	char cmd[64]={0};

	sprintf(cmd,"kill %s",pid);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	websSetCfgResponse(mosq, tp, "0", "reserv");
}


#endif

#if defined(SUPPORT_VPNSERVER)
int setPppConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char rule[1024];
	char *CurRules;
	
	char_t *user = websGetVar(data, T("vpn_user"), T(""));
	char_t *pwd = websGetVar(data, T("vpn_password"), T(""));
	char_t *ip = websGetVar(data, T("vpn_ip"), T(""));
	char_t *comment = websGetVar(data, T("comment"), T(""));

	//set rule
	if(( CurRules = (char *)nvram_bufget(RT2860_NVRAM, "VpnRules")) && strlen( CurRules) ) {
		snprintf(rule, sizeof(rule), "%s;%s,%s,%s,%s",	
		CurRules, user, pwd, ip, comment);
	}
	else{
		snprintf(rule, sizeof(rule), "%s,%s,%s,%s", user, pwd, ip, comment);
	}	
	nvram_bufset(RT2860_NVRAM, "VpnRules", rule);
	nvram_commit(RT2860_NVRAM);

END:
	setNetworkLktos("initvpn");
	websSetCfgResponse(mosq, tp, "1", "reserv");
	return 0;

}

int PppDelete(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i, j, rule_count;
	char_t *value;
	int *deleArray;
	cJSON *subObj, *root;

	char *new_rules;
	const char *rules = nvram_bufget(RT2860_NVRAM, "VpnRules");
	if(!rules || !strlen(rules) )
		goto END;
	
	rule_count = getRuleNums((char *)rules);
	if(!rule_count)
		goto END;

	deleArray = (int *)malloc(rule_count * sizeof(int));
	if(!deleArray)
		goto END;
		
	new_rules = strdup(rules);
	if(!new_rules){
		free(deleArray);
		goto END;
	}

	for(i=1,j=0;i<cJSON_GetArraySize(data);i++){
		subObj = cJSON_GetArrayItem(data,i);
		value=websGetVar(subObj, T("delRuleId"), T(""));
		deleArray[j++] = atoi(value);
	}

	deleteNthValueMulti(deleArray, j, new_rules, ';');

	nvram_bufset(RT2860_NVRAM, "VpnRules", new_rules); 	
	nvram_commit(RT2860_NVRAM);

	free(deleArray);
	free(new_rules);
	
	setNetworkLktos("initvpn");
END:
	websSetCfgResponse(mosq, tp, "1", "reserv");
	return 0;
}

int getPppRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i = 0;
	char rec[128],*output;
	cJSON *RulesArray, *root;
	
	char *rules = (char *)nvram_bufget(RT2860_NVRAM, "VpnRules");
	
	char u[40], p[40], ip[40], cm[40];
	
	RulesArray=cJSON_CreateArray();
	while(getNthValueSafe(i++, rules, ';', rec, sizeof(rec)) != -1 )
	{
		if((getNthValueSafe(0, rec, ',', u, sizeof(u)) == -1)){
			continue;
		}

		if((getNthValueSafe(1, rec, ',', p, sizeof(p)) == -1)){
			continue;
		}
	
		if((getNthValueSafe(2, rec, ',', ip, sizeof(ip)) == -1)){
			continue;
		}

		if((getNthValueSafe(3, rec, ',', cm, sizeof(cm)) == -1)){
			continue;
		}

		root=cJSON_CreateObject();
		cJSON_AddItemToArray(RulesArray,root);
		cJSON_AddStringToObject(root, "vpn_user",u);
		cJSON_AddStringToObject(root, "vpn_password",p);
		cJSON_AddStringToObject(root, "vpn_ip",ip);
		cJSON_AddStringToObject(root, "comment",cm);

	}
	
	output=cJSON_Print(RulesArray);
    websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(RulesArray);
	free(output);
	return 0;
	
}
#endif

#if defined(CONFIG_USER_SHADOWSOCKS)
int setssServer(struct mosquitto *mosq, cJSON* data, char *tp)
{

	char *enable ,*address ,*port, *timeout, *password, *encry;
	char cmd[128] = {0};
	
	enable  = websGetVar(data, T("enable"), T("0"));
	address = websGetVar(data, T("server"), T("0.0.0.0"));
	port = websGetVar(data, T("serverPort"), T("8338"));
	timeout = websGetVar(data, T("timeout"), T("120"));
	password = websGetVar(data, T("password"), T("m"));
	encry = websGetVar(data, T("encryptMethod"), T("rc4-md5"));

    nvram_bufset(RT2860_NVRAM, "SSServerEnable", enable);
	nvram_bufset(RT2860_NVRAM, "SSServerAddress", address);
	nvram_bufset(RT2860_NVRAM, "SSServerPort", port);
	nvram_bufset(RT2860_NVRAM, "SSServerPassword", password);
	nvram_bufset(RT2860_NVRAM, "SSServerEncry", encry);
	nvram_bufset(RT2860_NVRAM, "SSServerTimeout", timeout);
	
	nvram_commit(RT2860_NVRAM);
	
	setFWLktos("ssserver");
	if(atoi(enable) ==1)
	{
		CsteSystem("/sbin/ssserver.sh start", CSTE_PRINT_CMD);

	}else{
		CsteSystem("/sbin/ssserver.sh stop", CSTE_PRINT_CMD);
	}
	
    websSetCfgResponse(mosq, tp, "0", "reserv");
}

int getssServer(struct mosquitto *mosq, cJSON* data, char *tp)
{
    cJSON *root;

	char *enable ,*address ,*port, *password, *encry, *timeout, *output;;
	char* tmpBuf[128]={0};

	root=cJSON_CreateObject();
	enable = (char *)nvram_bufget(RT2860_NVRAM, "SSServerEnable");
	address = (char *)nvram_bufget(RT2860_NVRAM, "SSServerAddress");
	port = (char *)nvram_bufget(RT2860_NVRAM, "SSServerPort");
	password = (char *)nvram_bufget(RT2860_NVRAM, "SSServerPassword");
	encry = (char *)nvram_bufget(RT2860_NVRAM, "SSServerEncry");
	timeout = (char *)nvram_bufget(RT2860_NVRAM, "SSServerTimeout");
	get_wan_connect_status(tmpBuf);
	if(!strcmp(tmpBuf, "MM_connected")){
		memset(tmpBuf,0,sizeof(tmpBuf));
		getWanIp(tmpBuf);
		cJSON_AddStringToObject(root,"server",tmpBuf);
	}else if(!strcmp(tmpBuf, "MM_disconnected"))
		cJSON_AddStringToObject(root,"server","0.0.0.0");

	
	cJSON_AddStringToObject(root,"enable",enable);
//	cJSON_AddStringToObject(root,"server",address);
	cJSON_AddStringToObject(root,"serverPort",port);
	cJSON_AddStringToObject(root,"password",password);
	cJSON_AddStringToObject(root,"encryptMethod",encry);
	cJSON_AddStringToObject(root,"timeout",timeout);

    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);

    cJSON_Delete(root);
	free(output);

    return 0;
}
#endif


#if defined(CONFIG_USER_OPENVPND)

/**
* 获取OpenVPN服务器配置
* @Author   Amy       <amy@carystudio.com>
* @DateTime 2018-04-27
* @property    {String}   Enabled           状态：1 启用，0 禁用
* @property    {String}   port             服务器端口
* @property    {String}   subnet           VPN网段
* @property    {String}   mask             网段掩码
* @property    {String}   proto            隧道协议
* @property    {String}   dev_type         隧道类型
* @property    {String}   cipher           加密算法
* @property    {String}   comp_lzo         LZO压缩，值：1：开启，0：关闭
* @property    {String}   tun_mtu          MTU
* @property    {String}   ca               CA证书
* @property    {String}   cert             服务器证书
* @property    {String}   key              服务器私钥
* @property    {String}   push_route       推送路由
* @property    {String}   extra_config     附加配置
* @property {String}
* @return   {object}
* @example
* request:
* {
*       "topicurl":"getOpenVpnConfig"
* }
* response:
* {
*       "Enabled": 1, 
*       "port": 1194, 
*       "subnet": "10.7.7.0", 
*       "mask": "255.255.255.0", 
*       "proto": "udp",
*       "dev_type": "tun",
*       "cipher": "BF-CBC", 
*       "comp_lzo": 1, 
*       "tun_mtu": 1400, 
*       "ca": "-----BEGIN CERTIFICATE-----\nMIIDQTCCAimgAwIBAgIJAMVd\/timD6TjMA0GCSqGSIb3DQEBCwUAMDcxCzAJBgNV\nBAYTAkNOMQ4wDAYDVQQKDAVpS3VhaTEYMBYGA1UEAwwPaUt1YWkgRGV2aWNlIENB\nMB4XDTE4MDQwMjA5MDU0NFoXDTI4MDMzMDA5MDU0NFowNzELMAkGA1UEBhMCQ04x\nDjAMBgNVBAoMBWlLdWFpMRgwFgYDVQQDDA9pS3VhaSBEZXZpY2UgQ0EwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuZR38cfc6F+5rnYLNDX813NGytSR1\nHko8zb3S20zU9S0YY1FGQaDVz5qtq9PPVPp9327jwCOEnxsFx2O9dBI9nRPmMvMK\n2Zf0K27gh2UlHWs0A5DLelhcXSl0dg64wAvVRqIlySH9peZ\/XnGjqBiKxhswoDWq\nrmGRCuIam6icrLhGDPUO2zLtEyYK\/\/8d+t86NE61\/ykthP4YY1OggZywGEkOUdwL\nSNknlPavsW1yUGaw90iFqqkL9Wqvd1cs8FMEdyquveztqqcVOpxClD4JzJrR46bm\ngoXSoX+OFSs79xJUpQgggHDlvrnNOUQfWPwoDIDsN7\/tJv62cQ2ohyHtAgMBAAGj\nUDBOMB0GA1UdDgQWBBTr\/Cp6Cs8dBtgMMqR2Vvkv7ynf3TAfBgNVHSMEGDAWgBTr\n\/Cp6Cs8dBtgMMqR2Vvkv7ynf3TAMBgNVHRMEBTADAQH\/MA0GCSqGSIb3DQEBCwUA\nA4IBAQBiNXBP0OOhVYSTiL2shcJStGb3yGfzLU6QpHnlceZz1fCBJWbuSyA7Tr+M\nkSVJ3YgRKVH0d24nVR8XuDS4N8Lb+Vd0LYg8IqW6JjmUfzkAHi9FHh1ofzyfgVw2\nG2JpZF079tr1ZXGjbs+2ztKJ+6ty1XpM1I2\/Eu0CXakvGqanDKl9cxdzMCd6hShd\nTeTeNwaRqtqIRYOXUwm9KOQgYw3i2B0tYTP3fHuHCDe5+a5OZMLE50hf4WKFJJMm\nJoZv2bn7tvO\/lAUbSVJXgj5Vyq88tm1dPU5nZ201NHF4YQxtYyoIYWMjgfTDY8kB\nJP+NbvbGsvlacYe5J1n6SGYzaT8y\n-----END CERTIFICATE-----", 
*       "cert": "-----BEGIN CERTIFICATE-----\nMIIC6jCCAdICBFrB8mgwDQYJKoZIhvcNAQELBQAwNzELMAkGA1UEBhMCQ04xDjAM\nBgNVBAoMBWlLdWFpMRgwFgYDVQQDDA9pS3VhaSBEZXZpY2UgQ0EwHhcNMTgwNDAy\nMDkwNTQ0WhcNMjgwMzMwMDkwNTQ0WjA8MQswCQYDVQQGEwJDTjEOMAwGA1UECgwF\naUt1YWkxHTAbBgNVBAMMFGlLdWFpIE9wZW5WUE4gU2VydmVyMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEArmUd\/HH3Ohfua52CzQ1\/NdzRsrUkdR5KPM29\n0ttM1PUtGGNRRkGg1c+aravTz1T6fd9u48AjhJ8bBcdjvXQSPZ0T5jLzCtmX9Ctu\n4IdlJR1rNAOQy3pYXF0pdHYOuMAL1UaiJckh\/aXmf15xo6gYisYbMKA1qq5hkQri\nGpuonKy4Rgz1Dtsy7RMmCv\/\/HfrfOjROtf8pLYT+GGNToIGcsBhJDlHcC0jZJ5T2\nr7FtclBmsPdIhaqpC\/Vqr3dXLPBTBHcqrr3s7aqnFTqcQpQ+Ccya0eOm5oKF0qF\/\njhUrO\/cSVKUIIIBw5b65zTlEH1j8KAyA7De\/7Sb+tnENqIch7QIDAQABMA0GCSqG\nSIb3DQEBCwUAA4IBAQAmd7kWAbiefAfy01z484prNpwjmkvM0Qk6N9qz6Ux3LDck\ngUHvDut+xs0hhpoIlHNTail5o8Dwo6Ht2dInE55Q4qqj+f65SwBJ04pjPshZ11ki\nYsbp1axDkLgudE0pmtGnc0tJ5i8Bk5kTxokIwcQO1PTtAlE6hRzxPtX8mW+84FAt\n69naHwpHsKcdxOkQB7mk+2ImI23N6\/EGbBX1D60Wka7utbPbH\/rPMg1dSsEg3Ecb\nAOyO65FxH+0T8ynUONhMmnFsVx8qoXgkcBpe\/jx6ki\/CyPVGaWhdJhueEfZ0Q51b\nOEC64l0V4kPDFpSIl8dITIhVrff+eN0z\/gNvveeM\n-----END CERTIFICATE-----", 
*       "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEArmUd\/HH3Ohfua52CzQ1\/NdzRsrUkdR5KPM290ttM1PUtGGNR\nRkGg1c+aravTz1T6fd9u48AjhJ8bBcdjvXQSPZ0T5jLzCtmX9Ctu4IdlJR1rNAOQ\ny3pYXF0pdHYOuMAL1UaiJckh\/aXmf15xo6gYisYbMKA1qq5hkQriGpuonKy4Rgz1\nDtsy7RMmCv\/\/HfrfOjROtf8pLYT+GGNToIGcsBhJDlHcC0jZJ5T2r7FtclBmsPdI\nhaqpC\/Vqr3dXLPBTBHcqrr3s7aqnFTqcQpQ+Ccya0eOm5oKF0qF\/jhUrO\/cSVKUI\nIIBw5b65zTlEH1j8KAyA7De\/7Sb+tnENqIch7QIDAQABAoIBABdkmvQc+XPCeAnZ\ndA07bT\/1Ye+d2skXChBD7N2W6yR5ytXFpMZO0Vs84NvA+8WI+Zze1soYIOuOSBqr\nV1a3dibrphqv5Ogkrfxjwxi9MLUc0B+HBuo0fBvPp1rm5yyjHjM6qU92Pmf+0\/9r\n1MSGLNyYnFcWdnxxrca99fxpuuFhFO\/abCIgxG2XJwnlOIFGzK8tS5\/NH+YwzClN\nUmY+1HQVuSFfUHsslwzIb3dMBXbo4Atvy\/ckRJyWY+KHB\/I8kQNWn8TD\/vsL6aPG\n2vFEpVEiPJjjZsKbJj3HqmN9hoW7gPlbrtk5JMwlqGRZ0g39m9zkeoJNe+WprxRE\nbfmXSAUCgYEA5EcsdqUj8g5bRuXj1rruO7WipWOaIbKiUmD0eFm8\/W1dlPydJOTZ\nydKJN8YZNtU45YIgDhsvjZaBhUUMeoobr37q8Kn1I9u+\/wXMkFjco3DZjew1+EBw\n9\/B2sYYU4ra4sgt6+sdlskuRjWu0habmnBySMp0OYvu0VFrZoZdHGcMCgYEAw5LM\nsS70Axg29xStqYXPg\/sXPmq\/MhMMxN+41PDTgvU0c2Oq72WnHFaasSVsZMWeMGwW\nDxYNnuJ7BFgh0DkMoW2BL9CqRjrAN7FMIQ0Ndroo9erVNZCNDz1YyA6VuvUQ\/EoT\ntea\/a+QZw2aM210cvEjarwaBcoRup4FgFfT3ao8CgYAE9cbxjQUK7WTuVXBt6gHj\nKj8ueMuQj+EXCSRGuSxyFT5DTnnbo11YFUsF+zfxCREDa6BmrhCKcwq9apKq1vVj\nCs7wC8FX1h6ATA\/10vh4VKtlegxyKHRL7t2lXdR2WKIKvFUfvdVn2lx\/RifV\/5pj\nKfvDPcZiQDXa3157NF5HIQKBgDxGM\/uvgtipT9daciM68De23PUJpR9jq53JbYeD\nKUzFEYM2hmn9pEEhl89cv0lXdmdqCGph25TKLCuslc88pd3ih9warT+zv6XqaJIP\nGcUrnpAb7dXyVOcLex89D3xtJuz6T5TSJtCznhUQt\/yrd723nl4u3RpUIl5RizF5\nK\/+VAoGAPFO4Kr1X7bcY1zIPMtWnugI4luHD5HWHB4x+4iwT12ny5QvyhzBbFmeE\nuNlvPdqjoUchFkBZGcQ\/mzZ5Q2wwAuIlI0SvBFuO6TCyX02MyfSExWi3BCzisUKx\n0cL2q0+xiDu\/JhmBDbX2OSotfq9FCWdz8eVBD422M1PEgyZGe5w=\n-----END RSA PRIVATE KEY-----", 
*       "push_route": "10.7.0.0\/16",
*       "extra_config": "mtu-disc no"
* }
*/

int getOpenVpnConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output=NULL;
	cJSON *root;
	FILE *fp;
	char buf[2048]={0};
	char cert[4096]={0};//server cert need big buffer

	root=cJSON_CreateObject();

	cJSON_AddStringToObject(root, "Enabled", nvram_bufget(RT2860_NVRAM, "openvpnEnabled"));
	cJSON_AddStringToObject(root, "port", nvram_bufget(RT2860_NVRAM, "openvpnPort"));
	cJSON_AddStringToObject(root, "subnet", nvram_bufget(RT2860_NVRAM, "openvpnSubnet"));
	cJSON_AddStringToObject(root, "mask", nvram_bufget(RT2860_NVRAM, "openvpnMask"));
	cJSON_AddStringToObject(root, "proto", nvram_bufget(RT2860_NVRAM, "openvpnProto"));
	cJSON_AddStringToObject(root, "dev_type", nvram_bufget(RT2860_NVRAM, "openvpnDevType"));
	cJSON_AddStringToObject(root, "cipher", nvram_bufget(RT2860_NVRAM, "openvpnCipher"));
	cJSON_AddStringToObject(root, "comp_lzo", nvram_bufget(RT2860_NVRAM, "openvpnCompLzo"));
	cJSON_AddStringToObject(root, "tun_mtu", nvram_bufget(RT2860_NVRAM, "openvpnTunMtu"));
#if 0	
	cJSON_AddStringToObject(root, "ca", nvram_bufget(RT2860_NVRAM, "openvpnCa"));
	cJSON_AddStringToObject(root, "cert", nvram_bufget(RT2860_NVRAM, "openvpnCert"));
	cJSON_AddStringToObject(root, "key", nvram_bufget(RT2860_NVRAM, "openvpnKey"));

	cJSON_AddStringToObject(root, "push_route", nvram_bufget(RT2860_NVRAM, "openvpnPushRoute"));
	cJSON_AddStringToObject(root, "extra_config", nvram_bufget(RT2860_NVRAM, "openvpnExtraConfig"));
#else
	memset(buf, 0, 2048);
	if ((fp = fopen("/etc_ro/easy-rsa/keys/ca.crt", "r")) != NULL) 
	{
		fread(buf, 1, 2048, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "ca", buf);
	
	memset(buf, 0, 2048);
	if ((fp = fopen("/etc_ro/easy-rsa/keys/dh1024.pem", "r")) != NULL) 
	{
		fread(buf, 1, 2048, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "dh", buf);
	
	memset(cert, 0, 4096);
	if ((fp = fopen("/etc_ro/easy-rsa/keys/server.crt", "r")) != NULL) 
	{
		fread(cert, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "cert", cert);
	
	memset(buf, 0, 2048);
	if ((fp = fopen("/etc_ro/easy-rsa/keys/server.key", "r")) != NULL) 
	{
		fread(buf, 1, 2048, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "key", buf);
	
	memset(buf, 0, 2048);
	if ((fp = fopen("/etc_ro/easy-rsa/keys/extra.conf", "r")) != NULL) 
	{
		fread(buf, 1, 2048, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "extra_config", buf);
#endif

	output =cJSON_Print(root);
	
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);

	return 0;
}

/**
* 设置OpenVPN服务器
* @Author   Amy       <amy@carystudio.com>
* @DateTime 2018-04-27
* @param    {String}   Enabled           状态：1 启用，0 禁用
* @param    {String}   port             服务器端口
* @param    {String}   subnet           VPN网段
* @param    {String}   mask             网段掩码
* @param    {String}   proto            隧道协议
* @param    {String}   dev_type         隧道类型
* @param    {String}   cipher           加密算法
* @param    {String}   comp_lzo         LZO压缩，值：1：开启，0：关闭
* @param    {String}   tun_mtu          MTU
* @param    {String}   ca               CA证书
* @param    {String}   cert             服务器证书
* @param    {String}   key              服务器私钥
* @param    {String}   push_route       推送路由
* @param    {String}   extra_config     附加配置
* @return   {object}
* @property {String} success     响应状态：true：响应成功，false：响应失败
* @property {String} error       错误
* @property {String} lan_ip      局域网IP
* @property {String} wtime       等待时间
* @property {String} reserv      返回页面（参数未知）
* @example
* request:
* {
*      "topicurl":"setOpenVpnConfig",
*       "Enabled": 1, 
*       "port": 1194, 
*       "subnet": "10.7.7.0", 
*       "mask": "255.255.255.0", 
*       "proto": "udp",
*       "dev_type": "tun",
*       "cipher": "BF-CBC", 
*       "comp_lzo": 1, 
*       "tun_mtu": 1400, 
*       "ca": "-----BEGIN CERTIFICATE-----\nMIIDQTCCAimgAwIBAgIJAMVd\/timD6TjMA0GCSqGSIb3DQEBCwUAMDcxCzAJBgNV\nBAYTAkNOMQ4wDAYDVQQKDAVpS3VhaTEYMBYGA1UEAwwPaUt1YWkgRGV2aWNlIENB\nMB4XDTE4MDQwMjA5MDU0NFoXDTI4MDMzMDA5MDU0NFowNzELMAkGA1UEBhMCQ04x\nDjAMBgNVBAoMBWlLdWFpMRgwFgYDVQQDDA9pS3VhaSBEZXZpY2UgQ0EwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuZR38cfc6F+5rnYLNDX813NGytSR1\nHko8zb3S20zU9S0YY1FGQaDVz5qtq9PPVPp9327jwCOEnxsFx2O9dBI9nRPmMvMK\n2Zf0K27gh2UlHWs0A5DLelhcXSl0dg64wAvVRqIlySH9peZ\/XnGjqBiKxhswoDWq\nrmGRCuIam6icrLhGDPUO2zLtEyYK\/\/8d+t86NE61\/ykthP4YY1OggZywGEkOUdwL\nSNknlPavsW1yUGaw90iFqqkL9Wqvd1cs8FMEdyquveztqqcVOpxClD4JzJrR46bm\ngoXSoX+OFSs79xJUpQgggHDlvrnNOUQfWPwoDIDsN7\/tJv62cQ2ohyHtAgMBAAGj\nUDBOMB0GA1UdDgQWBBTr\/Cp6Cs8dBtgMMqR2Vvkv7ynf3TAfBgNVHSMEGDAWgBTr\n\/Cp6Cs8dBtgMMqR2Vvkv7ynf3TAMBgNVHRMEBTADAQH\/MA0GCSqGSIb3DQEBCwUA\nA4IBAQBiNXBP0OOhVYSTiL2shcJStGb3yGfzLU6QpHnlceZz1fCBJWbuSyA7Tr+M\nkSVJ3YgRKVH0d24nVR8XuDS4N8Lb+Vd0LYg8IqW6JjmUfzkAHi9FHh1ofzyfgVw2\nG2JpZF079tr1ZXGjbs+2ztKJ+6ty1XpM1I2\/Eu0CXakvGqanDKl9cxdzMCd6hShd\nTeTeNwaRqtqIRYOXUwm9KOQgYw3i2B0tYTP3fHuHCDe5+a5OZMLE50hf4WKFJJMm\nJoZv2bn7tvO\/lAUbSVJXgj5Vyq88tm1dPU5nZ201NHF4YQxtYyoIYWMjgfTDY8kB\nJP+NbvbGsvlacYe5J1n6SGYzaT8y\n-----END CERTIFICATE-----", 
*       "cert": "-----BEGIN CERTIFICATE-----\nMIIC6jCCAdICBFrB8mgwDQYJKoZIhvcNAQELBQAwNzELMAkGA1UEBhMCQ04xDjAM\nBgNVBAoMBWlLdWFpMRgwFgYDVQQDDA9pS3VhaSBEZXZpY2UgQ0EwHhcNMTgwNDAy\nMDkwNTQ0WhcNMjgwMzMwMDkwNTQ0WjA8MQswCQYDVQQGEwJDTjEOMAwGA1UECgwF\naUt1YWkxHTAbBgNVBAMMFGlLdWFpIE9wZW5WUE4gU2VydmVyMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEArmUd\/HH3Ohfua52CzQ1\/NdzRsrUkdR5KPM29\n0ttM1PUtGGNRRkGg1c+aravTz1T6fd9u48AjhJ8bBcdjvXQSPZ0T5jLzCtmX9Ctu\n4IdlJR1rNAOQy3pYXF0pdHYOuMAL1UaiJckh\/aXmf15xo6gYisYbMKA1qq5hkQri\nGpuonKy4Rgz1Dtsy7RMmCv\/\/HfrfOjROtf8pLYT+GGNToIGcsBhJDlHcC0jZJ5T2\nr7FtclBmsPdIhaqpC\/Vqr3dXLPBTBHcqrr3s7aqnFTqcQpQ+Ccya0eOm5oKF0qF\/\njhUrO\/cSVKUIIIBw5b65zTlEH1j8KAyA7De\/7Sb+tnENqIch7QIDAQABMA0GCSqG\nSIb3DQEBCwUAA4IBAQAmd7kWAbiefAfy01z484prNpwjmkvM0Qk6N9qz6Ux3LDck\ngUHvDut+xs0hhpoIlHNTail5o8Dwo6Ht2dInE55Q4qqj+f65SwBJ04pjPshZ11ki\nYsbp1axDkLgudE0pmtGnc0tJ5i8Bk5kTxokIwcQO1PTtAlE6hRzxPtX8mW+84FAt\n69naHwpHsKcdxOkQB7mk+2ImI23N6\/EGbBX1D60Wka7utbPbH\/rPMg1dSsEg3Ecb\nAOyO65FxH+0T8ynUONhMmnFsVx8qoXgkcBpe\/jx6ki\/CyPVGaWhdJhueEfZ0Q51b\nOEC64l0V4kPDFpSIl8dITIhVrff+eN0z\/gNvveeM\n-----END CERTIFICATE-----", 
*       "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEArmUd\/HH3Ohfua52CzQ1\/NdzRsrUkdR5KPM290ttM1PUtGGNR\nRkGg1c+aravTz1T6fd9u48AjhJ8bBcdjvXQSPZ0T5jLzCtmX9Ctu4IdlJR1rNAOQ\ny3pYXF0pdHYOuMAL1UaiJckh\/aXmf15xo6gYisYbMKA1qq5hkQriGpuonKy4Rgz1\nDtsy7RMmCv\/\/HfrfOjROtf8pLYT+GGNToIGcsBhJDlHcC0jZJ5T2r7FtclBmsPdI\nhaqpC\/Vqr3dXLPBTBHcqrr3s7aqnFTqcQpQ+Ccya0eOm5oKF0qF\/jhUrO\/cSVKUI\nIIBw5b65zTlEH1j8KAyA7De\/7Sb+tnENqIch7QIDAQABAoIBABdkmvQc+XPCeAnZ\ndA07bT\/1Ye+d2skXChBD7N2W6yR5ytXFpMZO0Vs84NvA+8WI+Zze1soYIOuOSBqr\nV1a3dibrphqv5Ogkrfxjwxi9MLUc0B+HBuo0fBvPp1rm5yyjHjM6qU92Pmf+0\/9r\n1MSGLNyYnFcWdnxxrca99fxpuuFhFO\/abCIgxG2XJwnlOIFGzK8tS5\/NH+YwzClN\nUmY+1HQVuSFfUHsslwzIb3dMBXbo4Atvy\/ckRJyWY+KHB\/I8kQNWn8TD\/vsL6aPG\n2vFEpVEiPJjjZsKbJj3HqmN9hoW7gPlbrtk5JMwlqGRZ0g39m9zkeoJNe+WprxRE\nbfmXSAUCgYEA5EcsdqUj8g5bRuXj1rruO7WipWOaIbKiUmD0eFm8\/W1dlPydJOTZ\nydKJN8YZNtU45YIgDhsvjZaBhUUMeoobr37q8Kn1I9u+\/wXMkFjco3DZjew1+EBw\n9\/B2sYYU4ra4sgt6+sdlskuRjWu0habmnBySMp0OYvu0VFrZoZdHGcMCgYEAw5LM\nsS70Axg29xStqYXPg\/sXPmq\/MhMMxN+41PDTgvU0c2Oq72WnHFaasSVsZMWeMGwW\nDxYNnuJ7BFgh0DkMoW2BL9CqRjrAN7FMIQ0Ndroo9erVNZCNDz1YyA6VuvUQ\/EoT\ntea\/a+QZw2aM210cvEjarwaBcoRup4FgFfT3ao8CgYAE9cbxjQUK7WTuVXBt6gHj\nKj8ueMuQj+EXCSRGuSxyFT5DTnnbo11YFUsF+zfxCREDa6BmrhCKcwq9apKq1vVj\nCs7wC8FX1h6ATA\/10vh4VKtlegxyKHRL7t2lXdR2WKIKvFUfvdVn2lx\/RifV\/5pj\nKfvDPcZiQDXa3157NF5HIQKBgDxGM\/uvgtipT9daciM68De23PUJpR9jq53JbYeD\nKUzFEYM2hmn9pEEhl89cv0lXdmdqCGph25TKLCuslc88pd3ih9warT+zv6XqaJIP\nGcUrnpAb7dXyVOcLex89D3xtJuz6T5TSJtCznhUQt\/yrd723nl4u3RpUIl5RizF5\nK\/+VAoGAPFO4Kr1X7bcY1zIPMtWnugI4luHD5HWHB4x+4iwT12ny5QvyhzBbFmeE\nuNlvPdqjoUchFkBZGcQ\/mzZ5Q2wwAuIlI0SvBFuO6TCyX02MyfSExWi3BCzisUKx\n0cL2q0+xiDu\/JhmBDbX2OSotfq9FCWdz8eVBD422M1PEgyZGe5w=\n-----END RSA PRIVATE KEY-----", 
*       "push_route": "10.7.0.0\/16",
*       "extra_config": "mtu-disc no"
* }
* response:
* {
*   "success": true,
*   "error":   null,
*   "lan_ip":  "192.168.0.5",
*   "wtime":   0,
*   "reserv":  "reserv"
* }
*/


int setOpenVpnConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *Enabled = websGetVar(data, T("Enabled"),T(""));
	char *port = websGetVar(data, T("port"), T(""));
	char *subnet = websGetVar(data, T("subnet"), T(""));
	char *mask = websGetVar(data, T("mask"), T(""));
	char *proto = websGetVar(data, T("proto"), T(""));
	char *dev_type = websGetVar(data, T("dev_type"), T(""));
	char *cipher = websGetVar(data, T("cipher"),T(""));
	char *comp_lzo = websGetVar(data, T("comp_lzo"),T(""));
	char *tun_mtu = websGetVar(data, T("tun_mtu"),T(""));
	char *ca = websGetVar(data, T("ca"),T(""));
	char *dh = websGetVar(data, T("dh"),T(""));
	char *cert = websGetVar(data, T("cert"), T(""));
	char *key = websGetVar(data, T("key"),T(""));
	char *push_route = websGetVar(data, T("push_route"),T(""));
	char *extra_config = websGetVar(data, T("extra_config"),T(""));
	FILE *fp;

	if(atoi(Enabled) == 0)
	{
		nvram_bufset(RT2860_NVRAM, "openvpnEnabled", "0");
	}
	else
	{
		nvram_bufset(RT2860_NVRAM, "openvpnEnabled",Enabled);
		nvram_bufset(RT2860_NVRAM, "openvpnPort", port);
		nvram_bufset(RT2860_NVRAM, "openvpnSubnet", subnet);
		nvram_bufset(RT2860_NVRAM, "openvpnMask",mask);
		nvram_bufset(RT2860_NVRAM, "openvpnProto", proto);
		nvram_bufset(RT2860_NVRAM, "openvpnDevType", dev_type);
		nvram_bufset(RT2860_NVRAM, "openvpnCipher", cipher);
		nvram_bufset(RT2860_NVRAM, "openvpnCompLzo", comp_lzo);
		nvram_bufset(RT2860_NVRAM, "openvpnTunMtu", tun_mtu);
	#if 0	
		nvram_bufset(RT2860_NVRAM, "openvpnCa", ca);
		nvram_bufset(RT2860_NVRAM, "openvpnCert", cert);
		nvram_bufset(RT2860_NVRAM, "openvpnKey", key);
		
		nvram_bufset(RT2860_NVRAM, "openvpnPushRoute", push_route);
		nvram_bufset(RT2860_NVRAM, "openvpnExtraConfig", extra_config);
	#else
		system("mkdir -p /userdata/openvpnd");
		if ((fp = fopen("/userdata/openvpnd/ca.crt", "w+")) != NULL) 
		{
			fprintf(fp, "%s", ca);
			fclose(fp);
		}
		if ((fp = fopen("/userdata/openvpnd/dh1024.pem", "w+")) != NULL) 
		{
			fprintf(fp, "%s", dh);
			fclose(fp);
		}
		if ((fp = fopen("/userdata/openvpnd/server.crt", "w+")) != NULL) 
		{
			fprintf(fp, "%s", cert);
			fclose(fp);
		}
		if ((fp = fopen("/userdata/openvpnd/server.key", "w+")) != NULL) 
		{
			fprintf(fp, "%s", key);
			fclose(fp);
		}
		if ((fp = fopen("/userdata/openvpnd/extra.conf", "w+")) != NULL) 
		{
			fprintf(fp, "%s", extra_config);
			fclose(fp);
		}
		system("mkdir -p /etc_ro/easy-rsa/keys");
		system("cp -rf /userdata/openvpnd/* /etc_ro/easy-rsa/keys/");
	#endif
	}
		
	nvram_commit(RT2860_NVRAM);

	setNetworkLktos("openvpnd");
	setFWLktos("openvpnd");
	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;

}


/**
* 获取OpenVPN日志
* @Author   Amy       <amy@carystudio.com>
* @DateTime 2018-04-27
* @property    {String}   log         日志信息
* @property {String}
* @return   {object}
* @example
* request:
* {
*       "topicurl":"getOpenVpnLog"
* }
* response:
* {
*       "log":"Fri Apr 27 18:47:00 2018 OpenVPN 2.3.11 mipsel-openwrt-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [MH] [IPv6] Fri Apr 27 18:47:00 2018 library versions: OpenSSL 1.0.2e 3 Dec 2015, LZO 2.08 Fri Apr 27 18:47:00 2018 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts Fri Apr 27 18:47:00 2018 WARNING: POTENTIALLY DANGEROUS OPTION --client-cert-not-required may accept clients which do not present a certificate Fri Apr 27 18:47:00 2018 WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu 1500 (currently it is 1400) Fri Apr 27 18:47:00 2018 TUN/TAP device sovpn opened Fri Apr 27 18:47:00 2018 do_ifconfig, tt->ipv6=0, tt->did_ifconfig_ipv6_setup=0 Fri Apr 27 18:47:00 2018 /sbin/ifconfig sovpn 10.7.7.1 pointopoint 10.7.7.2 mtu 1400 Fri Apr 27 18:47:00 2018 UDPv4 link local (bound): [undef] Fri Apr 27 18:47:00 2018 UDPv4 link remote: [undef] Fri Apr 27 18:47:00 2018 Initialization Sequence Completed"
* }
*/

int getOpenVpnLog(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output=NULL;
	cJSON *root;
	char *ptr = NULL;
	int log_len = 0;
	FILE *fp;
	
	root=cJSON_CreateObject();
	if ( f_exist("/var/log/openvpnd.log") )
	{
		log_len = f_size("/var/log/openvpnd.log");
		if ((fp = fopen("/var/log/openvpnd.log", "r")) != NULL) 
		{
			ptr = (char *)calloc(log_len+1, 1);
			if ( ptr == NULL )
			{
				printf("[%s:%d]->out of memory\n", __FUNCTION__, __LINE__);
				goto out;
			}

			fread(ptr, 1, log_len, fp);
			fclose(fp);
			cJSON_AddStringToObject(root, "log", ptr);
			free(ptr);
		}
		else
		{
			printf("[%s:%d]->open openvpn log fial\n", __FUNCTION__, __LINE__);
			goto out;
		}
			
	}
	else
	{
		printf("[%s:%d]->no openvpn log\n", __FUNCTION__, __LINE__);
		goto out;
	}

	output =cJSON_Print(root);

	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);

	return 0;

out:
	websGetCfgResponse(mosq,tp,"");
	cJSON_Delete(root);
	return 0;
}
#endif

#if defined(SUPPORT_L2TP_CLIENT) || defined (SUPPORT_PPTP_CLIENT)
int setVpnInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *vpn_type    = websGetVar(data, T("vpnType"), T(""));
	char *l2tp_srv    = websGetVar(data, T("l2tpServer"), T(""));
	char *l2tp_user   = websGetVar(data, T("l2tpUser"), T(""));
	char *l2tp_pass   = websGetVar(data, T("l2tpPass"), T(""));
	char *pptp_srv    = websGetVar(data, T("pptpServer"), T(""));
	char *pptp_user   = websGetVar(data, T("pptpUser"), T(""));
	char *pptp_pass   = websGetVar(data, T("pptpPass"), T(""));
	char *pptp_enable = websGetVar(data, T("pptpEnable"), T("0"));
	char *l2tp_enable = websGetVar(data, T("l2tpEnable"), T("0"));
	unsigned l2tpEnable, pptpEnable, portNum;
	char tmBuf[64]={0}, cmdBuf[128]={0};
	int wanDhcp=DHCP_CLIENT,wanIpDynamic=0;
	struct  in_addr inip;

	if (!strncmp(vpn_type, "1", 2)) //l2tp
	{
		if (!strncmp(l2tp_enable, "0", 2))
		{
			apmib_set(MIB_WAN_DHCP, (void *)&wanDhcp);
		}
		else
		{
			wanDhcp=L2TP;
			apmib_set(MIB_WAN_DHCP, (void *)&wanDhcp);
			apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&wanIpDynamic);
			if ( inet_aton(l2tp_srv, &inip) )
				apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&inip);
			apmib_set(MIB_L2TP_USER_NAME, (void *)l2tp_user);
			apmib_set(MIB_L2TP_PASSWORD, (void *)l2tp_pass);
		}
	}
	
	if (!strncmp(vpn_type, "2", 2)) //pptp
	{
		if (!strncmp(pptp_enable, "0", 2))
		{
			apmib_set(MIB_WAN_DHCP, (void *)&wanDhcp);
		}
		else
		{
			wanDhcp=PPTP;
			apmib_set(MIB_WAN_DHCP, (void *)&wanDhcp);
			apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&wanIpDynamic);
			if ( inet_aton(pptp_srv, &inip) )
				apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&inip);
			apmib_set(MIB_PPTP_USER_NAME, (void *)pptp_user);
			apmib_set(MIB_PPTP_PASSWORD, (void *)pptp_pass);
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	
	pptpEnable = atoi(pptp_enable);
	l2tpEnable = atoi(l2tp_enable);
	if(1==l2tpEnable){
		RunSystemCmd(NULL_FILE,"sysconf", "l2tp", "connect","eth1",NULL_STR);
	}else if(1==pptpEnable){
		RunSystemCmd(NULL_FILE,"sysconf", "pptp", "connect","eth1",NULL_STR);
	}else{
		RunSystemCmd(NULL_FILE,"init.sh", "gw", "all",NULL_STR);
	}
	
	websSetCfgResponse(mosq, tp, "30", "reserv");
	return 0;
}

int getVpnInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	cJSON *root;
	char  *output;
	char info[128]={0},buff[128],tmpStr[128];
	char *vpn_type  = websGetVar(data, T("vpnType"), T(""));
	char *pppifname = "ppp0";//nvram_bufget(RT2860_NVRAM, "wan_pppoe_interface");
	int wanMode;

	apmib_get(MIB_WAN_DHCP, (void *)&wanMode);
	
	root = cJSON_CreateObject();
	if (!strncmp(vpn_type, "1", 2)) //l2tp
	{
		if(L2TP==wanMode)
			cJSON_AddStringToObject(root,"l2tpEnable",   "1");
		else
			cJSON_AddStringToObject(root,"l2tpEnable",   "0");
		
		memset(buff,0,sizeof(buff));
		apmib_get(MIB_L2TP_SERVER_IP_ADDR,  (void *)buff);
        sprintf(tmpStr,"%s",inet_ntoa(*((struct in_addr *)buff)));
		cJSON_AddStringToObject(root,"l2tpServer", tmpStr);

		memset(buff,0,sizeof(buff));
		apmib_get(MIB_L2TP_USER_NAME,  (void *)buff);
		cJSON_AddStringToObject(root,"l2tpUser",   buff);

		memset(buff,0,sizeof(buff));
		apmib_get(MIB_L2TP_PASSWORD,  (void *)buff);
		cJSON_AddStringToObject(root,"l2tpPass",   buff);
		
		getIfIp(pppifname, info);
		if (L2TP==wanMode && strlen(info) > 4 )
		{
			cJSON_AddStringToObject(root, "l2tpConnect","1");
			cJSON_AddStringToObject(root, "l2tpClientAddr",info);
		}
		else
		{
			cJSON_AddStringToObject(root, "l2tpConnect","0");
			cJSON_AddStringToObject(root, "l2tpClientAddr","0.0.0.0");
		}
	}
	else if (!strncmp(vpn_type, "2", 2))  //pptp
	{
		if(PPTP==wanMode)
			cJSON_AddStringToObject(root,"pptpEnable", "1");
		else
			cJSON_AddStringToObject(root,"pptpEnable", "0");
	
		memset(buff,0,sizeof(buff));
		apmib_get(MIB_PPTP_SERVER_IP_ADDR,  (void *)buff);
		sprintf(tmpStr,"%s",inet_ntoa(*((struct in_addr *)buff)));
		cJSON_AddStringToObject(root,"pptpServer", tmpStr);

		memset(buff,0,sizeof(buff));
		apmib_get(MIB_PPTP_USER_NAME,  (void *)buff);
		cJSON_AddStringToObject(root,"pptpUser",   buff);

		memset(buff,0,sizeof(buff));
		apmib_get(MIB_PPTP_PASSWORD,  (void *)buff);
		cJSON_AddStringToObject(root,"pptpPass",   buff);

		memset(buff,0,sizeof(buff));
		cJSON_AddStringToObject(root,"pptpMppe",   buff);
		cJSON_AddStringToObject(root,"pptpMppc",   buff);

		getIfIp(pppifname, info);
		if (PPTP==wanMode && strlen(info) > 4 )
		{
			cJSON_AddStringToObject(root, "pptpConnect","1");
			cJSON_AddStringToObject(root, "pptpClientAddr",info);
		}
		else
		{
			cJSON_AddStringToObject(root, "pptpConnect","0");
			cJSON_AddStringToObject(root, "pptpClientAddr","0.0.0.0");
		}
	}
	
	output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
	return 0;
}
#endif

int module_init()
{

#if defined(CONFIG_USER_SHADOWSOCKS)
	cste_hook_register("setssServer",setssServer);
	cste_hook_register("getssServer",getssServer);
#endif

#if defined(CONFIG_USER_PPTPD)
	cste_hook_register("setPptpdConfig",setPptpdConfig);
	cste_hook_register("getPptpdConfig",getPptpdConfig);
#endif

#if defined(CONFIG_USER_L2TPD)
	cste_hook_register("setL2tpdConfig",setL2tpdConfig);
	cste_hook_register("getL2tpdConfig",getL2tpdConfig);
#endif

//pptpd & l2tpd Shared ppp user config
#if defined(CONFIG_USER_PPTPD)||defined(CONFIG_USER_L2TPD)
	cste_hook_register("getVpnUser",getVpnUser);
	cste_hook_register("setVpnUser",setVpnUser);
	cste_hook_register("deleteVpnUser",deleteVpnUser);
	cste_hook_register("getUserInfo",getUserInfo);
	cste_hook_register("disconnectVPN",disconnectVPN);
	//CsteSystem("mkdir -p /tmp/ppp",CSTE_PRINT_CMD);
#endif

#if defined(CONFIG_USER_OPENVPND)
cste_hook_register("getOpenVpnConfig",getOpenVpnConfig);
cste_hook_register("setOpenVpnConfig",setOpenVpnConfig);
cste_hook_register("getOpenVpnLog",getOpenVpnLog);
#endif

#if defined(SUPPORT_L2TP_CLIENT) || defined (SUPPORT_PPTP_CLIENT)
	cste_hook_register("setVpnInfo",setVpnInfo);
	cste_hook_register("getVpnInfo",getVpnInfo);
#endif

    return 0;  
}

