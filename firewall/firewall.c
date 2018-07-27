/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file firewall.c
* @author CaryStudio
* @brief  This is a firewall cste topic
* @date 2017-10-07
* @warning http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.
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

#include "firewall.h"



#if defined(CONFIG_PA_ONLINE_IP)
#define FILTER_RULE_NUM		10
struct auto_proto_prio 
{
	int prio;
};

enum proto_id
{
	PROTO_OTHER=0,
	PROTO_HTTP,
	PROTO_HTTP_DOWNLOAD,
	PROTO_HTTPS,
	PROTO_SMALLPKT,
	PROTO_P2P,
	PROTO_MAX
};
	
enum apptypeid
{
	appFilter=1,
	gameSpeed
};

#endif 

/**
* @note setFirewallType - Set firewall type,White List or Black List
*
* @param enabled - 0:White List,1:Black List
*
* @return Default JSON returns
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setFirewallType(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int enabled = atoi(websGetVar(data, T("firewallType"), T("0")));
	apmib_set(MIB_FIREWALL_MODE, (void *)&enabled);
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");      
}

/**
* @note getFirewallType - Get firewall type,White List or Black List
*
* @param {}
*
* @return Return Json Data
<pre>
{
	"firewallType":	"0"
}
Return parameter description:
	firewallType - 0:White List,1:Black List
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getFirewallType(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
	cJSON *root=cJSON_CreateObject();
	int tmpint=0;
	
	apmib_get(MIB_FIREWALL_MODE,  (void *)&tmpint);
	cJSON_AddNumberToObject(root,"firewallType",tmpint);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}

/**
* @note setIpPortFilterRules - Set current IP/Port filtering rules.
* 
* @param data
<pre>
{
	"enable":"1",
	"addEffect":"0",
	"ipAddress":"192.168.0.20",
	"dFromPort":"1",
	"dToPort":	"1024",
	"protocol":	"TCP+UDP",
	"comment":	"abcdefg"
}
Parameter description:
	enable		- On/Off IP port filter. eg:1 Enable,0 Disbale.
	addEffect 	- setting mode. eg:1 set switch only 0:set filtering rules.
	ipAddress	- source Ip address,This rule is for this IP.
	dFromPort	- destination port start.
	dToPort		- destination port end.
	protocol		- protocol. eg:TCP	/UDP /TCP+UDP
	comment		- Comment of each rule
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *ip = websGetVar(data, T("ipAddress"), T(""));	
	char *protocol = websGetVar(data, T("protocol"), T(""));
	char *comment = websGetVar(data, T("comment"), T(""));
	char *dprf = websGetVar(data, T("dFromPort"), T("0"));
	char *dprt = websGetVar(data, T("dToPort"), T(""));
	
	char cur_time[32]={0},comment_buf[64]={0};
	IPFILTER_T ipEntry;
	SCHEFILTER_T scheEntry;
	memset(&ipEntry, '\0', sizeof(ipEntry));
	memset(&scheEntry, '\0', sizeof(scheEntry));
	
	if (addEffect){
		apmib_set(MIB_IPFILTER_ENABLED, (void *)&enabled);
	}else{
		inet_aton(ip, (struct in_addr *)&ipEntry.ipAddr);
		ipEntry.fromPort = (unsigned short)atoi(dprf);
		if (!dprt[0]){
			ipEntry.toPort = ipEntry.fromPort;
		}else{
			ipEntry.toPort = (unsigned short)atoi(dprt);
		}
		if(!strcmp(protocol, T("TCP"))){
			ipEntry.protoType = PROTO_TCP;
		}else if( !strcmp(protocol, T("UDP"))){
			ipEntry.protoType = PROTO_UDP;
		}else if( !strcmp(protocol, T("ALL"))){
			ipEntry.protoType = PROTO_BOTH;
		}else{
			return;
		}
		strcpy(comment_buf, "1");
		strcat(comment_buf, comment);
		strcpy((char *)ipEntry.comment, comment_buf);				

#if defined(CONFIG_APP_EASYCWMP)
		get_Create_Time(cur_time);
		strcpy((char *)ipEntry.creTime, cur_time);
#endif
#if defined(CONFIG_APP_IPV6_SUPPORT)
		ipEntry.ipVer = IPv4;
#endif
		apmib_set(MIB_IPFILTER_DEL, (void *)&ipEntry);
		apmib_set(MIB_IPFILTER_ADD, (void *)&ipEntry);

		//for fwschedual
#if 0		
		inet_aton(ip, (struct in_addr *)&scheEntry.ipAddr);
		scheEntry.protoType = ipEntry.protoType;
		scheEntry.fromPort = ipEntry.fromPort;
		scheEntry.toPort = ipEntry.toPort;
		string_to_hex("000000000000", scheEntry.macAddr,12);
		strcpy((char *)scheEntry.day,"1,2,3,4,5,6,7");
		strcpy((char *)scheEntry.stime,"00:00");
		strcpy((char *)scheEntry.ttime,"23:59");
		apmib_set(MIB_SCHEFILTER_DEL, (void *)&scheEntry);
		apmib_set(MIB_SCHEFILTER_ADD, (void *)&scheEntry);
#endif				
	}

	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note getIpPortFilterRules - Get current IP/Port filtering list.
*
* @param {}
*
* @return Return Json Data
<pre>
[
	{
		"enabled":"1",
		"lanNetmask":"255.255.255.0",
		"lanIp":"192.168.0.1"
	},
	{
		"idx":"1",
		"ipAddress":"192.168.0.22",
		"protocol":"TCP+UDP",
		"portRange":"1-1024",
		"comment":"abcdefg",
		"delRuleName":"delRule0"
	}
	...
]
Return parameter description:
	enabled 		- On/Off IP port filter. eg:1 Enable,0 Disbale
	lanNetmask	- Router LAN mask. eg:255.255.255.0
	lanIp		- Router LAN IP. eg:192.168.0.1
	idx 			- Rule list index,starting at 1.
	ipAddress	- This rule is for this IP.eg:192.168.0.22
	protocol		- Protocol. eg:	TCP /UDP /TCP+UDP
	portRange	- Port range. eg:1-65535
	comment		- Comment of each rule
	delRuleName 	- Index for deletion. eg:delRule0,delRule1
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	IPFILTER_T entry;
	int i=0, len=0, tmpint, add, entryNum;
	char *type, *ip;
	char ad[4096],responseStr[4096],lanIp[32],lanNetmask[32],portRange[64],comment[64]={0};
	
	memset(responseStr,0,sizeof(responseStr));
	apmib_get(MIB_IPFILTER_ENABLED, (void *)&tmpint);
	getLanIp(lanIp);
	getLanNetmask(lanNetmask);
	snprintf(responseStr, (sizeof(responseStr) - len), \
		     "[{\"enable\":\"%d\",\"lanNetmask\":\"%s\",\"lanIp\":\"%s\"}\n", \
		     tmpint, lanNetmask, lanIp);
	len = strlen(responseStr);

	apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		sprintf(ad,"%s",responseStr);
		add=entryNum;
		if (!apmib_get(MIB_IPFILTER_TBL, (void *)&entry))
			return -1;
		entryNum=add;
		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if (!strcmp(ip, "0.0.0.0"))
			ip = "----";
		if (entry.protoType == PROTO_BOTH)
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP)
			type = "TCP";
		else
			type = "UDP";
		if (entry.fromPort == entry.toPort)
			snprintf(portRange, 20, "%d", entry.fromPort);
		else
			snprintf(portRange, 20, "%d-%d", entry.fromPort, entry.toPort);
		strcpy(comment, entry.comment);
		snprintf((responseStr + len), (sizeof(responseStr) - len),\
			",{\"idx\":\"%d\",\"ip\":\"%s\",\"proto\":\"%s\",\"portRange\":\"%s\",\"comment\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			i, ip, type, portRange, comment + 1, i-1);
		len = strlen(responseStr);
	}
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);
	websGetCfgResponse(mosq,tp,responseStr);
	return 0;	
}

int sche_ip_del(IPFILTER_T ipEntry)
{
	SCHEFILTER_T Entry;
	int i, num;

	if (!apmib_get(MIB_SCHEFILTER_TBL_NUM, (void *)&num))
		goto END;
	
	for (i=1; i<=num; i++) {
		*((char *)&Entry) = (char)i;
		if (!apmib_get(MIB_SCHEFILTER_TBL, (void *)&Entry)) 
			goto END;
		
		if(!memcmp(Entry.ipAddr, ipEntry.ipAddr, 4) && 
			Entry.fromPort == ipEntry.fromPort && 
			Entry.toPort == ipEntry.toPort &&
			Entry.protoType == ipEntry.protoType){
			apmib_set(MIB_SCHEFILTER_DEL, (void *)&Entry);
			return 1;
		}
	}

END:
	return 0;
}

/**
* @note delIpPortFilterRules - Delete current IP/Port filtering rules.
* 
* @param data
<pre>
{
  	"delRule0": 0,
  	"delRule1": 1,
  	"delRule2": 2
  	...
}
Parameter description:
	delRule- - If the value is passed, delete this item.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int delIpPortFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum,flag;
	char name_buf[16];
	char *value;
	IPFILTER_T ipEntry;
	
	apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&ipEntry) = (char)i;
			apmib_get(MIB_IPFILTER_TBL, (void *)&ipEntry);
			apmib_set(MIB_IPFILTER_DEL, (void *)&ipEntry);
			if(1 == sche_ip_del(ipEntry))flag = 1;
			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	if(flag == 1){
		system("csteSys fwSch");
		system("csteSys updateCrond");
	}
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note setMacFilterRules - Set current mac filtering rules.
* 
* @param data
<pre>
{
	"enable":"1",
	"addEffect":"0",
	"macAddress":"00:E0:4C:36:06:F0",
	"comment":"abc"
}
Parameter description:
	enable		- On/Off MAC filter. eg:1 Enable,0 Disbale.
	addEffect 	- setting mode. eg:1 set switch only 0:set filtering rules.
	macAddress	- MAC address.
	comment		- Comment of each rule.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int addEffect =atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *mac = websGetVar(data, T("macAddress"), T(""));		
	char *comment = websGetVar(data, T("comment"), T(""));

	int i=0,j=0;
	MACFILTER_T macEntry;
	SCHEFILTER_T scheEntry;
	char macbuf[13]={0}, cur_time[32]={0}, comment_buf[64]={0};
	memset(&macEntry, '\0', sizeof(macEntry));
	memset(&scheEntry, '\0', sizeof(scheEntry));

	if (addEffect){
		apmib_set(MIB_MACFILTER_ENABLED, (void *)&enabled);
	}else{		
		while(mac[i]!='\0'){
			if(mac[i]!=':'){
				macbuf[j]=mac[i];
				j++;
			}
			i++;
		}
		if(strlen(macbuf)==0) return;
		string_to_hex(macbuf, macEntry.macAddr,strlen(macbuf));
		strcpy(comment_buf, "1");
		strcat(comment_buf, comment);
		strcpy((char *)macEntry.comment, comment_buf);

#if defined(CONFIG_APP_EASYCWMP)
		get_Create_Time(cur_time);
		strcpy((char *)macEntry.creTime, cur_time);
#endif		
		apmib_set(MIB_MACFILTER_DEL, (void *)&macEntry);
		apmib_set(MIB_MACFILTER_ADD, (void *)&macEntry);

		//for fwschedual
#if 0		
		string_to_hex(macbuf, scheEntry.macAddr,strlen(macbuf));
		inet_aton("0.0.0.0", (struct in_addr *)&scheEntry.ipAddr);
		scheEntry.protoType = 0;
		scheEntry.fromPort = 0;
		scheEntry.toPort = 0;
		strcpy((char *)scheEntry.day,"1,2,3,4,5,6,7");
		strcpy((char *)scheEntry.stime,"00:00");
		strcpy((char *)scheEntry.ttime,"23:59");
		apmib_set(MIB_SCHEFILTER_DEL, (void *)&scheEntry);
		apmib_set(MIB_SCHEFILTER_ADD, (void *)&scheEntry);
#endif
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;
}

/**
* @note getMacFilterRules - Get Current MAC Filtering List 
*
* @param {}
*
* @return Return Json Data
<pre>
[
	{
		"enabled":"1"
	},
	{
		"idx":"1",
		"macAddress":"00:e0:4c:36:06:f0",
		"comment":"abc",
		"delRuleName":"delRule0"
	}
	...
]
Return parameter description:
	enabled		- On/Off MAC filter. eg:1 Enable,0 Disbale.
	idx 			- Rule list index,starting at 1.
	macAddress	- MAC address.
	comment		- Comment of each rule.
	delRuleName	- Index for deletion.
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	MACFILTER_T entry;
	int i=0, len=0, tmpint, entryNum;
	char responseStr[4096],macbuf[32]={0},comment[64]={0};
	
	memset(responseStr,0,sizeof(responseStr));	
	apmib_get(MIB_MACFILTER_ENABLED, (void *)&tmpint);
	snprintf(responseStr,(sizeof(responseStr)- len), "[{\"enable\":\"%d\"}\n", tmpint);
	len = strlen(responseStr);
	
	apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}
	
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if (!apmib_get(MIB_MACFILTER_TBL, (void *)&entry))
			return -1;	
		snprintf(macbuf, 32, ("%02X:%02X:%02X:%02X:%02X:%02X"),
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		strcpy(comment, entry.comment);
		snprintf((responseStr + len), (sizeof(responseStr) - len),\
			",{\"idx\":\"%d\",\"mac\":\"%s\",\"comment\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			i,macbuf,comment + 1,i-1);
		len = strlen(responseStr);
	}
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);	
	websGetCfgResponse(mosq,tp,responseStr);	
	return 0;	
}

int sche_mac_del(MACFILTER_T macEntry)
{
	SCHEFILTER_T Entry;
	int i, num;

	if ( !apmib_get(MIB_SCHEFILTER_TBL_NUM, (void *)&num))
		goto END;
	
	for (i=1; i<=num; i++) {
		*((char *)&Entry) = (char)i;
		if ( !apmib_get(MIB_SCHEFILTER_TBL, (void *)&Entry)) 
			goto END;
		
		if( !memcmp(Entry.macAddr, macEntry.macAddr, 6) ){
			apmib_set(MIB_SCHEFILTER_DEL, (void *)&Entry);
			return 1;
		}
	}

END:
	return 0;
}

/**
* @note delMacFilterRules - Delete current mac filtering rules.
* 
* @param data
<pre>
{
	"delRule0": 0,
	"delRule1": 1,
	"delRule2": 2
	...
}
Parameter description:
	delRule- - If the value is passed, delete this item.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int delMacFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum,flag;
	char name_buf[16];
	char *value;
	MACFILTER_T macEntry;
	
	apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&macEntry) = (char)i;
			apmib_get(MIB_MACFILTER_TBL, (void *)&macEntry);
			apmib_set(MIB_MACFILTER_DEL, (void *)&macEntry);
			if(1 == sche_mac_del(macEntry))flag = 1;			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	if(flag == 1){
		system("csteSys fwSch");
		system("csteSys updateCrond");
	}
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note ipPortMacRulesModify  	--set the firewall rules of time.
*
* @param data
<pre>
{
	"rulesModifySignal":"add;ip,192.168.0.10,TCP+UDP,1024-2048;mac,00:e0:4c:36:06:f0;"
}
or
{
	"rulesModifySignal":"del;mac,00:e0:4c:36:06:f0;ip,192.168.0.10,TCP+UDP,1024-2048;"
}
Parameter description:
	rulesModifySignal 		--add or del the firewall schedule rule,the two rules are separated by semicolons.
</pre>
*
* @return   json str format
<pre>
{
    "success":	true,
    "error":	null,
    "lan_ip":	"192.168.0.1",
    "wtime":	"0",
    "reserv":	"reserv"
}
</pre>
*
* @author	rockey
* @date		2017-11-07
*/
int delIpportMacRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	IPFILTER_T ipEntry, checkipEntry, ip_Entry[2]={0};
	MACFILTER_T macEntry, checkmacEntry, mac_Entry[2]={0};
	int i, j, num;
	int n = 0;
	char rule[24][64]={0};
	char member[4][24]={0};
	char buf[64]={0}, comment[64]={0};
	
	char *rules = websGetVar(data, T("rulesModifySignal"), T("0"));
	n = splitString2Arr_v2(rules, rule, 24, 64, ';');
	if(n == 1){
		printf("date error !\n");
		websSetCfgResponse(mosq, tp, "0", "reserv");
		return 0;
	}
	
	apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&num);
	for (i=1; i<=num; i++) {
		*((char *)&ipEntry) = (char)i;
		apmib_get(MIB_IPFILTER_TBL, (void *)&ipEntry);
		for(j=1; j<n; j++){
			if(strncmp("ip", rule[j], 2) == 0){
				splitString2Arr_v2(rule[j], member, 4, 24, ',');
				inet_aton(member[1], (struct in_addr *)&checkipEntry.ipAddr);
				if (!strcmp(member[2],"TCP+UDP"))
					checkipEntry.protoType=PROTO_BOTH;
				else if(!strcmp(member[2],"TCP"))
					checkipEntry.protoType=PROTO_TCP; 
				else
					checkipEntry.protoType=PROTO_UDP;
				checkipEntry.fromPort=atoi(strtok(member[3], "-"));
				checkipEntry.toPort=atoi(strtok(NULL, "-"));
				if( !memcmp(ipEntry.ipAddr, checkipEntry.ipAddr, 4) && 
					ipEntry.fromPort == checkipEntry.fromPort && 
					ipEntry.toPort == checkipEntry.toPort &&
					ipEntry.protoType == checkipEntry.protoType )
				{
					strncpy(rule[j], "  ", 2);
					memset(&ip_Entry, '\0', sizeof(ip_Entry));
					*((char *)(void *)&ip_Entry) = (char)i;
					apmib_get(MIB_IPFILTER_TBL,(void*)&ip_Entry);
					ip_Entry[1] = ip_Entry[0];
					strcpy(buf, ipEntry.comment + 1);
					if(strcmp("add", rule[0]) == 0)
						strcpy(comment, "0");
					else if(strcmp("del", rule[0]) == 0)
						strcpy(comment, "1");
					strcat(comment, buf);
					strcpy(ip_Entry[1].comment, comment);
					apmib_set(MIB_IPFILTER_MOD, (void*)&ip_Entry);
					apmib_update_web(CURRENT_SETTING);
					break;
				}
			}
		}
	}

	apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&num);
	for (i=1; i<=num; i++) {
		*((char *)&macEntry) = (char)i;
		apmib_get(MIB_MACFILTER_TBL, (void *)&macEntry);
		for(j=1; j<n; j++){
			if(strncmp("mac", rule[j], 3) == 0){
				splitString2Arr_v2(rule[j], member, 4, 24, ',');
				int k=0,index=0;
				char dmac[16]={0};
				while(member[1][k]){
					if(member[1][k] != ':'){
						dmac[index] = member[1][k];
						index++;
					}
					k++;
				}
				string_to_hex(dmac, checkmacEntry.macAddr, 12);
				if( !memcmp(macEntry.macAddr, checkmacEntry.macAddr, 6)){
					strncpy(rule[j], "  ", 2);
					memset(&mac_Entry, '\0', sizeof(mac_Entry));
					*((char *)(void *)&mac_Entry) = (char)i;
					apmib_get(MIB_MACFILTER_TBL,(void*)&mac_Entry);
					mac_Entry[1] = mac_Entry[0];
					strcpy(buf, macEntry.comment + 1);
					if(strcmp("add", rule[0]) == 0)
						strcpy(comment, "0");
					else if(strcmp("del", rule[0]) == 0)
						strcpy(comment, "1");
					strcat(comment, buf);
					strcpy(mac_Entry[1].comment, comment);
					apmib_set(MIB_MACFILTER_MOD, (void*)&mac_Entry);
					apmib_update_web(CURRENT_SETTING);
					break;
				}
			}
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "0", "reserv");

	int pid;
	pid=fork();
	if(0 == pid)
	{
		sleep(5);
		system("sysconf firewall");
		exit(1);
	}
	return 0;
}

/**
* @note setUrlFilterRules - Set current URL filtering rules.
* 
* @param data
<pre>
{
	"enable":"1",
	"addEffect":"0",
	"addURLFilter":"sina"
}
Parameter description:
	enable			- On/Off URL filter. eg:1 Enable,0 Disbale.
	addEffect 		- setting mode. eg:1 set switch only 0:set filtering rules.
	addURLFilter	- URL that needs filtering.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *url = websGetVar(data, T("url"), T(""));		

	char cur_time[32]={0};
	URLFILTER_T urlEntry;
	memset(&urlEntry, '\0', sizeof(urlEntry));

	if (addEffect){
		apmib_set(MIB_URLFILTER_ENABLED, (void *)&enabled);
	}else{
		get_Create_Time(cur_time);
		strcpy((char *)urlEntry.creTime, cur_time);		
		strcpy((char *)urlEntry.urlAddr, url);	
		apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);
		apmib_set(MIB_URLFILTER_ADD, (void *)&urlEntry);
	}
	
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	
	int pid;
	pid=fork();
	if(0 == pid)
	{
		sleep(3);
		system("sysconf firewall");
		exit(1);
	}
	return 0;
}

/**
* @note getUrlFilterRules - Get current URL filtering list.
*
* @param {}
*
* @return Return Json Data
<pre>
[
	{
		"enabled":"1"
	},
	{
		"idx":"1",
		"url":"sina",
		"delRuleName":"delRule0"
	}
	...
]

Return parameter description:
	enable 		- On/Off URL filter. eg:1 Enable,0 Disbale
	idx 		- Rule list index,starting at 1.
	url			- URL that needs filtering.
	delRuleName - Index for deletion
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	URLFILTER_T entry;
	int i=0, len=0, tmpint, entryNum;
	char *type, *ip;
	char responseStr[4096];
	
	memset(responseStr,0,sizeof(responseStr));	
	apmib_get(MIB_URLFILTER_ENABLED,  (void *)&tmpint);
	snprintf(responseStr,(sizeof(responseStr)- len), "[{\"enable\":\"%d\"}\n", tmpint);
	len = strlen(responseStr);

	apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}
	
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&entry))
			return -1;			
		snprintf((responseStr + len), (sizeof(responseStr) - len),\
			",{\"idx\":\"%d\",\"url\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			i,entry.urlAddr,i-1);
		len = strlen(responseStr);
	}
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);
	websGetCfgResponse(mosq,tp,responseStr);	
	return 0;	
}

/**
* @note delUrlFilterRules - Delete current URL filtering rules.
* 
* @param data
<pre>
{
	"delRule0": 0,
	"delRule1": 1,
	"delRule2": 2
	...
}
Parameter description:
	delRule- - If the value is passed, delete this item.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int delUrlFilterRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum;
	char name_buf[16];
	char *value;
	URLFILTER_T urlEntry;
	
	apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&urlEntry) = (char)i;
			apmib_get(MIB_URLFILTER_TBL, (void *)&urlEntry);
			apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);	
	websSetCfgResponse(mosq, tp, "0", "reserv");
	
	int pid;
	pid=fork();
	if(0 == pid)
	{
		sleep(3);
		system("sysconf firewall");
		exit(1);
	}
	return 0;
}

int setParentalRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char cur_time[32]={0};
	URLFILTER_T urlEntry;
	char full_info[64] = {0};
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *url_keyword = websGetVar(data, T("urlKeyword"), T(""));	//url + mac, infact.	
	int week = atoi(websGetVar(data, T("week"), T("000")));	
	char *startTime = websGetVar(data, T("startTime"), T("0000"));
	char *endTime = websGetVar(data, T("endTime"), T("2359"));
	memset(&urlEntry, '\0', sizeof(urlEntry));

	if (addEffect){
		apmib_set(MIB_URLFILTER_ENABLED, (void *)&enabled);
	}else{
		get_Create_Time(cur_time);
		strcpy((char *)urlEntry.creTime, cur_time);
		//week 前端未做补齐3位
		sprintf(full_info, "%s%03d%s%s", url_keyword, week, startTime, endTime);
		strcpy((char *)urlEntry.urlAddr, full_info);
		apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);
		apmib_set(MIB_URLFILTER_ADD, (void *)&urlEntry);
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;
}

// urgly code..  由于kernel 代码不使用分割符, 前端使用, 故转换
void format_trans(char input[], char output[])
{
	//input[] =  "hnu.edu.cn00:26:66:45:EF:3D12611112222";
	//output[]= "hnu.edu.cn,00:26:66:45:EF:3D,Mon Tue Wed Thu Fri Sat Sun,00:00,23:59"
	
	int mac_len=17, time_len=11, int_week;
	char buf[128] = {0}, mac[24] = {0}, week_buf[4] = {0}, week[32] = {0};
	char start_time[8] = {0}, end_time[8] = {0};

	int len =strlen(input);
	
	strncpy(mac, input+len-time_len-mac_len, mac_len);

	strncpy(week_buf, input+len-time_len, 3);
	int_week = atoi(week_buf);
	if(int_week & (1 << 0))
		strcat(week, "Mon ");
	if(int_week & (1 << 1))
		strcat(week, "Tue ");
	if(int_week & (1 << 2))
		strcat(week, "Wed ");
	if(int_week & (1 << 3))
		strcat(week, "Thu ");
	if(int_week & (1 << 4))
		strcat(week, "Fri ");
	if(int_week & (1 << 5))
		strcat(week, "Sat ");
	if(int_week & (1 << 6))
		strcat(week, "Sun ");
	
	if(strlen(week))
		week[strlen(week)-1] = '\0';
	
	strncpy(start_time, input+len-time_len+3, 2);
	strcat(start_time, ":");
	strncpy(start_time+3, input+len-time_len+5, 2);

	strncpy(end_time, input+len-time_len+7, 2);
	strcat(end_time, ":");
	strncpy(end_time+3, input+len-time_len+9, 2);
	input[len-time_len-mac_len] = '\0';
	sprintf(output, "%s,%s,%s,%s,%s", input, mac, week, start_time, end_time);
	return;
}

int getParentalRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	URLFILTER_T entry;
	int i=0, len=0, tmpint, entryNum;
	char *type, *ip;
	char responseStr[4096]={0}, macbuf[32]={0}, url_buf[128]={0};

	memset(responseStr,0,sizeof(responseStr));	
	apmib_get(MIB_URLFILTER_ENABLED, (void *)&tmpint);
	sprintf(responseStr, "[{\"enable\":\"%d\"}\n", tmpint);
	len = strlen(responseStr);

	apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);	
		return 0;
	}

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&entry)){
			return -1;			
		}

		memset(url_buf, 0, sizeof url_buf);
		format_trans(entry.urlAddr, url_buf);
		len = strlen(responseStr);
		sprintf(responseStr+len, ",{\"idx\":\"%d\",\"url\":\"%s\",\"delRuleName\":\"delRule%d\"}\n", i, url_buf, i-1);
	}
	
	responseStr[strlen(responseStr)-1] = '\0';
	strcat(responseStr, "]");
	websGetCfgResponse(mosq,tp,responseStr);	
	return 0;	
}

int delParentalRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum;
	char name_buf[16];
	char *value;
	URLFILTER_T urlEntry;
	
	apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&urlEntry) = (char)i;
			apmib_get(MIB_URLFILTER_TBL, (void *)&urlEntry);
			apmib_set(MIB_URLFILTER_DEL, (void *)&urlEntry);			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note setPortForwardRules - Set current port forward filtering rules.
* 
* @param data
<pre>
{
	"enable":	"1",
	"addEffect":	"0",
	"ipAddress":	"192.168.0.10",
	"wanPortFrom":"5100",
	"wanPortTo":	"5100",
	"lanPortFrom":	"5000",
	"lanPortTo":	"5000",
	"protocol":	"TCP&UDP",
	"comment":	"abcdefg"
}

Parameter description:
	enable		- On/Off Port forward. eg:1 Enable,0 Disbale.
	addEffect 	- Setting mode. eg:1 set switch only 0:set rules.
	ipAddress	- This rule is for this IP.
	wanPortFrom	- External start Port.
	wanPortTo	- External end Port.
	lanPortFrom	- Internal start port.
	lanPortTo		- Internal end port.
	protocol		- protocol. eg:	TCP / UDP / TCP+UDP
	comment		- Comment of each rule
</pre>
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
* @author rockey
* @date   2017-11-07
*/
int setPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *ip = websGetVar(data, T("ipAddress"), T(""));
	char *wan_from = websGetVar(data, T("wanPortFrom"), T(""));
	char *wan_to = websGetVar(data, T("wanPortTo"), T(""));
	char *lan_from = websGetVar(data, T("lanPortFrom"), T(""));
	char *lan_to = websGetVar(data, T("lanPortTo"), T(""));	
	char *protocol = websGetVar(data, T("protocol"), T(""));
	char *comment = websGetVar(data, T("comment"), T(""));
	int i=0,j=0;
	PORTFW_T entry;
	memset(&entry, '\0', sizeof(entry));

	if (addEffect){
		apmib_set(MIB_PORTFW_ENABLED, (void *)&enabled);
	}else{		
		// entry.fromPort   & entry.toPort   <---->  wan_from & wan_to
		// entry.fromPort2 & entry.toPort2  <---->  lan_from  & lan_to		
		inet_aton(ip, (struct in_addr *)&entry.ipAddr);
		entry.fromPort = (unsigned short)atoi(wan_from);
		entry.toPort   = (unsigned short)atoi(wan_to);
		entry.fromPort2= (unsigned short)atoi(lan_from);
		entry.toPort2  = (unsigned short)atoi(lan_to);
		if(!strcmp(protocol, T("TCP"))){
			entry.protoType = PROTO_TCP;
		}else if(!strcmp(protocol, T("UDP"))){
			entry.protoType = PROTO_UDP;
		}else if(!strcmp(protocol, T("TCP&UDP"))){
			entry.protoType = PROTO_BOTH;
		}else
			return;
		
		strcpy((char *)entry.comment, comment);					
		apmib_set(MIB_PORTFW_DEL, (void *)&entry);
		apmib_set(MIB_PORTFW_ADD, (void *)&entry);
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;
}

/**
* @note getPortForwardRules - Get current Port Forward filtering list.
* @param {}
*
* @return Return Json Data
<pre>
[
	{
		"enabled":"1",
		"lanNetmask":"255.255.255.0",
		"lanIp":"192.168.0.1"
	},
	{
		"idx":"1",
		"ipAddress":"192.168.0.10",
		"protocol":"TCP+UDP",
		"wanPortFrom":"5100",
		"wanPortTo":"5100",
		"lanPortFrom":"5000",
		"lanPortTo":"5000",
		"comment":"abcdefg",
		"delRuleName":"delRule0"
	}
]
Return parameter description:
	enabled		- On/Off IP port filter. eg:1 Enable,0 Disbale
	lanNetmask	- Router LAN netmask.
	lanIp		- Router LAN IP.
	idx 			- Rule list index,starting at 1.
	ipAddress	- This rule is for this IP.
	protocol		- Protocol. eg:	TCP/ UDP/ TCP+UDP
	wanPortFrom	- External start Port
	wanPortTo	- External end Port
	lanPortFrom	- Internal start port
	lanPortTo		- Internal end port
	comment		- Comment of each rule
	delRuleName 	- Index for deletion
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	PORTFW_T entry;
	int i=0, len=0, tmpint, entryNum;
	char *type,*ip;
	char responseStr[4096],lanIp[32],lanNetmask[32];
	int remoteCfg = 0;
	memset(responseStr,0,sizeof(responseStr));	
	apmib_get(MIB_PORTFW_ENABLED, (void *)&tmpint);
	getLanIp(lanIp);
	getLanNetmask(lanNetmask);
	apmib_get(MIB_WEB_WAN_ACCESS_PORT, (void *)&remoteCfg);	
	snprintf(responseStr, (sizeof(responseStr) - len), \
		     "[{\"enable\":\"%d\",\"lanNetmask\":\"%s\",\"lanIp\":\"%s\",\"remoteCfg\":\"%d\"}\n", \
		     tmpint, lanNetmask, lanIp, remoteCfg);
	len = strlen(responseStr);
	
	apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}
	
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if (!apmib_get(MIB_PORTFW_TBL, (void *)&entry))
			return -1;
		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if (!strcmp(ip, "0.0.0.0"))
			ip = "----";
		if (entry.protoType == PROTO_BOTH)
			type = "TCP+UDP";
		else if (entry.protoType == PROTO_TCP)
			type = "TCP";
		else
			type = "UDP";
		snprintf((responseStr + len), (sizeof(responseStr) - len),\
			",{\"idx\":\"%d\",\"ip\":\"%s\",\"proto\":\"%s\",\"wanPortFrom\":\"%d\",\"wanPortTo\":\"%d\",\"lanPortFrom\":\"%d\",\"lanPortTo\":\"%d\",\"comment\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			i,ip,type, entry.fromPort,entry.toPort,entry.fromPort2,entry.toPort2,entry.comment,i-1);
		len = strlen(responseStr);
	}
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);	
	websGetCfgResponse(mosq,tp,responseStr);	
	return 0;	
}

/**
* @note delPortForwardRules - Delete current port forward filtering rules.
* 
* @param data
<pre>
{
	"delRule0": 0,
	"delRule1": 1,
	"delRule2": 2
	...
}
Parameter description:
	delRule- - If the value is passed, delete this item.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int delPortForwardRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum;
	char name_buf[16];
	char *value;
	PORTFW_T entry;
	
	apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&entry) = (char)i;
			apmib_get(MIB_PORTFW_TBL, (void *)&entry);
			apmib_set(MIB_PORTFW_DEL, (void *)&entry);			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note setVpnPassCfg - Set current VPN Passthrough config.
*
* @param data
<pre>
{
	"wanPingFilter":	"1",
	"l2tpPassThru":	 	"1",
	"pptpPassThru":		"1",
	"ipsecPassThru":	"1"
}
Return parameter description:
	wanPingFilter 	- Ping Access on WAN. eg: 1 enable, 0 disable
	l2tpPassThru	- L2TP passthrough.   eg: 1 enable, 0 disable 
	pptpPassThru	- PPTP passthrough.   eg: 1 enable, 0 disable 
	ipsecPassThru	- IPSec passthrough.  eg: 1 enable, 0 disable 
</pre>
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setVpnPassCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int  wan_filter = atoi(websGetVar(data, T("wanPingFilter"), T("0")));
	int  l2tp_pt = atoi(websGetVar(data, T("l2tpPassThru"), T("0")));
	int  pptp_pt = atoi(websGetVar(data, T("pptpPassThru"), T("0")));
	int  ipsec_pt = atoi(websGetVar(data, T("ipsecPassThru"), T("0")));
	
	apmib_set(MIB_PING_WAN_ACCESS_ENABLED,(void *)&wan_filter);
	apmib_set(MIB_VPN_PASSTHRU_L2TP_ENABLED,(void *)&l2tp_pt);
	apmib_set(MIB_VPN_PASSTHRU_PPTP_ENABLED,(void *)&pptp_pt);
	apmib_set(MIB_VPN_PASSTHRU_IPSEC_ENABLED,(void *)&ipsec_pt);

	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;
}

/**
* @note getVpnPassCfg - Get current VPN Passthrough config.
*
* @param {}
*
* @return Return Json Data
<pre>
{
	"wanPingFilter":	"0",
	"l2tpPassThru":		"1",
	"pptpPassThru":		"1",
	"ipsecPassThru":	"1"
}
Return parameter description:
	wanPingFilter 	- Ping Access on WAN. eg: 1 enable, 0 disable
	l2tpPassThru	- L2TP passthrough.   eg: 1 enable, 0 disable 
	pptpPassThru	- PPTP passthrough.   eg: 1 enable, 0 disable 
	ipsecPassThru	- IPSec passthrough.  eg: 1 enable, 0 disable 
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getVpnPassCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char *output;
    cJSON *root=cJSON_CreateObject();
    int intVal;
  
	apmib_get(MIB_PING_WAN_ACCESS_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"wanPingFilter",intVal);
	
	apmib_get(MIB_VPN_PASSTHRU_L2TP_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"l2tpPassThru",intVal);
	
	apmib_get(MIB_VPN_PASSTHRU_PPTP_ENABLED, (void *)&intVal);	
	cJSON_AddNumberToObject(root,"pptpPassThru",intVal);
	
	apmib_get(MIB_VPN_PASSTHRU_IPSEC_ENABLED, (void *)&intVal);	
	cJSON_AddNumberToObject(root,"ipsecPassThru",intVal);
	
    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}

/**
* @note setDmzCfg - Set current DMZ config.
*
* @param data
<pre>
{
	"dmzEnabled":	"1",
	"dmzAddress":	"192.168.0.10"
}
parameter description:
	dmzEnabled 	- On/Off DMZ. eg:1 Enable,0 Disbale.
	dmzAddress	- DMZ host IP address.
</pre>
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setDMZCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *enabled = atoi(websGetVar(data, T("dmzEnabled"), T("0")));
	char *ip = websGetVar(data, T("dmzAddress"), T(""));
	struct in_addr ipAddr;
	
	apmib_set(MIB_DMZ_ENABLED, (void *)&enabled);
	if (enabled){
		inet_aton(ip, &ipAddr);
		apmib_set(MIB_DMZ_HOST, (void *)&ipAddr);
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;   
}

/**
* @note getDmzCfg - Get current DMZ config.
*
* @param {}
*
* @return Return Json Data
<pre>
{
	"dmzEnabled":	"1",
	"dmzAddress":	"192.168.0.10",
	"lanIp":			"192.168.0.1",
	"lanNetmask":		"255.255.255.0",
	"stationIp":		"192.168.0.20"
}
Return parameter description:
	dmzEnabled 	- On/Off DMZ. eg:1 Enable,0 Disbale.
	dmzAddress	- DMZ host IP address.
	lanIp		- Router LAN IP.
	lanNetmask	- Router LAN netmask.
	stationIp		- The current computer IP connection
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getDMZCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	char *sta_ip = websGetVar(data, T("stationIp"), T(""));
    char *output;
    cJSON *root=cJSON_CreateObject();
    int intVal;;
	char lanIp[32]={0},lanNetmask[32]={0},dmzAddress[32]={0};
	
	getLanIp(lanIp);
	getLanNetmask(lanNetmask);
	
	apmib_get(MIB_DMZ_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"dmzEnabled",intVal);
	
	apmib_get(MIB_DMZ_HOST, (void *)dmzAddress);		
	if(!strcmp(inet_ntoa(*((struct in_addr *)dmzAddress)), "0.0.0.0"))
		cJSON_AddStringToObject(root,"dmzAddress","");
	else
		cJSON_AddStringToObject(root,"dmzAddress",inet_ntoa(*((struct in_addr *)dmzAddress)));

	cJSON_AddStringToObject(root,"lanIp",lanIp);
	cJSON_AddStringToObject(root,"lanNetmask",lanNetmask);	
	cJSON_AddStringToObject(root,"stationIp",sta_ip);	

    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}

/**
* @note setRemoteCfg - Set Remote config.
*
* @param data
<pre>
{
	"remoteEnabled":	"1",
	"port":	"80"
}
parameter description:
	remoteEnabled 	- On/Off . eg:1 Enable,0 Disbale.
	port	- port.
</pre>
*
* @return Default JSON returns 
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setRemoteCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int enabled = atoi(websGetVar(data, T("remoteEnabled"), T("0")));
	int port = atoi(websGetVar(data, T("port"), T("")));

	apmib_set(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&enabled);
	if (enabled){
		apmib_set(MIB_WEB_WAN_ACCESS_PORT, (void *)&port);
	}
	
   	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0; 
}

/**
* @note getRemoteCfg - Get Remote config.
*
* @param {}
*
* @return Return Json Data
<pre>
{
	"remoteEnabled":	"1",
	"port":	"80",
	"csid":	"CS182R"
}
Return parameter description:
	remoteEnabled 	- On/Off . eg:1 Enable,0 Disbale.
	port		- port.
	csid		- CSID
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getRemoteCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char *output;
    cJSON *root=cJSON_CreateObject();
    int intVal, entryNum, len = 0, remoteEnabled, port, i;
	char csid[32]={0}, responseStr[4096];
	PORTFW_T entry;

	apmib_get(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&remoteEnabled);
	apmib_get(MIB_WEB_WAN_ACCESS_PORT, (void *)&port);
	apmib_get(MIB_CSID, (void *)csid);	
	memset(responseStr,0,sizeof(responseStr));		
	snprintf(responseStr, (sizeof(responseStr) - len), \
	     "{\"remoteEnabled\":\"%d\",\"port\":\"%d\",\"csid\":\"%s\"}\n", \
	     remoteEnabled, port, csid);
	len = strlen(responseStr);

	apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
	if(entryNum!=0){	
		for (i=1; i<=entryNum; i++) {
			*((char *)&entry) = (char)i;
			if ( !apmib_get(MIB_PORTFW_TBL, (void *)&entry))
				break;
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
				",{\"wanPortFrom\":\"%d\",\"lanPortFrom\":\"%d\"}\n",\
				entry.fromPort,entry.fromPort2);
			len = strlen(responseStr);
		}
	}
    websGetCfgResponse(mosq,tp,responseStr);
    return 0;
}

static char *ScheduleSetWeek(char *WeekBuf)
{
	char member[8][8] = {0}, tmp[8] = {0};
	static char week[32];
	int flag = 0, i = 0, n = 0;
	n = splitString2Arr_v2(WeekBuf, member, 8, 8, ',');
	for(i=0; i<n; i++){
		if(atoi(member[i]) == 1){
			if(flag == 0)
				sprintf(week,"%d",i+1);
			else if(flag == 1){
				sprintf(tmp,",%d",i+1);
				strcat(week,tmp);
			}
			flag = 1;
		}
	}
	
	return week;
}

static char *ScheduleGetWeek(char *WeekBuf)
{
	int flagWeek=0;
	static char week[32];

	memset(week, 0, 32);	

	if(strstr(WeekBuf,"1"))
	{
		sprintf(week,"Mon");
		flagWeek=1;
	}
	if(strstr(WeekBuf,"2"))
	{
		if(flagWeek)
		{
			strcat(week," Tue");
		}
		else
		{
			sprintf(week,"Tue");
			flagWeek=1;
		}
	}
	if(strstr(WeekBuf,"3"))
	{
		if(flagWeek)
		{
			strcat(week," Wed");
		}
		else
		{
			sprintf(week,"Wed");
			flagWeek=1;
		}
	}
	if(strstr(WeekBuf,"4"))
	{
		if(flagWeek)
		{
			strcat(week," Thu");
		}
		else
		{
			sprintf(week,"Thu");
			flagWeek=1;
		}
	}
	if(strstr(WeekBuf,"5"))
	{
		if(flagWeek)
		{
			strcat(week," Fri");
		}
		else
		{
			sprintf(week,"Fri");
			flagWeek=1;
		}
	}
	if(strstr(WeekBuf,"6"))
	{
		if(flagWeek)
		{
			strcat(week," Sat");
		}
		else
		{
			sprintf(week,"Sat");
			flagWeek=1;
		}
	}
	if(strstr(WeekBuf,"7"))
	{
		if(flagWeek)
		{
			strcat(week," Sun");
		}
		else
		{
			sprintf(week,"Sun");
			flagWeek=1;
		}
	}	
	return week;
}

int setIpportMacRuleSwitch(SCHEFILTER_T scheEntry, int val)
{
	IPFILTER_T entry_ip[2]={0}, entry_ip_check;
	MACFILTER_T entry_mac[2]={0}, entry_mac_check;
	int i,num;
	char buf[128]={0}, comment[128]={0};
	char *ip=NULL;
	ip = inet_ntoa(*((struct in_addr *)scheEntry.ipAddr));
	if(!strcmp(ip, "0.0.0.0")){//mac
		apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&num);
		for (i=1; i<=num; i++) {
			*((char *)&entry_mac_check) = (char)i;
			apmib_get(MIB_MACFILTER_TBL, (void *)&entry_mac_check);
		
			if( !memcmp(scheEntry.macAddr, entry_mac_check.macAddr, 6)){
				memset(&entry_mac, '\0', sizeof(entry_mac));
				*((char *)(void *)&entry_mac) = (char)i;
				apmib_get(MIB_MACFILTER_TBL,(void*)&entry_mac);
				entry_mac[1] = entry_mac[0];
				strcpy(buf, entry_mac_check.comment + 1);
				if(val == 0)
					strcpy(comment, "0");
				else if(val == 1)
					strcpy(comment, "1");
				strcat(comment, buf);
				strcpy(entry_mac[1].comment, comment);
				apmib_set(MIB_MACFILTER_MOD, (void*)&entry_mac);
				break;
			}
		}
	}else{ //ipport
		apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&num);
		for (i=1; i<=num; i++) {
			*((char *)&entry_ip_check) = (char)i;
			apmib_get(MIB_IPFILTER_TBL, (void *)&entry_ip_check);
	
			if( !memcmp(entry_ip_check.ipAddr, scheEntry.ipAddr, 4) && 
			entry_ip_check.fromPort == scheEntry.fromPort && 
			entry_ip_check.toPort == scheEntry.toPort &&
			entry_ip_check.protoType == scheEntry.protoType ){
				memset(&entry_ip, '\0', sizeof(entry_ip));
				*((char *)(void *)&entry_ip) = (char)i;
				apmib_get(MIB_IPFILTER_TBL,(void*)&entry_ip);
				entry_ip[1] = entry_ip[0];
				strcpy(buf, entry_ip_check.comment + 1);
				if(val == 0)
					strcpy(comment, "0");
				else if(val == 1)
					strcpy(comment, "1");
				strcat(comment, buf);
				strcpy(entry_ip[1].comment, comment);
				apmib_set(MIB_IPFILTER_MOD, (void*)&entry_ip);
				break;
			}
		}
	}
	apmib_update_web(CURRENT_SETTING);

	return 0;
}

/**
* @note setScheduleRules  	--set the firewall rules of time.
*
* @param data
<pre>
{
	"scheduleRulesList":"1,0,14,11:11-22:22,add,192.168.0.10,TCP+UDP,1024-2048;2,0,14,11:11-22:22,add,00:e0:4c:36:06:f0;",
	"actionType":"add"
}
or
{
	"scheduleDelRulesList":"delRuleName,1;delRuleName,0;",
	"actionType":"del"
}
Parameter description:
	actionType 		--action type [add : add rules  del : delete rules]
	scheduleRulesList 	--add the firewall schedule rule,the two rules are separated by semicolons.
	scheduleDelRulesList	--delete the firewall schedule rule
</pre>
*
* @return   json str format
<pre>
{
    "success":	true,
    "error":	null,
    "lan_ip":	"192.168.0.1",
    "wtime":	"0",
    "reserv":	"reserv"
}
</pre>
*
* @author	rockey
* @date		2017-11-07
*/
int setScheduleRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i=0, n=0, num=0, action=0, entryNum=0, scheListLen=0;
	char macbuf[40]={0}, ruleIndex[8]={0}, ruleType[8]={0}, deltmp[32]={0}, del_i[8]={0};
	char *actiontmp, *week, *time, *delRuleName;
	cJSON *scheList, *scherule;
	
	SCHEFILTER_T Entry, EntryDel, EntryModify[2];
	IPFILTER_T entry_ip;
	MACFILTER_T entry_mac;

	actiontmp = websGetVar(data, T("action"), T(""));
	if(!strcmp("add", actiontmp)){ //add
		action = 0;
	}else if(!strcmp("del", actiontmp)){//del
		action = 1;
	}
	
	scheList = cJSON_GetArrayItem(data,1);
	scheListLen=cJSON_GetArraySize(scheList);
	for(n=0; n<scheListLen; n++){
		scherule = cJSON_GetArrayItem(scheList,n);
		week = websGetVar(scherule, T("week"), T(""));
		time = websGetVar(scherule, T("time"), T(""));
		delRuleName = websGetVar(scherule, T("delRuleName"), T(""));
		getNthValueSafe(0, delRuleName, ',', ruleType, sizeof(ruleType));
		getNthValueSafe(1, delRuleName, ',', ruleIndex, sizeof(ruleIndex));
		if(atoi(ruleType) != 3){ 
			if(action == 0){
				if(atoi(ruleType) == 1){ //ipport
					apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
					if(entryNum != 0){
						i = atoi(ruleIndex);
						*((char *)&entry_ip) = (char)i;
						apmib_get(MIB_IPFILTER_TBL, (void *)&entry_ip);
					}

					inet_aton(inet_ntoa(*((struct in_addr *)entry_ip.ipAddr)), (struct in_addr *)&Entry.ipAddr);
					Entry.protoType=entry_ip.protoType;
					Entry.fromPort=entry_ip.fromPort;
					Entry.toPort=entry_ip.toPort;
					string_to_hex("000000000000", Entry.macAddr, 12);
				}else if(atoi(ruleType) == 2){ //mac
					apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
					if(entryNum != 0){
						i = atoi(ruleIndex);
						*((char *)&entry_mac) = (char)i;
						apmib_get(MIB_MACFILTER_TBL, (void *)&entry_mac);
					}

					inet_aton("0.0.0.0", (struct in_addr *)&Entry.ipAddr);
					Entry.protoType = 0;
					Entry.fromPort = 0;
					Entry.toPort = 0;
					snprintf(macbuf, 32, ("%02X%02X%02X%02X%02X%02X"),
					entry_mac.macAddr[0], entry_mac.macAddr[1], entry_mac.macAddr[2],
					entry_mac.macAddr[3], entry_mac.macAddr[4], entry_mac.macAddr[5]);
					
					string_to_hex(macbuf, Entry.macAddr, 12);	
				}

				strcpy((char *)Entry.day,ScheduleSetWeek(week));
				strcpy((char *)Entry.stime,strtok(time, "-"));
				strcpy((char *)Entry.ttime, strtok(NULL, "-"));
				apmib_set(MIB_SCHEFILTER_ADD,(void *)&Entry);
				setIpportMacRuleSwitch(Entry,0);
			}
		}else{ //sche
			if(action == 0){ //add(modify)
				i = atoi(ruleIndex);
				memset(&EntryModify, '\0', sizeof(EntryModify));
				*((char *)&EntryModify) = (char)i;
				apmib_get(MIB_SCHEFILTER_TBL, (void *)&EntryModify);
				EntryModify[1] = EntryModify[0];
				
				strcpy((char *)EntryModify[1].day,ScheduleSetWeek(week));
				strcpy((char *)EntryModify[1].stime,strtok(time, "-"));
				strcpy((char *)EntryModify[1].ttime, strtok(NULL, "-"));
				apmib_set(MIB_SCHEFILTER_MOD,(void *)&EntryModify);
			}else if(action == 1){ //del
				i = atoi(ruleIndex);
				*((char *)&EntryDel) = (char)i;
				apmib_get(MIB_SCHEFILTER_TBL, (void *)&EntryDel);
				setIpportMacRuleSwitch(EntryDel,1);
				strcat(deltmp,ruleIndex);
				strcat(deltmp,",");
			}			
		}
	}

	apmib_get(MIB_SCHEFILTER_TBL_NUM, (void *)&num);
	for (i=num; i>0; i--) {
		sprintf(del_i,"%d,",i);
		if(strstr(deltmp,del_i)){
			memset(&Entry, '\0', sizeof(Entry));
			*((char *)&Entry) = (char)i;
			apmib_get(MIB_SCHEFILTER_TBL, (void *)&Entry);
			apmib_set(MIB_SCHEFILTER_DEL, (void *)&Entry);
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("csteSys fwSch");
	system("csteSys updateCrond");
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");  
	return;
}

void showtime(char *week,char *time, unsigned char *addr, int proto, int fport, int tport, char *flg )
{
	SCHEFILTER_T Entry;
	int i, num;
	
	if(!apmib_get(MIB_SCHEFILTER_TBL_NUM, (void *)&num))
		goto Err;
	
	for (i=1; i<=num; i++) {
		*((char *)&Entry) = (char)i;
		if ( !apmib_get(MIB_SCHEFILTER_TBL, (void *)&Entry)) 
			goto Err;
		if( !memcmp(Entry.macAddr, addr, 6) && !strcmp(flg,"mac")){          
			sprintf(week, "%s", Entry.day);
			sprintf(time, "%s-%s",Entry.stime, Entry.ttime);			
			return;
		}
		
		if( !memcmp(Entry.ipAddr, addr, 4) && 
			Entry.fromPort == fport && 
			Entry.toPort == tport &&
			Entry.protoType == proto&& 
		    !strcmp(flg,"ip"))
		{
			sprintf(week, "%s", Entry.day);
			sprintf(time, "%s-%s",Entry.stime, Entry.ttime);
			return;
		}
	}
	return;

Err:
	strcpy(week, "1,2,3,4,5,6,7");
	strcpy(time, "00:00-23:59");
	return ;
}

/**
* @note getScheduleRules --Get a list of scheduling information
*
* @return   json str format
<pre>
{
	"itemList":	[{
			"firewallMode":	"IPPORT",
			"ipAddress":	"192.168.0.10",
			"protocol":	"TCP+UDP",
			"portRange":	"1024-2048",
		}, {
			"firewallMode":	"MAC",
			"macAddress":	"00:e0:4c:36:06:f0",
		}],
	"scheList":	[{
			"schFirewallMode":	"IPPORT",
			"schIp":	"192.168.0.10",
			"schProtocol":	"TCP+UDP",
			"schPortRange":	"1024-2048",
			"schWeek":	"Mon Tue Wed",
			"schTime":	"11:11-22:22",
			"schComment":	"abcdef",
			"schDelRuleName":	"0"
		}, {
			"schFirewallMode":	"MAC",
			"schMac":	"00:e0:4c:36:06:f0",
			"schWeek":	"Mon Tue Wed",
			"schTime":	"11:11-22:22",
			"schComment":	"abcdef",
			"schDelRuleName":	"1"
		}]
}
Return parameter description:
	itemList 		--Firewall rule list.
	firewallMode	--Firewall type.
	ipAddress		--The IP address of this rule.
	protocol		--Protocol type.
	portRange 		--Port range.
	macAddress	 	--The MAC address of this rule.
	scheList		--Firewall time scheduling rule list.
	schFirewallMode	--Firewall type of scheduling rule.
	schIp			--The IP address of this scheduling rule.
	schMac			--The MAC address of this scheduling rule.
	schProtocol		--Protocol type of this scheduling rule.
	schPortRange	--Port range of this scheduling rule.
	schWeek			--Date of this scheduling rule.
	schTime			--Time of this scheduling rule.
	schComment		--description of this rule.
	schDelRuleName	--The serial number deleted.
</pre>
*
* @author rockey
* @date    2017-11-07
*/
int getScheduleRules(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	int entryNum, i;
	char mac[100], portRange[20], week[50]={0}, time[50]={0}, delRuleName[8]={0};
	char *ip,*type,*output;
	cJSON *root;
	
	MACFILTER_T entry_mac;
	IPFILTER_T entry_ip;
	SCHEFILTER_T Entry;	
	
	root = cJSON_CreateArray();

	//ipport
	apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum != 0){
		for (i=1; i<=entryNum; i++) {
			*((char *)&entry_ip) = (char)i;
			apmib_get(MIB_IPFILTER_TBL, (void *)&entry_ip);	
			if(strncmp("1", entry_ip.comment, 1) == 0){
				ip = inet_ntoa(*((struct in_addr *)entry_ip.ipAddr));
				if ( entry_ip.protoType == PROTO_BOTH )
					type = "TCP+UDP";
				else if ( entry_ip.protoType == PROTO_TCP )
					type = "TCP";
				else
					type = "UDP";

				snprintf(portRange, 20, "%d-%d", entry_ip.fromPort, entry_ip.toPort);

				cJSON *ipportfilter = cJSON_CreateObject();
				cJSON_AddStringToObject(ipportfilter, "firewallMode", "IPPORT");
				cJSON_AddStringToObject(ipportfilter, "ip", ip);
				cJSON_AddStringToObject(ipportfilter, "proto", type);
				cJSON_AddStringToObject(ipportfilter, "portRange", portRange);
				cJSON_AddStringToObject(ipportfilter, "week", "Mon Tue Wed Thu Fri Sat Sun");
				cJSON_AddStringToObject(ipportfilter, "time", "00:00-23:59");
				sprintf(delRuleName, "1,%d", i);
				cJSON_AddStringToObject(ipportfilter, "delRuleName", delRuleName);
				cJSON_AddItemToArray(root,ipportfilter);
			}
		}
	}
	//mac
	apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum != 0){
		for (i=1; i<=entryNum; i++) {
			*((char *)&entry_mac) = (char)i;
			apmib_get(MIB_MACFILTER_TBL, (void *)&entry_mac);
			if(strncmp("1", entry_mac.comment, 1) == 0){
				snprintf(mac, 100, ("%02X:%02X:%02X:%02X:%02X:%02X"),
				entry_mac.macAddr[0], entry_mac.macAddr[1], entry_mac.macAddr[2],
				entry_mac.macAddr[3], entry_mac.macAddr[4], entry_mac.macAddr[5]);
				
				cJSON *macfilter = cJSON_CreateObject();
				cJSON_AddStringToObject(macfilter, "firewallMode", "MAC");
				cJSON_AddStringToObject(macfilter, "mac", mac);
				cJSON_AddStringToObject(macfilter, "week", "Mon Tue Wed Thu Fri Sat Sun");
				cJSON_AddStringToObject(macfilter, "time", "00:00-23:59");
				memset(delRuleName, 0, sizeof(delRuleName));
				sprintf(delRuleName, "2,%d", i);
				cJSON_AddStringToObject(macfilter, "delRuleName", delRuleName);
				cJSON_AddItemToArray(root,macfilter);
			}
		}
	}

	apmib_get(MIB_SCHEFILTER_TBL_NUM, (void *)&entryNum);
	if(entryNum != 0){
		for (i=1; i<=entryNum; i++) {
			*((char *)&Entry) = (char)i;
			apmib_get(MIB_SCHEFILTER_TBL, (void *)&Entry);
			showtime(week,time,Entry.ipAddr,Entry.protoType,Entry.fromPort,Entry.toPort,"ip");				
			ip = inet_ntoa(*((struct in_addr *)Entry.ipAddr));
			if(strcmp(ip, "0.0.0.0")){//sch_ip
				if ( Entry.protoType == PROTO_BOTH )
					type = "TCP+UDP";
				else if ( Entry.protoType == PROTO_TCP )
					type = "TCP";
				else
					type = "UDP";
				if ( Entry.fromPort == Entry.toPort )
					snprintf(portRange, 20, "%d", Entry.fromPort);
				else
					snprintf(portRange, 20, "%d-%d", Entry.fromPort, Entry.toPort);
				
				cJSON *ipportfilter = cJSON_CreateObject();
				cJSON_AddStringToObject(ipportfilter, "firewallMode", "IPPORT");
				cJSON_AddStringToObject(ipportfilter, "ip", ip);
				cJSON_AddStringToObject(ipportfilter, "proto", type);
				cJSON_AddStringToObject(ipportfilter, "portRange", portRange);
				cJSON_AddStringToObject(ipportfilter, "week", ScheduleGetWeek(week));
				cJSON_AddStringToObject(ipportfilter, "time", time);
				sprintf(delRuleName, "3,%d", i);
				cJSON_AddStringToObject(ipportfilter, "delRuleName", delRuleName);
				cJSON_AddItemToArray(root,ipportfilter);
			}else{//sch_mac
				showtime(week,time, Entry.macAddr, 0, 0, 0,"mac");			
				snprintf(mac, 100, ("%02X:%02X:%02X:%02X:%02X:%02X"),
				Entry.macAddr[0], Entry.macAddr[1], Entry.macAddr[2],
				Entry.macAddr[3], Entry.macAddr[4], Entry.macAddr[5]);

				cJSON *macfilter = cJSON_CreateObject();
				cJSON_AddStringToObject(macfilter, "firewallMode", "MAC");
				cJSON_AddStringToObject(macfilter, "mac", mac);
				cJSON_AddStringToObject(macfilter, "week", ScheduleGetWeek(week));
				cJSON_AddStringToObject(macfilter, "time", time);
				memset(delRuleName, 0, sizeof(delRuleName));
				sprintf(delRuleName, "3,%d", i);
				cJSON_AddStringToObject(macfilter, "delRuleName", delRuleName);
				cJSON_AddItemToArray(root,macfilter);
			}
	    }
	}

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;	
}

int setMacQos(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	char macqos[24] = {0}, rules[256] = {0}, rules_buf[10][24];
	int rul_num = 0;
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	
	if (addEffect){		
		int enabled = atoi(websGetVar(data, T("enable"), T("0")));
		apmib_set(MIB_MACQOS_ENABLED, (void *)&enabled);
	}else{
		char *pri_type = websGetVar(data, T("priority"), T("1"));
		char *mac = websGetVar(data, T("macAddress"), T(""));

		if(strlen(mac)==0) return;
		sprintf(macqos, "%s#%s", mac, pri_type);

		apmib_get(MIB_MACQOS_RULE, (void *)rules);

		if(strlen(rules)){
			rul_num = splitString2Arr_v2(rules, rules_buf, 10, 24, ';');
		}

		if(rul_num == 0)
			strcpy(rules, macqos);
		else if(rul_num < 8){
			strcat(rules, ";");
			strcat(rules, macqos);
		}
		apmib_set(MIB_MACQOS_RULE, (void *)rules);
	}
	
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "10", "reserv");

	int pid;		
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		system("sysconf firewall");
		exit(1);
	}
	
	return 0;  
}

int isValueInArr(int val, int arr[], int len)
{
	int i = 0;
	for(i=0; i<len; ++i){
		if(val == arr[i])
			return 1;
	}
	return 0;
}

int delMacQosRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char rules[256] = {0}, rules_arr[10][24], name_buf[16];;
	int i=0,j=0, num1 = 0,  arr[10] = {0};
	char *value;

	apmib_get(MIB_MACQOS_RULE, (void *)rules);
	if(strlen(rules)){
		num1 = splitString2Arr_v2(rules, rules_arr, 10, 24, ';');
	}else{
		goto Err;
	}

	for(i=num1; i>0; i--){
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value != NULL){
			arr[j]=i;
			j++;
		}
	}

	for(i=0; i<num1; i++){
		if(isValueInArr((i+1), arr, j+1) == 1){
			rules_arr[i][0] = '\0';
		}
	}

	memset(rules, 0, sizeof(rules));
	for(i=0; i<num1; i++){
		if(rules_arr[i][0] != '\0'){
			strcat(rules, rules_arr[i]);
			strcat(rules, ";");
		}
	}
	if(strlen(rules) != 0)rules[strlen(rules)-1]='\0';
	
	apmib_set(MIB_MACQOS_RULE, (void *)rules);
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	
Err:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int getMacQosRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i=0,u=0, len=0, high_num=0,ultra_num=0,tmpint;
	char rules[256] = {0}, rules_buf[10][24] = {0}, macpri[2][24] = {0}, mactmp[24] = {0}, pritmp[24] = {0};
	int rul_num=0, int_pri=0;
	char responseStr[4096];	
	memset(responseStr,0,sizeof(responseStr));
	
	apmib_get(MIB_MACQOS_ENABLED, (void *)&tmpint);
	snprintf(responseStr, (sizeof(responseStr) - len), \
		     "[{\"enable\":\"%d\"}\n", tmpint);
	len = strlen(responseStr);

	apmib_get(MIB_MACQOS_RULE, (void *)rules);
	if(strlen(rules)<10){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}

	rul_num = splitString2Arr_v2(rules, rules_buf, 10, 24, ';');
	for(i=0; i<rul_num; i++){
		splitString2Arr_v2(rules_buf[i], macpri, 2, 24, '#');
		sprintf(mactmp,"%s",macpri[0]);
		int_pri=atoi(macpri[1]);
		if(int_pri==1){
			sprintf(pritmp,"high");
			high_num++;
			u=high_num;
		}else if(int_pri==2){
			sprintf(pritmp,"ultra");
			ultra_num++;
			u=ultra_num;
		}
		snprintf((responseStr + len), (sizeof(responseStr) - len),\
			      ",{\"idx\":\"%d\",\"mac\":\"%s\",\"priority\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			      u, mactmp, pritmp, i);
		len = strlen(responseStr);
	}
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);
	websGetCfgResponse(mosq,tp,responseStr);
	return 0;
}

/**
* @note setIpQos - Set current qos rules.
* 
* @param data
<pre>
{
	"enabled":"1",
	"manualUplinkSpeed":"100000",
	"manualDownlinkSpeed":"100000"
}
Parameter description:
	enabled				- On/Off of qos. eg:1 Enable,0 Disbale.
	manualUplinkSpeed 	- Total uplink bandwidth.
	manualDownlinkSpeed	- Total downlink bandwidth.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setIpQos(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	int manual_up = atoi(websGetVar(data, T("manualUplinkSpeed"), T("1000000")));
	int manual_down = atoi(websGetVar(data, T("manualDownlinkSpeed"), T("1000000")));

	apmib_set(MIB_QOS_ENABLED, (void *)&enabled);
	if(enabled){
		apmib_set( MIB_QOS_MANUAL_UPLINK_SPEED,(void *)&manual_up);
		apmib_set( MIB_QOS_MANUAL_DOWNLINK_SPEED, (void *)&manual_down);
	}	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;  
}

/**
* @note setIpQosRules - Set current qos rules.
* 
* @param data
<pre>
{
	"ipStart":"192.168.0.30",
	"ipEnd":"192.168.0.35",
	"upBandwidth":"2000",
	"downBandwidth":"2000",
	"comment":"abcdefg"
}
Parameter description:
	ipStart			- IP address range start of this rule.eg:192.168.0.2
	ipEnd 			- IP address range end of this rule.eg:192.168.0.25
	upBandwidth		- Uplink bandwidth of this rule.
	downBandwidth	- Downlink bandwidth of this rule.
	comment			- description of this rule.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int setIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int up_bandwidth = atoi(websGetVar(data, T("upBandwidth"), T("")));
	int down_bandwidth = atoi(websGetVar(data, T("dwBandwidth"), T("")));
	char *ip_start = websGetVar(data, T("ipStart"), T(""));
	char *ip_end = websGetVar(data, T("ipEnd"), T(""));
	char *comment = websGetVar(data, T("comment"), T(""));
	IPQOS_T entry;

	inet_aton(ip_start, (struct in_addr *)&entry.local_ip_start);
	inet_aton(ip_end, (struct in_addr *)&entry.local_ip_end);
	entry.mode = QOS_RESTRICT_IP;
	entry.protocol=0;
	entry.enabled=1;
	entry.vlan_pri=ADVANCED_IPQOS_DEF_CHAR_VALUE;

	strcpy((char *)entry.l7_protocol,"");
	entry.bandwidth=(unsigned long)up_bandwidth;
	entry.bandwidth_downlink=(unsigned long)down_bandwidth;
	strcpy((char *)entry.entry_name,comment);
	
	apmib_set(MIB_QOS_DEL, (void *)&entry);
	apmib_set(MIB_QOS_ADD, (void *)&entry);

	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	  
	return 0;  
}

/**
* @note delIpQosRules - Delete current qos rules.
* 
* @param data
<pre>
{
  	"delRule0": 0,
  	"delRule1": 1,
  	"delRule2": 2
  	...
}
Parameter description:
	delRule- - If the value is passed, delete this item.
</pre>
*
* @return Default JSON returns  
<pre>
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int delIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	int i,entryNum;
	char name_buf[16];
	char *value;
	IPQOS_T entry;
	
	apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&entry) = (char)i;
			apmib_get(MIB_QOS_RULE_TBL, (void *)&entry);
			apmib_set(MIB_QOS_DEL, (void *)&entry);			
		}
	}
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

/**
* @note getIpQosRules - Get Current qos rules List 
*
* @param {}
*
* @return Return Json Data
<pre>
[
	{
		"enabled":	1,
		"manualUpSpeed":	100000,
		"manualDwSpeed":	100000,
		"lanIp":	"192.168.0.1",
		"lanNetmask":	"255.255.255.0"
	},
	{
		"idx":	1,
		"ipAddress":	"192.168.0.2-192.168.0.25",
		"upBandwidth":	1000,
		"dwBandwidth":	1000,
		"comment":	"abcdefg",
		"delRuleName":	"delRule0"
	}
]
Return parameter description:
	enabled			- On/Off MAC filter. eg:1 Enable,0 Disbale.
	manualUpSpeed	- Total uplink bandwidth.
	manualDwSpeed	- Total downlink bandwidth.
	lanIp			- Router LAN IP.
	lanNetmask		- Router LAN netmask.
	idx 			- Rule list index,starting at 1.
	ipAddress		- IP address range of this rule.eg:192.168.0.2-192.168.0.25
	upBandwidth		- Uplink bandwidth of this rule.
	dwBandwidth		- Downlink bandwidth of this rule.
	comment			- Comment of this rule.
	delRuleName		- Index for deletion.
</pre>
*
* @author rockey
* @date   2017-11-07
*/
int getIpQosRules(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char lanIp[32]={0},lanNetmask[32]={0},hostname[64]={0},csid[32]={0};	
	int i=0,j,tmpint, entryNum,upSpeed,dwSpeed;
	char mac_addr[40]={0},ipstart[32]={0},ipend[32]={0};
	char tmpbuf[64],*output;
	IPQOS_T entry;

	cJSON *rules_arry,*root;
	rules_arry=cJSON_CreateArray();
	root=cJSON_CreateObject();
	cJSON_AddItemToArray(rules_arry,root);

	getLanIp(lanIp);
	getLanNetmask(lanNetmask);
	apmib_get(MIB_QOS_ENABLED, (void *)&tmpint);
	apmib_get(MIB_QOS_MANUAL_UPLINK_SPEED,  (void *)&upSpeed);
	apmib_get(MIB_QOS_MANUAL_DOWNLINK_SPEED,  (void *)&dwSpeed);
	apmib_get(MIB_CSID,(void *)&csid);

	cJSON_AddNumberToObject(root,"enable",tmpint);
	cJSON_AddNumberToObject(root,"manualUpSpeed",upSpeed);
	cJSON_AddNumberToObject(root,"manualDwSpeed",dwSpeed);
	cJSON_AddStringToObject(root,"lanIp",lanIp);
	cJSON_AddStringToObject(root,"lanNetmask",lanNetmask);
#if defined(CONFIG_RTL_8367R_SUPPORT)
	cJSON_AddNumberToObject(root,"gigaBitBt",1);
#else
	cJSON_AddNumberToObject(root,"gigaBitBt",0);
#endif
#if defined(CONFIG_RTL_8211F_SUPPORT)
	cJSON_AddNumberToObject(root,"wanGigabitBt",1);
#else
	cJSON_AddNumberToObject(root,"wanGigabitBt",0);
#endif	

	apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum);
	if(entryNum==0){
		goto end_label;
	}
	
	for (i=1; i<=entryNum; i++){
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry)){
			goto end_label;
		}
		memset(hostname, '\0', sizeof(hostname));
		if(entry.entry_name&&strlen(entry.entry_name)>0){
			strncpy(hostname, entry.entry_name, strlen(entry.entry_name));
			hostname[strlen(entry.entry_name)]='\0';
		}

		root=cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"idx",i);
		
#if 0
		sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]);
		cJSON_AddStringToObject(root,"mac",mac_addr);
#else
		strcpy(ipstart,inet_ntoa(*((struct in_addr *)entry.local_ip_start)));
		strcpy(ipend,inet_ntoa(*((struct in_addr *)entry.local_ip_end)));
		sprintf(tmpbuf,"%s-%s",ipstart,ipend);
		cJSON_AddStringToObject(root,"ip",tmpbuf);
#endif
		cJSON_AddNumberToObject(root,"upBandwidth",entry.bandwidth);
		cJSON_AddNumberToObject(root,"dwBandwidth",entry.bandwidth_downlink);
		cJSON_AddStringToObject(root,"comment",hostname);
		sprintf(tmpbuf,"delRule%d",i-1);
		cJSON_AddStringToObject(root,"delRuleName",tmpbuf);
		cJSON_AddItemToArray(rules_arry,root);
	}
	
end_label:
	output=cJSON_Print(rules_arry);
    websGetCfgResponse(mosq,tp,output);	
	free(output);
    cJSON_Delete(rules_arry);
	return 0;
}

#if defined(CONFIG_PA_ONLINE_IP)
	
int getNums(char *value, char delimit)
{
    char *pos = value;
    int count=1;
    if(!pos)
        return 0;
    while( (pos = strchr(pos, delimit))){
        pos = pos+1;
        count++;
    }
    return count;
}

int setIpQosLimit(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char ipqos_limit_rule[4096]={0},curQosRules[4096]={0},cmd[128]={0};
	char *enaIpQosLimit, *addEffect; 
	char *ip_start, *ip_end, *up_bandwidth, *down_bandwidth, *entryid, *comment;

	struct in_addr s;
	int enabled = 0,count=0;
	
	enaIpQosLimit = websGetVar(data, T("enable"), T(""));
	addEffect = websGetVar(data, T("addEffect"), T("0"));
	ip_start = websGetVar(data, T("ipStart"), T(""));
	ip_end = websGetVar(data, T("ipEnd"), T(""));
	up_bandwidth = websGetVar(data, T("upBandwidth"), T(""));
	down_bandwidth = websGetVar(data, T("dwBandwidth"), T(""));
	entryid = websGetVar(data, T("index"), T(""));
	comment = websGetVar(data, T("comment"), T(""));

	if(atoi(addEffect)){
		enabled=atoi(enaIpQosLimit);
		apmib_set(MIB_IPQOSLIMITENABLED, (void *)&enabled);
	}
	else{
		int rule_count;
		memset(curQosRules,0,sizeof(curQosRules));
		apmib_get(MIB_IPQOSLIMITRULES,(void *)curQosRules);
		
		if(strlen(curQosRules)==0)
			rule_count = 0;
		else
			rule_count = getNums((char *)ipqos_limit_rule,';');

		if (rule_count>FILTER_RULE_NUM)
			goto End_label;

		if( strlen(up_bandwidth) > 0 && strlen(down_bandwidth) > 0 ) {
			if( strlen(curQosRules) ) {
				snprintf(ipqos_limit_rule, sizeof(ipqos_limit_rule), "%s;%s,%s,%d,%d,%d,%s",  
				curQosRules, ip_start, ip_end, atoi(up_bandwidth), atoi(down_bandwidth),6, comment);
			}
			else{
				snprintf(ipqos_limit_rule, sizeof(ipqos_limit_rule), "%s,%s,%d,%d,%d,%s",  
				ip_start, ip_end, atoi(up_bandwidth), atoi(down_bandwidth), 6, comment);
			}
			apmib_set(MIB_IPQOSLIMITRULES, (void *)ipqos_limit_rule);
	
			count=getNums((char *)ipqos_limit_rule,';');
			apmib_set(MIB_IPQOSLIMITNUM, (void *)&count);
		}
	}

	apmib_update_web(CURRENT_SETTING);
	system("sysconf ibmsiplimit");
	
End_label:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int getIpQosLimit(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i = 0, rule_count = 0, tmpint = 0;
	char rules[4096]={0},tmpBuf[32]={0},rec[128]={0},delNum[16]={0};
	char ipStart[32]={0}, ipEnd[32]={0}, upBandwidth[8]={0}, dwBandwidth[8]={0}, entryid[8]={0}, comment[128]={0};

	cJSON *connArray, *connEntry;
	char *output = NULL;
	
	connArray = cJSON_CreateArray();
	
	connEntry = cJSON_CreateObject();
	cJSON_AddItemToArray(connArray,connEntry);
	
	apmib_get(MIB_IPQOSLIMITENABLED, (void *)&tmpint);
	sprintf(tmpBuf,"%d",tmpint);
	cJSON_AddStringToObject(connEntry, "enable", tmpBuf);

	getIfIp("br0",tmpBuf);
	cJSON_AddStringToObject(connEntry, "lanIp", tmpBuf);
	memset(tmpBuf, 0, sizeof(tmpBuf));
	getIfMask("br0",tmpBuf);
	cJSON_AddStringToObject(connEntry, "lanNetmask", tmpBuf);

	memset(rules,0,sizeof(rules));
	apmib_get(MIB_IPQOSLIMITRULES,(void *)rules);
	
	if(strlen(rules)==0)
		rule_count = 0;
	else
		rule_count = getNums((char *)rules,';');

	if (rule_count>FILTER_RULE_NUM){
		goto End_label;
	}
	
	for(i = 0; i < rule_count; i++){
		getNthValueSafe(i, rules, ';', rec, sizeof(rec));
		connEntry = cJSON_CreateObject();
		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "%d", i);
		cJSON_AddStringToObject(connEntry, "idx", tmpBuf);
		getNthValueSafe(0, rec, ',', ipStart, sizeof(ipStart));
		cJSON_AddStringToObject(connEntry, "ipStart", ipStart);
		getNthValueSafe(1, rec, ',', ipEnd, sizeof(ipEnd));
		cJSON_AddStringToObject(connEntry, "ipEnd", ipEnd);
		getNthValueSafe(2, rec, ',', upBandwidth, sizeof(upBandwidth));
		cJSON_AddStringToObject(connEntry, "upBandwidth", upBandwidth);
		getNthValueSafe(3, rec, ',', dwBandwidth, sizeof(dwBandwidth));
		cJSON_AddStringToObject(connEntry, "dwBandwidth", dwBandwidth);	
		getNthValueSafe(5, rec, ',', comment, sizeof(comment));
		cJSON_AddStringToObject(connEntry, "comment", comment);	
		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray,connEntry);
	}

End_label:
	output=cJSON_Print(connArray);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	return 0;
}

int delIpQosLimit(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i, j, rule_count;
	char rules[4096]={0},name_buf[16],buftmp[32];
	char *value,*new_rules;
	int *deleArray;

	memset(rules,0,sizeof(rules));
	apmib_get(MIB_IPQOSLIMITRULES,(void *)rules);
	apmib_get(MIB_IPQOSLIMITNUM, (void *)&rule_count);

   	if(!rules || !strlen(rules) || !rule_count )
    	goto End_label;

	deleArray = (int *)malloc(rule_count * sizeof(int));
	if(!deleArray)
		goto End_label;
    	
	new_rules = strdup(rules);
	if(!new_rules){
		free(deleArray);
		goto End_label;
	}

	for(i=0, j=0; i< rule_count; i++){
    	snprintf(name_buf, 16, "delRule%d", i);
    	value = websGetVar(data, name_buf, NULL);
	
    	if(value){
        		deleArray[j++] = i;
    	}
	}

   	if(!j){
	   	free(deleArray);
    	free(new_rules);
		websErrorResponse(mosq, tp,"You did not select any rules to delete");
    	return;
	}

	deleteNthValueMulti(deleArray, j, new_rules, ';');
	
	apmib_set(MIB_IPQOSLIMITRULES, (void *)new_rules);
	rule_count = getNums((char *)new_rules,';');
	apmib_set(MIB_IPQOSLIMITNUM, (void *)&rule_count);

	free(deleArray);
	free(new_rules);
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf ibmsiplimit");

End_label:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int set_bandwidth(int up,int down)
{
#if 0
	int fd = -1;
	struct bandwidth bw;
	bw.up = up * 128 * 1024;  //KB
	bw.down = down * 128 * 1024;   //KB
	fd = open("/dev/qos_dev",O_RDWR);
	if(fd < 0) {
		printf("open /dev/qos_dev failed.\n");
	} else {
		if(ioctl(fd,1,&bw,sizeof(bw)) < 0){
			close (fd);
			printf("set bandwidth error!\n");
			return 0;
		}
		close (fd);
		return 1;
	}

#endif
	char cmd[1024] = {0};
	int tmp_up = 0, tmp_down = 0;
	tmp_up = up-(up*0.3);
	tmp_down = down-(down*0.3);
 	snprintf(cmd,1024,"ibms_cmd set system wan_up_bandwidth %d", tmp_up);
	CsteSystem(cmd, CSTE_PRINT_CMD);

	snprintf(cmd,1024,"ibms_cmd set system wan_down_bandwidth %d", tmp_down);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	
	return 0;
}

int setAppCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{

	int typeid = atoi(websGetVar(data, T("typeid"), T("0")));
	int enable = atoi(websGetVar(data, T("enable"), T("0")));

	switch (typeid)
	{
		case appFilter:
			apmib_set(MIB_APPFILTER_ENABLED, (void *)&enable);
			if(enable == 1){
				CsteSystem("ibms_cmd set system appfilter_enable 1", CSTE_PRINT_CMD);
			}else{
				CsteSystem("ibms_cmd set system appfilter_enable 0", CSTE_PRINT_CMD);
			}
			break;
		case gameSpeed:
			apmib_set(MIB_GAMESPEED_ENABLED, (void *)&enable);
			if(enable == 1){
				CsteSystem("ibms_cmd set system gameSpeed_enable 1", CSTE_PRINT_CMD);
			}else{
				CsteSystem("ibms_cmd set system gameSpeed_enable 0", CSTE_PRINT_CMD);
			}
			break;
		// add other app  function  .......... 	
		default :
			break;
	}
	apmib_update_web(CURRENT_SETTING);

	websSetCfgResponse(mosq, tp, "0", "reserv");

	return 0;
}

int getAppCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int enable;
	char *output;
	cJSON *root;
	
	root=cJSON_CreateObject();

	char *typeid = websGetVar(data, T("typeid"), T("0"));

	switch (atoi(typeid))
	{
		case appFilter:
			apmib_get(MIB_APPFILTER_ENABLED, (void *)&enable);
			break;
		case gameSpeed:
			apmib_get(MIB_GAMESPEED_ENABLED, (void *)&enable);
		default :
			break;
	}
	if(enable == 1)
		cJSON_AddStringToObject(root,"enable", "1");
	else
		cJSON_AddStringToObject(root,"enable", "0");
	
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	
	cJSON_Delete(root);
	free(output);
	
	return 0;
}

static int effectiveAppIbms(char * typeid,char *appid,int isEnable)
{
	char cmdbuf[128] = {0};
	switch (atoi(typeid))
	{
		case appFilter:
			sprintf(cmdbuf,"ibms_cmd update appfilter appid %s isfilter %d",appid,isEnable);
			break;
		case gameSpeed:
			sprintf(cmdbuf,"ibms_cmd update gameSpeed appid %s isquicken %d",appid,isEnable);
			break;
		default :
			break;
	}
	CsteSystem(cmdbuf,CSTE_PRINT_CMD);
	return 1;
}

int setAppById(struct mosquitto *mosq, cJSON* data, char *tp)
{

	int arr = 0;
	char cmdbuf[128] = {0},appbuf[32] = {0};

	char * typeid = websGetVar(data,T("typeid"),T(""));
	cJSON *appArray = cJSON_GetObjectItem(data,"app_array");
	for(arr = 0;arr<cJSON_GetArraySize(appArray);arr++){
		cJSON *appobj = cJSON_GetArrayItem(appArray,arr);
					
		char *appid = websGetVar(appobj,T("appid"),T(""));
		int isEnable = atoi(websGetVar(appobj,T("isEnable"),T("")));

		sprintf(appbuf,"app_%s",appid);
		setAppfilterSwitch(appbuf,&isEnable);
		effectiveAppIbms(typeid,appid,isEnable);
	}
	websSetCfgResponse(mosq, tp, "0", "reserv");	
    return 0;
}

int getAppTypeList(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL,cmdbuf[128] = {0};
	cJSON *tmpobj;
	struct dirent *ent;
	
	struct stat st;
	char *name = APP_CONFIG_TEMP_LIST_PATH;

	int f=stat(name,&st);
	if(f != -1)
	{
		FILE *fp = fopen(name, "r+");
		if(!fp){
			websGetCfgResponse(mosq,tp,"[]");
			return;
		}
		char *buffer = (char *)malloc(sizeof(char)*st.st_size+1);
		memset(buffer,'\0',sizeof(char)*st.st_size+1);
		fread(buffer,st.st_size,1,fp);
		fclose(fp);
		cJSON *root = cJSON_Parse(buffer);
		if(!root){
			free(buffer);
			websGetCfgResponse(mosq,tp,"[]");
			return;
		}	
		cJSON_Delete(root);
		websGetCfgResponse(mosq,tp,buffer);
		free(buffer);
	}else{
		websGetCfgResponse(mosq,tp,"[]");
	}
	return 0;
}

int getAppListById(struct mosquitto *mosq, cJSON* data, char *tp)
{
	
	int arr;
	char *output = NULL;
	char appbuf[32] = {0};
	
	char *apptype = websGetVar(data,T("config_name"),T(""));
	if(!strlen(apptype)){
		websGetCfgResponse(mosq,tp,"[]");
		return 0;
	}
	struct stat st;
	char *name = (char *)malloc(sizeof(char)*FILE_DIR_LEN);
	memset(name,'\0',sizeof(char)*FILE_DIR_LEN);
	strcpy(name,APP_CONFIG_TEMP_PATH);
	strcat(name,"/");
	strcat(name,apptype);

	int f=stat(name,&st);
	if(f != -1)
	{
		FILE *fp = fopen(name, "r+");
		if(!fp){
			free(name);
			goto end;
		}
		output = (char *)malloc(sizeof(char)*st.st_size+1);
		memset(output,'\0',sizeof(char)*st.st_size+1);
		fread(output,st.st_size,1,fp);
		fclose(fp);
		cJSON *appArray = cJSON_Parse(output);
		if(!appArray){
			free(name);
			free(output);
			output = NULL;
			goto end;
		}
		for(arr = 0;arr<cJSON_GetArraySize(appArray);arr++){
				cJSON * appobj = cJSON_GetArrayItem(appArray,arr);
				char *appid = websGetVar(appobj,T("appid"),T(""));
				sprintf(appbuf,"app_%s",appid);
				int isEnable,getflag;
				getflag=getAppfilterSwitch(appbuf,&isEnable);
				if(getflag==0)isEnable=0;
				char *idpoint = strstr(output,appid);
				char *ispoint = strstr(idpoint,"isEnable");
				while(*ispoint<'0'||*ispoint>'9'){
					ispoint++;
				}
				if(isEnable==1){
					*ispoint = '1';
				}else{
					*ispoint = '0';
				}
		}
		cJSON_Delete(appArray);
	}
	free(name);
end:
	if(output){
		websGetCfgResponse(mosq,tp,output);
		free(output);
	}else{
		websGetCfgResponse(mosq,tp,"[]");
	}
	return 0;
}

int set_autoenable(int enable)
{
	char cmd[1024] = {0};
 	snprintf(cmd,1024,"ibms_cmd set system auto_qos %d",enable);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	return 0;
}

int set_app_prio(struct auto_proto_prio *proto_prio_cfg)
{
#if 0
	int fd = -1;

	fd = open("/dev/qos_dev",O_RDWR);
	if(fd < 0) {
		printf("open /dev/qos_dev failed.\n");
	} else {
		if(ioctl(fd, 3, app_prio, sizeof(struct auto_qos_app)*(PROTO_MAX-1)) < 0){
			close (fd);
			printf("set app prio error!\n");
			return 0;
		}
		close (fd);
		return 1;
	}
	return 0;
#endif
	char cmd[1024] = {0};
	int i = 0;
	
	for(i=PROTO_OTHER;i<PROTO_MAX;i++){
		sprintf(cmd,"ibms_cmd update proto_prio protoid %d prio %d",i,proto_prio_cfg[i].prio);
		CsteSystem(cmd, CSTE_PRINT_CMD);
	}
	
	return 0;
}


int setQosPolicy(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char rule[64] = {0};
	struct auto_proto_prio proto_prio_cfg[PROTO_MAX];
	char *qos_enabled   = websGetVar(data, T("enable"),        T(""));
	char *other         = NULL;
	char *http          = NULL;
	char *http_download = NULL;
	char *https         = NULL;
	char *small_packet  = NULL;
	char *p2p           = NULL;
	char *priorityMode  = websGetVar(data, T("priorityMode"),  T("0"));
	char *upSpeed  		= websGetVar(data, T("manualUplinkSpeed"),T("100"));
	char *dwSpeed  		= websGetVar(data, T("manualDownlinkSpeed"),  T("100"));
	int enabled = 0,  ibms_upspeed = 0, ibms_dwspeed = 0, ibms_prioritymode = 0;

	if(atoi(qos_enabled)){
		CsteSystem("echo 0 > /proc/hw_nat", CSTE_PRINT_CMD);
		enabled = atoi(qos_enabled);
		apmib_set(MIB_IBMS_QOS_ENABLED, (void *)&enabled);
	} else {
		enabled = atoi(qos_enabled);
		apmib_set(MIB_IBMS_QOS_ENABLED, (void *)&enabled);
		CsteSystem("echo 1 > /proc/hw_nat", CSTE_PRINT_CMD);
	}
	
	if(strlen(qos_enabled) > 0)
		set_autoenable(atoi(qos_enabled));
	
	/*default value or nvram value*/
	if (1 == atoi(qos_enabled)) 
	{
		set_bandwidth(atoi(upSpeed), atoi(dwSpeed));
		ibms_upspeed = atoi(upSpeed);
		ibms_dwspeed = atoi(dwSpeed);
		apmib_set(MIB_IBMS_MANUALUPLINKSPEED, (void *)&ibms_upspeed);
		apmib_set(MIB_IBMS_MANUALDOWNLINKSPEED, (void *)&ibms_dwspeed);
	
		switch (atoi(priorityMode))
		{
			case DEFAULT_MODE:
			{
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));

				proto_prio_cfg[PROTO_HTTP].prio          = 0;
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = 3;
				proto_prio_cfg[PROTO_HTTPS].prio         = 0;
				proto_prio_cfg[PROTO_SMALLPKT].prio      = 0;
				proto_prio_cfg[PROTO_P2P].prio           = 4;
				proto_prio_cfg[PROTO_OTHER].prio         = 2;
				break;
			}
			case OFFICE_MODE:
			{
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));

				proto_prio_cfg[PROTO_HTTP].prio          = 0;
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = 1;
				proto_prio_cfg[PROTO_HTTPS].prio         = 0;
				proto_prio_cfg[PROTO_SMALLPKT].prio      = 3;
				proto_prio_cfg[PROTO_P2P].prio           = 4;
				proto_prio_cfg[PROTO_OTHER].prio         = 2;
				break;
			}
			case GAME_MODE:
			{
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));

				proto_prio_cfg[PROTO_HTTP].prio          = 3;
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = 3;
				proto_prio_cfg[PROTO_HTTPS].prio         = 1;
				proto_prio_cfg[PROTO_SMALLPKT].prio      = 0;
				proto_prio_cfg[PROTO_P2P].prio           = 4;
				proto_prio_cfg[PROTO_OTHER].prio         = 2;
				break;
			}
			case DOWNLOAD_MODE:
			{
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));

				proto_prio_cfg[PROTO_HTTP].prio          = 3;
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = 0;
				proto_prio_cfg[PROTO_HTTPS].prio         = 3;
				proto_prio_cfg[PROTO_SMALLPKT].prio      = 3;
				proto_prio_cfg[PROTO_P2P].prio           = 0;
				proto_prio_cfg[PROTO_OTHER].prio         = 2;
				break;
			}
			case ADVANCED_MODE:
			{
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));
				other         = websGetVar(data, T("other"),         T(""));
				http          = websGetVar(data, T("http"),          T(""));
				http_download = websGetVar(data, T("http_download"), T(""));
				https         = websGetVar(data, T("https"),         T(""));
				small_packet  = websGetVar(data, T("small_packet"),  T(""));
				p2p           = websGetVar(data, T("p2p"),           T(""));
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = atoi(http_download);
				proto_prio_cfg[PROTO_HTTP].prio          = atoi(http);
				proto_prio_cfg[PROTO_HTTPS].prio         = atoi(https);
				proto_prio_cfg[PROTO_SMALLPKT].prio      = atoi(small_packet);
				proto_prio_cfg[PROTO_P2P].prio           = atoi(p2p);
				proto_prio_cfg[PROTO_OTHER].prio         = atoi(other);
				break;
			}
			default :
			{
				printf("Unknow priorityMode\n");
				memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));

				proto_prio_cfg[PROTO_HTTP].prio          = 0;
				proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio = 3;
				proto_prio_cfg[PROTO_HTTPS].prio         = 0;
				proto_prio_cfg[PROTO_SMALLPKT].prio      = 0;
				proto_prio_cfg[PROTO_P2P].prio           = 4;
				proto_prio_cfg[PROTO_OTHER].prio         = 2;
				break;
			}
		}

		set_app_prio(&proto_prio_cfg);
		sprintf(rule,"%d;%d;%d;%d;%d;%d",
	                 proto_prio_cfg[PROTO_OTHER].prio,
	                 proto_prio_cfg[PROTO_HTTP].prio,
	                 proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio,
	                 proto_prio_cfg[PROTO_HTTPS].prio,
	                 proto_prio_cfg[PROTO_SMALLPKT].prio,
	                 proto_prio_cfg[PROTO_P2P].prio);
		apmib_set(MIB_IBMS_QOS_APP_PRIO, (void *)rule);
		char ibms_rule[64] = {0};
		apmib_get(MIB_IBMS_QOS_APP_PRIO, (void *)ibms_rule);
		ibms_prioritymode = atoi(priorityMode); 
		apmib_set(MIB_IBMS_PRIORITY_MODE, (void *)&ibms_prioritymode);
		
	}
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}


int getQosPolicy(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output = NULL;
	FILE *fp = NULL;
	cJSON *root,*https, *urlEntry;
	struct auto_proto_prio proto_prio_cfg[PROTO_MAX];
	char line[256] = {0};
	char buf[8]={0};
	int i=0;
	int priorityMode = 0;
	char rule[64] = {0};
	int qos_enabled = 0;
	int manualUplinkSpeed = 0;
	int manualDownlinkSpeed = 0;

	apmib_get(MIB_IBMS_PRIORITY_MODE, (void *)&priorityMode);
	apmib_get(MIB_IBMS_QOS_APP_PRIO, (void *)rule);
	memset(proto_prio_cfg,0,sizeof(proto_prio_cfg));
	sscanf(rule,"%d;%d;%d;%d;%d;%d",&proto_prio_cfg[PROTO_OTHER].prio,&proto_prio_cfg[PROTO_HTTP].prio,&proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio,
		&proto_prio_cfg[PROTO_HTTPS].prio,&proto_prio_cfg[PROTO_SMALLPKT].prio,&proto_prio_cfg[PROTO_P2P].prio);

	root = cJSON_CreateObject();

	snprintf(buf,8,"%d",priorityMode);
	cJSON_AddStringToObject(root, "priorityMode", buf);
	apmib_get(MIB_IBMS_QOS_ENABLED, (void *)&qos_enabled);
	
	cJSON_AddNumberToObject(root, "enable",qos_enabled);
	apmib_get(MIB_IBMS_MANUALUPLINKSPEED, (void *)&manualUplinkSpeed);

	cJSON_AddNumberToObject(root, "manualUplinkSpeed", manualUplinkSpeed);
	apmib_get(MIB_IBMS_MANUALDOWNLINKSPEED, (void *)&manualDownlinkSpeed);	

	printf("qos_enabled = %d, manualUplinkSpeed = %d, manualDownlinkSpeed = %d\n", qos_enabled, manualUplinkSpeed, manualDownlinkSpeed);

	cJSON_AddNumberToObject(root, "manualDownlinkSpeed", manualDownlinkSpeed);

	if(ADVANCED_MODE == priorityMode)
	{
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_OTHER].prio);
		cJSON_AddStringToObject(root,"other",buf);
	
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_HTTP].prio);
		cJSON_AddStringToObject(root,"http",buf);
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_HTTP_DOWNLOAD].prio);
		cJSON_AddStringToObject(root,"http_download",buf);
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_HTTPS].prio);
		cJSON_AddStringToObject(root,"https",buf);
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_SMALLPKT].prio);
		cJSON_AddStringToObject(root,"small_packet",buf);
		snprintf(buf,8,"%d",proto_prio_cfg[PROTO_P2P].prio);
		cJSON_AddStringToObject(root,"p2p",buf);	
	}
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

#endif
int module_init()
{
	cste_hook_register("setFirewallType",setFirewallType);
	cste_hook_register("getFirewallType",getFirewallType);
	
	cste_hook_register("setIpPortFilterRules",setIpPortFilterRules);
	cste_hook_register("getIpPortFilterRules",getIpPortFilterRules);
	cste_hook_register("delIpPortFilterRules",delIpPortFilterRules);
	
	cste_hook_register("setMacFilterRules",setMacFilterRules);
	cste_hook_register("getMacFilterRules",getMacFilterRules);
	cste_hook_register("delMacFilterRules",delMacFilterRules);

	cste_hook_register("delIpportMacRules",delIpportMacRules);
	
	cste_hook_register("setUrlFilterRules",setUrlFilterRules);
	cste_hook_register("getUrlFilterRules",getUrlFilterRules);
	cste_hook_register("delUrlFilterRules",delUrlFilterRules);
	cste_hook_register("setParentalRules",setParentalRules);
	cste_hook_register("getParentalRules",getParentalRules);
	cste_hook_register("delParentalRules",delParentalRules);
	
	cste_hook_register("setPortForwardRules",setPortForwardRules);	
	cste_hook_register("getPortForwardRules",getPortForwardRules);
	cste_hook_register("delPortForwardRules",delPortForwardRules);
	
	cste_hook_register("setVpnPassCfg",setVpnPassCfg);
	cste_hook_register("getVpnPassCfg",getVpnPassCfg);

	cste_hook_register("setDMZCfg",setDMZCfg);
	cste_hook_register("getDMZCfg",getDMZCfg);

	cste_hook_register("setRemoteCfg",setRemoteCfg);
	cste_hook_register("getRemoteCfg",getRemoteCfg);
	
	cste_hook_register("setScheduleRules",setScheduleRules);
	cste_hook_register("getScheduleRules",getScheduleRules);
	
	cste_hook_register("setIpQos",setIpQos);
	cste_hook_register("setIpQosRules",setIpQosRules);
	cste_hook_register("delIpQosRules",delIpQosRules);
	cste_hook_register("getIpQosRules",getIpQosRules);	

	cste_hook_register("setMacQos",setMacQos);
	cste_hook_register("delMacQosRules",delMacQosRules);
	cste_hook_register("getMacQosRules",getMacQosRules);

#if defined(CONFIG_PA_ONLINE_IP)
	cste_hook_register("setIpQosLimit",setIpQosLimit);
	cste_hook_register("delIpQosLimit",delIpQosLimit);
	cste_hook_register("getIpQosLimit",getIpQosLimit);
	cste_hook_register("setAppCfg",setAppCfg);
	cste_hook_register("getAppCfg",getAppCfg);
	cste_hook_register("setAppById",setAppById);
	cste_hook_register("getAppTypeList",getAppTypeList);
	cste_hook_register("getAppListById",getAppListById);
	cste_hook_register("setQosPolicy",setQosPolicy);
	cste_hook_register("getQosPolicy",getQosPolicy);
#endif

	return 0;  
}
