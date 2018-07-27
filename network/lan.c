/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file lan.c
* @author CaryStudio
* @brief  This is a network cste topic
* @date 2017-11-7
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

#include "lan.h"

#define LOG_MAX         16384
#define LOG_MAX_LINE    256
#define LOG_MAX_NUM     64

void checkStaticDhcpIP(struct in_addr inLanaddr_new, struct in_addr inLanmask_new){
	int i=0, entryNum_resvdip=0, link_type=8;//DHCPRSVDIP_ARRY_T;
	struct in_addr private_host, tmp_private_host, update;
	DHCPRSVDIP_T entry_resvdip, checkentry_resvdip;
#ifdef MIB_TLV
	char pmib_num[10]={0};
	mib_table_entry_T *pmib_tl = NULL;
	unsigned int offset;
#endif
	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum_resvdip);
	for (i=1; i<=entryNum_resvdip; i++)
	{
		memset(&checkentry_resvdip, '\0', sizeof(checkentry_resvdip));
		*((char *)&entry_resvdip) = (char)i;
		apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry_resvdip);
		memcpy(&checkentry_resvdip, &entry_resvdip, sizeof(checkentry_resvdip));
		memcpy((void *)&private_host, &(entry_resvdip.ipAddr), 4);
		if((inLanaddr_new.s_addr & inLanmask_new.s_addr) != (private_host.s_addr & inLanmask_new.s_addr))
		{
			update.s_addr = inLanaddr_new.s_addr & inLanmask_new.s_addr;
			tmp_private_host.s_addr  = ~(inLanmask_new.s_addr) & private_host.s_addr;
			update.s_addr = update.s_addr | tmp_private_host.s_addr;
			memcpy((void *)&(checkentry_resvdip.ipAddr), &(update), 4);
#if 0//defined(MIB_TLV)
			offset=0;//must initial first for mib_search_by_id
			mib_search_by_id(mib_root_table, MIB_DHCPRSVDIP_TBL, pmib_num, &pmib_tl, &offset);
			update_tblentry(pMib,offset,entryNum_resvdip,pmib_tl,&entry_resvdip, &checkentry_resvdip);
#else
			update_linkchain(link_type, &entry_resvdip, &checkentry_resvdip , sizeof(checkentry_resvdip));
#endif
		}
	}
}

/**
* @note setLanConfig - set current lan config
*
* @param Setting Json Data
<pre>
{
	"lanIp" :		"192.168.0.1"
	"lanNetMask":	"255.255.255.0"
	"dhcpServer":	"0"
	"dhcpStart":	"192.168.0.2"
	"dhcpEnd":	"192.168.0.250"
	"dhcpLease":	"86400"
}
setting parameter description:
lanIp		- the ip of lan 
lanNetMask	- net mask of lan
dhcpServer	- dhcp type	0 : dhcp disabled; 1 : dhcp server; 
dhcpStart		- start ip of dhcp
dhcpEnd		- end ip of dhcp
dhcpLease	- lease time of dhcp ip
</pre>
* @return Return Json Data
<pre>
{
    "success":	true
    "error":	null
    "lanIp":	"192.168.0.1"
    "wtime":	"70"
    "reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-7
*/
int setLanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char buffer[32]={0};
    int opmode, lan_dhcp_mode=0, dhcp_l_time;
    struct in_addr inLanaddr_orig, inLanaddr_new;
	struct in_addr inLanmask_orig, inLanmask_new;
	struct in_addr inIp, inMask, inDhcp_s, inDhcp_e;
    __FUNC_IN__
		
	apmib_get(MIB_OP_MODE,(void *)&opmode);
#if defined(SUPPORT_MESH)
	int rptEnable1=0,rptEnable2=0;
	apmib_get(MIB_REPEATER_ENABLED1,(void *)&rptEnable1);
	apmib_get(MIB_REPEATER_ENABLED2,(void *)&rptEnable2);
	if((rptEnable1==1||rptEnable2==1)&&opmode==0){
		if(rptEnable1==1){
			rptEnable1=0;
			apmib_set(MIB_REPEATER_ENABLED1,(void *)&rptEnable1);
			CsteSystem("ifconfig wlan0-vxd down &",CSTE_PRINT_CMD);
		}
		if(rptEnable2==1){
			rptEnable2=0;
			apmib_set(MIB_REPEATER_ENABLED2,(void *)&rptEnable2);
			CsteSystem("ifconfig wlan1-vxd down &",CSTE_PRINT_CMD);
		}
	}
#endif

	if(opmode==1){
		int dnsmode=0;
		struct in_addr inIp, inMask, inGw, inDns1, inDns2;
		char_t *ip, *nm, *gw, *pridns, *secdns;
		int lanmode = atoi(websGetVar(data,T("lanMode"),T("0")));
		apmib_set(MIB_LAN_MODE,(void *)&lanmode);
		if(0==lanmode)
			dnsmode = 1;
		else
			dnsmode = 0;
		apmib_set(MIB_DNS_MODE,(void *)&dnsmode);
		if(0==lanmode){
			ip = websGetVar(data, T("lanIp"), T(""));
			if ( inet_aton(ip, &inIp) ){
				apmib_set( MIB_IP_ADDR, (void *)&inIp);
			}	 
			nm = websGetVar(data, T("lanNetmask"), T(""));
			if ( inet_aton(nm, &inMask) ){
				apmib_set(MIB_SUBNET_MASK, (void *)&inMask);
			}
			gw=websGetVar(data,T("lanGateway"),T(""));
			if ( inet_aton(gw, &inGw) ){
				apmib_set(MIB_DEFAULT_GATEWAY, (void *)&inGw);
			}
			pridns=websGetVar(data,T("lanPriDns"),T(""));
			if ( inet_aton(pridns, &inDns1) ){
				apmib_set(MIB_DNS1, (void *)&inDns1);
			}
			secdns=websGetVar(data,T("lanSecDns"),T(""));
			if(!strlen(secdns)){
				char empty[8]="0.0.0.0";
				secdns = empty;
			}
			if ( inet_aton(secdns, &inDns2) ){
				apmib_set(MIB_DNS2, (void *)&inDns2);
			}
			
			char_t *dhcp_s = websGetVar(data, T("dhcpStart"), T(""));
			if ( inet_aton(dhcp_s, &inDhcp_s) ){
				apmib_set(MIB_DHCP_CLIENT_START, (void *)&inDhcp_s);
			}  
			
			char_t *dhcp_e = websGetVar(data, T("dhcpEnd"), T(""));
			if ( inet_aton(dhcp_e, &inDhcp_e) ){
				apmib_set(MIB_DHCP_CLIENT_END, (void *)&inDhcp_e);
			} 
			
			char_t *dhcp_l = websGetVar(data, T("dhcpLease"), T("86400"));
			dhcp_l_time = atoi(dhcp_l);
			apmib_set(MIB_DHCP_LEASE_TIME, (void *)&dhcp_l_time);
		}
	}else{
	    apmib_get( MIB_IP_ADDR, (void *)buffer); //save the orig lan subnet
	    memcpy((void *)&inLanaddr_orig, buffer, 4);
	    apmib_get( MIB_SUBNET_MASK, (void *)buffer); //save the orig lan mask
	    memcpy((void *)&inLanmask_orig, buffer, 4);

	    char_t *ip = websGetVar(data, T("lanIp"), T(""));
	    if ( inet_aton(ip, &inIp) ){
	        apmib_set(MIB_IP_ADDR, (void *)&inIp);
	    }    
		char_t *nm = websGetVar(data, T("lanNetmask"), T(""));
	    if ( inet_aton(nm, &inMask) ){
			apmib_set(MIB_SUBNET_MASK, (void *)&inMask);
		}

		char_t *dhcp_tp = websGetVar(data, T("dhcpServer"), T("0"));
	    lan_dhcp_mode = atoi(dhcp_tp);
	    lan_dhcp_mode = (lan_dhcp_mode==DHCP_DISABLED)?DHCP_DISABLED:DHCP_SERVER;	
	    apmib_set(MIB_DHCP, (void *)&lan_dhcp_mode);

	    char_t *dhcp_s = websGetVar(data, T("dhcpStart"), T(""));
	    if ( inet_aton(dhcp_s, &inDhcp_s) ){
	        apmib_set(MIB_DHCP_CLIENT_START, (void *)&inDhcp_s);
	    }  
		
	    char_t *dhcp_e = websGetVar(data, T("dhcpEnd"), T(""));
	    if ( inet_aton(dhcp_e, &inDhcp_e) ){
	        apmib_set(MIB_DHCP_CLIENT_END, (void *)&inDhcp_e);
	    } 
		
	    char_t *dhcp_l = websGetVar(data, T("dhcpLease"), T("86400"));
	    dhcp_l_time = atoi(dhcp_l);
	    apmib_set(MIB_DHCP_LEASE_TIME, (void *)&dhcp_l_time);

	    apmib_get(MIB_IP_ADDR, (void *)buffer); //check the new lan subnet
		memcpy((void *)&inLanaddr_new, buffer, 4);
		apmib_get(MIB_SUBNET_MASK, (void *)buffer); //check the new lan mask
		memcpy((void *)&inLanmask_new, buffer, 4);

		//check static dhcp ip
		if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inLanaddr_new.s_addr & inLanmask_new.s_addr)){
			checkStaticDhcpIP(inLanaddr_new, inLanmask_new);
		}
	}
    apmib_update_web(CURRENT_SETTING);	// update configuration to flash

	int pid;
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		CsteSystem("reboot",CSTE_PRINT_CMD);
		exit(1);
	}

	websSetCfgResponse(mosq, tp, "70", "reserv");

	__FUNC_OUT__
	return 0;
}

/**
* @note getLanConfig - get the lan config from web
*
* @param  NULL
* @return Return Json Data
<pre>
{
	"lanIp":			"192.168.0.1",
	"lanNetmask":		"255.255.255.0",
	"dhcpServer":		1,
	"dhcpStart":		"192.168.0.2",
	"dhcpEnd":		"192.168.0.250",
	"dhcpLease":		86400,
	"br0Ip":			"192.168.0.1",
	"br0Netmask":		"255.255.255.0",
	"operationMode":	0,
	"wanIp":			"172.1.1.1",
	"languageType":	"cn"
}
return parameter description:
lanIp:		lan ip
lanNetMask:	lan net mask
dhcpServer:	dhcp mode  0: disabled; 1: dhcp server;
dhcpStart:	start ip of dhcp
dhcpEnd:		end ip of dhcp
dhcpLease:	lease time of dhcp ip
br0Ip:		br0 ip
br0NetMask:	br0 net mask
operationMode:	system mode
wanIp:			wan ip
languageType:	language type
</pre>
* @author 	rancho
* @date 	2017-11-7
*/
int getLanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output,buff[64]={0};
    cJSON *root=cJSON_CreateObject(); 
    int arraylen,lanmode;
    char br0addr[64]={0},br0mask[64]={0},tmpbuf[16]={0};
	int dhcpLease=0;
	__FUNC_IN__	
	
	apmib_get(MIB_DHCP_LEASE_TIME,  (void *)&dhcpLease);
	sprintf(tmpbuf,"%d",dhcpLease);
	cJSON_AddStringToObject(root,"dhcpLease",tmpbuf);

    char *IPGetName[]={"lanIp","lanNetmask","dhcpStart","dhcpEnd"};
    int IPGetId[]={MIB_IP_ADDR,MIB_SUBNET_MASK,MIB_DHCP_CLIENT_START,MIB_DHCP_CLIENT_END};
    arraylen=sizeof(IPGetName)/sizeof(char *);
    getCfgArrayIP(root, arraylen, IPGetName, IPGetId);

	if(!getInAddr("br0", IP_ADDR_T, (void *)br0addr))
		sprintf(br0addr,"0.0.0.0");
	cJSON_AddStringToObject(root,"br0Ip",br0addr);

	if(!getInAddr("br0", NET_MASK_T, (void *)br0mask ))
		sprintf(br0mask,"0.0.0.0");
	cJSON_AddStringToObject(root,"br0Netmask",br0mask);

	apmib_get(MIB_LAN_MODE,(void *)&lanmode);
	cJSON_AddNumberToObject(root,"lanMode",lanmode);

	memset(buff,'0',sizeof(buff));
	getRealGateway(buff);
	cJSON_AddStringToObject(root,"lanGateway",buff);

	memset(buff,'0',sizeof(buff));
	strcpy(buff,getDns(1));
	if(strcmp(buff,"0.0.0.0")==0)
		cJSON_AddStringToObject(root,"lanPriDns","");
	else
		cJSON_AddStringToObject(root,"lanPriDns",buff);
	memset(buff,'0',sizeof(buff));
	strcpy(buff,getDns(2));
	if(strcmp(buff,"0.0.0.0")==0)
		cJSON_AddStringToObject(root,"lanSecDns","");
	else
		cJSON_AddStringToObject(root,"lanSecDns",buff);
	
	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());
	cJSON_AddNumberToObject(root,"dhcpServer",getDhcp());

	getWanIp(tmpbuf);
	cJSON_AddStringToObject(root,"wanIp",tmpbuf);

	apmib_get(MIB_LANGUAGE_TYPE, (void *)tmpbuf);
	cJSON_AddStringToObject(root,"languageType", tmpbuf);

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    __FUNC_OUT__
    return 0;
}

/**
* @note getDhcpCliList - get dhcp client list

* @param NULL
* @return Json Data
<pre>
{	
	"idx":	"0"
	"ip":	"192.168.0.2"
	"mac":	"xx:xx:xx:xx:xx:xx"
	"expires":	"86377"
}
return parameter description
idx:	wifi idx, 0: 5G; 1: 2.4G;
ip:	client ip
mac:	client mac
expires:	client ip expires time
</pre>
* @author	rancho
* @date		2017-11-7
*/
int getDhcpCliList(struct mosquitto *mosq, cJSON* data, char *tp)
{
    FILE *fp;
    struct stat status;
    int pid, ret, len=0, count=0;
    unsigned long fileSize=0;
    char *output,*buf=NULL, *ptr=NULL;
    char tmpBuf[128]={0}, ipAddr[32]={0}, macAddr[32]={0}, liveTime[32]={0}, hostName[64]={0};

	cJSON *cliInfo;
	cJSON *root=cJSON_CreateArray();
	

    // siganl DHCP server to update lease file
    snprintf(tmpBuf, 128, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
    pid = getPid(tmpBuf);
    if( pid > 0){
        snprintf(tmpBuf, 128, "kill -SIGUSR1 %d\n", pid);
        system(tmpBuf);
    }
    usleep(1000);

    if ( stat(_PATH_DHCPS_LEASES, &status) < 0 ){
    	goto end_label;
    }

    fileSize=status.st_size;
    buf = malloc(fileSize);
    if ( buf != NULL ){
        if( (fp=fopen(_PATH_DHCPS_LEASES, "r"))==NULL ){
        	sleep(1);
	        if( (fp=fopen(_PATH_DHCPS_LEASES, "r"))==NULL ){
				free(buf);
	    		goto end_label;
	        }
        }
        fread(buf, 1, fileSize, fp);
        fclose(fp);
        ptr = buf;
        while(1){
            ret = getOneDhcpClient(&ptr, &fileSize, ipAddr, macAddr, liveTime, hostName);
            if(ret<0)   break;
            if(ret==0)  continue;
            if(!strcmp(macAddr,"00:00:00:00:00:00"))  continue;
			count++;
			cliInfo=cJSON_CreateObject();
			cJSON_AddItemToArray(root,cliInfo);
			sprintf(tmpBuf,"%d",count);
			cJSON_AddStringToObject(cliInfo,"idx", tmpBuf);
			cJSON_AddStringToObject(cliInfo,"ip", ipAddr);
			cJSON_AddStringToObject(cliInfo,"mac", macAddr);
			cJSON_AddStringToObject(cliInfo,"expires", liveTime);
        }	
    }

end_label:
 	output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);

    cJSON_Delete(root);
	free(output);
	return 0;   
}

/**
* @note getArpTable - Get arp table
*
* @param NULL
* @return return Json Data
<pre>
{
	"enable":	"1"
	"idx":	"0"
	"ip":	"192.168.0.2"
	"mac":	"xx:xx:xx:xx:xx:xx"
}
return parameter description:
enable:	enable arp function
idx:	arp table sequence number
ip:	arp table ip
mac:	arp table mac
</pre>
* @author	rancho
* @date		2017-11-7
*/
int getArpTable(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int len=0, count=0;
	unsigned int flags;
	char arp_buf[256] = {0}, arp_ip[16] = {0}, arp_mac[18] = {0}, arp_dev[17] = {0}, arp_hostname[64] = {0};
	char responseStr[CSTEBUFSIZE] = {0};
	
	FILE *fp = fopen("/proc/net/arp","r");
	if(fp != NULL) {
		snprintf(responseStr, (sizeof(responseStr) - len), "[{\"enable\":\"1\"}\n");
		len = strlen(responseStr);
		while (fgets(arp_buf, sizeof(arp_buf), fp)) {
			if (sscanf(arp_buf, "%15s %*s 0x%X %17s %*s %16s", arp_ip, &flags, arp_mac, arp_dev) != 4) 
				continue;
			if ((strlen(arp_mac)!=17)||(strcmp(arp_mac,"00:00:00:00:00:00")==0)) 
				continue;
			if ((strlen(arp_dev)!=3)||(strcmp(arp_dev,"br0")!=0)) 
				continue;
			if (flags==0) 
				continue;			
			if (strstr(responseStr, arp_mac)!=NULL) 
				continue;
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
				",{\"idx\":\"%d\",\"ip\":\"%s\",\"mac\":\"%s\"}\n",	count, arp_ip, arp_mac);
			len = strlen(responseStr);
			count++;
			
			if(len > CSTEMAXSIZE)
				break;
		}		
		fclose(fp);	
	}
	else{
		CSTE_DEBUG("fopen /proc/net/arp failed!\n");
		strcpy(responseStr,"[{\"enable\":\"0\"}]");
		goto end;
	}
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	
end:
	websGetCfgResponse(mosq,tp,responseStr);
	return 1;		
}

int checkSameIpOrMac(struct in_addr *IpAddr, char *macAddr, int entryNum)
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
		if(memcmp(IpAddr, entry.ipAddr, 4)==0)
			return 1;
		if(memcmp(macAddr, entry.macAddr, 6)==0)
			return 2;
	}
	return 0;
}

/**
* @note setStaticDhcpConfig	-	Set static dhcp config
*
* @param Setting Json Data
<pre>
{
	"addEffect":	"0"
	"enable":	""
	"ipAddress":	"192.168.0.34"
	"macAddress":	"34:34:23:54:42:34"
	"comment":	""
}
setting parameter description:
addEffect:	take effect the config
enable:		0: off, 1: on
ipAddress:	static ip address
macAddress:	mac address
comment:		
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
* @author	rancho
* @date		2017-11-7
*/
int setStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int entryNum=0;
    DHCPRSVDIP_T staticIPEntry;
    struct in_addr inIp, inLanaddr_orig, inLanmask_orig;
    char *delim=":", *p=NULL;
    int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	int enabled = atoi(websGetVar(data, T("enable"), T("0")));
	char *comment = websGetVar(data, T("comment"), T(""));	
    char *mac = websGetVar(data, T("macAddress"), T(""));
	char *ip = websGetVar(data, T("ipAddress"), T(""));
	char buffer[32]={0};
	__FUNC_IN__
	
	if (addEffect){
		apmib_set(MIB_DHCPRSVDIP_ENABLED, (void *)&enabled);
	}
	else{	
        memset(&staticIPEntry, '\0', sizeof(staticIPEntry));
        if(comment!=NULL)
    		strcpy((char *)staticIPEntry.hostName, comment);
    	if(inet_aton(ip, &inIp))
    	    memcpy(staticIPEntry.ipAddr, &inIp, 4);
    	if(!isMacValid(mac)){
			return 0;
		}else{
		    if(mac!=NULL){
		        p = strtok(mac, delim);
		        if(p==NULL) return 0;
                strcat(buffer, p);
                while((p=strtok(NULL, delim))) {
            		strcat(buffer, p);
            	}
            	string_to_hex(buffer, staticIPEntry.macAddr, 12);
            	memset(buffer, '\0', sizeof(buffer));
		    }
        }
        apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
        if ( (entryNum + 1) > MAX_DHCP_RSVD_IP_NUM ){
			return 0;
        }
        apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
    	memcpy((void *)&inLanaddr_orig, buffer, 4);    	
    	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
    	memcpy((void *)&inLanmask_orig, buffer, 4);
        if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inIp.s_addr & inLanmask_orig.s_addr)){
			return 0;
        }
    	int ret=checkSameIpOrMac(&inIp, staticIPEntry.macAddr, entryNum);
    	if(ret>0){
            return 0;
    	}
    	// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&staticIPEntry);
		apmib_set(MIB_DHCPRSVDIP_ADD, (void *)&staticIPEntry);
		CsteSystem("ifconfig eth0 down up", CSTE_PRINT_CMD);
	}
	apmib_update_web(CURRENT_SETTING);

	CsteSystem("sysconf reservedIP", CSTE_PRINT_CMD);
	websSetCfgResponse(mosq, tp, "10", "reserv");
	__FUNC_OUT__
    return 0;
}

/**
* @note delStaticDhcpConfig -	delete static dhcp config
*
* @param Setting Json Data
<pre>
{
	"delRule1":	"1"
	"delRule2":	"2"
	...
}
setting parameter description:
delRule2:	delete static dhcp rule 2
</pre>
* @return 	Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"5",
	"reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-7
*/
int delStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int i,entryNum;
	char name_buf[32];
	char *value;
	DHCPRSVDIP_T delEntry;
	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delRule%d", i-1);
		value = websGetVar(data, name_buf, NULL);
		if (value){
			*((char *)(void *)&delEntry) = (char)i;
			apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&delEntry);
			apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&delEntry);			
		}
	}
	apmib_update_web(CURRENT_SETTING);	
	CsteSystem("sysconf reservedIP", CSTE_PRINT_CMD);
	websSetCfgResponse(mosq, tp, "5", "reserv");
	return 0;
}

/**
* @note  getStaticDhcpConfig		- Get static dhcp config
*
* @param	NULL
* @return	return Json Data
<pre>
{
	"enable":		"1",
	"lanNetmask":	"255.255.255.0",
	"lanIp":		"192.168.0.1"
	"idx":		"1",
	"ip":			"192.168.0.30",
	"mac":		"xx:xx:xx:xx:xx:xx",
	"comment":	"",
	"delRuleName":	"delRule0"
}
return parameter description:
enable:	enable static dhcp off/on		1: enabled;  0: disabled;
lanNetmask:	lan net mask
lanIp:	lan ip
idx:		index	
ip:		ip		
mac:	mac	
comment:	comment
delRuleName:	delete rule name 
</pre>
* @author	rancho
* @date		2017-11-7
*/
int getStaticDhcpConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    int enable=0, rulenum=0, len=0, i=0;
    DHCPRSVDIP_T entry;
    char macaddr[30]={0};
    char responseStr[CSTEBUFSIZE]={0},lanIp[32],lanNetmask[32];
    __FUNC_IN__

    apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&enable);
	getLanIp(lanIp);
	getLanNetmask(lanNetmask);
	snprintf(responseStr, (sizeof(responseStr) - len), \
		     "[{\"enable\":\"%d\",\"lanNetmask\":\"%s\",\"lanIp\":\"%s\"}\n", \
		     enable, lanNetmask, lanIp);
	len = strlen(responseStr);
	
    apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&rulenum);
    CSTE_DEBUG("enable=%d, rulenum=%d\n", enable, rulenum);
    if(rulenum==0){
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}
    for(i=1; i<=rulenum; i++){
        *((char *)&entry) = (char)i;
        apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
        if (!memcmp(entry.macAddr, "\x0\x0\x0\x0\x0\x0", 6))
			macaddr[0]='\0';
		else			
			sprintf(macaddr,"%02X:%02X:%02X:%02X:%02X:%02X", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
			
        snprintf((responseStr + len), (sizeof(responseStr) - len),\
			",{\"idx\":\"%d\",\"ip\":\"%s\",\"mac\":\"%s\",\"comment\":\"%s\",\"delRuleName\":\"delRule%d\"}\n",\
			i,inet_ntoa(*((struct in_addr*)entry.ipAddr)),macaddr,entry.hostName,i-1);
		len = strlen(responseStr);
		if(len>CSTEMAXSIZE)break;
    }
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);
    websGetCfgResponse(mosq,tp,responseStr);
    __FUNC_OUT__
    return 0;
}


#if defined(CONFIG_APP_IGMPPROXY)
/**
* @note	 setIgmpConfig  set igmp config
* @param setting Json Data
<pre>
{
	"igmpEnabled", "0"
}
setting parameter description:
igmpEnabled:		enable igmp off/on  0: off, 1:on
</pre>
* @return return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-7
*/
int setIgmpConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal=atoi(websGetVar(data, T("igmpEnabled"), T("0")));
	apmib_set(MIB_IGMP_PROXY_DISABLED,(void *)&intVal);	

	apmib_update_web(CURRENT_SETTING);
	system("sysconf firewall");
	websSetCfgResponse(mosq, tp, "0", "reserv");	
	return 0;
}

/**
* @note  getIgmpConfig		- Get igmp config
*
* @param	NULL
* @return	return Json Data
<pre>
{
	"igmpEnabled":		"0",
}
return parameter description:
igmpEnabled:		enable igmp off/on		1: enabled;  0: disabled;

</pre>
* @author	rancho
* @date		2017-11-7
*/
int getIgmpConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
    cJSON *root=cJSON_CreateObject();
    int intVal;
    
	apmib_get(MIB_IGMP_PROXY_DISABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root,"igmpEnabled",intVal);
	
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}
#endif

#if defined(CONFIG_SUPPORT_ETH_SPEED)
/**
* @note setEthSpeedConfig  -  Set ethernet speed 
*
* @param setting Json Data
<pre>
{
	"wanSpeed",	""
	"lan1Speed",	""
	"lan2Speed",	""
	"lan3Speed",	""
	"lan4Speed",	""
}
setting parameter description:
wanSpeed:	wan port speed   0: auto, 1: 10_half, 2: 10_full, 3: 100_half, 4: 100_full, 5: 1000_full   
lan1Speed:	lan1 port speed
lan2Speed:	lan2 port speed
lan3Speed:	lan3 port speed
lan4Speed:	lan4 port speed
</pre>
* @return  return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"10",
	"reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-7
*/
int setEthSpeedConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	unsigned int flagMode=0;
    int	wan_speed = atoi(websGetVar(data, T("wanSpeed"),  T("0")));
    int	lan1_speed = atoi(websGetVar(data, T("lan1Speed"), T("0")));
    int	lan2_speed = atoi(websGetVar(data, T("lan2Speed"), T("0")));
    int	lan3_speed = atoi(websGetVar(data, T("lan3Speed"), T("0")));
    int	lan4_speed = atoi(websGetVar(data, T("lan4Speed"), T("0")));
	
	flagMode |= wan_speed << 3*0;
	flagMode |= lan1_speed << 3*1;
	flagMode |= lan2_speed << 3*2;
	flagMode |= lan3_speed << 3*3;
	flagMode |= lan4_speed << 3*4;
	apmib_set(MIB_PORT_MODE, (void *)&flagMode);	
	
	apmib_update_web(CURRENT_SETTING);
	system("sysconf speedMode &");
    websSetCfgResponse(mosq, tp, "0", "reserv");
}

/**
* @note getEthSpeedConfig  Get ethernet speed config
*
* @param  NULL
* @return	return Json Data
<pre>
{
	"operationMode":	0,
	"wanSpeed":	0,
	"lan1Speed":	0,
	"lan2Speed":	0,
	"lan3Speed":	0,
	"lan4Speed":	0,
	"gigaBitBt":	1,
	"wanGigabitBt":	0,
	"hardModel":	"04336"
}
return parameter description:
operationMode":	0,
wanSpeed: 	0
lan1Speed:	0
lan2Speed:	0
lan3Speed:	0
lan4Speed:	0
gigaBitBt:	0
wanGigabitBt: 0
hardModel:	hard model
</pre>
* @author	rancho
* @date		2017-11-7
*/
int getEthSpeedConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	unsigned int portMode=0;
	char tmpBuf[32]={0};
    
	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());
	
	apmib_get(MIB_PORT_MODE, (void *)&portMode);
	cJSON_AddNumberToObject(root,"wanSpeed", (portMode&0x7)>6?0:(portMode&0x7));
	cJSON_AddNumberToObject(root,"lan1Speed",((portMode>>3)&0x7)>6?0:((portMode>>3)&0x7));
	cJSON_AddNumberToObject(root,"lan2Speed",((portMode>>6)&0x7)>6?0:((portMode>>6)&0x7));
	cJSON_AddNumberToObject(root,"lan3Speed",((portMode>>9)&0x7)>6?0:((portMode>>9)&0x7));
	cJSON_AddNumberToObject(root,"lan4Speed",((portMode>>12)&0x7)>6?0:((portMode>>12)&0x7));

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

	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}
#endif

#if defined(CONFIG_SUPPORT_IPTV) 
/**
* @note setIptvConfig  - Set iptv Config
*
* @param	Setting Json Data
<pre>
{
	"addEffect",		"0"
	"iptvEnabled", 	"0"
	"serviceType",	"1"
	"iptvPort",		"0"
	"iptvVid",		"20"
	"iptvPri",		"4"
	"ipPhonePort",	"1"
	"ipPhoneVid",	"1"
	"ipPhonePri",		"1"
	"internetPort",	"2"
	"internetVid",	"10"
	"internetPri",		"1"
}
setting parameter description:
addEffect:			
iptvEnabled:			
serviceType	
iptvPort
iptvVid		
iptvPri		
ipPhonePort	
ipPhoneVid	
ipPhonePri		
internetPort 
internetVid	
internetPri
</pre>
* @return return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"5",
	"reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-7
*/
int setIptvConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal=0;
	__FUNC_IN__ ;
	
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));
	if (addEffect){
		intVal = atoi(websGetVar(data, T("iptvEnabled"), T("0")));
		apmib_set(MIB_IPTV_ENABLED, (void *)&intVal);
	}else{
		intVal = atoi(websGetVar(data, T("serviceType"), T("1"))); // 0:userdefine; 1:Singapore-ExStream; 2:Malaysia-Unifi; 3:Malaysia-Maxis
		apmib_set(MIB_IPTV_SERVICETYPE, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("iptvPort"), T("0"))); // 0:lan1; 1:lan2
		apmib_set(MIB_IPTV_PORT, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("iptvVid"), T("20")));
		apmib_set(MIB_IPTV_VID, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("iptvPri"), T("4")));
		apmib_set(MIB_IPTV_PRI, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("ipPhonePort"), T("1"))); // 0:lan1; 1:lan2
		apmib_set(MIB_IPPHONE_PORT, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("ipPhoneVid"), T("1")));
		apmib_set(MIB_IPPHONE_VID, (void *)&intVal);
		
		intVal = atoi(websGetVar(data, T("ipPhonePri"), T("1")));
		apmib_set(MIB_IPPHONE_PRI, (void *)&intVal);

		intVal = atoi(websGetVar(data, T("internetPort"), T("2"))); 
		apmib_set(MIB_INTERNET_PORT, (void *)&intVal);

		intVal = atoi(websGetVar(data, T("internetVid"), T("10")));
		apmib_set(MIB_INTERNET_VID, (void *)&intVal);

		intVal = atoi(websGetVar(data, T("internetPri"), T("1")));
		apmib_set(MIB_INTERNET_PRI, (void *)&intVal);
	}	
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "8", "reserv");
	CsteSystem("sysconf iptv", CSTE_PRINT_CMD);
	__FUNC_OUT__ ;
	return 0;
}

/**
* @note  getIptvConfig   Get iptv config
*
* @param	NULL
* @return  Return Json Data
<pre>
{
	"addEffect",		"0"
	"iptvEnabled", 	"0"
	"serviceType",	"1"
	"iptvPort",		"0"
	"iptvVid",		"20"
	"iptvPri",		"4"
	"ipPhonePort",	"1"
	"ipPhoneVid",	"1"
	"ipPhonePri",		"1"
	"internetPort",	"2"
	"internetVid",	"10"
	"internetPri",		"1"
}
return  parameter description:
addEffect:			
iptvEnabled:			
serviceType	
iptvPort
iptvVid		
iptvPri		
ipPhonePort	
ipPhoneVid	
ipPhonePri		
internetPort 
internetVid	
internetPri
</pre>
* @author	rancho
* @date		2017-11-7
*/
int getIptvConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root=cJSON_CreateObject();
    int intVal=0;
	__FUNC_IN__	
		
	apmib_get(MIB_IPTV_ENABLED,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvEnabled",intVal);
	
	apmib_get(MIB_IPTV_SERVICETYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"serviceType",intVal);

	apmib_get(MIB_IPTV_PORT,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvPort",intVal);

	apmib_get(MIB_IPTV_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvVid",intVal);

	apmib_get(MIB_IPTV_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvPri",intVal);

	apmib_get(MIB_IPPHONE_PORT,(void *)&intVal);
	cJSON_AddNumberToObject(root,"ipPhonePort",intVal);

	apmib_get(MIB_IPPHONE_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"ipPhoneVid",intVal);

	apmib_get(MIB_IPPHONE_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"ipPhonePri",intVal);

	apmib_get(MIB_INTERNET_PORT,(void *)&intVal);
	cJSON_AddNumberToObject(root,"internetPort",intVal);
	
	apmib_get(MIB_INTERNET_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"internetVid",intVal);

	apmib_get(MIB_INTERNET_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"internetPri",intVal);

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
	__FUNC_OUT__ ;
	return 0;
}
#endif

int isLanClient(char *outmac)
{	
	char tmpCmd[128]={0},result[32]={0};
	
	sprintf(tmpCmd,"cat /var/MacPort_state | grep %s  | cut -f2 -d=",outmac);
waitResult:	
	if(-1!=getCmdStr(tmpCmd,result,sizeof(result)))
	{
		if(!strcmp(outmac,result)) 
		{
			sleep(1);
			goto  waitResult;
		}
		if(!strcmp(result,"-48")||!strcmp(result,"8"))
			return 1;
		else
			return 0;
	}
	return 1;
}

/**
* @note  getDeviceInfo   Get Device Info
*
* @param	NULL
* @return  Return Json Data
<pre>
[{
	"idx",		"0"
	"ip",			"192.168.0.2"
	"mac",		"00:26:66:45:ef:3d"
	"type",		"wired"
},
{
	"idx",		"0"
	"ip",			"192.168.0.3"
	"mac",		"00:26:66:45:ef:4d"
	"type",		"wireless"
}]
return  parameter description:
idx:			
ip:			
mac	
type
</pre>
* @author	felix
* @date		2018-1-24
*/
int getDeviceInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int len=0,count=0,csteDevicePid=0;
	unsigned int flags;
	char buf[256]={0},ip[16]={0},mac[18]={0},dev[17]={0},responseStr[CSTEBUFSIZE]={0};
	
	csteDevicePid=getCmdVal("cat /var/run/csteDrvierConnMachine.pid");
	sprintf(buf,"kill -SIGUSR1 %d",csteDevicePid);
	system(buf);
	memset(buf,0,sizeof(buf));
	sleep(1);
	
	FILE *fp=fopen("/proc/net/arp","r");
	if(fp!=NULL){
		snprintf(responseStr, (sizeof(responseStr) - len), "[");
		len = strlen(responseStr);
		while(fgets(buf, sizeof(buf), fp)){
			if(sscanf(buf, "%15s %*s 0x%X %17s %*s %16s", ip, &flags, mac, dev) != 4) continue;
			if((strlen(mac)!=17)||(strcmp(mac,"00:00:00:00:00:00")==0)) continue;
			if((strlen(dev)!=3)||(strcmp(dev,"br0")!=0)) continue;
			if(flags==0) continue;			
			if(strstr(responseStr, mac)!=NULL) continue;
			
			count++;
			snprintf((responseStr + len), (sizeof(responseStr) - len),\
				"{\"idx\":\"%d\",\"ip\":\"%s\",\"mac\":\"%s\",\"type\":\"%d\"},",
				 count, ip, mac, isLanClient(mac));
			
			len = strlen(responseStr);
			
			if(len > CSTEMAXSIZE) break;
		}
		fclose(fp);	

		if(count>0){
			responseStr[len-1]=']';
       		len = strlen(responseStr);
        }else{
            snprintf((responseStr + len), (sizeof(responseStr) - len), "]");
    	    len = strlen(responseStr);
        }
	}
	else{
		strcpy(responseStr,"[]");
	}
	websGetCfgResponse(mosq,tp,responseStr);
	return 1;		
}

#if defined(CONFIG_SUPPORT_CS_IPTV)
int setIptvConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int intVal=0;
	__FUNC_IN__ ;
	char *output=output=cJSON_Print(data);
	
	int igmpEnable = atoi(websGetVar(data, T("IgmpProxyEn"), T("0")));
	apmib_set(MIB_IGMP_PROXY_DISABLED,(void *)&igmpEnable);
	
	int igmpSnoop = atoi(websGetVar(data, T("igmpSnoopEn"), T("0")));
	apmib_set(MIB_IGMP_SNOOP_DISABLED,(void *)&igmpSnoop);
	
	int igmpVer = atoi(websGetVar(data, T("IgmpVer"), T("1")));
	apmib_set(MIB_IGMP_VER,(void *)&igmpVer);
	int addEffect = atoi(websGetVar(data, T("addEffect"), T("0")));

	intVal = atoi(websGetVar(data, T("iptvEnable"), T("0")));
	apmib_set(MIB_IPTV_ENABLED, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("serviceType"), T("1"))); // 0:userdefine; 1:Singapore-ExStream; 2:Malaysia-Unifi; 3:Malaysia-Maxis;4:VTV
	apmib_set(MIB_IPTV_SERVICETYPE, (void *)&intVal);
	
	intVal = atoi(websGetVar(data, T("iptvVid"), T("20")));
	apmib_set(MIB_IPTV_VID, (void *)&intVal);
	intVal = atoi(websGetVar(data, T("iptvPri"), T("4")));
	apmib_set(MIB_IPTV_PRI, (void *)&intVal);
	
	intVal = atoi(websGetVar(data, T("ipPhoneVid"), T("1")));
	apmib_set(MIB_IPPHONE_VID, (void *)&intVal);
	intVal = atoi(websGetVar(data, T("ipPhonePri"), T("1")));
	apmib_set(MIB_IPPHONE_PRI, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("internetVid"), T("10")));
	apmib_set(MIB_INTERNET_VID, (void *)&intVal);
	intVal = atoi(websGetVar(data, T("internetPri"), T("1")));
	apmib_set(MIB_INTERNET_PRI, (void *)&intVal);

	intVal = atoi(websGetVar(data,T("tagFlag"),T("0")));
	apmib_set(MIB_IPTV_TAG_FLAG,(void *)&intVal);
	
	intVal = atoi(websGetVar(data, T("lan1"), T("0"))); // 0:iptv; 1:internet; 2:ipPhone; 
	apmib_set(MIB_IPTV_LAN1_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("lan2"), T("0")));
	apmib_set(MIB_IPTV_LAN2_TYPE, (void *)&intVal);
	
#if !(defined(CONFIG_BOARD_04347)||defined(CONFIG_BOARD_04348))
	intVal = atoi(websGetVar(data, T("lan3"), T("0")));
	apmib_set(MIB_IPTV_LAN3_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("lan4"), T("0")));
	apmib_set(MIB_IPTV_LAN4_TYPE, (void *)&intVal);
#endif

	intVal = atoi(websGetVar(data, T("wlan0"), T("0")));
	apmib_set(MIB_IPTV_WLAN0_TYPE, (void *)&intVal);
	
	intVal = atoi(websGetVar(data, T("wlan0_va0"), T("0")));
	apmib_set(MIB_IPTV_WLAN0_VA0_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("wlan0_va1"), T("0")));
	apmib_set(MIB_IPTV_WLAN0_VA1_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("wlan1"), T("0")));
	apmib_set(MIB_IPTV_WLAN1_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("wlan1_va0"), T("0")));
	apmib_set(MIB_IPTV_WLAN1_VA0_TYPE, (void *)&intVal);

	intVal = atoi(websGetVar(data, T("wlan1_va1"), T("0")));
	apmib_set(MIB_IPTV_WLAN1_VA1_TYPE, (void *)&intVal);

	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "70", "reserv");
	int pid;
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		CsteSystem("reboot",CSTE_PRINT_CMD);
		exit(1);
	}
	__FUNC_OUT__ ;
	return 0;
}

int getIptvConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int intVal=0;
	char tmpBuf[32]={0};
	__FUNC_IN__ 

	apmib_get(MIB_IPTV_VERSION, (void *)&intVal);//0:all,1:Singapore,2:Malaysia,3:Vietnam,4:Russia,5:Taiwan region(A province of China)
	cJSON_AddNumberToObject(root,"iptvVer",intVal);
	
	apmib_get(MIB_HARDWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);
	
	apmib_get(MIB_IGMP_PROXY_DISABLED,(void *)&intVal);
	cJSON_AddNumberToObject(root,"IgmpProxyEn",intVal);

	apmib_get(MIB_IGMP_SNOOP_DISABLED,(void *)&intVal);
	cJSON_AddNumberToObject(root,"IgmpSnoopEn",intVal);

	apmib_get(MIB_IGMP_VER,(void *)&intVal);
	cJSON_AddNumberToObject(root,"IgmpVer",intVal);
	
	apmib_get(MIB_IPTV_ENABLED,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvEnabled",intVal);
	
	apmib_get(MIB_IPTV_SERVICETYPE,(void *)&intVal);// 0:userdefine; 1:Singapore-ExStream; 2:Malaysia-Unifi; 3:Malaysia-Maxis;4:VTV;5:Taiwan region
	cJSON_AddNumberToObject(root,"serviceType",intVal);

	apmib_get(MIB_IPTV_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvVid",intVal);

	apmib_get(MIB_IPTV_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"iptvPri",intVal);

	apmib_get(MIB_IPTV_TAG_FLAG,(void *)&intVal);
	cJSON_AddNumberToObject(root,"tagFlag",intVal);

	apmib_get(MIB_IPPHONE_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"ipPhoneVid",intVal);

	apmib_get(MIB_IPPHONE_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"ipPhonePri",intVal);

	apmib_get(MIB_INTERNET_VID,(void *)&intVal);
	cJSON_AddNumberToObject(root,"internetVid",intVal);

	apmib_get(MIB_INTERNET_PRI,(void *)&intVal);
	cJSON_AddNumberToObject(root,"internetPri",intVal);

	apmib_get(MIB_IPTV_LAN1_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"lan1",intVal);

	apmib_get(MIB_IPTV_LAN2_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"lan2",intVal);

#if !(defined(CONFIG_BOARD_04347)||defined(CONFIG_BOARD_04348))
	apmib_get(MIB_IPTV_LAN3_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"lan3",intVal);
	
	apmib_get(MIB_IPTV_LAN4_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"lan4",intVal);
#endif

	apmib_get(MIB_IPTV_WLAN0_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan0",intVal);
	
	apmib_get(MIB_IPTV_WLAN0_VA0_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan0_va0",intVal);

	apmib_get(MIB_IPTV_WLAN0_VA1_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan0_va1",intVal);

	apmib_get(MIB_IPTV_WLAN1_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan1",intVal);

	apmib_get(MIB_IPTV_WLAN1_VA0_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan1_va0",intVal);

	apmib_get(MIB_IPTV_WLAN1_VA1_TYPE,(void *)&intVal);
	cJSON_AddNumberToObject(root,"wlan1_va1",intVal);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	__FUNC_OUT__ ;
	return 0;
}
#endif

int module_init()
{
	cste_hook_register("setLanConfig",setLanConfig);
	cste_hook_register("getLanConfig",getLanConfig);
	
	cste_hook_register("getDhcpCliList",getDhcpCliList);
	cste_hook_register("getArpTable",getArpTable);
	
	cste_hook_register("setStaticDhcpConfig",setStaticDhcpConfig);
	cste_hook_register("delStaticDhcpConfig",delStaticDhcpConfig);
	cste_hook_register("getStaticDhcpConfig",getStaticDhcpConfig);	
	
#if defined(CONFIG_APP_IGMPPROXY)
	cste_hook_register("setIgmpConfig",setIgmpConfig);
	cste_hook_register("getIgmpConfig",getIgmpConfig);
#endif

#if defined(CONFIG_SUPPORT_ETH_SPEED)
	cste_hook_register("setEthSpeedConfig",setEthSpeedConfig);
	cste_hook_register("getEthSpeedConfig",getEthSpeedConfig);
#endif

#if defined(CONFIG_SUPPORT_CS_IPTV)
	cste_hook_register("setIptvConfig",setIptvConfig);
	cste_hook_register("getIptvConfig",getIptvConfig);
#endif
	cste_hook_register("getDeviceInfo",getDeviceInfo);

	return 0;  
}
