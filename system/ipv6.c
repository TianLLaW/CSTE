
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

#include "ipv6.h"
int setIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
		__FUNC_IN__
		char *strval;
		uint32 val;
		int dhcpMtu,staticMtu,pppoeMtu,i,lanIpPrefixType,lanIpMode,autoDns,connMode,pid,con_mode;
		char *pppoeUser,*pppoePass;
		char src[64] = {};
		FILE *fp=NULL;
		int	if_index;
		int ret;
		int	prefix_len;
		int	if_scope;
		int	if_flag;
		char devname[IFNAMESIZE];
		char cmd[128] = {0};
		struct in6_addr	addr6;
		addr6CfgParam_t addr6_lan;
		addr6CfgParam_t addr6_wan;
		addr6CfgParam_t addr6_gw;
		addr6CfgParam_t addr6_dns1;
		addr6CfgParam_t addr6_dns2;
		addr6CfgParam_t addr6_prefix;
		char *buf1, *buf2, *buf3, *buf4, *buf5, *buf6;

		char_t	*staticIp = websGetVar(data, T("staticIp"),  T(""));
		char_t	*staticGw = websGetVar(data, T("staticGw"),  T(""));
		char_t	*staticPriDns = websGetVar(data, T("staticPriDns"),  T(""));
		char_t	*staticSecDns = websGetVar(data, T("staticSecDns"),  T(""));
		char_t	*wanPriDns = websGetVar(data, T("wanPriDns"),  T(""));
		char_t	*wanSecDns = websGetVar(data, T("wanSecDns"),  T(""));

		int	staticIpPrefixLen = atoi(websGetVar(data, "staticIpPrefixLen",  "64"));
		int lanIpPrefixLen = atoi(websGetVar(data, "lanIpPrefixLen",  "64"));
		char_t	*lanIpPrefix = websGetVar(data, T("lanIpPrefix"),  T(""));
		autoDns = atoi(websGetVar(data, T("autoDns"), T("0")));
		strval=websGetVar(data,T("enabled"), T("0"));
		connMode = atoi(websGetVar(data,T("connMode"),T("2")));
		val= atoi(strval);
		apmib_set(MIB_IPV6_WAN_ENABLE,&val);
		apmib_set(MIB_IPV6_DNS_AUTO, &autoDns);
		apmib_get(MIB_IPV6_ORIGIN_TYPE, &con_mode);
		apmib_set(MIB_IPV6_ORIGIN_TYPE, &connMode);
		printf("---------[connMode]==%d con_mode=%d,\n",connMode,con_mode);
		if(val){
			if(connMode==0)
			{
				int dns_auto=0;
				staticMtu = atoi(websGetVar(data, T("staticMtu"), T("1492")));
				apmib_set(MIB_FIXED_IP_MTU_SIZE,&staticMtu);
				apmib_set(MIB_IPV6_DNS_AUTO,&dns_auto);
			}
			else if(connMode == 1 || connMode ==2)
			{
				pppoeUser = websGetVar(data, T("pppoeUser"), T(""));
				pppoePass = websGetVar(data, T("pppoePass"), T(""));
				pppoeMtu = atoi(websGetVar(data, T("pppoeMtu"), T("1492")));
				dhcpMtu = atoi(websGetVar(data, T("dhcpMtu"), T("1500")));
				
				apmib_set(MIB_PPP_USER_NAME, (void *)pppoeUser);
				apmib_set(MIB_PPP_PASSWORD, (void *)pppoePass);
				apmib_set(MIB_PPP_MTU_SIZE, &pppoeMtu);
				apmib_set(MIB_FIXED_IP_MTU_SIZE,&dhcpMtu);
			}
			apmib_get(MIB_IPV6_ADDR_WAN_PARAM,&addr6_wan);
			apmib_get(MIB_IPV6_ADDR_GW_PARAM,&addr6_gw);
			apmib_get(MIB_IPV6_ADDR_DNS_PARAM,&addr6_dns1);
			apmib_get(MIB_IPV6_ADDR_DNS_SECONDARY,&addr6_dns2);
			for(i=0;i<8;i++){
				if(staticIp[0]){
					buf1=strstr(staticIp,":");
					if(i!=7)
						buf1[0]='\0';
					addr6_wan.addrIPv6[i]=strtol(staticIp,NULL,16);
					if(i!=7)
						staticIp=buf1+1;
				}
				if(staticGw[0]){
					buf2=strstr(staticGw,":");
					if(i!=7)
						buf2[0]='\0';
					addr6_gw.addrIPv6[i]=strtol(staticGw,NULL,16);
					if(i!=7)
						staticGw=buf2+1;
				}
				if(staticPriDns[0]){
						buf3=strstr(staticPriDns,":");
						if(i!=7)
							buf3[0]='\0';
						addr6_dns1.addrIPv6[i]=strtol(staticPriDns,NULL,16);
						if(i!=7)
							staticPriDns=buf3+1;
				}
				if(staticSecDns[0]){
					buf6=strstr(staticSecDns,":");
					if(i!=7)
						buf6[0]='\0';
					addr6_dns2.addrIPv6[i]=strtol(staticSecDns,NULL,16);
					if(i!=7)
						staticSecDns=buf6+1;
				}
				if(wanPriDns[0]){
						buf4=strstr(wanPriDns,":");
						if(i!=7)
							buf4[0]='\0';
						addr6_dns1.addrIPv6[i]=strtol(wanPriDns,NULL,16);
						if(i!=7)
							wanPriDns=buf4+1;
				}
				if(wanSecDns[0]){
					buf5=strstr(wanSecDns,":");
					if(i!=7)
						buf5[0]='\0';
					addr6_dns2.addrIPv6[i]=strtol(wanSecDns,NULL,16);
					if(i!=7)
						wanSecDns=buf5+1;
				}
			}

			addr6_wan.prefix_len=staticIpPrefixLen;
			addr6_gw.prefix_len=staticIpPrefixLen;
			addr6_dns1.prefix_len=staticIpPrefixLen;
			addr6_dns2.prefix_len=staticIpPrefixLen;
			apmib_set(MIB_IPV6_ADDR_WAN_PARAM,&addr6_wan);
			apmib_set(MIB_IPV6_ADDR_GW_PARAM,&addr6_gw);
			apmib_set(MIB_IPV6_ADDR_DNS_PARAM,&addr6_dns1);
			apmib_set(MIB_IPV6_ADDR_DNS_SECONDARY,&addr6_dns2);
			lanIpMode=atoi(websGetVar(data, T("lanIpMode"), T("2")));
			apmib_set(MIB_IPV6_DHCP_MODE,&lanIpMode);
			
			lanIpPrefixType = atoi(websGetVar(data, T("lanIpPrefixType"), T("0")));
			apmib_set(MIB_IPV6_DHCP_PD_ENABLE, &lanIpPrefixType);
			printf("----3---------3-------------3-------\n");
			/*apmib_get(MIB_IPV6_ADDR_LAN_PARAM, &addr6_lan);
			for(i=0;i<8;i++){
				if(lanIpPrefix[0]){
					buf4=strstr(lanIpPrefix,":");
					if(i!=7)
						buf4[0]='\0';
					addr6_lan.addrIPv6[i]=strtol(lanIpPrefix,NULL,16);
					if(i!=7)
						lanIpPrefix=buf4+1;
				}
			}
		printf("----4---------4-------------4-------\n");
			addr6_lan.prefix_len=lanIpPrefixLen;
			apmib_set(MIB_IPV6_ADDR_LAN_PARAM,&addr6_lan);*/
		}
		if(val == 0 || connMode != con_mode)
		{
			printf("[-------else if val=0||con_mode!=connMode]\n");
			fp = fopen(IPV6_ADDR_PROC,"r");
			if(fp!=NULL)
			{
				while((ret=fscanf(fp,"%s %x %x %x %x %s",src,&if_index,&prefix_len,&if_scope,&if_flag,devname))!=EOF)
				{
					if(ret!=6)
						continue;
					
					/*interface match? || strcmp(devname, "ppp0")==0 */	
					if(strcmp(devname, "eth1")==0 ){									
						ret=sscanf(src,"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
									&addr6.s6_addr[ 0], &addr6.s6_addr[ 1], &addr6.s6_addr[ 2], &addr6.s6_addr[ 3],
									&addr6.s6_addr[ 4], &addr6.s6_addr[ 5], &addr6.s6_addr[ 6], &addr6.s6_addr[ 7],
									&addr6.s6_addr[ 8], &addr6.s6_addr[ 9], &addr6.s6_addr[10], &addr6.s6_addr[11],
									&addr6.s6_addr[12], &addr6.s6_addr[13], &addr6.s6_addr[14], &addr6.s6_addr[15]);
						if(addr6.s6_addr16[0]!=ntohs(0xFE80)){
							sprintf(src,"%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx",
										addr6.s6_addr[ 0], addr6.s6_addr[ 1], addr6.s6_addr[ 2], addr6.s6_addr[ 3],
										addr6.s6_addr[ 4], addr6.s6_addr[ 5], addr6.s6_addr[ 6], addr6.s6_addr[ 7],
										addr6.s6_addr[ 8], addr6.s6_addr[ 9], addr6.s6_addr[10], addr6.s6_addr[11],
										addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14], addr6.s6_addr[15]);
							printf("[-------src==%s]\n",src);
							sprintf(cmd, "ifconfig eth1 del %s/64", src);
							CsteSystem(cmd, CSTE_PRINT_CMD);
						}
					}
				}
				fclose(fp);
			}
			CsteSystem("rm -rf var/run/dhcp6c.pid 2> /dev/null", CSTE_PRINT_CMD);
			CsteSystem("killall dhcp6c 2> /dev/null", CSTE_PRINT_CMD);
			CsteSystem("killall ipv6_manage_inet 2> /dev/null", CSTE_PRINT_CMD);
		}

	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
	run_init_script("all");
	__FUNC_OUT__
	websSetCfgResponse(mosq, tp, "45", "reserv");
}
void getPrefixFromFile(char *buff, int* len)
{

	int i = 0, j = 0, ilen; 
	char _len[4] = {0}, prefix[64] = {0};
	if(isFileExist("/var/dhcp6pd.conf")){
		getCmdResult("awk '{print $1}' < /var/dhcp6pd.conf", prefix, sizeof(prefix));
		getCmdResult("awk '{print $2}' < /var/dhcp6pd.conf", _len, sizeof _len);
	}

	*len = atoi(_len);
	ilen = strlen(prefix);
	if(ilen){
		while(j < ilen){
			buff[i] = prefix[j];
			++i;
			++j;
			if(j%4==0 && j!=32){
				buff[i] = ':';
				++i;
			}
		}
	}
}
int getIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
    cJSON *root;
	char staticIp[64]={0},staticGw[64]={0},staticPriDns[64]={0},staticSecDns[64]={0},lanIpPrefix[64]={0},pppoeUser[64]={0},pppoePass[64]={0},lanIpPrefixType[16]={0},autoDns[16]={0},connMode[16]={0},lanIpMode[16]={0},enablde[16]={0};
	int mtu,pppoeMtu,pd_enable=0,ipv6_enable=0,origin_type=0,dns_auto=0,dhcp_mode=0;

	addr6CfgParam_t	addr6_wan;
	addr6CfgParam_t addr6_gw;
	addr6CfgParam_t addr6_dns1;
	addr6CfgParam_t addr6_dns2;
	addr6CfgParam_t addr6_prefix;
	
	__FUNC_IN__
	root=cJSON_CreateObject();

	apmib_get(MIB_IPV6_WAN_ENABLE,(void *)&ipv6_enable);
	sprintf(enablde,"%d",ipv6_enable);
	cJSON_AddStringToObject(root,"enabled",enablde);
	
	apmib_get(MIB_FIXED_IP_MTU_SIZE,&mtu);
	cJSON_AddNumberToObject(root,"staticMtu",mtu);
	cJSON_AddNumberToObject(root,"dhcpMtu",mtu);
	//wan ipv6 type
	apmib_get(MIB_IPV6_ORIGIN_TYPE,(void *)&origin_type);
	sprintf(connMode,"%d",origin_type);
	cJSON_AddStringToObject(root,"connMode",connMode);//0 static 1 pppoe 2 dynamic

	apmib_get(MIB_IPV6_DNS_AUTO, (void *)&dns_auto);
	sprintf(autoDns,"%d",dns_auto);
	cJSON_AddStringToObject(root,"autoDns",autoDns);

	if(origin_type==0){
	//wan ipv6 ip
		apmib_get(MIB_IPV6_ADDR_WAN_PARAM,(void *)&addr6_wan);
		sprintf(staticIp,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_wan.addrIPv6[0],addr6_wan.addrIPv6[1],addr6_wan.addrIPv6[2],addr6_wan.addrIPv6[3]\
			,addr6_wan.addrIPv6[4],addr6_wan.addrIPv6[5],addr6_wan.addrIPv6[6],addr6_wan.addrIPv6[7]);
		cJSON_AddStringToObject(root,"staticIp",staticIp);
		cJSON_AddNumberToObject(root,"staticIpPrefixLen",addr6_wan.prefix_len);

		apmib_get(MIB_IPV6_ADDR_GW_PARAM,(void *)&addr6_gw);
		sprintf(staticGw,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_gw.addrIPv6[0],addr6_gw.addrIPv6[1],addr6_gw.addrIPv6[2],addr6_gw.addrIPv6[3]\
			,addr6_gw.addrIPv6[4],addr6_gw.addrIPv6[5],addr6_gw.addrIPv6[6],addr6_gw.addrIPv6[7]);
		cJSON_AddStringToObject(root,"staticGw",staticGw);
	}else{
		cJSON_AddStringToObject(root,"staticIp","");
		cJSON_AddStringToObject(root,"staticGw","");
	}
	//wan ipv6 dns1
	if(dns_auto==0)
	{
		apmib_get(MIB_IPV6_ADDR_DNS_PARAM,(void *)&addr6_dns1);
		sprintf(staticPriDns,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_dns1.addrIPv6[0],addr6_dns1.addrIPv6[1],addr6_dns1.addrIPv6[2],addr6_dns1.addrIPv6[3]\
			,addr6_dns1.addrIPv6[4],addr6_dns1.addrIPv6[5],addr6_dns1.addrIPv6[6],addr6_dns1.addrIPv6[7]);
		cJSON_AddStringToObject(root,"staticPriDns",staticPriDns);
		cJSON_AddStringToObject(root,"wanPriDns",staticPriDns);
		//wan ipv6 dns2
		apmib_get(MIB_IPV6_ADDR_DNS_SECONDARY,(void *)&addr6_dns2);
		sprintf(staticSecDns,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_dns2.addrIPv6[0],addr6_dns2.addrIPv6[1],addr6_dns2.addrIPv6[2],addr6_dns2.addrIPv6[3]\
			,addr6_dns2.addrIPv6[4],addr6_dns2.addrIPv6[5],addr6_dns2.addrIPv6[6],addr6_dns2.addrIPv6[7]);
		cJSON_AddStringToObject(root,"staticSecDns",staticSecDns);
		cJSON_AddStringToObject(root,"wanSecDns",staticSecDns);
	}else{
		cJSON_AddStringToObject(root,"staticPriDns","");
		cJSON_AddStringToObject(root,"staticSecDns","");
		cJSON_AddStringToObject(root,"wanPriDns","");
		cJSON_AddStringToObject(root,"wanSecDns","");
	}
	
	apmib_get(MIB_IPV6_DHCP_MODE,(void *)&dhcp_mode);
	sprintf(lanIpMode,"%d",dhcp_mode);
	cJSON_AddStringToObject(root, "lanIpMode", lanIpMode);
	//lan ipv6 prefix
	apmib_get(MIB_IPV6_DHCP_PD_ENABLE, (void *)&pd_enable);
	sprintf(lanIpPrefixType,"%d",pd_enable);
	cJSON_AddStringToObject(root, "lanIpPrefixType", lanIpPrefixType);
	if(!atoi(lanIpPrefixType)){
		int lanIpPrefixLen = 0;
		getPrefixFromFile(lanIpPrefix, &lanIpPrefixLen);
	
		cJSON_AddStringToObject(root,"lanIpPrefix", lanIpPrefix);
		cJSON_AddNumberToObject(root,"lanIpPrefixLen", lanIpPrefixLen);
		
	}else{
		apmib_get(MIB_IPV6_ADDR_LAN_PARAM,(void *)&addr6_prefix);
		//apmib_get(MIB_IPV6_ADDR_PFEFIX_PARAM,(void *)&addr6_prefix);
		sprintf(lanIpPrefix,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_prefix.addrIPv6[0],addr6_prefix.addrIPv6[1],addr6_prefix.addrIPv6[2],addr6_prefix.addrIPv6[3],addr6_prefix.addrIPv6[4],addr6_prefix.addrIPv6[5],addr6_prefix.addrIPv6[6],addr6_prefix.addrIPv6[7]);
		cJSON_AddStringToObject(root,"lanIpPrefix",lanIpPrefix);
		cJSON_AddNumberToObject(root,"lanIpPrefixLen",addr6_prefix.prefix_len);
	}
	apmib_get(MIB_PPP_USER_NAME, (void *)&pppoeUser);
	cJSON_AddStringToObject(root,"pppoeUser",pppoeUser);
	apmib_get(MIB_PPP_PASSWORD, (void *)&pppoePass);
	cJSON_AddStringToObject(root,"pppoePass",pppoePass);
	apmib_get(MIB_PPP_MTU_SIZE, &pppoeMtu);
	cJSON_AddNumberToObject(root,"pppoeMtu",pppoeMtu);
	
	output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);

	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

int module_init()
{
    cste_hook_register("setIPv6Config",setIPv6Config);
	cste_hook_register("getIPv6Config",getIPv6Config);
	return 0;  
}

