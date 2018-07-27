
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
		char addr6_wan[64] = {};
		char addr6_gw[64] = {};
		char addr6_dns1[64] = {};
		char addr6_dns2[64] = {};
		addr6CfgParam_t addr6_prefix;
		dhcp6cCfgParam_t dhcp6cCfgParam;
		dnsv6CfgParam_t dnsCfgParam;
		char *submitUrl;
		char* strval;
		uint32 val;
		int pid;
		
		char *pppoeUser, *pppoePass, *staticIp, *staticIpPrefixLen, *staticGw, *staticMtu, *staticPriDns, *staticSecDns;

		strval=websGetVar(data,T("enabled"),T("0"));
		val= atoi(strval);
		apmib_set(MIB_IPV6_WAN_ENABLE,&val);
	
		if(val){
			strval = websGetVar(data,T("connMode"),T("2"));
			val = atoi(strval);
			apmib_set(MIB_IPV6_ORIGIN_TYPE,&val);
			
			if(val==0)
			{
				staticIp = websGetVar(data, T("staticIp"), T(""));
				staticIpPrefixLen = websGetVar(data, T("staticIpPrefixLen"), T(""));
				staticGw = websGetVar(data, T("staticGw"), T(""));
				staticPriDns = websGetVar(data, T("staticPriDns"), T(""));
				staticSecDns = websGetVar(data, T("staticSecDns"), T(""));
				
				staticMtu = websGetVar(data, T("staticMtu"), T("1500"));
				apmib_set(MIB_FIXED_IP_MTU_SIZE, (void *)&staticMtu);
			}
			else if(val == 1)
			{
				pppoe_user = websGetVar(data, T("pppoeUser"), T(""));
				pppoe_pass = websGetVar(data, T("pppoePass"), T(""));
				mtu = atoi(websGetVar(data, T("pppoeMtu"), T("1492")));
	
				apmib_set(MIB_PPP_USER_NAME, (void *)pppoe_user);
				apmib_set(MIB_PPP_PASSWORD, (void *)pppoe_pass);
				apmib_set(MIB_PPP_MTU_SIZE, (void *)&mtu);
			}
			else
			{

			
			}

			strval=websGetVar(data,T("dnsMode"),T("0"));
			val=atoi(strval);			
			apmib_set(MIB_IPV6_DNS_AUTO,&val);
	
			strval=websGetVar(data,T("staticIPv6"),T(""));
			strcpy(addr6_wan, strval);

			apmib_set(MIB_IPV6_ADDR_WAN_PARAM, &addr6_wan);
			memset(addr6_wan, 0 , sizeof(addr6_wan));
			if ( !apmib_get(MIB_IPV6_ADDR_WAN_PARAM,(void *)addr6_wan)){
				fprintf(stderr, "get mib %d error!\n", MIB_IPV6_ADDR_WAN_PARAM);
				return ;        
			}

			strval=websGetVar(data,T("staticGw"),T(""));
			strcpy(addr6_gw, strval);
			
			apmib_set(MIB_IPV6_ADDR_GW_PARAM, &addr6_gw);				

			if(!apmib_get(MIB_IPV6_DNS_AUTO,  (void *)&val))
			{
			 printf("get MIB_IPV6_DNS_AUTO failed\n");
			 return -1; 
			}
			if(val==0)	//Set DNS Manually 
			{
			strval=websGetVar(data,T("staticPriDns"),T(""));
			strcpy(addr6_dns1, strval);

			apmib_set(MIB_IPV6_ADDR_DNS_PARAM, &addr6_dns1);
			
			strval=websGetVar(data,T("staticSecDns"),T(""));
			strcpy(addr6_dns2, strval);

			
			apmib_set(MIB_IPV6_ADDR_DNS_SECONDARY, &addr6_dns2);
			}

			getDnsv6Info(&dnsCfgParam);
			set_DnsParam(mosq, data, tp,&dnsCfgParam);		
			apmib_set(MIB_IPV6_DNSV6_PARAM,&dnsCfgParam);
			
		}	
		setIPv6RadvdCfg(mosq, data, tp);

	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
	run_init_script("all");
	__FUNC_OUT__
	websSetCfgResponse(mosq, tp, "30", "reserv");
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
	char* output,enablde,wantype;
    cJSON *root;
	char IPv6Address[64]={0},IPv6LanAddress[64]={0},IPv6Gateway[64]={0},IPv6DNS1[64]={0},IPv6DNS2[64]={0},IPv6Prefix[64]={0},RadvdIPv6Prefix[64]={0},IPv6rdPrefix[64]={0},Ip4addr[20]={0},pppoe_user[20]={0}, pppoe_pass[20]={0};
	int pass_through, delegation,IPv4MaskLength,mtu,pppoe_mtu,ipv6DnsAuto;

	addr6CfgParam_t	addr6_wan;
	addr6CfgParam_t	addr6_lan;
	addr6CfgParam_t addr6_gw;
	addr6CfgParam_t addr6_dns1;
	addr6CfgParam_t addr6_dns2;
	addr6CfgParam_t addr6_prefix;
	tunnelCfgParam_t tunnelCfgParam;
	dhcp6sCfgParam_t dhcp6sCfgParam;
	radvdCfgParam_t radvdCfgParam;
	
	__FUNC_IN__
	root=cJSON_CreateObject();

	apmib_get(MIB_IPV6_WAN_ENABLE,&enablde);
	cJSON_AddNumberToObject(root,"enabled",enablde);
	
	apmib_get(MIB_FIXED_IP_MTU_SIZE, &mtu);
	cJSON_AddNumberToObject(root,"staticMtu",mtu);
	cJSON_AddNumberToObject(root,"dhcpMtu",mtu);
	//wan ipv6 type
	apmib_get(MIB_IPV6_ORIGIN_TYPE,&wantype);
	cJSON_AddNumberToObject(root,"connMode",wantype);//0 static 1 pppoe 2 dynamic


	apmib_get(MIB_IPV6_DNS_AUTO, &ipv6DnsAuto); 
	cJSON_AddNumberToObject(root,"dnsMode",ipv6DnsAuto);

	//apmib_get(MIB_MLD_PROXY_DISABLED,&mldproxyDisabled);
	//cJSON_AddNumberToObject(root,"mldproxyDisabled",mldproxyDisabled);
	//wan ipv6 ip
	apmib_get(MIB_IPV6_ADDR_WAN_PARAM,(void *)&addr6_wan);
	sprintf(IPv6Address,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_wan.addrIPv6[0],addr6_wan.addrIPv6[1],addr6_wan.addrIPv6[2],addr6_wan.addrIPv6[3]\
		,addr6_wan.addrIPv6[4],addr6_wan.addrIPv6[5],addr6_wan.addrIPv6[6],addr6_wan.addrIPv6[7]);
	cJSON_AddStringToObject(root,"staticIPv6",IPv6Address);
	cJSON_AddNumberToObject(root,"WanIPv6PrefixLength",addr6_wan.prefix_len);

	apmib_get(MIB_IPV6_ADDR_GW_PARAM,(void *)&addr6_gw);
	sprintf(IPv6Gateway,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_gw.addrIPv6[0],addr6_gw.addrIPv6[1],addr6_gw.addrIPv6[2],addr6_gw.addrIPv6[3]\
		,addr6_gw.addrIPv6[4],addr6_gw.addrIPv6[5],addr6_gw.addrIPv6[6],addr6_gw.addrIPv6[7]);
	cJSON_AddStringToObject(root,"staticGw",IPv6Gateway);
	//wan ipv6 dns1
	apmib_get(MIB_IPV6_ADDR_DNS_PARAM,(void *)&addr6_dns1);
	sprintf(IPv6DNS1,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_dns1.addrIPv6[0],addr6_dns1.addrIPv6[1],addr6_dns1.addrIPv6[2],addr6_dns1.addrIPv6[3]\
		,addr6_dns1.addrIPv6[4],addr6_dns1.addrIPv6[5],addr6_dns1.addrIPv6[6],addr6_dns1.addrIPv6[7]);
	cJSON_AddStringToObject(root,"staticPriDns",IPv6DNS1);
	//wan ipv6 dns2
	apmib_get(MIB_IPV6_ADDR_DNS_SECONDARY,(void *)&addr6_dns2);
	sprintf(IPv6DNS2,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_dns2.addrIPv6[0],addr6_dns2.addrIPv6[1],addr6_dns2.addrIPv6[2],addr6_dns2.addrIPv6[3]\
		,addr6_dns2.addrIPv6[4],addr6_dns2.addrIPv6[5],addr6_dns2.addrIPv6[6],addr6_dns2.addrIPv6[7]);
	cJSON_AddStringToObject(root,"staticSecDns",IPv6DNS2);

	//lan ipv6 addr
	apmib_get(MIB_IPV6_ADDR_LAN_PARAM,&addr6_lan);
	sprintf(IPv6LanAddress,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_lan.addrIPv6[0],addr6_lan.addrIPv6[1],addr6_lan.addrIPv6[2],addr6_lan.addrIPv6[3]\
		,addr6_lan.addrIPv6[4],addr6_lan.addrIPv6[5],addr6_lan.addrIPv6[6],addr6_lan.addrIPv6[7]);
	cJSON_AddStringToObject(root,"LanIPv6Address",IPv6LanAddress);
	//lan ipv6 type
	//dhcp6s
	apmib_get(MIB_IPV6_DHCPV6S_PARAM,(void *)&dhcp6sCfgParam);
	//radvd
	apmib_get(MIB_IPV6_RADVD_PARAM,(void *)&radvdCfgParam);
	if(radvdCfgParam.enabled==1)
		cJSON_AddStringToObject(root,"LanIPv6Type","SLAAC");
	else
		cJSON_AddStringToObject(root,"LanIPv6Type","DHCPv6");
	
	//dhcp6s pool
	if(!strlen(dhcp6sCfgParam.addr6PoolS) || strcmp(dhcp6sCfgParam.addr6PoolS, "0000:0000:0000:0000:0000:0000:0000:0000")==0){
		cJSON_AddStringToObject(root,"StartIpv6Address", "2001:0a1c:0000:0083:0000:0000:0000:0001");
		cJSON_AddStringToObject(root,"EndIpv6Address", "2001:0a1c:0000:0083:0000:0000:0000:00ff");
	}else{
		cJSON_AddStringToObject(root,"StartIpv6Address",dhcp6sCfgParam.addr6PoolS);
		cJSON_AddStringToObject(root,"EndIpv6Address",dhcp6sCfgParam.addr6PoolE);
	}
	//lan ipv6 prefix
	apmib_get(MIB_IPV6_DHCP_PD_ENABLE, &delegation);
	cJSON_AddNumberToObject(root, "lanIpPrefixType", delegation);
	if(delegation){
		int len = 0;
		char prefix[64] = {0};
		getPrefixFromFile(prefix, &len);
		
		cJSON_AddStringToObject(root,"lanIpPrefix", prefix);
		cJSON_AddNumberToObject(root,"lanIpPrefixLen", len);
		
	}else{
		apmib_get(MIB_IPV6_ADDR_PFEFIX_PARAM,(void *)&addr6_prefix);
		sprintf(IPv6Prefix,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_prefix.addrIPv6[0],addr6_prefix.addrIPv6[1],addr6_prefix.addrIPv6[2],addr6_prefix.addrIPv6[3],addr6_prefix.addrIPv6[4],addr6_prefix.addrIPv6[5],addr6_prefix.addrIPv6[6],addr6_prefix.addrIPv6[7]);
		cJSON_AddStringToObject(root,"lanIpPrefix",IPv6Prefix);
		cJSON_AddNumberToObject(root,"lanIpPrefixLen",addr6_prefix.prefix_len);
	}

	sprintf(RadvdIPv6Prefix,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",radvdCfgParam.interface.prefix[0].Prefix[0],radvdCfgParam.interface.prefix[0].Prefix[1],\
			radvdCfgParam.interface.prefix[0].Prefix[2],radvdCfgParam.interface.prefix[0].Prefix[3],radvdCfgParam.interface.prefix[0].Prefix[4], \
			radvdCfgParam.interface.prefix[0].Prefix[5],radvdCfgParam.interface.prefix[0].Prefix[6],radvdCfgParam.interface.prefix[0].Prefix[7]);
	cJSON_AddStringToObject(root,"RadvdLanIPv6Prefix",RadvdIPv6Prefix);
	apmib_get(MIB_PPP_USER_NAME, (void *)&pppoe_user);
	cJSON_AddStringToObject(root,"pppoeUser",pppoe_user);
	apmib_get(MIB_PPP_PASSWORD, (void *)&pppoe_pass);
	cJSON_AddStringToObject(root,"pppoePass",pppoe_pass);
	apmib_get(MIB_PPP_MTU_SIZE, (void *)&pppoe_mtu);
	cJSON_AddNumberToObject(root,"pppoeMtu",pppoe_mtu);
	cJSON_AddNumberToObject(root,"RadvdLanIPv6PrefixLength",radvdCfgParam.interface.prefix[0].PrefixLen);
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

