
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

#include "ipv6.h"

static int set_RadvdInterfaceParam(struct mosquitto *mosq, cJSON* data,char *tp, radvdCfgParam_t *pradvdCfgParam)
{
	char *tmp;
	uint32 value;

	/*check if enabled*/
	/*get cfg data from web*/
	tmp=websGetVar(data,T("RadvdInterFaceName"),T(""));
	if(strcmp(tmp,pradvdCfgParam->interface.Name))
	{
		/*interface name changed*/
		strcpy(pradvdCfgParam->interface.Name, tmp);
	}
	value =atoi(websGetVar(data,T("MaxRtrAdvInterval"),T("")));
	if(value != pradvdCfgParam->interface.MaxRtrAdvInterval)
	{
		pradvdCfgParam->interface.MaxRtrAdvInterval = value;
	}
	value =atoi(websGetVar(data,T("MinRtrAdvInterval"),T("")));
	if(value != pradvdCfgParam->interface.MinRtrAdvInterval)
	{
		pradvdCfgParam->interface.MinRtrAdvInterval = value;
	}
	value =atoi(websGetVar(data,T("MinDelayBetweenRAs"),T("")));
	if(value != pradvdCfgParam->interface.MinDelayBetweenRAs)
	{
		pradvdCfgParam->interface.MinDelayBetweenRAs = value;
	}
	value =atoi(websGetVar(data,T("AdvManagedFlag"),T("")));
	if(value > 0)
	{
		pradvdCfgParam->interface.AdvManagedFlag = 1;
	}
	else
	{
		pradvdCfgParam->interface.AdvManagedFlag =0; 
	}
	value =atoi(websGetVar(data,T("AdvOtherConfigFlag"),T("")));
	if(value >0)
	{
		pradvdCfgParam->interface.AdvOtherConfigFlag = 1;
	}
	else
	{
		pradvdCfgParam->interface.AdvOtherConfigFlag =0;
	}
	value =atoi(websGetVar(data,T("AdvLinkMTU"),T("")));
	if(value != pradvdCfgParam->interface.AdvLinkMTU)
	{
		pradvdCfgParam->interface.AdvLinkMTU = value;
	}
	/*replace atoi by strtoul to support max value test of ipv6 phase 2 test*/
	tmp = websGetVar(data,T("AdvReachableTime"),T(""));
	value = strtoul(tmp,NULL,10);
	if(value != pradvdCfgParam->interface.AdvReachableTime)
	{
		pradvdCfgParam->interface.AdvReachableTime = value;
	}
	
	/*replace atoi by strtoul to support max value test of ipv6 phase 2 test*/
	tmp = websGetVar(data,T("AdvRetransTimer"),T(""));
	value = strtoul(tmp,NULL,10);	
	if(value != pradvdCfgParam->interface.AdvRetransTimer)
	{
		pradvdCfgParam->interface.AdvRetransTimer = value;
	}
	value =atoi(websGetVar(data,T("AdvCurHopLimit"),T("")));
	if(value != pradvdCfgParam->interface.AdvCurHopLimit)
	{
		pradvdCfgParam->interface.AdvCurHopLimit = value;
	}
	value =atoi(websGetVar(data,T("AdvDefaultLifetime"),T("")));
	if(value != pradvdCfgParam->interface.AdvDefaultLifetime)
	{
		pradvdCfgParam->interface.AdvDefaultLifetime = value;
	}
	tmp=websGetVar(data,T("AdvDefaultPreference"),T(""));
	if(strcmp(tmp,pradvdCfgParam->interface.AdvDefaultPreference))
	{
		/*interface name changed*/
		strcpy(pradvdCfgParam->interface.AdvDefaultPreference, tmp);
	}
	value =atoi(websGetVar(data,T("AdvsourceLLAddress"),T("")));
	
	if(value > 0)
	{
		pradvdCfgParam->interface.AdvSourceLLAddress = 1;
	}
	else
	{
		pradvdCfgParam->interface.AdvSourceLLAddress=0; 
	}
	value =atoi(websGetVar(data,T("UnicastOnly"),T("")));
	if(value > 0)
	{
		pradvdCfgParam->interface.UnicastOnly = 1;
	}
	else
	{
		pradvdCfgParam->interface.UnicastOnly =0;
	}

	return 0;
}

static int set_RadvdPrefixParam(struct mosquitto *mosq, cJSON* data,char *tp, radvdCfgParam_t *pradvdCfgParam)
{
	/*get cfg data from web*/
	char *tmpstr;
	char tmpname[30]={0};
	char tmpaddr[30]={0};
	char prefix[64]={0};
	uint32 value;
	int i,j;

	for(j=0;j<MAX_PREFIX_NUM;j++)
	{
		/*get prefix j*/
		sprintf(tmpname,"Enabled_%d",j);
		value=atoi(websGetVar(data,T(tmpname),T("")));
		//printf("enabled_%d =%d\n",j,value);
		if(value >0)
		{
			pradvdCfgParam->interface.prefix[j].enabled = 1;
			
		}
		else
		{
			pradvdCfgParam->interface.prefix[j].enabled = 0;
		}
		
#ifdef CONFIG_IPV6_CE_ROUTER_SUPPORT
		sprintf(tmpname,"radvdprefix%d_mode",j);
		value=atoi(websGetVar(data,T(tmpname),T("")));
		pradvdCfgParam->interface.prefix[j].prefix_mode = value;

		if(value == 0)
		{
#endif

		tmpstr = websGetVar(data,T("Prefix"),T(""));
		printf("tmpstr = %s\n", tmpstr);
		strcpy(pradvdCfgParam->interface.prefix[j].Prefix, tmpstr);

		
/*
		for(i=0;i<8;i++)
		{			
			sprintf(tmpname,"radvdprefix%d_%d",j, i+1);
			sprintf(tmpaddr,"0x%s",websGetVar(data,T(tmpname),T("")));
			value =strtol(tmpaddr,NULL,16);
			pradvdCfgParam->interface.prefix[j].Prefix[i]= value;
		}
*/
#ifdef CONFIG_IPV6_CE_ROUTER_SUPPORT
		}
		else
		{
			for(i=0;i<8;i++)
			{			
				pradvdCfgParam->interface.prefix[j].Prefix[i]= 0;
			}
		}
#endif

/*		sprintf(tmpname,"radvdprefix%d_len",j);
		value =atoi(websGetVar(data,T(tmpname),T("")));
		if(value != pradvdCfgParam->interface.prefix[j].PrefixLen)
		{
			pradvdCfgParam->interface.prefix[j].PrefixLen = value;
		}
*/
		sprintf(tmpname,"AdvOnLinkFlag_%d",j);
		value =atoi(websGetVar(data,T(tmpname),T("")));
		if(value >0)
		{
			pradvdCfgParam->interface.prefix[j].AdvOnLinkFlag = 1;
		}
		else
		{
			pradvdCfgParam->interface.prefix[j].AdvOnLinkFlag = 0;
		}

		sprintf(tmpname,"AdvAutonomousFlag_%d",j);
		value =atoi(websGetVar(data,T(tmpname),T("")));
		if(value >0)
		{
			pradvdCfgParam->interface.prefix[j].AdvAutonomousFlag = 1;
		}
		else
		{					
			pradvdCfgParam->interface.prefix[j].AdvAutonomousFlag = 0;
		}		
		sprintf(tmpname,"AdvValidLifetime_%d",j);
		tmpstr = websGetVar(data,T(tmpname),T(""));
		/*replace atoi by strtoul to support max value test of ipv6 phase 2 test*/
		value = strtoul(tmpstr,NULL,10);
		if(value != pradvdCfgParam->interface.prefix[j].AdvValidLifetime)
		{
			pradvdCfgParam->interface.prefix[j].AdvValidLifetime = value;
		}
		sprintf(tmpname,"AdvPreferredLifetime_%d",j);
		tmpstr = websGetVar(data,T(tmpname),T(""));
		/*replace atoi by strtoul to support max value test of ipv6 phase 2 test*/
		value = strtoul(tmpstr,NULL,10);
		if(value != pradvdCfgParam->interface.prefix[j].AdvPreferredLifetime)
		{
			pradvdCfgParam->interface.prefix[j].AdvPreferredLifetime = value;
		}
		sprintf(tmpname,"AdvRouterAddr_%d",j);
		value =atoi(websGetVar(data,T(tmpname),T("")));
		if(value >0)
		{
			pradvdCfgParam->interface.prefix[j].AdvRouterAddr = 1;
		}
		else
		{
			pradvdCfgParam->interface.prefix[j].AdvRouterAddr=0;
		}
		sprintf(tmpname,"if6to4_%d",j);
		tmpstr =websGetVar(data,T(tmpname),T(""));
		if(strcmp(pradvdCfgParam->interface.prefix[j].if6to4, tmpstr))
		{
			/*interface name changed*/
			strcpy(pradvdCfgParam->interface.prefix[j].if6to4, tmpstr);
		}
	}

	return 0;
}

static int getRadvdInfo(radvdCfgParam_t *entry)
{
	if ( !apmib_get(MIB_IPV6_RADVD_PARAM,(void *)entry)){
		return -1 ;        
	}
	return 0;
}
static int  set_RadvdParam(struct mosquitto *mosq, cJSON* data,char *tp, radvdCfgParam_t *pradvdCfgParam)
{
	
	int enable;
	enable=atoi(websGetVar(data,T("enable_radvd"),T("")));
             
    printf("enable = %d\n", enable);
	if(enable ^ pradvdCfgParam->enabled )
	{
       	pradvdCfgParam->enabled = enable;
	}
	set_RadvdInterfaceParam(mosq,data,tp,pradvdCfgParam);
	set_RadvdPrefixParam(mosq,data,tp,pradvdCfgParam);
	
	return 0;
}

static int  set_DnsParam(struct mosquitto *mosq, cJSON* data, char *tp, dnsv6CfgParam_t *pdnsv6CfgParam)
{
	char *value;
	int enable;
	/*check if enabled*/
	enable=atoi(websGetVar(data,T("enable_dnsv6"),T("")));
	if(enable ^ pdnsv6CfgParam->enabled )
	{
       	pdnsv6CfgParam->enabled = enable;
	}
	if(enable)
	{
		value = websGetVar(data,T("routername"),T(""));
		strcpy(pdnsv6CfgParam->routerName,value);
	}
	return 0;
}


static int getDnsv6Info(dnsv6CfgParam_t *entry)
{
	if ( !apmib_get(MIB_IPV6_DNSV6_PARAM,(void *)entry)){
		return -1 ;        
	}
	return 0;
}

int setIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
		__FUNC_IN__
		char addr6_wan[64] = {};
		char addr6_gw[64] = {};
		char addr6_dns1[64] = {};
		char addr6_dns2[64] = {};
		addr6CfgParam_t addr6_prefix;
		addr6CfgParam_t addr6_6rd_prefix;
		dhcp6cCfgParam_t dhcp6cCfgParam;
		dnsv6CfgParam_t dnsCfgParam;
		char *submitUrl;
		char* strval;
		uint32 val;
		int pid,repid_commit=0,mtu=0,optime=0,spectype=0,opmode=0;
		
		int ctype=0;
		char_t  *pppoe_user, *pppoe_pass, *pppoe_opmode;

		strval=websGetVar(data,T("enabled"),T(""));
		val= atoi(strval);
		apmib_set(MIB_IPV6_WAN_ENABLE,&val);//ipv6的开关
	
		if(val){
			strval=websGetVar(data,T("OriginType"),T(""));//模式0pppoe，1静态，2动态
			if(strval!=NULL){
				val= atoi(strval);
				apmib_set(MIB_IPV6_ORIGIN_TYPE,&val);
			}
			
			strval=websGetVar(data,T("linkType"),T(""));
			if(strval!=NULL){
				val=atoi(strval);			
				apmib_set(MIB_IPV6_LINK_TYPE,&val);
			}
			if(!apmib_get(MIB_IPV6_ORIGIN_TYPE,  (void *)&val))
			{
			 	printf("get MIB_IPV6_ORIGIN_TYPE failed\n");
			 	return -1; 
			}
			
			if(val==1 || val == 2)
			{
				mtu = atoi(websGetVar(data, T("static_mtu"), T("1500")));
				apmib_set(MIB_FIXED_IP_MTU_SIZE, (void *)&mtu);
			}else if(val == 0)
			{
				ctype = atoi(websGetVar(data, T("connectionType"), T("0")));
				apmib_set(MIB_WAN_DHCP, (void *)&ctype);
				
				pppoe_user = websGetVar(data, T("pppoeUser"), T(""));//pppoe用户名
				pppoe_pass = websGetVar(data, T("pppoePass"), T(""));//pppoe密码
				opmode = atoi(websGetVar(data, T("pppoeOPMode"), T("0")));
				mtu = atoi(websGetVar(data, T("pppoeMtu"), T("1492")));
				spectype = atoi(websGetVar(data, T("pppoeSpecType"), T("0")));
				optime = atoi(websGetVar(data, T("pppoeRedialPeriod"), T("60"))) * 60;
	
				apmib_set(MIB_PPP_USER_NAME, (void *)pppoe_user);
				apmib_set(MIB_PPP_PASSWORD, (void *)pppoe_pass);
				apmib_set(MIB_PPP_MTU_SIZE, (void *)&mtu);
				apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&opmode);
				apmib_set(MIB_PPP_IDLE_TIME, (void *)&optime);
				apmib_set(MIB_PPP_SPEC_TYPE, (void *)&spectype);
			
			}

			strval=websGetVar(data,T("dnsType"),T(""));
			
			if(strval[0]){
				val=atoi(strval);
				printf("dnsType = %d\n", val);			
				apmib_set(MIB_IPV6_DNS_AUTO,&val);//DNS服务器0 使用下列的DNS地址，1 从ISP动态获取
			}
			strval=websGetVar(data,T("enable_dhcpv6RapidCommit"),T(""));
			val = atoi(strval);
			if(val == 1){
				repid_commit=1;					
			}
			if(apmib_set(MIB_IPV6_DHCP_RAPID_COMMIT_ENABLE,(void*)&repid_commit)==0)
			{
				printf("set MIB_IPV6_DHCP_RAPID_COMMIT_ENABLE fail!\n");
				return;
			}
			
			strval=websGetVar(data,T("dhcpMode"),T(""));
			if(strval[0]){
				if(strcmp(strval,"stateless")==0)
					val=IPV6_DHCP_STATELESS;
				else
				{
					val=IPV6_DHCP_STATEFUL;
					
				}

				apmib_set(MIB_IPV6_DHCP_MODE,&val);
			}
			strval=websGetVar(data,T("enable_dhcpv6pd"),T(""));	
			
			if(strval!=NULL){
				val = atoi(strval);
				apmib_set(MIB_IPV6_DHCP_PD_ENABLE,&val);
			}				
		
			strval=websGetVar(data,T("static_ipv6"),T(""));
			strcpy(addr6_wan, strval);

			apmib_set(MIB_IPV6_ADDR_WAN_PARAM, &addr6_wan);
			memset(addr6_wan, 0 , sizeof(addr6_wan));
			if ( !apmib_get(MIB_IPV6_ADDR_WAN_PARAM,(void *)addr6_wan)){
				fprintf(stderr, "get mib %d error!\n", MIB_IPV6_ADDR_WAN_PARAM);
				return ;        
			}

			strval=websGetVar(data,T("static_gw"),T(""));
			strcpy(addr6_gw, strval);
			
			apmib_set(MIB_IPV6_ADDR_GW_PARAM, &addr6_gw);				

			if(!apmib_get(MIB_IPV6_DNS_AUTO,  (void *)&val))
			{
			 printf("get MIB_IPV6_DNS_AUTO failed\n");
			 return -1; 
			}
			if(val==0)	//Set DNS Manually 
			{
			strval=websGetVar(data,T("static_dns1"),T(""));
			strcpy(addr6_dns1, strval);

			apmib_set(MIB_IPV6_ADDR_DNS_PARAM, &addr6_dns1);
			
			strval=websGetVar(data,T("static_dns2"),T(""));
			strcpy(addr6_dns2, strval);

			
			apmib_set(MIB_IPV6_ADDR_DNS_SECONDARY, &addr6_dns2);
			}
			


			/*Get parameters*/
			getDnsv6Info(&dnsCfgParam);
			/*Set to Parameters*/
			set_DnsParam(mosq, data, tp,&dnsCfgParam);				
			/*Set to pMIb*/
			apmib_set(MIB_IPV6_DNSV6_PARAM,&dnsCfgParam);
			
			strval = websGetVar(data, T("mldproxyEnabled"), T(""));
			printf("strval=%s.\n", strval);
			if ( !strcmp(strval, "ON"))
				val = 0;
			else
				val = 1;
			if ( !apmib_set(MIB_MLD_PROXY_DISABLED, (void *)&val)) {
				printf ("Set MIB_MLD_PROXY_DISABLED error!");
				return;
			}
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
	websSetCfgResponse(mosq, tp, "45", "reserv");
}

int getIPv6Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root;
	char IPv6Address[128]={0},IPv6LanAddress[128]={0},IPv6Gateway[128]={0},IPv6DNS1[128]={0},IPv6Prefix[128]={0},RadvdIPv6Prefix_0[128]={0},RadvdIPv6Prefix_1[128]={0},DhcpDuid[50]={0},IPv6DNS2[128]={0},dns[64]={0},dns2[64]={0};
	int enabled,wantype,pass_through,dhcpMode,ipv6DnsAuto,linkType,enable_dhcpv6pd,enable_dhcpv6RapidCommit,mldproxyDisabled,mtu,pppoe_mtu,prefix_type, opmode;

	addr6CfgParam_t	addr6_wan;
	addr6CfgParam_t	addr6_lan;
	addr6CfgParam_t addr6_gw;
	addr6CfgParam_t addr6_dns;
	addr6CfgParam_t addr6_prefix;
	tunnelCfgParam_t tunnelCfgParam;
	dhcp6sCfgParam_t dhcp6sCfgParam;
	radvdCfgParam_t radvdCfgParam;
	struct duid_t dhcp6c_duid={0};
	struct sockaddr hwaddr={0};
	dhcp6c_duid.duid_type=3;
	dhcp6c_duid.hw_type=1;
	
	FILE *fp=NULL;
	struct in6_addr	addr6;
	char src[64] = {};
	int	if_index;
	int ret;
	int	prefix_len;
	int	if_scope;
	int	if_flag;
	char devname[IFNAMESIZE];

	char  pppoe_user[20]={0}, pppoe_pass[20]={0};
	
	__FUNC_IN__
	root=cJSON_CreateObject();

	apmib_get(MIB_IPV6_WAN_ENABLE,&enabled);
	cJSON_AddNumberToObject(root,"enabled",enabled);
	
	apmib_get(MIB_FIXED_IP_MTU_SIZE, &mtu);//静态MTU
	cJSON_AddNumberToObject(root,"static_mtu",mtu);

	//wan ipv6 type
	apmib_get(MIB_IPV6_ORIGIN_TYPE,&wantype);
	apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&pass_through);
	apmib_get(MIB_IPV6_TUNNEL_PARAM,(void *)&tunnelCfgParam);

	cJSON_AddNumberToObject(root,"WanIPv6Type",wantype);//0:'DHCPv6',1:'Static IPv6'
	cJSON_AddNumberToObject(root,"tunnelEnable",tunnelCfgParam.enabled);

	if ( getInAddr( _IPV6_WAN_INTERFACE, HW_ADDR_T, (void *)&hwaddr )==0)
		fprintf(stderr, "Read hwaddr Error\n");

	memcpy(dhcp6c_duid.mac,hwaddr.sa_data,6);
	
	sprintf(DhcpDuid,"%04x%04x%02x%02x%02x%02x%02x%02x",dhcp6c_duid.duid_type,dhcp6c_duid.hw_type,dhcp6c_duid.mac[0],dhcp6c_duid.mac[1],dhcp6c_duid.mac[2],dhcp6c_duid.mac[3],dhcp6c_duid.mac[4],dhcp6c_duid.mac[5]);
	cJSON_AddStringToObject(root,"DhcpDuid",DhcpDuid);
 	
        apmib_get(MIB_IPV6_DHCP_MODE, &dhcpMode);
	cJSON_AddNumberToObject(root,"dhcpMode",dhcpMode);

	apmib_get(MIB_IPV6_DNS_AUTO, &ipv6DnsAuto); //DNS服务器0 使用下列的DNS地址，1 从ISP动态获取
	cJSON_AddNumberToObject(root,"ipv6DnsAuto",ipv6DnsAuto);

	apmib_get(MIB_IPV6_LINK_TYPE,&linkType);
	if(linkType==IPV6_LINKTYPE_IP)
		cJSON_AddStringToObject(root,"ipv6LinkType","IP link");
	else	
		cJSON_AddStringToObject(root,"ipv6LinkType","PPP link");

	apmib_get(MIB_IPV6_DHCP_PD_ENABLE,&enable_dhcpv6pd);
	cJSON_AddNumberToObject(root,"enable_dhcpv6pd",enable_dhcpv6pd);

	apmib_get(MIB_IPV6_DHCP_RAPID_COMMIT_ENABLE,&enable_dhcpv6RapidCommit);
	cJSON_AddNumberToObject(root,"enable_dhcpv6RapidCommit",enable_dhcpv6RapidCommit);

	apmib_get(MIB_MLD_PROXY_DISABLED,&mldproxyDisabled);
	cJSON_AddNumberToObject(root,"mldproxyDisabled",mldproxyDisabled);
	//wan ipv6 ip
	apmib_get(MIB_IPV6_WAN_ADDR,(void *)&IPv6Address);//静态IPv6地址
	cJSON_AddStringToObject(root,"IPv6Address",IPv6Address);

	apmib_get(MIB_IPV6_GW_ADDR,(void *)&IPv6Gateway);//静态IPv6网关
	cJSON_AddStringToObject(root,"IPv6Gateway",IPv6Gateway);
	//wan ipv6 dns
	apmib_get(MIB_IPV6_ADDR_DNS_PARAM,(void *)&IPv6DNS1);//pppoeDNS1 静态DNS1
	cJSON_AddStringToObject(root,"IPv6DNS1",IPv6DNS1);
	apmib_get(MIB_IPV6_ADDR_DNS_SECONDARY,(void *)&IPv6DNS2);//pppoeDNS2 静态DNS2
	cJSON_AddStringToObject(root,"IPv6DNS2",IPv6DNS2);
	
	apmib_get(MIB_IPV6_ADDR_DNS_PARAM, (void *)dns);
	cJSON_AddStringToObject(root,"RDDNS",dns);//wan 地址不为空时dhcp_dns ipv6DnsAuto!=0自动
	
	apmib_get(MIB_IPV6_ADDR_DNS_SECONDARY, (void *)dns2);//wan 地址不为空时dhcp_dns2 ipv6DnsAuto!=0自动
	cJSON_AddStringToObject(root,"RDDNS2",dns2);

	//lan ipv6 addr
	apmib_get(MIB_IPV6_ADDR_LAN_PARAM,&addr6_lan);
	sprintf(IPv6LanAddress,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_lan.addrIPv6[0],addr6_lan.addrIPv6[1],addr6_lan.addrIPv6[2],addr6_lan.addrIPv6[3]\
		,addr6_lan.addrIPv6[4],addr6_lan.addrIPv6[5],addr6_lan.addrIPv6[6],addr6_lan.addrIPv6[7]);
	cJSON_AddStringToObject(root,"LanIPv6Address",IPv6LanAddress);
	cJSON_AddNumberToObject(root,"IPv6LanPrefix",addr6_lan.prefix_len);
	//lan ipv6 type
	//dhcp6s
	apmib_get(MIB_IPV6_DHCPV6S_PARAM,(void *)&dhcp6sCfgParam);
	//radvd
	apmib_get(MIB_IPV6_RADVD_PARAM,(void *)&radvdCfgParam);

	apmib_get(MIB_PREFIX_TYPE,(void *)&prefix_type);
	cJSON_AddNumberToObject(root,"prefix_type",prefix_type);

	if(radvdCfgParam.enabled==1)
		cJSON_AddStringToObject(root,"LanIPv6Type","SLAAC");
	else
		cJSON_AddStringToObject(root,"LanIPv6Type","DHCPv6");
	
	cJSON_AddStringToObject(root,"StartIpv6Address",dhcp6sCfgParam.addr6PoolS);
	cJSON_AddStringToObject(root,"EndIpv6Address",dhcp6sCfgParam.addr6PoolE);
	cJSON_AddStringToObject(root,"IPv6Dnsaddr",dhcp6sCfgParam.DNSaddr6);
	cJSON_AddStringToObject(root,"interfaceNameds",dhcp6sCfgParam.interfaceNameds);
	cJSON_AddNumberToObject(root,"enable_dhcpv6s",dhcp6sCfgParam.enabled);
	//lan ipv6 prefix
	apmib_get(MIB_IPV6_ADDR_PFEFIX_PARAM,(void *)&addr6_prefix);
	sprintf(IPv6Prefix,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",addr6_prefix.addrIPv6[0],addr6_prefix.addrIPv6[1],addr6_prefix.addrIPv6[2],addr6_prefix.addrIPv6[3],addr6_prefix.addrIPv6[4],addr6_prefix.addrIPv6[5],addr6_prefix.addrIPv6[6],addr6_prefix.addrIPv6[7]);
	cJSON_AddStringToObject(root,"LanIPv6Prefix",IPv6Prefix);
	cJSON_AddNumberToObject(root,"LanIPv6PrefixLength",addr6_prefix.prefix_len);

	cJSON_AddNumberToObject(root,"enable_radvd",radvdCfgParam.enabled);
	cJSON_AddStringToObject(root,"RadvdInterFaceName",radvdCfgParam.interface.Name);
	cJSON_AddNumberToObject(root,"MaxRtrAdvInterval",radvdCfgParam.interface.MaxRtrAdvInterval);
	cJSON_AddNumberToObject(root,"MinRtrAdvInterval",radvdCfgParam.interface.MinRtrAdvInterval);
	cJSON_AddNumberToObject(root,"MinDelayBetweenRAs",radvdCfgParam.interface.MinDelayBetweenRAs);
	cJSON_AddNumberToObject(root,"AdvManagedFlag",radvdCfgParam.interface.AdvManagedFlag);
	cJSON_AddNumberToObject(root,"AdvOtherConfigFlag",radvdCfgParam.interface.AdvOtherConfigFlag);
	cJSON_AddNumberToObject(root,"AdvLinkMTU",radvdCfgParam.interface.AdvLinkMTU);
	cJSON_AddNumberToObject(root,"AdvReachableTime",radvdCfgParam.interface.AdvReachableTime);
	cJSON_AddNumberToObject(root,"AdvRetransTimer",radvdCfgParam.interface.AdvRetransTimer);
	cJSON_AddNumberToObject(root,"AdvCurHopLimit",radvdCfgParam.interface.AdvCurHopLimit);
	cJSON_AddNumberToObject(root,"AdvDefaultLifetime",radvdCfgParam.interface.AdvDefaultLifetime);
	cJSON_AddStringToObject(root,"AdvDefaultPreference",radvdCfgParam.interface.AdvDefaultPreference);
	cJSON_AddNumberToObject(root,"AdvsourceLLAddress",radvdCfgParam.interface.AdvSourceLLAddress);
	cJSON_AddNumberToObject(root,"UnicastOnly",radvdCfgParam.interface.UnicastOnly);

	cJSON_AddNumberToObject(root,"Enabled_0",radvdCfgParam.interface.prefix[0].enabled);

	sprintf(RadvdIPv6Prefix_0,"%s",radvdCfgParam.interface.prefix[0].Prefix);

	cJSON_AddStringToObject(root,"Prefix1",RadvdIPv6Prefix_0);
	//cJSON_AddNumberToObject(root,"radvdprefix0_len",radvdCfgParam.interface.prefix[0].PrefixLen);
	cJSON_AddNumberToObject(root,"AdvOnLinkFlag_0",radvdCfgParam.interface.prefix[0].AdvOnLinkFlag);
	cJSON_AddNumberToObject(root,"AdvAutonomousFlag_0",radvdCfgParam.interface.prefix[0].AdvAutonomousFlag);
	cJSON_AddNumberToObject(root,"AdvValidLifetime_0",radvdCfgParam.interface.prefix[0].AdvValidLifetime);
	cJSON_AddNumberToObject(root,"AdvPreferredLifetime_0",radvdCfgParam.interface.prefix[0].AdvPreferredLifetime);
	cJSON_AddNumberToObject(root,"AdvRouterAddr_0",radvdCfgParam.interface.prefix[0].AdvRouterAddr);
	cJSON_AddStringToObject(root,"if6to4_0",radvdCfgParam.interface.prefix[0].if6to4);

	//cJSON_AddNumberToObject(root,"RadvdLanIPv6PrefixLength",radvdCfgParam.interface.prefix[0].PrefixLen);

	cJSON_AddNumberToObject(root,"Enabled_1",radvdCfgParam.interface.prefix[1].enabled);
	sprintf(RadvdIPv6Prefix_1,"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",radvdCfgParam.interface.prefix[1].Prefix[0],radvdCfgParam.interface.prefix[1].Prefix[1],\
			radvdCfgParam.interface.prefix[1].Prefix[2],radvdCfgParam.interface.prefix[1].Prefix[3],radvdCfgParam.interface.prefix[1].Prefix[4], \
			radvdCfgParam.interface.prefix[1].Prefix[5],radvdCfgParam.interface.prefix[1].Prefix[6],radvdCfgParam.interface.prefix[1].Prefix[7]);
	cJSON_AddStringToObject(root,"Prefix2",RadvdIPv6Prefix_1);
	//cJSON_AddNumberToObject(root,"radvdprefix1_len",radvdCfgParam.interface.prefix[1].PrefixLen);
	cJSON_AddNumberToObject(root,"AdvOnLinkFlag_1",radvdCfgParam.interface.prefix[1].AdvOnLinkFlag);
	cJSON_AddNumberToObject(root,"AdvAutonomousFlag_1",radvdCfgParam.interface.prefix[1].AdvAutonomousFlag);
	cJSON_AddNumberToObject(root,"AdvValidLifetime_1",radvdCfgParam.interface.prefix[1].AdvValidLifetime);
	cJSON_AddNumberToObject(root,"AdvPreferredLifetime_1",radvdCfgParam.interface.prefix[1].AdvPreferredLifetime);
	cJSON_AddNumberToObject(root,"AdvRouterAddr_1",radvdCfgParam.interface.prefix[1].AdvRouterAddr);
	cJSON_AddStringToObject(root,"if6to4_1",radvdCfgParam.interface.prefix[1].if6to4);
	
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	
	if(opmode == GATEWAY_MODE)
	{	
		fp = fopen(IPV6_ADDR_PROC,"r");
		if(fp!=NULL){
			while((ret=fscanf(fp,"%s %x %x %x %x %s",src,&if_index,
					&prefix_len,&if_scope,&if_flag,devname))!=EOF){
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
						cJSON_AddStringToObject(root,"wan_addr6_global",src);//动态ipv6地址
						break;
					}
				}
			}
			fclose(fp);
		}
		else{
			printf("can't open if_inet6 file \n");
		}
	}else if(opmode == WISP_MODE)
	{
		fp = fopen(IPV6_ADDR_PROC,"r");
		if(fp!=NULL){
			while((ret=fscanf(fp,"%s %x %x %x %x %s",src,&if_index,
					&prefix_len,&if_scope,&if_flag,devname))!=EOF){
				if(ret!=6)
					continue;
				
				/*interface match? || strcmp(devname, "ppp0")==0 */	
				if(strcmp(devname, "wlan1-vxd")==0 ){									
					ret=sscanf(src,"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
								&addr6.s6_addr[ 0], &addr6.s6_addr[ 1], &addr6.s6_addr[ 2], &addr6.s6_addr[ 3],
								&addr6.s6_addr[ 4], &addr6.s6_addr[ 5], &addr6.s6_addr[ 6], &addr6.s6_addr[ 7],
								&addr6.s6_addr[ 8], &addr6.s6_addr[ 9], &addr6.s6_addr[10], &addr6.s6_addr[11],
								&addr6.s6_addr[12], &addr6.s6_addr[13], &addr6.s6_addr[14], &addr6.s6_addr[15]);
					if(addr6.s6_addr16[0]!=ntohs(0xFE80)){
						cJSON_AddStringToObject(root,"wan_addr6_global",src);//动态ipv6地址
						break;
					}
				}
			}
			fclose(fp);
		}
		else{
			printf("can't open if_inet6 file \n");
		}
	}

	apmib_get(MIB_PPP_USER_NAME, (void *)&pppoe_user);
	cJSON_AddStringToObject(root,"pppoe_user",pppoe_user);
	apmib_get(MIB_PPP_PASSWORD, (void *)&pppoe_pass);
	cJSON_AddStringToObject(root,"pppoe_pass",pppoe_pass);
	apmib_get(MIB_PPP_MTU_SIZE, (void *)&pppoe_mtu); //pppoe MTU
	cJSON_AddNumberToObject(root,"pppoe_mtu",pppoe_mtu);

	
	output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);

	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

int setIPv6RadvdCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{

     __FUNC_IN__
	 	
     int pid, val;
     char tmpBuf[256];
     char *submitUrl;
     char* value; 
     char *strval;
     int prefix_type = 0;
    strval=websGetVar(data,T("enable_dhcpv6pd"),T(""));	
				
	if(strval!=NULL){
		val = atoi(strval);
		apmib_set(MIB_IPV6_DHCP_PD_ENABLE,&val);
	}		

     strval=websGetVar(data,T("enabled"),T(""));
	 val= atoi(strval);
	 apmib_set(MIB_IPV6_WAN_ENABLE,&val);

     prefix_type = atoi(websGetVar(data,T("prefix_type"),T("")));
     apmib_set(MIB_PREFIX_TYPE,&prefix_type);//地址前缀分配类型0 delegate，1 static
     radvdCfgParam_t radvdCfgParam;

     getRadvdInfo(&radvdCfgParam);
     set_RadvdParam(mosq,data,tp,&radvdCfgParam);

     apmib_set(MIB_IPV6_RADVD_PARAM,&radvdCfgParam);

	return 0;


}


int module_init()
{
	cste_hook_register("setIPv6RadvdCfg",setIPv6RadvdCfg);
    cste_hook_register("setIPv6Config",setIPv6Config);
	cste_hook_register("getIPv6Config",getIPv6Config);
	return 0;  
}

