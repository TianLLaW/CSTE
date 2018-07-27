/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file wan.c
* @author CaryStudio
* @brief  This is a network cste topic
* @date 2017-11-8
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

#include "wan.h"
#include "discover.h"

#define LOG_MAX         16384
#define LOG_MAX_LINE    256
#define LOG_MAX_NUM     64

/////////////////////////////////////////////////////////////////////////////
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_VAP_SUPPORT)// keith. disabled if no this mode in 96c
	#define DEF_MSSID_NUM 0
#else
//		#if defined(CONFIG_RTL8196B)//we disable mssid first for 96b
//	#define DEF_MSSID_NUM 0
//		#else
#ifdef CONFIG_RTL8196B_GW_8M
	#define DEF_MSSID_NUM 1
#else
	#define DEF_MSSID_NUM 4
#endif
//		#endif
#endif //#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_VAP_SUPPORT)

#if defined(CONFIG_RTL_ISP_MULTI_WAN_SUPPORT)
int cmcc_genWanName(int index,WANIFACE_Tp pEntry)
{
	if(!pEntry) return -1;
	snprintf(pEntry->WanName,sizeof(pEntry->WanName),"%d_",index);
	switch(pEntry->applicationtype)
	{
		case APPTYPE_INTERNET:
			strcat(pEntry->WanName, "INTERNET_");
			break;
		case APPTYPE_TR069:
			strcat(pEntry->WanName, "TR069_");
			break;
		case APPTYPE_OTHER:
			strcat(pEntry->WanName, "Other_");
			break;
		case APPTYPE_TR069_INTERNET:
			strcat(pEntry->WanName, "TR069_INTERNET_");
			break;
		default:
			strcat(pEntry->WanName, "UNKNOWN_");
			break;
	}
	if(pEntry->AddressType==BRIDGE)
		strcat(pEntry->WanName, "B_");
	else
		strcat(pEntry->WanName, "R_");
	
	strcat(pEntry->WanName, "VID_");
	if(pEntry->vlan){
		snprintf(pEntry->WanName,sizeof(pEntry->WanName),"%s%d",pEntry->WanName,pEntry->vlanid);
	}
	return 1;
}

int getWanIfaceEntry(int index,WANIFACE_T* pEntry)
{	
	//apmib_init();
	memset(pEntry, '\0', sizeof(*pEntry));	
	*((char *)pEntry) = (char)index;
	if(!apmib_get(MIB_WANIFACE_TBL,(void *)pEntry)){
		printf("get wanIface mib error\n");
		return 0;
	}
	else
		return 1;
}

//if find, return wan idx, else return 0; if fail, return -1;
int get_wanEntry_by_wanName(WANIFACE_Tp pEntry,char* wan_name)
{
	int index=0;
#if 1
	char * strIdx=NULL;
	if(!wan_name) return 0;
	if((strIdx=strsep(&wan_name,"_"))==NULL){
		return 0;
	}
	index=strtoul(strIdx,NULL,10);
#else
	for(index=1;index<=WANIFACE_NUM;index++){
		if(!getWanIfaceEntry(index,pEntry)){
			return -1;
		}
		if(strcmp(wan_name,pEntry->WanName)==0) break;
	}
#endif
	if(index>WANIFACE_NUM) return 0;
	if(!getWanIfaceEntry(index,pEntry)){
			return -1;
		}
	return index;
}

int cmccWanSetStaticIp(cJSON* data,WANIFACE_Tp pEntry,char* erroMsgBuf)
{
	char * strIp=NULL;
	struct in_addr inIp={0};
	char *strVal=NULL;
	strIp = websGetVar(data, T("wanIpAddress"), T(""));
	if ( strIp[0] ) {
		if ( !inet_aton(strIp, &inIp) ) {
			sprintf(erroMsgBuf, "[%s][%d]:error!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		memcpy(pEntry->ipAddr,&inIp,sizeof(unsigned char)*4);
	}

	strIp = websGetVar(data, T("wanSubnetMask"), T(""));
	if ( strIp[0] ) {
		if ( !inet_aton(strIp, &inIp) ) {
			sprintf(erroMsgBuf, "[%s][%d]:error!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		memcpy(pEntry->netMask,&inIp,sizeof(unsigned char)*4);
	}

	strIp = websGetVar(data, T("defaultGateway"), T(""));
	if ( strIp[0] ) {
		if ( !inet_aton(strIp, &inIp) ) {
			sprintf(erroMsgBuf, "[%s][%d]:error!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		memcpy(pEntry->remoteIpAddr,&inIp,sizeof(unsigned char)*4);
	}

	strVal = websGetVar(data, T("MTU"), T(""));
	if ( strVal[0] ) {
		int mtuSize;
		mtuSize = strtol(strVal, (char**)NULL, 10);

		pEntry->staticIpMtu=mtuSize;
	}		
	pEntry->dnsAuto=0;
	
	strIp = websGetVar(data, T("dnsPrimary"), T(""));
	if ( strIp[0] ) {
		if ( !inet_aton(strIp, &inIp) ) {
			sprintf(erroMsgBuf, "[%s][%d]:error!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		memcpy(pEntry->wanIfDns1,&inIp,sizeof(unsigned char)*4);
	}
	strIp = websGetVar(data, T("dnsSecondary"), T(""));
	if ( strIp[0] ) {
		if ( !inet_aton(strIp, &inIp) ) {
			sprintf(erroMsgBuf, "[%s][%d]:error!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		memcpy(pEntry->wanIfDns2,&inIp,sizeof(unsigned char)*4);
	}
	return 0;
}

int cmcc_setbinding(cJSON* data,int wanIdx,char*erroMsgBuf,int len)
{
	char *strVal=NULL;
	int i=0;
	WanIntfacesType wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_WLAN_PORT_NUM]={0};
	apmib_set(MIB_WANIFACE_CURRENT_IDX,(void*)&wanIdx);
	if(!apmib_get(MIB_WANIFACE_BINDING_LAN_PORTS, (void *)wanBindingLanPorts))
	{
		snprintf(erroMsgBuf,len,"%s:%d get MIB_WANIFACE_BINDING_LAN_PORTS fail!\n",__FUNCTION__,__LINE__);
		return -1;
	}
	for(i=0;i<WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_WLAN_PORT_NUM;i++){
		if(wanBindingLanPorts[i]==wanIdx)
			wanBindingLanPorts[i]=0;
	}
	strVal = websGetVar(data, T("cb_bindlan1"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[0]=wanIdx;
	strVal = websGetVar(data, T("cb_bindlan2"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[1]=wanIdx;
	strVal = websGetVar(data, T("cb_bindlan3"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[2]=wanIdx;
	strVal = websGetVar(data, T("cb_bindlan4"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[3]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1_va1"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+1]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1_va2"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+2]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1_va3"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+3]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1_va4"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+4]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless1_vxd"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+5]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2_va1"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+1]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2_va2"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+2]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2_va3"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+3]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2_va4"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+4]=wanIdx;
	strVal = websGetVar(data, T("cb_bindwireless2_vxd"), T(""));
	if(strcmp(strVal, "on") == 0 ) wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+5]=wanIdx;

	if(!apmib_set(MIB_WANIFACE_BINDING_LAN_PORTS, (void *)wanBindingLanPorts))
	{
		snprintf(erroMsgBuf,len,"%s:%d set MIB_WANIFACE_BINDING_LAN_PORTS fail!\n",__FUNCTION__,__LINE__);
		return -1;
	}
	return 0;
}

int cmcc_setWanValues(int wanIdx,WANIFACE_Tp pWanEntry,char*erroMsgBuf,int len)
{
	apmib_set(MIB_WANIFACE_CURRENT_IDX,(void*)&wanIdx);
	if(!apmib_set(MIB_WANIFACE_ENABLE,(void*)&(pWanEntry->enable))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_ENABLE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_CONNDISABLE,(void*)&(pWanEntry->connDisable)))
	{
		snprintf(erroMsgBuf,len,"set wan MIB_WANIFACE_CONNDISABLE value fail!");
			return -1;
	}
	if(!apmib_set(MIB_WANIFACE_CMODE,(void*)&(pWanEntry->cmode))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_CMODE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_ADDRESSTYPE,(void*)&(pWanEntry->AddressType))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_ADDRESSTYPE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_BRMODE,(void*)&(pWanEntry->brmode))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_BRMODE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPADDR,(void*)&(pWanEntry->ipAddr))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPADDR value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_NETMASK,(void*)&(pWanEntry->netMask))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_NETMASK value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_REMOTEIPADDR,(void*)&(pWanEntry->remoteIpAddr))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_REMOTEIPADDR value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_STATIC_IP_MTU,(void*)&(pWanEntry->staticIpMtu))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_STATIC_IP_MTU value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_DHCP_MTU,(void*)&(pWanEntry->dhcpMtu))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_DHCP_MTU value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_PPPUSERNAME,(void*)(pWanEntry->pppUsername))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_PPPUSERNAME value fail!");
		return -1;
	}
	//printf("%s:%d pppUsername=%s\n",__FUNCTION__,__LINE__,pWanEntry->pppUsername);
	if(!apmib_set(MIB_WANIFACE_PPPPASSWD,(void*)(pWanEntry->pppPassword))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_PPPPASSWD value fail!");
		return -1;
	}
	//printf("%s:%d pppPassword=%s\n",__FUNCTION__,__LINE__,pWanEntry->pppPassword);
	if(!apmib_set(MIB_WANIFACE_PPPOE_MTU,(void*)&(pWanEntry->pppoeMtu))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_PPPOE_MTU value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_ENABLEIGMP,(void*)&(pWanEntry->enableIGMP))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_ENABLEIGMP value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_VLAN,(void*)&(pWanEntry->vlan))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_VLAN value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_VLANID,(void*)&(pWanEntry->vlanid))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_VLANID value fail!");
		return -1;
	}
	
	if(!apmib_set(MIB_WANIFACE_VPRIORITY,(void*)&(pWanEntry->vlanpriority))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_VPRIORITY value fail!");
		return -1;
	}
	
	if(!apmib_set(MIB_WANIFACE_MULTICAST_VLAN,(void*)&(pWanEntry->multicastVlan))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_VLANID value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_DNS_AUTO,(void*)&(pWanEntry->dnsAuto))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_DNS_AUTO value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_DNS1,(void*)&(pWanEntry->wanIfDns1))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_DNS1 value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_DNS2,(void*)&(pWanEntry->wanIfDns2))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_DNS2 value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_NAT_DISABLE,(void*)&(pWanEntry->nat_disable))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_NAT_DISABLE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_WANNAME,(void*)&(pWanEntry->WanName))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_WANNAME value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_APPLICATIONTYPE,(void*)&(pWanEntry->applicationtype))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_APPLICATIONTYPE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_SERVICELIST,(void*)&(pWanEntry->ServiceList))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_APPLICATIONTYPE value fail!");
		return -1;
	}
	
#ifdef CONFIG_APP_AWIFI_SUPPORT
	if(!apmib_set(MIB_WANIFACE_AWIFI_ENABLED,(void*)&(pWanEntry->aWiFi_enabled))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_AWIFI_ENABLED value fail!");
		return -1;
	}
#endif

#ifdef CONFIG_IPV6
	if(!apmib_set(MIB_WANIFACE_IPV6_ENABLE,(void*)&(pWanEntry->ipv6Enable))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_ENABLE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_LINK_TYPE,(void*)&(pWanEntry->ipv6LinkType))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_LINK_TYPE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_ORIGIN,(void*)&(pWanEntry->ipv6Origin))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_ORIGIN value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_ADDR,(void*)&(pWanEntry->ipv6Addr))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_ADDR value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_GW,(void*)&(pWanEntry->ipv6Gw))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_GW value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_DNS1,(void*)&(pWanEntry->ipv6dns1))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_DNS1 value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_DNS2,(void*)&(pWanEntry->ipv6dns2))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_DNS2 value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_DHCP_PD_ENABLE,(void*)&(pWanEntry->ipv6DhcpPdEnable))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_IPV6_DHCP_PD_ENABLE value fail!");
		return -1;
	}
#ifdef CONFIG_DSLITE_SUPPORT
	if(!apmib_set(MIB_WANIFACE_IPV6_DSLITE_MODE,(void*)&(pWanEntry->dsliteMode))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_APPLICATIONTYPE value fail!");
		return -1;
	}
	if(!apmib_set(MIB_WANIFACE_IPV6_ADDR_AFTR_PARAM,(void*)&(pWanEntry->addr6AftrParam))){
		snprintf(erroMsgBuf,len,"set MIB_WANIFACE_APPLICATIONTYPE value fail!");
		return -1;
	}
#endif
#endif
	return 0;
}

#if defined (CONFIG_ISP_IGMPPROXY_MULTIWAN)
#if defined(CONFIG_CMCC)
int checkAppTypeForIgmp(int appType)
{
	int ret = 0;
	
	switch(appType)
	{
		case APPTYPE_TR069_INTERNET:
		case APPTYPE_INTERNET:
		case APPTYPE_VOICE_INTERNET:
		case APPTYPE_TR069_VOICE_INTERNET:
		case APPTYPE_IPTV:
			ret = 1;
			break;
		case APPTYPE_TR069:
		case APPTYPE_OTHER:
		case APPTYPE_VOICE:
		case APPTYPE_TR069_VOICE:
		case APPTYPE_TR069_BRIDGE:
			ret = 0;
			break;
		default:
			ret =0;
			break;
	}
	return ret;
			
}
#endif
#endif

int getAndCheckDigitVal(cJSON* data,char* varName,int * pVal,char* erroMsgBuf,char notNull)
{
	char * pEndPos=NULL;
	char * pbuf = NULL;
	int val =0;

	pbuf = websGetVar(data, varName, T(""));
	if(notNull && !pbuf[0])
	{
		sprintf(erroMsgBuf,"%s can't be null!",varName);
		return -1;
	}
	if ( pbuf[0] ) 
	{
		val = strtol(pbuf,&pEndPos, 10);
		if(pEndPos && *pEndPos)
		{
			sprintf(erroMsgBuf,"%s have invalid character!",varName);
			return -1;
		}
		//printf("%s:%d pbuf=%s val=%d *pVal=%d\n",__FUNCTION__,__LINE__,pbuf,val,*pVal);
		*pVal = val;
		//printf("%s:%d pbuf=%s val=%d *pVal=%d\n",__FUNCTION__,__LINE__,pbuf,val,*pVal);
	}
	return 0;
}

int setMultiWanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *submitUrl=NULL,*strVal=NULL,*strIp=NULL, *tmpStr=NULL,*wanName=NULL;
	char erroMsgBuf[256]={0},cmdBuf[64]={0};
	WANIFACE_T wanEntry={0};
	int index=0,enable=0,i=0,lan_dhcp=0,val=0,prefixLen=64,disable=0;
	struct in6_addr ip6Addr={0};
	strVal = websGetVar(data, T("OperatorStyle"), T(""));
	wanName=websGetVar(data, T("wanName"), T(""));
	tmpStr=websGetVar(data, T("cb_enblService"), T(""));
	
	index=get_wanEntry_by_wanName(&wanEntry,wanName);
	if(strcmp(strVal,"Del")==0 || strcmp(tmpStr,"on")!=0 ){
		if(index<=0){
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"Can't find %s in wan setting!\n",wanName);
				goto setformEthernet_cmcc_err_end;
		}
//del the wan means set the wan disable
		enable=0;
		disable=1;
		apmib_set(MIB_WANIFACE_CURRENT_IDX,(void*)&index);
		if(!apmib_set(MIB_WANIFACE_ENABLE,(void*)&enable))
		{
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"set wan MIB_WANIFACE_ENABLE value fail!");
				goto setformEthernet_cmcc_err_end;
		}
		if(!apmib_set(MIB_WANIFACE_CONNDISABLE,(void*)&disable))
		{
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"set wan MIB_WANIFACE_CONNDISABLE value fail!");
				goto setformEthernet_cmcc_err_end;
		}
		goto setformEthernet_cmcc_ok;
	}
	else if(strcmp(strVal,"Add")==0){
		/*if(index!=0){
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"Can't add %s for wan with the same name already exist!\n",wanName);
				goto setformEthernet_cmcc_err_end;
		}*/
		for(i=1;i<=WANIFACE_NUM;i++){
			if(!getWanIfaceEntry(i,&wanEntry)){
				return -1;
			}
			if(!wanEntry.enable) {
				index=i;
				break;
			}
		}
		if(i>WANIFACE_NUM){
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"Can't add %s for max support %d wan!\n",wanName,WANIFACE_NUM);
				goto setformEthernet_cmcc_err_end;
		}
		bzero(&wanEntry,sizeof(wanEntry));
		wanEntry.enable=1;		
		wanEntry.connDisable=0;
		
	}
	else if(strcmp(strVal,"Modify")==0){
		if(index<=0){
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"Can't Modify %s in wan setting!\n",wanName);
				goto setformEthernet_cmcc_err_end;
		}
	}

	wanEntry.dnsAuto=1;
	tmpStr = websGetVar(data, T("wanMode"), T(""));
	if(strcmp(tmpStr,"Bridge")==0){
		wanEntry.AddressType=BRIDGE;
		wanEntry.cmode=IP_BRIDGE;
		wanEntry.brmode=BRIDGE_ETHERNET;
	#ifdef CONFIG_CMCC
		wanEntry.enableIGMP=0;
	#endif

#ifdef CONFIG_IPV6
	#ifdef CONFIG_CMCC
		wanEntry.enableMLD=0;
		apmib_set(MIB_WANIFACE_ENABLE_MLDPROXY,(void *)&wanEntry.enableMLD);
		#endif
		tmpStr = websGetVar(data, T("bridgeMode"), T(""));
		if (strcmp(tmpStr, "PPPoE_Bridged") == 0) //PPPoE_Bridged
				wanEntry.ipv6LinkType = IPV6_LINKTYPE_PPP;
			else //IP_Bridged
				wanEntry.ipv6LinkType= IPV6_LINKTYPE_IP;
#endif
	}else{
//route
		tmpStr = websGetVar(data, T("linkMode"), T(""));
		if(strcmp(tmpStr,"linkPPP")==0){
			wanEntry.AddressType=PPPOE;
			wanEntry.cmode=IP_PPP;
			wanEntry.brmode=BRIDGE_DISABLE;
			tmpStr=websGetVar(data, T("pppUserName"), T(""));
			strncpy(wanEntry.pppUsername,tmpStr,MAX_PPP_NAME_LEN+1);
			//printf("%s:%d pppUserName=%s\n",__FUNCTION__,__LINE__,tmpStr);
			tmpStr=websGetVar(data, T("pppPassword"), T(""));
			strncpy(wanEntry.pppPassword,tmpStr,MAX_PPP_NAME_LEN+1);
			//printf("%s:%d pppPassword=%s\n",__FUNCTION__,__LINE__,tmpStr);
			strVal=websGetVar(data, T("MTU"), T(""));
			if ( strVal[0] ) {
				int mtuSize;
				mtuSize = strtol(strVal, (char**)NULL, 10);
				wanEntry.pppoeMtu = mtuSize;
			}
		}else
		if(strcmp(tmpStr,"linkIP")==0){
			wanEntry.cmode=IP_ROUTE;
			wanEntry.brmode=BRIDGE_DISABLE;
			tmpStr=websGetVar(data, T("IpMode"), T(""));
			if(strcmp(tmpStr,"DHCP")==0){
				wanEntry.AddressType=DHCP_CLIENT;
				wanEntry.dnsAuto=1;
				strVal=websGetVar(data, T("MTU"), T(""));
				if ( strVal[0] ) {
					int mtuSize;
					mtuSize = strtol(strVal, (char**)NULL, 10);
					wanEntry.dhcpMtu = mtuSize;
				}
			}
			else if(strcmp(tmpStr,"Static")==0){
				wanEntry.AddressType=DHCP_DISABLED;
				if(cmccWanSetStaticIp(data,&wanEntry,erroMsgBuf)<0){
					goto setformEthernet_cmcc_err_end;
				}
			}
				
		}
	}

	if(cmcc_setbinding(data,index,erroMsgBuf,sizeof(erroMsgBuf))<0){
		goto setformEthernet_cmcc_err_end;
	}
	tmpStr = websGetVar(data, T("serviceList"), T(""));
	if(strcmp(tmpStr,"TR069_INTERNET")==0){
		wanEntry.applicationtype = APPTYPE_TR069_INTERNET;
		wanEntry.ServiceList = X_CT_SRV_TR069_INTERNET;
		}
	else if(strcmp(tmpStr,"INTERNET")==0){
		wanEntry.applicationtype = APPTYPE_INTERNET;
		wanEntry.ServiceList = X_CT_SRV_INTERNET;
		}
	else if(strcmp(tmpStr,"TR069")==0){
		wanEntry.applicationtype = APPTYPE_TR069;
		wanEntry.ServiceList = X_CT_SRV_TR069;
		}
	else if(strcmp(tmpStr,"Other")==0 || strcmp(tmpStr,"OTHER")==0){
		wanEntry.applicationtype = APPTYPE_OTHER;
		wanEntry.ServiceList = X_CT_SRV_OTHER;
		}
	else if(strcmp(tmpStr,"VOICE")==0){
		wanEntry.applicationtype = APPTYPE_VOICE;
		wanEntry.ServiceList = X_CT_SRV_VOICE;
		}
	else if(strcmp(tmpStr,"TR069_VOICE")==0){
		wanEntry.applicationtype = APPTYPE_TR069_VOICE;
		wanEntry.ServiceList = X_CT_SRV_VOICE;
		}
	else if(strcmp(tmpStr,"VOICE_INTERNET")==0){
		wanEntry.applicationtype = APPTYPE_VOICE_INTERNET;
		wanEntry.ServiceList = X_CT_SRV_VOICE;
		}
	else if(strcmp(tmpStr,"TR069_VOICE_INTERNET")==0){
		wanEntry.applicationtype = APPTYPE_TR069_VOICE_INTERNET;
		wanEntry.ServiceList = X_CT_SRV_VOICE;
		}
	
	//aWiFi
	#ifdef CONFIG_APP_AWIFI_SUPPORT
	int wan_index_tmp;
	WANIFACE_T wanEntry_tmp;
	
	tmpStr = websGetVar(data, T("cb_aWiFi"), T(""));
	printf("[%s:%d] cb_aWiFi = %s\n",__FUNCTION__,__LINE__, tmpStr);
	if(strcmp(tmpStr,"on")){
		wanEntry.aWiFi_enabled=0;
	}else{
		if(wanEntry.cmode == IP_BRIDGE){
			sprintf(erroMsgBuf, "aWiFi could not run with bridge mode!");
			goto setformEthernet_cmcc_err_end;
		}else if( (wanEntry.applicationtype != APPTYPE_TR069_INTERNET) &&
			(wanEntry.applicationtype != APPTYPE_INTERNET) &&
			(wanEntry.applicationtype != APPTYPE_VOICE_INTERNET) &&
			(wanEntry.applicationtype != APPTYPE_TR069_VOICE_INTERNET) ){
			sprintf(erroMsgBuf, "aWiFi should run with internet service type!");
			goto setformEthernet_cmcc_err_end;
		}else{
			for(wan_index_tmp = 1; wan_index_tmp <= WANIFACE_NUM; wan_index_tmp++){
				if(!getWanIfaceEntry(wan_index_tmp, &wanEntry_tmp)){
					sprintf(erroMsgBuf, "get wanIface%d mib error!",index);
					goto setformEthernet_cmcc_err_end;
				}
				if(wanEntry_tmp.aWiFi_enabled){
					if(wan_index_tmp != index){ /*Have enabled aWifi wan is not current set wan*/
						sprintf(erroMsgBuf, "Wan:%s has enabled aWiFi!",wanName);
						goto setformEthernet_cmcc_err_end;
					}						
				}
			}
		}
		
		wanEntry.aWiFi_enabled=1;
	}
	#endif

	
	#if defined (CONFIG_ISP_IGMPPROXY_MULTIWAN)
	#ifdef CONFIG_CMCC
	if(checkAppTypeForIgmp(wanEntry.applicationtype))
		wanEntry.enableIGMP=1;
	else
		wanEntry.enableIGMP=0;
	#endif
	#endif

	//don't show DHCP Server enable on wan webpage
#if 0
	tmpStr = req_get_cstream_var(wp, "cb_enabledhcp", "");
	if(strcmp(tmpStr,"on")==0){
		lan_dhcp=DHCP_SERVER;
	}else
		lan_dhcp=DHCP_DISABLED;
	if(!apmib_set(MIB_DHCP,(void*)&lan_dhcp)){
		snprintf(erroMsgBuf,sizeof(erroMsgBuf),"set MIB_DHCP value fail!");
		goto setformEthernet_cmcc_err_end;
	}
#endif
	
#ifdef CONFIG_IPV6
	tmpStr = websGetVar(data, T("IpVersion"), T(""));
	if(strstr(tmpStr,"IPv6")){
		wanEntry.ipv6Enable=1;
	}else
		wanEntry.ipv6Enable=0;
#endif
	tmpStr = websGetVar(data, T("VLANMode"), T(""));
	if(strcmp(tmpStr,"UNTAG")==0){
		wanEntry.vlan=0;
	}else
	if(strcmp(tmpStr,"TAG")==0){
		int vlanid=0, priority = 0;
		wanEntry.vlan=2; //2 wan tag, 1 vlan transparent

		val = getAndCheckDigitVal(data,"vlan",&vlanid,erroMsgBuf,1);
		if(val<0)
			goto setformEthernet_cmcc_err_end;

		if(vlanid == 1 || (vlanid >= 7 && vlanid <= 12)) 
		{
			sprintf(erroMsgBuf, "VLAN id %d is reserverd for internal use!", vlanid);
			goto setformEthernet_cmcc_err_end;
		}
		
		wanEntry.vlanid=vlanid;

		//vlan priority
		val = getAndCheckDigitVal(data,"v8021P",&priority,erroMsgBuf,1);
		if(val<0)
			goto setformEthernet_cmcc_err_end;

		if(priority < 0 || priority > 7) 
		{
			sprintf(erroMsgBuf, "8021p vlan priority invalid!");
			goto setformEthernet_cmcc_err_end;
		}
		wanEntry.vlanpriority = priority;
	}

	int mcastVid = 0;
	val = getAndCheckDigitVal(data,"MulticastVID",&mcastVid,erroMsgBuf,0);

	
	if(val<0)
		goto setformEthernet_cmcc_err_end;

	if(mcastVid == 1 || (mcastVid >= 7 && mcastVid <= 12)) 
	{
		sprintf(erroMsgBuf, "Multicast VLAN id %d is reserverd for internal use!", mcastVid);
		goto setformEthernet_cmcc_err_end;
	}
	
	wanEntry.multicastVlan = mcastVid;
	
	
	tmpStr = websGetVar(data, T("cb_nat"), T(""));
	if(strcmp(tmpStr,"on")==0){
		wanEntry.nat_disable=0;
	}else
		wanEntry.nat_disable=1;
	#ifndef CONFIG_CMCC
	tmpStr = websGetVar(data, T("enblIgmp"), T(""));
	if(strcmp(tmpStr,"Yes")==0){
		wanEntry.enableIGMP=0;
	}else
		wanEntry.enableIGMP=1;
	#endif
#ifdef CONFIG_IPV6
	tmpStr = websGetVar(data, T("IdIpv6AddrType"), T(""));
	if(strcmp(tmpStr,"SLAAC")==0){
		wanEntry.ipv6Origin=IPV6_ORIGIN_SLAAC;
		#ifdef CONFIG_CMCC
		wanEntry.enableMLD=0;
		apmib_set(MIB_WANIFACE_ENABLE_MLDPROXY,(void *)&wanEntry.enableMLD);
		#endif
	}else
	if(strcmp(tmpStr,"DHCP")==0){
		wanEntry.ipv6Origin=IPV6_ORIGIN_DHCP6C;
		#ifdef CONFIG_CMCC
		wanEntry.enableMLD=1;
		apmib_set(MIB_WANIFACE_ENABLE_MLDPROXY,(void *)&wanEntry.enableMLD);
		#endif
	}else
	if(strcmp(tmpStr,"Static")==0){
		#ifdef CONFIG_CMCC
		wanEntry.enableMLD=1;
		apmib_set(MIB_WANIFACE_ENABLE_MLDPROXY,(void *)&wanEntry.enableMLD);
		#endif
		wanEntry.ipv6Origin=IPV6_ORIGIN_STATIC;
		strIp = websGetVar(data, T("IdIpv6Addr"), T(""));
		if(strIp[0]){
			inet_pton(PF_INET6, strIp, &ip6Addr);
			for(i=0;i<8;i++)
				ip6Addr.s6_addr16[i]=htons(ip6Addr.s6_addr16[i]);
			memcpy(wanEntry.ipv6Addr.addrIPv6,&ip6Addr,sizeof(struct in6_addr));
		}
		strVal= websGetVar(data, T("IdIpv6PrefixLen"), T(""));
		if(strVal[0]){
			prefixLen=strtol(strVal, (char**)NULL, 10);
			wanEntry.ipv6Addr.prefix_len=prefixLen;
		}
		strIp = websGetVar(data, T("IdIpv6Gateway"), T(""));
		if(strIp[0]){
			inet_pton(PF_INET6, strIp, &ip6Addr);
			for(i=0;i<8;i++)
				ip6Addr.s6_addr16[i]=htons(ip6Addr.s6_addr16[i]);
			memcpy(wanEntry.ipv6Gw.addrIPv6,&ip6Addr,sizeof(struct in6_addr));
			wanEntry.ipv6Gw.prefix_len=prefixLen;
		}
		strIp = websGetVar(data, T("IdIpv6Dns1"), T(""));
		if(strIp[0]){
			inet_pton(PF_INET6, strIp, &ip6Addr);
			for(i=0;i<8;i++)
				ip6Addr.s6_addr16[i]=htons(ip6Addr.s6_addr16[i]);
			memcpy(wanEntry.ipv6dns1.addrIPv6,&ip6Addr,sizeof(struct in6_addr));
			wanEntry.ipv6dns1.prefix_len=prefixLen;
		}
		strIp = websGetVar(data, T("IdIpv6Dns2"), T(""));
		if(strIp[0]){
			inet_pton(PF_INET6, strIp, &ip6Addr);
			for(i=0;i<8;i++)
				ip6Addr.s6_addr16[i]=htons(ip6Addr.s6_addr16[i]);
			memcpy(wanEntry.ipv6dns2.addrIPv6,&ip6Addr,sizeof(struct in6_addr));
			wanEntry.ipv6dns2.prefix_len=prefixLen;
		}
	}else
	{
		sprintf(erroMsgBuf, "Invalid ipv6 addr type %s!", tmpStr);
		goto setformEthernet_cmcc_err_end;
	}
	tmpStr = websGetVar(data, T("enablepd"), T(""));
	if(strcmp(tmpStr,"Yes")==0){
		wanEntry.ipv6DhcpPdEnable=1;
	}else
		wanEntry.ipv6DhcpPdEnable=0;
#ifdef CONFIG_DSLITE_SUPPORT
	tmpStr = websGetVar(data, T("cb_enabledslite"), T(""));
	if(strcmp(tmpStr,"on")==0){
		wanEntry.ipv6Origin=IPV6_ORIGIN_DSLITE;
		strVal = websGetVar(data, T("dslitemode"), T(""));
		if(strVal[0]){
			wanEntry.dsliteMode=strtol(strVal,(char**)NULL, 10);
			if(wanEntry.dsliteMode==1){
				strIp = websGetVar(data, T("dsliteaddress"), T(""));
				if(strIp[0]){
					inet_pton(PF_INET6, strIp, &ip6Addr);
					for(i=0;i<8;i++)
						ip6Addr.s6_addr16[i]=htons(ip6Addr.s6_addr16[i]);
					memcpy(wanEntry.addr6AftrParam.addrIPv6,&ip6Addr,sizeof(struct in6_addr));
					wanEntry.addr6AftrParam.prefix_len=prefixLen;
				}
			}
		}
	}
#endif
#endif
	if(cmcc_genWanName(index,&wanEntry)<0){
			snprintf(erroMsgBuf,sizeof(erroMsgBuf),"cmcc_genWanName fail!\n");
				goto setformEthernet_cmcc_err_end;
	}

	if(cmcc_setWanValues(index,&wanEntry,erroMsgBuf,sizeof(erroMsgBuf))<0)
		goto setformEthernet_cmcc_err_end;
	
	
setformEthernet_cmcc_ok:
	apmib_update_web(CURRENT_SETTING);
	websSetCfgResponse(mosq, tp, "60", "reserv");
	//system("init.sh gw all");
	system("reinitCli -e 3 &");
	return 0;
setformEthernet_cmcc_err_end:
	printf("%s\n",erroMsgBuf);
	return 0;
}

int getIndex(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int tmpint=0;
	char tmp[64]={0};
	int intVal=0;

	sprintf(tmp, "%d", NUM_WLAN_INTERFACE);
	cJSON_AddStringToObject(root,"show_wlan_num",tmp);
	
	sprintf(tmp, "%d", DEF_MSSID_NUM);
	cJSON_AddStringToObject(root,"wlan_mssid_num",tmp);
	
	SetWlan_idx("wlan0");
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	sprintf(tmp, "%d", intVal);
	cJSON_AddStringToObject(root,"wlan0_Disabled",tmp);

	if(NUM_WLAN_INTERFACE > 1){
		SetWlan_idx("wlan1");
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		sprintf(tmp, "%d", intVal);
		cJSON_AddStringToObject(root,"wlan1_Disabled",tmp);
	}

#ifdef UNIVERSAL_REPEATER
	apmib_get( MIB_REPEATER_ENABLED1, (void *)&intVal);
	sprintf(tmp, "%d", (intVal==1?0:1));
	cJSON_AddStringToObject(root,"wlan0_DisabledVxd",tmp);

	if(NUM_WLAN_INTERFACE > 1){
		apmib_get( MIB_REPEATER_ENABLED2, (void *)&intVal);
		sprintf(tmp, "%d", (intVal==1?0:1));
		cJSON_AddStringToObject(root,"wlan1_DisabledVxd",tmp);
	}
	
#else
	sprintf(tmp, "%d", 1);
	cJSON_AddStringToObject(root,"wlan0_DisabledVxd",tmp);
	if(NUM_WLAN_INTERFACE > 1){
		cJSON_AddStringToObject(root,"wlan1_DisabledVxd",tmp);
	}
#endif

#ifdef CONFIG_IPV6
	sprintf(tmp, "%d", 1);	
#else
	sprintf(tmp, "%d", 0);
#endif
	cJSON_AddStringToObject(root,"ipv6",tmp);

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}

int getVirtualIndex(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root=cJSON_CreateObject();
	int tmpint=0;
	char tmp[64]={0};
	int intVal=0;
	
	SetWlan_idx("wlan0-va0");
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	sprintf(tmp, "%d", intVal);
	cJSON_AddStringToObject(root,"wlan0_Disabled1",tmp);

	SetWlan_idx("wlan0-va1");
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	sprintf(tmp, "%d", intVal);
	cJSON_AddStringToObject(root,"wlan0_Disabled2",tmp);

	SetWlan_idx("wlan0-va2");
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	sprintf(tmp, "%d", intVal);
	cJSON_AddStringToObject(root,"wlan0_Disabled3",tmp);

	SetWlan_idx("wlan0-va3");
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	sprintf(tmp, "%d", intVal);
	cJSON_AddStringToObject(root,"wlan0_Disabled4",tmp);

	if(NUM_WLAN_INTERFACE > 1){
		SetWlan_idx("wlan1-va0");
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		sprintf(tmp, "%d", intVal);
		cJSON_AddStringToObject(root,"wlan1_Disabled1",tmp);

		SetWlan_idx("wlan1-va1");
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		sprintf(tmp, "%d", intVal);
		cJSON_AddStringToObject(root,"wlan1_Disabled2",tmp);

		SetWlan_idx("wlan1-va2");
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		sprintf(tmp, "%d", intVal);
		cJSON_AddStringToObject(root,"wlan1_Disabled3",tmp);

		SetWlan_idx("wlan1-va3");
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		sprintf(tmp, "%d", intVal);
		cJSON_AddStringToObject(root,"wlan1_Disabled4",tmp);
	}
	
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
    cJSON_Delete(root);
	free(output);
    return 0;
}

int getInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root = cJSON_CreateArray();
	int tmpint=0;
	char tmp[128]={0};
	int intVal=0;
	
	int i=0,j=0,napt=0,cmode=0,brmode=0,AddrMode=0,ipDhcp=0,dnsMode=0,mtu=0,itfGroup=0,lan_dhcp_mode=0,
		disableLanDhcp=0,IpProtocolType=0,slacc=0,staticIpv6=0,dslite_enable=0,Ipv6PrefixLen=0,
		itfenable=0,dslite_aftr_mode=0,dnsv6Mode=0,mcast_vid=0;
	WANIFACE_T wanEntry={0};	
	WanIntfacesType wanBindingLanPorts[WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_WLAN_PORT_NUM]={0};
	char ipAddr[INET_ADDRSTRLEN]={0},remoteIpAddr[INET_ADDRSTRLEN]={0},netMask[INET_ADDRSTRLEN]={0},
		v4dns1[INET_ADDRSTRLEN]={0},v4dns2[INET_ADDRSTRLEN]={0},
		Ipv6Addr[INET6_ADDRSTRLEN]={0},Ipv6Gateway[INET6_ADDRSTRLEN]={0},Ipv6Dns1[INET6_ADDRSTRLEN]={0},
		Ipv6Dns2[INET6_ADDRSTRLEN]={0},DSLiteRemoteIP[INET6_ADDRSTRLEN]={0};
	if(!apmib_get(MIB_WANIFACE_BINDING_LAN_PORTS, (void *)wanBindingLanPorts))
	{
		printf("%s:%d get MIB_WANIFACE_BINDING_LAN_PORTS fail!\n",__FUNCTION__,__LINE__);
		return -1;
	}
	if(!apmib_get(MIB_DHCP,(void*)&lan_dhcp_mode)){
		printf("%s:%d get MIB_DHCP fail!\n",__FUNCTION__,__LINE__);
		return -1;
	}
	if(lan_dhcp_mode==DHCP_LAN_SERVER)
		disableLanDhcp=0;
	else
		disableLanDhcp=1;
//printf("%s:%d\n",__FUNCTION__,__LINE__);
	for(i=1;i<=WANIFACE_NUM;i++)
	{
		napt=0,cmode=0,brmode=0,AddrMode=0,ipDhcp=0,dnsMode=0,mtu=0,itfGroup=0,lan_dhcp_mode=0,
		IpProtocolType=0,slacc=0,staticIpv6=0,dslite_enable=0,Ipv6PrefixLen=0,
		itfenable=0,dslite_aftr_mode=0,dnsv6Mode=0,mcast_vid=0;
		bzero(&wanEntry,sizeof(wanEntry));
		bzero(ipAddr,sizeof(ipAddr));
		bzero(remoteIpAddr,sizeof(remoteIpAddr));
		bzero(netMask,sizeof(netMask));
		bzero(v4dns1,sizeof(v4dns1));
		bzero(v4dns2,sizeof(v4dns2));
		bzero(Ipv6Addr,sizeof(Ipv6Addr));
		bzero(Ipv6Gateway,sizeof(Ipv6Gateway));
		bzero(Ipv6Dns1,sizeof(Ipv6Dns1));
		bzero(Ipv6Dns2,sizeof(Ipv6Dns2));
		bzero(DSLiteRemoteIP,sizeof(DSLiteRemoteIP));
		//printf("%s:%d\n",__FUNCTION__,__LINE__);
		getWanIfaceEntry(i,&wanEntry);
		//printf("%s:%d wanEntry[%d].enable=%d\n",__FUNCTION__,__LINE__,i,wanEntry.enable);
		if(!wanEntry.enable) continue;
		cmcc_genWanName(i,&wanEntry);
		//printf("%s:%d wan_name=%s\n",__FUNCTION__,__LINE__,wanEntry.WanName);
		if(wanEntry.nat_disable)
			napt=0;
		else
			napt=1;
		if(wanEntry.AddressType==BRIDGE){
			cmode=0;
#ifdef CONFIG_IPV6
		if(wanEntry.ipv6LinkType==IPV6_LINKTYPE_IP)
			brmode=0;
		else if(wanEntry.ipv6LinkType==IPV6_LINKTYPE_PPP)
			brmode=1;
#else
			brmode=0;
#endif
		
		}
		else if(wanEntry.AddressType==PPPOE)
			cmode=2;
		else
			cmode=1;
		//printf("%s:%d cmode=%d\n",__FUNCTION__,__LINE__,cmode);
#ifdef CONFIG_IPV6
		switch(wanEntry.ipv6Origin){
			case IPV6_ORIGIN_STATIC:
				AddrMode=2;
				break;
			case IPV6_ORIGIN_SLAAC:
				AddrMode=1;
				break;
			case IPV6_ORIGIN_DHCP6C:
				AddrMode=16;
				break;
			case IPV6_ORIGIN_DSLITE:
				AddrMode=4;
				break;
			default:
				break;
		}
		
		
#endif
		if(wanEntry.AddressType==DHCP_DISABLED)
			ipDhcp=0;
		else if(wanEntry.AddressType==DHCP_CLIENT)
			ipDhcp=1;
		if(wanEntry.dnsAuto)
			dnsMode=1;
		else
			dnsMode=0;
		if(wanEntry.AddressType==DHCP_DISABLED)
			mtu=wanEntry.staticIpMtu;
		else if(wanEntry.AddressType==DHCP_CLIENT)
			mtu=wanEntry.dhcpMtu;
		else if(wanEntry.AddressType==PPPOE)
			mtu=wanEntry.pppoeMtu;
		
		mcast_vid = wanEntry.multicastVlan;
		
		snprintf(ipAddr,sizeof(ipAddr),"%s",inet_ntoa(*((struct in_addr *)wanEntry.ipAddr)));
		snprintf(netMask,sizeof(netMask),"%s",inet_ntoa(*((struct in_addr *)wanEntry.netMask)));
		snprintf(remoteIpAddr,sizeof(remoteIpAddr),"%s",inet_ntoa(*((struct in_addr *)wanEntry.remoteIpAddr)));
		snprintf(v4dns1,sizeof(v4dns1),"%s",inet_ntoa(*((struct in_addr *)wanEntry.wanIfDns1)));
		snprintf(v4dns2,sizeof(v4dns2),"%s",inet_ntoa(*((struct in_addr *)wanEntry.wanIfDns2)));
		 
		if(!wanEntry.enable) IpProtocolType=0;
		else{
#ifdef CONFIG_IPV6
			if(!wanEntry.ipv6Enable) IpProtocolType=1;
			else IpProtocolType=3;
#else
			IpProtocolType=1;
#endif
		}
		//itfGroup  //bit0- LAN 1; bit1- LAN 2; ...; bit 4- WLAN 2.4G ROOT; bit5- WLAN 2.4G SSID1; ...;bit9- 5G root
		for(j=0;j<sizeof(wanBindingLanPorts)/sizeof(WanIntfacesType);j++){
			if(wanBindingLanPorts[j]!=i) continue;
#if 1
			itfGroup |= (0x1 << j);
#else
			if(j<WAN_INTERFACE_LAN_PORT_NUM)
				itfGroup |= (0x1 << j);
			if(j==WAN_INTERFACE_LAN_PORT_NUM)
				itfGroup |= (0x1 << 9);//5g root
			if(j==WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM)
				itfGroup |= (0x1 << 4);//2g root
			if(j==WAN_INTERFACE_LAN_PORT_NUM+WAN_INTERFACE_EACH_WLAN_PORT_NUM+1)
				itfGroup |= (0x1 << 5);//2g SSID1
#endif
		}
#ifdef CONFIG_IPV6
		if(wanEntry.ipv6Origin==IPV6_ORIGIN_SLAAC) slacc=1;
		else if(wanEntry.ipv6Origin==IPV6_ORIGIN_STATIC) staticIpv6=1;	
		else if(wanEntry.ipv6Origin==IPV6_ORIGIN_DSLITE) dslite_enable=1;
		else if(wanEntry.ipv6Origin==IPV6_ORIGIN_DHCP6C) itfenable=1;
		if(addr6trans(&wanEntry.ipv6Addr,Ipv6Addr)<0)
		{
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		Ipv6PrefixLen=wanEntry.ipv6Addr.prefix_len;
		if(addr6trans(&wanEntry.ipv6Gw,Ipv6Gateway)<0)
		{
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		if(addr6trans(&wanEntry.ipv6dns1,Ipv6Dns1)<0)
		{
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		if(addr6trans(&wanEntry.ipv6dns2,Ipv6Dns2)<0)
		{
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		#ifdef CONFIG_DSLITE_SUPPORT
		if(addr6trans(&wanEntry.addr6AftrParam,DSLiteRemoteIP)<0)
		{
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		dslite_aftr_mode=wanEntry.dsliteMode;
		#endif
		#if 0
		if(!inet_ntop(AF_INET6,wanEntry.ipv6Addr.addrIPv6,Ipv6Addr,sizeof(Ipv6Addr))){
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		Ipv6PrefixLen=wanEntry.ipv6Addr.prefix_len;
		if(!inet_ntop(AF_INET6,wanEntry.ipv6Gw.addrIPv6,Ipv6Gateway,sizeof(Ipv6Gateway))){
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		if(!inet_ntop(AF_INET6,wanEntry.ipv6dns1.addrIPv6,Ipv6Dns1,sizeof(Ipv6Dns1))){
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		if(!inet_ntop(AF_INET6,wanEntry.ipv6dns2.addrIPv6,Ipv6Dns2,sizeof(Ipv6Dns2))){
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		#ifdef CONFIG_DSLITE_SUPPORT
		if(!inet_ntop(AF_INET6,wanEntry.addr6AftrParam.addrIPv6,DSLiteRemoteIP,sizeof(DSLiteRemoteIP))){
			printf("%s:%d inet_ntop fail!\n",__FUNCTION__,__LINE__);
			return -1;
		}
		dslite_aftr_mode=wanEntry.dsliteMode;
		#endif
		#endif
		if(wanEntry.ipv6Origin!=IPV6_ORIGIN_STATIC)
			dnsv6Mode=1;
#endif
	//	printf("%s:%d ipAddr=%s\n",__FUNCTION__,__LINE__,inet_ntoa(*((struct in_addr*)wanEntry.ipAddr)));

		cJSON *wanConnect = cJSON_CreateObject();

		sprintf(tmp, "%s", wanEntry.WanName);
		cJSON_AddStringToObject(wanConnect, "wanName", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "upmode", tmp);
		sprintf(tmp, "%d", napt);
		cJSON_AddStringToObject(wanConnect, "napt", tmp);
		sprintf(tmp, "%d", cmode);
		cJSON_AddStringToObject(wanConnect, "cmode", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "brmode", tmp);
		sprintf(tmp, "%d", AddrMode);
		cJSON_AddStringToObject(wanConnect, "AddrMode", tmp);
		sprintf(tmp, "%s", wanEntry.pppUsername);
		cJSON_AddStringToObject(wanConnect, "pppUserName", tmp);
		sprintf(tmp, "%s", wanEntry.pppPassword);
		cJSON_AddStringToObject(wanConnect, "pppPassword", tmp);
		sprintf(tmp, "%d", wanEntry.pppAuth);
		cJSON_AddStringToObject(wanConnect, "pppAuth", tmp);
		sprintf(tmp, "%s", wanEntry.pppServiceName);
		cJSON_AddStringToObject(wanConnect, "pppServiceName", tmp);
		sprintf(tmp, "%s", wanEntry.pppACName);
		cJSON_AddStringToObject(wanConnect, "pppACName", tmp);
		sprintf(tmp, "%d", wanEntry.pppCtype);
		cJSON_AddStringToObject(wanConnect, "pppCtype", tmp);
		sprintf(tmp, "%d", ipDhcp);
		cJSON_AddStringToObject(wanConnect, "ipDhcp", tmp);
		sprintf(tmp, "%s", ipAddr);
		cJSON_AddStringToObject(wanConnect, "ipAddr", tmp);
		sprintf(tmp, "%s", remoteIpAddr);
		cJSON_AddStringToObject(wanConnect, "remoteIpAddr", tmp);
		sprintf(tmp, "%s", netMask);
		cJSON_AddStringToObject(wanConnect, "netMask", tmp);
		sprintf(tmp, "%d", wanEntry.dgw);
		cJSON_AddStringToObject(wanConnect, "dgw", tmp);
		sprintf(tmp, "%s", v4dns1);
		cJSON_AddStringToObject(wanConnect, "v4dns1", tmp);
		sprintf(tmp, "%s", v4dns2);
		cJSON_AddStringToObject(wanConnect, "v4dns2", tmp);
		sprintf(tmp, "%d", dnsMode);
		cJSON_AddStringToObject(wanConnect, "dnsMode", tmp);
		sprintf(tmp, "%d", wanEntry.vlan);
		cJSON_AddStringToObject(wanConnect, "vlan", tmp);
		sprintf(tmp, "%d", wanEntry.vlanid);
		cJSON_AddStringToObject(wanConnect, "vid", tmp);
		sprintf(tmp, "%d", mtu);
		cJSON_AddStringToObject(wanConnect, "mtu", tmp);
		sprintf(tmp, "%d", wanEntry.vlanpriority);
		cJSON_AddStringToObject(wanConnect, "vprio", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "vpass", tmp);
		sprintf(tmp, "%d", itfGroup);
		cJSON_AddStringToObject(wanConnect, "itfGroup", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "qos", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "PPPoEProxyEnable", tmp);
		sprintf(tmp, "%d", 0);
		cJSON_AddStringToObject(wanConnect, "PPPoEProxyMaxUser", tmp);
		sprintf(tmp, "%d", wanEntry.applicationtype);
		cJSON_AddStringToObject(wanConnect, "applicationtype", tmp);
		sprintf(tmp, "%d", disableLanDhcp);
		cJSON_AddStringToObject(wanConnect, "disableLanDhcp", tmp);
		sprintf(tmp, "%d", IpProtocolType);
		cJSON_AddStringToObject(wanConnect, "IpProtocolType", tmp);
		sprintf(tmp, "%d", slacc);
		cJSON_AddStringToObject(wanConnect, "slacc", tmp);
		sprintf(tmp, "%d", staticIpv6);
		cJSON_AddStringToObject(wanConnect, "staticIpv6", tmp);
		sprintf(tmp, "%s", Ipv6Addr);
		cJSON_AddStringToObject(wanConnect, "Ipv6Addr", tmp);
		sprintf(tmp, "%s", Ipv6Gateway);
		cJSON_AddStringToObject(wanConnect, "Ipv6Gateway", tmp);
		sprintf(tmp, "%s", Ipv6Dns1);
		cJSON_AddStringToObject(wanConnect, "Ipv6Dns1", tmp);
		sprintf(tmp, "%s", Ipv6Dns2);
		cJSON_AddStringToObject(wanConnect, "Ipv6Dns2", tmp);
		sprintf(tmp, "%s", DSLiteRemoteIP);
		cJSON_AddStringToObject(wanConnect, "DSLiteRemoteIP", tmp);
		sprintf(tmp, "%d", dslite_enable);
		cJSON_AddStringToObject(wanConnect, "dslite_enable", tmp);
		sprintf(tmp, "%d", Ipv6PrefixLen);
		cJSON_AddStringToObject(wanConnect, "Ipv6PrefixLen", tmp);
		sprintf(tmp, "%d", itfenable);
		cJSON_AddStringToObject(wanConnect, "itfenable", tmp);
#ifdef CONFIG_IPV6
		sprintf(tmp, "%d", wanEntry.ipv6DhcpReqAddrEnable);
#else
		sprintf(tmp, "%d", 0);
#endif
		cJSON_AddStringToObject(wanConnect, "iana", tmp);
#ifdef CONFIG_IPV6
		sprintf(tmp, "%d", wanEntry.ipv6DhcpPdEnable);
#else
		sprintf(tmp, "%d", 0);
#endif
		cJSON_AddStringToObject(wanConnect, "iapd", tmp);
		sprintf(tmp, "%d", dslite_aftr_mode);
		cJSON_AddStringToObject(wanConnect, "dslite_aftr_mode", tmp);
		memset(tmp, 0, sizeof(tmp));
		cJSON_AddStringToObject(wanConnect, "dslite_aftr_hostname", tmp);
		sprintf(tmp, "%d", dnsv6Mode);
		cJSON_AddStringToObject(wanConnect, "dnsv6Mode", tmp);
		sprintf(tmp, "%d", wanEntry.enable);
		cJSON_AddStringToObject(wanConnect, "enable", tmp);
		sprintf(tmp, "%d", wanEntry.multicastVlan);
		cJSON_AddStringToObject(wanConnect, "mcastVid", tmp);


		cJSON_AddItemToArray(root,wanConnect);
	}

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

#endif

/**
* @note setWanDnsConfig  set WanDnsConfig configuration
* @param Setting Json Data
<pre>
{
	"dnsMode":	"0"
	"priDns":	""
	"secDns":	""
}
setting parameter description
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"50",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-14
*/
int setWanDnsConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char_t  *dns_mode,*pd, *sd;
	struct in_addr dns1, dns2;
	struct in_addr dns1_old, dns2_old;
	int ret=0, curDnsMode=0, iDnsMode=0;

    apmib_get(MIB_DNS_MODE,  (void *)&iDnsMode);
    apmib_get(MIB_DNS1, (void *)&dns1_old);
    apmib_get(MIB_DNS2, (void *)&dns2_old);
	dns_mode = websGetVar(data, T("dnsMode"), T("0"));
	curDnsMode = atoi(dns_mode);
	if(iDnsMode != curDnsMode)
	    ret=1;
	    
	apmib_set(MIB_DNS_MODE,  (void *)&curDnsMode);
	if (!strcmp(dns_mode, "1")) {
		pd = websGetVar(data, T("priDns"), T(""));
		sd = websGetVar(data, T("secDns"), T(""));
		if( !inet_aton(pd, &dns1) ) {
            return -1;
		}
        apmib_set(MIB_DNS1, (void *)&dns1);
        
        if( !inet_aton(sd, &dns2) ){
            return -1;
        }
        apmib_set(MIB_DNS2, (void *)&dns2);
        if ( *((long *)&dns1) != *((long *)&dns1_old) ||*((long *)&dns2) != *((long *)&dns2_old))
            ret = 1;
	}
	return ret;
}

/**
* @note setWanConfig	set wan configuration
*
* @param Setting Json Data
<pre>
{
	"wanMode":	"1",
	"staticIp":	""
	"staticMask":	""
	"staticGw":	""
	"pppoeUser":	""
	"pppoePass":	""
	"pptpIp":		""
	"pptpMask":	""
	"pptpGw":	""
	"pptpServerIp":	""
	"pptpUser":	""
	"pptpPass":	""
	"pptpMppe":	"0"
	"pptpMppc":	"0"
	"pptpMode":	"0"
	"l2tpMask":	""
	"l2tpGw":		""
	"l2tpServerIp":	""
	"l2tpUser":	""
	"l2tpPass":	""
	"l2tpMode":	"0"
	"hostName":	"",
	"dhcpMtu":	"1492",
	"macCloneEnabled":	"0",
	"macCloneMac":	"F4:38:54:00:02:15",
}
setting parameter description
</pre>
* @return Return Json Data
<pre>
{
    "success":	true
    "error":	null
    "lan_ip":	"192.168.0.1"
    "wtime":	"30"
    "reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-8
*/
int setWanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int ctype;
	char_t	*ip, *nm, *gw, *hostname;
    char_t  *pppoe_user, *pppoe_pass, *pppoe_opmode;
    char_t  *pptp_user, *pptp_pass, *pptp_ip, *pptp_nm, *pptp_gw, *pptp_server;
    char_t  *l2tp_user, *l2tp_pass, *l2tp_ip, *l2tp_nm, *l2tp_gw, *l2tp_server;
	char_t	*clone_en, *clone_mac;
	struct  in_addr wanip, wannm, wangw, pptpip, pptpnm, pptpgw, pptpsip, l2tpip, l2tpnm, l2tpgw, l2tpsip;
	int pid,btState=0,dnschg=0,spectype=0,mtu=0,pptp_mode=0,mppe,mppc=0,l2tp_mode=0,opmode=0,optime=0;
    char WAN_IF[32]={0},*arg;
	unsigned char tmpBuf[100];
	__FUNC_IN__
		
#if defined(SUPPORT_MESH)
	int rptEnable1=0,rptEnable2=0;
	apmib_get(MIB_OP_MODE,(void *)&opmode);
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
    //wan mode
    ctype = atoi(websGetVar(data, T("wanMode"), T("0")));
	apmib_set(MIB_WAN_DHCP, (void *)&ctype);
    if (ctype==DHCP_DISABLED) {
        ip = websGetVar(data, T("staticIp"), T(""));
		nm = websGetVar(data, T("staticMask"), T("0"));
		gw = websGetVar(data, T("staticGw"), T(""));
		mtu = atoi(websGetVar(data, T("staticMtu"), T("1500")));
		apmib_set(MIB_FIXED_IP_MTU_SIZE, (void *)&mtu);
		if ( !inet_aton(ip, &wanip) ) return 0;
        apmib_set(MIB_WAN_IP_ADDR, (void *)&wanip);
		if ( !inet_aton(nm, &wannm) ) return 0;
        apmib_set(MIB_WAN_SUBNET_MASK, (void *)&wannm);
		if ( !inet_aton(gw, &wangw) ) return 0;
        apmib_set(MIB_WAN_DEFAULT_GATEWAY, (void *)&wangw);
		dnschg=setWanDnsConfig(mosq, data, tp);
    }
	else if (ctype==DHCP_CLIENT) {
		hostname = websGetVar(data, T("hostName"), T(""));
		mtu = atoi(websGetVar(data, T("dhcpMtu"), T("1500")));
		apmib_set(MIB_HOST_NAME, (void *)hostname);
		apmib_set(MIB_DHCP_MTU_SIZE, (void *)&mtu);
		dnschg=setWanDnsConfig(mosq,data,tp);
    }
    else if(ctype==PPPOE) {
        pppoe_user = websGetVar(data, T("pppoeUser"), T(""));
		pppoe_pass = websGetVar(data, T("pppoePass"), T(""));
		opmode = atoi(websGetVar(data, T("pppoeOpMode"), T("0")));
		mtu = atoi(websGetVar(data, T("pppoeMtu"), T("1492")));
		spectype = atoi(websGetVar(data, T("pppoeSpecType"), T("0")));
		optime = atoi(websGetVar(data, T("pppoeTime"), T("60"))) * 60;
		
		apmib_set(MIB_PPP_USER_NAME, (void *)pppoe_user);
		apmib_set(MIB_PPP_PASSWORD, (void *)pppoe_pass);
		apmib_set(MIB_PPP_MTU_SIZE, (void *)&mtu);
		apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&opmode);
		apmib_set(MIB_PPP_IDLE_TIME, (void *)&optime);
		apmib_set(MIB_PPP_SPEC_TYPE, (void *)&spectype);
		dnschg=setWanDnsConfig(mosq,data,tp);

		char_t *strConnect = websGetVar(data, T("pppConnect"), T("0"));
		if (!strcmp(strConnect,"1")) btState = 1;
		char_t *strDisconnect = websGetVar(data, T("pppDisconnect"), T("0"));
		if (!strcmp(strDisconnect,"1")) btState = 2;
    }
	else if (ctype==PPTP) {
		pptp_ip = websGetVar(data, T("pptpIp"), T(""));
		pptp_nm = websGetVar(data, T("pptpMask"), T(""));
		pptp_gw = websGetVar(data, T("pptpGw"), T(""));
		pptp_server= websGetVar(data, T("pptpServerIp"), T(""));
		pptp_user = websGetVar(data, T("pptpUser"), T(""));
		pptp_pass = websGetVar(data, T("pptpPass"), T(""));
		mtu = atoi(websGetVar(data, T("pptpMtu"), T("1460")));
		mppe = atoi(websGetVar(data, T("pptpMppe"), T("0"))); 
		mppc = atoi(websGetVar(data, T("pptpMppc"), T("0"))); 
		pptp_mode = atoi(websGetVar(data, T("pptpMode"), T("0")));
		opmode = atoi(websGetVar(data, T("pptpOpMode"), T("0")));
		optime = atoi(websGetVar(data, T("pptpTime"), T("60")));

		apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&pptp_mode); 		
		if ( !inet_aton(pptp_ip, &pptpip) ) return 0;
		apmib_set(MIB_PPTP_IP_ADDR, (void *)&pptpip);
		if ( !inet_aton(pptp_nm, &pptpnm) ) return 0;
		apmib_set(MIB_PPTP_SUBNET_MASK, (void *)&pptpnm);
		if ( !inet_aton(pptp_gw, &pptpgw) ) return 0;
		apmib_set(MIB_PPTP_DEFAULT_GW, (void *)&pptpgw);
		if ( !inet_aton(pptp_server, &pptpsip) ) return 0;
		apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&pptpsip);
		
		apmib_set(MIB_PPTP_USER_NAME, (void *)pptp_user);
		apmib_set(MIB_PPTP_PASSWORD, (void *)pptp_pass);
		apmib_set(MIB_PPTP_MTU_SIZE, (void *)&mtu);
		apmib_set(MIB_PPTP_CONNECTION_TYPE, (void *)&opmode);
		apmib_set(MIB_PPTP_IDLE_TIME, (void *)&optime);
		apmib_set(MIB_PPTP_SECURITY_ENABLED, (void *)&mppe);
		apmib_set(MIB_PPTP_MPPC_ENABLED, (void *)&mppc);
		dnschg=setWanDnsConfig(mosq,data,tp);		
			
		char_t *strConnect = websGetVar(data, T("pppConnect"), T("0"));
		if (!strcmp(strConnect,"1")) btState = 1;

		char_t *strDisconnect = websGetVar(data, T("pppDisconnect"), T("0"));
		if (!strcmp(strDisconnect,"1")) btState = 2;
	}
    else if (ctype==L2TP) {
		l2tp_ip = websGetVar(data, T("l2tpIp"), T(""));
		l2tp_nm = websGetVar(data, T("l2tpMask"), T(""));
		l2tp_gw = websGetVar(data, T("l2tpGw"), T(""));
		l2tp_server= websGetVar(data, T("l2tpServerIp"), T(""));
		l2tp_user = websGetVar(data, T("l2tpUser"), T(""));
		l2tp_pass = websGetVar(data, T("l2tpPass"), T(""));
		mtu = atoi(websGetVar(data, T("l2tpMtu"), T("1460")));
		l2tp_mode = atoi(websGetVar(data, T("l2tpMode"), T("0")));
		opmode = atoi(websGetVar(data, T("l2tpOpMode"), T("0")));
		optime = atoi(websGetVar(data, T("l2tpTime"), T("60")));

		apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&l2tp_mode);			
		if ( !inet_aton(l2tp_ip, &l2tpip) ) return 0;
        apmib_set(MIB_L2TP_IP_ADDR, (void *)&l2tpip);
		if ( !inet_aton(l2tp_nm, &l2tpnm) ) return 0;
        apmib_set(MIB_L2TP_SUBNET_MASK, (void *)&l2tpnm);
		if ( !inet_aton(l2tp_gw, &l2tpgw) ) return 0;
        apmib_set(MIB_L2TP_DEFAULT_GW, (void *)&l2tpgw);
		if ( !inet_aton(l2tp_server, &l2tpsip) ) return 0;
	   	apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&l2tpsip);
		
		apmib_set(MIB_L2TP_USER_NAME, (void *)l2tp_user);
		apmib_set(MIB_L2TP_PASSWORD, (void *)l2tp_pass);
		apmib_set(MIB_L2TP_MTU_SIZE, (void *)&mtu);
		apmib_set(MIB_L2TP_CONNECTION_TYPE, (void *)&opmode);
		apmib_set(MIB_L2TP_IDLE_TIME, (void *)&optime);
		dnschg=setWanDnsConfig(mosq,data,tp);	

		char_t *strConnect = websGetVar(data, T("pppConnect"), T("0"));
		if (!strcmp(strConnect,"1")) btState = 1;

		char_t *strDisconnect = websGetVar(data, T("pppDisconnect"), T("0"));
		if (!strcmp(strDisconnect,"1")) btState = 2;
    }
    
    // mac clone
    clone_en = websGetVar(data, T("macCloneEnabled"), T("0"));
	clone_mac = websGetVar(data, T("macCloneMac"), T(""));
	//if(atoi(clone_en)) 
	{
	    char *delim=":", *p=NULL;
	    char buffer[32]={0}, clo_mac[32]={0};
        if(clone_mac!=NULL){
	        p = strtok(clone_mac, delim);
	        if(p==NULL) return 0;
            strcat(buffer, p);
            while((p=strtok(NULL, delim))) {
        		strcat(buffer, p);
        	}
        	string_to_hex(buffer, clo_mac, 12);
        	apmib_set(MIB_WAN_MAC_ADDR, (void *)clo_mac);
	    }
	}

	apmib_update_web(CURRENT_SETTING);	// update configuration to flash
	
    //手动PPPOE连接/断开
    apmib_get(MIB_OP_MODE,	(void *)&opmode);
	CSTE_DEBUG("~~~ btState=[%d] ctype=[%d] opmode=[%d] ~~~\n", btState, ctype, opmode);
	if ((btState==1)&&((ctype == PPPOE) || (ctype == PPTP) || (ctype == L2TP))) { // connect button is pressed
#if 1	//for manual pppoe set wan mac address
		char tmpBuff[32]={0}, cmdBuf[64]={0};
		apmib_get(MIB_WAN_MAC_ADDR,  (void *)tmpBuff);
		sprintf(cmdBuf,"ifconfig eth1 hw ether %02x%02x%02x%02x%02x%02x",(unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1],
			(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
		CsteSystem(cmdBuf,CSTE_PRINT_CMD);
#endif

	    int wait_time=30;
	    if(opmode==WISP_MODE){
            int wisp_wan_id, wlan_mode;
            char wlan_name[16], wisp_tmp[16]={0};
            apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
            sprintf(wlan_name,"wlan%d",wisp_wan_id);
            if(SetWlan_idx(wlan_name)){
                apmib_get(MIB_WLAN_MODE,(void *)&wlan_mode);
                if(wlan_mode == CLIENT_MODE)
                    sprintf(wisp_tmp, "wlan%d", wisp_wan_id);
                else
                    sprintf(wisp_tmp, "wlan%d-vxd", wisp_wan_id);
            }
            strcpy(WAN_IF, wisp_tmp);
	    }else if(opmode==GATEWAY_MODE){
	        strcpy(WAN_IF, "eth1");
	    }	
	    system("killall -9 igmpproxy 2> /dev/null");
		system("echo 1,0 > /proc/br_mCastFastFwd");
#ifdef CONFIG_APP_DNRD		
		system("killall -9 dnrd 2> /dev/null");
#endif
#ifndef CONFIG_APP_IPV6_SUPPORT
#ifdef CONFIG_APP_DNSMASQ	
		system("killall dnsmasq 2> /dev/null");//restart dnsmasq when hosts change
#endif
#endif
		if(ctype == PPPOE || ctype == PPTP)
		    system("killall -15 pppd 2> /dev/null");
        else
            system("killall -9 pppd 2> /dev/null");

		system("sysconf recordWanConnTime 0"); 
		system("sysconf recordWanConnTime 1"); 
		system("disconnect.sh option");
        pid = fork();
        if(pid)
    		waitpid(pid, NULL, 0);
        else if(pid==0){
            if(ctype == PPPOE){
				snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPPOE_SCRIPT_PROG);
				execl( tmpBuf, _PPPOE_SCRIPT_PROG, "connect", WAN_IF, NULL);
			}else if(ctype == PPTP){
				snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPTP_SCRIPT_PROG);
				execl( tmpBuf, _PPTP_SCRIPT_PROG, "connect", WAN_IF, NULL);
			}else if(ctype == L2TP){
				system("killall -9 l2tpd 2> /dev/null");
				system("rm -f /var/run/l2tpd.pid 2> /dev/null");
				snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _L2TP_SCRIPT_PROG);
				execl( tmpBuf, _L2TP_SCRIPT_PROG, "connect", WAN_IF, NULL);
			}
   			exit(1);
        }
        while (wait_time-- >0){
            if(isConnectPPP())
                break;
            sleep(1);
        }

        websSetCfgResponse(mosq, tp, "0", "reserv");
        return 0;
	}
	if ((btState==2)&&((ctype == PPPOE) || (ctype == PPTP) || (ctype == L2TP))) { // disconnect button is pressed
        if(ctype != PPTP){
            pid = fork();
            if(pid)
                waitpid(pid, NULL, 0);
            else if(pid == 0){
                snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPPOE_DC_SCRIPT_PROG);
                execl( tmpBuf, _PPPOE_DC_SCRIPT_PROG, "all", NULL);
                exit(1);
            }else{
                system("killall -15 ppp_inet 2> /dev/null");
                system("killall -15 pppd 2> /dev/null");
				CsteSystem("echo 0 > /var/wanconnect",CSTE_PRINT_CMD);
            }
        }
        websSetCfgResponse(mosq, tp, "0", "reserv");
        return 0;
	}
	
    if(dnschg == 1)
        arg = "all";
    else
        arg = "wan";

    run_init_script(arg);	
	__FUNC_OUT__
	websSetCfgResponse(mosq, tp, "30", "reserv");
}

/**
* @note getWanConfig	get wan configuration
* 
* @param NULL
* @return Return Json Data
<pre>
{
	"wanMode": 1,
	"dnsMode": 0,
	"pptpMode":	0,
	"l2tpMode":	0,
	"staticMtu":	1500,
	"dhcpMtu": 1492,
	"pppoeMtu":	1492,
	"pptpMtu": 1460,
	"l2tpMtu": 1460,
	"pppoeSpecType":	0,
	"pppoeTime": 300,
	"pptpTime":	300,
	"l2tpTime":	300,
	"pptpMppe":	0,
	"pptpMppc":	0,
	"l2tpDomainFlag": 0,
	"pptpDomainFlag": 0,
	"pppoeOpMode": 0,
	"pptpOpMode":	0,
	"l2tpOpMode":	0,	
	"lanIp":	"192.168.0.1",
	"staticIp":	"172.1.1.1",
	"staticMask":	"255.255.255.0",
	"staticGw":	"172.1.1.254",
	"pptpIp":	"172.1.1.2",
	"pptpMask": "255.255.255.0",
	"pptpGw": "0.0.0.0",
	"pptpServerIp":	"172.1.1.1",
	"l2tpIp":	"172.1.1.2",
	"l2tpMask": "255.255.255.0",
	"l2tpGw": "0.0.0.0",
	"l2tpServerIp":	"172.1.1.1",
	"pppoeUser":	"",
	"pppoePass":	"",
	"pptpUser":	"",
	"pptpPass":	"",
	"l2tpUser":	"",
	"l2tpPass":	"",
	"l2tpServerDomain":	"",
	"pptpServerDomain":	"",
	"wanConnStatus":	"disconnected",
	"wanDefMac":	"F4:38:54:00:02:15",
	"macCloneMac":	"F4:38:54:00:02:15",
	"macCloneEnabled":	0,
	"operationMode":	0,
	"priDns": "0.0.0.0",
	"secDns": "0.0.0.0",
	"wanAutoDetectBt":	0,
	"pppoeSpecBt":	1,
	"pptpBt":	0,
	"l2tpBt":	0
}
return parameter description
operationMode:Operate mode. eg: 0:gateway,1:bridge, 2:repeater, 3:wisp
wanMode:Connection Type. eg: Static IP,DHCP,PPPoE/PPTP/L2TP
Ip,Mask,Gateway,Mtu,User,Pass,Server-separate parameters depending on the connection mode
dnsMode-Manual or auto configuration of DNS. eg:1 auto 0 manual
defaultMac-Native MAC address 
cloneMac-MAC address of the stationMac
</pre>
* @author	rancho
* @date	2017-11-8
*/
int getWanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root=cJSON_CreateObject();
    int arraylen=0,dnsMode=0;
    char buffer[32]={0},tmpBuf[32]={0},wanDefMac[18]={0},cloneMac[18]={0};
	__FUNC_IN__
	
	//int type mib
    char *IntGetName[]={"wanMode","dnsMode","pptpMode","l2tpMode",\
    	"staticMtu","dhcpMtu","pppoeMtu","pptpMtu","l2tpMtu",\
    	"pppoeSpecBt","pppoeSpecType","pppoeTime","pptpTime","l2tpTime",\
    	"pptpMppe","pptpMppc","l2tpDomainFlag","pptpDomainFlag",\
    	"pppoeOpMode","pptpOpMode","l2tpOpMode"};
    int IntGetId[]={MIB_WAN_DHCP,MIB_DNS_MODE,MIB_PPTP_WAN_IP_DYNAMIC,MIB_L2TP_WAN_IP_DYNAMIC,\
		MIB_FIXED_IP_MTU_SIZE,MIB_DHCP_MTU_SIZE,MIB_PPP_MTU_SIZE,MIB_PPTP_MTU_SIZE,MIB_L2TP_MTU_SIZE,\
		MIB_PPPOE_SPEC_SUPPORT,MIB_PPP_SPEC_TYPE,MIB_PPP_IDLE_TIME,MIB_PPTP_IDLE_TIME,MIB_L2TP_IDLE_TIME,\
		MIB_PPTP_SECURITY_ENABLED,MIB_PPTP_MPPC_ENABLED,MIB_L2TP_GET_SERV_BY_DOMAIN,MIB_PPTP_GET_SERV_BY_DOMAIN,\		
    	MIB_PPP_CONNECT_TYPE,MIB_PPTP_CONNECTION_TYPE,MIB_L2TP_CONNECTION_TYPE};
    arraylen=sizeof(IntGetName)/sizeof(char *);
    getCfgArrayInt(root, arraylen, IntGetName, IntGetId);

	//ip type mib
    char *IPGetName[]={"lanIp","staticIp","staticMask","staticGw",\
    	"pptpIp","pptpMask","pptpGw","pptpServerIp",\
    	"l2tpIp","l2tpMask","l2tpGw","l2tpServerIp"};
    int IPGetId[]={MIB_IP_ADDR,MIB_WAN_IP_ADDR,MIB_WAN_SUBNET_MASK,MIB_WAN_DEFAULT_GATEWAY,\
		MIB_PPTP_IP_ADDR,MIB_PPTP_SUBNET_MASK,MIB_PPTP_DEFAULT_GW,MIB_PPTP_SERVER_IP_ADDR,\
		MIB_L2TP_IP_ADDR,MIB_L2TP_SUBNET_MASK,MIB_L2TP_DEFAULT_GW,MIB_L2TP_SERVER_IP_ADDR};
    arraylen=sizeof(IPGetName)/sizeof(char *);
    getCfgArrayIP(root, arraylen, IPGetName, IPGetId);

	//str type mib
    char *StrGetName[]={"wanList","hostName","pppoeUser","pppoePass",\
    	"pptpUser","pptpPass","l2tpUser","l2tpPass",\
    	"l2tpServerDomain","pptpServerDomain"};
	int StrGetId[]={MIB_WAN_LIST,MIB_HOST_NAME,MIB_PPP_USER_NAME, MIB_PPP_PASSWORD,\
		MIB_PPTP_USER_NAME,MIB_PPTP_PASSWORD,MIB_L2TP_USER_NAME,MIB_L2TP_PASSWORD,\
		MIB_L2TP_SERVER_DOMAIN,MIB_PPTP_SERVER_DOMAIN};	
    arraylen=sizeof(StrGetName)/sizeof(char *);
    getCfgArrayStr(root, arraylen, StrGetName, StrGetId);

	//pppoeConnectstatus
	get_wan_connect_status(tmpBuf);
	cJSON_AddStringToObject(root,"wanConnStatus",tmpBuf);
	
    apmib_get(MIB_HW_NIC1_ADDR, (void *)buffer);
    sprintf(wanDefMac, "%02X:%02X:%02X:%02X:%02X:%02X", (unsigned char)buffer[0], (unsigned char)buffer[1],\
        (unsigned char)buffer[2], (unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);
	cJSON_AddStringToObject(root,"wanDefMac",wanDefMac);

	//clone mac
    apmib_get(MIB_WAN_MAC_ADDR, (void *)buffer);
    sprintf(cloneMac, "%02X:%02X:%02X:%02X:%02X:%02X", (unsigned char)buffer[0], (unsigned char)buffer[1],\
        (unsigned char)buffer[2], (unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);
    cJSON_AddStringToObject(root,"macCloneMac",cloneMac);
    if(!strcasecmp(wanDefMac, cloneMac)||!strcasecmp("00:00:00:00:00:00", cloneMac)){
        cJSON_AddNumberToObject(root,"macCloneEnabled",0);
    }else{
        cJSON_AddNumberToObject(root,"macCloneEnabled",1);
    }
	
	//opmode
	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());

	//dns
	apmib_get(MIB_DNS_MODE, (void *)&dnsMode);
	if(dnsMode==1){//manual
	    char*IPGetName2[]={"priDns","secDns"};
        int IPGetId2[]={MIB_DNS1,MIB_DNS2};
	    arraylen=sizeof(IPGetName2)/sizeof(char *);
        getCfgArrayIP(root, arraylen, IPGetName2, IPGetId2);
	}else{//auto
        cJSON_AddStringToObject(root,"priDns",getDns(1));
		cJSON_AddStringToObject(root,"secDns",getDns(2));
    }

#ifdef CONFIG_SUPPORT_WAN_AUTODETECT
	cJSON_AddNumberToObject(root,"wanAutoDetectBt",1);
#else
	cJSON_AddNumberToObject(root,"wanAutoDetectBt",0);
#endif

	output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note  getStationMacByIp	get station mac by ip
* @param	setting Json Data
<pre>
{
	"stationIp":	"192.168.15.200"
}
setting parameter description
stationIp:	station ip
</pre>
* @return Return Json Data
<pre>
{
	"stationMac":	"c8:1f:66:17:ae:b7"
}
return parameter description
stationMac:	station mac
</pre>
* @author	rancho
* @date	2017-11-8
*/
int getStationMacByIp(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output,*sta_ip;
    cJSON *root;
    char myMAC[32]={0};
    
    root=cJSON_CreateObject();    
    sta_ip = websGetVar(data, T("stationIp"), T(""));

	arplookup(sta_ip, myMAC);
	cJSON_AddStringToObject(root,"stationMac",myMAC);
	
    output =cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
	__FUNC_OUT__
    return 0;
}

/**
* @note  discoverWan	discover wan
* @param	NULL
* @return Return Json Data
<pre>
{
	"discoverProto":	"1"
}
return parameter discription
discoverProto:	discover result	-1: disconnet; 0: no-respond; 1: dhcp; 3: pppoe
</pre>
* @author	felix
* @date	2018-2-23
*/
int discoverWan(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
    cJSON *root=cJSON_CreateObject();
	int phy_link=0,discover=0,ret=0;
    
	phy_link=get_wan_link_status("eth1");
	if(phy_link < 0){
		ret=-1;
	}else{
		discover=discover_all();
		if (discover > 0){
			ret=discover;
		}else{
			ret=0;
		}
	}
	cJSON_AddNumberToObject(root,"discoverProto",ret);
    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
    return 0;
}

#ifdef CONFIG_USER_VPND
int getVpnServerInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *f_info;
	cJSON *root,*subObj,*user_info;	
	VPNSERVER_T entry;
	char ServerAddr[32]={0},PreDns[32]={0},SecDns[32]={0},MTU[32]={0},MRU[32]={0},StartIP[32]={0},EndIP[32]={0};
	char ClientServerAddr[32]={0},ClientProtocol[4]={0},ClientUsername[64],ClientPassword[64],ClientOptionType[4]={0};
	char info[128]={0},buf[128]={0},authenticat[16]={0},device_ip[32]={0},name[64]={0},pid[32]={0};
	char Enable[4]={0},VpnType[4]={0}; 
	int i=0,entryNum=0,en=0,type=0,FALG=0;
	__FUNC_IN__

	apmib_get(MIB_VPN_ENABLE, (void *)&en);	
	sprintf(Enable,"%d",en);

	apmib_get(MIB_VPN_TYPE, (void *)&type);
	sprintf(VpnType,"%d",type);	

	apmib_get(MIB_VPN_STARTIP, (void *)StartIP);
	apmib_get(MIB_VPN_ENDIP, (void *)EndIP);
	apmib_get(MIB_VPN_SERVERADDR, (void *)ServerAddr);
	apmib_get(MIB_VPN_PREDNS, (void *)PreDns);
	apmib_get(MIB_VPN_SECDNS, (void *)SecDns);
	apmib_get(MIB_VPN_MTU, (void *)MTU);
	apmib_get(MIB_VPN_MRU, (void *)MRU);	
	apmib_get(MIB_VPN_CLI_SRVADDR, (void *)ClientServerAddr);
	apmib_get(MIB_VPN_CLI_PROTOCOL, (void *)&type);	
	sprintf(ClientProtocol,"%d",type);

	apmib_get(MIB_VPN_USERNAME, (void *)ClientUsername);
	apmib_get(MIB_VPN_PASSWORD, (void *)ClientPassword);
	apmib_get(MIB_VPN_OPTION_TYPE, (void *)&type);
	sprintf(ClientOptionType,"%d",type);

	apmib_get(MIB_VPNSERVER_TBL_NUM, (void *)&entryNum);	
	
	root=cJSON_CreateObject();
	cJSON_AddStringToObject(root, "VpnEnable",Enable);	
	cJSON_AddStringToObject(root, "VpnType",VpnType);
	
	cJSON_AddStringToObject(root, "StartIP",StartIP);	
	cJSON_AddStringToObject(root, "EndIP",EndIP);
	cJSON_AddStringToObject(root, "ServerAddr",ServerAddr);	
	cJSON_AddStringToObject(root, "PreDns",PreDns);
	cJSON_AddStringToObject(root, "SecDns",SecDns);	
	cJSON_AddStringToObject(root, "MTU",MTU);
	cJSON_AddStringToObject(root, "MRU",MRU);

	cJSON_AddStringToObject(root, "ClientServerAddr",ClientServerAddr);	
	cJSON_AddStringToObject(root, "ClientProtocol",ClientProtocol);	
	cJSON_AddStringToObject(root, "ClientUsername",ClientUsername);
	cJSON_AddStringToObject(root, "ClientPassword",ClientPassword);
	cJSON_AddStringToObject(root, "ClientOptionType",ClientOptionType);
	
	if ( strncmp(VpnType, "0", 1) == 0 ){ //client status
		f_read("/tmp/vpn_cli_connected", info, 0, sizeof(info));
		if ( strlen(info) > 4 ){
			cJSON_AddStringToObject(root, "ClientStatus","1");
			cJSON_AddStringToObject(root, "ClientLinkIpAddr",info);
		}else{
			cJSON_AddStringToObject(root, "ClientStatus","0");
			cJSON_AddStringToObject(root, "ClientLinkIpAddr","0.0.0.0");
		}
	}else{
		cJSON_AddStringToObject(root, "ClientStatus","0");
		cJSON_AddStringToObject(root, "ClientLinkIpAddr","0.0.0.0");
	}
	
	user_info=cJSON_CreateArray();
	if ((f_info = fopen("/tmp/vpnd_connected", "r")) != NULL) {
		for(i=0;i<entryNum;i++){
			FALG=0;
			*((char *)&entry) = (char)(i+1);
			apmib_get(MIB_VPNSERVER_TBL, (void *)&entry);
			while (fgets(info, sizeof(info), f_info)){//遍历在线用户
				if(strlen(info) > 0){
					sscanf(info,"%s %s %s %s",authenticat,pid,device_ip,name);
					if(strcmp(name,entry.vpnserver_name)== 0){
						FALG=1;
						cJSON *item	= cJSON_CreateObject();
						cJSON_AddStringToObject(item, "Username",entry.vpnserver_name);		
						cJSON_AddStringToObject(item, "Password",entry.vpnserver_passwd);		
						cJSON_AddStringToObject(item, "Status","1");
						cJSON_AddStringToObject(item, "IpAddr",device_ip);
						cJSON_AddItemToArray(user_info,item);
					}
				}
				memset(pid,0,sizeof(pid));
				memset(info,0,sizeof(info));
				memset(name,0,sizeof(name));
				memset(device_ip,0,sizeof(device_ip));
				memset(authenticat,0,sizeof(authenticat));
			}
			if(FALG == 0){
				cJSON *item	= cJSON_CreateObject();
				cJSON_AddStringToObject(item, "Username",entry.vpnserver_name);		
				cJSON_AddStringToObject(item, "Password",entry.vpnserver_passwd);		
				cJSON_AddStringToObject(item, "Status","0");
				cJSON_AddStringToObject(item, "IpAddr","NULL");
				cJSON_AddItemToArray(user_info,item);
			}
			rewind(f_info);
		}
		fclose(f_info);
	}
	else{
		for(i=0;i<entryNum;i++){
			*((char *)&entry) = (char)(i+1);
			apmib_get(MIB_VPNSERVER_TBL, (void *)&entry);
			cJSON *item	= cJSON_CreateObject();
			cJSON_AddStringToObject(item, "Username",entry.vpnserver_name);		
			cJSON_AddStringToObject(item, "Password",entry.vpnserver_passwd);		
			cJSON_AddStringToObject(item, "Status","0");
			cJSON_AddStringToObject(item, "IpAddr","NULL");
			cJSON_AddItemToArray(user_info,item);
		}
	}
	char *account=cJSON_Print(user_info);
	cJSON_AddStringToObject(root, "Account",account);
	char *output =cJSON_Print(root);	
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	__FUNC_OUT__
	return 0;
}

int setVpnServerInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int enabled=0,type=0,intVal=0;
	char *VpnActionType = websGetVar(data, T("VpnActionType"), T("0"));
	char *flag = websGetVar(data, T("addEffect"), T("0"));	
	char *VpnTypeFlag = websGetVar(data, T("VpnTypeFlag"), T(""));
	if(atoi(VpnTypeFlag) == 1){		
		char *VpnType = websGetVar(data, T("VpnType"), T(""));	
		type = atoi(VpnType);	
		apmib_set(MIB_VPN_TYPE, (void *)&type);
	}else if(atoi(flag)==1){	
		char *VpnEnable = websGetVar(data, T("VpnEnable"), T("0")); 
		enabled = atoi(VpnEnable);	
		apmib_set(MIB_VPN_ENABLE, (void *)&enabled);
	}else{
		if(atoi(VpnActionType)==1){
			//Server
			char *ServerAddr = websGetVar(data, T("ServerAddr"), T(""));
			char *StartIP = websGetVar(data, T("StartIP"), T(""));	
			char *EndIP = websGetVar(data, T("EndIP"), T(""));	
			char *PreDns = websGetVar(data, T("PreDns"), T("0"));
			char *SecDns = websGetVar(data, T("SecDns"), T("0"));
			char *MTU = websGetVar(data, T("MTU"), T(""));
			char *MRU = websGetVar(data, T("MRU"), T(""));

			//Client
			char *ClientServerAddr = websGetVar(data, T("ClientServerAddr"), T(""));
			char *ClientProtocol = websGetVar(data, T("ClientProtocol"), T(""));
			char *ClientUsername = websGetVar(data, T("ClientUsername"), T(""));
			char *ClientPassword = websGetVar(data, T("ClientPassword"), T(""));
			char *ClientOptionType = websGetVar(data, T("ClientOptionType"), T(""));

			apmib_get(MIB_VPN_TYPE, (void *)&type);
				
			if (type == 1){ //server
				printf("ServerAddr==[%s],StartIP==[%s],EndIP==[%s],PreDns==[%s],SecDns==[%s],MTU==[%s],MRU==[%s]\n",ServerAddr,StartIP,EndIP,PreDns,SecDns,MTU,MRU);
				if(strlen(ServerAddr) > 0)	apmib_set(MIB_VPN_SERVERADDR, (void *)ServerAddr);
				if(strlen(StartIP) > 0)		apmib_set(MIB_VPN_STARTIP, (void *)StartIP);
				if(strlen(EndIP) > 0)		apmib_set(MIB_VPN_ENDIP, (void *)EndIP);
				if(strlen(PreDns) > 0)		apmib_set(MIB_VPN_PREDNS, (void *)PreDns);
				if(strlen(SecDns) > 0)		apmib_set(MIB_VPN_SECDNS, (void *)SecDns);
				if(strlen(MTU) > 0)			apmib_set(MIB_VPN_MTU, (void *)MTU);
				if(strlen(MRU) > 0)			apmib_set(MIB_VPN_MRU, (void *)MRU);
			}else if (type == 0){
				printf("ClientServerAddr==[%s],ClientProtocol==[%s],ClientUsername==[%s],ClientPassword==[%s],ClientOptionType==[%s]\n",ClientServerAddr,ClientProtocol,ClientUsername,ClientPassword,ClientOptionType);
				if(strlen(ClientServerAddr) > 0) apmib_set(MIB_VPN_CLI_SRVADDR, (void *)ClientServerAddr);

				intVal = atoi(ClientProtocol);	
				apmib_set(MIB_VPN_CLI_PROTOCOL, (void *)&intVal);

				if(strlen(ClientUsername) > 0) apmib_set(MIB_VPN_USERNAME, (void *)ClientUsername);
				if(strlen(ClientPassword) > 0) apmib_set(MIB_VPN_PASSWORD, (void *)ClientPassword);

				intVal = atoi(ClientOptionType);	
				apmib_set(MIB_VPN_OPTION_TYPE, (void *)&intVal);
			}
		}else{
			//stop pptp
			system("killall pptpd 2> /dev/null");
			system("killall vpnpppd 2> /dev/null");
			system("killall xpptp 2> /dev/null");
			
			//stop xl2tpd
			if(f_exist("/var/run/xl2tpd")){
				system("echo \"d client\" > /var/run/xl2tpd/l2tp-control");
				system("rm -rf /var/run/xl2tpd/*");
				system("killall xl2tpd");
			}
			
			system("rm -f /tmp/vpnd_connected /tmp/vpn_cli_connected");
			goto dis_vpnc;
		}
	}
		
	apmib_update_web(CURRENT_SETTING);
	system("sysconf vpnd");
	
dis_vpnc:
	if(atoi(VpnActionType) == 1)	
		websSetCfgResponse(mosq, tp, "10", "reserv");
	else	
		websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

int AddVpnServerInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *fp;
	int entryNum=0;
	VPNSERVER_T entry;
	char *UserName = websGetVar(data, T("Username"), T("rd"));	
	char *PassWord = websGetVar(data, T("Password"), T("rd"));
	
	apmib_get(MIB_VPNSERVER_TBL_NUM, (void *)&entryNum);
	if(entryNum <= 10){
		strcpy((char *)entry.vpnserver_name, UserName);		
		strcpy((char *)entry.vpnserver_passwd, PassWord);
		strcpy((char *)entry.vpnserver_comment, "NULL");
		inet_aton("0.0.0.0", (struct in_addr *)&entry.vpnserver_ip);
		
		apmib_set(MIB_VPNSERVER_DEL, (void *)&entry);	
		apmib_set(MIB_VPNSERVER_ADD, (void *)&entry);	
		apmib_update_web(CURRENT_SETTING);
	}

	system("sysconf vpnduser");

out:
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

int DelteVpnServerInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *fp;
	int i,entryNum;
	char name_buf[16];
	char *username;
	VPNSERVER_T delEntry,entry;
	apmib_get(MIB_VPNSERVER_TBL_NUM, (void *)&entryNum);
	for (i=entryNum; i>0; i--) {
		snprintf(name_buf, 16, "delUser%d", i);
		username = websGetVar(data, name_buf, NULL);
		if (username){
			*((char *)(void *)&delEntry) = (char)i;
			apmib_get(MIB_VPNSERVER_TBL, (void *)&delEntry);
			apmib_set(MIB_VPNSERVER_DEL, (void *)&delEntry);
			
			disconnec_vpn(username);
		}
	}
	apmib_update_web(CURRENT_SETTING);

	system("sysconf vpnduser");
out:
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}
#endif /* CONFIG_UESR_VPND */

int module_init()
{
    cste_hook_register("setWanConfig",setWanConfig);
	cste_hook_register("getWanConfig",getWanConfig);
	cste_hook_register("getStationMacByIp",getStationMacByIp);
	cste_hook_register("discoverWan",discoverWan);

#ifdef CONFIG_USER_VPND
	cste_hook_register("getVpnServerInfo",getVpnServerInfo);
	cste_hook_register("setVpnServerInfo",setVpnServerInfo);
	cste_hook_register("AddVpnServerInfo",AddVpnServerInfo);
	cste_hook_register("DelteVpnServerInfo",DelteVpnServerInfo);
#endif	

#if defined(CONFIG_RTL_ISP_MULTI_WAN_SUPPORT)
	cste_hook_register("setMultiWanConfig",setMultiWanConfig);
	cste_hook_register("getIndex",getIndex);
	cste_hook_register("getVirtualIndex",getVirtualIndex);
	cste_hook_register("getInfo",getInfo);
#endif
	return 0;  
}
