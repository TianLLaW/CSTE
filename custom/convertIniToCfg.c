
/* System include files */
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

#include <apmib.h>
#include <mystdlib.h>


#define usleep_time 100000  //0.1s
#define INIFILE       "/mnt/custom/product.ini"


int getFixedMac(char *wlan_if,int count, char *buffmac)
{
	struct ifreq ifr;
	char *ptr,buff[8]={0};
	int skfd,i;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}

	strncpy(ifr.ifr_name, wlan_if, IF_NAMESIZE);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		close(skfd);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	for(i=12-count;i<12;i++){
		memset(buff,0,sizeof(buff));
		if(i%2)
		sprintf(buff, "%01X",(ptr[i/2] & 0xf));
		else
		sprintf(buff, "%01X",(ptr[i/2] & 0xf0)>>4);
		if(i==0)
			strcpy(buffmac,buff);
		else
			strcat(buffmac,buff);
	}
	close(skfd);
	return 0;
}


int set_wlan_config(char *wlan_if, char *tail)
{
	char buff[128], paraName[48];
	char ssid[33]={0},ssid_tail[33]={0},buffmac[16]={0},wlankey[64]={0},channel[8]={0},maxsta[8]={0},countrycode[8]={0},txpower[8] = {0};
	int tmpint;

	memset(buffmac,0,sizeof(buffmac));
	inifile_get_string(INIFILE,"WLAN","FixedMac",buffmac);

	memset(maxsta,0,sizeof(maxsta));
	inifile_get_string(INIFILE,"WLAN","MaxSta",maxsta);

	memset(ssid,0,sizeof(ssid));
	sprintf(paraName,"Ssid_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,ssid);

	memset(ssid_tail,0,sizeof(ssid_tail));
	sprintf(paraName,"Ssid_Tail_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,ssid_tail);

	memset(wlankey,0,sizeof(wlankey));
	sprintf(paraName,"WlanKey_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,wlankey);

	memset(channel,0,sizeof(channel));
	sprintf(paraName,"Channel_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,channel);

	memset(countrycode,0,sizeof(countrycode));
	sprintf(paraName,"CountryCode_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,countrycode);

	memset(txpower,0,sizeof(txpower));
	sprintf(paraName,"Txpower_%s",tail);
	inifile_get_string(INIFILE,"WLAN",paraName,txpower);
	
	SetWlan_idx(wlan_if);

	tmpint=atoi(buffmac);
	if(tmpint>12)tmpint=12;
	
	memset(buff,0,sizeof(buff));
	memset(buffmac,0,sizeof(buffmac));
	
	if(tmpint>0){
		getFixedMac(wlan_if,tmpint, buffmac);
		if(strlen(ssid_tail)>0)
			sprintf(buff,"%s%s%s",ssid,buffmac,ssid_tail);
		else
			sprintf(buff,"%s%s",ssid,buffmac);
	}else{
		if(strlen(ssid_tail)>0)
			sprintf(buff,"%s%s",ssid,ssid_tail);
		else
			strcpy(buff,ssid);
	}
	apmib_set(MIB_WLAN_SSID,(void *)buff);

	int wep=WEP_DISABLED;
	int auth_wpa=WPA_AUTH_AUTO;
	ENCRYPT_T encrypt=ENCRYPT_DISABLED;
	if(strlen(wlankey)>7){
		encrypt=ENCRYPT_WPA2_MIXED;//WPAPSKWPA2PSK
		auth_wpa=WPA_AUTH_PSK;
		int pskformat = 0;//0:ASCII
		int ciphersuite1 = WPA_CIPHER_MIXED, ciphersuite2 = WPA_CIPHER_MIXED;//TKIPAES

		apmib_set( MIB_WLAN_WEP, (void *)&wep);
		apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
		apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
		apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
		apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
		apmib_set( MIB_WLAN_WPA_PSK, (void *)wlankey);		
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);

	}else{
		encrypt=ENCRYPT_DISABLED;//None
		int auth_wpa=WPA_AUTH_AUTO;
		apmib_set( MIB_WLAN_WEP, (void *)&wep);
		apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt); 	
		apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	}
	
	//11abg Channel or AutoSelect
	int ichannel=atoi(channel);
	apmib_set(MIB_WLAN_CHANNEL, (void *)&ichannel);

	tmpint=atoi(maxsta);
	if(tmpint > 32)
		tmpint = 32;
	apmib_set(MIB_MAXSTANUM,(void *)&tmpint);

	//Country/RegDomain
	int regdomain=13;
	apmib_set(MIB_WLAN_COUNTRY_STRING, (void *)countrycode);
	if(!strcmp(countrycode,"US")){//usa
		regdomain=1;
	}else if(!strcmp(countrycode,"EU")){//europe
		regdomain=3;
	}else if(!strcmp(countrycode,"OT")){//other
		regdomain=16;
	}else{//china,Indonesia
		regdomain=13;
	}
	apmib_set(MIB_HW_REG_DOMAIN, (void *)&regdomain);

	int itxpower=atoi(txpower);
	if(itxpower==15)
		itxpower = 4;
	else if(itxpower==35)
		itxpower = 3;
	else if(itxpower==50)
		itxpower = 2;
	else if(itxpower==75)
		itxpower = 1;
	else
		itxpower = 0;
	apmib_set(MIB_WLAN_RFPOWER_SCALE, (void *)&itxpower);	
	
	apmib_update(HW_SETTING);

	return 0;
}


int main(int argc, char** argv)
{
	if ( !apmib_init()) {
		printf("convertIniToCfg[%d]Initialize AP MIB failed !\n",__LINE__);
		return 0;
	}

	if(0== f_exist(INIFILE))
	{
		return -1;
	}
	
	int fixed=0,tmpint=0;
	char buff[128]={0},def_buff[128]={0},cmdbuff[128]={};
	
	struct in_addr inIp,inDhcp_s, inDhcp_e;

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Csid",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_CSID, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Model",buff);
	apmib_set(MIB_HARDWARE_MODEL, buff);

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","HostName",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_HOST_NAME, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","WebTitle",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_WEB_TITLE, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Vendor",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_VENDOR, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","CopyRight",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_COPYRIGHT, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","DomainAccess",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_DOMAIN_NAME, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","SoftVersion",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_SOFTWARE_VERSION, buff);
	}
	
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","IpAddress",buff);
	if (strlen(buff)>0 && inet_aton(buff, &inIp) ){
		apmib_set( MIB_IP_ADDR, (void *)&inIp);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","DhcpStart",buff);
	if (strlen(buff)>0 && inet_aton(buff, &inDhcp_s) ){
		apmib_set( MIB_DHCP_CLIENT_START, (void *)&inDhcp_s);
	}	
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","DhcpEnd",buff);
	if(strlen(buff)>0 && inet_aton(buff, &inDhcp_s)){
		apmib_set( MIB_DHCP_CLIENT_END, (void *)&inDhcp_s);	
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Language",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_LANGUAGE_TYPE, buff);
	}

	memset(buff,0,sizeof(buff));
	apmib_get(MIB_LANGUAGE_TYPE, (void *)def_buff);
	sprintf(cmdbuff,"HelpUrl_%s",def_buff);
	inifile_get_string(INIFILE,"PRODUCT",cmdbuff,buff);
	apmib_set(MIB_CUSTOMERURL, buff);

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","MultiLang",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_MULTIPLE_LANGUAGE, buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","TimeZone",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_NTP_TIMEZONE,buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","StatisticsDomain",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_STATISTICS_DOMAIN,buff);
	}
	
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","StatisticsModel",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_STATISTICS_MODEL,buff);
	}
	
#if	defined(CONFIG_APP_CLOUDSRVUP)
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","CloudUpdateDomain",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_CLOUDUPG_HOST,buff);
	}
#endif

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","TelnetKey",buff);
	if(strlen(buff)==0)
		strcpy(buff,"cs2012");
	apmib_set(MIB_TELNET_PASSWORD,buff);

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","LoginPassword",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_USER_PASSWORD,buff);
	}
	
    //set wlan
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"WLAN","CountryCodeSupport",buff);
	if(strlen(buff)>0){
		int icountrysu=atoi(buff);
		apmib_set(MIB_COUNTRYCODE_SUPPORT, (void *)&icountrysu);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"WLAN","CountryCodeList",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_COUNTRYCODE_LIST, buff);
	}

#if defined (ONLY_5G_SUPPORT)
	set_wlan_config("wlan0", "5G");
#else
	#if defined (FOR_DUAL_BAND)
	set_wlan_config("wlan0", "5G");
	set_wlan_config("wlan1", "2G");
	#else
	set_wlan_config("wlan0", "2G");
	#endif
#endif

	//PLUGIN
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","WanTypeList",buff);
	if(strlen(buff)>0){
		apmib_set(MIB_WAN_LIST,buff);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","WanTypeDefault",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_WAN_DHCP,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","PppoeSpecSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_PPPOE_SPEC_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","PppoeSpecRussia",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_PPPOE_RUSSIA_SUPPORT,(void *)&tmpint);
	}

#if 1
	//IPTV
	int iptvIntVal = 0;
	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"IPTV","IptvSupport",buff);
	if(strlen(buff)>0){
		iptvIntVal=atoi(buff);
		apmib_set(MIB_IPTV_SUPPORT, (void *)&iptvIntVal);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"IPTV","IptvEnable",buff);
	if(strlen(buff)>0){
		iptvIntVal=atoi(buff);
		apmib_set(MIB_IPTV_ENABLED, (void *)&iptvIntVal);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"IPTV","IptvModeList",buff);
	if(strlen(buff)>0){
		iptvIntVal=atoi(buff);
		apmib_set(MIB_IPTV_MODELIST, (void *)&iptvIntVal);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"IPTV","IptvModeDefault",buff);
	if(strlen(buff)>0){
		iptvIntVal=atoi(buff);
		apmib_set(MIB_IPTV_MODEDEFAULT, (void *)&iptvIntVal);
	}
#endif

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Ipv6Support",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_IPV6_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","Ipv6Support",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_IPV6_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","L2tpClientSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_L2TPCLIENT_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","PptpClientSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_PPTPCLIENT_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","L2tpServerSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_L2TPSERVER_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","PptpServerSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_PPTPSERVER_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","DdnsSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_DDNSCLIENT_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","SsrServerSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_SSRSERVER_SUPPORT,(void *)&tmpint);
	}

	memset(buff,0,sizeof(buff));
	inifile_get_string(INIFILE,"PRODUCT","WechatQrSupport",buff);
	if(strlen(buff)>0){
		tmpint=atoi(buff);
		apmib_set(MIB_WECHATQR_SUPPORT,(void *)&tmpint);
	}

	fixed = 1;
	apmib_set(MIB_CUSTOM_FIXEDINI,	&fixed);

	printf("convertIniToCfg[%d]Restore Product Info form INI!!!\n",__LINE__);

	return 0;
}

