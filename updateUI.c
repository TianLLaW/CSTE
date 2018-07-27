#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "apmib.h"

#define MENUNUM 64
#define array_len(x)   (sizeof(x)/sizeof(x[0]))

int usege()
{
	printf("./updateUI");
}

int addToNodisplay(char array[MENUNUM][64],char *id)
{
	int index=0;
	for( index=0;index<MENUNUM;index++){			
		if(strlen (array[index]) == 0 )
			break ;
		else if(!strcmp(array[index],id))
			return 0;
	}
	strcpy (array[index],id);
	return 0;
}

int main(int argc, char *argv[])
{
	int  tmpInt=0, opmode=0, i = 0, display_offset = 0, mesh_enable = 0, mesh_slave = 0;
	char tmp[32]={0},tmpcmd[256], tmpStr[256]={0}, buf[8192] = {0};
	char *findp;
	FILE *fp;

	if ( !apmib_init()) {
		printf("[%s:%d]updateUI Initialize AP MIB failed !\n",__FUNCTION__,__LINE__);
		return 0;
	}

	if(0 == f_exist("/web_cste/static/js/config.js_priv")){
		system("cp /web_cste/static/js/config.js /web_cste/static/js/config.js_priv");
	}else{
		system("cp /web_cste/static/js/config.js_priv /web_cste/static/js/config.js");
	}

	fp = fopen("/web_cste/static/js/config.js", "r+");
	if(NULL == fp){
		printf("[%s:%d]open /web_cste/static/js/config.js failed!\n",__FUNCTION__,__LINE__);
		return -1;
	}

	char nodisplay[MENUNUM][64]= {0};
	char brnodisplay[MENUNUM][64] = {"3-1","3-3","3-4","3-5","3-6",
		#if!defined (SUPPORT_WLAN)
			"id:\"4\"",
		#else
		#if !defined (SUPPORT_MBSS)
			"4-3",
		#endif
		#if !defined (SUPPORT_WDS)
			"4-5",
		#endif
		#if !defined (SUPPORT_WPS)
			"4-6",
		#endif
		#endif
		
		#if !defined(SUPPORT_WLAN5G)
			"id:\"5\"",
		#else
		#if !defined (SUPPORT_WDS5G)
			"5-5",
		#endif
		#endif
			"id:\"6\"",
			"id:\"7\"",
			"8-3",
			"8-4",
		#if !defined (SUPPORT_MINIUPNPD)
			"8-5",
		#endif
		#if !defined (SUPPORT_SYSLOGD)
			"8-8",
		#endif
		#if !defined (SUPPORT_HAC)
			"id:\"9\"",
		#endif
			"id:\"10\"",
			"id:\"11\"",
			"id:\"14\"",
		#if !defined(SUPPORT_MANAGEMENTAC)
			"id:\"13\""
		#endif
		};
	
	char gwnodisplay[MENUNUM][64] = {
		#if !defined(SUPPORT_DHCP_DETECT)
			"3-4",
		#endif
			"3-5",

		#if!defined (SUPPORT_WLAN)
			"id:\"4\"",
		#else
		#if !defined (SUPPORT_MBSS)
			"4-3",
		#endif
		#if !defined (SUPPORT_WDS)
			"4-5",
		#endif
		#if !defined (SUPPORT_WPS)
			"4-6",
		#endif
		#endif

		#if !defined(SUPPORT_WLAN5G)
			"id:\"5\"",
		#else
		#if !defined (SUPPORT_MBSS5G)
			"5-3",
		#endif
		#if !defined (SUPPORT_WDS5G)
			"5-5",
		#endif
		#if !defined (SUPPORT_WPS5G)
			"5-6",
		#endif
		#endif

		#if !defined (SUPPORT_BWCONTRL)
			"id:\"6\"",
		#endif
		#if !defined (SUPPORT_BMCONTRL)
			"id:\"11\"",
		#endif

		#if !defined (SUPPORT_MINIUPNPD)
			"8-5",
		#endif
		#if !defined (SUPPORT_SYSLOGD)
			"8-8",
		#endif
		#if !defined (SUPPORT_HAC)
			"id:\"9\"",
		#endif
		
		#if !defined (SUPPORT_NETX)
			"id:\"10\"",
		#endif
		
		#if !defined (SUPPORT_OPENVPND)
			"10-6",
		#endif

		#if !defined (SUPPORT_DIAGNOSTIC)
			"id:\"14\"",
		#endif
		#if !defined(SUPPORT_MANAGEMENTAC)
			"id:\"13\""
		#endif
	};

	char wifioff_2g[10][64] = {
		"4-1",
		"4-3",
		"4-4",
		"4-5",
		"4-6",
		"4-7"
	};

	char wifioff_5g[10][64] = {
		"5-1",
		"5-3",
		"5-4",
		"5-5",
		"5-6",
		"5-7"
	};

	//GATEWAY_MODE=0, BRIDGE_MODE=1, WISP_MODE=2, REPEATER_MODE=3
	apmib_get(MIB_OP_MODE, (void *)&opmode);
#if defined(SUPPORT_MESH)
	apmib_get(MIB_WLAN_MESH_ENABLE, (void * )&mesh_enable);
	if(opmode==1&&mesh_enable==1)
		mesh_slave=1;
#endif
	if(BRIDGE_MODE==opmode || REPEATER_MODE==opmode)
	{
		memcpy(nodisplay,brnodisplay,sizeof(brnodisplay));
	}
	else if(GATEWAY_MODE==opmode || WISP_MODE==opmode) //gw
	{
		memcpy(nodisplay,gwnodisplay,sizeof(gwnodisplay));
	}
	if(mesh_slave==1){
		addToNodisplay(nodisplay,"id:\"2\"");
		addToNodisplay(nodisplay,"id:\"3\"");
		addToNodisplay(nodisplay,"id:\"6\"");
		addToNodisplay(nodisplay,"id:\"7\"");
		addToNodisplay(nodisplay,"id:\"9\"");
		addToNodisplay(nodisplay,"id:\"10\"");
		addToNodisplay(nodisplay,"id:\"11\"");
		addToNodisplay(nodisplay,"id:\"12\"");
		addToNodisplay(nodisplay,"id:\"13\"");
		addToNodisplay(nodisplay,"id:\"14\"");
		
		addToNodisplay(nodisplay,"4-2");
		addToNodisplay(nodisplay,"4-3");
		addToNodisplay(nodisplay,"4-4");
		addToNodisplay(nodisplay,"4-5");
		addToNodisplay(nodisplay,"4-6");
		addToNodisplay(nodisplay,"4-7");
		
		addToNodisplay(nodisplay,"5-2");
		addToNodisplay(nodisplay,"5-3");
		addToNodisplay(nodisplay,"5-4");
		addToNodisplay(nodisplay,"5-5");
		addToNodisplay(nodisplay,"5-6");
		addToNodisplay(nodisplay,"5-7");
		
		addToNodisplay(nodisplay,"8-1");
		addToNodisplay(nodisplay,"8-2");
		addToNodisplay(nodisplay,"8-3");
		addToNodisplay(nodisplay,"8-4");
		addToNodisplay(nodisplay,"8-5");
		addToNodisplay(nodisplay,"8-8");
		addToNodisplay(nodisplay,"8-9");
		addToNodisplay(nodisplay,"8-10");
		addToNodisplay(nodisplay,"8-11");
		addToNodisplay(nodisplay,"8-12");
		
	}else{
		apmib_get(MIB_OPMODE_LIST, tmpStr);
		if(!strstr(tmpStr,";")){
			addToNodisplay(nodisplay,"id:\"2\"");
		}
		
		apmib_get(MIB_IPTV_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"3-6");
		}else{
		}

		apmib_get(MIB_IPV6_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"3-7");
		}

		apmib_get(MIB_DDNSCLIENT_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"8-3");
		}

		apmib_get(MIB_SSRSERVER_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"10-1");
		}

		int pptvServerSupport=0;
		apmib_get(MIB_PPTPSERVER_SUPPORT, (void *)&pptvServerSupport);
		if(pptvServerSupport==0){
			addToNodisplay(nodisplay,"10-2");
		}

		int l2tvServerSupport=0;
		apmib_get(MIB_L2TPSERVER_SUPPORT, (void *)&l2tvServerSupport);
		if(l2tvServerSupport==0){
			addToNodisplay(nodisplay,"10-3");
		}

		if(pptvServerSupport==0 && l2tvServerSupport==0){
			addToNodisplay(nodisplay,"10-4");
			addToNodisplay(nodisplay,"10-5");
		}

		apmib_get(MIB_PPTPCLIENT_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"10-7");
		}

		apmib_get(MIB_L2TPCLIENT_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"10-8");
		}

		apmib_get(MIB_WECHATQR_SUPPORT, (void *)&tmpInt);
		if(tmpInt==0){
			addToNodisplay(nodisplay,"id:\"12\"");
		}
	}

#if defined(FOR_DUAL_BAND)
	//5G show
	memset(tmpStr,0,sizeof(tmpStr));
	sprintf(tmpcmd,"ifconfig | grep -v vxd |grep wlan0 | awk 'NR==1{print $1}'");
	getCmdStr(tmpcmd,tmpStr,sizeof(tmpStr));
	if(!strcmp(tmpStr,"")){
		for( i=0;i<10;i++){
			if(strlen(wifioff_5g[i])>0){
				addToNodisplay(nodisplay,wifioff_5g[i]);
			}else{
				break;
			}
		}
	}
	//2.4G show
	memset(tmpStr,0,sizeof(tmpStr));
	sprintf(tmpcmd,"ifconfig | grep -v vxd |grep wlan1 | awk 'NR==1{print $1}'");
	getCmdStr(tmpcmd,tmpStr,sizeof(tmpStr));
	if(!strcmp(tmpStr,"")){	
		for( i=0;i<10;i++){
			if(strlen(wifioff_2g[i])>0){
				addToNodisplay(nodisplay,wifioff_2g[i]);
			}else{
				break;
			}
		}
	}
#else
	memset(tmpStr,0,sizeof(tmpStr));
	sprintf(tmpcmd,"ifconfig | grep -v vxd |grep wlan0 | awk 'NR==1{print $1}'");
	getCmdStr(tmpcmd,tmpStr,sizeof(tmpStr));
	if(!strcmp(tmpStr,"")){				
		for( i=0;i<10;i++){
			if(strlen(wifioff_2g[i])>0){
				addToNodisplay(nodisplay,wifioff_2g[i]);
			}else{
				break;
			}
		}
	}
#endif

	fread(buf, sizeof(buf)-1, 1, fp);
	buf[sizeof(buf)-1] = '\0';	
	fclose(fp);
	for(i=0;i<array_len(nodisplay);i++){
		if(2 > strlen(nodisplay[i]))
			continue;
		if(findp = strstr(buf, nodisplay[i])){
				if(findp = strstr(findp, "display")){
					display_offset = findp - buf;
					strncpy(tmp,findp,10);
					buf[display_offset+9]='1';
					memset(tmp,0,sizeof(tmp));
					strncpy(tmp,findp,10);
				}
			}
			else{
				printf("[updeateUI:%d] not found!\n",__LINE__);
			}
	}
	
	
	fp = fopen("/web_cste/static/js/config.js", "w");
	if(NULL == fp){
		printf("open file error\n");
		return -1;
	}
	fwrite(buf,strlen(buf),1,fp);
	fclose(fp);
	
	return 0;
}
