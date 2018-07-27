/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file vlan.c
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/wireless.h>

#include "vlan.h"

#define VLAN_TYPE_NAT 0
#define VLAN_TYPE_BRIDGE 1

#define GATEWAY_MODE 0
#define BRIDGE_MODE 1
#define WISP_MODE 2
#define SOURCE_TAG_MODE (1 << 2)

#define DEFAULT_NAT_LAN_VID 9
#define DEFAULT_NAT_WAN_VID 8

#define DEFAULT_ETH_WAN_PORT_MASK 0x1
#define DEF_MSSID_NUM 4


static const char *portDisplayName[] =
{
	"port1", "port2", "port3", "port4", "port5",
	"wlan1", "wlan1-va1", "wlan1-va2", "wlan1-va3", "wlan1-va4", "wlan1-vxd",
	"wlan2", "wlan2-va1", "wlan2-va2", "wlan2-va3", "wlan2-va4", "wlan2-vxd"
};

struct nameMapping
{
	char display[32];
	char ifname[16];
};
static struct nameMapping vlanNameMapping[15] =
{
#if defined(CONFIG_KL_LANWANPORT)
	{"Port1","eth4"},//page-lan1
	{"Port2","eth3"},//page-lan2
	{"Port3","eth2"},//page-lan3
	{"Port4","eth0"},//page-lan4
	{"Port5","eth1"},//page-wan
#else
	{"Port1","eth0"},
	{"Port2","eth2"},
	{"Port3","eth3"},
	{"Port4","eth4"},
	{"Port5","eth1"},
#endif	
#if defined (FOR_DUAL_BAND)	
	{"5G Wireless","wlan0"},
	{"Multiple AP1","wlan0-va0"},
	{"Multiple AP2","wlan0-va1"},
	{"Multiple AP3","wlan0-va2"},
	{"Multiple AP4","wlan0-va3"},
	{"2.4G Wireless","wlan1"},
	{"Multiple AP1","wlan1-va0"},
	{"Multiple AP2","wlan1-va1"},
	{"Multiple AP3","wlan1-va2"},
	{"Multiple AP4","wlan1-va3"},
#else
	{"Wireless","wlan0"},
	{"Multiple AP1","wlan0-va0"},
	{"Multiple AP2","wlan0-va1"},
	{"Multiple AP3","wlan0-va2"},
	{"Multiple AP4","wlan0-va3"},
#endif
};

#define APMIB_GET(A, B, C)	 \
		{if(!apmib_get(A, B)) { strcpy(errBuf, (C)); goto setErr; }}
#define APMIB_SET(A, B, C)	  \
		{if(!apmib_set(A, B)) { strcpy(errBuf, (C)); goto setErr; }}


static inline int iw_get_ext(int                  skfd,           /* Socket to the kernel */
           char *               ifname,         /* Device name */
           int                  request,        /* WE ID */
           struct iwreq *       pwrq)           /* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

int getWlStaNum( char *interface, int *num )
{
#ifndef NO_ACTION
	int skfd=0;
	unsigned short staNum;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
	/* Get wireless name */
	if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
	{
	/* If no wireless name : no wireless extensions */
		close( skfd );
		return -1;
	}
	wrq.u.data.pointer = (caddr_t)&staNum;
	wrq.u.data.length = sizeof(staNum);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSTANUM, &wrq) < 0)
	{
		close( skfd );
		return -1;
	}
	*num  = (int)staNum;

	close( skfd );
#else
	*num = 0 ;
#endif

	return 0;
}
static int getWanPortMask(void)
{
		int opMode = 0;
	
		apmib_get(MIB_OP_MODE, (void *)&opMode);
	
		if(opMode == GATEWAY_MODE)
			return DEFAULT_ETH_WAN_PORT_MASK;
		else if(opMode == BRIDGE_MODE)
			return 0;
		else
			return DEFAULT_ETH_WAN_PORT_MASK;
}
static int setDefaultPVid(void)
{
	int port_idx=0, port_num=0, vlan_idx=0, entry_num=0, opmode=0;
	int default_vid_find=0, wan_mask=0, wan_idx=0, hw_nat_lan_vid=0;
	char pVidArray[MAX_VLAN_PORT_NUM * 2];
	VLAN_CONFIG_T entry;

	apmib_get(MIB_OP_MODE, (void *)&opmode);
	port_num = sizeof(portDisplayName)/sizeof(char *);
	apmib_get(MIB_VLAN_TBL_NUM, (void *)&entry_num);
	printf("VLAN_TBL_NUM =%d\n",entry_num);
	memset((void *)pVidArray, 0, MAX_VLAN_PORT_NUM * 2);
	memset((void *)&entry, 0, sizeof(VLAN_CONFIG_T));

	apmib_get(MIB_VLAN_HW_NAT_LAN_VID, (void *)&hw_nat_lan_vid);

	wan_mask = getWanPortMask();
	for(wan_idx=0; wan_idx<port_num; wan_idx++)
		if(1<<wan_idx == wan_mask) break;

	//LAN/WLAN port.
	for(port_idx=0; port_idx<port_num; port_idx++)
	{
		if(1<<port_idx == wan_mask)
			continue;

		default_vid_find = 0;

		if(opmode == GATEWAY_MODE)
		{
			//As long as the vlan entry has this lan port, no matter tagged/untagged.
			for(vlan_idx=1; vlan_idx<=entry_num; vlan_idx++)
			{
				*(char *)&entry = (char)vlan_idx;
				apmib_get(MIB_VLAN_TBL, (void *)&entry);

				if(!(entry.MemberPortMask & (1<<port_idx)))
					continue;

				default_vid_find = entry.VlanId;
			}
		}
		else
		{
			//Search vlan group which contains this port untagged.
			for(vlan_idx=1; vlan_idx<=entry_num; vlan_idx++)
			{
				*(char *)&entry = (char)vlan_idx;
				apmib_get(MIB_VLAN_TBL, (void *)&entry);

				if(!(entry.MemberPortMask & (1<<port_idx)))
					continue;

				if(!(entry.TaggedPortMask & (1<<port_idx)))
				{
					default_vid_find = entry.VlanId;
						break;
				}
			}

			//Then search vlan group which contains this port tagged.
			if(default_vid_find == 0)
			{
				for(vlan_idx=1; vlan_idx<=entry_num; vlan_idx++)
				{
					*(char *)&entry = (char)vlan_idx;
					apmib_get(MIB_VLAN_TBL, (void *)&entry);

					if(!(entry.MemberPortMask & (1<<port_idx)))
						continue;

					default_vid_find = entry.VlanId;
						break;
				}
			}
		}

		if(default_vid_find)
			*((short *)pVidArray + port_idx) = default_vid_find;
		else
		{
			if(port_idx>=0 && port_idx<=4)
				*((short *)pVidArray + port_idx) = DEFAULT_NAT_LAN_VID;
			else
				*((short *)pVidArray + port_idx) = DEFAULT_NAT_LAN_VID;
		}
	}
	//WAN port.
	if(wan_mask != 0)
	{	
		default_vid_find = 0;

		for(vlan_idx=1; vlan_idx<=entry_num; vlan_idx++)
		{
			*(char *)&entry = (char)vlan_idx;
			apmib_get(MIB_VLAN_TBL, (void *)&entry);

			//Untagged bridge-wan.
			if(entry.VlanType == VLAN_TYPE_BRIDGE &&
				(entry.MemberPortMask & wan_mask) &&
				!(entry.TaggedPortMask & wan_mask))
			{
				default_vid_find = entry.VlanId;
				break;
			}
		}

		if(default_vid_find == 0)
		{
			for(vlan_idx=1; vlan_idx<=entry_num; vlan_idx++)
			{
				*(char *)&entry = (char)vlan_idx;
				apmib_get(MIB_VLAN_TBL, (void *)&entry);
				//Untagged nat group.
				if(entry.VlanType == VLAN_TYPE_NAT &&
					(entry.MemberPortMask & wan_mask) &&
					!(entry.TaggedPortMask & wan_mask))
				{
					default_vid_find = entry.VlanId;
					break;
				}
			}
		}

		if(default_vid_find)
			*((short *)pVidArray + wan_idx) = default_vid_find;
		else
			*((short *)pVidArray + wan_idx) = DEFAULT_NAT_WAN_VID;
	}
		
	apmib_set(MIB_VLAN_PVID_ARRAY, (void *)pVidArray);
	
	return 0;
}	

static struct nameMapping* findNameMapping(const char *display)
{
	int i;
	for(i = 0; i < MAX_IFACE_VLAN_CONFIG;i++)
	{
		if(strcmp(display,vlanNameMapping[i].display) == 0)
			return &vlanNameMapping[i];
	}
	return NULL;
}

/**
* @note setVlanConfig  Set Vlan Config
*
* @param setting Json Data
<pre>
{
	"addEffect":	"0"
	"vlanEnabled":	""
	"vlanIface1":	""
	"enable1":	""
	"vlanTag1":	""
	"vlanCfg1":	""
	"vlanId1":	""
	"vlanPriority1":	""
	"vlanForward1":	""
}
setting parameter description
addEffect:	enable vlan function	 off/on
vlanEnabled:	enable vlan off/on
vlanIface1:	vlan interface port
enable1:
vlanTag1:	vlan 1 tag
vlanCfg1:	vlan 1 configuration 
vlanId1:	vlan 1 ID
vlanPriority1:	vlan 1 priority
vlanForward1:	vlan 1 forward
</pre>
* @return Return Json Data
<pre>
{
    "success":	true
    "error":	null
    "lan_ip":	"192.168.0.1"
    "wtime":	"70"
    "reserv":	"reserv"
}
</pre>
* @author	rancho
* @date		2017-11-8
*/


int setVlanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
		VLAN_CONFIG_T new_entry, entry;
		char *submitUrl=NULL, *strTmp=NULL;
		int vlan_enabled=0, vlan_enabled_last=0, idx=0, vlan_id=0, priority=0, entry_num=0, opmode=0;
		int i,j,port_idx=0, port_num=0, port_flag=0, port_member_mask=0, port_tagged_mask=0, wan_mask=0;
		int hw_nat_flag=0, hw_nat_lan_vid=0; 
		char strBuf[50], errBuf[100];
		char pVidArray[MAX_VLAN_PORT_NUM * 2];
		char tmpBuf[100];

		int	vlan_onoff;
		int pid;
		APMIB_GET(MIB_OP_MODE, (void *)&opmode, "Get operation mode error!");
		
		strTmp= websGetVar(data, T("vlanEnabled"), T(""));
		
			
	    
		if(opmode!= 0)
		{	
			vlan_enabled =0;
			APMIB_GET(MIB_VLAN_ENABLED, (void *)&vlan_enabled_last, "Get VLAN enable error!");
			APMIB_SET(MIB_VLAN_ENABLED, (void *)&vlan_enabled, "Set VLAN enable error!");		
			
			goto ApmibUpdate;
		}
		if(strTmp[0])
		{
			vlan_enabled =atoi(strTmp);
			APMIB_GET(MIB_VLAN_ENABLED, (void *)&vlan_enabled_last, "Get VLAN enable error!");
		        APMIB_SET(MIB_VLAN_ENABLED, (void *)&vlan_enabled, "Set VLAN enable error!");		
		}
		printf("set apmib_enabled ok!\n");	
		if(!vlan_enabled)
		{
			goto ApmibUpdate;
		}
		APMIB_GET(MIB_VLAN_TBL_NUM, (void *)&entry_num, "Get VLAN table entry number error!");
		if(1 == entry_num)
		{
			goto SetPVid;
		}
		APMIB_SET(MIB_VLAN_DELALL, (void *)&new_entry, "Delete all table error!");
		if(vlan_enabled)
		{	
		 #if defined(CONFIG_BOARD_04339)			
			new_entry.MemberPortMask = 0x11;
		#elif defined(CONFIG_BOARD_04347)||defined(CONFIG_BOARD_04348)
			new_entry.MemberPortMask = 0x11;
		#elif defined(CONFIG_BOARD_04325)
			new_entry.MemberPortMask = 0x10;
		#else
			new_entry.MemberPortMask = 0x3;
		#endif
			
			new_entry.TaggedPortMask=0;
			new_entry.VlanId =2;
			new_entry.VlanType=VLAN_TYPE_BRIDGE;
			new_entry.VlanPriority=0;
			APMIB_SET(MIB_VLAN_ADD, (void *)&new_entry, "Add VLAN table entry error!");
	
	
			#if 0
			new_entry.MemberPortMask = 0x1FFFE;
			//new_entry.TaggedPortMask = 0x1FFFE;
			//new_entry.MemberPortMask = 0x1FFFD;
			new_entry.TaggedPortMask=0;
			new_entry.VlanId =1;
			new_entry.VlanType=VLAN_TYPE_NAT;
			new_entry.VlanPriority=0;
			hw_nat_lan_vid = new_entry.VlanId;	
			APMIB_SET(MIB_VLAN_HW_NAT_LAN_VID, (void *)&hw_nat_lan_vid, "Set hw nat lan vid error!");
			APMIB_SET(MIB_VLAN_ADD, (void *)&new_entry, "Add VLAN table entry error!");
			printf("leave  set default vlan value \n");
			#endif
		}
	
	SetPVid:
		setDefaultPVid();
	ApmibUpdate:
        #ifdef CONFIG_RTL_8021Q_VLAN_SUPPORT_SRC_TAG
		opmode |= SOURCE_TAG_MODE;
	#endif
		APMIB_SET(MIB_VLAN_OPMODE, (void *)&opmode, "Set VLAN OPMODE error!");

	apmib_update_web(CURRENT_SETTING);
	
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		run_init_script("all");
		exit(1);
	}
	websSetCfgResponse(mosq, tp, "30", "reserv");
	
	__FUNC_OUT__
	return 0;
	setErr:
	ERR_MSG(errBuf);
	return -1;	
}

/**
* @note	  getVlanConfig  Get Vlan Config
* 
* @param NULL
* @return Return Json Data
<pre>
{
	"vlanEnable":	""
	"maxWebVlanNum":	""
	"hwVlanSupport":	"0"
	"vlanBridgeFeature":	"1"
	"wlanBand2G5GSelect":	"2"
	"wlan0Disabled":	"0"
	"mssid0Disable":	"0"
	"wlan1Disabled":	"1"
	"mssid1Disable":	"1"	
	"vlanSetting0":		"0|none|LAN|0|0|0|0|0|0"
}
return parameter description
vlanEnable:	
maxWebVlanNum:	
hwVlanSupport:	
vlanBridgeFeature:	
wlanBand2G5GSelect:	
wlan0Disabled:	
mssid0Disable:	
wlan1Disabled:	
mssid1Disable:	
</pre>
* @author	rancho
* @date	2017-11-8
*/



int getVlanConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char* output;
	cJSON *root;
	
	VLAN_CONFIG_T entry;
	
	int vlan_onoff,opmode=-1;
	
	char Buf[32]={0},strTmp[32], entryName[32];
	
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	int forwarding_rule;
#endif

	__FUNC_IN__ ;
	root=cJSON_CreateObject();

	apmib_get(MIB_VLAN_ENABLED, (void *)&vlan_onoff);
	sprintf(Buf,"%d",vlan_onoff);
	cJSON_AddStringToObject(root, "vlanEnabled", Buf);
	output =cJSON_Print(root);
	websGetCfgResponse(mosq, tp, output);
	free(output);
	cJSON_Delete(root);

	__FUNC_OUT__ ;
	return 0;
}



int setVlan8021Q_Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
	VLAN_CONFIG_T entry,new_entry;
	char *strTmp,*addEffect,*strTmp0;
	int   vlan_num=0,vlan_num_temp, i,j,flag=0, vlan_onoff;
	struct nameMapping *mapping;
	char tmpBuf[100],tmpBuf0[100],errBuf[100];;
	int  tmp0,tmp1,wan_idx,opmode,hw_nat_lan_vid,idx=0;
	int pid,port_member_mask_NAT=0,tagged_member_list=0,untagged_member_list=0;
	int tag_member_mask_NAT=0,tag_member_mask_Bridge=0;
	int wan_mask,port_num,a[20][3]={{0,0,0},};
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	port_num = sizeof(portDisplayName)/sizeof(char *);
	wan_mask = getWanPortMask();
	for(wan_idx=0; wan_idx<port_num; wan_idx++)
		if(1<<wan_idx == wan_mask) break;

	addEffect = websGetVar(data, T("addEffect"), T("0"));
	strTmp= websGetVar(data, T("vlanEnabled"), T(""));
	vlan_onoff = atoi(strTmp);
	if(atoi(addEffect))
	{
		apmib_set(MIB_VLAN_ENABLED, (void *)&vlan_onoff);
		goto ApmibUpdate;
	}
	else
	{
		apmib_set(MIB_VLAN_DELALL, (void *)&entry);
		apmib_set(MIB_VLAN_ENABLED, (void *)&vlan_onoff);
		if(opmode == GATEWAY_MODE)
		{
			#ifdef CONFIG_RTL_HW_NAPT
			hw_nat_lan_vid = DEFAULT_NAT_LAN_VID;
			APMIB_SET(MIB_VLAN_HW_NAT_LAN_VID, (void *)&hw_nat_lan_vid, "Set hw nat lan vid error!");
			#endif
		}

		memset(&entry, '\0', sizeof(entry));
		for(i=1; i<=port_num ; i++)
		{
			

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			memset(tmpBuf0,0x00, sizeof(tmpBuf0));
			
			sprintf(tmpBuf,"Enable_%d",i);
			strTmp = websGetVar(data, T(tmpBuf), T(""));
			tmp0=atoi(strTmp);
			if(0==tmp0) continue;
			else idx++;
			sprintf(tmpBuf0,"vlan_forward_%d",i);
                                       strTmp0 = websGetVar(data, T(tmpBuf0), T(""));
                                       tmp1=atoi(strTmp0);

			if((1==tmp0) && (1==tmp1))
			{
				port_member_mask_NAT |=0x1<<(i-1);
				a[i-1][0]=1;
				
			}
			if((1==tmp0) && (2==tmp1))
			{
				a[i-1][0]=2;
			}
			
			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_tag_%d",i);
			strTmp = websGetVar(data, T(tmpBuf), T(""));
			tmp0=atoi(strTmp);
			if(1==tmp0)
			{	
				//entry.tagged = atoi(strTmp);
				a[i-1][1]=1;
			}
			else  a[i-1][1]=0;
			
			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_id_%d",i);
			strTmp = websGetVar(data, T(tmpBuf), T(""));
			//tmp0=atoi(strTmp);
			if(strTmp[0])
			{
				tmp1 = atoi(strTmp);
				a[i-1][2]=tmp1;
				if(i==(wan_idx+1))
				{
				   entry.VlanId= tmp1;
				}
			}		
		}
		if(idx==0) goto SetPVid;
		memset(tmpBuf,0x00, sizeof(tmpBuf));
		sprintf(tmpBuf,"vlan_tag_%d",wan_idx+1);
		strTmp = websGetVar(data, T(tmpBuf), T(""));
		tmp0=atoi(strTmp);
		if(1==tmp0)
		{
			entry.TaggedPortMask=port_member_mask_NAT;
                          }
		else
		{
			entry.TaggedPortMask=0;
		}
		if(port_member_mask_NAT)
                          {	entry.MemberPortMask=port_member_mask_NAT;
			entry.VlanType=VLAN_TYPE_NAT;
			#ifdef CONFIG_RTL_HW_NAPT
			hw_nat_lan_vid = entry.VlanId;	
			APMIB_SET(MIB_VLAN_HW_NAT_LAN_VID, (void *)&hw_nat_lan_vid, "Set hw nat lan vid error!");
			#endif		
			apmib_set(MIB_VLAN_ADD, (void *)&entry);
			printf("entry Id: %d  entry.membermask :%d \n",entry.VlanId,entry.MemberPortMask);
		}
		
		memset(&entry, '\0', sizeof(entry));
		memset(&new_entry, '\0', sizeof(entry));
		untagged_member_list=0;

		for(i=0; i<port_num; i++)
		{  
		     if((2==a[i][0])&&(1==a[i][1]))
                               {  tagged_member_list =0;
                                  tagged_member_list |=0x1<<i;
		        for(j=0;j<port_num;j++)
		        {
			if((i!=j) && (2==a[i][0])&&(1==a[i][1]))
			{
			    if(a[i][2]==a[j][2])
			    {
                                               tagged_member_list |= 0x1<<j;
			         a[j][1]=-1;
			    }
			}

		        }
			entry.VlanType=VLAN_TYPE_BRIDGE;
			entry.VlanId=a[i][2];
			if(opmode == GATEWAY_MODE)
			{ tagged_member_list |= 1<<wan_idx; }
			entry.MemberPortMask = tagged_member_list; 
			entry.TaggedPortMask = tagged_member_list;
			a[i][1]=-1;
			apmib_set(MIB_VLAN_ADD, (void *)&entry);
			memset(&entry, '\0', sizeof(entry));
                               }
		     if((2==a[i][0])&&(0==a[i][1]))
	                  {
                                   untagged_member_list |=0x1<<i;
		         if(!flag) { new_entry.VlanId=a[i][2]; flag=1;}
                               }
                          }
		if(untagged_member_list)
		{
			new_entry.VlanType=VLAN_TYPE_BRIDGE;
			//entry.VlanId=a[i][2];
			if(opmode == GATEWAY_MODE)
			{  untagged_member_list |= 1<<wan_idx; }
			new_entry.MemberPortMask = untagged_member_list; 
			new_entry.TaggedPortMask = 0;
			apmib_set(MIB_VLAN_ADD, (void *)&new_entry);	
                          }

	}

	apmib_get(MIB_VLAN_TBL_NUM,(void *)&vlan_num_temp);
	
SetPVid:
	setDefaultPVid();
ApmibUpdate:
	#ifdef CONFIG_RTL_8021Q_VLAN_SUPPORT_SRC_TAG
	opmode |= SOURCE_TAG_MODE;
	#endif
	APMIB_SET(MIB_VLAN_OPMODE, (void *)&opmode, "Set VLAN OPMODE error!");
	
	apmib_update_web(CURRENT_SETTING);

ApmibNoUpdate:	
	pid=fork();
	if(0 == pid)
	{
		sleep(1);
		run_init_script("all");
		exit(1);
	}
	websSetCfgResponse(mosq, tp, "30", "reserv");
	
	__FUNC_OUT__
	return 0;
setErr:
	ERR_MSG(errBuf);
	return -1;	
}

int getVlan8021Q_Config(struct mosquitto *mosq, cJSON* data, char *tp)
{
  char* output;
  cJSON *root;
  int entryNum,port_num,add,pVid,wan_mask,wan_idx,tmp_flag,len,idx,flg;
  char pVidArray[MAX_VLAN_PORT_NUM * 2], strBuf[200], strBuf1[20], strBuf2[200];	
	VLAN_CONFIG_T entry;
	
	char ad[4096],responseStr[4096];
             int  VlanType,VlanId,VlanPriority,port_mask,port_member_mask,port_tagged_mask,hw_nat_lan_vid;
	int i,j, tag,maxWebVlanNum;
	int vlan_enabled,opmode=-1;
	int wlan_disabled=0,ssid0_disabled=0,ssid1_disabled=0;
	char Buf[32]={0},strTmp[32], entryName[32];
	char entryBuf[MAX_MSG_BUFFER_SIZE]={0};
	char wlan_if[32]={0}, wlan_vap0_if[32]={0}, wlan_vap1_if[32]={0};

#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	int forwarding_rule;
#endif

	__FUNC_IN__ 

	//root=cJSON_CreateObject();
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	port_num=sizeof(portDisplayName)/sizeof(char *);
	memset(responseStr,0,sizeof(responseStr));
	apmib_get(MIB_VLAN_ENABLED, (void *)&vlan_enabled);
	sprintf(Buf,"%d",vlan_enabled);
	memset((void *)pVidArray, 0, MAX_VLAN_PORT_NUM * 2);
	apmib_get(MIB_VLAN_PVID_ARRAY, (void *)pVidArray);
	apmib_get(MIB_VLAN_HW_NAT_LAN_VID, (void *)&hw_nat_lan_vid);
	
	wan_mask = getWanPortMask();
	for(wan_idx=0; wan_idx<port_num; wan_idx++)
		if(1<<wan_idx == wan_mask) break;

	
	
	snprintf(responseStr, (sizeof(responseStr) - len), \
          "[{\"vlanEnabled\":\"%d\",\"opMode\":\"%d\",\"portNum\":\"%d\",\"wanPortId\":\"%d\",\"maxvlannum\":\"%d\",\"default_nat_lan_vid\":\"%d\",\"default_nat_wan_vid\":\"%d\"}\n", \
		     vlan_enabled, opmode, port_num, wan_idx+1,MAX_VLAN_CONFIG_NUM,DEFAULT_NAT_LAN_VID,DEFAULT_NAT_WAN_VID);
	
	
	len = strlen(responseStr);
	
	apmib_get(MIB_VLAN_TBL_NUM, (void *)&entryNum);
	if(entryNum==0)
	{
		snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
		len = strlen(responseStr);
		printf("len:%d,responseStr:%s\n",len,responseStr);
		websGetCfgResponse(mosq,tp,responseStr);
		return 0;
	}
            for(j=1;j<=port_num;j++)
            { 
	 flg=0;
	 for (i=1; i<=entryNum; i++)
              {
		*((char *)&entry) = (char)i;
		sprintf(ad,"%s",responseStr);
		
		if ( !apmib_get(MIB_VLAN_TBL, (void *)&entry))
			return -1;
		
		
		port_member_mask=entry.MemberPortMask;
		port_tagged_mask=entry.TaggedPortMask;
		memset((void *)strBuf1, 0, 20);
		
		if(opmode == GATEWAY_MODE)
		{
			if(entry.VlanType == VLAN_TYPE_NAT)
			{	
			    strcpy(strBuf1, "NAT");
			}
			else if(entry.VlanType == VLAN_TYPE_BRIDGE)
				strcpy(strBuf1, "Bridge");
			else
				strcpy(strBuf1, "Unknown");
		}
		else if(opmode == BRIDGE_MODE)
		{
			strcpy(strBuf1, "Bridge");
		}
		if((opmode == GATEWAY_MODE) && (entry.VlanType == VLAN_TYPE_BRIDGE) && (j==(wan_idx+1))) 
                          { flg=1; break;}
		if(port_member_mask & (0x1<<(j-1)))
		{
		    flg=1;
		    if(port_tagged_mask) tag=1;
		    else tag =0;
		    snprintf((responseStr + len), (sizeof(responseStr) - len),\
			      ",{\"vlan_id_%d\":\"%d\",\"vlan_forward_%d\":\"%s\",\"vlan_tag_%d\":\"%d\",\"Enable_%d\":\"1\"}\n",\
			      j,entry.VlanId,j, strBuf1,j,tag,j);
		    len = strlen(responseStr);
		}
                }
	             if(!flg)  snprintf((responseStr + len), (sizeof(responseStr) - len),\
			      ",{\"Enable_%d\":\"0\"}\n",j);
	             len = strlen(responseStr);
		
	}
	
	snprintf((responseStr + len), (sizeof(responseStr) - len),"]");
	len = strlen(responseStr);
	
	websGetCfgResponse(mosq,tp,responseStr);
			
	__FUNC_OUT__ 
	return 0;
}

int getOtherConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{	
	
	char *output;
	cJSON *root=cJSON_CreateObject();
	int val,idx, num, port_num;
	char strBuf[50], devName[10];
	
	
	cJSON_AddNumberToObject(root,"wlan_mssid_num",DEF_MSSID_NUM);
	#if defined(CONFIG_POCKET_ROUTER_SUPPORT) || defined(CONFIG_RTL_ULINKER)
		cJSON_AddNumberToObject(root, "isPocketRouter", 1 );
	#else
		cJSON_AddNumberToObject(root, "isPocketRouter", 0 );
	#endif

	#if defined(CONFIG_RTL_92D_SUPPORT)
		cJSON_AddNumberToObject(root, "wlan_support_92D", 1);
	#else
		cJSON_AddNumberToObject(root, "wlan_support_92D", 0);
	#endif
	apmib_get(MIB_WLAN_BAND2G5G_SELECT,(void *)&val);
             cJSON_AddNumberToObject(root, "wlanBand2G5GSelect", val);
	for (idx=0; idx<2; idx++)
	{
		sprintf(devName, "wlan%d", idx);
		sprintf(strBuf,"wlanValid[%d]",idx);
		if (getWlStaNum(devName, &num) < 0)		
			cJSON_AddNumberToObject(root, strBuf, 0);
		else
			cJSON_AddNumberToObject(root, strBuf, 1);
	}

	
	port_num = sizeof(portDisplayName)/sizeof(char *);

	for(idx=0; idx<port_num; idx++)
	{
		sprintf(strBuf, "portDisplayName[%d]", idx+1);
		cJSON_AddStringToObject(root, strBuf, portDisplayName[idx]);	
	}
	
	#ifdef CONFIG_RTL_HW_NAPT
	cJSON_AddNumberToObject(root, "isHwNatEnabled", 1);
	#else
	cJSON_AddNumberToObject(root, "isHwNatEnabled", 0);
	#endif
	
             
	output=cJSON_Print(root);
    	websGetCfgResponse(mosq,tp,output);
	free(output);
             cJSON_Delete(root);
	
 return 0;
}

int module_init()
{
	cste_hook_register("setVlanConfig",setVlanConfig);
	cste_hook_register("getVlanConfig",getVlanConfig);
	cste_hook_register("setVlan8021Q_Config",setVlan8021Q_Config);
	cste_hook_register("getVlan8021Q_Config",getVlan8021Q_Config);
	cste_hook_register("getOtherConfig",getOtherConfig);
	return 0;  
}

