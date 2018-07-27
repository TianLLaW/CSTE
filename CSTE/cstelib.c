#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>  
#include <pthread.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include<sys/wait.h>

#include <linux/wireless.h>
#include <net/route.h>
#include <dirent.h>
#include <setjmp.h>
#include <sys/select.h>

#include "cstelib.h"
#ifdef CONFIG_APP_TR069
#include <stdarg.h>
#endif

char *WAN_IF;
char *BRIDGE_IF;
char *ELAN_IF;
char *ELAN2_IF;
char *ELAN3_IF;
char *ELAN4_IF;
char *PPPOE_IF;
char WLAN_IF[20];
int wlan_num;
#ifdef MBSSID
int vwlan_num=0;
int mssid_idx=0;
#endif
int last_wantype=-1;


tag_mqtt_func_list *first_cste_hook = NULL;

char * safe_strdup(const char *s) {
	char * retval = NULL;
	if (!s) {

		exit(1);
	}
	retval = strdup(s);
	if (!retval) {
		exit(1);
	}
	return (retval);
}


/*CSTE hook list 初始化*/
void hook_list_init(void)
{
    first_cste_hook = NULL;
}

/*CSTE hook list 添加节点*/
tag_mqtt_func_list *cste_hook_register(char *name, int(*func)())
{
    tag_mqtt_func_list         *curhook, *prevhook;
    prevhook = NULL;
    curhook = first_cste_hook;

    while (curhook != NULL) {
        prevhook = curhook;
        curhook = curhook->next;
    }
    
    curhook = malloc(sizeof(tag_mqtt_func_list));
    memset(curhook, 0, sizeof(tag_mqtt_func_list));
    curhook->name = safe_strdup(name);
    curhook->func = func;
	
    if (prevhook == NULL) 
    {
        first_cste_hook = curhook;
    } 
    else 
    {
        prevhook->next = curhook;
    }

    return curhook;
    
}

int Cal_file_md5(const char *file_path, char *md5_str)
{
	char cmd[256] = { 0 };

	sprintf(cmd, "md5sum %s | awk '{print $1}' > /tmp/md5_sum", file_path);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	f_read("/tmp/md5_sum", md5_str, 0, 32);

	return 0;
}


/*=========================================================================*/
/*  函数名称: CsteSystem                                                   */
/*  函数功能: 系统调用system的替代                                         */
/*  输  入  : char* 命令行语句                                             */
/*            int   命令打印标志，0：不打印，其它：打印                    */
/*  输  出  : int   0:执行成功，其它：错误                                 */
/*  创  建  : CaryStudio / 2014-8-22                                       */
/*=========================================================================*/
int CsteSystem(char *command, int printFlag)
{
	int pid = 0, status = 0;

    if( !command )
    {
        printf("CsteSystem: Null Command, Error!");
        return -1;
    }

	pid = fork();
  	if ( pid == -1 )
  	{
		return -1;
	}

  	if ( pid == 0 )
  	{
        char *argv[4];
    	argv[0] = "sh";
    	argv[1] = "-c";
    	argv[2] = command;
    	argv[3] = 0;
    	if (printFlag)
    	{
	        printf("[system]: %s\r\n", command);
        }
    	execv("/bin/sh", argv);
    	exit(127);
	}

  	/* wait for child process return */
  	do
  	{
	  	if ( waitpid(pid, &status, 0) == -1 )
    	{
	    	if ( errno != EINTR )
    		{
            	return -1;
      	    }
	    }
    	else
    	{
	    	return status;
		}
	} while ( 1 );

	return status;
}

/*=========================================================================*/
/*  函数名称: websGetVar                                                   */
/*  函数功能: 获取页面下发的参数，若取不到则设置默认值                     */
/*  输  入  : cJSON *  页面下发参数集合                                    */
/*            char_t *   参数名称                                          */
/*            char_t *   默认值                                            */
/*  输  出  : 参数值                                                       */
/*  创  建  : CaryStudio / 2014-8-22                                       */
/*=========================================================================*/
char_t *websGetVar(cJSON *object, char_t *var, char_t *defaultGetValue)
{
	cJSON	*sp;

    assert(var && *var);
 
	if ((sp = cJSON_GetObjectItem(object, var)) != NULL) {
		if (sp->valuestring) 
		{
			return sp->valuestring;
		}
		else if (sp->type==cJSON_False)
		{
			return "0";
		}
		else if (sp->type==cJSON_True)
		{
			return "1";
		}
		else if (sp->type==cJSON_Number)
		{
			static char_t tmp[16] = { 0 };
			sprintf(tmp, "%d", sp->valueint);
			return tmp;
		}		
		else if (!sp->valuestring) 
		{
			return defaultGetValue;
		}
		else 
		{
			return "";
		}
	}
	return defaultGetValue;
}

/*=========================================================================*/
/*  函数名称: getCfgArray                                                  */
/*  函数功能: 从flash读配置参数                                            */
/*  输  入  : cJSON * 用于组装配置参数的json对象                           */
/*            int   默认值设置标志，0：默认返回0，其它：默认返回空         */
/*  输  出  : int   0:执行成功，其它：错误                                 */
/*  创  建  : CaryStudio / 2014-8-25                                       */
/*=========================================================================*/
int getCfgArrayInt(cJSON *root, int argc, char_t **argv, int **argvid)
{
    int i;
	int tmpint=0;
    char buff[1024]={0};
    for(i = 0;i < argc; i++){
		apmib_get(argvid[i],  (void *)&tmpint);
		sprintf(buff,"%d",tmpint);
		cJSON_AddStringToObject(root,argv[i],buff);
    }

    return 0;
}
int getCfgArrayStr(cJSON *root, int argc, char_t **argv, int **argvid)
{
    int i;
    char tmpStr[500];
    
    for(i = 0;i < argc; i++){
        apmib_get(argvid[i],  (void *)tmpStr);
        cJSON_AddStringToObject(root,argv[i],tmpStr);
    }

    return 0;
}

void get_Create_Time(char * tmpbuf){
	char *p,buf[64]={0};

	FILE *fp = popen("date +\"%Y-%m-%d %I:%M:%S %p\"", "r");
	if(!fp) return;
    
    while(fgets(buf, sizeof(buf), fp) != NULL){
        if(p=strstr(buf, "\n"))
            p[0]='\0';
    }
    pclose(fp);
	
  	strcpy(tmpbuf,buf);
	return ;
}

#if defined(CONFIG_APP_EASYCWMP)
void apmib_get_bool(int id,char * tmpbuf){
	int enabled=0;
	apmib_get(id,(void *)&enabled);
	if(enabled){
		strcpy(tmpbuf,"TRUE");
	}else{
		strcpy(tmpbuf,"FALSE");
	}
	return;
}

int isIPValid(char *str)
{
	char *p=NULL,buf[64]={0};
	int flag = 0;
	strcpy(buf,str);
	strtok(buf,".");
	while(p =strtok(NULL,".")){
		flag++;
	}
	if(flag > 2)
		return 1;
	else
		return 0;
}

void getCurrentTime(char *tmpbuf)
{
	char *p,buf[64]={0};

	FILE *fp = popen("date", "r");
	if(!fp) return;
    
    while(fgets(buf, sizeof(buf), fp) != NULL){
        if(p=strstr(buf, "\n"))
            p[0]='\0';
    }
    pclose(fp);
	
  	strcpy(tmpbuf,buf);
	return ;
}

void getMaxstanum(char *tmpbuf)
{
	char *p,buf[64]={0};

	FILE *fp = popen("iwpriv wlan0 get_mib stanum | cut -d ' ' -f12", "r");
	if(!fp) return;
    
    while(fgets(buf, sizeof(buf), fp) != NULL){
        if(p=strstr(buf, "\n"))
            p[0]='\0';
    }
    pclose(fp);
	
  	strcpy(tmpbuf,buf);
	return ;
}

void getCurrentCPU(char *cpubuf)
{
	char *p=NULL, buf[128]={0};
	int cpu;
	
	FILE *fp = popen("top -n 1 | grep \"CPU:\" | grep -v \"grep\" | awk '{print $2+$4}'", "r");
	if(!fp) return;
    
	while(fgets(buf, sizeof(buf), fp) != NULL){
	    if(p=strstr(buf, "\n"))
	        p[0]='\0';
	}
	pclose(fp);

	//计算总CPU 值
	cpu=atoi(buf);
	sprintf(cpubuf,"%d%%",cpu);
	return ;
}

int getAcsNameMac(char *ifname, char *acsName)
{
	struct ifreq ifr;
	char *ptr;
	int skfd;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//error(E_L, E_LOG, T("getIfMac: open socket error"));
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		close(skfd);
		//error(E_L, E_LOG, T("getIfMac: ioctl SIOCGIFHWADDR error for %s"), ifname);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(acsName, "%02X%02X%02X%02X%02X%02X",(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
		(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	close(skfd);
	return 0;
}

int getDefaultAcsName(char *acsName)
{
	if (-1 == getAcsNameMac("br0", acsName)) {
		strcpy(acsName, "000000000000");
	}
	
	return 0;
}

int addBooleanToArray(cJSON *root,int argc, char_t **argv, int **argvid)
{
	int i;
	int tmpInt;
	cJSON *p;
	for(i = 0;i < argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argv[i]);
		apmib_get(argvid[i], (void *)&tmpInt);
		if(argvid[i] == MIB_WLAN_HIDDEN_SSID)
		{
			if(tmpInt == 1)
				cJSON_AddStringToObject(p,"value","FALSE");
			else
				cJSON_AddStringToObject(p,"value","TRUE");

		}
		else{
			if(tmpInt == 1)
				cJSON_AddStringToObject(p,"value","TRUE");
			else
				cJSON_AddStringToObject(p,"value","FALSE");
		}
	}
	return 0;
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

int addObjectToArray(cJSON *root,int argc, char_t **argv, int **argvid)
{
	int i;
	char tmpStr[500];
	cJSON *p;
	for(i = 0;i < argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argv[i]);
		apmib_get(argvid[i], (void *)tmpStr);
		cJSON_AddStringToObject(p,"value",tmpStr);
	}
	
	return 0;
}

int addObjectIntToArray(cJSON *root,int argc, char **argv, int **argvid)
{
	int i;
	char tmpStr[500];
	int tmpint=0;
	cJSON *p;
	for(i = 0;i < argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argv[i]);
		apmib_get(argvid[i], (void *)&tmpint);
		sprintf(tmpStr,"%d",tmpint);
		cJSON_AddStringToObject(p,"value",tmpStr);
	}
	
	return 0;
}

int addObjectIPToArray(cJSON *root,int argc, char_t **argv, int **argvid)
{
	int i;
	char buf[32], tmpStr[32];
	cJSON *p;
	for(i = 0;i < argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argv[i]);
		apmib_get(argvid[i], (void *)buf);
		sprintf(tmpStr,"%s",inet_ntoa(*((struct in_addr *)buf)));
		cJSON_AddStringToObject(p,"value",tmpStr);
	}
	
	return 0;
}

int addPandValueToArray(cJSON *root, int argc, char **argp, char **argv)
{
	int i;
	cJSON *p;
	for(i = 0;i<argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argp[i]);
		cJSON_AddStringToObject(p,"value",argv[i]);
	}
	
	return 0;
}

int addIntValueToArray(cJSON * root,int argc,char * * argv,int * * argvid)
{
	int i;
	char tmpStr[500];
	cJSON *p;
	for(i = 0;i<argc; i++){
		cJSON_AddItemToArray(root,p=cJSON_CreateObject());
		cJSON_AddStringToObject(p,"parameter",argv[i]);
		sprintf(tmpStr,"%d",argvid[i]);
		cJSON_AddStringToObject(p,"value",tmpStr);
	}
	return 0;
}

void ddnsStatus(int tmpBuf)
{
	int intVal, opmode;
	struct stat st;
	
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	apmib_get(MIB_DDNS_ENABLED, (void *)&intVal);
	if (intVal == 0){
		tmpBuf=0;
	}
	else {
		if (opmode == GATEWAY_MODE) {
			int isWanPhy_Link = get_wan_link_status("eth1");
			if(isWanPhy_Link < 0)
				tmpBuf=0;
			else {
				if (!stat("/var/ddns_ok", &st))
					tmpBuf=1;
				else
					tmpBuf=0;
			}
		}
		else if (opmode == WISP_MODE){
			if (!stat("/var/ddns_ok", &st))
				tmpBuf=1;
			else
				tmpBuf=0;
		}
	}
}

char *getModeEnabled(char *wlanIfname)
{
	int intEncrypt,wep;
	static char authmode[32]={0};
	SetWlan_idx(wlanIfname);
	apmib_get( MIB_WLAN_ENCRYPT, (void *)&intEncrypt);
	apmib_get(MIB_WLAN_WEP, (void *)&wep);
	switch(intEncrypt)
	{
		case ENCRYPT_DISABLED:	
			sprintf(authmode,"%s","NONE");break;
		case ENCRYPT_WEP:
			if(wep==WEP64)
				sprintf(authmode,"%s","WEP-64");
			else
				sprintf(authmode,"%s","WEP-128");
			break;
		case ENCRYPT_WPA:
			sprintf(authmode,"%s","WPA-Personal");break;
		case ENCRYPT_WPA2:
			sprintf(authmode,"%s","WPA2-Personal");break;
		case ENCRYPT_WPA2_MIXED:
			sprintf(authmode,"%s","WPA-WPA2-Personal");break;
		default:			
			sprintf(authmode,"%s","NONE");
	}
	return authmode;
}

#define	FILE_WSCD_STATUS	"/tmp/wscd_status"
void getWpsTates(char *tmpbuf){
	FILE *fp;
	int status;
	fp = fopen( FILE_WSCD_STATUS, "r");
	if(fp != NULL)
	{
		fscanf(fp,"%d",&status);
		fclose(fp);
	}
	//CSTE_DEBUG("status=[%d]\n", status);
	memset(tmpbuf, '\0', sizeof(tmpbuf));
	switch(status){
		case -1 ://NOT_USED
			sprintf(tmpbuf, "%s", "Disconnected");	break;
		case 0 ://PROTOCOL_START
			sprintf(tmpbuf, "%s", "Connecting"); break;
		case 1 ://PBC_OVERLAPPING
			sprintf(tmpbuf, "%s", "Failed");break;
		case 2 ://TIMEOUT
			sprintf(tmpbuf, "%s", "Failed");break;
		case 3 ://sucess
			sprintf(tmpbuf, "%s", "Conneceted");break;
		case 28://FAIL
		case 29:
		case 30:
		case 31:
		case 32:
		case 33:
			sprintf(tmpbuf, "%s", "Failed");break;
		default :			
			sprintf(tmpbuf, "%s", "Connecting");
	}
	return;
}
#endif

char *getSysUptime()
{
	unsigned long sec, mn, hr, day;
	struct sysinfo info;
	static char sysTime[32]={0};
	
	sysinfo(&info);
	sec = (unsigned long) info.uptime;
	day = sec / 86400;
	//day -= 10957; // day counted from 1970-2000

	sec %= 86400;
	hr = sec / 3600;
	sec %= 3600;
	mn = sec / 60;
	sec %= 60;
	sprintf(sysTime,"%d;%d;%d;%d",day,hr,mn,sec);

	return sysTime;
}

char *getPortLinkStaus()
{
	FILE *fp;
	char *p,*q,*d;
	int flag;
	char val[16]={0},long_buf[1024]={0},buf[50]={0};	
	static char port_status[64]={0};	
	memset(val,0x00,sizeof(val));
	memset(port_status,0x00,sizeof(port_status));
	CsteSystem("cat /proc/rtl865x/port_status | grep Link > /tmp/port_status", CSTE_PRINT_CMD);
	fp = fopen ( "/tmp/port_status", "r" );    
	if (!fp) return NULL;		
	while(fgets(long_buf, 512, fp)) { 
#if !defined(CONFIG_RTL_8367R_SUPPORT)		
		d = strstr(long_buf, "Port");
		if(d!=NULL) continue;
#endif		
		p = strstr(long_buf, "Link");
		q = strstr(p, "Up");
		if(p==NULL) break;		
		if(q!=NULL) flag=1;
		else flag=0;
		sprintf(val, "%d,", flag);
		strcat(port_status, val);	
	}
	fclose(fp);	
	return port_status;
}

int getCfgArrayIP(cJSON *root, int argc, char_t **argv, int **argvid)
{
    int i;
    char buf[32], tmpStr[32];
    
    for(i = 0;i < argc; i++){
        apmib_get(argvid[i],  (void *)buf);
        sprintf(tmpStr,"%s",inet_ntoa(*((struct in_addr *)buf)));
        cJSON_AddStringToObject(root,argv[i],tmpStr);
    }

    return 0;
}


/*=========================================================================*/
/*  函数名称: websSetCfgResponse                                           */
/*  函数功能: 页面设置回应函数(需根据页面需求完善)                         */
/*  输  入  : mosq     当前主题的mqtt连接句柄                              */
/*            tp       当前的主题                                          */
/*            result   处理成功/失败标志                                   */
/*            time     页面等待时间                                        */
/*            reserv   保留，可用作附加信息                                */
/*  输  出  :                                                              */
/*  创  建  : CaryStudio / 2014-8-25                                       */
/*=========================================================================*/
void websSetCfgResponse(struct mosquitto *mosq, char *tp, char *time, char *reserv)
{	
    char* output;
    cJSON *root=cJSON_CreateObject();
    char topic[256]={0};
    int mid_sent=0;
	char lan_ip[32]={0},ipaddr[18]={0};
    struct in_addr intaddr;

    cJSON_AddTrueToObject(root,"success");
    cJSON_AddNullToObject(root,"error");   

    getLanIp(lan_ip);   
    getInAddr("br0", IP_ADDR_T, ipaddr);

	if(getOperationMode()==1||getOperationMode()==2)
    	cJSON_AddStringToObject(root,"lan_ip",ipaddr);
	else
		cJSON_AddStringToObject(root,"lan_ip",lan_ip);
    cJSON_AddStringToObject(root,"wtime",time);
    cJSON_AddStringToObject(root,"reserv",reserv);

    output=cJSON_Print(root);
    sprintf(topic,"%s/R", tp);
    mosquitto_publish(mosq, &mid_sent, topic, strlen(output), output, 0, 0);
    cJSON_Delete(root);
	free(output);
}

/*=========================================================================*/
/*  函数名称: websGetCfgResponse                                           */
/*  函数功能: 页面获取参数回应函数                                         */
/*  输  入  : struct mosquitto * 当前主题的mqtt连接句柄                    */
/*            char *   当前的主题                                          */
/*            char *   返回的参数信息                                      */
/*  输  出  : 无                                                           */
/*  创  建  : CaryStudio / 2014-8-27                                       */
/*=========================================================================*/
void websGetCfgResponse(struct mosquitto *mosq, char *tp, char *msg)
{
    char topic[256]={0};
    int mid_sent = 0;
    sprintf(topic,"%s/R",tp);
	if(strlen(msg) == 0)
		mosquitto_publish(mosq, &mid_sent, topic, 0, NULL, 0, 0);
	else
    	mosquitto_publish(mosq, &mid_sent, topic, strlen(msg), msg, 0, 0);
	CSTE_DEBUG("[%s]%s\n",tp,msg);
    return;
}

/*=========================================================================*/
/*  函数名称: websErrorResponse                                            */
/*  函数功能: 后台处理出错时回给页面相应错误信息                           */
/*  输  入  : mosq     当前主题的mqtt连接句柄                              */
/*            tp       当前的主题                                          */
/*            JS_Num   language.js中对应的错误码标识                       */
/*  输  出  :                                                              */
/*  创  建  : CaryStudio / 2014-8-25                                       */
/*=========================================================================*/
void websErrorResponse(struct mosquitto *mosq, char *tp, char *JS_Num)
{
    char* output;
    cJSON *root;
    char topic[256]={0};
    int mid_sent = 0;
    
    root=cJSON_CreateObject();

    cJSON_AddFalseToObject(root,"success");
    cJSON_AddStringToObject(root,"error",JS_Num);

    output =cJSON_Print(root);

    sprintf(topic,"%s/R", tp);
    mosquitto_publish(mosq, &mid_sent, topic, strlen(output), output, 0, 0);
	CSTE_DEBUG("%s\n",output);
    cJSON_Delete(root);
	free(output);
}

int getOperationMode()
{
	static int mode;
	int opmode=0,rpt_enabled1=0,rpt_enabled2=0;
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled1);
#if defined(FOR_DUAL_BAND)	
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&rpt_enabled2);
#endif

	if(opmode==GATEWAY_MODE){
		mode=0;//router
	}else if(opmode==BRIDGE_MODE){
		if(rpt_enabled1==1
#if defined(FOR_DUAL_BAND)
		||rpt_enabled2==1
#endif
		){
			mode=2;//repeater
		}else{
			mode=1;//ap(bridge)
		}
	}else if(opmode==WISP_MODE){
		mode=3;//wisp
	}else{
		mode=0;//router
	}
	return mode;
}

int getDhcp()
{
	static int dhcp;
	apmib_get(MIB_DHCP,	(void *)&dhcp);
	if(dhcp==2) dhcp=1;
	return dhcp;
}

/*=========================================================================*/
/*  函数名称: getLanIp                                                  								 */
/*  函数功能:   获取LAN 的IP地址                			              */
/*  输  入  : 无     							 							 */
/*  输  出  :返回LAN 的IP地址                                     */
/*  创  建  : CaryStudio / 2014-9-17                                    											 */
/*=========================================================================*/
void getLanIp(char *tmpBuf)
{
	char lan_ip_buf[30];
	apmib_get(MIB_IP_ADDR,  (void *)lan_ip_buf) ;
	sprintf(tmpBuf,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
	return;
}

void getLanNetmask(char *tmpBuf)
{
	char lan_mask_buf[30];
	apmib_get(MIB_SUBNET_MASK,  (void *)lan_mask_buf) ;
	sprintf(tmpBuf,"%s",inet_ntoa(*((struct in_addr *)lan_mask_buf)) );
	return;
}


/*=========================================================================*/
/*  函数名称: getDevName                                                     */
/*  函数功能: 获取相应接口的MAC  用于dev name                                          */
/*  输  入  : char *  接口名称                                             */
/*            char *  用于保存dev name                                          */
/*  输  出  : 失败:-1 ,成功:0                                              */
/*  创  建  : CaryStudio / 2014-8-28                                       */
/*=========================================================================*/
int getDevName(char *ifname, char *devname)
{
	struct ifreq ifr;
	char *ptr;
	int skfd;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//error(E_L, E_LOG, T("getIfMac: open socket error"));
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		close(skfd);
		//error(E_L, E_LOG, T("getIfMac: ioctl SIOCGIFHWADDR error for %s"), ifname);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(devname, "%02x%02x%02x%02x%02x%02x",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	close(skfd);
	return 0;
}

/*=========================================================================*/
/*  函数名称: getLanMac                                                  								 */
/*  函数功能:   获取LAN 的MAC地址                			              */
/*  输  入  : 无     							 							 */
/*  输  出  :返回LAN 的MAC地址                                     */
/*  创  建  : CaryStudio / 2014-9-17                                    											 */
/*=========================================================================*/
char *getLanMac()
 {	
 	char ifname[20]={0};
	static char if_mac[18];
#if defined(VOIP_SUPPORT) && defined(ATA867x)
	sprintf(ifname,"%s","eth0");
#else
	sprintf(ifname,"%s","br0");
#endif
	 if (-1 == getIfMac(ifname, if_mac)) {
		 return NULL;
	 }	 
	 return if_mac;
 }

void getRealGateway(char  *sgw)
{
	char   buff[256];
	int    nl = 0 ;
	struct in_addr dest;
	struct in_addr gw;
	int    flgs, ref, use, metric;
	unsigned long int d,g,m;
	int    find_default_flag = 0;

	FILE *fp = fopen("/proc/net/route", "r");

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if (nl) {
			int ifl = 0;
			while (buff[ifl]!=' ' && buff[ifl]!='\t' && buff[ifl]!='\0')
				ifl++;
			buff[ifl]=0;    /* interface */
			if (sscanf(buff+ifl+1, "%lx%lx%X%d%d%d%lx",
						&d, &g, &flgs, &ref, &use, &metric, &m)!=7) {
				fclose(fp);
				return ;
			}

			if (flgs&0x0001) {
				dest.s_addr = d;
				gw.s_addr   = g;
				strcpy(sgw, (gw.s_addr==0 ? "" : inet_ntoa(gw)));

				if (dest.s_addr == 0) {
					find_default_flag = 1;
					break;
				}
			}
		}
		nl++;
	}
	fclose(fp);

	if (find_default_flag == 1)
		return ;
	else{
		strcpy(sgw, "");
		return ;
	}
}


/*=========================================================================*/
/*  函数名称: isMacValid                                                   */
/*  函数功能: 判断MAC的合法性                                              */
/*  输  入  : char * MAC                                                   */
/*  输  出  : int   0:非法，1：合法                                        */
/*  创  建  : CaryStudio / 2014-8-26                                       */
/*=========================================================================*/
int isMacValid(char *str)
{
	int i, len = strlen(str);
	if(len != 17)
		return 0;

	for(i=0; i<5; i++){
		if( (!isxdigit( str[i*3])) || (!isxdigit( str[i*3+1])) || (str[i*3+2] != ':') )
			return 0;
	}
	return (isxdigit(str[15]) && isxdigit(str[16])) ? 1: 0;
}


int getInAddr( char *interface,int type, char *if_addr )
{
    struct ifreq ifr;
    int skfd=0, found=0;
    struct sockaddr_in *addr;
	char ptr[18]={0};
	char tmpbuf[18]={0};
	unsigned char *buff;
	
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return 0;		
    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    	close( skfd );
		return (0);
	}
	/*
    if (type ==HW_ADDR_T) {
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(ptr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
        buff = (unsigned char *)(((struct sockaddr *)&ifr.ifr_hwaddr)->sa_data);
		sprintf(tmpbuf, "%02X:%02X:%02X:%02X:%02X:%02X",buff[0],buff[1],buff[2],buff[3],buff[4],buff[5]);
		printf("tmpbuf:%s\n",tmpbuf);
		memcpy(if_addr,tmpbuf,sizeof(tmpbuf));
		found = 1;
		}
    }*/
    if (type ==HW_ADDR_T) {
		if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
			memcpy(if_addr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
			found = 1;
		}
    }
    else if (type ==IP_ADDR_T) {
		if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {		
			strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
			found = 1;
		}
	}
    else if (type ==NET_MASK_T) {
		if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
		strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		found = 1;
		}
    }
    close( skfd );
    return found;

}

/* IOCTL system call */
static int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
    unsigned int args[4];
    struct ifreq ifr;
    int sockfd;

    args[0] = arg0;
    args[1] = arg1;
    args[2] = arg2;
    args[3] = arg3;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("fatal error socket\n");
        return -3;
    }
  
    strcpy((char*)&ifr.ifr_name, name);
    ((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

    if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr)<0)
    {
        perror("device ioctl:");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return 0;
} /* end re865xIoctl */

int get_wan_link_status(char *interface)
{
    unsigned int    ret;
    unsigned int    args[0];
    
    re865xIoctl(interface, RTL8651_IOCTL_GETWANLINKSTATUS, (unsigned int)(args), 0, (unsigned int)&ret) ;
	return ret;
}

int isDhcpClientExist()
{
	char tmpBuf[100];
	struct in_addr intaddr;
    char if_wan[32]={0};
    char buff[32]={0};
    getWanIfNameCs(if_wan);
    strcpy(buff, if_wan);
	if ( getInAddr(if_wan, IP_ADDR_T, (void *)&intaddr ) ) {
		snprintf(tmpBuf, 100, "%s/%s-%s.pid", _DHCPC_PID_PATH, _DHCPC_PROG_NAME, buff);
		if ( getPid(tmpBuf) > 0)
			return 1;
	}
	return 0;
}

int isConnectPPP()
{
	struct stat status;
	if ( stat("/etc/ppp/link", &status) < 0)
		return 0;
	return 1;
}


//用于检测所有eth口是否已有IP
int checkEthStatus(void)
{
    int ret=0;
    DHCP_T dhcp=DHCP_SERVER;
	OPMODE_T opmode=GATEWAY_MODE;
	char *wan_ip=NULL;
		
    apmib_get( MIB_OP_MODE, (void *)&opmode);
    apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
    CSTE_DEBUG("~~~ opmode=[%d] dhcp=[%d] ~~~\n", opmode, dhcp);

	if(opmode==GATEWAY_MODE){
		ret=get_wan_link_status("eth1");
		if(dhcp == DHCP_CLIENT){//dhcp
            if (!isDhcpClientExist()){
    			return 0;
            }else{
                if(ret < 0)
    				return 0;
    			else
    				return 1;
            }                
        }else if(dhcp == DHCP_DISABLED){//static
            if(ret < 0)
				return 0;
			else
				return 1;
        }else if(dhcp == PPPOE||dhcp == PPTP||dhcp == L2TP){
            if ( isConnectPPP()){
    			if(ret < 0)
    				return 0;
    			else
    				return 1;
    		}
    		else
    			return 0;
        }
	}
	else{
		if (!isDhcpClientExist()){
			return 0;
        }else{
            if(ret < 0)
				return 0;
			else
				return 1;
        } 
	}
    return 0;
}

void get_wan_connect_status(char *tmpBuf)
{
	int ret=0;
	DHCP_T dhcp=DHCP_SERVER;
	apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
	if(dhcp == DHCP_DISABLED){
		ret=get_wan_link_status("eth1");
	}else{
		ret=getCmdVal("cat /var/wanconnect");
	}
	if(ret == 1)
		sprintf(tmpBuf, "%s", "connected");
	else
		sprintf(tmpBuf, "%s", "disconnected");
	return ;
}

/*=========================================================================*/
/*  函数名称: getDns                                                  								 */
/*  函数功能:  获取DNS                   			              */
/*  输  入  : DNS索引                   							 									 */
/*  输  出  :返回指定索引的DNS                                      */
/*  创  建  : CaryStudio / 2014-9-17                                    											 */
/*=========================================================================*/
char *getDns(int dnsIdx)
{
	FILE *fp;
	char buf[80] = {0}, ns_str[11];
	static char dns[16] = {0};
	int idx = 0;
	
	fp = fopen("/etc/resolv.conf", "r");
	if (NULL == fp){
		fp = fopen("/etc/resolv.dnsmasq.conf", "r");
	}
	if (NULL == fp){
		CSTE_DEBUG("open /etc/resolv.dnsmasq.conf failed\n");
		return "0.0.0.0";
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strncmp(buf, "nameserver", 10) != 0)
			continue;
		sscanf(buf, "%s %s", ns_str, dns);
		idx++;
		if (idx == dnsIdx)
			break;
	}
	fclose(fp);

	if (idx == dnsIdx){	
		return  dns;
	}else{
		return  "0.0.0.0";
	}
}

int getWanIfNameCs(char *wanIf)
{
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	unsigned int wispWanId=0;
	struct in_addr	intaddr;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;
	int isWanPhyLink = 0;	
	if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
		return -1;
 	if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
		return -1;
	if ( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
		return -1;

	if ( dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP || dhcp == USB3G ) { /* # keith: add l2tp support. 20080515 */
		sprintf(wanIf, "%s", "ppp0");
	}
	else if (opmode == WISP_MODE){
#ifdef CONFIG_SMART_REPEATER
		sprintf(wanIf, "wlan%d-vxd",wispWanId);
#else
		sprintf(wanIf, "wlan%d",wispWanId);
#endif			
	}
	else
		sprintf(wanIf, "%s", "eth1");
	return 0;	
}

void getWanIp(char *if_addr)
{
	char if_wan[32]={0}, tmpCmd[128]={0};

    getWanIfNameCs(if_wan);

	if(!strcmp(if_wan,""))
		strcpy(if_wan,"eth1");

	sprintf(tmpCmd,"ifconfig %s | grep \"inet addr\" | awk '{print $2}' | cut -f2 -d:",if_wan);
	if(-1==getCmdStr(tmpCmd,if_addr,16))
	{
		strcpy(if_addr,"0.0.0.0");
	}	

	return ;
}

char* getWanNetmask()
{
	static char if_addr[18]={0};
	char if_wan[32]={0};
    getWanIfNameCs(if_wan);
  	if (-1 == getInAddr(if_wan,NET_MASK_T,if_addr)) {
		return "0.0.0.0";
	}	
	return if_addr;
}

char* getWanGateway()
{
	struct in_addr if_addr={0};
	char if_wan[32]={0};
    getWanIfNameCs(if_wan);
  	if (-1 == getDefaultRoute(if_wan,&if_addr)){
		return "0.0.0.0";
	}
	return inet_ntoa(if_addr);
}

char* getWanMac()
{
	static char if_addr[18]={0};
	char buff[32]={0},if_wan[32]={0};
    getWanIfNameCs(buff);
    if(!strcmp(buff, "ppp0"))
        strcpy(if_wan, "eth1");
    else
        strcpy(if_wan, buff);
  	if (-1 == getIfMac(if_wan, if_addr)) {
		return "";
	}	
	return if_addr;
}

void getWanLinktime(char *tmpBuf)
{
	int opmode=0,wispid=0,ret, dhcpMode = 0;
	apmib_get(MIB_OP_MODE,	(void *)&opmode);
	if ((opmode==0&&get_wan_link_status("eth1")==0)||\
		(opmode==2&&(getRepeaterStatus("wlan0-vxd")==1||getRepeaterStatus("wlan1-vxd")==1))){

		unsigned long sec, sec2, mn, hr, day;
		FILE *f;
		char buf[256];
		struct timeval	new;
		get_wan_connect_status(buf);
		if(strcmp(buf,"disconnected") == 0){
			strcpy(tmpBuf, "0;0;0;0");
			return;
		}
		
		gettimeofday(&new, NULL);		

		f = fopen("/tmp/wanranchocontime", "r");
		if (f == NULL ){	
			strcpy(tmpBuf, "0;0;0;0");
			return;
		}			
		
		fscanf(f, "%s", buf);		
		sec = atoi(buf);
		fclose(f);

		sec = new.tv_sec - sec;	
		sec %= 86400;
		hr = sec / 3600;
		sec %= 3600;
		mn = sec / 60;
		sec %= 60;

		sprintf(tmpBuf, "%d;%d;%d;%d", day, hr, mn, sec);
		return;
	}
	else{
		strcpy(tmpBuf, "0;0;0;0");
		return;
	}
}

int getDefaultRoute(char *interface, struct in_addr *route)
{
	char buff[1024], iface[16];
	char gate_addr[128], net_addr[128], mask_addr[128];
	int num, iflags, metric, refcnt, use, mss, window, irtt;
	FILE *fp = fopen("/proc/net/route", "r");
	char *fmt;
	int found=0;
	unsigned long addr;
	char tmpbuf[32]={0};
	if (!fp) {
       	printf("Open %s file error.\n", "/proc/net/route");
		return -1;
    }
	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";
	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr,
		     		&iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY) || strcmp(iface, interface))
	    		continue;
		sscanf(gate_addr, "%lx", &addr );
		*route = *((struct in_addr *)&addr);
		found = 1;
		break;
	}
    fclose(fp);
    return found;
}

void arplookup(char *ip, char *arp)
{
	char buf[256];
    char ip_entry[16], hw_address[18];
	FILE *fd = fopen("/proc/net/arp", "r");
	if(!fd){
		strcpy(arp, "");
		return;
	}
	strcpy(arp, "00:00:00:00:00:00");
	while(fgets(buf, 256, fd)){
	    memset(ip_entry, '\0', sizeof(ip_entry));
	    memset(hw_address, '\0', sizeof(hw_address));
		sscanf(buf, "%s %*s %*s %s %*s %*s", ip_entry, hw_address);
		if(!strcmp(ip_entry, "IP")) continue;
		if(!strcmp(ip, ip_entry)){
			strcpy(arp, hw_address);
			break;
		}
	}
	fclose(fd);
}

int apmib_update_web(int type)
{
	int ret=0, mesh_sync=0;
#if defined(SUPPORT_MESH)	
	apmib_get(MIB_MESH_SYNC_FLAG,(void *)&mesh_sync);
	if(mesh_sync==0)
	{
		mesh_sync=1;
		apmib_set(MIB_MESH_SYNC_FLAG,(void *)&mesh_sync);
		system("csteSys csnl 6 0");
	}
#endif	
	ret = apmib_update(type);

	if (ret == 0)
		return 0;

	if (type & CURRENT_SETTING) {
		save_cs_to_file();
	}
	return ret;
}
int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}
int __inline__ string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;
		key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

void convert_bin_to_str(unsigned char *bin, int len, char *out)
{
	int i;
	char tmpbuf[10];

	out[0] = '\0';

	for (i=0; i<len; i++) {
		sprintf(tmpbuf, "%02x", bin[i]);
		strcat(out, tmpbuf);
	}
}

int getFlashSize(void)
{
	char *p;
	char buf[1024]={0}, tmp[16];
	unsigned int fsize=0,tmpint,mtd_2=0,mtd_3=0;

	memset(buf,0,1024);
	memset(tmp,0,16);
	system("cat /proc/mtd > /tmp/mtdzize");
	f_read("/tmp/mtdzize", buf, 0, sizeof(buf));
	system("rm -f /tmp/mtdzize");
	if (strlen(buf) < 4){
		printf("[Debug] get data from FlashSize error!\n");
		return 0;
	}
	p=strstr(buf,"mtd0:");
	snprintf(tmp,5,"%s",(p+6));
	sscanf(tmp,"%x",&fsize);

	p=strstr(buf,"mtd1:");
	snprintf(tmp,5,"%s",(p+6));
	sscanf(tmp,"%x",&tmpint);

#if defined(CONFIG_KL_DUAL_CFG_PARTITION) && defined(CONFIG_KL_USER_DATA_PARTITION)
	p=strstr(buf,"mtd2:");
	snprintf(tmp,5,"%s",(p+6));
	sscanf(tmp,"%x",&mtd_2);

	p=strstr(buf,"mtd3:");
	snprintf(tmp,5,"%s",(p+6));
	sscanf(tmp,"%x",&mtd_3);
	
	fsize=(fsize+tmpint+mtd_2+mtd_3)/16;
#elif defined(CONFIG_KL_DUAL_CFG_PARTITION) || defined(CONFIG_KL_USER_DATA_PARTITION)
	p=strstr(buf,"mtd2:");
	snprintf(tmp,5,"%s",(p+6));
	sscanf(tmp,"%x",&mtd_2);
	fsize=(fsize+tmpint+mtd_2)/16;
#else
	fsize=(fsize+tmpint)/16;
#endif

	return fsize;
}


int getPid(char *filename)
{
	struct stat status;
	char buff[100];
	FILE *fp;

	if ( stat(filename, &status) < 0)
		return -1;
	fp = fopen(filename, "r");
	if (!fp) {
        	fprintf(stderr, "Read pid file error!\n");
		return -1;
   	}
	fgets(buff, 100, fp);
	fclose(fp);

	return (atoi(buff));
}

int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime, char *hsnm)
{
	int len=0;
	struct dhcpOfferedAddr {
        	u_int8_t chaddr[16];
        	u_int32_t yiaddr;       /* network order */
        	u_int32_t expires;      /* host order */
			char hostname[56]; /* Brad add for get hostname of client */
			char hostlen[8];
			u_int32_t isUnAvailableCurr;
	};

	struct dhcpOfferedAddr entry;
	u_int8_t empty_haddr[16]; 
   	memset(empty_haddr, 0, 16); 
	if ( *size < sizeof(entry) )
		return -1;
	entry = *((struct dhcpOfferedAddr *)*ppStart);
	*ppStart = *ppStart + sizeof(entry);
	*size = *size - sizeof(entry);

	if (entry.expires == 0)
		return 0;

	if(!memcmp(entry.chaddr, empty_haddr, 16))
		return 0;

	strcpy(ip, inet_ntoa(*((struct in_addr *)&entry.yiaddr)) );
	snprintf(mac, 20, "%02X:%02X:%02X:%02X:%02X:%02X",
			entry.chaddr[0],entry.chaddr[1],entry.chaddr[2],entry.chaddr[3],
			entry.chaddr[4], entry.chaddr[5]);
	if(entry.expires == 0xffffffff)
    	sprintf(liveTime,"%s", "MM_Always");
    else
	    snprintf(liveTime, 10, "%lu", (unsigned long)ntohl(entry.expires));

	memset(hsnm, 0, 64);
	len = atoi(entry.hostlen);
	if(len == 0)
		strcpy(hsnm, "Unknown");
	else
	{
		strncpy(hsnm, entry.hostname, len);
		hsnm[len] = '\0';
	}
	
	return 1;
}
/*
string : 分割字符串
idx    : 返回第几个分割段
buff   : 返回分割结果
*/
int checkVar(char *string, int idx, char *buff)
{
    char src_str[128]={0};
	char tmp[128]={0};
    char *delimit=";";
    char *p=NULL;
	memset(tmp, '\0', sizeof(tmp));
    if(strlen(string)>0&&strlen(string)<128){
        strncpy(src_str, string, strlen(string));   
        p=strtok(src_str, delimit);

        if(idx==1){
            sprintf(tmp, "%s", p);
        }else{
            int num=0;
            while(p=strtok(NULL, delimit)){
                if(num==0&&idx==2){
                    sprintf(tmp, "%s", p);
                    break;
                }else if(num==1&&idx==3){
                    sprintf(tmp, "%s", p);
                    break;
                }else if(num==2&&idx==4){
					sprintf(tmp, "%s", p);
                    break;
				}
                num++;
            }
        }
    }else{
		strcpy(tmp, "");
	}
	memset(buff, '\0', strlen(buff));
	strncpy(buff, tmp, strlen(tmp));
    return 0;
}


void killSomeDaemon(void)
{
	CsteSystem("killall -9 sleep 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 routed 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 pppoe 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 pppd 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 pptp 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 dnrd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 ntpclient 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 miniigd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 lld2d 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 l2tpd 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 udhcpc 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall -9 udhcpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 reload 2> /dev/null", CSTE_PRINT_CMD);		
	CsteSystem("killall -9 iapp 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 wscd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 mini_upnpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 iwcontrol 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 auth 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 disc_server 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 igmpproxy 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("echo 1,0 > /proc/br_mCastFastFwd", CSTE_PRINT_CMD);
	CsteSystem("killall -9 syslogd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 klogd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 ppp_inet 2> /dev/null", CSTE_PRINT_CMD);
#ifdef WLAN_HS2_CONFIG	
	CsteSystem("killall -9 hs2 2> /dev/null", CSTE_PRINT_CMD);
#endif
#ifdef CONFIG_IPV6
	CsteSystem("killall -9 dhcp6c 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 dhcp6s 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 radvd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 ecmh 2> /dev/null", CSTE_PRINT_CMD);
	//kill mldproxy
	CsteSystem("killall -9 mldproxy 2> /dev/null", CSTE_PRINT_CMD);
#endif
#ifdef CONFIG_SNMP
	CsteSystem("killall -9 snmpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("rm -f /var/run/snmpd.pid", CSTE_PRINT_CMD);
#endif
}

void run_init_script(char *arg)
{
	int pid=0;
	int i,op_mode=0;
	char tmpBuf[MAX_MSG_BUFFER_SIZE]={0};

#ifdef RTK_USB3G
	CsteSystem("killall -9 mnet 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 hub-ctrl 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall -9 usb_modeswitch 2> /dev/null", CSTE_PRINT_CMD);
    CsteSystem("killall -9 ppp_inet 2> /dev/null", CSTE_PRINT_CMD);
    CsteSystem("killall -9 pppd 2> /dev/null", CSTE_PRINT_CMD);
    CsteSystem("rm /etc/ppp/connectfile >/dev/null 2>&1", CSTE_PRINT_CMD);
#endif /* #ifdef RTK_USB3G */

#if 0// defined(CONFIG_RTL_ULINKER)
	extern int kill_ppp(void);
	int wan_mode, op_mode;

	apmib_get(MIB_OP_MODE,(void *)&op_mode);
	apmib_get(MIB_WAN_DHCP,(void *)&wan_mode);
	if(wan_mode == PPPOE && op_mode == GATEWAY_MODE)
		kill_ppp();
	
	stop_dhcpc();
	stop_dhcpd();
	clean_auto_dhcp_flag();
	disable_bridge_dhcp_filter();
#endif

	snprintf(tmpBuf, MAX_MSG_BUFFER_SIZE, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmpBuf);
	if ( pid > 0)
		kill(pid, SIGUSR1);
		
	usleep(1000);
	
	if ( pid > 0){
		CsteSystem("killall -9 udhcpd 2> /dev/null", CSTE_PRINT_CMD);
		CsteSystem("rm -f /var/run/udhcpd.pid 2> /dev/null", CSTE_PRINT_CMD);
	}

	//Patch: kill some daemons to free some RAM in order to call "init.sh gw all" more quickly
	//which need more tests especially for 8196c 2m/16m
	killSomeDaemon();	
	CsteSystem("killsh.sh", CSTE_PRINT_CMD);	// kill all running script	

	pid = fork();
	if (pid == 0) {
		apmib_get(MIB_OP_MODE,(void *)&op_mode);
#ifdef HOME_GATEWAY
		if(op_mode==1)
    		sprintf(tmpBuf, "%s ap %s", _CONFIG_SCRIPT_PROG, arg);
		else
    		sprintf(tmpBuf, "%s gw %s", _CONFIG_SCRIPT_PROG, arg);
#else
		sprintf(tmpBuf, "%s ap %s", _CONFIG_SCRIPT_PROG, arg);
#endif
		for(i=3; i<sysconf(_SC_OPEN_MAX); i++)
            close(i);
		sleep(1);
		CsteSystem(tmpBuf, CSTE_PRINT_CMD);
		exit(1);
	}
}
inline int
iw_get_ext(int                  skfd,           /* Socket to the kernel */
           char *               ifname,         /* Device name */
           int                  request,        /* WE ID */
           struct iwreq *       pwrq)           /* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

int getStaAssociatedNum(char *ifname)
{
	int num=0;
#ifndef NO_ACTION
    int skfd=0;
    unsigned short staNum;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
      	close( skfd );
      	return -1;
	}
    wrq.u.data.pointer = (caddr_t)&staNum;
    wrq.u.data.length = sizeof(staNum);

    if (iw_get_ext(skfd, ifname, SIOCGIWRTLSTANUM, &wrq) < 0){
    	close( skfd );
		return -1;
	}
    num  = (int)staNum;
    close( skfd );
#else
    num = 0 ;
#endif
    return num;
}

void getWanConnectMode(char *buff)
{
	DHCP_T dhcp;
	apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
	if ( dhcp == DHCP_CLIENT) 
		sprintf(buff,"%s","DHCP");
	else if(dhcp == DHCP_DISABLED)
		sprintf(buff,"%s","STATIC");
	else if(dhcp ==  PPPOE)
		sprintf(buff,"%s","PPPOE");
	else if(dhcp ==  L2TP)
		sprintf(buff,"%s","L2TP");
	else if(dhcp ==  PPTP)
		sprintf(buff,"%s","PPTP");
	else if(dhcp ==  USB3G)
		sprintf(buff,"%s","3G");
	return;
}

int SetWlan_idx(char * wlan_iface_name)
{
	int idx;
	
		idx = atoi(&wlan_iface_name[4]);
		if (idx >= NUM_WLAN_INTERFACE) {
				printf("invalid wlan interface index number!\n");
				return 0;
		}
		wlan_idx = idx;
		vwlan_idx = 0;
	
#ifdef MBSSID		
		
		if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
				wlan_iface_name[6] == 'v' && wlan_iface_name[7] == 'a') {
				idx = atoi(&wlan_iface_name[8]);
				if (idx >= NUM_VWLAN_INTERFACE) {
					printf("invalid virtual wlan interface index number!\n");
					return 0;
				}
				
				vwlan_idx = idx+1;
				idx = atoi(&wlan_iface_name[4]);
				wlan_idx = idx;
		}
#endif		

#ifdef UNIVERSAL_REPEATER
				if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
						!memcmp(&wlan_iface_name[6], "vxd", 3)) {
					vwlan_idx = NUM_VWLAN_INTERFACE;
					idx = atoi(&wlan_iface_name[4]);
					wlan_idx = idx;
				}
#endif				

//printf("\r\n wlan_iface_name=[%s],wlan_idx=[%u],vwlan_idx=[%u],__[%s-%u]\r\n",wlan_iface_name,wlan_idx,vwlan_idx,__FILE__,__LINE__);

	return 1;		
}

static int get_dev_fields(int type, char *bp, struct user_net_device_stats *pStats)
{
    switch (type) {
    case 3:
	sscanf(bp,
	"%Lu %Lu %lu %lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu %lu",
	       &pStats->rx_bytes,
	       &pStats->rx_packets,
	       &pStats->rx_errors,
	       &pStats->rx_dropped,
	       &pStats->rx_fifo_errors,
	       &pStats->rx_frame_errors,
	       &pStats->rx_compressed,
	       &pStats->rx_multicast,

	       &pStats->tx_bytes,
	       &pStats->tx_packets,
	       &pStats->tx_errors,
	       &pStats->tx_dropped,
	       &pStats->tx_fifo_errors,
	       &pStats->collisions,
	       &pStats->tx_carrier_errors,
	       &pStats->tx_compressed);
	break;

    case 2:
	sscanf(bp, "%Lu %Lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu",
	       &pStats->rx_bytes,
	       &pStats->rx_packets,
	       &pStats->rx_errors,
	       &pStats->rx_dropped,
	       &pStats->rx_fifo_errors,
	       &pStats->rx_frame_errors,

	       &pStats->tx_bytes,
	       &pStats->tx_packets,
	       &pStats->tx_errors,
	       &pStats->tx_dropped,
	       &pStats->tx_fifo_errors,
	       &pStats->collisions,
	       &pStats->tx_carrier_errors);
	pStats->rx_multicast = 0;
	break;

    case 1:
	sscanf(bp, "%Lu %lu %lu %lu %lu %Lu %lu %lu %lu %lu %lu",
	       &pStats->rx_packets,
	       &pStats->rx_errors,
	       &pStats->rx_dropped,
	       &pStats->rx_fifo_errors,
	       &pStats->rx_frame_errors,

	       &pStats->tx_packets,
	       &pStats->tx_errors,
	       &pStats->tx_dropped,
	       &pStats->tx_fifo_errors,
	       &pStats->collisions,
	       &pStats->tx_carrier_errors);
	pStats->rx_bytes = 0;
	pStats->tx_bytes = 0;
	pStats->rx_multicast = 0;
	break;
    }
    return 0;
}

static char *get_name(char *name, char *p)
{
    while (isspace(*p))
	p++;
    while (*p) {
	if (isspace(*p))
	    break;
	if (*p == ':') {	/* could be an alias */
	    char *dot = p, *dotname = name;
	    *name++ = *p++;
	    while (isdigit(*p))
		*name++ = *p++;
	    if (*p != ':') {	/* it wasn't, backup */
		p = dot;
		name = dotname;
	    }
	    if (*p == '\0')
		return NULL;
	    p++;
	    break;
	}
	*name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

int getStats(char *interface, struct user_net_device_stats *pStats)
{
 	FILE *fh;
  	char buf[512];
	int type;

	fh = fopen(_PATH_PROCNET_DEV, "r");
	if (!fh) {
		printf("Warning: cannot open %s\n",_PATH_PROCNET_DEV);
		return -1;
	}
	fgets(buf, sizeof buf, fh);	/* eat line */
	fgets(buf, sizeof buf, fh);

  	if (strstr(buf, "compressed"))
		type = 3;
	else if (strstr(buf, "bytes"))
		type = 2;
	else
		type = 1;

	while (fgets(buf, sizeof buf, fh)) {
		char *s, name[40];
		s = get_name(name, buf);
		if ( strcmp(interface, name))
			continue;
		get_dev_fields(type, s, pStats);
		fclose(fh);
		return 0;
    	}
	fclose(fh);
	return -1;
}

int getWlBssInfo(char *interface, bss_info *pInfo)
{
#ifndef NO_ACTION
    int skfd=0;
    struct iwreq wrq;
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
      	close( skfd );
        return -1;
    }
	
    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(bss_info);
	
    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0){
    	close( skfd );
		return -1;
	}
	
    close( skfd );
#else
    memset(pInfo, 0, sizeof(bss_info)); 
#endif
	return 0;
}

int getWlJoinResult(char *interface, unsigned char *res)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
      	/* If no wireless name : no wireless extensions */
      	close( skfd );
        return -1;
	}
    wrq.u.data.pointer = (caddr_t)res;
    wrq.u.data.length = 1;

    if (iw_get_ext(skfd, interface, SIOCGIWRTLJOINREQSTATUS, &wrq) < 0){
    	close( skfd );
		return -1;
	}
    close( skfd );

    return 0;
}

int getRepeaterStatus(char *ifname)
{
	static int status=0;
	bss_info bss;
	getWlBssInfo(ifname, &bss);
	switch (bss.state) {
		case STATE_DISABLED:		
		case STATE_IDLE:			
		case STATE_STARTED:
			status=0;
			break;
		case STATE_CONNECTED:
			status=1;
			break;
		case STATE_WAITFORKEY:
		case STATE_SCANNING:
			status=-1;
			break;
		default:
			status=-1;
	}
	return status;
}

int getRptStaAndRssi(char *ifname)
{
	bss_info bss;
	getWlBssInfo(ifname, &bss);
	return bss.rssi;
}

char *getRptAuthMode(char *wlanIfname)
{	
	int intEncrypt;
	static char authmode[16]={0};
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intEncrypt);
	switch(intEncrypt)
	{
		case ENCRYPT_DISABLED:
			sprintf(authmode,"%s","NONE");break;
		case ENCRYPT_WEP:
			sprintf(authmode,"%s","WEP");break;
		case ENCRYPT_WPA:
			sprintf(authmode,"%s","WPAPSK");break;
		case ENCRYPT_WPA2:
			sprintf(authmode,"%s","WPA2PSK");break;
		case ENCRYPT_WPA2_MIXED:
			sprintf(authmode,"%s","WPAPSKWPA2PSK");break;
		default:			
			sprintf(authmode,"%s","NONE");
	}
	return authmode;
}

char *getRptEncrypType(char *wlanIfname)
{	
	int intEncrypt,wepType,wpaType,wpa2Type;
	static char encryptype[8]={0};
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intEncrypt);	
	switch(intEncrypt)
	{
		case ENCRYPT_DISABLED:
			sprintf(encryptype,"%s","NONE");break;
		case ENCRYPT_WEP:	
			apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&wepType); 
			if(wepType==AUTH_OPEN)
				sprintf(encryptype,"%s","OPEN");
			else
				sprintf(encryptype,"%s","SHARED");
			break;
		case ENCRYPT_WPA:
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaType);
			if(wpaType==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else
				sprintf(encryptype,"%s","AES");
			break;
		case ENCRYPT_WPA2:
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Type);
			if(wpa2Type==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else if(wpa2Type==WPA_CIPHER_AES)
				sprintf(encryptype,"%s","AES");
			else
				sprintf(encryptype,"%s","TKIPAES");
			break;
		case ENCRYPT_WPA2_MIXED:
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaType);
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Type);
			if(wpaType==WPA_CIPHER_TKIP&&wpa2Type==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else if(wpaType==WPA_CIPHER_AES&&wpa2Type==WPA_CIPHER_AES)
				sprintf(encryptype,"%s","AES");
			else
				sprintf(encryptype,"%s","TKIPAES");
			break;
		default:			
			sprintf(encryptype,"%s","NONE");
	}
	return encryptype;
}

char *getAuthMode(char *wlanIfname)
{	
	int intEncrypt,wepType;
	static char authmode[16]={0};
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intEncrypt);
	switch(intEncrypt)
	{
		case ENCRYPT_DISABLED:
			sprintf(authmode,"%s","NONE");break;
		case ENCRYPT_WEP:
			apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&wepType); 
			if(wepType==AUTH_OPEN)
				sprintf(authmode,"%s","OPEN");
			else
				sprintf(authmode,"%s","SHARED");
			break;
		case ENCRYPT_WPA:
			sprintf(authmode,"%s","WPAPSK");break;
		case ENCRYPT_WPA2:
			sprintf(authmode,"%s","WPA2PSK");break;
		case ENCRYPT_WPA2_MIXED:
			sprintf(authmode,"%s","WPAPSKWPA2PSK");break;
		default:			
			sprintf(authmode,"%s","NONE");
	}
	return authmode;
}

char *getEncrypType(char *wlanIfname)
{	
	int intEncrypt,wepType,wpaType,wpa2Type;
	static char encryptype[8]={0};
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intEncrypt);	
	switch(intEncrypt)
	{
		case ENCRYPT_DISABLED:
			sprintf(encryptype,"%s","NONE");break;
		case ENCRYPT_WEP:	
			apmib_get(MIB_WLAN_WEP, (void *)&wepType); 
			if(wepType==WEP64)
				sprintf(encryptype,"%s","WEP64");
			else
				sprintf(encryptype,"%s","WEP128");
			break;
		case ENCRYPT_WPA:
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaType);
			if(wpaType==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else
				sprintf(encryptype,"%s","AES");
			break;
		case ENCRYPT_WPA2:
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Type);
			if(wpa2Type==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else if(wpa2Type==WPA_CIPHER_AES)
				sprintf(encryptype,"%s","AES");
			else
				sprintf(encryptype,"%s","TKIPAES");
			break;
		case ENCRYPT_WPA2_MIXED:
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaType);
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Type);
			if(wpaType==WPA_CIPHER_TKIP&&wpa2Type==WPA_CIPHER_TKIP)
				sprintf(encryptype,"%s","TKIP");
			else if(wpaType==WPA_CIPHER_AES&&wpa2Type==WPA_CIPHER_AES)
				sprintf(encryptype,"%s","AES");
			else
				sprintf(encryptype,"%s","TKIPAES");
			break;
		default:			
			sprintf(encryptype,"%s","NONE");
	}
	return encryptype;
}

char *getWirelessKey(char *wlanIfname)
{
	int intEncrypt, wep=0, keytype=0, defkeyid=0, keyid=0;
	static char encrypkey[100]={0};
	char tmpBuf[32]={0},wepkey[27]={0};
	SetWlan_idx(wlanIfname);
	
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&intEncrypt);	
	switch(intEncrypt)
	{
		case ENCRYPT_WPA:
		case ENCRYPT_WPA2:
		case ENCRYPT_WPA2_MIXED:
			apmib_get(MIB_WLAN_WPA_PSK, (void *)encrypkey);
			break;
		case ENCRYPT_WEP:
			apmib_get(MIB_WLAN_WEP, (void *)&wep);
			apmib_get(MIB_WLAN_WEP_KEY_TYPE,  (void *)&keytype);
			apmib_get(MIB_WLAN_WEP_DEFAULT_KEY,  (void *)&defkeyid);
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			if(wep == WEP64){
				if(defkeyid==0)
					keyid = MIB_WLAN_WEP64_KEY1;
				else if(defkeyid==1)
					keyid = MIB_WLAN_WEP64_KEY2;
				else if(defkeyid==2)
					keyid = MIB_WLAN_WEP64_KEY3;
				else if(defkeyid==3)
					keyid = MIB_WLAN_WEP64_KEY4;

				apmib_get(keyid, (void *)tmpBuf);
				if(keytype==1){//Hex
					convert_bin_to_str(tmpBuf, 5, wepkey);
				}else{
					snprintf(wepkey, 6, "%s", tmpBuf);
				}
			}else if(wep == WEP128){
				if(defkeyid==0)
					keyid = MIB_WLAN_WEP128_KEY1;
				else if(defkeyid==1)
					keyid = MIB_WLAN_WEP128_KEY2;
				else if(defkeyid==2)
					keyid = MIB_WLAN_WEP128_KEY3;
				else if(defkeyid==3)
					keyid = MIB_WLAN_WEP128_KEY4;

				apmib_get(keyid, (void *)tmpBuf);
				if(keytype==1){//Hex
					convert_bin_to_str(tmpBuf, 13, wepkey);
				}else{
					snprintf(wepkey, 14, "%s", tmpBuf);
				}
			}
			sprintf(encrypkey,"%s",wepkey);
			break;
		default:
			strcpy(encrypkey,"");
	}
	return encrypkey;
}

int getWirelessBand(char *wlanIfname)
{	
	int intVal;
	static int band;
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_BAND, (void *)&intVal);
	switch(intVal)
	{
		case BAND_11B:
			band=1;
			break;
		case BAND_11G:			
			band=4;
			break;
		case BAND_11BG:			
			band=0;
			break;
		case BAND_11A:
			band=2;
			break;
		case BAND_11N:
			band=6;
			break;
		case 11:
			band=9;
			break;
		case BAND_5G_11AN:
			band=8;
			break;
		case BAND_5G_11AC:
		case BAND_5G_11AAC:
		case BAND_5G_11NAC:
		case BAND_5G_11ANAC:
			band=14;
			break;
		case 75:
			band=75;
			break;
		default:
			band=9;
	}
	return band;
}

int getWirelessChannel(char *wlanIfname)
{
	FILE *fp;
	char openFileStr[64]={0};
	char inUseProfileStr[8]={0};
	static int channel=0;
	
	sprintf(openFileStr,"iwpriv %s get_mib channel | grep get_mib | cut -d':' -f2",wlanIfname);

	fp = popen(openFileStr, "r");
	if(fp && (NULL != fgets(inUseProfileStr, sizeof(inUseProfileStr),fp)))
	{
		channel=atoi(inUseProfileStr);
		pclose(fp);
	}
	return channel;
}

int *getWirelessOnOff(char *wlanIfname)
{
	static int wifioff;
	SetWlan_idx(wlanIfname);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wifioff);
	return wifioff;
}

int write_line_to_file(char *filename, int mode, char *line_data)
{
    unsigned char tmpbuf[512];
    int fh=0;

    if(mode == 1) {/* write line datato file */
        fh = open(filename, O_RDWR|O_CREAT|O_TRUNC);
    }else if(mode == 2){/*append line data to file*/
        fh = open(filename, O_RDWR|O_APPEND);
    }

    if (fh < 0) {
        fprintf(stderr, "Create %s error!\n", filename);
        return 0;
    }

    sprintf(tmpbuf, "%s", line_data);
    write(fh, tmpbuf, strlen(tmpbuf));
    close(fh);
    return 1;
}

int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo )
{
    int skfd=0;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
        /* If no wireless name : no wireless extensions */
        close( skfd );
        return -1;
	}
    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1);
    memset(pInfo, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSTAINFO, &wrq) < 0){
    	close( skfd );
		return -1;
	}
    close( skfd );
    return 0;
}

int getWlSiteSurveyRequest(char *interface, int *pStatus)
{
#ifndef NO_ACTION
    int skfd=0;
    struct iwreq wrq;
    unsigned char result;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1){
		return -1;
	}

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
		/* If no wireless name : no wireless extensions */
		close( skfd );
		return -1;
	}
    wrq.u.data.pointer = (caddr_t)&result;
    wrq.u.data.length = sizeof(result);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0){
		close( skfd );
		return -1;
	}
    close( skfd );
    if ( result == 0xff )
    	*pStatus = -1;
    else
		*pStatus = (int) result;
#else
	*pStatus = -1;
#endif
#ifdef SUPPORT_MESH 
	// ==== modified by GANTOE for site survey 2008/12/26 ==== 
	return (int)*(char*)wrq.u.data.pointer; 
#else
	return 0;
#endif
}

int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus )
{
#ifndef NO_ACTION
    int skfd=0;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
      close( skfd );
        return -1;
	}
    wrq.u.data.pointer = (caddr_t)pStatus;

    if ( pStatus->number == 0 )
    	wrq.u.data.length = sizeof(SS_STATUS_T);
    else
        wrq.u.data.length = sizeof(pStatus->number);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0){
    	close( skfd );
	return -1;
	}
    close( skfd );
#else
	return -1 ;
#endif

    return 0;
}

void update_wps_configured(int reset_flag)
{
	int is_configured, encrypt1, encrypt2, auth, disabled, iVal, format, shared_type;
	char ssid1[100];
	unsigned char tmpbuf[MAX_MSG_BUFFER_SIZE]={0};	
	if (wps_config_info.caller_id == CALLED_FROM_WLANHANDLER) {
		//apmib_get(MIB_WLAN_SSID, (void *)ssid1);
		//apmib_get(MIB_WLAN_MODE, (void *)&iVal);
		strncpy(ssid1, wps_config_info_tmp.ssid, strlen(wps_config_info_tmp.ssid));
		iVal = wps_config_info_tmp.wlan_mode;
		if (strcmp(ssid1, (char *)wps_config_info.ssid) || (iVal != wps_config_info.wlan_mode)) {
			apmib_set(MIB_WLAN_WSC_SSID, (void *)ssid1);
			goto configuration_changed;
		}

		return;
	}
	else if (wps_config_info.caller_id == CALLED_FROM_ADVANCEHANDLER) {
		//apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&shared_type);
		//apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
		shared_type = wps_config_info_tmp.shared_type;
		encrypt1 = wps_config_info_tmp.auth;
		if (encrypt1 == ENCRYPT_WEP && 
			shared_type != wps_config_info.shared_type) {
			if (shared_type == AUTH_OPEN || shared_type == AUTH_BOTH) {
				if (wps_config_info.shared_type == AUTH_SHARED) {
					auth = WSC_AUTH_OPEN;
					apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
					goto configuration_changed;
				}
			}
			else {
				if (wps_config_info.shared_type == AUTH_OPEN ||
					wps_config_info.shared_type == AUTH_BOTH) {
					auth = WSC_AUTH_SHARED;
					apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
					goto configuration_changed;
				}
			}
		}

		return;
	}

	//apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
	encrypt1 = wps_config_info_tmp.auth;
	if (encrypt1 == ENCRYPT_DISABLED) {
		auth = WSC_AUTH_OPEN;
		encrypt2 = WSC_ENCRYPT_NONE;
	}
	else if (encrypt1 == ENCRYPT_WEP) {
		//apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&shared_type);
		shared_type = wps_config_info_tmp.shared_type;
		if (shared_type == AUTH_OPEN || shared_type == AUTH_BOTH)
			auth = WSC_AUTH_OPEN;
		else
			auth = WSC_AUTH_SHARED;
		encrypt2 = WSC_ENCRYPT_WEP;		
	}
	else if (encrypt1 == ENCRYPT_WPA) {
		auth = WSC_AUTH_WPAPSK;
		//apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		encrypt1 = wps_config_info_tmp.wpa_enc;
		if (encrypt1 == WPA_CIPHER_TKIP)
			encrypt2 = WSC_ENCRYPT_TKIP;		
		else if (encrypt1 == WPA_CIPHER_AES)
			encrypt2 = WSC_ENCRYPT_AES;		
		else 
			encrypt2 = WSC_ENCRYPT_TKIPAES;				
	}
	else if (encrypt1 == ENCRYPT_WPA2) {
		auth = WSC_AUTH_WPA2PSK;
		//apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encrypt1);
		encrypt1 = wps_config_info_tmp.wpa2_enc;
		if (encrypt1 == WPA_CIPHER_TKIP)
			encrypt2 = WSC_ENCRYPT_TKIP;		
		else if (encrypt1 == WPA_CIPHER_AES)
			encrypt2 = WSC_ENCRYPT_AES;		
		else 
			encrypt2 = WSC_ENCRYPT_TKIPAES;				
	}
	else {
		auth = WSC_AUTH_WPA2PSKMIXED;
		encrypt2 = WSC_ENCRYPT_TKIPAES;			

// When mixed mode, if no WPA2-AES, try to use WPA-AES or WPA2-TKIP
		//apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		//apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&iVal);
		encrypt1 = wps_config_info_tmp.wpa_enc;
		iVal = wps_config_info_tmp.wpa2_enc;
		if (!(iVal &	WPA_CIPHER_AES)) {
			if (encrypt1 &	WPA_CIPHER_AES) {			
				//auth = WSC_AUTH_WPAPSK;
				encrypt2 = WSC_ENCRYPT_AES;
			}
			else{
				encrypt2 = WSC_ENCRYPT_TKIP;
			}
		}
//-------------------------------------------- david+2008-01-03
		if(encrypt1==WPA_CIPHER_AES && iVal ==WPA_CIPHER_AES){
			encrypt2 = WSC_ENCRYPT_AES;	
			CSTE_DEBUG("\n");
		}
		// for correct wsc_auth wsc_encry value when security is mixed mode
	}
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&encrypt2);

	//apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
	encrypt1 = wps_config_info_tmp.auth;
	if (encrypt1 == ENCRYPT_WPA || encrypt1 == ENCRYPT_WPA2 || encrypt1 == ENCRYPT_WPA2_MIXED) {
		//apmib_get(MIB_WLAN_WPA_AUTH, (void *)&format);
		format = wps_config_info_tmp.shared_type;
		if (format & 2) { // PSK
			//apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
			strncpy(tmpbuf, wps_config_info_tmp.wpaPSK, strlen(wps_config_info_tmp.wpaPSK));
			apmib_set(MIB_WLAN_WSC_PSK, (void *)tmpbuf);					
		}		
	}
	if (reset_flag) {
		reset_flag = 0;
		apmib_set(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&reset_flag);		
	}	

	if (wps_config_info.caller_id == CALLED_FROM_WEPHANDLER) {
		//apmib_get(MIB_WLAN_ENCRYPT, (void *)&auth);
		auth = wps_config_info_tmp.auth;
		if (wps_config_info.auth != auth)
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP, (void *)&encrypt2);
		encrypt2 = wps_config_info_tmp.wep_enc;
		if (wps_config_info.wep_enc != encrypt2)
			goto configuration_changed;
		
		//apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&iVal);
		iVal = wps_config_info_tmp.KeyId;
		if (wps_config_info.KeyId != iVal)
			goto configuration_changed;
		
		//apmib_get(MIB_WLAN_WEP64_KEY1, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep64Key1, strlen(wps_config_info_tmp.wep64Key1));
		if (strcmp((char *)wps_config_info.wep64Key1, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP64_KEY2, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep64Key2, strlen(wps_config_info_tmp.wep64Key2));
		if (strcmp((char *)wps_config_info.wep64Key2, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP64_KEY3, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep64Key3, strlen(wps_config_info_tmp.wep64Key3));
		if (strcmp((char *)wps_config_info.wep64Key3, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP64_KEY4, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep64Key4, strlen(wps_config_info_tmp.wep64Key4));
		if (strcmp((char *)wps_config_info.wep64Key4, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP128_KEY1, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep128Key1, strlen(wps_config_info_tmp.wep128Key1));
		if (strcmp((char *)wps_config_info.wep128Key1, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP128_KEY2, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep128Key2, strlen(wps_config_info_tmp.wep128Key2));
		if (strcmp((char *)wps_config_info.wep128Key2, (char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP128_KEY3, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep128Key3, strlen(wps_config_info_tmp.wep128Key3));
		if (strcmp((char *)wps_config_info.wep128Key3,(char *)tmpbuf))
			goto configuration_changed;

		//apmib_get(MIB_WLAN_WEP128_KEY4, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wep128Key4, strlen(wps_config_info_tmp.wep128Key4));
		if (strcmp((char *)wps_config_info.wep128Key4, (char *)tmpbuf))
			goto configuration_changed;

		return;
	}
	else if (wps_config_info.caller_id == CALLED_FROM_WPAHANDLER) {
		//apmib_get(MIB_WLAN_ENCRYPT, (void *)&auth);
		auth = wps_config_info_tmp.auth;
		if (wps_config_info.auth != auth)
			goto configuration_changed;
		
		//apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		encrypt1 = wps_config_info_tmp.wpa_enc;
		if (wps_config_info.wpa_enc != encrypt1)
			goto configuration_changed;
		
		//apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encrypt2);
		encrypt2 = wps_config_info_tmp.wpa2_enc;
		if (wps_config_info.wpa2_enc != encrypt2)
			goto configuration_changed;
		
		//apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
		strncpy(tmpbuf, wps_config_info_tmp.wpaPSK, strlen(wps_config_info_tmp.wpaPSK));
		if (strcmp((char *)wps_config_info.wpaPSK, (char *)tmpbuf))
			goto configuration_changed;

		return;
	}
	else
		return;
	
configuration_changed:	
	reset_flag = 0;
	apmib_set(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&reset_flag);
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&disabled);	
	apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
	//if (!is_configured && !disabled) { //We do not care wsc is enable for disable--20081223
	if (!is_configured) {
		is_configured = 1;
		apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
#if defined(CONFIG_RTL_92D_SUPPORT)
		if(wlan_idx==0){
			wlan_idx = 1;
			apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
			wlan_idx = 0;			
		}else if(wlan_idx == 1){
			wlan_idx = 0;
			apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
			wlan_idx = 1;			
		}
#endif
	}
}

void takeEffectWlan(char *wlan_if,int actionFlag)
{
	int op_mode=GATEWAY_MODE;
	int wan_type=DHCP_DISABLED;
    char root_if[6],br_if[128],cmd[128],wifi_if[16];
	char wifi_vap0_if[16]={0},wifi_vap1_if[16]={0};
	int mesh_enable1=0,mesh_enable2=0;
	int wlan_disabled=0,wlan_va0_disabled=0,wlan_va1_disabled=0;
	int intVal=0;

	memset(root_if, '\0', sizeof(root_if));
	memset(cmd, '\0', sizeof(cmd));
	apmib_get(MIB_OP_MODE, (void *)&op_mode);	
	apmib_get(MIB_WAN_DHCP,(void *)&wan_type);	

#ifdef SUPPORT_MESH	
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable1);
#if defined(FOR_DUAL_BAND)	
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_MESH_ENABLE,(void *)&mesh_enable2);	
#endif
#endif		
    if(strlen(wlan_if) > 5){
        memcpy(root_if, wlan_if, 5);
        sprintf(cmd,"ifconfig %s down;ifconfig %s down",wlan_if,root_if);
        CsteSystem(cmd,CSTE_PRINT_CMD);
        bzero(cmd,64);
        sprintf(cmd,"flash set_mib %s;flash set_mib %s",root_if,wlan_if);
        CsteSystem(cmd,CSTE_PRINT_CMD);
        bzero(cmd,64);
        sprintf(cmd,"ifconfig %s up;ifconfig %s up",root_if,wlan_if);
        CsteSystem(cmd,CSTE_PRINT_CMD);
    }else{
    	strcpy(root_if, wlan_if);
   		sprintf(cmd,"flash set_mib %s;ifconfig %s down;ifconfig %s up",wlan_if,wlan_if,wlan_if);
        CsteSystem(cmd,CSTE_PRINT_CMD);
    }

#if 1
	memset(wifi_if, '\0', sizeof(wifi_if));
	sprintf(wifi_if,"%s-va0",root_if);
	SetWlan_idx(wifi_if);
	apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va0_disabled);
	if(wlan_va0_disabled==0){ 
		strcpy(wifi_vap0_if,wifi_if); 
	}else{
		strcpy(wifi_vap0_if,""); 
	}
	
	memset(wifi_if, '\0', sizeof(wifi_if));
	sprintf(wifi_if,"%s-va1",root_if);
	SetWlan_idx(wifi_if);
	apmib_get(MIB_WLAN_WLAN_DISABLED,(void *)&wlan_va1_disabled);
	if(wlan_va1_disabled==0){ 
		strcpy(wifi_vap1_if,wifi_if); 
	}else{
		strcpy(wifi_vap1_if,""); 
	}
#endif	

	memset(br_if, '\0', sizeof(br_if));
	memset(cmd, '\0', sizeof(cmd));    
    if(actionFlag){
#if defined(FOR_DUAL_BAND)
		int wispWanId=0;
		if (op_mode == WISP_MODE){
			if(!apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId)) wispWanId = 0;
			if(wispWanId == 1){
				if(!strcmp(root_if,"wlan0"))
					strcpy(br_if,"wlan0 wlan0-va0 wlan0-va1 wlan0-vxd");
				else
					strcpy(br_if,"wlan1 wlan1-va0 wlan1-va1");
			}else{
				if(!strcmp(root_if,"wlan0"))
					strcpy(br_if,"wlan0 wlan0-va0 wlan0-va1");
				else
					strcpy(br_if,"wlan1 wlan1-va0 wlan1-va1 wlan1-vxd");
			}
			//printf("=br_if=[%s]=\n",br_if);
		}else{
			if(mesh_enable1==1||mesh_enable2==1){
				//sprintf(br_if,"%s %s-va0 %s-va1",root_if,root_if,root_if);
				sprintf(br_if,"wlan0 wlan1 %s %s",wifi_vap0_if,wifi_vap1_if);
			}else{
				//sprintf(br_if,"%s %s-va0 %s-va1 %s-vxd",root_if,root_if,root_if,root_if);
				sprintf(br_if,"%s %s %s %s-vxd",root_if,wifi_vap0_if,wifi_vap1_if,root_if);
			}
			//printf("=br_if=[%s]=\n",br_if);
		}	

		if(mesh_enable1==1 || mesh_enable2 == 1) strcat(br_if, " wlan-msh ");
		
		sprintf(cmd,"sysconf wlan_set %s & \n",br_if);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		sprintf(cmd,"sysconf wlanapp start wlan0 wlan1 br0 &",root_if);
		CsteSystem(cmd,CSTE_PRINT_CMD);
#else
		if (op_mode == WISP_MODE || op_mode == BRIDGE_MODE) 
			//strcpy(br_if,"wlan0 wlan0-va0 wlan0-va1 wlan0-vxd");
			sprintf(br_if,"%s %s %s %s-vxd",root_if,wifi_vap0_if,wifi_vap1_if,root_if);
		else
			//strcpy(br_if,"wlan0 wlan0-va0 wlan0-va1");
			sprintf(br_if,"%s %s %s",root_if,wifi_vap0_if,wifi_vap1_if);

 		if(mesh_enable1==1) strcat(br_if, " wlan-msh ");
 			
		sprintf(cmd,"sysconf wlan_set %s & \n",br_if);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		CsteSystem("sysconf wlanapp start wlan0 br0 &",CSTE_PRINT_CMD);
#endif
		sleep(1);
		CsteSystem("sysconf upnpd 1 1",CSTE_PRINT_CMD);
		
		sleep(1);
		if (op_mode == WISP_MODE) {		
			memset(cmd, '\0', sizeof(cmd));
			if(wan_type == DHCP_DISABLED){
				char Gateway[32],tmpBuff[32];
				apmib_get(MIB_WAN_DEFAULT_GATEWAY,  (void *)tmpBuff);
				if (!memcmp(tmpBuff, "\x0\x0\x0\x0", 4))
					memset(Gateway, 0x00, 32);
				else
					sprintf(Gateway, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));

				if(Gateway[0]){
#if defined(FOR_DUAL_BAND)
					if(wispWanId == 1){
						if(!strcmp(root_if,"wlan1")){
							CsteSystem("route del start default wlan1-vxd",CSTE_PRINT_CMD);
							sprintf(cmd, "route add -net default gw %s dev wlan1-vxd\n",Gateway);
						}
					}else{
						if(!strcmp(root_if,"wlan0")){
							CsteSystem("route del start default wlan0-vxd",CSTE_PRINT_CMD);
							sprintf(cmd, "route add -net default gw %s dev wlan0-vxd\n",Gateway);
						}
					}
#else					
					CsteSystem("route del start default wlan0-vxd",CSTE_PRINT_CMD);
					sprintf(cmd, "route add -net default gw %s dev wlan0-vxd\n",Gateway);
#endif
					CsteSystem(cmd,CSTE_PRINT_CMD);
				}
			}
			else if(wan_type == DHCP_CLIENT){
				CsteSystem("killall -SIGUSR1 udhcpc",CSTE_PRINT_CMD);//renew dhcpc
			}
		}
    }

	SetWlan_idx(wlan_if);
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled); 
	if(wlan_disabled == 1){
		sprintf(cmd,"ifconfig %s down 2> /dev/null",wlan_if);
		system(cmd);
		memset(wifi_if, '\0', sizeof(wifi_if));
		sprintf(wifi_if,"%s-va0",root_if);
		SetWlan_idx(wifi_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		if(wlan_disabled == 0){
			sprintf(cmd,"ifconfig %s down 2> /dev/null",wifi_if);
			system(cmd);
		}
		memset(wifi_if, '\0', sizeof(wifi_if));
		sprintf(wifi_if,"%s-va1",root_if);
		SetWlan_idx(wifi_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		if(wlan_disabled ==0){
			sprintf(cmd,"ifconfig %s down 2> /dev/null",wifi_if);
			system(cmd);
		}
	}
	else
	{
		memset(wifi_if, '\0', sizeof(wifi_if));
		sprintf(wifi_if,"%s-va0",root_if);
		SetWlan_idx(wifi_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		if(wlan_disabled == 0){
			sprintf(cmd,"ifconfig %s up 2> /dev/null",wifi_if);
			system(cmd);
		}
		memset(wifi_if, '\0', sizeof(wifi_if));
		sprintf(wifi_if,"%s-va1",root_if);
		SetWlan_idx(wifi_if);
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		if(wlan_disabled ==0){
			sprintf(cmd,"ifconfig %s up 2> /dev/null",wifi_if);
			system(cmd);
		}
	}
	if(!strcmp(root_if,"wlan0"))
	{
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);
		if(intVal==0){
			sprintf(cmd,"ifconfig %s-vxd down 2> /dev/null",root_if);
			system(cmd);
		}
	}
	else if(!strcmp(root_if,"wlan1"))
	{
		apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);
		if(intVal==0){
			sprintf(cmd,"ifconfig %s-vxd down 2> /dev/null",root_if);
			system(cmd);
		}
	}
#if !defined(CONFIG_BOARD_WX022)
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
	if(wlan_disabled==1)
		CsteSystem("csteSys setWifiLedCtrl 0 1",CSTE_PRINT_CMD);
	else
		CsteSystem("csteSys setWifiLedCtrl 0 0",CSTE_PRINT_CMD);
	
	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
	if(wlan_disabled==1)
		CsteSystem("csteSys setWifiLedCtrl 1 1",CSTE_PRINT_CMD);
	else
		CsteSystem("csteSys setWifiLedCtrl 1 0",CSTE_PRINT_CMD);
#endif
#if defined(CONFIG_SUPPORT_CS_IPTV)
	int IptvEnabled = 0;
	apmib_get(MIB_OP_MODE, (void *)&op_mode);
	apmib_get(MIB_IPTV_ENABLED,(void *)&IptvEnabled);
	
	if((op_mode == GATEWAY_MODE)&&(IptvEnabled == 1))
	{
		int wlan0_enable=0, wlan0va0_enable=0, wlan0va1_enable=0, wlan0va2_enable=0, wlan0mesh_enable=0;
		int wlan1_enable=0, wlan1va0_enable=0, wlan1va1_enable=0, wlan1va2_enable=0, wlan1mesh_enable=0;
		SetWlan_idx("wlan0");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0_enable);
		apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&wlan0mesh_enable);
		SetWlan_idx("wlan0-va0");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0va0_enable);
		SetWlan_idx("wlan0-va1");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0va1_enable);
		SetWlan_idx("wlan0-va2");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0va2_enable);
		
		SetWlan_idx("wlan1");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1_enable);
		apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&wlan1mesh_enable);
		SetWlan_idx("wlan1-va0");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1va0_enable);
		SetWlan_idx("wlan1-va1");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1va1_enable);
		SetWlan_idx("wlan1-va2");
		apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1va2_enable);
		
		if(wlan0_enable==0)system("brctl delif br0 wlan0");			
		if(wlan0va0_enable==0)system("brctl delif br0 wlan0-va0");
		if(wlan0va1_enable==0)system("brctl delif br0 wlan0-va1");
		if(wlan0va2_enable==0)system("brctl delif br0 wlan0-va2");
		if(wlan1_enable==0)system("brctl delif br0 wlan1");
		if(wlan1va0_enable==0)system("brctl delif br0 wlan1-va0");
		if(wlan1va1_enable==0)system("brctl delif br0 wlan1-va1");
		if(wlan1va2_enable==0)system("brctl delif br0 wlan1-va2");
	}
#endif
    return ;        
}

#ifdef CONFIG_APP_TR069
#define CWMPPID  "/var/run/cwmp.pid"

void off_tr069()
{
	int cwmppid=0,i=0;
	char cmd[64]={0},buf[64]={0};
	cwmppid = getPid((char*)CWMPPID);

	printf("\ncwmppid=%d\n",cwmppid);
	
	if(cwmppid > 0){
		getCmdStr("ps | grep \"cwmpClient\" | grep -v \"grep\"",buf,sizeof(buf));
		while(strlen(buf)){
			sprintf(cmd,"kill -9 %d",cwmppid);
			CsteSystem(cmd, CSTE_PRINT_CMD);
			memset(buf, 0x00, sizeof(buf));
			getCmdStr("ps | grep \"cwmpClient\" | grep -v \"grep\"",buf,sizeof(buf));
			if((i++)>3)
				break;
		}
	}
}

int do_cmd(const char *filename, char *argv [], int dowait)
{
	pid_t pid, wpid;
	int stat=0, st;
	
	if((pid = vfork()) == 0) {
		/* the child */
		char *env[3];
		
		signal(SIGINT, SIG_IGN);
		argv[0] = (char *)filename;
		env[0] = "PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin";
		env[1] = NULL;

		execve(filename, argv, env);

		printf("exec %s failed\n", filename);
		_exit(2);
	} else if(pid > 0) {
		if (!dowait)
			stat = 0;
		else {
			/* parent, wait till rc process dies before spawning */
			while ((wpid = wait(&st)) != pid)
				if (wpid == -1 && errno == ECHILD) { /* see wait(2) manpage */
					stat = 0;
					break;
				}
		}
	} else if(pid < 0) {
		printf("fork of %s failed\n", filename);
		stat = -1;
	}
	return st;
}

int va_cmd(const char *cmd, int num, int dowait, ...)
{
	va_list ap;
	int k;
	char *s;
	char *argv[24];
	int status;
	
	va_start(ap, dowait);
	
	for (k=0; k<num; k++)
	{
		s = va_arg(ap, char *);
		argv[k+1] = s;
	}
	
	argv[k+1] = NULL;
	status = do_cmd(cmd, argv, dowait);
	va_end(ap);
	
	return status;
}

int startCWMP(unsigned char urlChanged)
{
	unsigned int cwmp_flag;
	/*add a wan port to pass */
	CsteSystem("sysconf firewall", CSTE_PRINT_CMD);

	/*start the cwmpClient program*/
	apmib_get(MIB_CWMP_FLAG, (void *)&cwmp_flag);
	if( cwmp_flag&CWMP_FLAG_AUTORUN )
		va_cmd( "/bin/cwmpClient", 0, 0 );

	return 0;
}
#endif

int splitString2Arr_v2(char *src, char *desArr, unsigned int lenOf1d, unsigned int lenOf2d, char delimiter)
{
	char *pchar = desArr;
	int tmp = 0, len = 0;
	if(!strlen(src) || desArr == NULL || lenOf1d < 1 || lenOf2d < 1)
		return -1;
	while(*src != '\0'){
		if(*src != delimiter && (len < lenOf2d - 1)){
			*pchar++ = *src++;
			++len;		//when len = pchar = lenOf2d-1, we have copied lenOf2d-1 characters;
		}
		else{
			if(len == lenOf2d-1){					//when len = pchar = lenOf2d-1
				if(*src != delimiter && *src != '\0'){	//there are still characters not copied, too long.
					*pchar = '\0';
					return -1;
				}
			}
			
			*pchar = '\0';
			len = 0;
			++tmp;
			
			if(tmp == lenOf1d)
				return -1;
			
			pchar = desArr + tmp*lenOf2d;
			if(*(src+1) == delimiter)
				*pchar = '\0';
			
			++src;
		}
		
	}
	*pchar = '\0';
	
	return ++tmp;
}
int tcpcheck_net(const char *host, int port, int timeout)
{
	FILE *f = NULL;
	char s[64] = { 0 }; 
	char cmd[128] = { 0 }; 
	int ok = 0;

	if ((NULL == host) || (strlen(host)<7))/* 地址合法性检测 */
		return ok;
	
	sprintf(cmd, "tcpcheck %d %s:%d > %s", timeout, host, port, TCP_TMPFILE);
	system(cmd);
	sleep(1);
	if ((f = fopen(TCP_TMPFILE, "r")) != NULL) {
		if ( NULL != fgets(s, sizeof(s), f)) {
			if (strstr(s, "alive") != NULL) {
				ok = 1;
			}
			else if (strstr(s, "timed out") != NULL) {
				ok = 0;
			}
			else {
				ok = 0;
			}
		}
		fclose(f);
	}
	unlink(TCP_TMPFILE);
	
	return ok;
}

int safe_cs_pub(char *hst, char *tp, char *msg)
{
	char cmd[256]={0},ftmp[64];
	struct timeval begin;

	gettimeofday(&begin, NULL);
	sprintf(ftmp,"/tmp/pubMsg%lu",begin.tv_usec);
	
	f_write(ftmp, msg, strlen(msg), FW_CREATE, 0);
	sprintf(cmd,"cste_pub -h %s -t totolink/router/%s -f %s",hst,tp,ftmp);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	sprintf(cmd,"rm -f %s",ftmp);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	return 0;
}

#if defined(SUPPORT_MESH)
int addInfoToroot(char root[], char *name, char *val){
	char tmpStr[128]={0},tmpVal[128]={0},tmpbuf[8]={0};
	int i=0;

	for(i=0;i<strlen(val);i++)
	{
		if(val[i]==' '||val[i]=='&'||val[i]=='('||val[i]==')'||val[i]=='|')
		{
			sprintf(tmpbuf,"\\%c",val[i]);
			strcat(tmpVal,tmpbuf);
		}
		else
		{
			tmpVal[strlen(tmpVal)]=val[i];
		}
			
	}
	
	if(strlen(root)==0)
	{
		sprintf(tmpStr,"{\\\"%s\\\":\\\"%s\\\"}",name,tmpVal);
		strcat(root,tmpStr);
	}
	else
	{
		sprintf(tmpStr,",\\\"%s\\\":\\\"%s\\\"}",name,tmpVal);
		root[strlen(root)-1]='\0';
		strcat(root,tmpStr);
	}
}

int addNumInfoToroot(char root[], char *name, int val){
	char tmpStr[128]={0};
	if(strlen(root)==0)
	{
		sprintf(tmpStr,"{\\\"%s\\\":\\\"%d\\\"}",name,val);
		strcat(root,tmpStr);
	}
	else
	{
		sprintf(tmpStr,",\\\"%s\\\":\\\"%d\\\"}",name,val);
		root[strlen(root)-1]='\0';
		strcat(root,tmpStr);
	}
}
#endif

#if defined(CONFIG_PA_ONLINE_IP)
int getAppfilterSwitch(char *name, int *enable)
{
	char tmp[512]={0}, switch_tmp[20][16]={0}, buf[2][10]={0};
	int i=0;
	
	apmib_get(MIB_APPFILTER_SWITCH, (void *)tmp);
	splitString2Arr_v2(tmp, switch_tmp, 20, 16, ';');
	for(i=0;i<20;i++){
		splitString2Arr_v2(switch_tmp[i], buf, 2, 10, '#');
		if(strcmp(name,buf[0])==0){
			*enable=atoi(buf[1]);
			return 1;
		}
	}
	return 0;
}

int setAppfilterSwitch(char *name, int *enable)
{
	char tmp[512]={0}, new_tmp[16]={0}, switch_tmp[20][16]={0}, buf[2][10]={0};
	int find=0, i=0;
	apmib_get(MIB_APPFILTER_SWITCH, (void *)tmp);
	splitString2Arr_v2(tmp, switch_tmp, 20, 16, ';');
	for(i=0;i<20;i++){
		splitString2Arr_v2(switch_tmp[i], buf, 2, 10, '#');
		if(strcmp(name,buf[0])==0){
			find=1;
			sprintf(buf[1],"%d",*enable);
			strcpy(switch_tmp[i],buf[0]);
			strcat(switch_tmp[i],"#");
			strcat(switch_tmp[i],buf[1]);
			break;
		}
	}

	if(find == 1){
		memset(tmp,0,sizeof(tmp));
		strcpy(tmp,switch_tmp[0]);
		for(i=1;i<20;i++){
			if(strlen(switch_tmp[i])>0){
				strcat(tmp,";");
				strcat(tmp,switch_tmp[i]);
			}
		}
		apmib_set(MIB_APPFILTER_SWITCH, (void *)tmp);
	}else if(find == 0){
		sprintf(new_tmp,"%s#%d",name,*enable);
		strcat(tmp,";");
		strcat(tmp,new_tmp);
		apmib_set(MIB_APPFILTER_SWITCH, (void *)tmp);
	}

	apmib_update_web(CURRENT_SETTING);
	return 0;
}
#endif
