/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file statistics.c
* @author CaryStudio
* @brief  This is a statistics cste topic
* @date 2017-11-15
* @warning http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.
			http://www.cnblogs.com/davygeek/p/5658968.html
* @bug
*/

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <setjmp.h> 
#include <sys/wait.h>
#include "apmib.h"
#include "mibtbl.h"

#include "statistics.h"
#include "sigHd.h"


#if defined(SUPPORT_CUSTOMIZATION)
#define INIFILE       "/mnt/custom/product.ini"
#endif

#define SOAPAUTH_LOCK 			"/tmp/soapauth_new"

static sigjmp_buf jmpbuf;


static void alarm_func()
{
	siglongjmp(jmpbuf, 1);
}

struct hostent *gngethostbyname(char *HostName, int timeout)
{
     struct hostent *lpHostEnt;
     signal(SIGALRM, alarm_func);
     if(sigsetjmp(jmpbuf, 1) != 0) {
           alarm(0);//timout
           signal(SIGALRM, SIG_IGN);
           return NULL;
     }

     alarm(timeout);//setting alarm
     lpHostEnt = gethostbyname(HostName);
     signal(SIGALRM, SIG_IGN);
     return lpHostEnt;
}
/**
* @note reportStatisticsInfo_New_child  report Statistics Information
*
* @param NULL
* @return return Json Data
<pre>
{
	"mac":	"F4:28:54:00:33:17"
	"model":	"A950RG"
	"csid":	"CS18ER"
	"swv":	"V5.9c"
	"svn":	"680"
}
return parameter description:
"mac":	current mac address
"model":	software model
"csid": current csid
"swv":	current version
"svn":	build version
</pre>
*@author		Kris
*@date	2017-11-15
*/

int reportStatisticsInfo_New_child()
{
	int server_sk_new, ret;
   	fd_set rdfds;
	struct timeval tv;
    struct sockaddr_in server_addr;

	cJSON *root=cJSON_CreateObject();
	char buf[32]={0};
	char *input,*r_status;
	
	char http_h[512]={0};
    char http_b[1536]={0};
	char w_buff[2048]={0};
	char r_buff[2048]={0};
    char hardwareVersion[32]={0};
	char hardwareModel[32]={0};
	char server_domain[64]={0},server_api[64]={0};
	int  server_port=80;
    long long int mac_int;
    struct sockaddr hwaddr;
    unsigned char *pMacAddr;

	
	getInAddr("eth0", HW_ADDR_T, (void *)&hwaddr );
    pMacAddr = (unsigned char *)hwaddr.sa_data;
    mac_int=((long long)(pMacAddr[0]&0x0ff) << 40 | (long long)(pMacAddr[1]&0x0ff) << 32 | (long long)(pMacAddr[2]&0x0ff) << 24 | (long long)(pMacAddr[3]&0x0ff) << 16 | (long long)(pMacAddr[4]&0x0ff) << 8 | (long long)(pMacAddr[5]&0x0ff));

	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%lld",mac_int);
	cJSON_AddStringToObject(root,"mac",buf);
	
	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_STATISTICS_MODEL, (void *)buf);
	cJSON_AddStringToObject(root,"model",buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_CSID, (void *)buf);
	cJSON_AddStringToObject(root,"csid",buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_SOFTWARE_VERSION, (void *)buf);
	cJSON_AddStringToObject(root,"swv",buf);
	
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%d",PRODUCT_SVN);
	cJSON_AddStringToObject(root,"svn",buf);
	cJSON_AddStringToObject(root,"ext","root");
	
	input=cJSON_Print(root);
	cJSON_Delete(root);
	
	memset(server_domain,'\0',sizeof(server_domain));
	apmib_get(MIB_STATISTICS_DOMAIN,(void*)&server_domain);
	
	memset(server_api,'\0',sizeof(server_api));
	apmib_get(MIB_STATISTICS_API,(void*)&server_api);
	
	apmib_get(MIB_STATISTICS_PORT,(void*)&server_port);
	
	struct hostent *host=gngethostbyname(server_domain,1);
	if(host == NULL)
	{
		CSTE_DEBUG("Cannot connect to the data statistics server in monitor!\n");
		if(input!=NULL)	free(input);
		return 0;
	}

	memset(w_buff,0x00,2048);
	memset(r_buff,0x00,2048);
	memset(http_b,0x00,1536);
	memset(http_h,0x00,512);
	
	sprintf(http_b,"%s",input);
	sprintf(http_h,"POST %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",server_api,server_domain,strlen(http_b));
	if(input!=NULL)	free(input);
	strcpy(w_buff,http_h);
    strcat(w_buff,http_b);
	
	if((server_sk_new= socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        CSTE_DEBUG("create socket error!!!\n");
		return 0;
    }
	
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));
	server_addr.sin_port = htons(server_port);

	if(connect(server_sk_new, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        CSTE_DEBUG("connect msg error!!!\n"); 
        close(server_sk_new);
		return 0;
    }

	FD_ZERO(&rdfds);
    FD_SET(server_sk_new, &rdfds);
    tv.tv_sec = 1;
	tv.tv_usec = 500000;

	if(send(server_sk_new, w_buff, strlen(w_buff), 0) < 0)    	
	{    		
		CSTE_DEBUG("send msg error!!!\n");  
        close(server_sk_new);
		return 0;    	
	}
	
	ret = select(server_sk_new+ 1, &rdfds, NULL, NULL, &tv);
	if(ret < 0) 
		perror("select error!\n");//select error
	else if(ret == 0)
		CSTE_DEBUG("timeout\n");//1s+500ms socket status no change;
	else
	{
		if(FD_ISSET(server_sk_new, &rdfds))
		{
			ret=recv(server_sk_new, r_buff, 2048, 0);
			if(ret==0)
			{
				close(server_sk_new);
				return 0;
			}

			r_status=strstr(r_buff, "status");
			CSTE_DEBUG("r_buff=%s \n",r_buff);
			if(r_status&&strstr(r_status,"1"))
			{
				system("echo ''> /tmp/soapauth_new");
				close(server_sk_new);
				return 0;
			}
		}			
	}
	close(server_sk_new);	
	return 0;
}

int count=0;
int main(int argc, char *argv[])
{
	if (!apmib_init()) 
	{		
		printf("statistics:Initialize AP MIB failed !\n");
		return -1;	
	}
	
#if defined(SUPPORT_CUSTOMIZATION)
	int fixed=0;
	apmib_get(MIB_CUSTOM_FIXEDINI,	&fixed);
	if(fixed==0 && 0 != f_exist(INIFILE))
	{
		return -1;
	}
#endif

	int soapsta=1;
	apmib_get(MIB_SOAP_AUTHSTATUS,(void*)&soapsta);
	if(soapsta==0)
	{
		return 0;
 	}

	while(1)
	{
		if (0 == f_exist(SOAPAUTH_LOCK))
		{
			reportStatisticsInfo_New_child();
		}
		if (0 != f_exist(SOAPAUTH_LOCK))
		{
			int result=0;
			printf("[Dbg]======Statistics Success!==========\n");
			apmib_set(MIB_SOAP_AUTHSTATUS,(void*)&result);
			apmib_update_web(CURRENT_SETTING);
			return 0;
		}
		
		if(count < 2)
			count++;
		else
			return 0;
		sleep(60);
	}
	return 0;
}
