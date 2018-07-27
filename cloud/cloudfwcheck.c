#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <setjmp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>

#include <apmib.h>
#include <sigHd.h>
#include <cJSON.h>
#include <cstelib.h>
#include <mystdlib.h>


#define CHECK_TIMEOUT 2
#define SOCK_CONNECT_TIMEOUT 3
#define SOCK_RW_TIMEOUT 5
#define SAFE_CLOSE(fd)				if(fd > 0)	{ close(fd); fd = -1; }

#define PATH_CLOUDFWCHECK_PID "/var/run/cs_cloudfwcheck.pid"

typedef struct {
	unsigned long total;
	unsigned long free;
} meminfo_t;


static char LanMac[18]={0};

int  CPORT=80;
char CHOST[64]={0};
char CAPI[64]={0};


static sigjmp_buf jmpbuf;
static void alarm_func()
{
     siglongjmp(jmpbuf, 1);
}

struct hostent *gngethostbyname(char *HostName, int timeout)
{
     struct hostent *lpHostEnt;
 
     signal(SIGALRM, alarm_func);
     if(sigsetjmp(jmpbuf, 1) != 0)
     {
           alarm(0);//timout
           signal(SIGALRM, SIG_IGN);
           return NULL;
     }
	 
     alarm(timeout);//setting alarm
     lpHostEnt = gethostbyname(HostName);
     signal(SIGALRM, SIG_IGN);
 
     return lpHostEnt;
}

int get_memory(meminfo_t *m)
{
	FILE *f;
	char s[128];
	int ok = 0;

	memset(m, 0, sizeof(*m));
	if ((f = fopen("/proc/meminfo", "r")) != NULL) {
		while (fgets(s, sizeof(s), f)) {
			if (strncmp(s, "MemTotal:", 9) == 0) {
				m->total = strtoul(s + 12, NULL, 10) * 1024;
				++ok;
			}
			else if (strncmp(s, "MemFree:", 8) == 0) {
				m->free = strtoul(s + 12, NULL, 10) * 1024;
				++ok;
			}
		}
		fclose(f);
	}
	if (ok == 0) {
		return 0;
	}
	return 1;
}


int server_send(int server_sk, char *w_buff, fd_set *rdfds, int timeout)
{
	int ret = 0;
	struct timeval tv;
	
	FD_ZERO(rdfds);
    FD_SET(server_sk, rdfds);
    tv.tv_sec = timeout;
	tv.tv_usec = 500000;

    if(send(server_sk, w_buff, strlen(w_buff), 0) < 0){    		
		perror("send");
        goto end;  	
	}
	ret = select(server_sk + 1, rdfds, NULL, NULL, &tv);
end:
	return ret;
}

int init_tcp_client(void)
{
	int server_sk;
    struct sockaddr_in server_addr;
	struct hostent *host;
	fd_set rdfds;
	struct timeval timeout;
	unsigned long ul = 1;
	int error = -1, len = sizeof(int);
	int bTimeoutFlag = 0;
	int ret;
	host = gngethostbyname(CHOST,CHECK_TIMEOUT);
	if(host == NULL)
	{
		printf("Cloudfwcheck[%d]Cannot connect server:%s!\n",__LINE__,CHOST);
		return -1;		
	}
	
    if((server_sk = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        perror("socket");
		return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));    
    server_addr.sin_port = htons(CPORT);
	
	ioctl(server_sk, FIONBIO, &ul);
    if(connect(server_sk, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		timeout.tv_sec  = SOCK_CONNECT_TIMEOUT;
		timeout.tv_usec = 0;
		FD_ZERO(&rdfds);
		FD_SET(server_sk, &rdfds);

		ret = select(server_sk+1, NULL, &rdfds, NULL, &timeout);
		if (ret == 0)              //返回0，代表在描述词状态改变已超过timeout时间
		{
			getsockopt(server_sk, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
			if (error == 0)          // 超时，可以做更进一步的处理，如重试等
			{
				bTimeoutFlag = 1;
				perror("connect timeout");
			}
			else
			{
				perror("Cann't connect to server!");
			}
			goto end;
		}
		else if ( ret == -1)      // 返回-1， 有错误发生，错误原因存在于errno
		{
			perror("connect error");
			goto end;
		}
		else                      // 成功，返回描述词状态已改变的个数
		{
			printf("Connect success!\n");
		}
	}
	else
	{
		printf("Connect success!\n");
		ret = 1;
	}

	ul = 0;
	ioctl(server_sk, FIONBIO, &ul); //重新将socket设置成阻塞模式

	return server_sk;

end:
	SAFE_CLOSE(server_sk);
	return -1;
}


int update_fw(cJSON *root )
{
	int iRet=0, updateMode=0;
	char *dlURL=NULL, cmd[512]={0};
	
	updateMode = atoi(websGetVar(root, T("mode"), T("0")));

	if( 1!=updateMode && 2!=updateMode )
	{
		printf("cs_cloudfwCheck[%s:%d]updateMode=%d,Not valid update mode, return!\n",__FUNCTION__,__LINE__,updateMode);
		return iRet;
	}

	dlURL= websGetVar(root, T("url"), T(""));
	if( 0==strcmp(dlURL, "") )
	{
		return iRet;
	}

	char *fwVersion=websGetVar(root, T("version"), T(""));
	char *fwSvn=websGetVar(root, T("svn"), T(""));

	memset(cmd, 0x00 ,sizeof(cmd));
	sprintf(cmd, "%s.%s", fwVersion, fwSvn);
	RunSystemCmd("/tmp/cloudFwStatus","echo","New",NULL_STR);
	RunSystemCmd("/tmp/newVersion","echo",cmd,NULL_STR);
	RunSystemCmd("/tmp/DlFileUrl","echo",dlURL,NULL_STR);

	if( updateMode == 2 ) //auto update
	{			
		int aprule=-1, updatetime=0;
	
		aprule=atoi(websGetVar(root,T("aprule"),T("1")));
		updatetime=atoi(websGetVar(root,T("time"),T("0")));
		
		if( 1==aprule ){
			RunSystemCmd(NULL_FILE,"killall","forceupg",NULL_STR);
			RunSystemCmd(NULL_FILE,"forceupg","1",updatetime, "&",NULL_STR);
		}else if( 2==aprule ){
			RunSystemCmd(NULL_FILE,"killall","forceupg",NULL_STR);
			RunSystemCmd(NULL_FILE,"forceupg","2",updatetime, "&",NULL_STR);
		}else{//0
			RunSystemCmd(NULL_FILE,"killall","forceupg",NULL_STR);
			RunSystemCmd(NULL_FILE,"forceupg","2","7200", "&",NULL_STR);//2:00
		}
	}
	
	return 0;
}

int parse_sys_update(int server_sk, char *r_buff, int recvLen)
{
	if(strstr(r_buff,"200 OK"))
    {  
		char *r_data;
		if(!(r_data=strstr(r_buff, "{\"")))
			printf("cs_cloudfwCheck[%s:%d]Server retunr error!\n",__FUNCTION__,__LINE__);
		else{
			if(!(r_data=strstr(r_buff, "{\"")))
			{
				printf("cs_cloudfwCheck[%s:%d]Server retunr error!\n",__FUNCTION__,__LINE__);
			}
			else			
			{
				char *output = (char *)malloc(recvLen); 		

				memset(output,0x00, recvLen);
				sprintf(output, "%s", r_data);
				printf("cs_cloudfwCheck[%s:%d]output=[%s]\n",__FUNCTION__,__LINE__,output);
				
				cJSON *root = cJSON_Parse(output);
				if(root != NULL){
					update_fw(root);
					cJSON_Delete(root);
				}
				free(output);
			}
		}		
	}
	return 0;
}

int connect_cloud(char *sendBuf,char *senddata)
{
	fd_set rdfds;
    int server_sk;
    char w_buff[2048]={0};
    char r_buff[2048]={0};
    int ret,arrarLen,i,recvLen;
	char *out;

	strcpy(w_buff,sendBuf);
    strcat(w_buff,senddata);
	printf("cs_cloudfwCheck[%s:%d]w_buff = %s\n",__FUNCTION__,__LINE__,w_buff);

	if( (server_sk=init_tcp_client()) < 0 ){
		printf("cs_cloudfwCheck[%s:%d]init_tcp_client error!!!\n",__FUNCTION__,__LINE__);
		goto end;
	}
	ret =  server_send(server_sk, w_buff, &rdfds,SOCK_RW_TIMEOUT);
	if(ret < 0){
		perror("select");/* 这说明select函数出错 */
		//RunSystemCmd("/tmp/cloudFwStatus","echo","TimeOut",NULL_STR);
	}
	else if(ret == 0){ 
		perror("timeout\n"); /* 说明在我们设定的时间值2秒加500毫秒的时间内，socket的状态没有发生变化 */
		//RunSystemCmd("/tmp/cloudFwStatus","echo","TimeOut",NULL_STR);
	}
	else{
		if(FD_ISSET(server_sk, &rdfds)){
			recvLen = recv(server_sk, r_buff, 2048, 0);
			printf("cs_cloudfwCheck[%s:%d]r_buff=[%s], len=%d.\n",__FUNCTION__,__LINE__,r_buff, recvLen);
			parse_sys_update(server_sk, r_buff, recvLen);
		}
	}
	close(server_sk);
end:
	return 0;  
}

void cloudVersionCheck(void)
{
	unsigned long FLASHSIZE;
	meminfo_t mt;
	FLASHSIZE=getFlashSize();
	
	/* check free memory */
	if ( get_memory(&mt) == 0 )
	{
		printf("cs_cloudfwCheck[%s:%d]get_memory fail!\n",__FUNCTION__,__LINE__);
		return 0;
	}
	else
	{
		 //must  >	10M
		if ( mt.free < (FLASHSIZE) ){
			printf("cs_cloudfwCheck[%s:%d]free memory is too small!\n",__FUNCTION__,__LINE__);
			return 0;
		}
	}

	char sendBuf[2048]={0};
	char *sendData;
	char *tmpBuf[128]={0};
	cJSON *root,*plugin;

	root=cJSON_CreateObject();
	getIfMac("br0", LanMac);
	cJSON_AddStringToObject(root, "protocol", "2.0");
	cJSON_AddStringToObject(root, "mac", LanMac);
	
	memset(tmpBuf,0,sizeof(tmpBuf));
	apmib_get(MIB_CSID, (void *)tmpBuf);
	cJSON_AddStringToObject(root, "csid", tmpBuf);

	memset(tmpBuf,0,sizeof(tmpBuf));
	apmib_get(MIB_SOFTWARE_VERSION, (void *)tmpBuf);
	cJSON_AddStringToObject(root, "version", tmpBuf);

	memset(tmpBuf,0,sizeof(tmpBuf));
	sprintf(tmpBuf,"%d",PRODUCT_SVN);
	cJSON_AddStringToObject(root,"svn",tmpBuf);

	plugin= cJSON_CreateArray();
	cJSON_AddItemToObject(root,"plugin",plugin);

	cJSON_AddStringToObject(root, "ext", "{}");
	sendData=cJSON_Print(root);
	cJSON_Delete(root);

	memset(sendBuf,0x00,2048);
	sprintf(sendBuf,"POST %s HTTP/1.0\r\n" \
		"Host: %s:%d\r\n" \
		"Content-Length: %d\r\n" \
		"Content-Type: application/x-www-form-urlencoded\r\n" 
		"\r\n", 
		CAPI, CHOST, CPORT, strlen(sendData));
	
	connect_cloud(sendBuf,sendData);
}

int initServerInfo()
{
	apmib_get(MIB_CLOUDUPG_HOST, (void *)CHOST);
	if(strlen(CHOST)<2)
		strcpy(CHOST,"update.carystudio.com");

	apmib_get(MIB_CLOUDUPG_API, (void *)CAPI);
	if(strlen(CAPI)<2)
		strcpy(CAPI,"/device/upgrade/check");
	
	apmib_get(MIB_CLOUDUPG_PORT, (void *)&CPORT);
	if(CPORT<2)
		CPORT=80;
	return 0;
}

int main(int argc, char * argv[])
{
	printf("==========cs_cloudfwCheck begain======\n");

	if ( !apmib_init()) {
		printf("cs_cloudfwCheck[%d]Initialize AP MIB failed !\n",__LINE__);
		return 0;
	}

	initServerInfo();

	if ( !tcpcheck_net( "114.114.114.114", 53, 2) && !tcpcheck_net( "www.qq.com", 80, 2))
	{
		printf("cs_cloudfwCheck[%d]Can not connect to server!\n",__LINE__);
		RunSystemCmd("/tmp/cloudFwStatus","echo","UnNet",NULL_STR);
		return 0;
	}

	RunSystemCmd("/tmp/cloudFwStatus","echo","Idle",NULL_STR);

	//Web login will check once in 1 hour
	if(argc >=2 && atoi(argv[1])==1 ){
		RunSystemCmd("/var/CloudCheckTime","cat","/proc/uptime",NULL_STR);
	}
	cloudVersionCheck();

	printf("==========cs_cloudfwCheck end======\n");
	return 0;
}
