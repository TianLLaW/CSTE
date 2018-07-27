#include "manageAgent.h"
#include "../cstelib.h"

JOB_BOOL gRun;
pthread_t handerThread;
struct sockaddr_in broad_cast_addr;
int broad_sk = -1;

void MAC17_TO_MAC6( unsigned char * MAC_17, unsigned char * MAC_6)
{
	int i = 0;
	memset(MAC_6,0,CSTE_MAC_LEN);	
	for(i = 0; i < CSTE_MAC_LEN; i++)
	{		
		MAC_6[i] = strtoul((unsigned char *)(&(MAC_17[i*3])), 0, 16);
	}
	return;
}

void print_mem (unsigned char *p, int k)
{
	int i;
	printf("\n");

	for (i = 0; i < k; i++)
	{
		printf("%02x ", *p++);

		if ((i + 1) % 16 == 0) printf("\n");
	}

	printf("\n");
}

int isSameNetwork(char *AcIp, char *AcMask, char *SelfIp, char *SelfMask)
{
	struct in_addr inIp, inMask;
	struct in_addr myIp, myMask, mask;
	unsigned int inIpVal, inMaskVal, myIpVal, myMaskVal, maskVal;
	
	if ( !inet_aton(AcIp, &inIp) ) {
		return 0;
	}
	
	if ( !inet_aton(AcMask, &inMask) ) {
		return 0;
	}
	
	memcpy(&inIpVal, &inIp, 4);
	memcpy(&inMaskVal, &inMask, 4);

	if ( !inet_aton(SelfIp, &myIp) ) {
		return 0;
	}
	
	if ( !inet_aton(SelfMask, &myMask) ) {
		return 0;
	}		
	
	memcpy(&myIpVal, &myIp, 4);
	memcpy(&myMaskVal, &myMask, 4);
	memcpy(&maskVal,myMaskVal>inMaskVal?&myMaskVal:&inMaskVal,4);
	
	if((inIpVal & maskVal) == (myIpVal & maskVal))
	{
		return 1;
	}

	return 0;
}

void MainInit(struct heartbeat_agent *agent)
{
	gRun = J_TRUE;
	memset(agent,0,sizeof(struct heartbeat_agent));
	sprintf(agent->ap_mac_str,"%s",getLanMac());
	MAC17_TO_MAC6(agent->ap_mac_str,agent->ap_mac);
	
}
void MainGracefulExit(int sig)
{
	gRun = J_FALSE;
	(void) signal(SIGTERM, SIG_IGN);
}


void cste_bind_to_ac()
{	

}

void ap_heart_beat(void)
{
	send_mqtt_heart_beat();
	
	send_http_heart_beat();

	JobQueueAddJob(HEART_BEAT_INTERVAL,JOB_HEART_BEAT, ap_heart_beat, NULL, NULL);
		
}

void cloudac_register(int signum)
{
	if(signum != CSTE_BIND_SIG)
		goto end;
	
	cste_bind_to_ac();

	JobQueueDeleteFirstJobByType(JOB_HEART_BEAT);
	
	ap_heart_beat();
	
end:
	return;

}

int  HeartBeatSockInit(struct heartbeat_agent *agent)
{
	int nReuseFlag = 1;
	if ((agent->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
			printf("CsteHeartBeatSockInit Error Creating Socket\n");
			return HB_FALSE;
	}
	
	memset(&(agent->address),0,sizeof(agent->address));
	agent->address.sin_family = AF_INET;
	
	agent->address.sin_addr.s_addr = htonl(INADDR_ANY);

	agent->address.sin_port = htons(UDP_HEART_BEAT_PORT);

	if(setsockopt(agent->socket, SOL_SOCKET, SO_REUSEADDR, &nReuseFlag, sizeof(int)) < 0)
	{ 
		printf("CsteHeartBeatSockInit:Set socket option	failed!\n "); 
		close(agent->socket); 
		return HB_FALSE; 
	} 

	if((bind(agent->socket, (struct sockaddr *)&agent->address, sizeof(agent->address))) < 0)
	{
		printf("CsteHeartBeatSockInit:Error Binding Socket \n");
		return HB_FALSE;
	}
	
	return HB_TRUE;
}

void HeartBeatProcessReceiveMsg(struct heartbeat_agent* agent,unsigned char *RecvMsgArray,int byteReceived)
{
	char mac_str[CSTE_MAC_STR_LEN]= {0};
	HB_BOOL result;
	AC_TYPE type;

	
	if(byteReceived == (CSTE_MAC_LEN+2))
	{
		//print_mem(RecvMsgArray,byteReceived);
		
		snprintf(mac_str,CSTE_MAC_STR_LEN,"%02X:%02X:%02X:%02X:%02X:%02X",*RecvMsgArray,*(RecvMsgArray+1),*(RecvMsgArray+2),*(RecvMsgArray+3),*(RecvMsgArray+4),*(RecvMsgArray+5));
		//printf("@@mac_str is %s\n",mac_str);	
		if(strcmp(agent->ap_mac_str,mac_str))
		{
			goto end;
		}

		agent->heart_rece = HB_TRUE;
		
		if(*(RecvMsgArray+CSTE_MAC_LEN+1) == HB_FALSE)
		{
			goto end;
		}else
		{
			type = *(RecvMsgArray+CSTE_MAC_LEN);
			//printf("===ac type %d===\n",type);
			switch (type)
			{
				case GATEWAY_AC:
					gatewayac_handler();
					break;
				default:
					printf("unknown ac type!\n");
					goto end;
					break;
			}
		}
	}

end:
	return;
}

void HeartBeatReceive(struct heartbeat_agent* agent)
{

	unsigned char RecvMsgArray[TEMP_BUF_SIZE];
	int RecvAddrLen = sizeof(struct sockaddr_in);
	int byteReceived;
	struct sockaddr_in RecvAddr;
					
	memset(RecvMsgArray,0,TEMP_BUF_SIZE);
	byteReceived = recvfrom(agent->socket, RecvMsgArray, TEMP_BUF_SIZE, 0, (struct sockaddr *)&RecvAddr, &RecvAddrLen);
	//printf("inet_ntoa(RecvAddr.sin_addr) is %s\n",inet_ntoa(RecvAddr.sin_addr));
	if(byteReceived < 0) 
	{
		printf("HeartBeatReceive: Receive Msg Error\n");
		return;
	}
	
	HeartBeatProcessReceiveMsg(agent,RecvMsgArray,byteReceived);
	return;
}

static int broadcastRouteInit( void )
{
	FILE *fp;
	char *ptr = NULL;
	char buffer[128] = { 0 };
	char node_key[] = "255.255.255.255";
	int found = 0;

	fp = popen("route -n", "r");
	if (fp==NULL)
	{
		perror("popen");
		return found;
	}

	while (NULL != fgets(buffer, sizeof(buffer),fp))
	{
		ptr = strstr(buffer, node_key);
		if (ptr) {
			found = 1;
			break;
		}
	}
	pclose(fp);

	if ( 0 == found ){
		system("route add -net 255.255.255.255 netmask 255.255.255.255 br0");
	}

	return 0;
}

static int broadcastInit(void)
{	
	int so_broadcast=1;
	int socket_fd;
	struct sockaddr_in myaddr;

	broad_cast_addr.sin_family=AF_INET;
	broad_cast_addr.sin_port=htons(BROADCAST_DPORT);
	broad_cast_addr.sin_addr.s_addr=inet_addr(BROADCAST_IP);
	bzero(&(broad_cast_addr.sin_zero),8);
	
    myaddr.sin_family=AF_INET;
    myaddr.sin_port=htons(BROADCAST_SPORT);
	myaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    bzero(&(myaddr.sin_zero),8);
	
	broadcastRouteInit();
    if((socket_fd=(socket(AF_INET,SOCK_DGRAM,0)))==-1) {
		perror("socket");
		return HB_FALSE;
    }
    setsockopt(socket_fd,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));
    if((bind(socket_fd,(struct sockaddr *)&myaddr,sizeof(struct sockaddr)))==-1) {
		perror("bind");
		return HB_FALSE;
    }
	broad_sk = socket_fd;

	return HB_TRUE;
}

int setAPNetwork(cJSON* data)
{
	int LanCurMode,lanMode;
	char *LanAutoDhcp= websGetVar(data, T("dhcp"), T(""));
	char *lanIp= websGetVar(data, T("ip"), T(""));
	char *lanmask= websGetVar(data, T("mask"), T(""));
	char *lanGw= websGetVar(data, T("gateway"), T(""));
	char *priDns= websGetVar(data, T("dns"), T(""));
	struct in_addr inIp;
	
	//lan network
	apmib_get(MIB_LAN_MODE, (void *)&LanCurMode);
	//printf("MIB_LAN_MODE=%d,dhcp=%s\n",LanCurMode,LanAutoDhcp);
	if ((strlen(lanIp)>5) || (0==strcmp(LanAutoDhcp, "1") && 1 == LanCurMode )
		|| (0==strcmp(LanAutoDhcp, "0") && 0 == LanCurMode ))
	{
		if(strlen(lanIp)>5)
		{
	   	 	if ( inet_aton(lanIp, &inIp) ){
	        	apmib_set( MIB_IP_ADDR, (void *)&inIp);
	    	}    
		}
		if(strlen(lanGw)>5)
		{
		    if ( inet_aton(lanGw, &inIp) ){
				apmib_set(MIB_DEFAULT_GATEWAY, (void *)&inIp);
			}
		}
		
		if( 0 == strcmp(LanAutoDhcp, "1") )
		{
			lanMode=1;
			apmib_set(MIB_LAN_MODE, (void *)&lanMode);
			apmib_set(MIB_DNS1, "");
		}
		else if( 0 == strcmp(LanAutoDhcp, "0"))
		{
			lanMode=0;
			apmib_set(MIB_LAN_MODE, (void *)&lanMode);
		    if ( inet_aton(priDns, &inIp) ){
				apmib_set(MIB_DNS1, (void *)&inIp);
			}
		}
		
	apmib_update_web(CURRENT_SETTING);
    run_init_script("all");
	}
	
	return 0;
}

void broadcastResponse(char *action)
{
	int sendbyte;
	char mac[CSTE_MAC_STR_LEN] = {0},ip[CSTE_IP_STR_LEN] = {0},mask[CSTE_IP_STR_LEN] = {0};
	char *rspmsg = NULL;
	cJSON *root = NULL;
	char buf[32]={0};
	
	root = cJSON_CreateObject();
	
	sprintf(mac,"%s",getLanMac());
	cJSON_AddStringToObject(root, "mac", mac);
	getLanIp(ip);
	cJSON_AddStringToObject(root, "ip", ip);
	getLanNetmask(mask);
	cJSON_AddStringToObject(root, "mask",mask);

#if defined(FOR_DUAL_BAND)
	cJSON_AddStringToObject(root, "type", "3");
#else
	#if defined(ONLY_5G_SUPPORT)
		cJSON_AddStringToObject(root, "type", "2");
	#else
		cJSON_AddStringToObject(root, "type", "1");
	#endif
#endif

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_CSID, (void *)buf);
	cJSON_AddStringToObject(root,"csid",buf);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_SOFTWARE_VERSION, (void *)buf);
	cJSON_AddStringToObject(root,"softVer",buf);
	
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%d",PRODUCT_SVN);
	cJSON_AddStringToObject(root,"svnNum",buf);
	
	cJSON_AddStringToObject(root, "version", ACVERSION);
	cJSON_AddStringToObject(root, "action", action);

	memset(buf,'\0',sizeof(buf));
	apmib_get(MIB_HARDWARE_VERSION, (void *)buf);
	cJSON_AddStringToObject(root,"softModel",buf);
	
	rspmsg=cJSON_Print(root);
	cJSON_Delete(root);

	//printf("sendto===%s:%d\n%s\n",inet_ntoa(broad_cast_addr.sin_addr),ntohs(broad_cast_addr.sin_port),rspmsg); 
	sendbyte = sendto(broad_sk,rspmsg,strlen(rspmsg), 0, (struct sockaddr *)&broad_cast_addr, sizeof(struct sockaddr_in));
	if (sendbyte < 0)
	{
		printf("Broadcast response to ac error: %d \n %s  \n",sendbyte,rspmsg);
	}
	free(rspmsg);
}

void HeartBroadcastReceive(struct heartbeat_agent* agent)
{
	cJSON *root = NULL;
	AC_TYPE type;
	char *action,*actype,*version;
	char myIp[CSTE_IP_STR_LEN] = {0},myMask[CSTE_IP_STR_LEN] = {0};
	char RecvMsgArray[MAX_BUF_SIZE] = {0},rspaction[TEMP_BUF_SIZE] = {0};

	struct sockaddr_in RecvAddr;
	int byteReceived;
	int RecvAddrLen = sizeof(struct sockaddr_in);
					
	memset(RecvMsgArray,0,MAX_BUF_SIZE);
	byteReceived = recvfrom(broad_sk, RecvMsgArray, MAX_BUF_SIZE, 0, (struct sockaddr *)&RecvAddr, &RecvAddrLen);

	if(byteReceived < 0)
	{
		printf("HeartScanReceive: Receive Msg Error\n");
		return;
	}
	//printf("AP-recv:%s:%d---%s\n",inet_ntoa(RecvAddr.sin_addr),ntohs(RecvAddr.sin_port),RecvMsgArray);

	if(ntohs(RecvAddr.sin_port)!=BROADCAST_DPORT)
		return;
	
	root=cJSON_Parse(RecvMsgArray);
	if(root==NULL){
		printf("[HeartBroadcastReceive]Scan Recv data not json!\n");
		return;
	}
	getIfIp("br0",myIp);
	getLanNetmask(myMask);
	action =  websGetVar(root, T("action"), T(""));
	actype = websGetVar(root, T("type"), T(""));
	version = websGetVar(root, T("version"), T(""));
	
	type = atoi(actype);
	switch (type)
	{
		case GATEWAY_AC:
			if(!strcmp(action,ACTION_SCANAP))
			{
				char *acIp= websGetVar(root, T("ip"), T(""));
				char *acMask= websGetVar(root, T("mask"), T(""));
				if(isSameNetwork(acIp,acMask, myIp, myMask)==1)
				{
					apmib_set(MIB_GATEWAYAC_HOSTPATH, (void *)acIp);
					apmib_update_web(CURRENT_SETTING);
					gatewayac_handler();
				}
				else
				{
					memset(rspaction,0,sizeof(rspaction));
					sprintf(rspaction,"%s",ACTION_BROADCASTAP);
					broadcastResponse(rspaction);
				}
			}
			else if(!strcmp(action,ACTION_SETAPIP))
			{
				char *mac = websGetVar(root, T("mac"), T(""));
				char *gateway = websGetVar(root, T("gateway"), T(""));
				if(strcmp(agent->ap_mac_str,mac))
				{
					break;
				}

				setAPNetwork(root);

				if(strlen(gateway))
				{
					apmib_set(MIB_GATEWAYAC_HOSTPATH, (void *)gateway);
					apmib_update_web(CURRENT_SETTING);
					JobQueueAddJob(10, JOB_HEART_BEAT, gatewayac_handler, NULL, NULL);
				}
			}
			break;
		default:
			printf("unknown ac type!\n");
			break;
	}
	cJSON_Delete(root);
	return;
}


HB_BOOL fill_in_remote_addr(struct heartbeat_agent* agent,AC_TYPE type)
{
	struct hostent *host;
	char acaddr[TEMP_BUF_SIZE] = {0};
	
	apmib_get(MIB_GATEWAYAC_HOSTPATH, (void *)acaddr);
	host = gngethostbyname(acaddr,1);
	if(host == NULL)
	{
		//printf("gngethostbyname fail!\n");
		return HB_FALSE;		
	}
    agent->address.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)host->h_addr_list[0]));
	return HB_TRUE;
}

void check_heart_time(struct heartbeat_agent* agent)
{
	if(agent->heart_rece)
	{
		agent->heart_fail_count = 0;
		agent->heart_rece = HB_FALSE;
	}else
	{
		(agent->heart_fail_count >= MAX_HEART_BEAT_COUNT) ? (agent->heart_fail_count= MAX_HEART_BEAT_COUNT):agent->heart_fail_count++;
	}
}

void send_msg_to_ac(struct heartbeat_agent* agent)
{
	int sendbyte = 0;
	int size = CSTE_MAC_LEN;
	
	//printf("agent->address.sin_addr=%s\n",inet_ntoa(agent->address.sin_addr));
	sendbyte = sendto(agent->socket, agent->ap_mac, size, 0, (struct sockaddr *)&agent->address, sizeof(agent->address));
	if (sendbyte != size)
	{
		printf("send_response_to_ap:sent a different number of bytes than expected, send %d byte \n", sendbyte);
	}
	
	JobQueueAddJob(CHECK_HEART_INTERVAL,JOB_HEART_RESPONSE, check_heart_time, NULL, agent);
	return;
}

void send_udp_heart_beat(struct heartbeat_agent* agent)
{
	if(fill_in_remote_addr(agent,GATEWAY_AC))
	{
		send_msg_to_ac(agent);
	}
	
	return;
}

void ap_send_heart_beat(struct heartbeat_agent* agent)
{
	int interval = 0;
	
	send_udp_heart_beat(agent);
	//send_mqtt_heart_beat();
	
	//send_http_heart_beat();

	interval=HEART_BEAT_INTERVAL+(HEART_BEAT_INTERVAL * agent->heart_fail_count);
	JobQueueAddJob(interval, JOB_HEART_BEAT, ap_send_heart_beat, NULL, agent);
}

static int apAutoBroadcast(void)
{	
	char rspaction[TEMP_BUF_SIZE] = {0};

	memset(rspaction,0,sizeof(rspaction));
	sprintf(rspaction,"%s",ACTION_BROADCASTAP);
	broadcastResponse(rspaction);

	JobQueueAddJob(AUTO_BROADCAST_INTERVAL, JOB_HEART_BEAT, apAutoBroadcast, NULL, NULL);
}

int CreatPthread(void)
{
	pthread_mutex_init(&thd_mutex, NULL);
	if (pthread_create(&handerThread, NULL,HanderThread, NULL) !=0 ){
		printf("Create thread 2 error!\n");
		pthread_mutex_destroy(&thd_mutex);
		exit(1);
	}
	
	return 0;
}

int gethwaddr( char *interface, void *pAddr )
{
	struct ifreq ifr;
	int skfd, found=0;
	struct sockaddr_in *addr;
	skfd = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(ifr.ifr_name, interface);
	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
		close( skfd );
		return (0);
	}
	
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}

	close( skfd );
	return found;
}

int getDelayTimeByMac()
{
	long long int mac_int=0;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;

	gethwaddr("br0", (void *)&hwaddr );

	pMacAddr = (unsigned char *)hwaddr.sa_data;
	mac_int=((long long)(pMacAddr[0]&0x0ff) << 40 | (long long)(pMacAddr[1]&0x0ff) << 32 | (long long)(pMacAddr[2]&0x0ff) << 24 | (long long)(pMacAddr[3]&0x0ff) << 16 | (long long)(pMacAddr[4]&0x0ff) << 8 | (long long)(pMacAddr[5]&0x0ff));

	return mac_int%20;
}

int main(int argc, char** argv)
{
	
	if (!apmib_init()) 
	{		
		printf("cste_thinap:Initialize AP MIB failed !\n");
		return -1;	
	}
	
	int sleeptime=getDelayTimeByMac();		
	sleep(sleeptime);

	struct heartbeat_agent agent;
	MainInit(&agent);
	(void) signal(SIGTERM,MainGracefulExit);
	(void) signal(CSTE_BIND_SIG,cloudac_register);
	JobQueueInit();
	JobQueueDebug(J_FALSE);
	CreatPthread();
	if(!HeartBeatSockInit(&agent))
	{
		printf("manageAgent:Can't create heartbeat handle socket");
		exit(1);
	}
	
	if(!broadcastInit())
	{
		printf("broadcastInit:Can't create heartbeat handle socket\n");
		exit(1);
	}

	//printf("========self mac_str is %s========\n",agent.ap_mac_str);
	
	if(!JobQueueRegisterSocket(agent.socket,(void*)HeartBeatReceive,(void *)&agent))
	{
		printf("manageAgent:Can't register socket to job queue");
		exit(1);
	}
	
	if(!JobQueueRegisterSocket(broad_sk,(void*)HeartBroadcastReceive,(void *)&agent))
	{
		printf("heartbeatAgent:Can't register socket to job queue\n");
		exit(1);
	}
	
	ap_send_heart_beat(&agent);
	
	//apAutoBroadcast();

	while(gRun == J_TRUE) 
	{
		JobQueueExecutionLoop();
	}
	close(agent.socket);
	JobQueueDeleteAllJob();
	return 0;
}

