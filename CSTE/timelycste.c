#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define _PATH_PROCNET_DEV	"/proc/net/dev"
#define _PATH_DHCPS_LEASES	"/var/lib/misc/udhcpd.leases"
#define _DHCPD_PID_PATH 	"/var/run"
#define _DHCPD_PROG_NAME 	"udhcpd"

#define ALINK_SRV_BW_CHECK			"/var/alink/BwCheckUrl"

static int exit_flag=0;
static int BwCheck_flag=0;
static unsigned int time_count=1;
unsigned long long	DlSpeed=0;
unsigned long long	UlSpeed=0;
int prob_flag = 1;
int ProbedNum = 0;

/* getAttrProb use these definitions */
# define MAX_ATTRMAC_NUM 40
typedef struct attrmac_st {
    int  flag;
    char mac[18];
}macArr;
static macArr attrMac[MAX_ATTRMAC_NUM];


/*sendMsgtoALink use these definitions */
#define SER_BUFSIZ					512
#define KEY_T                       9375182604

struct msg_st{
    int msg_type;
    char some_text[SER_BUFSIZ];
}msgData;

enum msgType{
	ALISECURITY = 1,
	URLPROTECTINFO,
	PROBEDSWITCHSTATE,
	PROBEDNUM,
	PROBERINFO = 5,
	ACCESSATTACKSWITCHSTATE,
	ACCESSATTACKNUM,
	ACCESSATTACKERINFO,
	WLANSWITCHSTATE,
	FWDOWNLOADINFO = 10,
	FWUPGRADEINFO,
	WANDLSPEED,
	WANULSPEED,
	DLBWINFO,
	ULBWINFO = 15,
	WLANPAMODE,
	SPEEDUPSETTING,
	WLANSETTING24G,
	WLANSETTING5G,
	WLANSECURITY24G = 20,
	WLANSECURITY5G,
	WLANCHANNELCONDITION24G,
	WLANCHANNELCONDITION5G,
	TPSK,
	TPSKLIST= 25,
	RESETBINGDING,
	GETLANDEVEICE};
	
/* type define */
struct user_net_device_stats {
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
	unsigned long tx_multicast;	/* multicast packets transmitted   */
	unsigned long rx_unicast;	/* unicast packets received   */
	unsigned long tx_unicast;	/* unicast packets transmitted   */
	unsigned long rx_broadcast;	/* broadcast packets received   */
	unsigned long tx_broadcast;	/* broadcast packets transmitted   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;

    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
};


int alinkSetValtoFile(char *file, int mode, char *line_data)
{
    static char buf[512]={0};
    int fh=0;

    if(line_data==NULL)
        return 0;

    if(mode == 1) {/* write line datato file */
        fh = open(file, O_RDWR|O_CREAT|O_TRUNC);
    }else if(mode == 2){/*append line data to file*/
        fh = open(file, O_RDWR|O_APPEND);
    }

    if (fh < 0) {
        fprintf(stderr, "Create %s error!\n", file);
        return 0;
    }
	flock(fh, LOCK_EX);
    sprintf(buf, "%s", line_data);
    write(fh, buf, strlen(buf));
    close(fh);
	flock(fh, LOCK_UN);
    return 1;
}

char *alinkGetValByFile(const char *file)
{
    static char szValue[512]={0};
    FILE *fp;
	int fh;
    char *p;

    memset((char *)szValue, '\0', sizeof(szValue));

    fp = fopen( file, "r");
    if(fp != NULL)
    {
    	fh=fileno(fp);
		flock(fh, LOCK_EX);
        while(fgets(szValue, 512, fp) != NULL)
        {
            if(p=strstr(szValue, "\n"))
                p[0]='\0';
        }
        fclose(fp);
		flock(fh, LOCK_UN);
    }

    return szValue;
}

void sendMsgtoALink(int msg_type, char *msg_data)
{
    struct msg_st some_data;
    int msgid;

    msgid = msgget((key_t)KEY_T,0666|IPC_CREAT);
    if(msgid == -1){
        perror("msgget failed\r\n");
        return;
    }

    if((strlen(msg_data)+1)>SER_BUFSIZ){
        perror("buffer insufficent\r\n");
        return;
    }

    some_data.msg_type = msg_type;
    strcpy(some_data.some_text, msg_data);
    if(msgsnd(msgid, (void *)&some_data, SER_BUFSIZ, IPC_NOWAIT) == -1){
        perror("msgsnd failed\r\n");
        return;
    }

	return;
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

int CalculateWanSpeed()
{
	static char tmp_dl[32], tmp_ul[32];

    struct user_net_device_stats stats;
	static unsigned long long old_wanRx, old_wanTx;
	unsigned long long curr_wanRx,curr_wanTx;
	
	//printf("[%s %d]~~ wan: old_wanRx(%lld) old_wanTx(%lld)\n", __FUNCTION__,__LINE__, old_wanRx, old_wanTx);
	if ( getStats("eth1", &stats) < 0){//what about repeater interface???
		curr_wanRx = 0;
		curr_wanTx = 0;
	}else{
		curr_wanRx = stats.rx_bytes;
		curr_wanTx = stats.tx_bytes;
	}
	//printf("[%s %d]~~ wan: curr_wanRx(%lld) curr_wanTx(%lld)\n", __FUNCTION__,__LINE__, curr_wanRx, curr_wanTx);	

	DlSpeed = (curr_wanRx-old_wanRx)/8;
	UlSpeed = (curr_wanTx-old_wanTx)/8;
	old_wanTx = curr_wanTx;
	old_wanRx = curr_wanRx;

	memset(tmp_dl, 0, sizeof(tmp_dl));
	memset(tmp_dl, 0, sizeof(tmp_ul));
	sprintf(tmp_dl, "%llu", DlSpeed);
	sprintf(tmp_ul, "%llu", UlSpeed);
	sendMsgtoALink(WANDLSPEED, tmp_dl);
	sendMsgtoALink(WANULSPEED, tmp_ul);

    return 0;
}

static int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime, char *hsnm)
{
	struct dhcpOfferedAddr {
    	u_int8_t chaddr[16];
    	u_int32_t yiaddr;       /* network order */
    	u_int32_t expires;      /* host order */
		char hostname[64];
		u_int32_t isUnAvailableCurr;
	};

	struct dhcpOfferedAddr entry;
	 u_int8_t empty_haddr[16]; 
    	int len;
		
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
	snprintf(mac, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
			entry.chaddr[0],entry.chaddr[1],entry.chaddr[2],entry.chaddr[3],
			entry.chaddr[4], entry.chaddr[5]);
	if(entry.expires == 0xffffffff)
        	sprintf(liveTime,"%s", "Always");
        else
		snprintf(liveTime, 10, "%lu", (unsigned long)ntohl(entry.expires));

	memset(hsnm, 0, 64);
	len = strlen(entry.hostname);
	if(len == 0)
		strcpy(hsnm, "Unknown");
	else if(len >15)
		strncpy(hsnm, entry.hostname, 15);
	else
		strcpy(hsnm, entry.hostname);
	
	return 1;
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

int reportLanDeveice()
{
	int pid, ret=0, onoff=1;
	FILE *fp;
	char tmpBuf[128], ipAddr[16], macAddr[18], liveTime[32], hostname[64];
	char *buf=NULL, *ptr;
	struct stat status;
	unsigned long fileSize=0;

	//siganl DHCP server to update lease file
	memset(tmpBuf, 0, sizeof(tmpBuf));
	snprintf(tmpBuf, 128, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmpBuf);
	memset(tmpBuf, 0, sizeof(tmpBuf));
	snprintf(tmpBuf, 128, "kill -SIGUSR1 %d\n", pid);
	if ( pid > 0)	system(tmpBuf);
	usleep(1000);
	if ( stat(_PATH_DHCPS_LEASES, &status) < 0 )	goto err;

	fileSize=status.st_size;
	buf = malloc(fileSize);
	if ( buf == NULL )	goto err;

	fp = fopen(_PATH_DHCPS_LEASES, "r");
	if ( fp == NULL )	goto err;
	fread(buf, 1, fileSize, fp);
	fclose(fp);

	ptr = buf;
	while(1){
		ret = getOneDhcpClient(&ptr, &fileSize, ipAddr, macAddr, liveTime, hostname);
		if (ret < 0)	break;
		if (ret == 0)	continue;
		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "##%d##%s##%s##%s", onoff, ipAddr, macAddr, hostname);
		sendMsgtoALink(GETLANDEVEICE, tmpBuf);
	}

err:
    if (buf)
        free(buf);

	return 0;
}

void CalculateProbNumAndInfo()
{
    static char szMac[32]={0};
    FILE *fp0, *fp1;
    char *p;
	int count = 0, i = 0, exits = 0, idx = 0;
	static char probStr[16] = {0};

    fp0 = fopen( "/proc/wlan0/historyAuthMac", "r");
    if(fp0 != NULL)
    {
        while(fgets(szMac, 32, fp0) != NULL)
        {
            if(p=strstr(szMac, "\n"))
                p[0]='\0';
            //printf("[%s %d] szMac=%s \n", __FUNCTION__,__LINE__,szMac);
            if(!strcmp(szMac, "00:00:00:00:00:00")||!strcmp(szMac, "HistoryMAC:"))
            {
                continue;
            }else{
                for(i=0; i<MAX_ATTRMAC_NUM; i++)
                {
                    if(attrMac[i].flag==1)
                        idx++;
                    if(!strcmp(attrMac[i].mac, szMac))
                    {
                        exits=1;
                        break;
                    }
                        
                }
                count++;
                if(exits==1){
                    exits=0;
                    continue;
                }
                else
                {
                    sprintf(attrMac[idx].mac, "%s", szMac);
                    attrMac[idx].flag=1;
                    sendMsgtoALink(PROBERINFO, szMac);
                }
            }
        }
        fclose(fp0);
    }

#ifdef FOR_DUAL_BAND
    fp1 = fopen( "/proc/wlan1/historyAuthMac", "r");
    if(fp1 != NULL)
    {
        while(fgets(szMac, 32, fp1) != NULL)
        {
            if(p=strstr(szMac, "\n"))
                p[0]='\0';
            //printf("[%s %d] szMac=%s \n", __FUNCTION__,__LINE__,szMac);
            if(!strcmp(szMac, "00:00:00:00:00:00")||!strcmp(szMac, "HistoryMAC:"))
            {
                continue;
            }else{
                for(i=0; i<MAX_ATTRMAC_NUM; i++)
                {
                    if(attrMac[i].flag==1)
                        idx++;
                    if(!strcmp(attrMac[i].mac, szMac))
                    {
                        exits = 1;
                        break;
                    }
                }
                count++;
                if(exits == 1){
                    exits = 0;
                    continue;
                }
                else
                {
                    sprintf(attrMac[idx].mac, "%s", szMac);
                    attrMac[idx].flag = 1;
                    sendMsgtoALink(PROBERINFO, szMac);
                }
            }
        }
        fclose(fp1);
    }
#endif

    ProbedNum += count;
	sprintf(probStr, "%d", ProbedNum);
	sendMsgtoALink(PROBEDNUM, probStr);

    return;
}

int reportBwInfo()
{
	long lBwInfo=0;
	char cBwInfo[32];
	FILE *pf = NULL;

	if((pf = fopen("/tmp/dlbwinfo","r+"))!= NULL){
		fscanf(pf,"%ld",&lBwInfo);
		fclose(pf);
	}
	
	memset(cBwInfo,0,sizeof(cBwInfo));
	sprintf(cBwInfo,"%ld",lBwInfo);
	
	sendMsgtoALink(DLBWINFO, cBwInfo);
	sendMsgtoALink(ULBWINFO, "0");
	return 0;
}

void detectSysOp()
{
	FILE *pf = NULL;
	int sysOp=0;

	if((pf = fopen("/var/sys_op","r+"))!= NULL){
		fscanf(pf,"%d",&sysOp);
		fclose(pf);
	}
	if(sysOp==1){//0:gw 1:br 2:wisp
		exit_flag=1;
		system("killall -9 alink > /dev/null 2>&1");
	}

	return;
}

void detectAlinkProcess()
{
	FILE *ptr;
	char *p;
	char buff[32];

	if((ptr=popen("ps -ef | grep alink | grep -v grep | wc -l", "r")) != NULL)
	{
		memset(buff,0,sizeof(buff));
		while (fgets(buff, 32, ptr) != NULL)
		{
			if(p=strstr(buff, "\n"))	p[0]='\0';
        	if(atoi(buff)==0)
			{
				pclose(ptr);
				exit_flag=1;				
				return;
			}
		}
		pclose(ptr);
	}

	return;
}

void timely_handler()
{
	//printf("[%s %d] ~~~~~ time_count=[%d] ~~~~~\n",__FUNCTION__,__LINE__,time_count);
	if(BwCheck_flag)
	{
		reportBwInfo();
	}

	if(!(time_count%8))
 	{
		CalculateWanSpeed();
	}

	if(!(time_count%20))
 	{
		detectSysOp();
		detectAlinkProcess();
	}

	if(!(time_count%18))
 	{
		reportLanDeveice();
	}

	if(prob_flag && !(time_count%33))
	{
		CalculateProbNumAndInfo();
	}

	time_count++;

	if(time_count==604800)//Ò»ÖÜ
		time_count=1;
	
	alarm(1);
}

void onBwCheck_handler()
{
	BwCheck_flag=1;
	char cmd[128], url[128];
	memset(cmd, 0, sizeof(url));
	memset(url, 0, sizeof(url));
	sprintf(url, "%s", alinkGetValByFile(ALINK_SRV_BW_CHECK));
	sprintf(cmd, "wget -O /dev/null %s &", url);
	system(cmd);
}

void offBwCheck_handler()
{
	BwCheck_flag=0;
	system("killall -9 wget > /dev/null 2>&1");
}

void onProb_handler()
{
	prob_flag = 1;
}

void offProb_handler()
{
	prob_flag = 0;
}

void exit_handler()
{
	char str_buff[16]={0};
	sprintf(str_buff, "%d", ProbedNum);
	alinkSetValtoFile("/var/alink/ProbedNum", 1, str_buff);
	exit_flag=1;
}

int main(int argc, char** argv)
{

	char buff[16] = {0};
	strcpy(buff, alinkGetValByFile("/var/alink/ProbedNum"));
	ProbedNum = atoi(buff);
	sendMsgtoALink(PROBEDNUM, buff);

	signal(SIGALRM,timely_handler);
	signal(51,exit_handler);
	signal(58,onBwCheck_handler);
	signal(59,offBwCheck_handler);
	signal(60,onProb_handler);
	signal(61,offProb_handler);
	alarm(1);

	while(!exit_flag){
		sleep(3);
	}

	return 0;
}

