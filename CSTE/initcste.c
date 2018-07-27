#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <mystdlib.h>
#include "cstelib.h"


#if defined(SUPPORT_APAC)
void setRebootScheCfg()
{
	int sche;
	unsigned long cfg_sec,sec;	
	struct sysinfo info;
	char cmd[128];
	apmib_get(MIB_SCHE_DAY,(void *)&sche);
	if(sche>0){
		sysinfo(&info);
		sec = (unsigned long) info.uptime ;
		cfg_sec = sche * 86400-sec;
		if(cfg_sec>0){
			CsteSystem("killall sche_reboot", CSTE_PRINT_CMD);
			sprintf(cmd,"sche_reboot %ld &",(cfg_sec-sec));
			CsteSystem(cmd, CSTE_PRINT_CMD);
		}
	}else{
		CsteSystem("killall sche_reboot",CSTE_PRINT_CMD);
	}
	
	return ;	
}
#endif


void setHosts()
{
	struct in_addr lanaddr;
	char domain_name[32]={0};
	char str_cmd[128]={0};
	char str_lanIP[32]={0};
	apmib_get(MIB_DOMAIN_NAME,(void*)&domain_name);

	getIfIp("br0",str_lanIP);

	CsteSystem("echo >/etc/hosts", CSTE_PRINT_CMD);
	if(domain_name[0]){
		sprintf(str_cmd,"echo '%s	%s'>/etc/hosts", str_lanIP, domain_name);
	}else{
		sprintf(str_cmd,"echo '%s	%s%s	%s%s'>/etc/hosts", str_lanIP, "realtek", "AP.com|","realtek", "AP.net");
	}
	CsteSystem(str_cmd, CSTE_PRINT_CMD);

	return;
}

static int start_telnetd()
{
	char buff[128]={0},cmdbuff[128]={0};
	apmib_get(MIB_TELNET_PASSWORD,(void *)buff);
	if(strlen(buff)==0)
		strcpy(buff,"cs2012");
	sprintf(cmdbuff,"echo \"%s\" > /var/tmppwd",buff);
	system(cmdbuff);
	sprintf(cmdbuff,"echo \"%s\" >> /var/tmppwd",buff);
	system(cmdbuff);
	system("passwd < /var/tmppwd");
	system("rm -f /var/tmppwd");

	int telnet_enable;
	apmib_get(MIB_TELNET_ENABLED,(void *)&telnet_enable);
	system("killall telnetd 2> /dev/null");
	if(telnet_enable == 1)
		system("telnetd &");
	return 0;
}

#if	defined(SUPPORT_CS_TIME)
#define TIME_CONF_FILE	"var/time_conf"
#define MINUTE_NUM(hour,minute)  (hour*60+minute)
void init_time_conf(void)
{
	FILE  *fd = fopen(TIME_CONF_FILE, "w+");
	if (fd != NULL) 
	{
		unsigned int start=0,end=0,range=0,Enable=0,entryNum=0,i=0;
		unsigned int hour=0,minute=0,week=0;
		//reboot
#if defined(SUPPORT_SCHEDULE_REBOOT)
		apmib_get(MIB_REBOOTSCH_ENABLED,&Enable);
		if(Enable)
		{
			apmib_get(MIB_REBOOTSCH_HOUR,&hour);
			apmib_get(MIB_REBOOTSCH_HOUR,&minute);
			start = MINUTE_NUM(hour,minute);

			apmib_get(MIB_REBOOTSCH_WEEK,  (void *)&week);

			fprintf(fd, "config:reboot\n");
			fprintf(fd, "\tstart=%d\n", start);
			fprintf(fd, "\trange=%d\n", range);
			fprintf(fd, "\tweek=%d\n", week);
			fprintf(fd, "\tEnable=%d\n", Enable);
			fprintf(fd, "\thander=%s\n", "reboot");
			fprintf(fd, "\tparameter=%s\n", "{\\\"time_states\\\":\\\"\\\"}");
		}
#endif
		//Wireless
		SCHEDULE_T entry;
		apmib_get(MIB_WLAN_SCHEDULE_ENABLED, (void *)&Enable);
		if(Enable)
		{
			apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);
			for (i=1; i<=entryNum; i++) {
				*((char *)&entry) = (char)i;
				apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);

				hour= floor(entry.fTime/60.0);
				minute = entry.fTime %60;
				start = MINUTE_NUM(hour,minute);
				
				hour= floor(entry.tTime/60.0);
				minute = entry.tTime%60;
				end = MINUTE_NUM(hour,minute);
				
				range = end - start;
				week = entry.day;
					
				fprintf(fd, "config:wireless\n");
				fprintf(fd, "\tstart=%d\n", start);
				fprintf(fd, "\trange=%d\n", range);
				fprintf(fd, "\tweek=%d\n", week);
				fprintf(fd, "\tEnable=%d\n", Enable);
				fprintf(fd, "\thander=%s\n", "setCsTimeWifiSch");
				fprintf(fd, "\tparameter=%s\n", "{\\\"time_states\\\":\\\"\\\"}");
			}
		}
		fclose(fd);
	} 
	else
	{
		perror("fopen var/time_conf file");
	}
}
#endif

int main(int argc, char *argv[])
{
	printf("\n[initcste]Init system in cste...\n");
	
	if ( !apmib_init()) {
		printf("[initcste][%s:%d]Initialize AP MIB failed !\n",__FUNCTION__,__LINE__);
		return ;
	}

	setHosts();

#ifdef CONFIG_APP_CSTE_DEBUG
	CsteSystem("cp -rf /lib/cste_modules /var/", CSTE_PRINT_CMD);
#endif

	CsteSystem("killall cs_broker 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("cs_broker -c /etc/mosquitto.conf & 2> /dev/null", CSTE_PRINT_CMD);
	sleep(1);
	CsteSystem("killall cste_sub 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("cste_sub -h 127.0.0.1 -t totolink/router/+ &", CSTE_PRINT_CMD);

	CsteSystem("updateUI &",CSTE_PRINT_CMD);
	CsteSystem("/bin/lighttpd -f /lighttp/lighttpd.conf -m /lighttp/lib/ &",CSTE_PRINT_CMD);

#if defined(CONFIG_APP_STORAGE)
	int usb_onoff = 0;
	apmib_get(MIB_USB_ENABLE, (void *)&usb_onoff);
	if(usb_onoff)
		CsteSystem("insmod /lib/modules/3.10.9/kernel/drivers/usb/storage/usb-storage.ko", CSTE_PRINT_CMD);
#endif

#if defined(CONFIG_USER_VPND)
	CsteSystem("sysconf vpnd &", CSTE_PRINT_CMD);
#endif

	start_telnetd();

#if defined(SUPPORT_APAC)
	CsteSystem("killall hapc 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("hapc &", CSTE_PRINT_CMD);
	setRebootScheCfg();
	CsteSystem("killall mngTimer 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("mngTimer &", CSTE_PRINT_CMD);
#endif

//cs_thinap
#if defined(SUPPORT_CSTE_THINAP)
	CsteSystem("killall cs_thinap 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("cs_thinap &", CSTE_PRINT_CMD);
#endif

#if defined(SUPPORT_CLOUDAP)
	CsteSystem("killall cs_cloudap 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("cs_cloudap &", CSTE_PRINT_CMD);
#endif

#ifdef CONFIG_APP_CS_TIME
	init_time_conf();
	CsteSystem("/bin/cs_time &",CSTE_PRINT_CMD);
#endif


#if defined(CONFIG_KL_USER_DATA_PARTITION)
	//wait for erase user-data when mount
	while(1){
		RunSystemCmd("/proc/udwrite", "echo", "2", NULL_STR);
		sleep(1);
		if(getCmdVal("cat /proc/udwrite")==2){
			RunSystemCmd("/proc/udwrite", "echo", "1", NULL_STR);
			break;
		}
	}
#endif

#if defined(SUPPORT_MANAGEMENTAC)
	CsteSystem("killall cste_heartbeat > /dev/null 2>&1", CSTE_PRINT_CMD);
	CsteSystem("cste_heartbeat &", CSTE_PRINT_CMD);
#endif


	return 0;
}
