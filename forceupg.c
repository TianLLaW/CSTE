#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/ioctl.h>

#include <assert.h>
#include <mosquitto.h>
#include <cJSON.h>
#include <cs_comm.h>

#include "apmib.h"
#include "mibdef.h"
#include "mibtbl.h"
#include "sigHd.h"
#include "cstelib.h"

static int forceupg_help( void )
{
	printf("Usage: \n");
	printf("forceupg aprule[1,2] time[0-86400] \n");

	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 3)
	{
		forceupg_help();
		return 0;
	}
	printf("[dbg]Enter forceupg!\n");
	
	int mode,upg_time,cur_time;
	if ( !apmib_init()) {		
		printf("forceupg Initialize MIB failed !\n");
		return 0;	
	}

	mode=atoi(argv[1]);
	upg_time=atoi(argv[2]);
	if(mode==1)
	{
		sleep(upg_time);
		safe_cs_pub("127.0.0.1", "CloudACMunualUpdate","{}");
	}
	else if(mode==2)
	{
		struct tm tmp,tm_time;
		while(1)
		{
			time(&tmp);
			memcpy(&tm_time, localtime(&tmp), sizeof(tm_time));
			cur_time=tm_time.tm_hour*60*60+tm_time.tm_min*60+tm_time.tm_sec;
			if(cur_time < upg_time && cur_time+10 > upg_time )
			{
				safe_cs_pub("127.0.0.1", "CloudACMunualUpdate","{}");
				break;
			}
			sleep(5);
		}
	}
	else
	{
		
	}
	
	return 0;
}
