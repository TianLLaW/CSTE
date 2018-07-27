/*
  
   support CLOUDUPDATE  by CaryStudio  20150920
  
*/
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <linux/if.h>
#include <fcntl.h>

#include "cloudupdate.h"


int CloudSrvVersionCheck(struct mosquitto *mosq, cJSON* data, char *tp)
{
	cJSON *root;
	char *output, cloudFwStatus[64]={0}, buff[512]={0}, new_version[32]={0};

	root=cJSON_CreateObject();

	//Network & update ing
	if ( !tcpcheck_net( "114.114.114.114", 53, 2) && !tcpcheck_net( "www.qq.com", 80, 2))
	{
		cJSON_AddStringToObject(root, "cloudFwStatus", "UnNet");
		goto err;
	}
	if ( 0 != f_exist("/tmp/update_flag") )
	{
		cJSON_AddStringToObject(root, "cloudFwStatus", "Update");
		goto err;
	}
	
	CsteSystem("echo 3 > /proc/sys/vm/drop_caches", CSTE_PRINT_CMD);
	CsteSystem("killall cs_cloudfwcheck 1>/dev/null 2>&1", CSTE_PRINT_CMD);
	CsteSystem("/bin/cs_cloudfwcheck", CSTE_PRINT_CMD);

	sleep(1);
	
	f_read("/tmp/cloudFwStatus", cloudFwStatus, 0, sizeof(cloudFwStatus));
	cJSON_AddStringToObject(root, "cloudFwStatus", cloudFwStatus);

	f_read("/tmp/newVersion", new_version, 0, sizeof(new_version));
	cJSON_AddStringToObject(root, "newVersion", new_version);

err:
	output =cJSON_Print(root);
	CSTE_DEBUG("CloudSrvVersionCheck: output = %s \n", output);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int module_init()
{
	cste_hook_register("CloudSrvVersionCheck",CloudSrvVersionCheck);
	return 0;
}
