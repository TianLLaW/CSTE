/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/wireless.h>
#include <netdb.h> 
#include <setjmp.h> 
#include <sys/wait.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <assert.h>
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include "cste.h"
#include "cstelib.h"

#include "apmib.h"
#include "mibtbl.h"

#define FILE_DIR_LEN 256
#ifdef CONFIG_APP_CSTE_DEBUG
#define CSTE_MODULE_PATH "/var/cste_modules/"
#else
#define CSTE_MODULE_PATH "/lib/cste_modules/"
#endif
void *flib;
int (*pfunc)();
char *error_message;

bool process_messages = true;
int msg_count = 0;

int wps_status=4;
#if defined(SUPPORT_MESH)
int smartmesh_MID=0;
#endif

static int unknowTopic(struct mosquitto *mosq, char *tp)
{
    websGetCfgResponse(mosq,tp,"{\"error\":\"Unknow Topic\"}");
    return 0;
}
int get_action(char* topic, char* action)
{
    int i;
    for(i=strlen(topic);i>1;i--){
        if(topic[i]=='/'){
            strcpy(action,&topic[i+1]);
            break;
        }
    }
    return strlen(action);
}

int mqtt_process_publish_msg(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    char action[64]={0};
    int  found=0, ret=0;

    cJSON *root = cJSON_Parse(message->payload);
    if(!root){
        printf("[%s][%d] cJSON_Parse error!\n[%s]\n",__FUNCTION__,__LINE__,message->payload);
        return -1;
    }
    
    get_action(message->topic, action);
	if(!strcmp(action,"R")){
		goto End_label;
	}

	CSTE_DEBUG("[%s]%s\n",action,message->payload);
	
    tag_mqtt_func_list  *curhook;
    curhook = first_cste_hook;
    while (NULL != curhook) {
        if(0==strcmp(action,curhook->name)){
            ret =(*curhook->func)(mosq,root,message->topic);
            found = 1;
            break;  
        }
        
        ret = -1;
        curhook = curhook->next;
    }

    if(1 != found)
    {
		printf("*********%s[%d]**Unknown module:[%s]!********\n", __FUNCTION__, __LINE__, action);
		ret =unknowTopic(mosq, message->topic);
    }

End_label:
    cJSON_Delete(root);

    return 0;
}

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct mosq_config *cfg;
	int i;
	bool res;

	if(process_messages == false) return;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(message->retain && cfg->no_retain) return;
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			mosquitto_topic_matches_sub(cfg->filter_outs[i], message->topic, &res);
			if(res) return;
		}
	}
#if 0
	if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			fwrite(message->payload, 1, message->payloadlen, stdout);
			if(cfg->eol){
				printf("\n");
			}
		}else{
			if(cfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}else{
		if(message->payloadlen){
			fwrite(message->payload, 1, message->payloadlen, stdout);
			if(cfg->eol){
				printf("\n");
			}
			fflush(stdout);
		}
	}
#endif
	if(cfg->msg_count>0){
		msg_count++;
		if(cfg->msg_count == msg_count){
			process_messages = false;
			mosquitto_disconnect(mosq);
		}
	}

	mqtt_process_publish_msg(mosq, obj, message);
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	int i;
	struct mosq_config *cfg;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(!result){
		for(i=0; i<cfg->topic_count; i++){
			mosquitto_subscribe(mosq, NULL, cfg->topics[i], cfg->qos);
		}
	}else{
		if(result && !cfg->quiet){
			fprintf(stderr, "%s\n", mosquitto_connack_string(result));
		}
	}
}

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	struct mosq_config *cfg;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(!cfg->quiet) printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
	for(i=1; i<qos_count; i++){
		if(!cfg->quiet) printf(", %d", granted_qos[i]);
	}
	if(!cfg->quiet) printf("\n");
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

void print_usage(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("cste_sub is a simple mqtt client that will subscribe to a single topic and print all messages it receives.\n");
	//printf("cste_sub version %s running on libmosquitto %d.%d.%d.\n\n", VERSION, major, minor, revision);
	printf("Usage: cste_sub [-c] [-h host] [-k keepalive] [-p port] [-q qos] [-R] -t topic ...\n");
	printf("                     [-C msg_count] [-T filter_out]\n");
#ifdef WITH_SRV
	printf("                     [-A bind_address] [-S]\n");
#else
	printf("                     [-A bind_address]\n");
#endif
	printf("                     [-i id] [-I id_prefix]\n");
	printf("                     [-d] [-N] [--quiet] [-v]\n");
	printf("                     [-u username [-P password]]\n");
	printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
#ifdef WITH_TLS
	printf("                     [{--cafile file | --capath dir} [--cert file] [--key file]\n");
	printf("                      [--ciphers ciphers] [--insecure]]\n");
#ifdef WITH_TLS_PSK
	printf("                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]\n");
#endif
#endif
#ifdef WITH_SOCKS
	printf("                     [--proxy socks-url]\n");
#endif
	printf("       cste_sub --help\n\n");
	printf(" -A : bind the outgoing socket to this host/ip address. Use to control which interface\n");
	printf("      the client communicates over.\n");
	printf(" -c : disable 'clean session' (store subscription and pending messages when client disconnects).\n");
	printf(" -C : disconnect and exit after receiving the 'msg_count' messages.\n");
	printf(" -d : enable debug messages.\n");
	printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
	printf(" -i : id to use for this client. Defaults to mosquitto_sub_ appended with the process id.\n");
	printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
	printf("      broker is using the clientid_prefixes option.\n");
	printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
	printf(" -N : do not add an end of line character when printing the payload.\n");
	printf(" -p : network port to connect to. Defaults to 1883.\n");
	printf(" -P : provide a password (requires MQTT 3.1 broker)\n");
	printf(" -q : quality of service level to use for the subscription. Defaults to 0.\n");
	printf(" -R : do not print stale messages (those with retain set).\n");
#ifdef WITH_SRV
	printf(" -S : use SRV lookups to determine which host to connect to.\n");
#endif
	printf(" -t : mqtt topic to subscribe to. May be repeated multiple times.\n");
	printf(" -T : topic string to filter out of results. May be repeated.\n");
	printf(" -u : provide a username (requires MQTT 3.1 broker)\n");
	printf(" -v : print published messages verbosely.\n");
	printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
	printf("      Can be mqttv31 or mqttv311. Defaults to mqttv31.\n");
	printf(" --help : display this message.\n");
	printf(" --quiet : don't print error messages.\n");
	printf(" --will-payload : payload for the client Will, which is sent by the broker in case of\n");
	printf("                  unexpected disconnection. If not given and will-topic is set, a zero\n");
	printf("                  length message will be sent.\n");
	printf(" --will-qos : QoS level for the client Will.\n");
	printf(" --will-retain : if given, make the client Will retained.\n");
	printf(" --will-topic : the topic on which to publish the client Will.\n");
#ifdef WITH_TLS
	printf(" --cafile : path to a file containing trusted CA certificates to enable encrypted\n");
	printf("            certificate based communication.\n");
	printf(" --capath : path to a directory containing trusted CA certificates to enable encrypted\n");
	printf("            communication.\n");
	printf(" --cert : client certificate for authentication, if required by server.\n");
	printf(" --key : client private key for authentication, if required by server.\n");
	printf(" --ciphers : openssl compatible list of TLS ciphers to support.\n");
	printf(" --tls-version : TLS protocol version, can be one of tlsv1.2 tlsv1.1 or tlsv1.\n");
	printf("                 Defaults to tlsv1.2 if available.\n");
	printf(" --insecure : do not check that the server certificate hostname matches the remote\n");
	printf("              hostname. Using this option means that you cannot be sure that the\n");
	printf("              remote host is the server you wish to connect to and so is insecure.\n");
	printf("              Do not use this option in a production environment.\n");
#ifdef WITH_TLS_PSK
	printf(" --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.\n");
	printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#endif
#endif
#ifdef WITH_SOCKS
	printf(" --proxy : SOCKS5 proxy URL of the form:\n");
	printf("           socks5h://[username[:password]@]hostname[:port]\n");
	printf("           Only \"none\" and \"username\" authentication is supported.\n");
#endif
	printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

int load_customSo()
{
	char path[128];
	int result=0;
	
	strcpy(path,"/tmp/custom_module/custom.so");

    flib = dlopen(path, RTLD_LAZY);
    error_message = dlerror();

    if(error_message)
    {   
       // printf("[%s:%d]Error:%s!Can not load %s\n",__FUNCTION__,__LINE__, error_message,path);
        return (-1);
    }
    
    //找到模块中的module_init函数
    pfunc = dlsym(flib, "module_init");
    error_message = dlerror();
    if(error_message)
    {
		printf("[%s:%d]Error:%s!Can not open the function:module_init\n",__FUNCTION__,__LINE__, error_message);
        return (-1);
    }

    //执行module_init函数
    result = pfunc();
    CSTE_DEBUG("%s load result is: %d\n",path, result);

}


/*加载所有的子模块*/
int load_modules()
{
    char path[FILE_DIR_LEN]=CSTE_MODULE_PATH;
    DIR *dir = opendir(CSTE_MODULE_PATH);
    if(dir == NULL) 
        printf("[cste]we cannot open the path:%s\n",CSTE_MODULE_PATH);

    struct dirent *ent;
    int result = 0;
    char *name = (char *)malloc(sizeof(char)*FILE_DIR_LEN);
    //tag_mqtt_funct *modulelist;
	if ( !apmib_init()) {//RTL
		printf("Initialize AP MIB failed !\n");
		free(name);
		closedir(dir);
		return -1;
	}
	
    //while 循环遍历/lib/cste_modules/下的动态库
    while((ent=readdir(dir)) != NULL)
    {
        if(!strcmp(ent->d_name,".")||!strncmp(ent->d_name,"..",2))
            continue;

        //文件中要包含lib和.so
        if(!strstr(ent->d_name,".so"))
            continue;

        struct stat st;
        memset(name,'\0',sizeof(char)*FILE_DIR_LEN);
        strcpy(name,CSTE_MODULE_PATH);
        strcat(name,"/");
        strcat(name,ent->d_name);

        int f=stat(name,&st);
        if(f == -1)
        {
            switch(errno)
            {
                case EACCES: puts("EACCES");break;
                case EBADF: puts("EBADF");break;
                case EFAULT: puts("EFAULT");break;
                case ENOENT: puts("ENOENT");break;
                case ENOMEM: puts("ENOMEM");break;
                case ENOTDIR: puts("ENOTDIR");break;  
            }
        }

        //如果不是目录是文件
        if(!S_ISDIR(st.st_mode)) 
        {
            sprintf(path,"%s%s",CSTE_MODULE_PATH,ent->d_name);
            flib = dlopen(path, RTLD_LAZY);
            error_message = dlerror();

            if(error_message)
            {   
                CSTE_DEBUG("%s\n", error_message);
                CSTE_DEBUG("cannot load %s\n", path);
				continue;
            }
            
            //找到模块中的module_init函数
            pfunc = dlsym(flib, "module_init");
            error_message = dlerror();
            if(error_message)
            {
                CSTE_DEBUG("cannot open the function func:module_init\n");
				continue;
            }

            //执行module_init函数
            result = pfunc();
            CSTE_DEBUG("%s load result is: %d\n",path, result);
        }
            
    }

	free(name);
	closedir(dir);
	
    return 0;
}

static void sig_child(int signo)
{
	pid_t pid;
	int   stat;
	//处理僵尸进程
	while ((pid = waitpid(-1, &stat, WNOHANG)) >0){
		CSTE_DEBUG("[Debug]cste_sub child %d terminated.\n", pid);
		return;
	}
}

#if defined(WLAN_PROFILE)
int addWlProfileHandler(char *tmpBuf, int wlan_id)
{
	__FUNC_IN__;
	CSTE_DEBUG("tmpBuf=%s wlan_idx=%d\n", tmpBuf, wlan_idx);
	__FUNC_OUT__;
	return 0;
}
#endif
#define REINIT_WEB_FILE	"/tmp/reinit_web"
static void sig_reinit(int signo)
{
	return ;
	__FUNC_IN__;
	CSTE_DEBUG("int signo=%d wlan_idx=%d\n", signo, wlan_idx);
	struct stat status;
	int reinit=1;

	if (stat(REINIT_WEB_FILE, &status) == 0) { // file existed
		unlink(REINIT_WEB_FILE);
		reinit = 0;		
	}

	if (reinit) { // re-init system
#if defined(WLAN_PROFILE)
		int profile_enabled_id, profileEnabledVal, wlan_mode;
		if(wlan_idx == 0)
			profile_enabled_id = MIB_PROFILE_ENABLED1;
		else
			profile_enabled_id = MIB_PROFILE_ENABLED2;
		apmib_get( profile_enabled_id, (void *)&profileEnabledVal);
		apmib_get(MIB_WLAN_MODE, (void *)&wlan_mode);
		if((profileEnabledVal == 1) && (wlan_mode == CLIENT_MODE))
		{
			char tmpBuf[128]="wps_client_profile";
			addWlProfileHandler(tmpBuf, wlan_idx);
			apmib_update(CURRENT_SETTING);
		}
		run_init_script("all");
#endif
	}
	
	apmib_reinit();
	__FUNC_OUT__;
}

void register_signal(void)
{
    signal(SIGCHLD, sig_child);
		
	signal(SIGUSR1, sig_reinit);
}

#define CSTE_SUB_PID_FILE "/var/run/cste_sub.pid"
int main(int argc, char *argv[])
{
	struct mosq_config cfg;
	struct mosquitto *mosq = NULL;
	int rc;
	pid_t pid_cste_sub;

	pid_cste_sub=getpid();
	CSTE_DEBUG("pid_cste_sub=[%d]\n", pid_cste_sub);
	FILE_ENTRY_T *PID_FILE = fopen(CSTE_SUB_PID_FILE, "w");
	if (PID_FILE != NULL) 
	{
		fprintf(PID_FILE, "%d\n", pid_cste_sub);
		fclose(PID_FILE);
	} 
	else 
	{
		perror("fopen pid file");
	}
	
	rc = client_config_load(&cfg, CLIENT_SUB, argc, argv);
	if(rc){
		client_config_cleanup(&cfg);
		if(rc == 2){
			/* --help */
			print_usage();
		}else{
			fprintf(stderr, "\nUse 'cste_sub --help' to see usage.\n");
		}
		return 1;
	}

	hook_list_init();
	load_modules();
	load_customSo();
	register_signal();
	mosquitto_lib_init();

	if(client_id_generate(&cfg, "mosqsub")){
		return 1;
	}

	mosq = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!mosq){
		switch(errno){
			case ENOMEM:
				if(!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
				break;
			case EINVAL:
				if(!cfg.quiet) fprintf(stderr, "Error: Invalid id and/or clean_session.\n");
				break;
		}
		mosquitto_lib_cleanup();
		return 1;
	}
	if(client_opts_set(mosq, &cfg)){
		return 1;
	}
	if(cfg.debug){
		mosquitto_log_callback_set(mosq, my_log_callback);
		mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
	}
	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_message_callback_set(mosq, my_message_callback);

	rc = client_connect(mosq, &cfg);
	if(rc) return rc;


	rc = mosquitto_loop_forever(mosq, -1, 1);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN){
		rc = 0;
	}
	if(rc){
		fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
	}
	if(!cfg.id){
		free(cfg.id);
	}
	return rc;
}

