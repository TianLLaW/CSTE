/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file Usb.c
* @author CaryStudio
* @brief  This is a usb cste topic
* @date 2017-11-14
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

#include "usb.h"

#define DLNA_CONFIG_FILE "/etc/minidlna.conf"
#define Tsize (1024.00*1024.00*1024.00)
#define Gsize (1024.00*1024.00)
#define Msize 1024.00
/**
* @note getUsbStorageCfg  get Usb Storage configuration
*
* @param NULL
* @return return Json Data
<pre>
{
	"smbEnabled":	""
	"dlnaEnabled":	""
}
return parameter description:
"smbEnabled":	Switch of samba,0 is OFF,1 is ON
"dlnaEnabled":	Switch of DLNA,0 is OFF,1 is ON
</pre>
*@author		Kris
*@date	2017-11-14
*/

int getUsbStorageCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output;
	cJSON *root=cJSON_CreateObject();
	int intVal;
#if 0	
	char tmp[256]={0},buf[256],*pstr1=NULL,*pstr2=NULL;
   	if(access("/sys/class/usbmisc/lp0/device/ieee1284_id", F_OK)==0){
		FILE *fp = fopen("/sys/class/usbmisc/lp0/device/ieee1284_id", "r");
		if(fp){
			fgets(buf, sizeof(buf), fp);
			pstr1=strstr(buf,"MDL:");
			if(pstr1!=NULL){
				pstr2=strchr(pstr1,';');
				if(pstr2!=NULL){
					*pstr2='\0';
					memset(tmp,0,sizeof(tmp));
					strcpy(tmp,pstr1+4);
				}else{
					strcpy(tmp,"No find printer");
				}
			}else{
				strcpy(tmp,"No find printer");
			}
			fclose(fp);
		}
   	}else{
   		strcpy(tmp,"No find printer");
   	}	

	apmib_get(MIB_FTP_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root, "FtpEnabled", intVal);
	apmib_get(MIB_FTP_USERNAME, (void *)tmp);
	cJSON_AddStringToObject(root, "FtpUserName", tmp);
	apmib_get(MIB_FTP_PASSWORD, (void *)tmp);
	cJSON_AddStringToObject(root, "FtpPassword", tmp);

	apmib_get(MIB_PRINTER_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root, "PrinterEnabled", intVal);
	cJSON_AddStringToObject(root, "PrinterName", tmp);
	
	apmib_get(MIB_DLNA_SERVERNAME, (void *)tmp);
	cJSON_AddStringToObject(root, "DlnaServerName", tmp);
	
	apmib_get(MIB_SAMBA_USERNAME, (void *)tmp);
	cJSON_AddStringToObject(root, "SmbUserName", tmp);
	apmib_get(MIB_SAMBA_PASSWORD, (void *)tmp);
	cJSON_AddStringToObject(root, "SmbPassword", tmp);
#endif

	apmib_get(MIB_SAMBA_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root, "SmbEnabled", intVal);

	apmib_get(MIB_DLNA_ENABLED, (void *)&intVal);
	cJSON_AddNumberToObject(root, "DlnaEnabled", intVal);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}
/**
* @note setUsbStorageCfg  set Usb Storage configuration
* @param Setting Json Data
<pre>
{
	"dlnaEnabled":	"0"
	"smbEnabled":	"0"
}
setting parameter description
"dlnaEnabled":	Switch of DLNA,0 is OFF,1 is ON
"smbEnabled":	Switch of samba,0 is OFF,1 is ON
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-14
*/

int setUsbStorageCfg(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int orig_dlna_enabled,orig_smb_enabled;
#if 0
	int printer_enabled = atoi(websGetVar(data, T("PrinterEnabled"), T("0")));
	int ftp_enabled = atoi(websGetVar(data, T("FtpEnabled"), T("0")));
	char *ftp_username = websGetVar(data, T("FtpUserName"), T(""));
	char *ftp_passwd = websGetVar(data, T("FtpPassword"), T(""));
	char *dlna_servername = websGetVar(data, T("DlnaServerName"), T(""));
	char *smb_username = websGetVar(data, T("SmbUserName"), T(""));
	char *smb_passwd = websGetVar(data, T("SmbPassword"), T(""));
#endif
	int dlna_enabled = atoi(websGetVar(data, T("DlnaEnabled"), T("0")));
	int smb_enabled = atoi(websGetVar(data, T("SmbEnabled"), T("0")));

#if 0
	apmib_set(MIB_PRINTER_ENABLED,(void *)&printer_enabled);
	apmib_set(MIB_FTP_ENABLED,(void *)&ftp_enabled);
	apmib_set(MIB_FTP_USERNAME,(void *)ftp_username);
	apmib_set(MIB_FTP_PASSWORD,(void *)ftp_passwd);
	apmib_set(MIB_DLNA_SERVERNAME,(void *)dlna_servername);
	apmib_set(MIB_SAMBA_USERNAME,(void *)smb_username);
	apmib_set(MIB_SAMBA_PASSWORD,(void *)smb_passwd);
#endif

	apmib_get(MIB_DLNA_ENABLED, (void *)&orig_dlna_enabled);
	apmib_get(MIB_SAMBA_ENABLED, (void *)&orig_smb_enabled);

	apmib_set(MIB_DLNA_ENABLED,(void *)&dlna_enabled);
	apmib_set(MIB_SAMBA_ENABLED,(void *)&smb_enabled);	
	apmib_update_web(CURRENT_SETTING);

	if (orig_dlna_enabled!=dlna_enabled){
		system("sysconf minidlna &");
	}
	if (orig_smb_enabled!=smb_enabled){
		system("sysconf samba &");
	}
#if 0	
	system("sysconf vsftpd &");
	system("sysconf printer &");
#endif
	websSetCfgResponse(mosq, tp, "0", "reserv");
	return 0;
}

#if 0
int chform_size_usb(unsigned long long ac_size,char *ch_size)
{
	float c_size;

	memset(ch_size,0,16);
	if(ac_size>=Gsize)
	{
		c_size=ac_size/Gsize;
		sprintf(ch_size,"%.2f %s",c_size,"GB");
		return 0;
	}
	else if(ac_size>=Msize)
	{
		c_size=ac_size/Msize;
		sprintf(ch_size,"%.2f %s",c_size,"MB");
		return 0;
	}
	else
	{
		strcpy(ch_size,"< 1M");
		return 0;
	}
}

int getUsbInfo(struct mosquitto *mosq, cJSON* data, char *tp)
{
	cJSON *root, *jsonPt;
	char *output,  strsize[16], dir[16], percent[8];
	long long totalsize=0,usedsize=0, freesize=0,tmp_totalsize=0, tmp_usedsize=0, tmp_freesize=0;
	char file_name[64],Manufacturer_name[32]="Unknown",*p1=NULL,*p2=NULL,buff[64];
	int file_flag=0,i;
	FILE *pp_df = popen("df | grep /dev/sd", "r");
	if(pp_df==NULL){
		websGetCfgResponse(mosq,tp,"[]");
		return 0;
	}

	root=cJSON_CreateArray();
	while(EOF != fscanf(pp_df,"%*s %lld %lld %lld %s %s\n",&tmp_totalsize,&tmp_usedsize,&tmp_freesize,percent,dir)){
		totalsize+=tmp_totalsize;
		usedsize+=tmp_usedsize;
		freesize+=tmp_freesize;
	}
	pclose(pp_df);
	if(d_exist("/proc/scsi/usb-storage"))
	{
		for(i=0;i<13&&(file_flag==0);i++)
		{
			sprintf(file_name,"/proc/scsi/usb-storage/%d",i);
			if( f_exist(file_name))
			file_flag=1;
		}
	}
	if(file_flag)
	{
		FILE* fp=fopen(file_name,"r");
		if(fgets(buff,64,fp)!=NULL)
		{
		p1=strstr(buff,"Manufacturer");
		p1=strchr(buff,':');
	 	strcpy(Manufacturer_name,p1+1);
		p2=strchr(Manufacturer_name,'\n');
		*p2=' ';
		if(strstr(Manufacturer_name,"Unknown")==NULL)
	 		{
			fgets(buff,64,fp);
		  	p1=strstr(buff,"ProductClass");
			 p1=strchr(buff,':');
		  	strcpy(p2+1,p1+1);	
	 		}
		fclose(fp);
		}
	}
	jsonPt = cJSON_CreateObject();
	cJSON_AddStringToObject(jsonPt,"PtName",dir);

	chform_size_usb(totalsize, strsize);
	cJSON_AddStringToObject(jsonPt,"totalsize",strsize);

	chform_size_usb(usedsize, strsize);
	cJSON_AddStringToObject(jsonPt,"usedsize",strsize);

	chform_size_usb(freesize, strsize);
	cJSON_AddStringToObject(jsonPt,"freesize",strsize);

	cJSON_AddStringToObject(jsonPt,"percent",percent);

	cJSON_AddStringToObject(jsonPt,"usbDeviceName",Manufacturer_name);

	cJSON_AddItemToArray(root,jsonPt);
	sync();

	output=cJSON_Print(root);
	websGetCfgResponse(mosq, tp, output);
	free(output);
	cJSON_Delete(root);
	return 0;
}

int delUsbDevice(struct mosquitto *mosq, cJSON* data, char *tp)
{
	FILE *fp_mount = NULL;
	char part[30],cmdbuf[64]={0};

	if (NULL == (fp_mount = fopen("/proc/mounts", "r"))){
		DBG_MSG();
		return;
	}
	while(EOF != fscanf(fp_mount, "%s %*s %*s %*s %*s %*s\n", part)){
		if (NULL != strstr(part, "/dev/sd") || NULL != strstr(part, "/dev/mmc")){
			sprintf(cmdbuf,"DEVPATH=%s ACTION=remove usbmount block",part);			
			CsteSystem(cmdbuf, CSTE_PRINT_CMD);
		}
	}
	system("echo 0 > /proc/usb_mode_detect");
	system("echo 0 > /tmp/usbFlag");
	fclose(fp_mount);
	websSetCfgResponse(mosq, tp, "10", "reserv");
	return 0;
}
#endif

int module_init()
{
	cste_hook_register("getUsbStorageCfg",getUsbStorageCfg);
	cste_hook_register("setUsbStorageCfg",setUsbStorageCfg);
#if 0	
	cste_hook_register("getUsbInfo",getUsbInfo);
	cste_hook_register("delUsbDevice",delUsbDevice);
#endif
    return 0;
}
