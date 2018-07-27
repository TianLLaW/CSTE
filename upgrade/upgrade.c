/**
* Copyright (c) 2013-2017 CARY STUDIO
* @file upgrade.c
* @author CaryStudio
* @brief  This is a upgrade cste topic
* @date 2017-11-14
* @warning http://www.latelee.org/using-gnu-linux/how-to-use-doxygen-under-linux.html.
			http://www.cnblogs.com/davygeek/p/5658968.html
* @bug
*/

/*
 * upgrade  
 * cste upgrade模块
 *
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
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>

#include "upgrade.h"
#include "mtd.h"

int configlen = 0;
int wait_time=50;//system reboot time


static int updateConfigIntoFlash(unsigned char *data, int total_len, int *pType, int *pStatus)
{
	printf("[%s:%d]----------Begain-------------\n",__FUNCTION__,__LINE__);
	int len=0, status=1, type=0, ver, force;
#ifdef HEADER_LEN_INT
	HW_PARAM_HEADER_Tp phwHeader;
	int isHdware=0;
#endif
	PARAM_HEADER_Tp pHeader;
#ifdef COMPRESS_MIB_SETTING
	COMPRESS_MIB_HEADER_Tp pCompHeader;
	unsigned char *expFile=NULL;
	unsigned int expandLen=0;
	int complen=0;
	int compLen_of_header=0;
	short compRate=0;
#endif
	char *ptr;
	unsigned char isValidfw = 0;

	do {
		if (
#ifdef COMPRESS_MIB_SETTING
			memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
			memcmp(&data[len], CURRENT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) 
#endif
		) {
			if (isValidfw == 1)
				break;
		}
#ifdef HEADER_LEN_INT
	if(
	#ifdef COMPRESS_MIB_SETTING
		memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN)==0
	#else
		memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
	#endif
	)
	{
		isHdware=1;
	}
#endif
#ifdef COMPRESS_MIB_SETTING
		pCompHeader =(COMPRESS_MIB_HEADER_Tp)&data[complen];
		compRate = WORD_SWAP(pCompHeader->compRate);
		compLen_of_header = DWORD_SWAP(pCompHeader->compLen);
		/*decompress and get the tag*/
#ifdef RTK_MIB_TAG_CHECK
		expFile=malloc(compLen_of_header*WORD_SWAP(pCompHeader->realcompRate));
#else
		expFile=malloc(compLen_of_header*compRate);
#endif
		if (NULL==expFile) {
			printf("malloc for expFile error!!\n");
			return 0;
		}
		expandLen = Decode(data+complen+sizeof(COMPRESS_MIB_HEADER_T), compLen_of_header, expFile);
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)expFile;
#else
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)&data[len];
#endif
		
#ifdef _LITTLE_ENDIAN_
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader->len = WORD_SWAP(phwHeader->len);
		else
#endif
		pHeader->len = HEADER_SWAP(pHeader->len);
#endif
#ifdef HEADER_LEN_INT
		if(isHdware)
			len += sizeof(HW_PARAM_HEADER_T);
		else
#endif
		len += sizeof(PARAM_HEADER_T);

        /*in case use wrong version config.dat*/
        #define MAX_CONFIG_LEN 1024*1024
        #define MIN_CONFIG_LEN 8*1024
#ifdef HEADER_LEN_INT
		if(isHdware)
        {
            if((phwHeader->len > MAX_CONFIG_LEN)||(phwHeader->len < MIN_CONFIG_LEN))
            {
                printf("INVALID config.data FILE\n");
                status = 0;
                break;
            }
        }else
#endif
        {
            if((pHeader->len > MAX_CONFIG_LEN)||(pHeader->len < MIN_CONFIG_LEN))
            {
                printf("INVALID config.data FILE\n");
                status = 0;
                break;
            }
        }
		if ( sscanf((char *)&pHeader->signature[TAG_LEN], "%02d", &ver) != 1)
			ver = -1;
		
		force = -1;
		if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1; // update
		}
		else if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN)) {
			isValidfw = 1;
			force = 2; // force
		}
		else if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)) {
			isValidfw = 1;
			force = 0; // upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( !force && (ver < CURRENT_SETTING_VER || // version is less than current
				(pHeader->len < (sizeof(APMIB_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif

#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif

#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
					if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
						status = 0;
						break;
					}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}
//#ifdef _LITTLE_ENDIAN_
//			swap_mib_word_value((APMIB_Tp)ptr);
//#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
	#ifndef VOIP_SUPPORT_TLV_CFG
			flash_voip_import_fix(&((APMIB_Tp)ptr)->voipCfgParam, &pMib->voipCfgParam);
#endif
#endif

#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(CURRENT_SETTING, (char *)&data[complen], compLen_of_header+sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(CURRENT_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(CURRENT_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += compLen_of_header+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif
			type |= CURRENT_SETTING;
			continue;
		}

		if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1;	// update
		}
		else if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 2;	// force
		}
		else if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 0;	// upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( (ver < DEFAULT_SETTING_VER) || // version is less than current
				(pHeader->len < (sizeof(APMIB_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif

#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif

#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
				if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
				status = 0;
				break;
				}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}

//#ifdef _LITTLE_ENDIAN_
//			swap_mib_word_value((APMIB_Tp)ptr);
//#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
	#ifndef VOIP_SUPPORT_TLV_CFG
			flash_voip_import_fix(&((APMIB_Tp)ptr)->voipCfgParam, &pMibDef->voipCfgParam);
#endif
#endif

#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(DEFAULT_SETTING, (char *)&data[complen], compLen_of_header+sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(DEFAULT_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(DEFAULT_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += compLen_of_header+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}	
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif
			type |= DEFAULT_SETTING;
			continue;
		}

		if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1;	// update
		}
		else if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 2;	// force
		}
		else if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 0;	// upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( (ver < HW_SETTING_VER) || // version is less than current
				(pHeader->len < (sizeof(HW_SETTING_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif
#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif
			

#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
				if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
				status = 0;
				break;
				}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}
#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(HW_SETTING, (char *)&data[complen], compLen_of_header + sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(HW_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(HW_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += compLen_of_header + sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif

			type |= HW_SETTING;
			continue;
		}
	}
#ifdef COMPRESS_MIB_SETTING	
	while (complen < total_len);

	if (expFile) {
		free(expFile);
		expFile=NULL;
	}
#else
	while (len < total_len);
#endif

	*pType = type;
	*pStatus = status;
	printf("[%s:%d]----------End-------------\n",__FUNCTION__,__LINE__);

#ifdef COMPRESS_MIB_SETTING	
	return complen;
#else
	return len;
#endif
}

int fwChecksumOk(char *data, int len)
{
	unsigned short sum=0;
	int i;

	for (i=0; i<len; i+=2) {
#ifdef _LITTLE_ENDIAN_
		sum += WORD_SWAP( *((unsigned short *)&data[i]) );
#else
		sum += *((unsigned short *)&data[i]);
#endif
	}

	return( (sum==0) ? 1 : 0);
}
void kill_processes(void)
{
	CsteSystem("ifconfig br0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig eth0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig eth1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig ppp0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-vxd down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan0-va0 down 2> /dev/null", CSTE_PRINT_CMD);	
	CsteSystem("ifconfig wlan0-va1 down 2> /dev/null", CSTE_PRINT_CMD);	
	CsteSystem("ifconfig wlan0-va2 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan0-va3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds2 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds4 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds5 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds6 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds7 down 2> /dev/null", CSTE_PRINT_CMD);
#if defined(CONFIG_RTL_92D_SUPPORT)	
	CsteSystem("ifconfig wlan1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-vxd down 2> /dev/null", CSTE_PRINT_CMD);	
	CsteSystem("ifconfig wlan1-va0 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan1-va1 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan1-va2 down 2> /dev/null", CSTE_PRINT_CMD);	
	CsteSystem("ifconfig wlan1-va3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds2 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds4 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds5 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds6 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds7 down 2> /dev/null", CSTE_PRINT_CMD);
#endif
	//kill process 
#if defined(SUPPORT_MESH)
	CsteSystem("killall AC 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall WTP 2> /dev/null", CSTE_PRINT_CMD);
#endif	
	CsteSystem("csteSys csnl 2 -1 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("echo '' >> /var/spool/cron/crontabs/root 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("cp	/etc/cs_watchdog.conf  /var/cs_watchdog.conf 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall watchdog;watchdog -c /var/cs_watchdog.conf &", CSTE_PRINT_CMD);
	CsteSystem("killall csteDriverConnMachine 2> /dev/null", CSTE_PRINT_CMD);
	
	CsteSystem("killall crond 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall udhcpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall udhcpc 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall dnsmasq 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall ppp_inet 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall pppd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall lighttpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall cs_statistics 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall ntp_inet 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall pathsel 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall wscd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall iwcontrol 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall telnetd 2> /dev/null", CSTE_PRINT_CMD);
	//free memory
	CsteSystem("echo 128> /proc/sys/vm/min_free_kbytes", CSTE_PRINT_CMD);
	CsteSystem("echo 3> /proc/sys/vm/drop_caches", CSTE_PRINT_CMD);
	sleep(1);

	printf("upgrade: killing tasks...\n");
	
	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	kill(1, SIGSTOP);		
	kill(2, SIGSTOP);		
	kill(3, SIGSTOP);		
	kill(4, SIGSTOP);		
	kill(5, SIGSTOP);		
	kill(6, SIGSTOP);		
	kill(7, SIGSTOP);		
	//atexit(restartinit);		/* If exit prematurely, restart init */
	//sync();

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	//setpgrp(); 			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to a closed controlling terminal */
}

#if defined(SUPPORT_UPGRADE_PROTECTED)
int writeTmpFile(int _len,char *_path,char *_appendData)
{
	int writeNum=0;
	int fh = open(_path, O_RDWR|O_CREAT|O_APPEND);
	writeNum=write(fh, _appendData, _len);
	close(fh);
	return writeNum;
}
#endif

int CheckUpgradeFW(int headoffset, int upload_len, char *upload_data)
{
	IMG_HEADER_Tp pHeader;
	int ret, flag=0, iRet=0;
	unsigned long len;
	int head_offset=headoffset;
	int isValidfw = 0, isValidfw_fw = 0, isValidfw_desc = 0;
	
	printf("[%s:%d]--------Begain----------\n",__FUNCTION__,__LINE__);

	while ((head_offset+sizeof(IMG_HEADER_T)) <  upload_len)
	{
		pHeader = (IMG_HEADER_Tp) &upload_data[head_offset];
		len = pHeader->len;
#ifdef _LITTLE_ENDIAN_
		len  = DWORD_SWAP(len);
		int stadd=-1;
		stadd=DWORD_SWAP(pHeader->startAddr);
		int brn=-1;
		brn=DWORD_SWAP(pHeader->burnAddr);
#endif   
		// check header and checksum
		int i=0;
		for(i=0; i<4; i++){
			printf("%c",upload_data[head_offset+i]);
		}
		printf("\n");
		
		if (!memcmp(&upload_data[head_offset], FW_HEADER, SIGNATURE_LEN) ||
		    !memcmp(&upload_data[head_offset], FW_HEADER_WITH_ROOT, SIGNATURE_LEN)) {
		    isValidfw_fw = 1;
			flag = 1;
			CSTE_DEBUG("===the head_offset====%d the upload_data[head_offset]=====%s\n",head_offset,&upload_data[head_offset]);
			wait_time+=60;
		} else if (!memcmp(&upload_data[head_offset], WEB_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 2;
			CSTE_DEBUG("===the head_offset====%d the upload_data[head_offset]=====%s\n",head_offset,&upload_data[head_offset]);
			wait_time+=40;
		} else if (!memcmp(&upload_data[head_offset], ROOT_HEADER, SIGNATURE_LEN)) {
			CSTE_DEBUG("===the head_offset====%d the upload_data[head_offset]=====%s\n",head_offset,&upload_data[head_offset]);
			isValidfw = 1;
			flag = 3;
			wait_time+=140;
		}
#if defined(SUPPORT_UPGRADE_PROTECTED)
		 else if (!memcmp(&upload_data[head_offset], DESC_HEADER, SIGNATURE_LEN)) {
			CSTE_DEBUG("===the head_offset====%d the upload_data[head_offset]=====%s\n",head_offset,&upload_data[head_offset]);
			isValidfw_desc = 1;
			flag = 5;
		} 
#endif	
		else if ( 
			!memcmp(&upload_data[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)) {
			CSTE_DEBUG("===the head_offset====%d the upload_data[head_offset]=====%s\n",head_offset,&upload_data[head_offset]);
			COMPRESS_MIB_HEADER_Tp pHeader_cfg;
			pHeader_cfg = (COMPRESS_MIB_HEADER_Tp)&upload_data[head_offset];
			if(!memcmp(&upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)) {
				head_offset +=  CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET + (CODE_IMAGE_OFFSET - WEB_PAGE_OFFSET);//16384=16KB,131072=128KB，current配置增加16和128跳到kernel
				configlen = head_offset;
				
			}else {
				head_offset +=  CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET;//default配置增加16kb跳到current
			}
			isValidfw = 1;
			//update_cfg = 1;
			continue;
		}
		else {
			CSTE_DEBUG("[isValidfw_fw:%d][isValidfw_desc:%d]\n",isValidfw_fw,isValidfw_desc);
#if defined(SUPPORT_UPGRADE_PROTECTED)
			if (isValidfw_fw == 1 && isValidfw_desc == 1)
#else
			if (isValidfw_fw == 1)
#endif
			{
				break;
			}
			return -1;
		}

		if ((flag == 1) || (flag == 3)) {
			if (!fwChecksumOk((char *)&upload_data[sizeof(IMG_HEADER_T)+head_offset], len)) {
				return -1;
			}
		}
#if defined(SUPPORT_UPGRADE_PROTECTED)
		else if ( flag == 5) {
			int leng;
			IMG_HEADER_Tp desc;
			char csid_str[16]={0};
			
			desc = (IMG_HEADER_Tp)(&upload_data[head_offset]);
			leng = desc->len;
		#ifdef _LITTLE_ENDIAN_
			leng  = DWORD_SWAP(desc->len);
		#endif 
			writeTmpFile(leng,"/tmp/desc.ini",(&upload_data[head_offset])+sizeof(IMG_HEADER_T));
			if ( 1 == inifile_get_int("/tmp/desc.ini","upgrade","upg_protect_enable")){
				inifile_get_string("/tmp/desc.ini","vendor","PRODUCT_CSID",csid_str);
				if (strncmp(PRODUCT_CSID,csid_str,strlen(PRODUCT_CSID))){
					printf("[%s:%d]PRODUCT_CSID=%s,INI_CSID=%s\n",__FUNCTION__,__LINE__,PRODUCT_CSID,csid_str);
					return  -1;
				}
			}
		}		
#endif
		else {
			char *ptr = (char *)&upload_data[sizeof(IMG_HEADER_T)+head_offset];
			if ( !CHECKSUM_OK((unsigned char *)ptr, len) ) {
				return -1;
			}
		}		
		head_offset += len + sizeof(IMG_HEADER_T);
		}
	printf("[%s:%d]--------End----------\n",__FUNCTION__,__LINE__);
	return iRet;
}


#if defined(CONFIG_APP_DAT_IN_ROOTFS) && defined(CONFIG_KL_USER_DATA_PARTITION)
int reset_config(int reset)  
{  
	if ( 1 == reset )
	{
		system("umount /mnt");	
		system("mount -t jffs2 /dev/mtdblock2 /mnt");  
		check_ini_sys_file();
		cfg_version_set(1);
	}
	
	return 0;
} 
#endif
#if defined(SUPPORT_MESH)
void kill_processes1(void)
{
#if  defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)	
	return 0;
#endif
	CsteSystem("echo '' >> /var/spool/cron/crontabs/root 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("cp  /etc/cs_watchdog.conf  /var/cs_watchdog.conf 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall watchdog;watchdog -c /var/cs_watchdog.conf &", CSTE_PRINT_CMD);

	//CsteSystem("ifconfig br0 down 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("ifconfig eth0 down 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("ifconfig eth1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig ppp0 down 2> /dev/null", CSTE_PRINT_CMD);
/*	CsteSystem("ifconfig wlan0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-vxd down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan0-va0 down 2> /dev/null", CSTE_PRINT_CMD); 
	CsteSystem("ifconfig wlan0-va1 down 2> /dev/null", CSTE_PRINT_CMD); 
	CsteSystem("ifconfig wlan0-va2 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan0-va3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds2 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds4 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds5 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds6 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan0-wds7 down 2> /dev/null", CSTE_PRINT_CMD);
#if defined(CONFIG_RTL_92D_SUPPORT)	
	CsteSystem("ifconfig wlan1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-vxd down 2> /dev/null", CSTE_PRINT_CMD); 
	CsteSystem("ifconfig wlan1-va0 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan1-va1 down 2> /dev/null", CSTE_PRINT_CMD); 	
	CsteSystem("ifconfig wlan1-va2 down 2> /dev/null", CSTE_PRINT_CMD); 
	CsteSystem("ifconfig wlan1-va3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds0 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds1 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds2 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds3 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds4 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds5 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds6 down 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("ifconfig wlan1-wds7 down 2> /dev/null", CSTE_PRINT_CMD);
#endif*/
	//kill process 
	//CsteSystem("killall watchdog 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall crond 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall udhcpd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall udhcpc 2> /dev/null", CSTE_PRINT_CMD);

	//CsteSystem("killall dnsmasq 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall ppp_inet 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall pppd 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall lighttpd 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall soapserver 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall statistics 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall ntp_inet 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall pathsel 2> /dev/null", CSTE_PRINT_CMD);
//	CsteSystem("killall wscd 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall iwcontrol 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall telnetd 2> /dev/null", CSTE_PRINT_CMD);
	//CsteSystem("killall cs_daemon 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall AC 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall WTP 2> /dev/null", CSTE_PRINT_CMD);
//	CsteSystem("csteSys csnl 2 -1 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall crond 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall csteDriverConnMachine 2> /dev/null", CSTE_PRINT_CMD);
	CsteSystem("killall elink 2> /dev/null", CSTE_PRINT_CMD);
	//free memory
	CsteSystem("echo 128> /proc/sys/vm/min_free_kbytes", CSTE_PRINT_CMD);
	CsteSystem("echo 3> /proc/sys/vm/drop_caches", CSTE_PRINT_CMD);
	sleep(1);

	printf("upgrade: killing tasks...\n");
	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	kill(1, SIGSTOP);		
	kill(2, SIGSTOP);		
	kill(3, SIGSTOP);		
	kill(4, SIGSTOP);		
	kill(5, SIGSTOP);		
	kill(6, SIGSTOP);		
	kill(7, SIGSTOP);		
	//atexit(restartinit);		/* If exit prematurely, restart init */
	//sync();

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	//setpgrp();			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to a closed controlling terminal */
}
#endif
#if  defined(CONFIG_KL_C7185R_04336) ||defined(CONFIG_KL_C7187R_1200)	
static int check_system_image(int fh,IMG_HEADER_Tp pHeader)
{
	// Read header, heck signature and checksum
	int ret=0;		
	char image_sig[4]={0};
	char image_sig_root[4]={0};
	
        /*check firmware image.*/
//	if ( read(fh, pHeader, sizeof(IMG_HEADER_T)) != sizeof(IMG_HEADER_T)) 
//     		return 0;	

	memcpy(image_sig, FW_HEADER, SIGNATURE_LEN);
	memcpy(image_sig_root, FW_HEADER_WITH_ROOT, SIGNATURE_LEN);

	if (!memcmp(pHeader->signature, image_sig, SIGNATURE_LEN))
		ret=1;
	else if  (!memcmp(pHeader->signature, image_sig_root, SIGNATURE_LEN))
		ret=2;
	else{
		ERR_PRINT("ERROR (%s)%d no sys signature at !\n", __FUNCTION__, __LINE__);
	}
    if(pHeader->burnAddr == FORCEBOOT_BANK_MARK){
	    pHeader->burnAddr = BASIC_BANK_MARK;
	} 
    //mark_dual , ignore checksum() now.(to do) 
	return (ret);
}
static int get_image_header(int fh,IMG_HEADER_Tp header_p)
{
	int ret=0;
	//check 	CODE_IMAGE_OFFSET2 , CODE_IMAGE_OFFSET3 ?
	//ignore check_image_header () for fast get header , assume image are same offset......	
	// support CONFIG_RTL_FLASH_MAPPING_ENABLE ? , scan header ...
#ifndef CONFIG_MTD_NAND
	lseek(fh, CODE_IMAGE_OFFSET, SEEK_SET);		
#else
	lseek(fh, CODE_IMAGE_OFFSET-NAND_BOOT_SETTING_SIZE, SEEK_SET);	
#endif
    if ( read(fh, header_p, sizeof(IMG_HEADER_T)) != sizeof(IMG_HEADER_T)){
        ERR_PRINT("ERROR (%s)%d read img header error!\n", __FUNCTION__, __LINE__);
     		return 0;
    }
	ret = check_system_image(fh,header_p);

	//assume , we find the image header in CODE_IMAGE_OFFSET
#ifndef CONFIG_MTD_NAND
	lseek(fh, CODE_IMAGE_OFFSET, SEEK_SET);	
#else
	lseek(fh, CODE_IMAGE_OFFSET-NAND_BOOT_SETTING_SIZE, SEEK_SET);	
#endif
    if ( write(fh, header_p, sizeof(IMG_HEADER_T)) != sizeof(IMG_HEADER_T)){
        ERR_PRINT("ERROR (%s)%d write img header error!\n", __FUNCTION__, __LINE__);
        return 0;
    }
	return ret;	
}
static unsigned long header_to_mark(int  flag, IMG_HEADER_Tp pHeader)
{
	unsigned long ret_mark=NO_IMAGE_BANK_MARK;
	//mark_dual ,  how to diff "no image" "image with no bank_mark(old)" , "boot with lowest priority"
	if(flag) //flag ==0 means ,header is illegal
	{
		if( (pHeader->burnAddr & GOOD_BANK_MARK_MASK) )
			ret_mark=pHeader->burnAddr;	
		else
			ret_mark = OLD_BURNADDR_BANK_MARK;
	}
	return ret_mark;
}

static unsigned long get_next_bankmark(char *kernel_dev,int dual_enable)
{
    unsigned int bankmark=NO_IMAGE_BANK_MARK;
    int ret=0,fh;
    IMG_HEADER_T header; 	
	fh = open(kernel_dev, O_RDWR);
	if ( fh == -1 ) {
	    ERR_PRINT("ERROR (%s)%d Open file failed!\n",  __FUNCTION__, __LINE__);
		return NO_IMAGE_BANK_MARK;
	}
	ret = get_image_header(fh,&header);	

	bankmark= header_to_mark(ret, &header);	
	close(fh);
	//get next boot mark

	if( bankmark < BASIC_BANK_MARK)
		return BASIC_BANK_MARK;
	else if( (bankmark ==  FORCEBOOT_BANK_MARK) || (dual_enable == 0)) //dual_enable = 0 ....
	{
		return FORCEBOOT_BANK_MARK;//it means dual bank disable
	}
	else{
		return bankmark+1;
    }
	
}
#endif
void WriteUpgradeFW(int headoffset, long upload_len, char *upload_data, int iflags)
{
	fprintf(stderr, "[%s:%d]---------Begain-----------\n",__FUNCTION__,__LINE__);
	
	IMG_HEADER_Tp pHeader;
	int len=0, flag=0, startAddr=-1, startAddrWeb=-1 ;
	int fh,numLeft, isValidfw, locWrite, numWrite;
	int head_offset=headoffset;
	struct erase_info_user mtdEraseInfo;
	char str_tmp[10];


	while ((head_offset+sizeof(IMG_HEADER_T)) < upload_len){
		locWrite = 0;
		pHeader = (IMG_HEADER_Tp) &upload_data[head_offset];
		len = pHeader->len;
#ifdef _LITTLE_ENDIAN_
		len  = DWORD_SWAP(len);
		int stadd=-1;
		stadd=DWORD_SWAP(pHeader->startAddr);
		int brn=-1;
		brn=DWORD_SWAP(pHeader->burnAddr);
#endif
		numLeft = len + sizeof(IMG_HEADER_T) ;

		// check header and checksum
		if (!memcmp(&upload_data[head_offset], FW_HEADER, SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], FW_HEADER_WITH_ROOT, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 1;
			fprintf(stderr, "[%s:%d]FW_HEADER OK!\n",__FUNCTION__,__LINE__);
		}
		else if (!memcmp(&upload_data[head_offset], WEB_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 2;
			fprintf(stderr, "[%s:%d]WEB_HEADER OK!\n",__FUNCTION__,__LINE__);
		}
		else if (!memcmp(&upload_data[head_offset], ROOT_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 3;
			fprintf(stderr, "[%s:%d]ROOTFS_HEADER OK!\n",__FUNCTION__,__LINE__);
		}
		else if (
			!memcmp(&upload_data[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)		
			)
		{
			int type=0, status=0, cfg_len;
			if(!memcmp(&upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN))
			{
				if(iflags==1){
					cfg_len = updateConfigIntoFlash((unsigned char *)&upload_data[head_offset],CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET, &type, &status);
				}else{
					type=CURRENT_SETTING;
					status=1;
				}
			}else{
				cfg_len = updateConfigIntoFlash((unsigned char *)&upload_data[head_offset],CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET, &type, &status);
			}

			if (status == 0 || type == 0) { // checksum error
			}
			else if(!memcmp(&upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN)){
				head_offset += CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET;
				isValidfw = 1;
			}
			else{ // upload success
				head_offset = configlen;
				isValidfw = 1;
				//update_cfg = 1;
			}
			continue;
		}
		else {
			if (isValidfw == 1)
				break;
			return -1;
		}

#if  defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)
		int active_bank=0,backup_bank=0;
		//apmib_get(MIB_DUALBANK_ENABLED,(void *)&dual_enable);   
		active_bank=getCmdVal("cat /proc/bootbank");
		backup_bank=active_bank==1?2:1;
		CSTE_DEBUG("(%s)%d active_bank = %d, backup_bank = %d\n", __FUNCTION__, __LINE__, active_bank, backup_bank);

		if (flag == 3) //rootfs
		{
		
		CSTE_DEBUG("(%s)%d  %s, backup_bank = %d\n", __FUNCTION__, __LINE__, Rootfs_dev_name[backup_bank-1], backup_bank);
			fh = open(Rootfs_dev_name[backup_bank-1], O_RDWR);

		}	
		else if(flag == 1) //linux
		{
		CSTE_DEBUG("(%s)%d  %s, backup_bank = %d\n", __FUNCTION__, __LINE__, Kernel_dev_name[backup_bank-1], backup_bank);
			fh = open(Kernel_dev_name[backup_bank-1], O_RDWR);
		}
#else
		
		if (flag == 3)
		{
			fh = open(MTD_ROOTFS, O_RDWR); //rootfs
		}
		else
		{
			fh = open(MTD_KERNEL, O_RDWR);//kernel
		}

#endif
		if ( fh == -1 ) {
		//	strcpy(buffer, ("File open failed!"));
		} else {
			if (flag == 1) {
				if (startAddr == -1) {
					//startAddr = CODE_IMAGE_OFFSET;
					startAddr = pHeader->burnAddr ;
#ifdef _LITTLE_ENDIAN_
					startAddr = DWORD_SWAP(startAddr);
#endif
				}
			}
			else if (flag == 3) {
				if (startAddr == -1) {
					startAddr = 0; // always start from offset 0 for 2nd FLASH partition
				}
			}
			else {
				if (startAddrWeb == -1) {
					//startAddr = WEB_PAGE_OFFSET;
					startAddr = pHeader->burnAddr ;
#ifdef _LITTLE_ENDIAN_
					startAddr = DWORD_SWAP(startAddr);
#endif
				}
				else
					startAddr = startAddrWeb;
			}
			
			lseek(fh, startAddr, SEEK_SET);			
			if (flag == 3) {
				locWrite += sizeof(IMG_HEADER_T); // remove header,the sizeof header
				numLeft -=  sizeof(IMG_HEADER_T); //the section length of no header
#if defined(SUPPORT_MESH)
				kill_processes1();
#else	
				kill_processes();
#endif	
				sleep(2);
			}
#if defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)
			if (flag == 1) {  //kernel image
				pHeader->burnAddr =	 get_next_bankmark(Kernel_dev_name[active_bank-1],1);//replace the firmware header with new bankmark //mark_debug		
			}
#endif
			fprintf(stderr, "[%s:%d]burn start addr:%x,len=%x\n",__FUNCTION__,__LINE__,startAddr,numLeft);
			int wsize=0, e=startAddr;
			for (; numLeft;) {

				/* need to erase the next block before writing data to it */
				{
					mtdEraseInfo.start = e;
					mtdEraseInfo.length = 0x1000;
					
					/* erase the chunk */
					fprintf(stderr, ".");
					if (ioctl (fh,MEMERASE,&mtdEraseInfo) < 0) {
						fprintf(stderr, "Erasing mtd failed: %d\n", flag);
						goto flash_err;
					}
					e += 0x1000;
				}
		
				if ( numLeft > 0x1000 )
					wsize = 0x1000;
				else
					wsize = numLeft;
				fprintf(stderr, ".");
				if ((numWrite = write(fh, &(upload_data[locWrite+head_offset]), wsize)) < wsize) {//write the header
					if (numWrite  < 0) {
						fprintf(stderr, "Error writing image.\n");
						goto flash_err;
					} else {
						fprintf(stderr, "Insufficient space.\n");
						goto flash_err;
					}
				}
				
				locWrite += numWrite;//the next header startAddr
				numLeft -= numWrite;//the next section length

				sync();
			}

			fprintf(stderr, "\n");
			close(fh);

			head_offset += len + sizeof(IMG_HEADER_T) ;
			startAddr = -1 ; //by sc_yang to reset the startAddr for next image
		}
	}

flash_err:
	sync();
#if  defined(SUPPORT_CUSTOMIZATION)
	if(1 == iflags && 0 != f_exist(INIFILE)){
		apmib_reinit();
		CsteSystem("convertIniToCfg", CSTE_PRINT_CMD);
		apmib_update(CURRENT_SETTING);
	}
#endif

	fprintf(stderr, "[%s:%d]---------End-----------\n",__FUNCTION__,__LINE__);
	CsteSystem("reboot", CSTE_PRINT_CMD);
	
	exit(1);
}



int setCloudUpgradeFW(int flag, char *dl_image_file) //hac or cloud upgrade use this one
{
	CSTE_DEBUG("======setCloudUpgradeFW======\n");
	FILE *fp = NULL;
	char *output,*upload_data,tmpBuf[256];
	int fwSizeLimit, head_offset=0, pid, ret;
	char FileName[256] = {0},custom_csid[32],fw_csid[16];
	sprintf(FileName,"%s",dl_image_file);

	int upload_len = f_size(FileName) + 1; //~ long upload_len	
	if(upload_len < 1000){
		printf("failed, can't get env var[1].\n");
		goto err;
	}
	
	fwSizeLimit=getFlashSize();
	if(upload_len >= fwSizeLimit*1024*1024){
		printf("failed, the file is too large!\n");
		goto err;
	}

	int ifd;
	struct stat sbuf;
	char *ptr;
	
	ifd = open(FileName, O_RDONLY);
	if(!ifd){
		goto err;
	}

	if (fstat(ifd, &sbuf) < 0) {
		close(ifd);
		goto err;
	}
	kill_processes1();
	//mmap 像访问普通内存一样对文件进行访问,快速访问文件
	ptr = (unsigned char *) mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, ifd, 0);
	if ((caddr_t)ptr == (caddr_t)-1) {
		close(ifd);
		goto err;
	}
	upload_data=ptr;

#if defined(SUPPORT_CUSTOMIZATION)
	custom_header_t *pHeader;
	char mtdname[32],cmdBuf[128];

	pHeader = (custom_header_t *)upload_data;

	if(strstr(pHeader->ih_name,"USERDATABIN"))
	{
		char md5_str[40]={0};
		memcpy(fw_csid,&pHeader->ih_name[12],sizeof(fw_csid));
		apmib_get(MIB_CSID,(void *)&custom_csid);
		if(strcmp(PRODUCT_MODEL,custom_csid)!=0 && strcmp(PRODUCT_MODEL,fw_csid)!=0 && strcmp(custom_csid,fw_csid)!=0){
			munmap(upload_data,sbuf.st_size);
			close(ifd);
			goto err;
		}
		
		f_write("/var/custom.bin", upload_data+head_offset+sizeof(custom_header_t), pHeader->ih_size, FW_CREATE, 0);
		Cal_file_md5("/var/custom.bin", md5_str);
		printf("[Debug]====size==%d====md5=%s==md5_str=%s=\n",pHeader->ih_size,pHeader->ih_md5,md5_str);
		if(strcasecmp(md5_str,pHeader->ih_md5)!=0){
			munmap(upload_data,sbuf.st_size);
			close(ifd);
			goto err;
		}	

		rtl_name_to_mtdblock("userdata", mtdname);

		sprintf(cmdBuf,"cat /var/custom.bin > %s", mtdname);
		CsteSystem(cmdBuf, CSTE_PRINT_CMD);

		CsteSystem("rm -f /var/custom.bin 1>/dev/null 2>&1", CSTE_PRINT_CMD);
		
		head_offset+=sizeof(custom_header_t)+pHeader->ih_size;
		if(upload_len < 1024*1024){
			munmap(upload_data,sbuf.st_size);
			close(ifd);
			goto err;
		}
	}
#endif

	ret=CheckUpgradeFW(head_offset, upload_len, upload_data);
	if(ret==-1){
		printf("Invalid upgrade firmware file!");
		munmap(upload_data,sbuf.st_size);
		close(ifd);
		goto err;
	}
	
	pid=fork();
	if(0 == pid){
		sleep(1);
#if defined(SUPPORT_UPATE_WITHCONFIG)
		//hac or cloud or softAC upgrade use this one
		head_offset += 2*(CURRENT_SETTING_OFFSET-DEFAULT_SETTING_OFFSET) + (CODE_IMAGE_OFFSET - WEB_PAGE_OFFSET);
#endif
#if defined(SUPPORT_MESH)
		kill_processes1();
#endif
		WriteUpgradeFW( head_offset, upload_len, upload_data, flag);
		exit(1);
	}
	return 0;

err:

	sprintf(tmpBuf,"rm -f %s 1>/dev/null 2>&1",FileName);
	CsteSystem(tmpBuf, CSTE_PRINT_CMD);
	return 0;
}


int f_size(const char *path)	// 4GB-1	-1 = error
{
	struct stat st;
	if (stat(path, &st) == 0) return (int)st.st_size;
	return (int)-1;
}

#if defined(SUPPORT_UPGRADE_PROTECTED)
int update_fw_by_ini(int flag, char *fwfile)
{
	int pid;		
	pid=fork();
	if(0 == pid)
	{
		sleep(2);
		setCloudUpgradeFW(flag,fwfile);
		exit(1);
	}	
	return 0;
}
#endif
int update_fw(int flag, char *fwfile)
{
	CsteSystem("echo 0 > /tmp/protect_process", CSTE_PRINT_CMD);

	int ret;
	char DlFwMd5[33] = {0}, ActionMd5[33] = {0}, cmd[256] = {0};
	int len = f_size(fwfile);

	sprintf(cmd, "md5sum %s | cut -d' ' -f1 > %s", fwfile, "/tmp/DloadFwMd5");
	CsteSystem(cmd, CSTE_PRINT_CMD);
	f_read("/tmp/DloadFwMd5", DlFwMd5, 0, sizeof(DlFwMd5));
	f_read("/tmp/ActionMd5", ActionMd5, 0, sizeof(ActionMd5));
	
#ifdef CONFIG_APP_WGET
	//The tr069 upgrade does not require an MD5 value to be verified
	strcpy(ActionMd5,DlFwMd5);
#endif
	if( 0 != strcmp("", ActionMd5) && 0 != strcasecmp(DlFwMd5, ActionMd5) ){
		printf("err update_fw check\n");	
		unlock_file("/tmp/update_flag");
		sprintf(cmd,"rm -f %s",DL_IMAGE_FILE);
		system(cmd);
		CsteSystem("echo 1 > /tmp/protect_process", CSTE_PRINT_CMD);
		return 1;
	}
	
	int pid;		
	pid=fork();
	if(0 == pid){
		sleep(2);
		setCloudUpgradeFW(flag,fwfile);
		exit(1);
	}	
	return 0;
}

int dl(char *dl_image_file)
{
	int iRet=0;
	char cmd[512]={0}, FileUrl[256]={0};
	f_read("/tmp/DlFileUrl", FileUrl, 0, sizeof(FileUrl));
	char *tmp = FileUrl;
	sprintf(cmd, "wget -O %s  %s", dl_image_file, FileUrl);
	iRet=CsteSystem(cmd, CSTE_PRINT_CMD);
	return iRet;
}

#if defined(SUPPORT_MESH)
int check_ping_state(const char *host)
{
	char cmd[256] = {0};

	if ((NULL == host) || (strlen(host)<7))/* 地址合法性检测 */
		goto fail;
	
	snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s > /dev/null && echo \"1\" > %s", 1, host, "/tmp/pingstate");
	system(cmd);

	if ( getCmdVal("cat /tmp/pingstate") == 1)
	{
		CsteSystem("rm -rf /tmp/pingstate", CSTE_PRINT_CMD);
		CSTE_DEBUG("ping %s ok\n", host);
		return 1;
	}
fail:
	CSTE_DEBUG("ping %s fail\n", host);
	return 0;
}

int checkMeshState(void)//check mesh state
{
	int num=0;
	
	CsteSystem("cat /proc/kl_reg | grep meshSuccNum |cut -d = -f 2 > /tmp/meshState", CSTE_PRINT_CMD);
	num=getCmdVal("cat /tmp/meshState");

	return num;
}

/**
* @note slaveUpgrade  slave Upgrade
* @param Setting Json Data
<pre>
{
	"url":	""
}
setting parameter description
"url":	The firmware file path
</pre>
* @return Return Json Data
<pre>
{
	"success":	true,
	"error":	null,
	"lanIp":	"192.168.0.1",
	"wtime":	"45",
	"reserv":	"reserv"
}
</pre>
*@author		Kris
*@date	2017-11-14
*/
int slaveUpgrade(struct mosquitto *mosq, cJSON* data, char *tp)//Tell the slave device to download the new firmware
{
	char cmd[128]={0}, FileUrl[64]={0};
	char * tmp=NULL, *pchar=NULL;
	cJSON *root=cJSON_CreateObject();
	char *output;
	if(getCmdVal("cat /tmp/slaveUpgradeflag")==1)//Firmware is being upgraded now
		goto END;
	tmp = websGetVar(data, T("url"), T(""));
	strcat(FileUrl, tmp);
	sprintf(cmd, "echo \"%s\" > /tmp/DlFileUrl", FileUrl);//firmware file path
	CsteSystem(cmd, CSTE_PRINT_CMD);
#if defined(SUPPORT_MESH)
	CsteSystem("rm -rf /var/cloudupdate.web", CSTE_PRINT_CMD);
#else
	CsteSystem("rm -rf /tmp/cloudupdate.web", CSTE_PRINT_CMD);
#endif
	CsteSystem("echo 3 > /proc/sys/vm/drop_caches", CSTE_PRINT_CMD);
	if(pchar = strstr(FileUrl, "/")){
		pchar++;
		pchar++;
		strcpy(FileUrl, pchar);
		if(pchar = strstr(FileUrl, "/"))
			*pchar = '\0';
	}
	sprintf(cmd, "cs_pub 127.0.0.1 CloudACMunualUpdate {\\\"masterIp\\\":\\\"%s\\\"}", FileUrl);//download firmware
	CsteSystem(cmd, CSTE_PRINT_CMD);
	
END:
	cJSON_AddStringToObject(root,"state","success");
	output=cJSON_Print(root);
	websGetCfgResponse(mosq, tp, output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

#endif

/**
* @note CloudACMunualUpdate  Cloud Munual Update
* @param Setting Json Data
<pre>
{
	"flags":	""
	"fileName":	""
	"ipAddr":	"0"
	"fwVersion":	"0"
	"masterIp":	""
}
setting parameter description
"flags":	The flag of upgrade
"fileName": The file name
"ipAddr":	IP address
"fwVersion":	Firmware Version
"masterIp": host IP
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
int CloudACMunualUpdate(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int iRet = 36;
	int FLASHSIZE;
	cJSON *root=cJSON_CreateObject();
	char *output = NULL,fwfile[256]={0}, cmd[128]={0};

	char *Flags = websGetVar(data, T("Flags"), T(""));
	char *FileName = websGetVar(data, T("FileName"), T(""));
	
#if defined(SUPPORT_MESH)
	int filesize=0, opmode=0, meshNum=0, i=0, n=0, ping=0;
	cJSON *Devlist,*subObj;
	char * devInfo, * tmp;
	char br0addr[32]={0}, IpAddr[32]={0}, url[64]={0}, FwVersion[32]={0}, new_version[32]={0};
#endif

	FLASHSIZE=getFlashSize();
	if(FLASHSIZE==0){
		cJSON_AddStringToObject(root,"upgradeERR","MM_FlashSizeErr");
		goto err1;
	}
	lock_file("/tmp/update_flag");
	if(strcmp(FileName,"")==0)
	{
		iRet = dl(DL_IMAGE_FILE);
		strcpy(fwfile,DL_IMAGE_FILE);
	}
	else
	{
		iRet = 0;
		strcpy(fwfile,FileName);
	}

#if defined(SUPPORT_MESH)
	if((meshNum=checkMeshState())>0){//mesh success
		apmib_get(MIB_OP_MODE, (void *)&opmode);
		if(opmode == 0){//if this device is a master device	
			if(f_exist("/tmp/MinorDevInfoList"))
			{
				filesize = f_size("/tmp/MinorDevInfoList");
				devInfo = (char *)malloc(filesize); 
				f_read("/tmp/MinorDevInfoList", devInfo, 0, filesize);
				
				getInAddr("br0", IP_ADDR_T, (void *)br0addr);
				Devlist = cJSON_Parse(devInfo);
				free(devInfo);
				for(i=0;i<cJSON_GetArraySize(Devlist);i++)
				{
					subObj = cJSON_GetArrayItem(Devlist,i);

					tmp = websGetVar(subObj, T("IpAddr"), T("0"));
					strcpy(IpAddr, tmp);
					tmp = websGetVar(subObj, T("FwVersion"), T("0"));
					strcpy(FwVersion, tmp);
					f_read("/tmp/NewVersion", new_version, 0, sizeof(new_version));
					if(strcmp(new_version, FwVersion)){
						strcpy(url, "http://");
						strcat(url, br0addr);
						strcat(url, "/fw_ln");
						do{
							ping = check_ping_state(IpAddr);
							sprintf(cmd, "cs_pub %s slaveUpgrade {\\\"url\\\":\\\"%s\\\"}", IpAddr, url);
							CsteSystem(cmd, CSTE_PRINT_CMD);
							sleep(5);
							n++;
						}while(n<3 && ping ==0);//check if the slave device has completed the download,and if not, notify the maximum 3 times.
					}
				}
				
			}
		}else if(opmode == 1){//if this device is a slave device
			tmp = websGetVar(data, T("masterIp"), T(""));
			if(f_exist(DL_IMAGE_FILE)){
				CsteSystem("echo 1 > /tmp/slaveUpgradeflag", CSTE_PRINT_CMD);
			}
		}
	}
#endif

	if ( 0 == iRet ){
		int flag=atoi(Flags);
#if defined(SUPPORT_UPGRADE_PROTECTED)
		if ( update_fw_by_ini(flag,fwfile) == 1 ) //check error
#else
 		if ( update_fw(flag,fwfile) == 1 ) //check error
#endif
			cJSON_AddStringToObject(root,"upgradeERR","MM_FwFileInvalid");
		else
			cJSON_AddStringToObject(root,"upgradeStatus","1");
	}
	else{
		unlock_file("/tmp/update_flag");
		sprintf(cmd,"rm -f %s",DL_IMAGE_FILE);
		system(cmd);
		cJSON_AddStringToObject(root,"upgradeERR","MM_DownloadFail");
	}
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq, tp, output);

err1:	
	cJSON_Delete(root);
	free(output);
	return 0;
}

#define FWINFO_FILE 	"/tmp/fwinfo"
void cste_save_fwinfo()
{
	char buff[128],tmpbuf[64];
#if defined (SUPPORT_CUSTOMIZATION)
	memset(tmpbuf,'\0',sizeof(tmpbuf));
	apmib_get( MIB_CSID, (void *)tmpbuf);
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_CSID: %s\" > %s", tmpbuf ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
	memset(tmpbuf,'\0',sizeof(tmpbuf));
	apmib_get(MIB_HARDWARE_MODEL,(void *)tmpbuf);
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_MODEL: %s\" >> %s", tmpbuf ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
#else
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_CSID	: %s\" > %s", PRODUCT_CSID ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_MODEL: %s\" >> %s", PRODUCT_MODEL ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
#endif	
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_SVN  : %d\" >> %s", PRODUCT_SVN ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
#if defined(SUPPORT_CUSTOMIZATION)
	memset(tmpbuf,'\0',sizeof(tmpbuf));
	apmib_get(MIB_SOFTWARE_VERSION,(void *)tmpbuf);
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_VER  : %s.%d\" >> %s", tmpbuf ,PRODUCT_SVN ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
#else
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_VER  : %s.%d\" >> %s", PRODUCT_VER ,PRODUCT_SVN ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
#endif
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_DATE : %s\" >> %s", PRODUCT_DATE ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
	memset(buff, '\0', sizeof(buff));
	sprintf(buff, "echo \"PRODUCT_TIME : %s\" >> %s", PRODUCT_TIME ,FWINFO_FILE);
	CsteSystem(buff, CSTE_PRINT_CMD);
}


#ifdef  CONFIG_APP_EASYCWMP
int AcsUpdate(struct mosquitto *mosq, cJSON* data, char *tp){
	printf("------AcsUpdate-----\n");
	CsteSystem("echo 0 > /tmp/protect_process", CSTE_PRINT_CMD);

	int pid;		
	pid=fork();
	if(0 == pid)
	{
		setCloudUpgradeFW("/var/cwmp_download");
		exit(1);
	}
	return 0;
}
#endif
//-----------------------------------------------------------------
int FirmwareUpgrade(struct mosquitto *mosq, cJSON* data, char *tp)
{
    char* output;
    cJSON *root=cJSON_CreateObject();
	char tmpBuf[32]={0},maxSize[16]={0};
	int tmp_size=8;
	tmp_size=getFlashSize();

	apmib_get(MIB_HARDWARE_VERSION,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel",tmpBuf);	

	sprintf(tmpBuf,"%s.%d",PRODUCT_VER,PRODUCT_SVN);
    cJSON_AddStringToObject(root,"fmVersion",tmpBuf);

#ifdef CONFIG_APP_CLOUDSRVUP
	cJSON_AddNumberToObject(root,"cloudFw",1);
	f_read("/tmp/cloudFwStatus", tmpBuf, 0, sizeof(tmpBuf));
	cJSON_AddStringToObject(root,"cloudFwStatus",tmpBuf);
#else	
	cJSON_AddNumberToObject(root,"cloudFw",0);
#endif

	sprintf(tmpBuf,"%d",tmp_size);
	cJSON_AddStringToObject(root,"flashSize",tmpBuf);

	getInAddr("br0", IP_ADDR_T, (void *)tmpBuf);

	cJSON_AddStringToObject(root,"lanIp",tmpBuf);
	
	sprintf(tmpBuf,"%s %s",PRODUCT_DATE,PRODUCT_TIME);
	cJSON_AddStringToObject(root,"buildTime",tmpBuf);

	sprintf(maxSize,"%d",tmp_size*1000);
	cJSON_AddStringToObject(root,"maxSize",maxSize);
	cJSON_AddStringToObject(root,"platform","rtl");
	cJSON_AddStringToObject(root,"upgradeAction","/cgi-bin/cstecgi.cgi?action=upload&setUpgradeFW");
	cJSON_AddStringToObject(root,"setUpgradeFW","0");

    output=cJSON_Print(root);
    websGetCfgResponse(mosq,tp,output);
	free(output);
    cJSON_Delete(root);
    return 0;
}

int setUpgradeFW(struct mosquitto *mosq, cJSON* data, char *tp)
{
	printf("[%s:%d]--------DBG----------\n",__FUNCTION__,__LINE__);
	wait_time=50;
	struct stat sbuf;
	char *output,*upload_data,tmpBuf[128],custom_csid[32],fw_csid[16];
	long upload_len, fwSizeLimit;
	int  ifd, head_offset=0, pid, ret, iflags=0,custom_valid=0;
	
	char *Flags = websGetVar(data, T("Flags"), T(""));
	char *FileName = websGetVar(data, T("FileName"), T(""));
	char *FullName = websGetVar(data, T("FullName"), T(""));
	char *ContentLength= websGetVar(data, T("ContentLength"), T(""));

	cJSON *root=cJSON_CreateObject();

	CSTE_DEBUG("[%s:%d]FullName=%s\n",__FUNCTION__,__LINE__,FullName);

	upload_len = strtol(ContentLength, NULL, 10) + 1;

	if(upload_len < 256*1024)//不允许小于256K
	{
		printf("[%s:%d]upg failed, the file is too small!\n",__FUNCTION__,__LINE__);
		cJSON_AddStringToObject(root,"upgradeERR","MM_FwFileInvalid");//Unable to get Flash size
		goto err;
	}
	fwSizeLimit=getFlashSize();
	if(upload_len >= fwSizeLimit*1024*1024){//不允许大于flash 大小， 例如fwSizeLimit=8
		printf("[%s:%d]upg failed, the file is too large!fwSizeLimit=%d M.\n",__FUNCTION__,__LINE__,fwSizeLimit);
		cJSON_AddStringToObject(root,"upgradeERR","MM_FwFileErr");
		goto err;
	}

	ifd = open(FileName, O_RDONLY);
	if(!ifd){
		printf("[%s:%d]open %s failed!\n",__FUNCTION__,__LINE__,FileName);
		goto err;
	}

	if (fstat(ifd, &sbuf) < 0) {
		printf("[%s:%d]fstat %s failed!\n",__FUNCTION__,__LINE__,FileName);
		close(ifd);
		goto err;
	}

	//mmap 像访问普通内存一样对文件进行访问,快速访问文件
	upload_data = (unsigned char *) mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, ifd, 0);
	if ((caddr_t)upload_data == (caddr_t)-1) {
		printf("[%s:%d]mmap %s failed!\n",__FUNCTION__,__LINE__,FileName);
		close(ifd);
		goto err;
	}
#if defined(SUPPORT_CUSTOMIZATION)
	custom_header_t *pHeader;
	char mtdname[32],cmdBuf[128];

	pHeader = (custom_header_t *)(upload_data+head_offset);
	if(strstr(pHeader->ih_name,"USERDATABIN"))
	{
		char md5_str[40]={0};
		memcpy(fw_csid,&pHeader->ih_name[12],sizeof(fw_csid));

		rtl_name_to_mtdblock("userdata", mtdname);

		apmib_get(MIB_CSID,(void *)&custom_csid);
		if(strcmp(PRODUCT_MODEL,custom_csid)!=0 && strcmp(PRODUCT_MODEL,fw_csid)!=0 && strcmp(custom_csid,fw_csid)!=0){
			cJSON_AddStringToObject(root, "upgradeERR","MM_FwFileInvalid");
			munmap(upload_data,sbuf.st_size);
			close(ifd);
			goto err;
		}

		f_write("/var/custom.bin", upload_data+head_offset+sizeof(custom_header_t), pHeader->ih_size, FW_CREATE, 0);
		Cal_file_md5("/var/custom.bin", md5_str);
		printf("[%s:%d]ih_size=%d, ih_md5=%s,md5_str=%s!\n",__FUNCTION__,__LINE__,pHeader->ih_size,pHeader->ih_md5,md5_str);
		if(strcasecmp(md5_str,pHeader->ih_md5)!=0){
			cJSON_AddStringToObject(root, "upgradeERR","MM_FwFileInvalid");
			munmap(upload_data,sbuf.st_size);
			close(ifd);
			goto err;
		}
		wait_time+=40;
		custom_valid=1;
		head_offset+=sizeof(custom_header_t)+pHeader->ih_size;
		if((upload_len-head_offset) < 1024*1024){
			custom_valid=2;
			goto success;
		}
	}
#endif
	ret=CheckUpgradeFW(head_offset, upload_len, upload_data);
	if(ret==-1){
		printf("[%s:%d]ret=%d,Invalid upgrade firmware file!\n",__FUNCTION__,__LINE__, ret);
		cJSON_AddStringToObject(root, "upgradeERR","MM_FwFileInvalid");
		munmap(upload_data,sbuf.st_size);
		close(ifd);
		goto err;
	}

success:

	pid=fork();
	if(0 == pid)
	{
		sleep(2);
		if(0!=custom_valid){
			CsteSystem("echo 0 > /proc/udwrite", CSTE_PRINT_CMD);
			
			sprintf(cmdBuf,"cat /var/custom.bin > %s", mtdname);
			CsteSystem(cmdBuf, CSTE_PRINT_CMD);

			CsteSystem("rm -f /var/custom.bin 1>/dev/null 2>&1", CSTE_PRINT_CMD);
			if(2==custom_valid){
				CsteSystem("reboot", CSTE_PRINT_CMD);
				exit(1);
			}
		}
		iflags=atoi(Flags);
		WriteUpgradeFW( head_offset, upload_len, upload_data, iflags);
		exit(1);
	}

	cJSON_AddStringToObject(root,"upgradeStatus","1");
	sprintf(tmpBuf,"%d",wait_time);
	cJSON_AddStringToObject(root,"wtime",tmpBuf);

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);

	return 0;

err:

	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	if(output!=NULL)  free(output);
	cJSON_Delete(root);
	sprintf(tmpBuf,"rm -f %s 1>/dev/null 2>&1",FileName);
	CsteSystem(tmpBuf, CSTE_PRINT_CMD);
	return 0;
}


int SystemSettings(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char *output=NULL, flashsize[16]={0}, tmpBuf[32]={0};
	int tmp_size = 0, mesh2g_enabled, mesh5g_enabled;
	
	cJSON *root=cJSON_CreateObject();
		
	cJSON_AddNumberToObject(root,"operationMode",getOperationMode());

#if defined(FOR_DUAL_BAND)
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh5g_enabled);

	SetWlan_idx("wlan1");
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh2g_enabled);
#else
	SetWlan_idx("wlan0");
	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&mesh2g_enabled);
#endif

#if defined(SUPPORT_MESH)
	if(mesh2g_enabled==1||mesh5g_enabled==1){
		cJSON_AddNumberToObject(root,"meshEnabled",1);	
	}else{
		cJSON_AddNumberToObject(root,"meshEnabled",0);
	}
#else
	cJSON_AddNumberToObject(root,"meshEnabled",0);	
#endif

	//apmib_get(MIB_HARDWARE_VERSION,(void *)tmpBuf);
	cJSON_AddStringToObject(root,"hardModel","AC200");	

	cJSON_AddStringToObject(root,"exportAction", "/cgi-bin/cstecgi.cgi?action=upload&getSaveConfig");
	cJSON_AddStringToObject(root,"importAction", "/cgi-bin/cstecgi.cgi?action=upload&setUploadSetting");

	tmp_size = getFlashSize();
	sprintf(flashsize,"%d",tmp_size*1000);
	cJSON_AddStringToObject(root,"maxSize", flashsize);
	
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(root);
	free(output);
	return 0;
}

int setUploadSetting(struct mosquitto *mosq, cJSON* data, char *tp)
{
	printf("[%s:%d]----------Begain-------------\n",__FUNCTION__,__LINE__);
	cJSON *root;
	FILE *fp = NULL;
	long inLen;
	
	CONFIG_DATA_T type=0;
	
	int head_offset=0, status=0;
	
	char *upload_data, *inStr, *output;
	char csid[16]={0},tmpCmd[128]={0},msgBuf[128]={0}, resultbuf[16]={0};

	char *FileName = websGetVar(data, T("FileName"), T(""));
	char *ContentLength= websGetVar(data, T("ContentLength"), T(""));
	
	root=cJSON_CreateObject();

	apmib_get(MIB_CSID,(void *)csid);
	sprintf(tmpCmd,"cat %s | grep %s",FileName,csid);
	if(getCmdStr(tmpCmd,resultbuf,sizeof(resultbuf))==-1)
	{
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigFileInvalid");//Invalid config file!
		goto err;
	}

	inLen = strtol(ContentLength, NULL, 10) + 1;	
	root=cJSON_CreateObject();
	if(inLen < 1000){
		printf("[%s:%d]len=%d, the cfg file is too small!\n",__FUNCTION__,__LINE__,inLen);
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigSizeErr");
		goto err;
	}
	if(inLen >= CONFIGSIZE){
		printf("[%s:%d]len=%d, the cfg file is too large!\n",__FUNCTION__,__LINE__,inLen);
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigFileErr");
		goto err;
	}
	
	inStr = malloc(inLen);
	memset(inStr, 0, inLen);
	if((fp = fopen(FileName, "r")) != NULL){
		fread(inStr, 1, inLen, fp);
	}else{
		printf("[%s:%d]open %s failed!\n",__FUNCTION__,__LINE__,FileName);
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigSizeErr");//Unable to get config file
		free(inStr);
		goto err;
	}
	
	if(
#ifdef COMPRESS_MIB_SETTING
		!memcmp(&inStr[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		!memcmp(&inStr[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		!memcmp(&inStr[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
		!memcmp(&inStr[head_offset], CURRENT_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], HW_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&inStr[head_offset], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) 
#endif
	) {
		updateConfigIntoFlash((unsigned char *)&inStr[head_offset], (inLen-head_offset), (int *)&type, &status);
	}
	else{ // checksum error
		printf("[%s:%d]Head check error!Invalid config file!\n",__FUNCTION__,__LINE__);
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigFileInvalid");
		free(inStr);
		fclose(fp);
		goto err;
	}

	if (status == 0 || type == 0) { // checksum error
		printf("[%s:%d]checksum error!Invalid config file!\n",__FUNCTION__,__LINE__);
		cJSON_AddStringToObject(root,"settingERR","MM_ConfigFileInvalid");
		free(inStr);
		fclose(fp);
		goto err;
	}
	else {
		if (type) { // upload success
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
			CsteSystem("rsCert -rst", CSTE_PRINT_CMD);
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT 
			//To clear CA files
			CsteSystem("storeWapiFiles -reset", CSTE_PRINT_CMD);
#endif
		}	
		apmib_reinit();
		apmib_update_web(CURRENT_SETTING);	// update configuration to flash
		
		cJSON_AddStringToObject(root, "settingERR","1");
		sprintf(msgBuf,"%d",wait_time);
		cJSON_AddStringToObject(root,"wtime",msgBuf);
		getLanIp(msgBuf);
		cJSON_AddStringToObject(root, "lan_ip",msgBuf);
		
		output=cJSON_Print(root);		
		websGetCfgResponse(mosq, tp, output);
	
		free(output);
		cJSON_Delete(root);
		fclose(fp);

		int pid=fork();
		if(0 == pid){
			sleep(2);
			CsteSystem("reboot", CSTE_PRINT_CMD);
			exit(1);
		}
	}
	printf("[%s:%d]----------End-------------\n",__FUNCTION__,__LINE__);
	return 0;
err:

	printf("[%s:%d]----------Err-------------\n",__FUNCTION__,__LINE__);
	output=cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);
	free(output);
	cJSON_Delete(root);
	return 0;
}

#if defined(CONFIG_PA_ONLINE_IP)
static int cleanAppfiltercCfg(void)
{
	char appbuf[32] = {0};
	int intval = 0;

	struct dirent *ent;
	
    DIR *dir = opendir(APP_CONFIG_PATH);
	if(dir == NULL){
        perror("cannot open the path\n");
		return 0;
    }
    while((ent=readdir(dir)) != NULL)
    {
        if(!strstr(ent->d_name,"app_config"))
            continue;
        struct stat st;
        char *name = (char *)malloc(sizeof(char)*FILE_DIR_LEN);
        memset(name,'\0',sizeof(char)*FILE_DIR_LEN);
        strcpy(name,APP_CONFIG_PATH);
        strcat(name,"/");
        strcat(name,ent->d_name);
		int f=stat(name,&st);
        if(f != -1)
        {
			FILE *fp = fopen(name, "r+");
			if(!fp){
				printf("can not open config file\n");
				free(name);
				continue;
			}
			char *buffer = (char *)malloc(sizeof(char)*st.st_size+1);
			memset(buffer,'\0',sizeof(char)*st.st_size+1);
			fread(buffer,st.st_size,1,fp);
			fclose(fp);
			char *appid = buffer;
			while(appid){
				appid = strstr(appid,"appid");
				if(appid == NULL)
					break;
				while(*appid<'0'||*appid>'9'){//atoi must  '0'-'9' start can succ
					appid++;
				}
				int appid_int = atoi(appid);
				if(appid_int<1000){
					continue;
				}
				sprintf(appbuf,"app_%d",appid_int);
				setAppfilterSwitch(appbuf,&intval);
			}
			free(buffer);
        }
		free(name);
    }
	closedir(dir);
	apmib_set(MIB_APPFILTER_ENABLED, (void *)&intval);
	apmib_set(MIB_GAMESPEED_ENABLED, (void *)&intval);
	apmib_update_web(CURRENT_SETTING);

    return 0;
}

int setQosConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	int f;
	long inLen;
	char cmd[128] = {0};
	char *output, *p=NULL;
	char *FileName = websGetVar(data, T("FileName"), T(""));
	char *ContentLength= websGetVar(data, T("ContentLength"), T(""));

	inLen = strtol(ContentLength, NULL, 10) + 1;
	
	cJSON *rsp=cJSON_CreateObject();
	if(inLen >= 1024*1024){
		cJSON_AddStringToObject(rsp, "settingERR","MSG_config_big");
		goto err;
	}
	if ((f = open(FileName, O_RDONLY)) < 0){ 
		cJSON_AddStringToObject(rsp, "settingERR","MM_ConfigFileInvalid");
		goto err;
	}
	system("mkdir -p /tmp/ibms");
	sprintf(cmd, "cp %s /tmp/ibms_config.tar.gz",FileName);
	CsteSystem(cmd, CSTE_PRINT_CMD);
	sprintf(cmd, "cd /tmp;gzip -d /tmp/ibms_config.tar.gz");
	CsteSystem(cmd, CSTE_PRINT_CMD);
	sprintf(cmd, "cd /tmp;tar -xf /tmp/ibms_config.tar -C /tmp/ibms",FileName);
	CsteSystem(cmd, CSTE_PRINT_CMD);

	if( 0 == d_exist("/tmp/ibms/ibms_config"))
	{
		cJSON_AddStringToObject(rsp, "settingERR","MM_ConfigFileInvalid");
		goto err;
	}
	cJSON_AddStringToObject(rsp, "settingERR","1");
	int pid=fork();
	if(0 == pid){
		sprintf(cmd, "echo %d > /proc/udwrite",0);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		cleanAppfiltercCfg();
		sprintf(cmd, "rm  -rf %s",APP_CONFIG_PATH);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		sprintf(cmd, "mkdir -p %s",APP_CONFIG_PATH);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		sprintf(cmd, "cp /tmp/ibms/ibms_config/* %s ",APP_CONFIG_PATH);
		CsteSystem(cmd,CSTE_PRINT_CMD);
		sleep(2);
		CsteSystem("reboot", CSTE_PRINT_CMD);
		exit(1);
	}
err:
	unlink(FileName);
	output =cJSON_Print(rsp);	
	websGetCfgResponse(mosq,tp,output);
	cJSON_Delete(rsp);
	free(output);
	return 0;
	
}

int uploadQosConfig(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char hardModel[16]={0};
	char *output=NULL,filesize[16]={0};
	int tmp_size = 0;
	cJSON *root;
	
	root=cJSON_CreateObject();

	apmib_get(MIB_HARDWARE_MODEL,(void *)hardModel);
	cJSON_AddStringToObject(root,"hardModel", hardModel);

	cJSON_AddStringToObject(root,"meshEnabled", "0");

	cJSON_AddStringToObject(root,"exportAction", "/cgi-bin/ExportIbmsConfig.sh");
	cJSON_AddStringToObject(root,"importAction", "/cgi-bin/cstecgi.cgi?action=upload&setting/setQosConfig");

	tmp_size = getFlashSize();
	sprintf(filesize,"%d",tmp_size*1000);
	cJSON_AddStringToObject(root,"maxSize", filesize);
	output =cJSON_Print(root);
	websGetCfgResponse(mosq,tp,output);

	cJSON_Delete(root);
	free(output);
	return 0;
}

#endif

//-----------------------------------------------------------------
int module_init()
{
	cste_save_fwinfo();
	cste_hook_register("FirmwareUpgrade",FirmwareUpgrade);
	cste_hook_register("setUpgradeFW",   setUpgradeFW);

	cste_hook_register("SystemSettings",   SystemSettings);
	cste_hook_register("setUploadSetting", setUploadSetting);
	
	cste_hook_register("CloudACMunualUpdate", CloudACMunualUpdate);
#if defined(SUPPORT_MESH)
	cste_hook_register("slaveUpgrade", slaveUpgrade);
#endif
#ifdef CONFIG_APP_EASYCWMP
	cste_hook_register("AcsUpdate",AcsUpdate);
#endif

#if defined(CONFIG_PA_ONLINE_IP)
	cste_hook_register("setQosConfig",setQosConfig);
	cste_hook_register("uploadQosConfig",uploadQosConfig);
#endif

    return 0;  
}
