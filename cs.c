
/* System include files */
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define usleep_time 100000  //0.1s


static int get_flash_str_value(char *keyword, char *pVal)
{	
	FILE *fp; 	
	char buf[128];	
	char tmp[128];	
	char *tmpVal;
	
	sprintf(buf, "flash get %s", keyword);    
	fp = popen(buf, "r");	
	if (fp==NULL)		
		return -1;
	
	if (NULL == fgets(buf, sizeof(buf),fp)) {		
		pclose(fp);		
		return -1;	
	}	
	pclose(fp);	
	
	strcpy(pVal, strstr(buf, "=")+1);    
	/*   replace \ to emport for ssid include space */    
	char *p,*p1,tmpbuf[128];    
	p1=buf;    
	while(p=strstr(buf,"\\")){        
		p[0]='\0';        
		memset(tmpbuf,0,128);        
		strcat(tmpbuf,p1);        
		strcat(tmpbuf,p+1);        
		strcpy(buf,tmpbuf);        
		p1=buf;    
	}	
	/*   del " if have   */	
	if(tmpVal = strstr(buf, "\""))	
	{        
		strcpy(tmp,++tmpVal);        
		tmp[strlen(tmp)-2]='\0';		
		strcpy(pVal, tmp);	
	}	
	else	
	{		
		pVal[strlen(pVal)-1]='\0';	
	}		
	return 0;
}

int read_md5()
{
	char tmp[2] = {0},tmpbuf[128]={0};
	FILE *fp;
	int i = 0;
	
	fp = fopen("/mnt/SysCurVerMd5", "r");
	if (!fp) {
		printf("Read file error:/mnt/SysCurVerMd5!\n");
		return -1;
	}
	while(!feof(fp)){
		fread(tmp,1,1,fp);
		tmpbuf[i++] = tmp[0];
	}
	tmpbuf[i-2]='\0';//del "\n\r"
	
	fclose(fp);
	printf("MD5     %s\n",tmpbuf);
	
	return 0;
}

int read_mac(char *interface)
{
	char input_mac[32]={0};
	
	if(strcmp(interface,"lan")==0){
		get_flash_str_value("HW_WLAN0_WLAN_ADDR",input_mac);
		printf("LAN MAC     %s\n",input_mac);
	}else if(strcmp(interface,"wan")==0){
		get_flash_str_value("HW_NIC1_ADDR",input_mac);
		printf("WAN MAC     %s\n",input_mac);
	}else if(strcmp(interface,"2g")==0){
#if defined(FOR_DUAL_BAND)
		get_flash_str_value("HW_WLAN1_WLAN_ADDR",input_mac);
#else
		get_flash_str_value("HW_WLAN0_WLAN_ADDR",input_mac);
#endif
		printf("2G  MAC     %s\n",input_mac);
	}else if(strcmp(interface,"5g")==0){
		get_flash_str_value("HW_WLAN0_WLAN_ADDR",input_mac);
		printf("5G  MAC     %s\n",input_mac);
	}
	
	return 0;
}

int write_mac(char *mac)
{	
	int i,j;
	char buf[128]={0},tembuf[64]={0},t_lower[64]={0};

	for(i=0;i<strlen(mac);i++)
		t_lower[i] = tolower(mac[i]);
	
	if(strchr(t_lower,':')!=NULL){
		tembuf[0]=t_lower[0];
		j=1;
		for(i=1;i<strlen(t_lower);i++){
			if((i+1)%3!=0){
				tembuf[j]=t_lower[i];
				j++;
			}
		}
		sprintf(buf,"flash set HW_WLAN0_WLAN_ADDR %s",tembuf);
	}else
		sprintf(buf,"flash set HW_WLAN0_WLAN_ADDR %s",t_lower);
	system(buf);
	return 0;
}

int compare_argv(char *argv, char *comp)
{
	int i;
	char t_comp[32]={0};

	for(i=0;i<strlen(argv);i++)
		t_comp[i] = tolower(argv[i]);
	if(strcmp(t_comp,comp)==0)
		return 1;
		
	return 0;
}

static int cs_help( void )
{
	printf("Usage: \n");
	printf("cs reset \n");
	printf("cs mac w [ XXXXXXXXXXX | XX:XX:XX:XX:XX:XX] \n");
	printf("cs mac r [ lan | wan | 2g | 5g ], Null is get all \n");
	printf("cs sn w	[ 8-24 ] \n");
	printf("cs sn r	[ read SN ] \n");
	printf("cs cpu	[ read CPU model ] \n");
	printf("cs mem	[ read Memory size] \n");
	printf("cs device	[ read Device model ] \n");
	printf("cs flash	[ read Flash size ] \n");
	printf("cs md5 \n");
	printf("cs usb	[ 1/0 ] \n");
	printf("cs button_disable \n");
	printf("cs button_status  \n");
	printf("cs button_enable  \n");
	printf("cs portspeed x  \n");
	return 0;
}

int status_mount()
{
	int iRet=0;
	FILE *fp = popen("cat /proc/mounts | grep usb", "r");
	char dir[13];

	while(EOF != fscanf(fp, "%*s %s %*s %*s %*s %*s\n", dir)){
		if (strstr(dir, "/usb/sd")!=NULL){
			iRet=1;
		}
	}
	pclose(fp);

	return iRet;
}

int portspeed(int index)
{
	char *p = NULL, *q = NULL ;
	char port[8], speed[8], buf[256] = {0};
	int thisPort=0;

	sprintf(port,"Port%d",index);

	FILE *fp = fopen("/proc/rtl865x/port_status", "r");
	if(!fp){
		printf("portspeed failed\n");
		return -1;
	}
	
	while (fgets(buf, sizeof(buf), fp) != NULL){
		p = strstr(buf, port);
		if(p){
			thisPort=1;
			q = strstr(p, "LinkUp");
			if(!q){
				printf("%s LinkDown\n",port);
				return 0;
			}
		}
		else if(1==thisPort){
			p = strstr(buf, "Speed");
			if(p){
				strcpy(speed,p+6);
				break;
			}
		}
	}
	fclose(fp);
	printf("%s Speed:%s\n",port,speed);
	
	return 0;
}

int main(int argc, char** argv)
{
	int i;
	//printf("start.......:%s\n",argv[1]);
#if 0   
{
    printf("******************\n");
    for(i=0;i<argc;i++)
    {
        printf("%s [%d]",argv[i],i);
    }
    printf("\n***************\n");
}
#endif
	if(argv[1] && (compare_argv(argv[1], "reset")==1)){
		if(argc > 2)
			goto err;
#if defined(SUPPORT_APAC)
#if defined(CONFIG_KL_C8B180A_AP0167)||defined(CONFIG_KL_CSB180A_AP0167)||defined(CONFIG_KL_C8B181A_AP0169)
				system("csteSys reg 1 0xb8003528 25 1");//¹Ø±ÕºìÉ«µÆH1
#elif defined(CONFIG_KL_C8B182A_AP0170)
				system("csteSys reg 1 0xb800350c 15 1");//¹Ø±ÕºìÉ«µÆ
#endif	
				system("csteSys reg 1 0xb800350c 31 2");//ÂÌµÆ¿ìÉÁ
				system("csteSys csnl 1 -2");
#endif
		system("flash reset");
		printf("OK\n");

		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "mac")==1)){
		if(argv[2] && (compare_argv(argv[2], "w")==1)){
			if(argc > 4)
				goto err;
			if(argv[3]){
				write_mac(argv[3]);
				return 1;
			}
		}
		else if(argv[2] && (compare_argv(argv[2], "r")==1)){
			if(argc > 7)
				goto err;
			if(argc == 3){
				read_mac("lan");
				read_mac("wan");
				read_mac("2g");
#if defined(FOR_DUAL_BAND)
				read_mac("5g");
#endif
			}
			for(i=3;i<argc;i++){
				if(argv[i] && (compare_argv(argv[i], "lan")==1)){
					read_mac("lan");
				}else if(argv[i] && (compare_argv(argv[i], "wan")==1)){
					read_mac("wan");
				}else if(argv[i] && (compare_argv(argv[i], "2g")==1)){
					read_mac("2g");
#if defined(FOR_DUAL_BAND)
				}else if(argv[i] && (compare_argv(argv[i], "5g")==1)){
					read_mac("5g");
#endif
				}else{
					goto err;
				}
			}
			return 1;
		} 	
	}
	else if(argv[1] && (compare_argv(argv[1], "md5")==1)){
		if(argc > 2)
			goto err;
		read_md5();
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "sn")==1)){
		if(argv[2] && (compare_argv(argv[2], "w")==1)){
			if(argc > 4)
				goto err;
			if(strlen(argv[3])<8 || strlen(argv[3])>24)
				return 1;
			if(argv[3]){
				char buf[128]={0};
				sprintf(buf,"flash set HW_PRODUCT_SN %s",argv[3]);
				system(buf);
				return 1;
			}
		}
		else if(argv[2] && (compare_argv(argv[2], "r")==1)){
			if(argc > 3)
				goto err;
				
			char tmpStr[32]={0};
			get_flash_str_value("HW_PRODUCT_SN",tmpStr);
			printf("PRODUCT_SN:	%s\n",tmpStr);
			return 1;
		}		
	}
	else if(argv[1] && (compare_argv(argv[1], "wifi2gkey")==1)){
#if defined(FOR_DUAL_BAND)	
		if(argv[2] && (compare_argv(argv[2], "w")==1)){
			if(argc > 4)
				goto err;
			if(argv[3]){
				if(strlen(argv[3])<8 || strlen(argv[3])>63)
					return 1;
				char buf[128]={0};
				system("flash set WLAN1_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set WLAN1_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN1_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN1_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set WLAN1_WPA_PSK %s",argv[3]);
				system(buf);

				system("flash set DEF_WLAN1_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set DEF_WLAN1_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN1_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN1_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set DEF_WLAN1_WPA_PSK %s",argv[3]);
				system(buf);
				
				return 1;
			}
		}
		else if(argv[2] && (compare_argv(argv[2], "r")==1)){
			if(argc > 3)
				goto err;
			
			char tmpStr[65]={0};
			get_flash_str_value("WLAN1_WPA_PSK",tmpStr);
			printf("WIFI2GKEY:	%s\n",tmpStr);
			return 1;
		}	
#else
		if(argv[2] && (compare_argv(argv[2], "w")==1)){
			if(argc > 4)
				goto err;
			if(argv[3]){
				if(strlen(argv[3])<8 || strlen(argv[3])>63)
					return 1;
				char buf[128]={0};
				system("flash set WLAN0_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set WLAN0_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN0_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN0_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set WLAN0_WPA_PSK %s",argv[3]);
				system(buf);

				system("flash set DEF_WLAN0_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set DEF_WLAN0_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN0_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN0_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set DEF_WLAN0_WPA_PSK %s",argv[3]);
				system(buf);
				return 1;
			}
		}
		else if(argv[2] && (compare_argv(argv[2], "r")==1)){
			if(argc > 3)
				goto err;
			
			char tmpStr[65]={0};
			get_flash_str_value("WLAN0_WPA_PSK",tmpStr);
			printf("WIFI2GKEY:	%s\n",tmpStr);
			return 1;
		}
#endif
	}
	else if(argv[1] && (compare_argv(argv[1], "wifi5gkey")==1)){
		if(argv[2] && (compare_argv(argv[2], "w")==1)){
			if(argc > 4)
				goto err;
			if(argv[3]){
				if(strlen(argv[3])<8 || strlen(argv[3])>63)
				{
					return 1;
				}
				
				char buf[128]={0};
				system("flash set WLAN0_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set WLAN0_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN0_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set WLAN0_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set WLAN0_WPA_PSK %s",argv[3]);
				system(buf);

				system("flash set DEF_WLAN0_ENCRYPT 6");//ENCRYPT_WPA2_MIXED
				system("flash set DEF_WLAN0_WPA_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN0_WPA2_CIPHER_SUITE 3");//WPA_CIPHER_MIXED
				system("flash set DEF_WLAN0_PSK_FORMAT 0");//KEY_ASCII
				sprintf(buf,"flash set DEF_WLAN0_WPA_PSK %s",argv[3]);
				system(buf);
				return 1;
			}
		}else if(argv[2] && (compare_argv(argv[2], "r")==1)){
			if(argc > 3)
				goto err;
			
			char tmpStr[65]={0};
			get_flash_str_value("WLAN0_WPA_PSK",tmpStr);
			printf("WIFI2GKEY:	%s\n",tmpStr);
			return 1;
		}		
	}
	else if(argv[1] && (compare_argv(argv[1], "cpu")==1)){
		if(argc > 2)
			goto err;
		char strVal[64]={0},strVal2[16]={0};
		getCmdStr("cat /proc/cpuinfo  | grep cpu  | cut -f2 -d:",strVal,sizeof(strVal));
		getCmdStr("cat /proc/cpuinfo  | grep system  | cut -f2 -d:",strVal2,sizeof(strVal2));
		printf("CPU mode:	%s %s\n",strVal2,strVal);
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "mem")==1)){
		if(argc > 2)
			goto err;
		int memTotal=0;
		memTotal=getCmdVal("cat /proc/meminfo | grep MemTotal  | awk '{print $2}'");
		printf("Memory size:	%d MB\n",memTotal/1024);
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "device")==1)){
		if(argc > 2)
			goto err;
		char deviceName[32]={0};
	//	getCmdStr("cat /tmp/fwinfo  | grep PRODUCT_MODEL  | awk '{print $2}'",deviceName,sizeof(deviceName));
		get_flash_str_value("HARDWARE_MODEL",deviceName);
		printf("Device Name:	%s\n",deviceName);
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "flash")==1)){
		if(argc > 2)
			goto err;
		int flashSize=0;
		flashSize=getFlashSize();
		printf("Flash Size:	%d MB\n",flashSize);
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "usb")==1)){
		if(argc > 2)
			goto err;
		int iRet=0;
		iRet=status_mount();
		printf("%d\n",iRet);
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "button_disable")==1)){
		if(argc > 2)
			goto err;
		
		system("csteSys button_disable");
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "button_enable")==1)){
		if(argc > 2)
			goto err;

		system("csteSys button_enable");
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "button_status")==1)){
		if(argc > 2)
			goto err;

		system("csteSys button_status");
		int count=0;
		while(count<60){
			usleep(usleep_time);
			if(f_exist("/tmp/button_press")){
				printf("OK\n");
				system("rm -f /tmp/button_press");
				break;
			}
			count++;
		}
		return 1;
	}
	else if(argv[1] && (compare_argv(argv[1], "portspeed")==1)){
		if(argc < 2 || argc > 3)
			goto err;

		portspeed(atoi(argv[2]));
		return 1;
	}
	
	err:
		cs_help();
		
	return 0;
}

