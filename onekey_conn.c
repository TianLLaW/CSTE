
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include "cstelib.h"
#include "apmib.h"
#include "mibtbl.h"


#define 	GETDATA_TAG "GET CONFIG"
#define   LISTEN_PORT 8003
#define   REMOTE_IP_SEG "192.168.166."
#define   APCLIENT_NAME "wlan0-vxd"
#define   MANAGE_SSID  "TOTOLINK-manage"
#define MAX_LOG_LEN 256

#define LOG_TAG "onekey_conn: "

int client_wlanidx;

#if 0
#define util_logger(fmt, args...) printf(fmt, args...)
#else
#define util_logger(fmt, args...) do { \
FILE *fp = fopen("/tmp/onekey_conn.log", "a"); \
	if (fp) { \
		fprintf(fp, LOG_TAG fmt , ## args); \
		fclose(fp); \
	} \
} while(0)
#endif

int get_main_ssid_config(char *config_info,int wlanIdx)
{
	int auth_mode,ciphersuite1=WPA_CIPHER_AES,ciphersuite2=WPA_CIPHER_AES,pskformat;
	char ssid[32]={0},bssid[32]={0},encryption[32]={0},wpaKey[64]={0},wlan_if[8]={0};
	unsigned char mac[6];
	sprintf(wlan_if,"wlan%d",wlanIdx);
	SetWlan_idx(wlan_if);
	apmib_get(MIB_WLAN_SSID, (void *)ssid);
	apmib_get(MIB_WLAN_WPA_PSK,(void *)wpaKey);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&auth_mode);
	apmib_get( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	apmib_get( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
	apmib_get(MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
	apmib_get(MIB_HW_WLAN_ADDR,mac);
	sprintf(bssid,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

	if (auth_mode==2){
		if (ciphersuite1==WPA_CIPHER_AES)
			strcpy(encryption, "psk+ccmp");
		else
			strcpy(encryption, "psk+tkip");
	}
	else if (auth_mode==4){
		if (ciphersuite2==WPA_CIPHER_AES)
			strcpy(encryption, "psk2+ccmp");
		else if (ciphersuite2==WPA_CIPHER_TKIP)
			strcpy(encryption, "psk2+tkip");
		else
			strcpy(encryption, "psk2+tkip+ccmp");
	}
	else if (auth_mode==6){
		if ((ciphersuite1 = WPA_CIPHER_AES))
			strcpy(encryption, "psk-mixed+ccmp");
		else if (ciphersuite1 = WPA_CIPHER_TKIP)
			strcpy(encryption, "psk-mixed+tkip");
		else
			strcpy(encryption, "psk-mixed+tkip+ccmp");
	}
	
	sprintf(config_info,"bssid=%s ssid=%s encryption=%s key=%s key1=%s keys=%s pskformat=%d",bssid,ssid,encryption,wpaKey,"","",pskformat);

}

int set_main_ssid_config(char *config_info)
{
	char buff[64]={0},pskformat[8]={0};
	char ssid[32]={0},mac_bssid[32]={0},encryption[32]={0},key[64]={0},key1[64]={0},keys[64]={0};
	if(strlen(config_info)==0)return 0;
	sscanf(config_info,"bssid=%s ssid=%s encryption=%s key=%s key1=%s keys=%s pskformat=%s",mac_bssid,ssid,encryption,key,key1,keys,pskformat);
	printf("[onekey_conn] set config!\n");

	if(client_wlanidx == 0){
		SetWlan_idx("wlan0-vxd");
		apmib_set(MIB_REPEATER_SSID1, (void *)ssid);
	}else if(client_wlanidx == 1){
		SetWlan_idx("wlan1-vxd");		
		apmib_set(MIB_REPEATER_SSID2, (void *)ssid);
	}	

	apmib_set(MIB_WLAN_SSID, (void *)ssid); 
	apmib_set(MIB_WLAN_WSC_SSID, (void *)ssid);
	apmib_set(MIB_ROOTAP_MAC, (void *)mac_bssid);
	
	int auth_mode=0,wep=WEP_DISABLED;
	int auth_wpa=WPA_AUTH_PSK;
	int ciphersuite1=WPA_CIPHER_AES,ciphersuite2=WPA_CIPHER_AES;

	if(strcmp(encryption,"psk+ccmp")==0)
	{
		auth_mode=ENCRYPT_WPA;
		ciphersuite1=WPA_CIPHER_AES;
	}else if(strcmp(encryption,"psk+tkip")==0)
	{
		auth_mode=ENCRYPT_WPA;
		ciphersuite2=WPA_CIPHER_TKIP;
	}else if(strcmp(encryption,"psk2+ccmp")==0)
	{
		auth_mode=ENCRYPT_WPA2;
		ciphersuite2=WPA_CIPHER_AES;
	}else if(strcmp(encryption,"psk2+tkip")==0)
	{
		auth_mode=ENCRYPT_WPA2;
		ciphersuite2=WPA_CIPHER_TKIP;
	}else if(strcmp(encryption,"psk2+tkip+ccmp")==0)
	{
		auth_mode=ENCRYPT_WPA2;
		ciphersuite2=WPA_CIPHER_MIXED;
	}else if(strcmp(encryption,"psk-mixed+ccmp")==0)
	{
		auth_mode=ENCRYPT_WPA2_MIXED;
		ciphersuite1 = WPA_CIPHER_AES;
        ciphersuite2 = WPA_CIPHER_AES;
	}else if(strcmp(encryption,"psk-mixed+tkip")==0)
	{
		auth_mode=ENCRYPT_WPA2_MIXED;
		ciphersuite1 = WPA_CIPHER_TKIP;
        ciphersuite2 = WPA_CIPHER_TKIP;
	}else if(strcmp(encryption,"psk-mixed+tkip+ccmp")==0)
	{
		auth_mode=ENCRYPT_WPA2_MIXED;
		ciphersuite1 = WPA_CIPHER_MIXED;
        ciphersuite2 = WPA_CIPHER_MIXED;
	}else{	
		printf("No such encryption\n");
		}
	
	apmib_set( MIB_WLAN_WEP, (void *)&wep);
	apmib_set( MIB_WLAN_WPA_PSK,(void *)key);
	apmib_set( MIB_WLAN_WSC_AUTH, (void *)&auth_wpa);
	apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
	apmib_set( MIB_WLAN_WSC_PSK, (void *)key);
	apmib_set( MIB_WLAN_ENCRYPT, (void *)&auth_mode);
	apmib_set( MIB_WLAN_WSC_ENC, (void *)&auth_mode);	
	apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
	apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
	int format=atoi(pskformat);
	apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&format);
	int pid=fork();
	if(0 == pid)
	{
		sleep(1);
		apmib_update_web(CURRENT_SETTING);
		exit(1);
	}
	
	return 1;
}


int server(char *ipstr)
{
	int udpSocket, nBytes;
	char buffer[1024] = {0};
	struct sockaddr_in serverAddr, clientAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size, client_addr_size;
	int i;

	fd_set readfd; //
	struct timeval timeout;
	int ret = 0;

	/*Create UDP socket*/
	udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

	if (udpSocket < 0)
	{
		util_logger("create server socket failed:");
		return -1;
	}

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(LISTEN_PORT);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//inet_addr(ipstr);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

	/*Bind socket with address struct*/
	bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverStorage;

	while(1){
		timeout.tv_sec = 100;
		timeout.tv_usec = 0;
		
		FD_ZERO(&readfd);
		
		FD_SET(udpSocket, &readfd);
		
		ret = select(udpSocket + 1, &readfd, NULL, NULL, &timeout);

		switch (ret)
		{
			case -1:
				perror("select error:");
				break;
			case 0:
				break;
			default:
				if (FD_ISSET(udpSocket,&readfd))
				{
				/* Try to receive any incoming UDP datagram. Address and port of 
				requesting client will be stored on serverStorage variable */
				nBytes = recvfrom(udpSocket,buffer,1024,0,(struct sockaddr *)&serverStorage, &addr_size);
				
				 if (strstr(buffer, GETDATA_TAG))
				 {
				 		int wlanIdx=0;
				 		sscanf(buffer,"GET CONFIG wlanIdx=%d",&wlanIdx);
						get_main_ssid_config(buffer,wlanIdx);
						
						nBytes = strlen(buffer) + 1;
						/*Send uppercase message back to client, using serverStorage as the address*/
						sendto(udpSocket,buffer,nBytes,0,(struct sockaddr *)&serverStorage,addr_size);
				 }
				}
			break;
		}
		
	}

  	if (udpSocket >= 0)
	{
       	close(udpSocket);
  	}
  return 0;
}

int start_client()
{
		char remote_ip[32] = {0};
		char bssid[32] = {0};
		int  tmp_mac[6] = {0};
		apmib_get(MIB_ROOTAP_MAC,(void *)bssid);
		sscanf(bssid,"%2x:%2x:%2x:%2x:%2x:%2x",&tmp_mac[0],&tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
		if(client_wlanidx == 1)
			tmp_mac[5] = tmp_mac[5] - 4;

		if(tmp_mac[5] == 0)
			tmp_mac[5]=1;
		if(tmp_mac[5] == 255)
			tmp_mac[5]=254;
	
		sprintf(remote_ip,"%s%d",REMOTE_IP_SEG,tmp_mac[5]);
		util_logger("remote ip is %s\n",remote_ip);
		client(remote_ip);
		
}

int check_apcli_link_manage_ssid()
{
		char ssid[32] = {0};
		int ret = 0;
		
		if(client_wlanidx == 0){
			ret = getRepeaterStatus("wlan0-vxd");
			apmib_get(MIB_REPEATER_SSID1, (void *)ssid);
		}else if(client_wlanidx == 1){
			ret = getRepeaterStatus("wlan1-vxd");
			apmib_get(MIB_REPEATER_SSID2, (void *)ssid);
		}
		if(1 == ret)
		{
			if (!strncmp(ssid, MANAGE_SSID,15))
			{
				printf("ssid is %s\n",ssid);
				return 1;
			}
		}
		return 0;
}
int client(char *server_ipstr)
{
	int clientSocket, portNum, nBytes;
	char send_buf[521]= {0};
	char rcv_buf[521] = {0};
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	
	fd_set readfd; //读文件描述符集合
	struct timeval timeout;
	int ret = 0, val = 0;
	char wlan_if[16] = {0};


  while(1){

		if(1 == check_apcli_link_manage_ssid())
		{
			/*Create UDP socket*/
			clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
			if (clientSocket < 0)
			{
			      util_logger("create socket failed:");
				 continue;
			}

			/*Configure settings in address struct*/
			serverAddr.sin_family = AF_INET;
			serverAddr.sin_port = htons(LISTEN_PORT);
			serverAddr.sin_addr.s_addr = inet_addr(server_ipstr);
			util_logger("client socket and remote ip: %s\n",server_ipstr);
			memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

			/*Initialize size variable to be used later on*/
			addr_size = sizeof serverAddr;

			sprintf(send_buf,"%s wlanIdx=%d",GETDATA_TAG,client_wlanidx);
			nBytes = strlen(send_buf) + 1;
			/*Send message to server*/
			sendto(clientSocket,send_buf,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);

			timeout.tv_sec = 2;
			timeout.tv_usec = 0;

			FD_ZERO(&readfd);

			FD_SET(clientSocket, &readfd);

			ret = select(clientSocket + 1, &readfd, NULL, NULL, &timeout);
			
			switch (ret)
			{
			    case -1:
			        perror("client select error:");
			        break;
			    case 0:
			        break;
			    default:
			        if (FD_ISSET(clientSocket,&readfd))
			        {
			        	memset(rcv_buf,0,sizeof(rcv_buf));
						/*Receive message from server*/
						nBytes = recvfrom(clientSocket,rcv_buf,1024,0,NULL, NULL);	
						util_logger("Received from server: %s\n",rcv_buf);
						val = set_main_ssid_config(rcv_buf);
			        }
				break;
			}
			if (clientSocket >= 0)
				close(clientSocket);
			if(val == 1){
				sprintf(wlan_if,"wlan%d-vxd",client_wlanidx);
				takeEffectWlan(wlan_if, 1);
				break;
			}
		}

		 sleep(1);
  }

  return 0;
}

int set_brlan2_ip(char *ipstr)
{
	char mac_str[32] ={0};
	int  tmp_mac[6] = {0}; 
	char cmd_buf[64] = {0}; 
	unsigned char mac[6];
	apmib_get(MIB_HW_WLAN_ADDR,mac);
	sprintf(mac_str,"%2x:%2x:%2x:%2x:%2x:%2x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]); 

	sscanf(mac_str,"%2x:%2x:%2x:%2x:%2x:%2x",&tmp_mac[0],&tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);

	if(tmp_mac[5] == 0)
		tmp_mac[5]=1;
	if(tmp_mac[5] == 255)
		tmp_mac[5]=254;
	
	sprintf(ipstr,"%s%d",REMOTE_IP_SEG,tmp_mac[5]);
	sprintf(cmd_buf,"ifconfig br0:1 %s up",ipstr);

	system(cmd_buf);
	util_logger("%s\n",cmd_buf);
		
	return 0;

}

int main()
{
	char OperationMode[8] = {0};
	char ipstr[32]={0};
	int opmode = 0,repEnable1 = 0,repEnable2 = 0;

	if ( !apmib_init()) {		
			CSTE_DEBUG("Initialize AP MIB failed !\n");
			return ;	
	}

	
	apmib_get(MIB_OP_MODE,	(void *)&opmode);

	apmib_get(MIB_REPEATER_ENABLED1, (void *)&repEnable1);
#if defined(FOR_DUAL_BAND)	
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&repEnable2);
#endif
	if (-1 == getIfIp("br0:1", ipstr))
	{
		util_logger("error no ip is %s\n",ipstr);
		if(-1 == set_brlan2_ip(ipstr))
		{
			return -1;
		}
	}

	if(1 == opmode && repEnable1==0 && repEnable2==0)//BRIDGE_MODE
	{
		util_logger("server ip %s\n",ipstr);
		server(ipstr);
	}
	else if((4 == opmode) ||( 1 == opmode && (repEnable1==1 || repEnable2==1)))//rpt or client mode
	{
		util_logger("mode %d,1--repeater,4--client\n",opmode);
		if(repEnable1==1&&repEnable2==0){
			client_wlanidx = 0;//wlan0
		}else if(repEnable1==0&&repEnable2==1){
			client_wlanidx = 1;//wlan1
		}
		start_client();
	}
	util_logger("opmode %d\n",opmode);		
	return 0;								
}
