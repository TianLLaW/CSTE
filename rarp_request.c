#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <signal.h>
//netlink
#include <sys/socket.h>
/* Local include files */
#include <time.h>
#include <string.h>  
#include <errno.h>  
#include <netdb.h>  
  
#include <sys/types.h>  
  
#include <netinet/if_ether.h>  
#include <netinet/in.h>  
  
#include <arpa/inet.h>  


	//File Name : get_ip_by_mac.cpp

struct arpMsg {
	struct ethhdr ethhdr;    /* Ethernet header */
	u_short htype;    /* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;    /* protocol type (must be ETH_P_IP) */
	u_char  hlen;    /* hardware address length (must be 6) */
	u_char  plen;    /* protocol address length (must be 4) */
	u_short operation;   /* ARP opcode */
	u_char  sHaddr[6];   /* sender's hardware address */
	u_char  sInaddr[4];   /* sender's IP address */
	u_char  tHaddr[6];   /* target's hardware address */
	u_char  tInaddr[4];   /* target's IP address */
	u_char  pad[18];   /* pad for min. Ethernet payload (60 bytes) */
};

	/* miscellaneous defines */
#define MAC_BCAST_ADDR  (uint8_t *) "\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2


void print_mac(unsigned char * mac_addr)
{
	int i=0;
	for (i =0; i < 6; ++i)
	{
		printf("%02X", mac_addr[i]);
		if (i != 5) printf(":");
	} 
	printf("\n");
} 

void print_ip(unsigned char * ip_addr)
{
	int i=0;
	char tmpIp[16]={0},tmpCmd[64]={0};

	sprintf(tmpIp,"%d.%d.%d.%d",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
	sprintf(tmpCmd,"echo %d.%d.%d.%d > /tmp/mesh_ac_ip",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
	printf("tmpIp: %s\n",tmpIp);
	system(tmpCmd);
} 

void  get_local_addr(unsigned char *mac)
{
	struct ifconf  interface_conf;
	struct ifreq  ifreq1;
	int     sock;
	struct sockaddr_in* psockaddr_in = NULL;

	if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("Unable to create socket for geting the mac address");
		exit(1);
	}  
	strcpy(ifreq1.ifr_name, "br0");

	if (ioctl(sock, SIOCGIFHWADDR, &ifreq1) < 0)
	{
		perror("Unable to get the mac address");
		exit(1); 
	}     
//	memcpy(tmpMac, ifreq1.ifr_hwaddr.sa_data, 6); 
	mac[0]=ifreq1.ifr_hwaddr.sa_data[0];
	mac[1]=ifreq1.ifr_hwaddr.sa_data[1];
	mac[2]=ifreq1.ifr_hwaddr.sa_data[2];
	mac[3]=ifreq1.ifr_hwaddr.sa_data[3];
	mac[4]=ifreq1.ifr_hwaddr.sa_data[4];
	mac[5]=ifreq1.ifr_hwaddr.sa_data[5];

	return 0 ;
} 


int main(int argc, char* argv[])
{
	int i = 0;
	int timeout = 2;
	int  optval = 1;
	int s;   /* socket */
	int rv = 1;   /* return value */
	struct sockaddr addr;  /* for interface name */
	struct arpMsg arp;
	fd_set  fdset;
	struct timeval tm;
	time_t  prevTime;
	u_int32_t  ip;
	struct in_addr my_ip;
	struct in_addr dst_ip;
	char  buff[2000];
	char br0Ip[16]={0};
	unsigned char mac[6];
	unsigned char dmac[6];
	unsigned char tmpMac[6];
	char interface[] = "br0";
	char acMacAddr[32]={0};

	get_local_addr(mac);

	getCmdStr("ifconfig br0  | grep inet | awk '{print $2}' | cut -f2 -d:",br0Ip,sizeof(br0Ip));

	getCmdStr("flash get AC_MAC | cut -f2 -d\\\"",acMacAddr,sizeof(acMacAddr));
	
printf("[acMacAddr:%s]\n",acMacAddr);
	if(strlen(acMacAddr)<10)	
		return 0;
	
	for (i=0; i < 6; ++i)
	{
		strncpy(buff, acMacAddr+3*i, 2);
		buff[3] = '\0';
		dmac[i] = strtol(buff, (char**)NULL, 16);
	}  

	if ((s = socket (PF_PACKET, SOCK_PACKET, htons(ETH_P_RARP))) == -1) 
	{
		printf("Could not open raw socket\n");
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) 
	{
		printf("Could not setsocketopt on raw socket\n");
		close(s);
		return -1;
	}


	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sa_data, interface);

	/* send rarp request */
	memset(&arp, 0, sizeof(arp));
	memcpy(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6); /* MAC DA */
	memcpy(arp.ethhdr.h_source, mac, 6);  /* MAC SA */
	arp.ethhdr.h_proto = htons(ETH_P_RARP);  /* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);  /* hardware type */
	arp.ptype = htons(ETH_P_IP);   /* protocol type (ARP message) */
	arp.hlen = 6;     /* hardware address length */
	arp.plen = 4;     /* protocol address length */
	arp.operation = htons(3);  /* RARP request code */
	*((u_int *) arp.sInaddr) = inet_addr(br0Ip);   /* source IP address */
	memcpy(arp.sHaddr, mac, 6);   /* source hardware address */ 
	memcpy(arp.tHaddr, dmac, 6);


	if (sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0)
	{
		perror("Unabele to send arp request");
		return 0;  
	}
	rv = 0;

	/* wait arp reply, and check it */
	tm.tv_usec = 0;
	time(&prevTime);
	while (timeout > 0) 
	{
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec = timeout;
		if (select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm) < 0) 
		{
			printf("Error on ARPING request:");
			if (errno != EINTR) rv = 0;
		} 
		else if (FD_ISSET(s, &fdset)) 
		{
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) 
			{
				perror("Unable get valid rarp response");
				rv = 0;
			} 
			if (arp.operation == htons(4) && 
			bcmp(arp.tHaddr, mac, 6) == 0 ) 
			{
				print_ip(arp.sInaddr);
				rv = 0;
				break;
			}
		}
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	close(s);
	return 0;
}

